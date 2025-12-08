"""
Ingestion Worker

Main orchestration: Listen → Parse → Save

Now uses Repository Pattern for clean database access.
"""

import time
from typing import List, Dict, Any
from datetime import datetime
import threading
import signal
import sys

from src.listener.listener import UdpListener
from src.parsers.parser_manager import ParserManager
from src.db import (
    get_or_create_server,
    insert_raw_log,
    SessionLocal
)


class IngestionWorker:
    """
    Orchestrates the complete log ingestion pipeline.
    
    Flow:
        1. Listen for UDP logs on port 5140
        2. Parse logs using ParserManager
        3. Batch logs (100 or 5 seconds)
        4. Save to database
    """
    
    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 514,
        batch_size: int = 100,
        batch_timeout: float = 5.0,
        output_dir: str = "./collected_logs/processed"
    ):
        """
        Initialize ingestion worker.
        
        Args:
            host: UDP bind host
            port: UDP bind port
            batch_size: Max logs per batch
            batch_timeout: Max seconds before forcing batch save
            output_dir: Directory for parsed log files
        """
        self.host = host
        self.port = port
        self.batch_size = batch_size
        self.batch_timeout = batch_timeout
        
        # Components
        self.listener = UdpListener(host=host, port=port, timeout=1.0)
        self.parser_manager = ParserManager(output_dir=output_dir)
        
        # State
        self.running = False
        self.batch: List[Dict[str, Any]] = []
        self.last_batch_time = time.time()
        
        # Stats
        self.stats = {
            "received": 0,
            "parsed": 0,
            "saved": 0,
            "errors": 0,
            "batches": 0
        }
        
        print("[IngestionWorker] Initialized")
        print(f"  Listening: {host}:{port}")
        print(f"  Batch: {batch_size} logs or {batch_timeout}s")
        print(f"  Parsers: {', '.join(self.parser_manager.list_parsers())}")
    
    def _should_flush_batch(self) -> bool:
        """Check if batch should be flushed."""
        if len(self.batch) >= self.batch_size:
            return True
        
        if len(self.batch) > 0 and (time.time() - self.last_batch_time) >= self.batch_timeout:
            return True
        
        return False
    
    def _flush_batch(self):
        """Save batch to database using repository pattern."""
        if not self.batch:
            return
        
        batch_size = len(self.batch)
        saved_count = 0
        
        try:
            for log_data in self.batch:
                try:
                    # Extract server info
                    hostname = log_data.get("hostname", "unknown")
                    ip = log_data.get("source_ip") or log_data.get("src_ip", "0.0.0.0")
                    
                    # Get log source - try multiple keys
                    log_source = (
                        log_data.get("log_source") or 
                        log_data.get("log_type") or 
                        "unknown"
                    )
                    
                    # Get content - handle both raw_line and line
                    content = log_data.get("raw_line") or log_data.get("line") or str(log_data)
                    
                    # Parse timestamp if it's a string
                    recv_time = log_data.get("timestamp") or log_data.get("recv_time")
                    if recv_time and isinstance(recv_time, str):
                        try:
                            from datetime import datetime
                            recv_time = datetime.strptime(recv_time, "%Y-%m-%d %H:%M:%S")
                        except:
                            recv_time = None
                    
                    # Get or create server
                    server_id = get_or_create_server(
                        hostname=hostname,
                        ip=ip,
                        server_type=log_source
                    )
                    
                    # Insert raw log
                    log_id = insert_raw_log(
                        server_id=server_id,
                        log_source=log_source,
                        content=content,
                        recv_time=recv_time
                    )
                    
                    saved_count += 1
                    
                except Exception as e:
                    print(f"[IngestionWorker] Error saving log: {e}")
                    print(f"  Log data keys: {list(log_data.keys())}")
                    import traceback
                    traceback.print_exc()
                    self.stats["errors"] += 1
            
            self.stats["saved"] += saved_count
            self.stats["batches"] += 1
            
            print(f"[IngestionWorker] Batch saved: {saved_count}/{batch_size} logs")
            
        except Exception as e:
            print(f"[IngestionWorker] Error in batch processing: {e}")
            self.stats["errors"] += batch_size - saved_count
        
        finally:
            # Clear batch
            self.batch.clear()
            self.last_batch_time = time.time()
    
    def _process_log(self, raw_data: Dict[str, Any]):
        """Process single log: parse and add to batch."""
        try:
            # Parse log
            parsed = self.parser_manager.parse(raw_data)
            
            if parsed:
                self.batch.append(parsed)
                self.stats["parsed"] += 1
            else:
                self.stats["errors"] += 1
        
        except Exception as e:
            print(f"[IngestionWorker] Error processing log: {e}")
            print(f"  Raw: {raw_data.get('line', '')[:80]}...")
            self.stats["errors"] += 1
    
    def run(self):
        """
        Main loop: listen → parse → batch → save.
        
        Runs until stopped with Ctrl+C.
        """
        print("[IngestionWorker] Starting...")
        self.running = True
        
        with self.listener:
            while self.running:
                try:
                    # Listen for log
                    raw_data = self.listener.receive()
                    
                    if raw_data:
                        self.stats["received"] += 1
                        
                        # Process log
                        self._process_log(raw_data)
                        
                        # Check if batch should be flushed
                        if self._should_flush_batch():
                            self._flush_batch()
                    
                    # Print stats every 100 logs
                    if self.stats["received"] % 100 == 0 and self.stats["received"] > 0:
                        self._print_stats()
                
                except KeyboardInterrupt:
                    print("\n[IngestionWorker] Shutting down...")
                    break
                
                except Exception as e:
                    print(f"[IngestionWorker] Error in main loop: {e}")
                    self.stats["errors"] += 1
        
        # Flush remaining logs
        if self.batch:
            print(f"[IngestionWorker] Flushing remaining {len(self.batch)} logs...")
            self._flush_batch()
        
        # Final stats
        self._print_stats()
        
        self.running = False
        
        print("[IngestionWorker] Stopped")
    
    def _print_stats(self):
        """Print current statistics."""
        print(f"\n{'='*60}")
        print(f"[Stats] Received: {self.stats['received']}")
        print(f"[Stats] Parsed:   {self.stats['parsed']}")
        print(f"[Stats] Saved:    {self.stats['saved']}")
        print(f"[Stats] Errors:   {self.stats['errors']}")
        print(f"[Stats] Batches:  {self.stats['batches']}")
        
        # Query database stats
        try:
            from src.db import get_recent_logs
            from src.db.models import LogEntry
            
            db = SessionLocal()
            total_logs = db.query(LogEntry).count()
            
            # Count by type
            linux_count = db.query(LogEntry).filter_by(log_source="linux").count()
            windows_count = db.query(LogEntry).filter_by(log_source="windows").count()
            nginx_count = db.query(LogEntry).filter_by(log_source="nginx").count()
            
            db.close()
            
            print(f"[Stats] DB Total: {total_logs}")
            print(f"[Stats] By Type:  Linux={linux_count}, Windows={windows_count}, Nginx={nginx_count}")
        except Exception as e:
            print(f"[Stats] Could not query DB: {e}")
        
        print(f"{'='*60}\n")
    
    def stop(self):
        """Stop worker gracefully."""
        self.running = False
    
    def start(self):
        """Start worker in background thread."""
        if hasattr(self, '_thread') and self._thread and self._thread.is_alive():
            print("[IngestionWorker] Already running")
            return
        
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()
        print("[IngestionWorker] Started in background thread")
    
    def is_running(self) -> bool:
        """Check if worker is running."""
        return self.running
    
    def get_stats(self) -> Dict[str, int]:
        """Get current statistics."""
        return self.stats.copy()


# Signal handler for graceful shutdown
def signal_handler(worker):
    """Handle Ctrl+C gracefully."""
    def handler(signum, frame):
        print("\n[Signal] Received interrupt signal")
        worker.stop()
        sys.exit(0)
    return handler


# Entry point
if __name__ == "__main__":
    # Create worker
    worker = IngestionWorker(
        host="0.0.0.0",
        port=514,
        batch_size=100,
        batch_timeout=5.0,
        output_dir="./collected_logs/processed"
    )
    
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler(worker))
    
    # Run
    try:
        worker.run()
    except Exception as e:
        print(f"[Error] Fatal error: {e}")
        worker.stop()
