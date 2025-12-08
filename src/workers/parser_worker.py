"""
Parser Worker (Repository Pattern)

Background worker that reads unparsed logs from the database,
extracts detailed fields, and saves them to detail tables.
"""

import time
import sys
from pathlib import Path
from typing import Optional
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.db.setup import SessionLocal
from src.db.models import LogEntry
from src.db.repository.log_repo import get_unparsed_linux_logs, get_unparsed_windows_logs, get_unparsed_nginx_logs
from src.db.repository.linux_repo import insert_linux_details
from src.db.repository.windows_repo import insert_windows_details
from src.db.repository.nginx_repo import insert_nginx_details
from src.parsers.parser_manager import ParserManager


class ParserWorker:
    """
    Background worker for parsing unparsed logs using repository pattern.
    
    Flow:
    1. Poll database for unparsed logs
    2. Parse each log using ParserManager
    3. Save parsed details to detail tables
    4. Sleep and repeat
    """
    
    def __init__(
        self,
        poll_interval: float = 5.0,
        batch_size: int = 50
    ):
        """
        Initialize parser worker.
        
        Args:
            poll_interval: Seconds between database polls
            batch_size: Max logs to process per batch
        """
        self.poll_interval = poll_interval
        self.batch_size = batch_size
        
        self.parser_manager = ParserManager()
        self.running = False
        
        # Statistics
        self.stats = {
            'logs_processed': 0,
            'linux_parsed': 0,
            'windows_parsed': 0,
            'nginx_parsed': 0,
            'errors': 0,
            'started_at': None
        }
        
        print("[ParserWorker] Initialized (Repository Pattern)")
        print(f"  Poll Interval: {poll_interval}s")
        print(f"  Batch Size: {batch_size}")
    
    def run(self):
        """Main worker loop."""
        print("[ParserWorker] Starting...")
        
        self.running = True
        self.stats['started_at'] = datetime.now().isoformat()
        
        print("[ParserWorker] Running...")
        
        try:
            while self.running:
                # Process each log type
                processed = 0
                processed += self._process_linux_logs()
                processed += self._process_windows_logs()
                processed += self._process_nginx_logs()
                
                if processed > 0:
                    print(f"[ParserWorker] Processed {processed} logs | "
                          f"Linux: {self.stats['linux_parsed']} | "
                          f"Windows: {self.stats['windows_parsed']} | "
                          f"Nginx: {self.stats['nginx_parsed']} | "
                          f"Errors: {self.stats['errors']}")
                
                # Sleep before next poll
                time.sleep(self.poll_interval)
        
        except KeyboardInterrupt:
            print("\n[ParserWorker] Interrupted")
        
        except Exception as e:
            print(f"[ParserWorker] Fatal error: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            self.running = False
            print("[ParserWorker] Stopped")
    
    def _process_linux_logs(self) -> int:
        """Process unparsed Linux logs."""
        try:
            # Get unparsed logs
            unparsed = get_unparsed_linux_logs(limit=self.batch_size)
            
            if not unparsed:
                return 0
            
            processed = 0
            
            for log_entry in unparsed:
                try:
                    # Parse the log content
                    parsed = self._parse_linux_log(log_entry.content)
                    
                    if parsed:
                        # Save to linux_log_details
                        insert_linux_details(
                            log_entry_id=log_entry.id,
                            timestamp=parsed.get('timestamp'),
                            app_name=parsed.get('app_name') or parsed.get('program'),
                            pid=parsed.get('pid'),
                            raw_message=parsed.get('message') or parsed.get('raw_message'),
                            ssh_action=parsed.get('ssh_action'),
                            ssh_user=parsed.get('ssh_user'),
                            ssh_ip=parsed.get('ssh_ip')
                        )
                        
                        self.stats['linux_parsed'] += 1
                        processed += 1
                    else:
                        self.stats['errors'] += 1
                
                except Exception as e:
                    print(f"[ParserWorker] Error parsing Linux log {log_entry.id}: {e}")
                    self.stats['errors'] += 1
            
            self.stats['logs_processed'] += processed
            return processed
        
        except Exception as e:
            print(f"[ParserWorker] Error in _process_linux_logs: {e}")
            return 0
    
    def _process_windows_logs(self) -> int:
        """Process unparsed Windows logs."""
        try:
            # Get unparsed logs
            unparsed = get_unparsed_windows_logs(limit=self.batch_size)
            
            if not unparsed:
                return 0
            
            processed = 0
            
            for log_entry in unparsed:
                try:
                    # Parse the log content
                    parsed = self._parse_windows_log(log_entry.content)
                    
                    if parsed:
                        # Save to windows_log_details
                        insert_windows_details(
                            log_entry_id=log_entry.id,
                            content=log_entry.content  # Store full content as JSON/text
                        )
                        
                        self.stats['windows_parsed'] += 1
                        processed += 1
                    else:
                        self.stats['errors'] += 1
                
                except Exception as e:
                    print(f"[ParserWorker] Error parsing Windows log {log_entry.id}: {e}")
                    self.stats['errors'] += 1
            
            self.stats['logs_processed'] += processed
            return processed
        
        except Exception as e:
            print(f"[ParserWorker] Error in _process_windows_logs: {e}")
            return 0
    
    def _process_nginx_logs(self) -> int:
        """Process unparsed Nginx logs."""
        try:
            # Get unparsed logs
            unparsed = get_unparsed_nginx_logs(limit=self.batch_size)
            
            if not unparsed:
                return 0
            
            processed = 0
            
            for log_entry in unparsed:
                try:
                    # Parse the log content
                    parsed = self._parse_nginx_log(log_entry.content)
                    
                    if parsed:
                        # Save to nginx_log_details
                        insert_nginx_details(
                            log_entry_id=log_entry.id,
                            remote_addr=parsed.get('remote_addr'),
                            timestamp=parsed.get('timestamp'),
                            request_method=parsed.get('request_method') or parsed.get('method'),
                            request_uri=parsed.get('request_uri') or parsed.get('path'),
                            status=parsed.get('status') or parsed.get('status_code'),
                            body_bytes_sent=parsed.get('body_bytes_sent') or parsed.get('bytes'),
                            http_referer=parsed.get('http_referer') or parsed.get('referer'),
                            http_user_agent=parsed.get('http_user_agent') or parsed.get('user_agent')
                        )
                        
                        self.stats['nginx_parsed'] += 1
                        processed += 1
                    else:
                        self.stats['errors'] += 1
                
                except Exception as e:
                    print(f"[ParserWorker] Error parsing Nginx log {log_entry.id}: {e}")
                    self.stats['errors'] += 1
            
            self.stats['logs_processed'] += processed
            return processed
        
        except Exception as e:
            print(f"[ParserWorker] Error in _process_nginx_logs: {e}")
            return 0
    
    def _parse_linux_log(self, content: str) -> Optional[dict]:
        """Parse Linux log content."""
        try:
            # Use the parser manager to parse
            raw_data = {'line': content, 'log_type': 'linux'}
            parsed = self.parser_manager.parse(raw_data)
            return parsed
        except Exception as e:
            print(f"[ParserWorker] Linux parse error: {e}")
            return None
    
    def _parse_windows_log(self, content: str) -> Optional[dict]:
        """Parse Windows log content."""
        try:
            # Use the parser manager to parse
            raw_data = {'line': content, 'log_type': 'windows'}
            parsed = self.parser_manager.parse(raw_data)
            return parsed
        except Exception as e:
            print(f"[ParserWorker] Windows parse error: {e}")
            return None
    
    def _parse_nginx_log(self, content: str) -> Optional[dict]:
        """Parse Nginx log content."""
        try:
            # Use the parser manager to parse
            raw_data = {'line': content, 'log_type': 'nginx'}
            parsed = self.parser_manager.parse(raw_data)
            return parsed
        except Exception as e:
            print(f"[ParserWorker] Nginx parse error: {e}")
            return None
    
    def stop(self):
        """Stop worker gracefully."""
        self.running = False
        print("[ParserWorker] Stopping...")
    
    def get_stats(self) -> dict:
        """Get worker statistics."""
        return self.stats.copy()


# Entry point for standalone execution
if __name__ == "__main__":
    import signal
    
    def signal_handler(signum, frame):
        print("\n[Signal] Received interrupt signal")
        worker.stop()
        sys.exit(0)
    
    # Create worker
    worker = ParserWorker(
        poll_interval=5.0,
        batch_size=50
    )
    
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    
    # Run
    try:
        worker.run()
    except Exception as e:
        print(f"[Error] Fatal error: {e}")
        import traceback
        traceback.print_exc()
