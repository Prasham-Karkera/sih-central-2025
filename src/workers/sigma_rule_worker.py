"""
Sigma Rule Worker (Repository Pattern)

Background worker that continuously monitors the database for new logs
and runs Sigma rule detection, storing alerts back to the database.
"""

import time
import threading
import sys
import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.db.setup import SessionLocal
from src.db.models import LogEntry, LinuxLogDetails, WindowsLogDetails, NginxLogDetails, Server
from src.db.repository.alert_repo import create_alert
from src.workers.sigma_rule_engine import SigmaRuleEngine


class SigmaRuleWorker:
    """
    Background worker for Sigma rule detection using repository pattern.
    
    Flow:
    1. Poll database for new unprocessed logs
    2. Run Sigma rule matching on each log
    3. Store alerts using repository
    4. Track progress with checkpoint
    5. Sleep and repeat
    """
    
    def __init__(
        self,
        rules_dir: str = "./Sigma_Rules",
        poll_interval: float = 5.0,
        batch_size: int = 100
    ):
        """
        Initialize Sigma rule worker.
        
        Args:
            rules_dir: Path to Sigma rules directory
            poll_interval: Seconds between database polls
            batch_size: Max logs to process per batch
        """
        self.rules_dir = rules_dir
        self.poll_interval = poll_interval
        self.batch_size = batch_size
        
        self.engine: Optional[SigmaRuleEngine] = None
        
        self.running = False
        self._thread: Optional[threading.Thread] = None
        self._last_processed_id = 0
        self._start_time: Optional[datetime] = None
        
        # Statistics
        self.stats = {
            'logs_processed': 0,
            'alerts_generated': 0,
            'rules_matched': 0,
            'errors': 0,
            'started_at': None
        }
        
        print("[SigmaWorker] Initialized (Repository Pattern)")
        print(f"  Rules: {rules_dir}")
        print(f"  Poll Interval: {poll_interval}s")
        print(f"  Batch Size: {batch_size}")
    
    def start(self):
        """Start worker in background thread."""
        if self.running:
            print("[SigmaWorker] Already running")
            return
        
        self._thread = threading.Thread(target=self.run, daemon=True)
        self._thread.start()
        print("[SigmaWorker] Started in background thread")
    
    def run(self):
        """Main worker loop."""
        print("[SigmaWorker] Starting...")
        
        try:
            # Initialize checkpoint: get latest log ID to start from
            self._start_time = datetime.now()
            self._last_processed_id = self._get_latest_log_id()
            print(f"[SigmaWorker] Starting from log ID: {self._last_processed_id}")
            print(f"[SigmaWorker] Will only process logs arriving after: {self._start_time}")
            
            # Load Sigma rules
            self.engine = SigmaRuleEngine(self.rules_dir)
            rules_loaded = self.engine.load_rules()
            
            if rules_loaded == 0:
                print("[SigmaWorker] No rules loaded, worker will not process logs")
                return
            
            self.running = True
            self.stats['started_at'] = datetime.now().isoformat()
            
            print("[SigmaWorker] Running...")
            
            while self.running:
                # Process batch of logs
                processed = self._process_batch()
                
                if processed > 0:
                    print(f"[SigmaWorker] Processed {processed} logs, "
                          f"{self.stats['alerts_generated']} total alerts")
                
                # Sleep before next poll
                time.sleep(self.poll_interval)
        
        except KeyboardInterrupt:
            print("\n[SigmaWorker] Interrupted")
        
        except Exception as e:
            print(f"[SigmaWorker] Fatal error: {e}")
            import traceback
            traceback.print_exc()
        
        finally:
            self.running = False
            print("[SigmaWorker] Stopped")
    
    def _get_latest_log_id(self) -> int:
        """
        Get the latest log ID from database to start processing from.
        This ensures we only process NEW logs arriving after worker starts.
        
        Returns:
            Latest log ID, or 0 if no logs exist
        """
        db = SessionLocal()
        try:
            result = db.query(LogEntry.id).order_by(LogEntry.id.desc()).first()
            return result[0] if result else 0
        finally:
            db.close()
    
    def _process_batch(self) -> int:
        """
        Process a batch of unprocessed logs.
        
        Returns:
            Number of logs processed
        """
        # Get unprocessed logs
        logs = self._get_unprocessed_logs()
        
        if not logs:
            return 0
        
        processed = 0
        
        for log in logs:
            try:
                # Match against Sigma rules
                alerts = self.engine.match_log(log)
                
                # Store alerts
                if alerts:
                    self._store_alerts(alerts)
                    self.stats['alerts_generated'] += len(alerts)
                    self.stats['rules_matched'] += len(alerts)
                
                # Update last processed ID
                self._last_processed_id = max(self._last_processed_id, log['id'])
                
                processed += 1
                self.stats['logs_processed'] += 1
            
            except Exception as e:
                print(f"[SigmaWorker] Error processing log {log.get('id')}: {e}")
                import traceback
                traceback.print_exc()
                self.stats['errors'] += 1
        
        return processed
    
    def _get_unprocessed_logs(self) -> List[Dict[str, Any]]:
        """
        Get batch of logs that haven't been processed yet using repository pattern.
        
        Returns:
            List of log entries as dictionaries
        """
        db = SessionLocal()
        try:
            # Query unprocessed logs with server info
            log_entries = (
                db.query(LogEntry, Server)
                .join(Server, LogEntry.server_id == Server.id, isouter=True)
                .filter(LogEntry.id > self._last_processed_id)
                .order_by(LogEntry.id.asc())
                .limit(self.batch_size)
                .all()
            )
            
            logs = []
            for entry, server in log_entries:
                log = {
                    'id': entry.id,
                    'timestamp': entry.recv_time.isoformat() if entry.recv_time else None,
                    'recv_time': entry.recv_time.isoformat() if entry.recv_time else None,
                    'log_type': entry.log_source,
                    'raw_line': entry.content,
                    'hostname': server.hostname if server else None,
                    'ip_address': server.ip_address if server else None
                }
                
                # Add type-specific details
                log_type = entry.log_source
                
                if log_type == 'linux':
                    details = db.query(LinuxLogDetails).filter_by(log_entry_id=entry.id).first()
                    if details:
                        log.update({
                            'facility': details.facility,
                            'severity': details.severity,
                            'program': details.program,
                            'pid': details.pid,
                            'message': details.message
                        })
                
                elif log_type == 'windows':
                    details = db.query(WindowsLogDetails).filter_by(log_entry_id=entry.id).first()
                    if details:
                        log.update({
                            'channel': details.channel,
                            'event_id': details.event_id,
                            'message': details.message,
                            'user_name': details.user_name
                        })
                
                elif log_type == 'nginx':
                    details = db.query(NginxLogDetails).filter_by(log_entry_id=entry.id).first()
                    if details:
                        log.update({
                            'method': details.method,
                            'path': details.path,
                            'status_code': details.status_code,
                            'bytes': details.bytes_sent,
                            'user_agent': details.user_agent,
                            'remote_addr': details.remote_addr
                        })
                
                logs.append(log)
            
            return logs
        finally:
            db.close()
    
    def _store_alerts(self, alerts: List[Dict[str, Any]]):
        """Store alerts in database using repository."""
        db = SessionLocal()
        try:
            for alert in alerts:
                try:
                    # Get server_id from log_entry
                    from src.db.models import LogEntry
                    log_entry = db.query(LogEntry).filter_by(id=alert['log_id']).first()
                    if not log_entry:
                        print(f"[SigmaWorker] Log entry {alert['log_id']} not found")
                        continue
                    
                    create_alert(
                        log_entry_id=alert['log_id'],
                        server_id=log_entry.server_id,
                        rule_id=alert['rule_id'],
                        title=alert['rule_title'],
                        description=alert.get('rule_description', ''),
                        severity=alert['severity'],
                        metadata={
                            'timestamp': alert['timestamp'],
                            'alert_id': alert['alert_id'],
                            'log_type': alert['log_type'],
                            'hostname': alert.get('hostname'),
                            'ip_address': alert.get('ip_address'),
                            'raw_line': alert.get('raw_line'),
                            'matched_fields': alert.get('matched_fields', {}),
                            'false_positives': alert.get('false_positives', []),
                            'references': alert.get('references', [])
                        }
                    )
                except Exception as e:
                    print(f"[SigmaWorker] Error storing alert: {e}")
                    import traceback
                    traceback.print_exc()
        finally:
            db.close()
    
    def stop(self):
        """Stop worker gracefully."""
        self.running = False
        print("[SigmaWorker] Stopping...")
    
    def is_running(self) -> bool:
        """Check if worker is running."""
        return self.running
    
    def get_stats(self) -> Dict[str, Any]:
        """Get worker statistics."""
        stats = self.stats.copy()
        
        if self.engine:
            stats['engine'] = self.engine.get_stats()
        
        return stats


# Entry point for standalone execution
if __name__ == "__main__":
    import signal
    
    def signal_handler(signum, frame):
        print("\n[Signal] Received interrupt signal")
        worker.stop()
        sys.exit(0)
    
    # Create worker
    worker = SigmaRuleWorker(
        rules_dir="./Sigma_Rules",
        poll_interval=5.0,
        batch_size=100
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
