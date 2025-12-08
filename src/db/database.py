"""
Database Manager

Manages SQLite database for log storage.
"""

import sqlite3
from typing import Dict, List, Any, Optional
from pathlib import Path
from datetime import datetime
import threading


class DatabaseManager:
    """
    Manages SQLite database with normalized schema.
    
    Schema:
    - server: hostname, ip_address, first_seen, last_seen
    - log_entry: timestamp, server_id, log_type, raw_line, parsed_data
    - linux_log_details: facility, severity, program, pid, message
    - windows_log_details: channel, event_id, message, user_name
    - nginx_log_details: method, path, status_code, bytes, user_agent
    """
    
    def __init__(self, db_path: str = "./logs.db"):
        """
        Initialize database manager.
        
        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Thread-local connections
        self._local = threading.local()
        
        # Initialize schema
        self._init_schema()
        
        print(f"[DatabaseManager] Initialized at {self.db_path}")
    
    def get_connection(self) -> sqlite3.Connection:
        """Get thread-safe database connection."""
        if not hasattr(self._local, 'conn') or self._local.conn is None:
            self._local.conn = sqlite3.connect(
                str(self.db_path),
                check_same_thread=False
            )
            self._local.conn.row_factory = sqlite3.Row
        return self._local.conn
    
    def _init_schema(self):
        """Create database tables if they don't exist."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Server table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS server (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                ip_address TEXT,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(hostname, ip_address)
            )
        ''')
        
        # Main log entry table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS log_entry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP NOT NULL,
                recv_time TIMESTAMP,
                server_id INTEGER,
                log_type TEXT NOT NULL,
                raw_line TEXT NOT NULL,
                parsed_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (server_id) REFERENCES server(id)
            )
        ''')
        
        # Linux log details
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS linux_log_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_entry_id INTEGER NOT NULL,
                facility TEXT,
                severity TEXT,
                program TEXT,
                pid INTEGER,
                message TEXT,
                FOREIGN KEY (log_entry_id) REFERENCES log_entry(id)
            )
        ''')
        
        # Windows log details
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS windows_log_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_entry_id INTEGER NOT NULL,
                channel TEXT,
                event_id INTEGER,
                message TEXT,
                user_name TEXT,
                FOREIGN KEY (log_entry_id) REFERENCES log_entry(id)
            )
        ''')
        
        # Nginx log details
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS nginx_log_details (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                log_entry_id INTEGER NOT NULL,
                method TEXT,
                path TEXT,
                status_code INTEGER,
                bytes INTEGER,
                user_agent TEXT,
                FOREIGN KEY (log_entry_id) REFERENCES log_entry(id)
            )
        ''')
        
        # Sigma alerts table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sigma_alert (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                alert_id TEXT UNIQUE NOT NULL,
                rule_id TEXT NOT NULL,
                rule_title TEXT NOT NULL,
                rule_description TEXT,
                severity TEXT NOT NULL,
                log_entry_id INTEGER NOT NULL,
                log_type TEXT NOT NULL,
                hostname TEXT,
                ip_address TEXT,
                raw_line TEXT,
                matched_fields TEXT,
                false_positives TEXT,
                rule_refs TEXT,
                acknowledged INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (log_entry_id) REFERENCES log_entry(id)
            )
        ''')
        
        # Create indexes
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_timestamp ON log_entry(timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_log_type ON log_entry(log_type)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_server_hostname ON server(hostname)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON sigma_alert(timestamp DESC)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_severity ON sigma_alert(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_log ON sigma_alert(log_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_alert_ack ON sigma_alert(acknowledged)')
        
        conn.commit()
    
    def _get_or_create_server(self, hostname: str, ip_address: str = None) -> int:
        """Get server ID or create new server entry."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Try to find existing
        cursor.execute(
            'SELECT id FROM server WHERE hostname = ? AND (ip_address = ? OR ? IS NULL)',
            (hostname, ip_address, ip_address)
        )
        result = cursor.fetchone()
        
        if result:
            server_id = result[0]
            # Update last_seen
            cursor.execute(
                'UPDATE server SET last_seen = CURRENT_TIMESTAMP WHERE id = ?',
                (server_id,)
            )
            conn.commit()
            return server_id
        
        # Create new
        cursor.execute(
            'INSERT INTO server (hostname, ip_address) VALUES (?, ?)',
            (hostname, ip_address)
        )
        conn.commit()
        return cursor.lastrowid
    
    def save(self, parsed_log: Dict[str, Any]) -> int:
        """
        Save single parsed log to database.
        
        Args:
            parsed_log: Parsed log dictionary
            
        Returns:
            log_entry_id
        """
        if not parsed_log:
            return None
        
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Get server ID
        hostname = parsed_log.get("hostname", "unknown")
        ip_address = parsed_log.get("src_ip")
        server_id = self._get_or_create_server(hostname, ip_address)
        
        # Insert main log entry
        cursor.execute('''
            INSERT INTO log_entry (timestamp, recv_time, server_id, log_type, raw_line, parsed_data)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            parsed_log.get("timestamp"),
            parsed_log.get("recv_time"),
            server_id,
            parsed_log.get("log_type"),
            parsed_log.get("raw_line"),
            str(parsed_log)
        ))
        
        log_entry_id = cursor.lastrowid
        
        # Insert type-specific details
        log_type = parsed_log.get("log_type")
        
        if log_type == "linux":
            cursor.execute('''
                INSERT INTO linux_log_details (log_entry_id, facility, severity, program, pid, message)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                log_entry_id,
                parsed_log.get("facility"),
                parsed_log.get("severity"),
                parsed_log.get("program"),
                parsed_log.get("pid"),
                parsed_log.get("message")
            ))
        
        elif log_type == "windows":
            cursor.execute('''
                INSERT INTO windows_log_details (log_entry_id, channel, event_id, message, user_name)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                log_entry_id,
                parsed_log.get("channel"),
                parsed_log.get("event_id"),
                parsed_log.get("message"),
                parsed_log.get("user_name")
            ))
        
        elif log_type == "nginx":
            cursor.execute('''
                INSERT INTO nginx_log_details (log_entry_id, method, path, status_code, bytes, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                log_entry_id,
                parsed_log.get("method"),
                parsed_log.get("path"),
                parsed_log.get("status_code"),
                parsed_log.get("bytes"),
                parsed_log.get("user_agent")
            ))
        
        conn.commit()
        return log_entry_id
    
    def save_batch(self, parsed_logs: List[Dict[str, Any]]) -> int:
        """
        Save batch of parsed logs.
        
        Args:
            parsed_logs: List of parsed log dictionaries
            
        Returns:
            Number of logs saved
        """
        count = 0
        for log in parsed_logs:
            try:
                self.save(log)
                count += 1
            except Exception as e:
                print(f"[DatabaseManager] Error saving log: {e}")
                print(f"  Log: {log.get('raw_line', '')[:80]}...")
        
        return count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get database statistics."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT COUNT(*) FROM log_entry')
        total_logs = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM server')
        total_servers = cursor.fetchone()[0]
        
        cursor.execute('SELECT log_type, COUNT(*) FROM log_entry GROUP BY log_type')
        by_type = dict(cursor.fetchall())
        
        return {
            "total_logs": total_logs,
            "total_servers": total_servers,
            "by_type": by_type
        }
    
    def get_recent_logs(
        self,
        limit: int = 50,
        offset: int = 0,
        log_type: Optional[str] = None,
        server_id: Optional[int] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get recent logs with optional filtering."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = '''
            SELECT 
                l.id, l.timestamp, l.recv_time, l.log_type, l.raw_line,
                s.hostname, s.ip_address, s.id as server_id
            FROM log_entry l
            LEFT JOIN server s ON l.server_id = s.id
            WHERE 1=1
        '''
        params = []
        
        if log_type:
            query += ' AND l.log_type = ?'
            params.append(log_type)
        
        if server_id:
            query += ' AND l.server_id = ?'
            params.append(server_id)
        
        if start_time:
            query += ' AND l.timestamp >= ?'
            params.append(start_time)
        
        if end_time:
            query += ' AND l.timestamp <= ?'
            params.append(end_time)
        
        query += ' ORDER BY l.timestamp DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            logs.append({
                "id": row[0],
                "timestamp": row[1],
                "recv_time": row[2],
                "log_type": row[3],
                "raw_line": row[4],
                "hostname": row[5],
                "ip_address": row[6],
                "server_id": row[7]
            })
        
        return logs
    
    def get_log_by_id(self, log_id: int) -> Optional[Dict[str, Any]]:
        """Get single log by ID with type-specific details."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                l.id, l.timestamp, l.recv_time, l.log_type, l.raw_line, l.parsed_data,
                s.hostname, s.ip_address, s.id as server_id
            FROM log_entry l
            LEFT JOIN server s ON l.server_id = s.id
            WHERE l.id = ?
        ''', (log_id,))
        
        row = cursor.fetchone()
        if not row:
            return None
        
        log = {
            "id": row[0],
            "timestamp": row[1],
            "recv_time": row[2],
            "log_type": row[3],
            "raw_line": row[4],
            "parsed_data": row[5],
            "hostname": row[6],
            "ip_address": row[7],
            "server_id": row[8]
        }
        
        log_type = log["log_type"]
        
        if log_type == "linux":
            cursor.execute('''
                SELECT facility, severity, program, pid, message
                FROM linux_log_details WHERE log_entry_id = ?
            ''', (log_id,))
            details = cursor.fetchone()
            if details:
                log.update({
                    "facility": details[0],
                    "severity": details[1],
                    "program": details[2],
                    "pid": details[3],
                    "message": details[4]
                })
        
        elif log_type == "windows":
            cursor.execute('''
                SELECT channel, event_id, message, user_name
                FROM windows_log_details WHERE log_entry_id = ?
            ''', (log_id,))
            details = cursor.fetchone()
            if details:
                log.update({
                    "channel": details[0],
                    "event_id": details[1],
                    "message": details[2],
                    "user_name": details[3]
                })
        
        elif log_type == "nginx":
            cursor.execute('''
                SELECT method, path, status_code, bytes, user_agent
                FROM nginx_log_details WHERE log_entry_id = ?
            ''', (log_id,))
            details = cursor.fetchone()
            if details:
                log.update({
                    "method": details[0],
                    "path": details[1],
                    "status_code": details[2],
                    "bytes": details[3],
                    "user_agent": details[4]
                })
        
        return log
    
    def search_logs(
        self,
        text: Optional[str] = None,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 50,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Search logs with text and filters."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = '''
            SELECT 
                l.id, l.timestamp, l.recv_time, l.log_type, l.raw_line,
                s.hostname, s.ip_address
            FROM log_entry l
            LEFT JOIN server s ON l.server_id = s.id
            WHERE 1=1
        '''
        params = []
        
        if text:
            query += ' AND l.raw_line LIKE ?'
            params.append(f'%{text}%')
        
        if filters:
            if 'log_type' in filters:
                query += ' AND l.log_type = ?'
                params.append(filters['log_type'])
            
            if 'hostname' in filters:
                query += ' AND s.hostname = ?'
                params.append(filters['hostname'])
        
        query += ' ORDER BY l.timestamp DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            logs.append({
                "id": row[0],
                "timestamp": row[1],
                "recv_time": row[2],
                "log_type": row[3],
                "raw_line": row[4],
                "hostname": row[5],
                "ip_address": row[6]
            })
        
        return logs
    
    def get_servers_with_stats(self) -> List[Dict[str, Any]]:
        """Get all servers with activity statistics."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                s.id, s.hostname, s.ip_address, s.first_seen, s.last_seen,
                COUNT(l.id) as log_count,
                MAX(l.timestamp) as last_log_time
            FROM server s
            LEFT JOIN log_entry l ON s.id = l.server_id
            GROUP BY s.id
            ORDER BY log_count DESC
        ''')
        
        rows = cursor.fetchall()
        
        servers = []
        for row in rows:
            last_log = row[6]
            status = "offline"
            if last_log:
                try:
                    from datetime import datetime, timedelta
                    last_time = datetime.fromisoformat(last_log.replace('Z', '+00:00'))
                    now = datetime.now()
                    diff = (now - last_time).total_seconds()
                    
                    if diff < 300:  # 5 minutes
                        status = "online"
                    elif diff < 3600:  # 1 hour
                        status = "delayed"
                except:
                    status = "offline"
            
            servers.append({
                "id": row[0],
                "hostname": row[1],
                "ip_address": row[2],
                "first_seen": row[3],
                "last_seen": row[4],
                "log_count": row[5],
                "last_log_time": last_log,
                "status": status
            })
        
        return servers
    
    def get_server_logs(self, server_id: int, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent logs for specific server."""
        return self.get_recent_logs(limit=limit, server_id=server_id)
    
    def get_timeseries_stats(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Get log counts grouped by hour for charts."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                strftime('%Y-%m-%d %H:00:00', timestamp) as hour,
                log_type,
                COUNT(*) as count
            FROM log_entry
            WHERE timestamp >= datetime('now', '-' || ? || ' hours')
            GROUP BY hour, log_type
            ORDER BY hour DESC
        ''', (hours,))
        
        rows = cursor.fetchall()
        
        timeseries = []
        for row in rows:
            timeseries.append({
                "hour": row[0],
                "log_type": row[1],
                "count": row[2]
            })
        
        return timeseries
    
    def get_recent_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get recent alerts with filtering."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        query = '''
            SELECT 
                a.id, a.timestamp, a.alert_id, a.rule_id, a.rule_title,
                a.rule_description, a.severity, a.log_entry_id, a.log_type,
                a.hostname, a.ip_address, a.raw_line, a.matched_fields,
                a.false_positives, a.rule_refs, a.acknowledged, a.created_at
            FROM sigma_alert a
            WHERE 1=1
        '''
        params = []
        
        if severity:
            query += ' AND a.severity = ?'
            params.append(severity)
        
        if acknowledged is not None:
            query += ' AND a.acknowledged = ?'
            params.append(1 if acknowledged else 0)
        
        if start_time:
            query += ' AND a.timestamp >= ?'
            params.append(start_time)
        
        if end_time:
            query += ' AND a.timestamp <= ?'
            params.append(end_time)
        
        query += ' ORDER BY a.timestamp DESC LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        alerts = []
        for row in rows:
            alerts.append({
                "id": row[0],
                "timestamp": row[1],
                "alert_id": row[2],
                "rule_id": row[3],
                "rule_title": row[4],
                "rule_description": row[5],
                "severity": row[6],
                "log_entry_id": row[7],
                "log_type": row[8],
                "hostname": row[9],
                "ip_address": row[10],
                "raw_line": row[11],
                "matched_fields": row[12],
                "false_positives": row[13],
                "rule_refs": row[14],
                "acknowledged": bool(row[15]),
                "created_at": row[16]
            })
        
        return alerts
    
    def get_alert_by_id(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Get single alert by ID."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                a.id, a.timestamp, a.alert_id, a.rule_id, a.rule_title,
                a.rule_description, a.severity, a.log_entry_id, a.log_type,
                a.hostname, a.ip_address, a.raw_line, a.matched_fields,
                a.false_positives, a.rule_refs, a.acknowledged, a.created_at
            FROM sigma_alert a
            WHERE a.id = ?
        ''', (alert_id,))
        
        row = cursor.fetchone()
        if not row:
            return None
        
        return {
            "id": row[0],
            "timestamp": row[1],
            "alert_id": row[2],
            "rule_id": row[3],
            "rule_title": row[4],
            "rule_description": row[5],
            "severity": row[6],
            "log_entry_id": row[7],
            "log_type": row[8],
            "hostname": row[9],
            "ip_address": row[10],
            "raw_line": row[11],
            "matched_fields": row[12],
            "false_positives": row[13],
            "rule_refs": row[14],
            "acknowledged": bool(row[15]),
            "created_at": row[16]
        }
    
    def get_alerts_by_log(self, log_entry_id: int) -> List[Dict[str, Any]]:
        """Get all alerts for a specific log entry."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                a.id, a.timestamp, a.alert_id, a.rule_id, a.rule_title,
                a.rule_description, a.severity, a.log_entry_id, a.log_type,
                a.hostname, a.ip_address, a.matched_fields,
                a.false_positives, a.acknowledged
            FROM sigma_alert a
            WHERE a.log_entry_id = ?
            ORDER BY a.timestamp DESC
        ''', (log_entry_id,))
        
        rows = cursor.fetchall()
        
        alerts = []
        for row in rows:
            alerts.append({
                "id": row[0],
                "timestamp": row[1],
                "alert_id": row[2],
                "rule_id": row[3],
                "rule_title": row[4],
                "rule_description": row[5],
                "severity": row[6],
                "log_entry_id": row[7],
                "log_type": row[8],
                "hostname": row[9],
                "ip_address": row[10],
                "matched_fields": row[11],
                "false_positives": row[12],
                "acknowledged": bool(row[13])
            })
        
        return alerts
    
    def get_alert_stats(self) -> Dict[str, Any]:
        """Get alert statistics."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        # Total alerts
        cursor.execute('SELECT COUNT(*) FROM sigma_alert')
        total_alerts = cursor.fetchone()[0]
        
        # By severity
        cursor.execute('''
            SELECT severity, COUNT(*) 
            FROM sigma_alert 
            GROUP BY severity
        ''')
        by_severity = dict(cursor.fetchall())
        
        # By log type
        cursor.execute('''
            SELECT log_type, COUNT(*) 
            FROM sigma_alert 
            GROUP BY log_type
        ''')
        by_log_type = dict(cursor.fetchall())
        
        # Acknowledged vs unacknowledged
        cursor.execute('''
            SELECT acknowledged, COUNT(*) 
            FROM sigma_alert 
            GROUP BY acknowledged
        ''')
        ack_stats = dict(cursor.fetchall())
        
        # Recent alert rate (last hour)
        cursor.execute('''
            SELECT COUNT(*) 
            FROM sigma_alert 
            WHERE timestamp >= datetime('now', '-1 hour')
        ''')
        last_hour = cursor.fetchone()[0]
        
        return {
            "total_alerts": total_alerts,
            "by_severity": by_severity,
            "by_log_type": by_log_type,
            "acknowledged": ack_stats.get(1, 0),
            "unacknowledged": ack_stats.get(0, 0),
            "last_hour": last_hour
        }
    
    def acknowledge_alert(self, alert_id: int) -> bool:
        """Mark alert as acknowledged."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE sigma_alert 
            SET acknowledged = 1 
            WHERE id = ?
        ''', (alert_id,))
        
        conn.commit()
        return cursor.rowcount > 0
    
    def get_logs_for_sigma_processing(
        self,
        last_processed_id: int,
        batch_size: int = 100
    ) -> List[Dict[str, Any]]:
        """Get unprocessed logs for Sigma rule matching."""
        conn = self.get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                l.id, l.timestamp, l.log_type, l.raw_line, l.parsed_data,
                s.hostname, s.ip_address
            FROM log_entry l
            LEFT JOIN server s ON l.server_id = s.id
            WHERE l.id > ?
            ORDER BY l.id ASC
            LIMIT ?
        ''', (last_processed_id, batch_size))
        
        rows = cursor.fetchall()
        
        logs = []
        for row in rows:
            logs.append({
                "id": row[0],
                "timestamp": row[1],
                "log_type": row[2],
                "raw_line": row[3],
                "parsed_data": row[4],
                "hostname": row[5],
                "ip_address": row[6]
            })
        
        return logs
    
    def close(self):
        """Close database connection."""
        if hasattr(self._local, 'conn') and self._local.conn:
            self._local.conn.close()
            self._local.conn = None


# Example usage
if __name__ == "__main__":
    db = DatabaseManager("./test_logs.db")
    
    # Test saving
    test_log = {
        "timestamp": "2025-12-06 04:06:30",
        "recv_time": "2025-12-06T10:00:00",
        "hostname": "HP-LAP704",
        "src_ip": "10.78.233.207",
        "log_type": "windows",
        "raw_line": '{"timestamp":"2025-12-06 04:06:30","hostname":"HP-LAP704","channel":"Security","event_id":4799}',
        "channel": "Security",
        "event_id": 4799,
        "message": "Test event"
    }
    
    log_id = db.save(test_log)
    print(f"Saved log ID: {log_id}")
    
    stats = db.get_stats()
    print(f"Stats: {stats}")
    
    db.close()
  