"""
Log Entry Repository

Handles raw log storage and retrieval.
"""

from datetime import datetime
from typing import List, Optional
from src.db.setup import SessionLocal
from src.db.models import LogEntry


def insert_raw_log(
    server_id: int,
    log_source: str,
    content: str,
    recv_time: Optional[datetime] = None
) -> int:
    """
    Insert a raw log entry.
    
    Args:
        server_id: ID of the server that sent the log
        log_source: Source type (linux, windows, nginx)
        content: Raw log content
        recv_time: Time received (defaults to now)
        
    Returns:
        Log entry ID
    """
    db = SessionLocal()
    try:
        entry = LogEntry(
            server_id=server_id,
            log_source=log_source,
            content=content,
            recv_time=recv_time or datetime.utcnow()
        )
        db.add(entry)
        db.commit()
        db.refresh(entry)
        return entry.id

    finally:
        db.close()


def get_unparsed_linux_logs(limit: int = 50) -> List[LogEntry]:
    """
    Get Linux logs that haven't been parsed yet.
    
    Args:
        limit: Maximum number of logs to retrieve
        
    Returns:
        List of unparsed log entries
    """
    db = SessionLocal()
    try:
        logs = db.query(LogEntry).filter(
            LogEntry.log_source == "linux",
            LogEntry.linux_details is None
        ).limit(limit).all()

        return logs

    finally:
        db.close()


def get_unparsed_windows_logs(limit: int = 50) -> List[LogEntry]:
    """
    Get Windows logs that haven't been parsed yet.
    
    Args:
        limit: Maximum number of logs to retrieve
        
    Returns:
        List of unparsed log entries
    """
    db = SessionLocal()
    try:
        logs = db.query(LogEntry).filter(
            LogEntry.log_source == "windows",
            LogEntry.windows_details is None
        ).limit(limit).all()

        return logs

    finally:
        db.close()


def get_unparsed_nginx_logs(limit: int = 50) -> List[LogEntry]:
    """
    Get Nginx logs that haven't been parsed yet.
    
    Args:
        limit: Maximum number of logs to retrieve
        
    Returns:
        List of unparsed log entries
    """
    db = SessionLocal()
    try:
        logs = db.query(LogEntry).filter(
            LogEntry.log_source == "nginx",
            LogEntry.nginx_details is None
        ).limit(limit).all()

        return logs

    finally:
        db.close()


def get_logs_by_server(server_id: int, limit: int = 100) -> List[LogEntry]:
    """Get recent logs for a specific server."""
    db = SessionLocal()
    try:
        return db.query(LogEntry).filter(
            LogEntry.server_id == server_id
        ).order_by(LogEntry.recv_time.desc()).limit(limit).all()
    finally:
        db.close()


def get_recent_logs(log_source: Optional[str] = None, limit: int = 100) -> List[LogEntry]:
    """
    Get recent logs, optionally filtered by source.
    
    Args:
        log_source: Filter by source type (linux, windows, nginx)
        limit: Maximum number of logs
        
    Returns:
        List of log entries
    """
    db = SessionLocal()
    try:
        query = db.query(LogEntry)
        
        if log_source:
            query = query.filter(LogEntry.log_source == log_source)
            
        return query.order_by(LogEntry.recv_time.desc()).limit(limit).all()
    finally:
        db.close()
