"""
Database module with Repository Pattern

Provides clean, modular database access layer.
"""

from src.db.base import Base
from src.db.setup import SessionLocal, engine, init_db
from src.db.models import (
    Server,
    LogEntry,
    LinuxLogDetails,
    WindowsLogDetails,
    NginxLogDetails,
    Alert,
    AlertRule
)

# Import all repository functions
from src.db.repository import (
    # Server operations
    get_or_create_server,
    
    # Log operations
    insert_raw_log,
    get_unparsed_linux_logs,
    get_unparsed_windows_logs,
    get_unparsed_nginx_logs,
    get_recent_logs,
    
    # Parsed log details
    insert_linux_details,
    insert_windows_details,
    insert_nginx_details,
    
    # Alert operations
    create_alert,
    get_recent_alerts,
    resolve_alert,
    
    # Rule operations
    get_active_rules_for_source,
    get_all_rules,
)

__all__ = [
    # Database setup
    "SessionLocal",
    "Base",
    "engine",
    "init_db",
    
    # Models
    "Server",
    "LogEntry",
    "LinuxLogDetails",
    "WindowsLogDetails",
    "NginxLogDetails",
    "Alert",
    "AlertRule",
    
    # Server operations
    "get_or_create_server",
    
    # Log operations
    "insert_raw_log",
    "get_unparsed_linux_logs",
    "get_unparsed_windows_logs",
    "get_unparsed_nginx_logs",
    "get_recent_logs",
    
    # Parsed log details
    "insert_linux_details",
    "insert_windows_details",
    "insert_nginx_details",
    
    # Alert operations
    "create_alert",
    "get_recent_alerts",
    "resolve_alert",
    
    # Rule operations
    "get_active_rules_for_source",
    "get_all_rules",
]


