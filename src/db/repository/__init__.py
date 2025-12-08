"""
Repository Layer for Database Access

Provides clean, modular access to database operations.
"""

from .server_repo import get_or_create_server
from .log_repo import (
    insert_raw_log,
    get_unparsed_linux_logs,
    get_unparsed_windows_logs,
    get_unparsed_nginx_logs,
    get_recent_logs
)
from .linux_repo import insert_linux_details
from .windows_repo import insert_windows_details
from .nginx_repo import insert_nginx_details
from .alert_repo import create_alert, get_recent_alerts, resolve_alert
from .rule_repo import get_active_rules_for_source, get_all_rules

__all__ = [
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
