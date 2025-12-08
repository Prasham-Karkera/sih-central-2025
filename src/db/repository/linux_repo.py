"""
Linux Log Details Repository

Handles parsed Linux log details.
"""

from typing import Dict, Any, Optional
from src.db.setup import SessionLocal
from src.db.models import LinuxLogDetails


def insert_linux_details(log_entry_id: int, parsed: Dict[str, Any]) -> None:
    """
    Insert parsed Linux log details.
    
    Args:
        log_entry_id: ID of the parent log entry
        parsed: Dictionary containing parsed fields
    """
    db = SessionLocal()
    try:
        details = LinuxLogDetails(
            log_entry_id=log_entry_id,
            timestamp=parsed.get("timestamp"),
            app_name=parsed.get("app_name"),
            pid=parsed.get("pid"),
            raw_message=parsed.get("raw_message"),
            ssh_action=parsed.get("ssh_action"),
            ssh_user=parsed.get("ssh_user"),
            ssh_ip=parsed.get("ssh_ip")
        )

        db.add(details)
        db.commit()

    finally:
        db.close()


def get_linux_details(log_entry_id: int) -> Optional[LinuxLogDetails]:
    """Get Linux log details for a specific log entry."""
    db = SessionLocal()
    try:
        return db.query(LinuxLogDetails).filter_by(
            log_entry_id=log_entry_id
        ).first()
    finally:
        db.close()


def get_ssh_logs(limit: int = 100):
    """Get recent SSH-related logs."""
    db = SessionLocal()
    try:
        return db.query(LinuxLogDetails).filter(
            LinuxLogDetails.ssh_action != None
        ).limit(limit).all()
    finally:
        db.close()
