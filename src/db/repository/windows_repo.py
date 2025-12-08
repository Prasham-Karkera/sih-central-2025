"""
Windows Log Details Repository

Handles parsed Windows log details.
"""

import json
from typing import Dict, Any, Optional
from src.db.setup import SessionLocal
from src.db.models import WindowsLogDetails


def insert_windows_details(log_entry_id: int, event_json: Dict[str, Any]) -> None:
    """
    Insert parsed Windows log details.
    
    Args:
        log_entry_id: ID of the parent log entry
        event_json: Dictionary containing Windows event data
    """
    db = SessionLocal()
    try:
        details = WindowsLogDetails(
            log_entry_id=log_entry_id,
            content=json.dumps(event_json)
        )
        db.add(details)
        db.commit()

    finally:
        db.close()


def get_windows_details(log_entry_id: int) -> Optional[Dict[str, Any]]:
    """
    Get Windows log details for a specific log entry.
    
    Returns:
        Parsed JSON content or None
    """
    db = SessionLocal()
    try:
        details = db.query(WindowsLogDetails).filter_by(
            log_entry_id=log_entry_id
        ).first()
        
        if details:
            return json.loads(details.content)
        return None
    finally:
        db.close()


def get_windows_events_by_id(event_id: int, limit: int = 50):
    """Get Windows events by Event ID."""
    db = SessionLocal()
    try:
        details = db.query(WindowsLogDetails).limit(limit).all()
        
        # Filter by event ID in JSON content
        results = []
        for detail in details:
            content = json.loads(detail.content)
            if content.get("EventID") == event_id:
                results.append(detail)
                
        return results
    finally:
        db.close()
