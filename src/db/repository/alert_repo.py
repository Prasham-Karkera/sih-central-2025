"""
Alert Repository

Handles alert creation and management.
"""

import json
from typing import Dict, Any, List, Optional
from src.db.setup import SessionLocal
from src.db.models import Alert


def create_alert(
    log_entry_id: int,
    server_id: int,
    rule_id: int,
    severity: str,
    title: str,
    description: str,
    metadata: Dict[str, Any]
) -> int:
    """
    Create a new alert.
    
    Args:
        log_entry_id: ID of the log that triggered the alert
        server_id: ID of the server
        rule_id: ID of the rule that was triggered
        severity: Alert severity (low, medium, high, critical)
        title: Alert title
        description: Alert description
        metadata: Additional metadata as dictionary
        
    Returns:
        Alert ID
    """
    db = SessionLocal()
    try:
        alert = Alert(
            log_entry_id=log_entry_id,
            server_id=server_id,
            rule_id=rule_id,
            severity=severity,
            title=title,
            description=description,
            alert_metadata=json.dumps(metadata)  # Use alert_metadata
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert.id

    finally:
        db.close()


def get_recent_alerts(
    limit: int = 100,
    severity: Optional[str] = None,
    resolved: Optional[bool] = None
) -> List[Alert]:
    """
    Get recent alerts with optional filtering.
    
    Args:
        limit: Maximum number of alerts
        severity: Filter by severity
        resolved: Filter by resolved status (None = all, True = resolved, False = active)
        
    Returns:
        List of alerts
    """
    db = SessionLocal()
    try:
        query = db.query(Alert)
        
        if severity:
            query = query.filter(Alert.severity == severity)
            
        if resolved is not None:
            query = query.filter(Alert.resolved == (1 if resolved else 0))
            
        return query.order_by(Alert.triggered_at.desc()).limit(limit).all()
        
    finally:
        db.close()


def resolve_alert(alert_id: int) -> bool:
    """
    Mark an alert as resolved.
    
    Args:
        alert_id: ID of the alert to resolve
        
    Returns:
        True if successful, False if alert not found
    """
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter_by(id=alert_id).first()
        
        if alert:
            alert.resolved = 1
            db.commit()
            return True
        return False
        
    finally:
        db.close()


def get_alerts_by_server(server_id: int, limit: int = 100) -> List[Alert]:
    """Get alerts for a specific server."""
    db = SessionLocal()
    try:
        return db.query(Alert).filter(
            Alert.server_id == server_id
        ).order_by(Alert.triggered_at.desc()).limit(limit).all()
    finally:
        db.close()


def get_critical_alerts(limit: int = 50) -> List[Alert]:
    """Get unresolved critical alerts."""
    db = SessionLocal()
    try:
        return db.query(Alert).filter(
            Alert.severity == "critical",
            Alert.resolved == 0
        ).order_by(Alert.triggered_at.desc()).limit(limit).all()
    finally:
        db.close()
