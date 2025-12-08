"""
Alert Rule Repository

Handles alert rule management.
"""

from typing import List, Optional
from src.db.setup import SessionLocal
from src.db.models import AlertRule


def get_active_rules_for_source(log_source: str) -> List[AlertRule]:
    """
    Get active rules for a specific log source.
    
    Args:
        log_source: Log source type (linux, windows, nginx)
        
    Returns:
        List of active rules
    """
    db = SessionLocal()
    try:
        # Get rules that match the source OR are global (log_source = None)
        rules = db.query(AlertRule).filter(
            AlertRule.enabled == 1,
            (AlertRule.log_source == log_source) | (AlertRule.log_source == None)
        ).all()
        return rules

    finally:
        db.close()


def get_all_rules() -> List[AlertRule]:
    """Get all rules (enabled and disabled)."""
    db = SessionLocal()
    try:
        return db.query(AlertRule).all()
    finally:
        db.close()


def get_rule_by_id(rule_id: int) -> Optional[AlertRule]:
    """Get a specific rule by ID."""
    db = SessionLocal()
    try:
        return db.query(AlertRule).filter_by(id=rule_id).first()
    finally:
        db.close()


def create_rule(
    name: str,
    severity: str,
    rule_content: str,
    log_source: Optional[str] = None,
    enabled: bool = True
) -> int:
    """
    Create a new alert rule.
    
    Args:
        name: Rule name
        severity: Severity level
        rule_content: Rule definition (YAML/JSON)
        log_source: Target log source (None = all sources)
        enabled: Whether rule is enabled
        
    Returns:
        Rule ID
    """
    db = SessionLocal()
    try:
        rule = AlertRule(
            name=name,
            log_source=log_source,
            severity=severity,
            enabled=1 if enabled else 0,
            rule_content=rule_content
        )
        db.add(rule)
        db.commit()
        db.refresh(rule)
        return rule.id
    finally:
        db.close()


def toggle_rule(rule_id: int, enabled: bool) -> bool:
    """
    Enable or disable a rule.
    
    Args:
        rule_id: ID of the rule
        enabled: New enabled state
        
    Returns:
        True if successful, False if rule not found
    """
    db = SessionLocal()
    try:
        rule = db.query(AlertRule).filter_by(id=rule_id).first()
        
        if rule:
            rule.enabled = 1 if enabled else 0
            db.commit()
            return True
        return False
    finally:
        db.close()


def delete_rule(rule_id: int) -> bool:
    """
    Delete a rule.
    
    Args:
        rule_id: ID of the rule to delete
        
    Returns:
        True if successful, False if rule not found
    """
    db = SessionLocal()
    try:
        rule = db.query(AlertRule).filter_by(id=rule_id).first()
        
        if rule:
            db.delete(rule)
            db.commit()
            return True
        return False
    finally:
        db.close()
