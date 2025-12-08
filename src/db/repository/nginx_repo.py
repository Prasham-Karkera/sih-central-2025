"""
Nginx Log Details Repository

Handles parsed Nginx log details.
"""

from typing import Dict, Any, Optional
from src.db.setup import SessionLocal
from src.db.models import NginxLogDetails


def insert_nginx_details(log_entry_id: int, parsed: Dict[str, Any]) -> None:
    """
    Insert parsed Nginx log details.
    
    Args:
        log_entry_id: ID of the parent log entry
        parsed: Dictionary containing parsed fields
    """
    db = SessionLocal()
    try:
        details = NginxLogDetails(
            log_entry_id=log_entry_id,
            remote_addr=parsed.get("remote_addr"),
            remote_user=parsed.get("remote_user"),
            time_local=parsed.get("time_local"),
            request_method=parsed.get("request_method"),
            request_uri=parsed.get("request_uri"),
            status=parsed.get("status"),
            body_bytes_sent=parsed.get("body_bytes_sent"),
            http_referer=parsed.get("http_referer"),
            http_user_agent=parsed.get("http_user_agent"),
        )

        db.add(details)
        db.commit()

    finally:
        db.close()


def get_nginx_details(log_entry_id: int) -> Optional[NginxLogDetails]:
    """Get Nginx log details for a specific log entry."""
    db = SessionLocal()
    try:
        return db.query(NginxLogDetails).filter_by(
            log_entry_id=log_entry_id
        ).first()
    finally:
        db.close()


def get_error_requests(limit: int = 100):
    """Get requests with error status codes (4xx, 5xx)."""
    db = SessionLocal()
    try:
        return db.query(NginxLogDetails).filter(
            NginxLogDetails.status >= 400
        ).limit(limit).all()
    finally:
        db.close()


def get_requests_by_ip(ip_address: str, limit: int = 100):
    """Get requests from a specific IP address."""
    db = SessionLocal()
    try:
        return db.query(NginxLogDetails).filter(
            NginxLogDetails.remote_addr == ip_address
        ).limit(limit).all()
    finally:
        db.close()
