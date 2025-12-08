"""
Server Repository

Handles server registration and retrieval.
"""

from src.db.setup import SessionLocal
from src.db.models import Server


def get_or_create_server(hostname: str, ip: str, server_type: str) -> int:
    """
    Get existing server or create new one.
    
    Args:
        hostname: Server hostname
        ip: IP address
        server_type: Type of server (linux, windows, nginx, etc.)
        
    Returns:
        Server ID
    """
    db = SessionLocal()
    try:
        # Check if server exists
        server = db.query(Server).filter_by(
            hostname=hostname,
            ip_address=ip,
            server_type=server_type
        ).first()

        if server:
            return server.id

        # Create new server
        server = Server(
            hostname=hostname,
            ip_address=ip,
            server_type=server_type
        )
        db.add(server)
        db.commit()
        db.refresh(server)
        return server.id

    finally:
        db.close()


def get_server_by_id(server_id: int):
    """Get server by ID."""
    db = SessionLocal()
    try:
        return db.query(Server).filter_by(id=server_id).first()
    finally:
        db.close()


def get_all_servers():
    """Get all registered servers."""
    db = SessionLocal()
    try:
        return db.query(Server).all()
    finally:
        db.close()
