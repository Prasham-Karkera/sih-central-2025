"""
Alerts API Routes
Alert management and querying
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Dict, Any, List, Optional
from datetime import datetime
import json
import sys
from cryptography.fernet import Fernet
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from src.db.setup import SessionLocal
from src.db.models import Alert, Server, LogEntry
from src.db.repository.alert_repo import resolve_alert

router = APIRouter(prefix="/api/alerts", tags=["alerts"])


@router.get("/")
async def get_alerts(
    severity: Optional[str] = None,
    resolved: Optional[bool] = None,
    server_id: Optional[int] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0)
) -> Dict[str, Any]:
    """Get paginated alerts with filters."""
    db = SessionLocal()
    try:
        query = db.query(Alert, Server, LogEntry).join(
            Server, Alert.server_id == Server.id
        ).join(
            LogEntry, Alert.log_entry_id == LogEntry.id
        )
        
        # Apply filters
        if severity:
            query = query.filter(Alert.severity == severity)
        if resolved is not None:
            query = query.filter(Alert.resolved == resolved)
        if server_id:
            query = query.filter(Alert.server_id == server_id)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and order
        results = query.order_by(Alert.triggered_at.desc()).limit(limit).offset(offset).all()
        
        alerts = []
        for alert, server, log_entry in results:
            alerts.append({
                "id": alert.id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "resolved": bool(alert.resolved),
                "triggered_at": alert.triggered_at.isoformat() if alert.triggered_at else None,
                "server": {
                    "id": server.id,
                    "hostname": server.hostname,
                    "ip_address": server.ip_address
                },
                "log_source": log_entry.log_source,
                "metadata": json.loads(alert.alert_metadata) if alert.alert_metadata else None
            })
        
        return {
            "alerts": alerts,
            "total": total,
            "limit": limit,
            "offset": offset
        }
    finally:
        db.close()


@router.get("/{alert_id}")
async def get_alert_detail(alert_id: int) -> Dict[str, Any]:
    """Get detailed information about a specific alert."""
    db = SessionLocal()
    try:
        alert = db.query(Alert).filter_by(id=alert_id).first()
        if not alert:
            raise HTTPException(status_code=404, detail="Alert not found")
        
        server = db.query(Server).filter_by(id=alert.server_id).first()
        log_entry = db.query(LogEntry).filter_by(id=alert.log_entry_id).first()
        
        import json
        metadata = {}
        if alert.alert_metadata:
            try:
                metadata = json.loads(alert.alert_metadata)
            except:
                pass
        
        return {
            "id": alert.id,
            "title": alert.title,
            "description": alert.description,
            "severity": alert.severity,
            "resolved": bool(alert.resolved),
            "triggered_at": alert.triggered_at.isoformat() if alert.triggered_at else None,
            "server": {
                "id": server.id if server else None,
                "hostname": server.hostname if server else None,
                "ip_address": server.ip_address if server else None,
                "server_type": server.server_type if server else None
            },
            "log": {
                "id": log_entry.id if log_entry else None,
                "source": log_entry.log_source if log_entry else None,
                "content": log_entry.content if log_entry else None,
                "recv_time": log_entry.recv_time.isoformat() if log_entry and log_entry.recv_time else None
            },
            "metadata": metadata
        }
    finally:
        db.close()


@router.patch("/{alert_id}/resolve")
async def resolve_alert_endpoint(alert_id: int) -> Dict[str, Any]:
    """Mark an alert as resolved."""
    try:
        resolve_alert(alert_id)
        return {"success": True, "message": f"Alert {alert_id} resolved"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats/summary")
async def get_alert_stats() -> Dict[str, Any]:
    """Get alert statistics summary."""
    db = SessionLocal()
    try:
        from sqlalchemy import func
        
        # By severity
        by_severity = {}
        severity_query = db.query(Alert.severity, func.count()).group_by(Alert.severity).all()
        for severity, count in severity_query:
            by_severity[severity] = count
        
        # By source
        by_source = {}
        source_query = db.query(
            LogEntry.log_source,
            func.count(Alert.id)
        ).join(
            Alert, LogEntry.id == Alert.log_entry_id
        ).group_by(LogEntry.log_source).all()
        
        for source, count in source_query:
            by_source[source] = count
        
        # Active vs resolved
        total = db.query(Alert).count()
        active = db.query(Alert).filter_by(resolved=False).count()
        resolved = total - active
        
        return {
            "total": total,
            "active": active,
            "resolved": resolved,
            "by_severity": by_severity,
            "by_source": by_source
        }
    finally:
        db.close()


@router.get("/export/encrypted")
async def export_encrypted_alerts() -> Dict[str, Any]:
    """Export all alerts encrypted."""
    db = SessionLocal()
    try:
        # Fetch all alerts
        alerts_query = db.query(Alert).all()
        
        alerts_data = []
        for alert in alerts_query:
            alerts_data.append({
                "id": alert.id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "resolved": alert.resolved,
                "triggered_at": alert.triggered_at.isoformat() if alert.triggered_at else None,
                "metadata": alert.alert_metadata
            })
            
        json_data = json.dumps(alerts_data)
        
        # Generate Key
        key = Fernet.generate_key()
        f = Fernet(key)
        
        # Encrypt
        encrypted_data = f.encrypt(json_data.encode())
        
        return {
            "key": key.decode(),
            "encrypted_data": encrypted_data.decode()
        }
    finally:
        db.close()


from pydantic import BaseModel

class DecryptRequest(BaseModel):
    encrypted_data: str
    key: str

@router.post("/decrypt")
async def decrypt_alerts(request: DecryptRequest) -> Dict[str, Any]:
    """Decrypt alerts data."""
    try:
        f = Fernet(request.key.encode())
        decrypted_data = f.decrypt(request.encrypted_data.encode())
        alerts = json.loads(decrypted_data.decode())
        return {"success": True, "alerts": alerts}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption failed: {str(e)}")
