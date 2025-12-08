"""
Logs API Routes
Log querying and search
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Dict, Any, List, Optional
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from src.db.setup import SessionLocal
from src.db.models import LogEntry, Server

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.get("/")
async def get_logs(
    source: Optional[str] = None,
    server_id: Optional[int] = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0)
) -> Dict[str, Any]:
    """Get paginated logs with filters."""
    db = SessionLocal()
    try:
        query = db.query(LogEntry, Server).join(Server, LogEntry.server_id == Server.id)
        
        # Apply filters
        if source:
            query = query.filter(LogEntry.log_source == source)
        if server_id:
            query = query.filter(LogEntry.server_id == server_id)
        
        # Get total
        total = query.count()
        
        # Paginate
        results = query.order_by(LogEntry.recv_time.desc()).limit(limit).offset(offset).all()
        
        logs = []
        for log_entry, server in results:
            print(log_entry.log_source)
            if log_entry.log_source == 'linux':
                logs.append({
                    "id": log_entry.id,
                    "source": log_entry.log_source,
                    "content": log_entry.content,
                    "recv_time": log_entry.recv_time.isoformat() if log_entry.recv_time else None,
                    "server": {
                        "id": server.id,
                        "hostname": server.hostname,
                        "ip_address": server.ip_address
                    }
                    
                })
            else:
                logs.append({
                    "id": log_entry.id,
                    "source": log_entry.log_source,
                    "content": json.loads(log_entry.content) if log_entry.content else log_entry.content,
                    "recv_time": log_entry.recv_time.isoformat() if log_entry.recv_time else None,
                    "server": {
                        "id": server.id,
                        "hostname": server.hostname,
                        "ip_address": server.ip_address
                    }
                })
        
        return {
            "logs": logs,
            "total": total,
            "limit": limit,
            "offset": offset
        }
    finally:
        db.close()


@router.get("/{log_id}")
async def get_log_detail(log_id: int) -> Dict[str, Any]:
    """Get detailed log information."""
    db = SessionLocal()
    try:
        log_entry = db.query(LogEntry).filter_by(id=log_id).first()
        if not log_entry:
            raise HTTPException(status_code=404, detail="Log not found")
        
        server = db.query(Server).filter_by(id=log_entry.server_id).first()
        
        # Get type-specific details
        details = None
        if log_entry.log_source == 'linux':
            from src.db.models import LinuxLogDetails
            linux_details = db.query(LinuxLogDetails).filter_by(log_entry_id=log_id).first()
            if linux_details:
                details = {
                    "app_name": linux_details.app_name,
                    "pid": linux_details.pid,
                    "raw_message": linux_details.raw_message,
                    "ssh_action": linux_details.ssh_action,
                    "ssh_user": linux_details.ssh_user,
                    "ssh_ip": linux_details.ssh_ip
                }
        
        elif log_entry.log_source == 'windows':
            from src.db.models import WindowsLogDetails
            windows_details = db.query(WindowsLogDetails).filter_by(log_entry_id=log_id).first()
            if windows_details:
                details = {
                    "content": windows_details.content
                }
        
        elif log_entry.log_source == 'nginx':
            from src.db.models import NginxLogDetails
            nginx_details = db.query(NginxLogDetails).filter_by(log_entry_id=log_id).first()
            if nginx_details:
                details = {
                    "remote_addr": nginx_details.remote_addr,
                    "request_method": nginx_details.request_method,
                    "request_uri": nginx_details.request_uri,
                    "status": nginx_details.status,
                    "body_bytes_sent": nginx_details.body_bytes_sent,
                    "http_user_agent": nginx_details.http_user_agent
                }
        
        return {
            "id": log_entry.id,
            "source": log_entry.log_source,
            "content": log_entry.content,
            "recv_time": log_entry.recv_time.isoformat() if log_entry.recv_time else None,
            "server": {
                "id": server.id if server else None,
                "hostname": server.hostname if server else None,
                "ip_address": server.ip_address if server else None
            },
            "details": details
        }
    finally:
        db.close()


@router.get("/search")
async def search_logs(
    q: str = Query(..., min_length=1),
    source: Optional[str] = None,
    limit: int = Query(50, ge=1, le=500)
) -> Dict[str, Any]:
    """Search logs by content."""
    db = SessionLocal()
    try:
        query = db.query(LogEntry, Server).join(Server, LogEntry.server_id == Server.id)
        
        # Search in content
        query = query.filter(LogEntry.content.like(f"%{q}%"))
        
        if source:
            query = query.filter(LogEntry.log_source == source)
        
        total = query.count()
        results = query.order_by(LogEntry.recv_time.desc()).limit(limit).all()
        
        logs = []
        for log_entry, server in results:
            logs.append({
                "id": log_entry.id,
                "source": log_entry.log_source,
                "content": log_entry.content[:200] + "..." if len(log_entry.content) > 200 else log_entry.content,
                "recv_time": log_entry.recv_time.isoformat() if log_entry.recv_time else None,
                "server": {
                    "id": server.id,
                    "hostname": server.hostname,
                    "ip_address": server.ip_address
                }
            })
        
        return {
            "logs": logs,
            "total": total,
            "query": q
        }
    finally:
        db.close()
