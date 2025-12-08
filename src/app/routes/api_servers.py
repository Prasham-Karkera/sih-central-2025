"""
Servers API Routes
Server information and stats with device discovery features
"""
from fastapi import APIRouter, HTTPException, Query
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from src.db.setup import SessionLocal
from src.db.models import Server, LogEntry, Alert
from sqlalchemy import func, or_, and_, desc

router = APIRouter(prefix="/api/servers", tags=["servers"])


@router.get("/")
async def get_servers(
    search: Optional[str] = Query(None, description="Search by hostname or IP address"),
    server_type: Optional[str] = Query(None, description="Filter by server type (linux, windows, nginx)"),
    status: Optional[str] = Query(None, description="Filter by status (online, offline)"),
    limit: int = Query(50, ge=1, le=200, description="Number of servers to return"),
    offset: int = Query(0, ge=0, description="Number of servers to skip")
) -> Dict[str, Any]:
    """
    Get all servers with statistics, search, and filtering.
    
    - **search**: Search servers by hostname or IP address
    - **server_type**: Filter by server type (linux, windows, nginx)
    - **status**: Filter by online (active in last 5 min) or offline status
    - **limit**: Maximum number of results (1-200)
    - **offset**: Pagination offset
    """
    db = SessionLocal()
    try:
        # Build query
        query = db.query(Server)
        
        # Apply search filter
        if search:
            query = query.filter(
                or_(
                    Server.hostname.ilike(f"%{search}%"),
                    Server.ip_address.ilike(f"%{search}%")
                )
            )
        
        # Apply server type filter
        if server_type:
            query = query.filter(Server.server_type == server_type.lower())
        
        # Get total count before pagination
        total = query.count()
        
        # Apply pagination
        servers = query.offset(offset).limit(limit).all()
        
        # Calculate online threshold (5 minutes ago)
        online_threshold = datetime.utcnow() - timedelta(minutes=5)
        
        server_list = []
        for server in servers:
            # Get stats
            log_count = db.query(LogEntry).filter_by(server_id=server.id).count()
            alert_count = db.query(Alert).filter_by(server_id=server.id).count()
            active_alerts = db.query(Alert).filter_by(server_id=server.id, resolved=False).count()
            
            # Recent log to determine online status
            recent_log = db.query(LogEntry).filter_by(server_id=server.id).order_by(LogEntry.recv_time.desc()).first()
            
            # Determine if server is online
            is_online = False
            last_seen = None
            if recent_log and recent_log.recv_time:
                last_seen = recent_log.recv_time.isoformat()
                is_online = recent_log.recv_time >= online_threshold
            
            # Apply status filter
            if status:
                if status.lower() == "online" and not is_online:
                    continue
                if status.lower() == "offline" and is_online:
                    continue
            
            server_list.append({
                "id": server.id,
                "hostname": server.hostname,
                "ip_address": server.ip_address,
                "server_type": server.server_type,
                "status": "online" if is_online else "offline",
                "stats": {
                    "total_logs": log_count,
                    "total_alerts": alert_count,
                    "active_alerts": active_alerts,
                    "last_seen": last_seen
                }
            })
        
        return {
            "servers": server_list,
            "total": len(server_list),
            "total_available": total,
            "limit": limit,
            "offset": offset
        }
    finally:
        db.close()


@router.get("/stats")
async def get_servers_stats() -> Dict[str, Any]:
    """
    Get overall server statistics across all devices.
    
    Returns:
    - Total servers count
    - Servers by type breakdown
    - Online/offline status counts
    - Total logs and alerts
    """
    db = SessionLocal()
    try:
        # Total servers
        total_servers = db.query(Server).count()
        
        # Servers by type
        servers_by_type = {}
        type_query = db.query(Server.server_type, func.count()).group_by(Server.server_type).all()
        for server_type, count in type_query:
            servers_by_type[server_type] = count
        
        # Online/offline count
        online_threshold = datetime.utcnow() - timedelta(minutes=5)
        online_count = 0
        offline_count = 0
        
        servers = db.query(Server).all()
        for server in servers:
            recent_log = db.query(LogEntry).filter_by(server_id=server.id).order_by(LogEntry.recv_time.desc()).first()
            if recent_log and recent_log.recv_time and recent_log.recv_time >= online_threshold:
                online_count += 1
            else:
                offline_count += 1
        
        # Total logs and alerts
        total_logs = db.query(LogEntry).count()
        total_alerts = db.query(Alert).count()
        active_alerts = db.query(Alert).filter_by(resolved=False).count()
        
        return {
            "total_servers": total_servers,
            "servers_by_type": servers_by_type,
            "status": {
                "online": online_count,
                "offline": offline_count
            },
            "logs": {
                "total": total_logs,
                "alerts": total_alerts,
                "active_alerts": active_alerts
            }
        }
    finally:
        db.close()


@router.get("/{server_id}")
async def get_server_detail(server_id: int) -> Dict[str, Any]:
    """
    Get detailed server information including comprehensive statistics.
    
    - **server_id**: The unique identifier of the server
    
    Returns detailed server info with stats, log sources, and recent activity.
    """
    db = SessionLocal()
    try:
        server = db.query(Server).filter_by(id=server_id).first()
        if not server:
            raise HTTPException(status_code=404, detail="Server not found")
        
        # Get stats
        total_logs = db.query(LogEntry).filter_by(server_id=server_id).count()
        total_alerts = db.query(Alert).filter_by(server_id=server_id).count()
        active_alerts = db.query(Alert).filter_by(server_id=server_id, resolved=False).count()
        resolved_alerts = db.query(Alert).filter_by(server_id=server_id, resolved=True).count()
        
        # Logs by source
        logs_by_source = {}
        source_query = db.query(LogEntry.log_source, func.count()).filter_by(server_id=server_id).group_by(LogEntry.log_source).all()
        for source, count in source_query:
            logs_by_source[source] = count
        
        # Alerts by severity
        alerts_by_severity = {}
        severity_query = db.query(Alert.severity, func.count()).filter_by(server_id=server_id).group_by(Alert.severity).all()
        for severity, count in severity_query:
            alerts_by_severity[severity] = count
        
        # Recent logs (extended to 20)
        recent_logs = db.query(LogEntry).filter_by(server_id=server_id).order_by(LogEntry.recv_time.desc()).limit(20).all()
        logs = []
        for log in recent_logs:
            logs.append({
                "id": log.id,
                "source": log.log_source,
                "content": log.content[:150] + "..." if len(log.content) > 150 else log.content,
                "recv_time": log.recv_time.isoformat() if log.recv_time else None
            })
        
        # Recent alerts (extended to 10)
        recent_alerts = db.query(Alert).filter_by(server_id=server_id).order_by(Alert.triggered_at.desc()).limit(10).all()
        alerts = []
        for alert in recent_alerts:
            alerts.append({
                "id": alert.id,
                "title": alert.title,
                "severity": alert.severity,
                "description": alert.description[:200] + "..." if alert.description and len(alert.description) > 200 else alert.description,
                "resolved": bool(alert.resolved),
                "triggered_at": alert.triggered_at.isoformat() if alert.triggered_at else None
            })
        
        # Calculate online status
        online_threshold = datetime.utcnow() - timedelta(minutes=5)
        recent_log = db.query(LogEntry).filter_by(server_id=server_id).order_by(LogEntry.recv_time.desc()).first()
        is_online = False
        last_seen = None
        if recent_log and recent_log.recv_time:
            last_seen = recent_log.recv_time.isoformat()
            is_online = recent_log.recv_time >= online_threshold
        
        return {
            "server": {
                "id": server.id,
                "hostname": server.hostname,
                "ip_address": server.ip_address,
                "server_type": server.server_type,
                "status": "online" if is_online else "offline",
                "last_seen": last_seen
            },
            "stats": {
                "total_logs": total_logs,
                "total_alerts": total_alerts,
                "active_alerts": active_alerts,
                "resolved_alerts": resolved_alerts,
                "logs_by_source": logs_by_source,
                "alerts_by_severity": alerts_by_severity
            },
            "recent_logs": logs,
            "recent_alerts": alerts
        }
    finally:
        db.close()


@router.get("/{server_id}/logs")
async def get_server_logs(
    server_id: int,
    log_source: Optional[str] = Query(None, description="Filter by log source"),
    hours: Optional[int] = Query(None, ge=1, le=168, description="Filter logs from last N hours (max 7 days)"),
    limit: int = Query(100, ge=1, le=500, description="Number of logs to return"),
    offset: int = Query(0, ge=0, description="Number of logs to skip")
) -> Dict[str, Any]:
    """
    Get logs for a specific server with filtering options.
    
    - **server_id**: The unique identifier of the server
    - **log_source**: Filter by specific log source
    - **hours**: Get logs from last N hours (1-168)
    - **limit**: Maximum number of results (1-500)
    - **offset**: Pagination offset
    """
    db = SessionLocal()
    try:
        # Verify server exists
        server = db.query(Server).filter_by(id=server_id).first()
        if not server:
            raise HTTPException(status_code=404, detail="Server not found")
        
        # Build query
        query = db.query(LogEntry).filter_by(server_id=server_id)
        
        # Apply log source filter
        if log_source:
            query = query.filter(LogEntry.log_source == log_source)
        
        # Apply time filter
        if hours:
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            query = query.filter(LogEntry.recv_time >= time_threshold)
        
        # Order by most recent
        query = query.order_by(LogEntry.recv_time.desc())
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        logs = query.offset(offset).limit(limit).all()
        
        log_list = []
        for log in logs:
            log_list.append({
                "id": log.id,
                "source": log.log_source,
                "content": log.content,
                "recv_time": log.recv_time.isoformat() if log.recv_time else None
            })
        
        return {
            "logs": log_list,
            "total": total,
            "limit": limit,
            "offset": offset,
            "server": {
                "id": server.id,
                "hostname": server.hostname,
                "ip_address": server.ip_address
            }
        }
    finally:
        db.close()


@router.get("/{server_id}/alerts")
async def get_server_alerts(
    server_id: int,
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low, info)"),
    resolved: Optional[bool] = Query(None, description="Filter by resolved status"),
    hours: Optional[int] = Query(None, ge=1, le=168, description="Filter alerts from last N hours (max 7 days)"),
    limit: int = Query(50, ge=1, le=200, description="Number of alerts to return"),
    offset: int = Query(0, ge=0, description="Number of alerts to skip")
) -> Dict[str, Any]:
    """
    Get alerts for a specific server with filtering options.
    
    - **server_id**: The unique identifier of the server
    - **severity**: Filter by severity level
    - **resolved**: Filter by resolved status (true/false)
    - **hours**: Get alerts from last N hours (1-168)
    - **limit**: Maximum number of results (1-200)
    - **offset**: Pagination offset
    """
    db = SessionLocal()
    try:
        # Verify server exists
        server = db.query(Server).filter_by(id=server_id).first()
        if not server:
            raise HTTPException(status_code=404, detail="Server not found")
        
        # Build query
        query = db.query(Alert).filter_by(server_id=server_id)
        
        # Apply severity filter
        if severity:
            query = query.filter(Alert.severity == severity.lower())
        
        # Apply resolved filter
        if resolved is not None:
            query = query.filter(Alert.resolved == resolved)
        
        # Apply time filter
        if hours:
            time_threshold = datetime.utcnow() - timedelta(hours=hours)
            query = query.filter(Alert.triggered_at >= time_threshold)
        
        # Order by most recent
        query = query.order_by(Alert.triggered_at.desc())
        
        # Get total count
        total = query.count()
        
        # Apply pagination
        alerts = query.offset(offset).limit(limit).all()
        
        alert_list = []
        for alert in alerts:
            alert_list.append({
                "id": alert.id,
                "title": alert.title,
                "description": alert.description,
                "severity": alert.severity,
                "resolved": bool(alert.resolved),
                "triggered_at": alert.triggered_at.isoformat() if alert.triggered_at else None,
                "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at else None
            })
        
        return {
            "alerts": alert_list,
            "total": total,
            "limit": limit,
            "offset": offset,
            "server": {
                "id": server.id,
                "hostname": server.hostname,
                "ip_address": server.ip_address
            }
        }
    finally:
        db.close()


@router.get("/{server_id}/timeline")
async def get_server_timeline(
    server_id: int,
    hours: int = Query(24, ge=1, le=168, description="Timeline range in hours (1-168, default 24)")
) -> Dict[str, Any]:
    """
    Get timeline data for a server showing activity over time.
    
    - **server_id**: The unique identifier of the server
    - **hours**: Time range for timeline in hours (1-168)
    
    Returns hourly breakdown of logs and alerts for visualization.
    """
    db = SessionLocal()
    try:
        # Verify server exists
        server = db.query(Server).filter_by(id=server_id).first()
        if not server:
            raise HTTPException(status_code=404, detail="Server not found")
        
        # Calculate time threshold
        time_threshold = datetime.utcnow() - timedelta(hours=hours)
        
        # Get logs grouped by hour
        logs_query = db.query(
            func.strftime('%Y-%m-%d %H:00:00', LogEntry.recv_time).label('hour'),
            func.count().label('count')
        ).filter(
            and_(
                LogEntry.server_id == server_id,
                LogEntry.recv_time >= time_threshold
            )
        ).group_by('hour').order_by('hour').all()
        
        # Get alerts grouped by hour
        alerts_query = db.query(
            func.strftime('%Y-%m-%d %H:00:00', Alert.triggered_at).label('hour'),
            func.count().label('count')
        ).filter(
            and_(
                Alert.server_id == server_id,
                Alert.triggered_at >= time_threshold
            )
        ).group_by('hour').order_by('hour').all()
        
        # Format timeline data
        timeline = []
        log_dict = {hour: count for hour, count in logs_query}
        alert_dict = {hour: count for hour, count in alerts_query}
        
        # Get all hours in range
        current_time = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
        for i in range(hours):
            hour_time = current_time - timedelta(hours=i)
            hour_str = hour_time.strftime('%Y-%m-%d %H:00:00')
            
            timeline.append({
                "timestamp": hour_time.isoformat(),
                "logs": log_dict.get(hour_str, 0),
                "alerts": alert_dict.get(hour_str, 0)
            })
        
        # Reverse to get chronological order
        timeline.reverse()
        
        return {
            "timeline": timeline,
            "hours": hours,
            "server": {
                "id": server.id,
                "hostname": server.hostname,
                "ip_address": server.ip_address
            }
        }
    finally:
        db.close()
