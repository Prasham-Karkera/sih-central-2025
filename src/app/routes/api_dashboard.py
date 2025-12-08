"""
Dashboard API Routes
Provides overview statistics and metrics
"""
from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from datetime import datetime, timedelta

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from src.db.setup import SessionLocal
from src.db.models import Server, LogEntry, Alert, AlertRule
from sqlalchemy import func

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/overview")
async def get_overview() -> Dict[str, Any]:
    """Get dashboard overview statistics."""
    db = SessionLocal()
    try:
        # Basic counts
        total_servers = db.query(Server).count()
        total_logs = db.query(LogEntry).count()
        total_alerts = db.query(Alert).count()
        active_alerts = db.query(Alert).filter_by(resolved=False).count()
        
        # Logs by source
        logs_by_source = {}
        for source in ['linux', 'windows', 'nginx']:
            count = db.query(LogEntry).filter_by(log_source=source).count()
            logs_by_source[source] = count
        
        # Alerts by severity
        alerts_by_severity = {}
        alert_severity_query = db.query(Alert.severity, func.count()).group_by(Alert.severity).all()
        for severity, count in alert_severity_query:
            alerts_by_severity[severity] = count
        
        # Recent activity (last hour)
        one_hour_ago = datetime.now() - timedelta(hours=1)
        recent_logs = db.query(LogEntry).filter(LogEntry.recv_time >= one_hour_ago).count()
        recent_alerts = db.query(Alert).filter(Alert.triggered_at >= one_hour_ago).count()
        
        # Threat level calculation
        critical_count = alerts_by_severity.get('critical', 0)
        high_count = alerts_by_severity.get('high', 0)
        
        if critical_count > 5:
            threat_level = "critical"
        elif critical_count > 0 or high_count > 10:
            threat_level = "high"
        elif high_count > 0:
            threat_level = "medium"
        else:
            threat_level = "low"
        
        return {
            "servers": {
                "total": total_servers,
                "online": total_servers  # Simplified - all servers considered online
            },
            "logs": {
                "total": total_logs,
                "by_source": logs_by_source,
                "recent_hour": recent_logs
            },
            "alerts": {
                "total": total_alerts,
                "active": active_alerts,
                "resolved": total_alerts - active_alerts,
                "by_severity": alerts_by_severity,
                "recent_hour": recent_alerts
            },
            "threat_level": threat_level,
            "timestamp": datetime.now().isoformat()
        }
    finally:
        db.close()


@router.get("/timeline")
async def get_alert_timeline(hours: int = 24) -> Dict[str, Any]:
    """Get alert timeline for specified hours."""
    db = SessionLocal()
    try:
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        # Get alerts grouped by hour
        alerts = db.query(
            func.strftime('%Y-%m-%d %H:00:00', Alert.triggered_at).label('hour'),
            Alert.severity,
            func.count().label('count')
        ).filter(
            Alert.triggered_at >= cutoff_time
        ).group_by('hour', Alert.severity).all()
        
        # Organize by hour
        timeline = {}
        for hour, severity, count in alerts:
            if hour not in timeline:
                timeline[hour] = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
            timeline[hour][severity] = count
        
        return {
            "timeline": timeline,
            "period_hours": hours
        }
    finally:
        db.close()


@router.get("/top-threats")
async def get_top_threats(limit: int = 10) -> Dict[str, Any]:
    """Get top triggered alert rules."""
    db = SessionLocal()
    try:
        # Count alerts by rule title
        top_rules = db.query(
            Alert.title,
            Alert.severity,
            func.count().label('count')
        ).group_by(
            Alert.title, Alert.severity
        ).order_by(
            func.count().desc()
        ).limit(limit).all()
        
        threats = []
        for title, severity, count in top_rules:
            threats.append({
                "title": title,
                "severity": severity,
                "count": count
            })
        
        return {"threats": threats}
    finally:
        db.close()
