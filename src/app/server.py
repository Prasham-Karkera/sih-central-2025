"""
FastAPI Server for SIEM Dashboard

Main server handling all API endpoints and WebSocket connections.
"""
import asyncio
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.db.setup import SessionLocal
from src.db.models import Server, LogEntry, Alert
from fastapi.templating import Jinja2Templates

# Import API routes
from src.app.routes import api_dashboard, api_alerts, api_logs, api_servers, api_sigma, api_tasks

# === Configuration ===
DB_PATH = "./ironchad_logs.db"
STATIC_DIR = Path(__file__).parent / "static"
ASSETS_DIR = Path(__file__).parent / "assets"
TEMPLATES_DIR = Path(__file__).parent / "templates"
SIGMA_RULES_DIR = "./Sigma_Rules"

# === Pydantic Models ===
class StatsResponse(BaseModel):
    total_logs: int
    total_servers: int
    total_alerts: int
    by_type: Dict[str, int]
    uptime: float

class AlertsResponse(BaseModel):
    alerts: List[Dict[str, Any]]
    count: int

class ServerDetailResponse(BaseModel):
    server: Dict[str, Any]
    recent_logs: List[Dict[str, Any]]
    alerts: List[Dict[str, Any]]
    stats: Dict[str, Any]

# === WebSocket Manager ===
class ConnectionManager:
    def __init__(self):
        self.active_connections: set = set()
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
        print(f"[WebSocket] Client connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
        print(f"[WebSocket] Client disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, message: Dict[str, Any]):
        if not self.active_connections:
            return
        
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.add(connection)
        
        self.active_connections -= disconnected

# === FastAPI App ===
app = FastAPI(title="Ironclad SIEM Dashboard", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Global State ===
ws_manager: ConnectionManager = ConnectionManager()
start_time: datetime = None
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# === Startup/Shutdown ===
@app.on_event("startup")
async def startup_event():
    global start_time
    
    start_time = datetime.now()
    print(f"[Server] Starting Ironclad SIEM Dashboard")
    
    # Create directories
    STATIC_DIR.mkdir(exist_ok=True, parents=True)
    TEMPLATES_DIR.mkdir(exist_ok=True, parents=True)
    
    # Start all background tasks
    await api_tasks.start_all_workers()
    
    print("[Server] All systems ready. Access dashboard at http://localhost:8000")

@app.on_event("shutdown")
async def shutdown_event():
    # Stop all background tasks gracefully
    await api_tasks.stop_all_workers()
    
    print("[Server] Shutdown complete")

# === Include API Routers ===
app.include_router(api_dashboard.router)
app.include_router(api_alerts.router)
app.include_router(api_logs.router)
app.include_router(api_servers.router)
app.include_router(api_sigma.router)
app.include_router(api_tasks.router)

# === Static Files ===
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
if ASSETS_DIR.exists():
    app.mount("/assets", StaticFiles(directory=str(ASSETS_DIR)), name="assets")

# === Routes ===
# === Template Routes ===
@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Serve main dashboard."""
    return FileResponse(Path(__file__).parent / "index.html")

@app.get("/servers", response_class=HTMLResponse)
async def servers_page(request: Request):
    """Serve servers page."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    """Serve alerts page."""
    # For now, redirect to dashboard until alerts.html is created
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/logs", response_class=HTMLResponse)
async def logs_page(request: Request):
    """Serve logs page."""
    # For now, redirect to dashboard until logs.html is created
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/health")
async def health():
    """Health check."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "ingestion_task": "running" if api_tasks.task_state.ingestion_running else "stopped",
        "sigma_task": "running" if api_tasks.task_state.sigma_running else "stopped",
        "parser_task": "running" if api_tasks.task_state.parser_running else "stopped"
    }

@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    """Get system statistics."""
    db = SessionLocal()
    try:
        from sqlalchemy import func
        
        total_logs = db.query(func.count(LogEntry.id)).scalar() or 0
        total_servers = db.query(func.count(Server.id)).scalar() or 0
        total_alerts = db.query(func.count(Alert.id)).scalar() or 0
        
        by_type = {}
        for log_source, count in db.query(LogEntry.log_source, func.count(LogEntry.id)).group_by(LogEntry.log_source).all():
            by_type[log_source] = count
        
        uptime = (datetime.now() - start_time).total_seconds()
        
        return StatsResponse(
            total_logs=total_logs,
            total_servers=total_servers,
            total_alerts=total_alerts,
            by_type=by_type,
            uptime=uptime
        )
    finally:
        db.close()

@app.get("/api/servers")
async def get_servers():
    """Get all servers with dummy data for demonstration."""
    
    # Generate realistic dummy data
    dummy_servers = [
        {
            "id": 1,
            "hostname": "web-server-01",
            "ip_address": "192.168.1.100",
            "status": "online",
            "log_count": 1523,
            "alert_count": 3,
            "last_log_time": datetime.now().isoformat(),
            "first_seen": (datetime.now() - timedelta(days=30)).isoformat(),
            "last_seen": datetime.now().isoformat()
        },
        {
            "id": 2,
            "hostname": "dc-server-01",
            "ip_address": "192.168.1.10",
            "status": "online",
            "log_count": 5087,
            "alert_count": 12,
            "last_log_time": datetime.now().isoformat(),
            "first_seen": (datetime.now() - timedelta(days=60)).isoformat(),
            "last_seen": datetime.now().isoformat()
        },
        {
            "id": 3,
            "hostname": "ubuntu-server-01",
            "ip_address": "192.168.1.50",
            "status": "online",
            "log_count": 892,
            "alert_count": 1,
            "last_log_time": datetime.now().isoformat(),
            "first_seen": (datetime.now() - timedelta(days=45)).isoformat(),
            "last_seen": datetime.now().isoformat()
        },
        {
            "id": 4,
            "hostname": "app-server-02",
            "ip_address": "192.168.1.110",
            "status": "delayed",
            "log_count": 2341,
            "alert_count": 7,
            "last_log_time": (datetime.now() - timedelta(minutes=15)).isoformat(),
            "first_seen": (datetime.now() - timedelta(days=20)).isoformat(),
            "last_seen": (datetime.now() - timedelta(minutes=15)).isoformat()
        },
        {
            "id": 5,
            "hostname": "win-workstation-03",
            "ip_address": "192.168.1.45",
            "status": "offline",
            "log_count": 156,
            "alert_count": 0,
            "last_log_time": (datetime.now() - timedelta(hours=2)).isoformat(),
            "first_seen": (datetime.now() - timedelta(days=10)).isoformat(),
            "last_seen": (datetime.now() - timedelta(hours=2)).isoformat()
        },
        {
            "id": 6,
            "hostname": "db-server-01",
            "ip_address": "192.168.1.20",
            "status": "online",
            "log_count": 3421,
            "alert_count": 5,
            "last_log_time": datetime.now().isoformat(),
            "first_seen": (datetime.now() - timedelta(days=90)).isoformat(),
            "last_seen": datetime.now().isoformat()
        }
    ]
    
    return {"servers": dummy_servers, "count": len(dummy_servers)}

@app.get("/api/servers/{server_id}", response_model=ServerDetailResponse)
async def get_server_detail(server_id: int):
    """Get detailed information for a specific server with dummy data."""
    
    # Generate detailed dummy data based on server_id
    server_types = ["nginx", "windows", "linux"]
    server_type = server_types[server_id % 3]
    
    dummy_detail = {
        "id": server_id,
        "hostname": f"server-{server_id:02d}",
        "ip_address": f"192.168.1.{100 + server_id}",
        "status": "online" if server_id <= 3 else ("delayed" if server_id == 4 else "offline"),
        "log_count": 1000 + (server_id * 500),
        "alert_count": server_id * 2,
        "last_log_time": datetime.now().isoformat(),
        "stats": {
            "total_logs": 1000 + (server_id * 500),
            "alerts_count": server_id * 2,
            "log_types": {
                "info": 800 + (server_id * 300),
                "warning": 150 + (server_id * 50),
                "error": 50 + (server_id * 10)
            },
            "last_seen": datetime.now().isoformat(),
            "status": "online" if server_id <= 3 else "delayed",
            "uptime": "30d 12h 45m",
            "cpu_usage": 45.2 + (server_id * 5),
            "memory_usage": 60.5 + (server_id * 3),
            "disk_usage": 55.0 + (server_id * 2)
        },
        "recent_logs": [
            {
                "id": i,
                "timestamp": (datetime.now() - timedelta(minutes=i*5)).isoformat(),
                "log_type": server_type,
                "raw_line": f"Sample log entry {i} from {server_type} server",
                "hostname": f"server-{server_id:02d}",
                "ip_address": f"192.168.1.{100 + server_id}"
            }
            for i in range(1, 11)
        ],
        "alerts": [
            {
                "id": i,
                "timestamp": (datetime.now() - timedelta(hours=i)).isoformat(),
                "severity": ["critical", "high", "medium", "low"][i % 4],
                "rule_title": f"Security Alert {i}",
                "description": f"Suspicious activity detected on {server_type} server",
                "log_entry_id": i * 10
            }
            for i in range(1, min(server_id * 2 + 1, 6))
        ]
    }
    
    return ServerDetailResponse(**dummy_detail)

@app.get("/api/logs")
async def get_logs(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    log_type: Optional[str] = None,
    server_id: Optional[int] = None
):
    """Get logs with filtering and pagination."""
    db = SessionLocal()
    try:
        query = db.query(LogEntry)
        
        if log_type:
            query = query.filter(LogEntry.log_source == log_type)
        if server_id:
            query = query.filter(LogEntry.server_id == server_id)
        
        logs = query.order_by(LogEntry.recv_time.desc()).offset(offset).limit(limit).all()
        
        return {
            "logs": [{"id": log.id, "server_id": log.server_id, "log_source": log.log_source, 
                      "recv_time": log.recv_time.isoformat(), "raw_log": log.content[:200]} for log in logs],
            "count": len(logs)
        }
    finally:
        db.close()

@app.get("/api/alerts", response_model=AlertsResponse)
async def get_alerts(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None
):
    """Get alerts with filtering."""
    db = SessionLocal()
    try:
        query = db.query(Alert).filter(Alert.resolved == False)
        
        if severity:
            query = query.filter(Alert.severity == severity)
        
        alerts = query.order_by(Alert.triggered_at.desc()).offset(offset).limit(limit).all()
        
        return AlertsResponse(alerts=alerts, count=len(alerts))
    finally:
        db.close()

@app.get("/api/alerts/stats")
async def get_alert_stats():
    """Get alert statistics."""
    db = SessionLocal()
    try:
        from sqlalchemy import func
        
        total = db.query(func.count(Alert.id)).scalar() or 0
        active = db.query(func.count(Alert.id)).filter(Alert.resolved == False).scalar() or 0
        by_severity = {}
        for severity, count in db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all():
            by_severity[severity] = count
        
        return {"total_alerts": total, "active_alerts": active, "by_severity": by_severity}
    finally:
        db.close()

@app.get("/api/timeseries")
async def get_timeseries(hours: int = Query(24, ge=1, le=168)):
    """Get time-series data for charts."""
    # TODO: Implement timeseries data aggregation
    return {"timeseries": []}

@app.get("/api/worker/status")
async def get_worker_status():
    """Get worker status."""
    return {
        "ingestion": {
            "running": api_tasks.task_state.ingestion_running,
            "stats": api_tasks.task_state.stats["ingestion"]
        },
        "sigma": {
            "running": api_tasks.task_state.sigma_running,
            "stats": api_tasks.task_state.stats["sigma"]
        },
        "parser": {
            "running": api_tasks.task_state.parser_running,
            "stats": api_tasks.task_state.stats["parser"]
        }
    }

# === WebSocket ===
@app.websocket("/ws/live")
async def websocket_live(websocket: WebSocket):
    """WebSocket for real-time updates."""
    await ws_manager.connect(websocket)
    
    try:
        # Send initial data
        db = SessionLocal()
        try:
            from sqlalchemy import func
            total_logs = db.query(func.count(LogEntry.id)).scalar() or 0
            await websocket.send_json({"type": "stats", "data": {"total_logs": total_logs}})
        finally:
            db.close()
        
        # Keep connection alive
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        print(f"[WebSocket] Error: {e}")
        ws_manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    
    print("=" * 80)
    print("🛡️  IRONCLAD SIEM DASHBOARD")
    print("=" * 80)
    print(f"Database: {DB_PATH}")
    print(f"Sigma Rules: {SIGMA_RULES_DIR}")
    print(f"Server: http://0.0.0.0:8000")
    print(f"API Docs: http://0.0.0.0:8000/docs")
    print("=" * 80)
    
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
