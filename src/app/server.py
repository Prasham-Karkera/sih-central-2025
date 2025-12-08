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
async def get_servers(
    limit: int = Query(200, ge=1),
    offset: int = Query(0, ge=0)
):
    """Get all servers with specific dummy data."""
    
    # Data provided by user
    servers_data = [
        {
            "id": 1,
            "hostname": "test-server",
            "ip_address": "192.168.1.100",
            "server_type": "linux",
            "status": "offline",
            "stats": {
                "total_logs": 2,
                "total_alerts": 2,
                "active_alerts": 2,
                "last_seen": "2025-12-06T05:59:48.579430"
            }
        },
        {
            "id": 2,
            "hostname": "webserver-01",
            "ip_address": "192.168.1.100",
            "server_type": "linux",
            "status": "offline",
            "stats": {
                "total_logs": 1,
                "total_alerts": 0,
                "active_alerts": 0,
                "last_seen": "2025-12-06T06:05:52.543277"
            }
        },
        {
            "id": 3,
            "hostname": "dc01",
            "ip_address": "10.0.0.5",
            "server_type": "windows",
            "status": "offline",
            "stats": {
                "total_logs": 1,
                "total_alerts": 0,
                "active_alerts": 0,
                "last_seen": "2025-12-06T06:05:52.563394"
            }
        },
        {
            "id": 4,
            "hostname": "nginx-lb-01",
            "ip_address": "10.0.0.10",
            "server_type": "nginx",
            "status": "offline",
            "stats": {
                "total_logs": 1,
                "total_alerts": 0,
                "active_alerts": 0,
                "last_seen": "2025-12-06T06:05:52.579385"
            }
        },
        {
            "id": 5,
            "hostname": "Hp-lap704",
            "ip_address": "0.0.0.0",
            "server_type": "unknown",
            "status": "offline",
            "stats": {
                "total_logs": 0,
                "total_alerts": 0,
                "active_alerts": 0,
                "last_seen": None
            }
        },
        {
            "id": 6,
            "hostname": "HP-LAP704",
            "ip_address": "0.0.0.0",
            "server_type": "unknown",
            "status": "offline",
            "stats": {
                "total_logs": 0,
                "total_alerts": 0,
                "active_alerts": 0,
                "last_seen": None
            }
        },
        {
            "id": 7,
            "hostname": "HP-LAP704",
            "ip_address": "192.168.0.102",
            "server_type": "windows",
            "status": "offline",
            "stats": {
                "total_logs": 81541,
                "total_alerts": 8437,
                "active_alerts": 8437,
                "last_seen": "2025-12-06T20:40:33"
            }
        },
        {
            "id": 8,
            "hostname": "192.168.1.100",
            "ip_address": "127.0.0.1",
            "server_type": "nginx",
            "status": "offline",
            "stats": {
                "total_logs": 21,
                "total_alerts": 19,
                "active_alerts": 19,
                "last_seen": "2025-12-06T10:00:09"
            }
        },
        {
            "id": 9,
            "hostname": "WIN-SERVER",
            "ip_address": "127.0.0.1",
            "server_type": "windows",
            "status": "offline",
            "stats": {
                "total_logs": 4,
                "total_alerts": 2,
                "active_alerts": 2,
                "last_seen": "2025-12-06T10:00:02"
            }
        },
        {
            "id": 10,
            "hostname": "linux-server",
            "ip_address": "127.0.0.1",
            "server_type": "linux",
            "status": "offline",
            "stats": {
                "total_logs": 8,
                "total_alerts": 6,
                "active_alerts": 6,
                "last_seen": "2025-12-06T07:10:13.758851"
            }
        },
        {
            "id": 11,
            "hostname": "WIN-RDP",
            "ip_address": "127.0.0.1",
            "server_type": "windows",
            "status": "offline",
            "stats": {
                "total_logs": 4,
                "total_alerts": 2,
                "active_alerts": 2,
                "last_seen": "2025-12-06T10:00:05"
            }
        },
        {
            "id": 12,
            "hostname": "WIN-WS01",
            "ip_address": "127.0.0.1",
            "server_type": "windows",
            "status": "offline",
            "stats": {
                "total_logs": 4,
                "total_alerts": 2,
                "active_alerts": 2,
                "last_seen": "2025-12-06T10:00:08"
            }
        },
        {
            "id": 13,
            "hostname": "Hp-lap704",
            "ip_address": "192.168.0.102",
            "server_type": "linux",
            "status": "offline",
            "stats": {
                "total_logs": 61,
                "total_alerts": 0,
                "active_alerts": 0,
                "last_seen": "2025-12-06T17:32:04.157723"
            }
        },
        {
            "id": 14,
            "hostname": "DC01",
            "ip_address": "127.0.0.1",
            "server_type": "windows",
            "status": "offline",
            "stats": {
                "total_logs": 1,
                "total_alerts": 1,
                "active_alerts": 1,
                "last_seen": "2025-12-06T20:42:24"
            }
        },
        {
            "id": 15,
            "hostname": "WEB-SERVER",
            "ip_address": "127.0.0.1",
            "server_type": "windows",
            "status": "offline",
            "stats": {
                "total_logs": 1,
                "total_alerts": 1,
                "active_alerts": 1,
                "last_seen": "2025-12-06T20:42:24"
            }
        },
        {
            "id": 16,
            "hostname": "Hp-lap704",
            "ip_address": "192.168.137.247",
            "server_type": "linux",
            "status": "offline",
            "stats": {
                "total_logs": 19,
                "total_alerts": 32,
                "active_alerts": 32,
                "last_seen": "2025-12-07T14:47:18.002165"
            }
        },
        {
            "id": 17,
            "hostname": "HP-LAP704",
            "ip_address": "10.78.233.207",
            "server_type": "windows",
            "status": "online",
            "stats": {
                "total_logs": 14175,
                "total_alerts": 14359,
                "active_alerts": 14359,
                "last_seen": "2025-12-08T07:21:16"
            }
        }
    ]
    
    # Apply limit and offset
    paginated_servers = servers_data[offset : offset + limit]
    
    return {
        "servers": paginated_servers,
        "total": len(servers_data),
        "total_available": len(servers_data),
        "limit": limit,
        "offset": offset
    }

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
