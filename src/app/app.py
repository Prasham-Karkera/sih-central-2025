"""FastAPI SIEM Dashboard Application."""
import asyncio
import json
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, UploadFile, File, Query
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.db.database import DatabaseManager
from src.workers.ingestion_worker import IngestionWorker

# === Configuration ===
DB_PATH = "ironchad_logs.db"
STATIC_DIR = Path(__file__).parent / "static"
TEMPLATES_DIR = Path(__file__).parent / "templates"
PLUGINS_DIR = Path(__file__).parent / "plugins"

# === Pydantic Models ===
class StatsResponse(BaseModel):
    total_logs: int
    total_servers: int
    by_type: Dict[str, int]
    uptime: float

class LogFilter(BaseModel):
    log_type: Optional[str] = None
    server_id: Optional[int] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    limit: int = 50
    offset: int = 0

class SearchRequest(BaseModel):
    text: Optional[str] = None
    filters: Optional[Dict[str, Any]] = None
    limit: int = 50
    offset: int = 0

class WorkerStatus(BaseModel):
    running: bool
    stats: Dict[str, Any]

# === WebSocket Connection Manager ===
class ConnectionManager:
    """Manage WebSocket connections for real-time updates."""
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self._log_queue: asyncio.Queue = asyncio.Queue()
        self._broadcast_task = None
    
    async def connect(self, websocket: WebSocket):
        """Accept new WebSocket connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        print(f"[WebSocket] Client connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, websocket: WebSocket):
        """Remove WebSocket connection."""
        self.active_connections.discard(websocket)
        print(f"[WebSocket] Client disconnected. Total: {len(self.active_connections)}")
    
    async def broadcast(self, message: Dict[str, Any], event_type: str = "log"):
        """Broadcast message to all connected clients."""
        if not self.active_connections:
            return
        
        data = json.dumps({"type": event_type, "data": message})
        
        # Remove disconnected clients
        disconnected = set()
        for connection in self.active_connections:
            try:
                await connection.send_text(data)
            except Exception as e:
                print(f"[WebSocket] Error sending to client: {e}")
                disconnected.add(connection)
        
        self.active_connections -= disconnected
    
    async def send_personal(self, message: Dict[str, Any], websocket: WebSocket):
        """Send message to specific client."""
        try:
            await websocket.send_json(message)
        except Exception as e:
            print(f"[WebSocket] Error sending personal message: {e}")
    
    def queue_log(self, log_data: Dict[str, Any]):
        """Queue log for broadcasting."""
        try:
            self._log_queue.put_nowait(log_data)
        except asyncio.QueueFull:
            print("[WebSocket] Log queue full, dropping log")
    
    async def start_broadcaster(self):
        """Start background task to broadcast queued logs."""
        self._broadcast_task = asyncio.create_task(self._broadcast_loop())
    
    async def stop_broadcaster(self):
        """Stop background broadcaster."""
        if self._broadcast_task:
            self._broadcast_task.cancel()
            try:
                await self._broadcast_task
            except asyncio.CancelledError:
                pass
    
    async def _broadcast_loop(self):
        """Background loop to broadcast queued logs."""
        while True:
            try:
                log_data = await self._log_queue.get()
                await self.broadcast(log_data, event_type="log")
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[WebSocket] Broadcast error: {e}")

# === FastAPI App ===
app = FastAPI(title="SIEM Dashboard", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# === Global State ===
db: DatabaseManager = None
worker: IngestionWorker = None
ws_manager: ConnectionManager = ConnectionManager()
start_time: datetime = None

# === Startup/Shutdown ===
@app.on_event("startup")
async def startup_event():
    """Initialize database and start worker."""
    global db, worker, start_time
    
    start_time = datetime.now()
    
    # Initialize database
    db = DatabaseManager(DB_PATH)
    print(f"[FastAPI] Database initialized: {DB_PATH}")
    
    # Start WebSocket broadcaster
    await ws_manager.start_broadcaster()
    print("[FastAPI] WebSocket broadcaster started")
    
    # Start ingestion worker in background thread
    worker = IngestionWorker(db_path=DB_PATH)
    worker.start()
    print("[FastAPI] IngestionWorker started")
    
    # Create plugins directory if not exists
    PLUGINS_DIR.mkdir(exist_ok=True, parents=True)

@app.on_event("shutdown")
async def shutdown_event():
    """Stop worker and close database."""
    global db, worker
    
    # Stop WebSocket broadcaster
    await ws_manager.stop_broadcaster()
    print("[FastAPI] WebSocket broadcaster stopped")
    
    # Stop worker
    if worker:
        worker.stop()
        print("[FastAPI] IngestionWorker stopped")
    
    # Close database
    if db:
        db.close()
        print("[FastAPI] Database closed")

# === Static Files ===
# Mount static files
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# === Routes ===
@app.get("/", response_class=HTMLResponse)
async def home():
    """Serve main dashboard."""
    # Try simple version first
    index_file = TEMPLATES_DIR / "index_simple.html"
    if not index_file.exists():
        # Fall back to full version
        index_file = TEMPLATES_DIR / "index.html"
    
    if not index_file.exists():
        return HTMLResponse("<h1>SIEM Dashboard</h1><p>Template not found. Please create src/app/templates/index.html</p>")
    
    return FileResponse(index_file)

@app.get("/api/health")
async def health():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "database": "connected" if db else "disconnected",
        "worker": "running" if worker and worker.is_running() else "stopped"
    }

@app.get("/api/stats", response_model=StatsResponse)
async def get_stats():
    """Get system statistics."""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    stats = db.get_stats()
    uptime = (datetime.now() - start_time).total_seconds()
    
    return StatsResponse(
        total_logs=stats["total_logs"],
        total_servers=stats["total_servers"],
        by_type=stats["by_type"],
        uptime=uptime
    )

@app.post("/api/logs")
async def get_logs(filter: LogFilter):
    """Get logs with filtering and pagination."""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    logs = db.get_recent_logs(
        limit=filter.limit,
        offset=filter.offset,
        log_type=filter.log_type,
        server_id=filter.server_id,
        start_time=filter.start_time,
        end_time=filter.end_time
    )
    
    return {"logs": logs, "count": len(logs)}

@app.get("/api/logs/{log_id}")
async def get_log(log_id: int):
    """Get single log by ID with details."""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    log = db.get_log_by_id(log_id)
    
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    
    return log

@app.post("/api/logs/search")
async def search_logs(request: SearchRequest):
    """Search logs with text and filters."""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    logs = db.search_logs(
        text=request.text,
        filters=request.filters,
        limit=request.limit,
        offset=request.offset
    )
    
    return {"logs": logs, "count": len(logs)}

@app.get("/api/servers")
async def get_servers():
    """Get all servers with statistics."""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    servers = db.get_servers_with_stats()
    
    return {"servers": servers, "count": len(servers)}

@app.get("/api/servers/{server_id}/logs")
async def get_server_logs(server_id: int, limit: int = Query(50, ge=1, le=1000)):
    """Get logs for specific server."""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    logs = db.get_server_logs(server_id, limit=limit)
    
    return {"logs": logs, "count": len(logs)}

@app.get("/api/timeseries")
async def get_timeseries(hours: int = Query(24, ge=1, le=168)):
    """Get time-series statistics for charts."""
    if not db:
        raise HTTPException(status_code=503, detail="Database not initialized")
    
    timeseries = db.get_timeseries_stats(hours=hours)
    
    return {"timeseries": timeseries}

@app.get("/api/worker/status", response_model=WorkerStatus)
async def get_worker_status():
    """Get ingestion worker status."""
    if not worker:
        raise HTTPException(status_code=503, detail="Worker not initialized")
    
    return WorkerStatus(
        running=worker.is_running(),
        stats=worker.get_stats()
    )

@app.post("/api/worker/start")
async def start_worker():
    """Start ingestion worker."""
    if not worker:
        raise HTTPException(status_code=503, detail="Worker not initialized")
    
    if worker.is_running():
        return {"message": "Worker already running"}
    
    worker.start()
    return {"message": "Worker started"}

@app.post("/api/worker/stop")
async def stop_worker():
    """Stop ingestion worker."""
    if not worker:
        raise HTTPException(status_code=503, detail="Worker not initialized")
    
    if not worker.is_running():
        return {"message": "Worker already stopped"}
    
    worker.stop()
    return {"message": "Worker stopped"}

# === WebSocket Endpoints ===
@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    """WebSocket endpoint for real-time log streaming."""
    await ws_manager.connect(websocket)
    
    try:
        # Send initial stats
        if db:
            stats = db.get_stats()
            await ws_manager.send_personal({"type": "stats", "data": stats}, websocket)
        
        # Keep connection alive
        while True:
            # Wait for messages from client (ping/pong)
            data = await websocket.receive_text()
            
            if data == "ping":
                await websocket.send_text("pong")
    
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as e:
        print(f"[WebSocket] Error: {e}")
        ws_manager.disconnect(websocket)

@app.websocket("/ws/stats")
async def websocket_stats(websocket: WebSocket):
    """WebSocket endpoint for real-time statistics."""
    await websocket.accept()
    
    try:
        while True:
            if db:
                stats = db.get_stats()
                await websocket.send_json({"type": "stats", "data": stats})
            
            await asyncio.sleep(5)  # Update every 5 seconds
    
    except WebSocketDisconnect:
        print("[WebSocket] Stats client disconnected")
    except Exception as e:
        print(f"[WebSocket] Stats error: {e}")

# === Plugin System ===
@app.get("/api/plugins")
async def list_plugins():
    """List available plugins."""
    if not PLUGINS_DIR.exists():
        return {"plugins": []}
    
    plugins = []
    for plugin_file in PLUGINS_DIR.glob("*.py"):
        plugins.append({
            "name": plugin_file.stem,
            "path": str(plugin_file),
            "size": plugin_file.stat().st_size,
            "modified": plugin_file.stat().st_mtime
        })
    
    return {"plugins": plugins}

@app.post("/api/plugins/upload")
async def upload_plugin(file: UploadFile = File(...)):
    """Upload new plugin."""
    if not file.filename.endswith(".py"):
        raise HTTPException(status_code=400, detail="Only .py files allowed")
    
    # Save plugin
    plugin_path = PLUGINS_DIR / file.filename
    
    content = await file.read()
    plugin_path.write_bytes(content)
    
    return {
        "message": "Plugin uploaded successfully",
        "filename": file.filename,
        "path": str(plugin_path)
    }

@app.delete("/api/plugins/{plugin_name}")
async def delete_plugin(plugin_name: str):
    """Delete plugin."""
    plugin_path = PLUGINS_DIR / f"{plugin_name}.py"
    
    if not plugin_path.exists():
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    plugin_path.unlink()
    
    return {"message": f"Plugin {plugin_name} deleted"}

# === Helper: Broadcast logs from worker ===
def broadcast_log_callback(log_data: Dict[str, Any]):
    """Callback for worker to broadcast new logs."""
    ws_manager.queue_log(log_data)

# Connect callback (will be used when worker supports callbacks)
# worker.set_log_callback(broadcast_log_callback)

if __name__ == "__main__":
    import uvicorn
    
    print("=" * 60)
    print("SIEM Dashboard Starting")
    print("=" * 60)
    print(f"Database: {DB_PATH}")
    print(f"Templates: {TEMPLATES_DIR}")
    print(f"Static: {STATIC_DIR}")
    print(f"Plugins: {PLUGINS_DIR}")
    print("=" * 60)
    print("Server: http://localhost:8000")
    print("API Docs: http://localhost:8000/docs")
    print("=" * 60)
    
    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
