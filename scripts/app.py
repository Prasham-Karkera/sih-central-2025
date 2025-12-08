"""
FastAPI application for Agentless SIEM Dashboard
"""
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from datetime import datetime, timedelta
from pathlib import Path
import sys
from contextlib import asynccontextmanager

# Add src to path for imports
sys.path.append(str(Path(__file__).parent))

from src.models.source import LogSource, calculate_source_status
from src.manager.listener_manager import ListenerManager

# Global listener manager instance
listener_manager = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage FastAPI lifecycle events"""
    global listener_manager
    
    # Startup
    listener_manager = ListenerManager(db_path="logs/siem.db")
    listener_manager.start()
    
    yield
    
    # Shutdown
    if listener_manager:
        listener_manager.stop()


# Initialize FastAPI app with lifespan
app = FastAPI(
    title="Agentless SIEM",
    description="Portable log analysis tool for isolated networks",
    version="1.0.0",
    lifespan=lifespan
)

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Templates
templates = Jinja2Templates(directory="app/templates")


def get_live_sources():
    """Get live sources from database"""
    if not listener_manager:
        return []
    
    db = listener_manager.db_manager
    sources_list = []
    
    with db.get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT source_id, hostname, ip_address, source_type, protocol,
                   last_seen, total_events
            FROM sources
            ORDER BY last_seen DESC
        """)
        
        rows = cursor.fetchall()
        
        for row in rows:
            # Calculate events per minute (simplified - should be calculated from actual events)
            cursor.execute("""
                SELECT COUNT(*) FROM log_entries
                WHERE source_id = ? AND timestamp > datetime('now', '-1 minute')
            """, (row[0],))
            
            epm = cursor.fetchone()[0]
            
            # Parse last_seen timestamp
            try:
                last_seen = datetime.fromisoformat(row[5]) if row[5] else datetime.now()
            except:
                last_seen = datetime.now()
            
            source = LogSource(
                source_id=row[0],
                display_name=row[1],
                hostname=row[1],
                ip_address=row[2],
                device_type="server",
                os_name=row[3].title(),
                source_type=row[3],
                protocol=row[4],
                last_seen=last_seen,
                events_per_minute=epm,
                total_events=row[6],
                risk_score=0
            )
            
            source.status = calculate_source_status(last_seen)
            sources_list.append(source)
    
    return sources_list


# Mock data generator (fallback when no live data)
def get_mock_sources():

    """Generate mock log sources for demonstration"""
    now = datetime.now()
    
    sources = [
        LogSource(
            source_id="src_001",
            display_name="Domain Controller 01",
            hostname="dc01.corp.local",
            ip_address="10.0.1.10",
            device_type="server",
            os_name="Windows",
            source_type="windows",
            protocol="wef",
            last_seen=now - timedelta(seconds=2),
            events_per_minute=45,
            total_events=125430,
            risk_score=15
        ),
        LogSource(
            source_id="src_002",
            display_name="Linux Web Server",
            hostname="webserver01",
            ip_address="10.0.1.20",
            device_type="server",
            os_name="Linux",
            source_type="linux",
            protocol="syslog_tcp",
            last_seen=now - timedelta(seconds=1),
            events_per_minute=89,
            total_events=456789,
            risk_score=8
        ),
        LogSource(
            source_id="src_003",
            display_name="Firewall - Edge",
            hostname="fw-edge-01",
            ip_address="10.0.0.1",
            device_type="network",
            os_name="Cisco",
            source_type="network",
            protocol="syslog_udp",
            last_seen=now - timedelta(seconds=3),
            events_per_minute=234,
            total_events=2345678,
            risk_score=42
        ),
        LogSource(
            source_id="src_004",
            display_name="File Server 01",
            hostname="fileserver01",
            ip_address="10.0.1.30",
            device_type="server",
            os_name="Windows",
            source_type="windows",
            protocol="wef",
            last_seen=now - timedelta(seconds=12),
            events_per_minute=23,
            total_events=89234,
            risk_score=5
        ),
        LogSource(
            source_id="src_005",
            display_name="Database Server",
            hostname="db-prod-01",
            ip_address="10.0.2.10",
            device_type="server",
            os_name="Linux",
            source_type="linux",
            protocol="syslog_tcp",
            last_seen=now - timedelta(seconds=45),
            events_per_minute=0,
            total_events=567123,
            risk_score=78
        ),
        LogSource(
            source_id="src_006",
            display_name="Router - Core",
            hostname="router-core-01",
            ip_address="10.0.0.2",
            device_type="network",
            os_name="Cisco",
            source_type="network",
            protocol="snmp",
            last_seen=now - timedelta(seconds=4),
            events_per_minute=156,
            total_events=1234567,
            risk_score=12
        ),
        LogSource(
            source_id="src_007",
            display_name="Exchange Server",
            hostname="exchange01",
            ip_address="10.0.1.40",
            device_type="server",
            os_name="Windows",
            source_type="windows",
            protocol="wef",
            last_seen=now - timedelta(seconds=1),
            events_per_minute=67,
            total_events=234567,
            risk_score=18
        ),
        LogSource(
            source_id="src_008",
            display_name="Workstation - IT",
            hostname="ws-it-05",
            ip_address="10.0.3.15",
            device_type="endpoint",
            os_name="Windows",
            source_type="windows",
            protocol="wef",
            last_seen=now - timedelta(seconds=8),
            events_per_minute=12,
            total_events=45678,
            risk_score=3
        ),
    ]
    
    # Update status for each source
    for source in sources:
        source.status = calculate_source_status(source.last_seen)
    
    return sources


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    """Main dashboard page"""
    sources = get_live_sources() or get_mock_sources()
    
    return templates.TemplateResponse(
        "sources.html",  # For now, redirect to sources
        {
            "request": request,
            "now": datetime.now(),
            "sources": sources
        }
    )


@app.get("/sources", response_class=HTMLResponse)
async def sources_page(request: Request):
    """Log sources page"""
    sources = get_live_sources() or get_mock_sources()
    
    return templates.TemplateResponse(
        "sources.html",
        {
            "request": request,
            "now": datetime.now(),
            "sources": sources
        }
    )


@app.get("/logs/{source_id}", response_class=HTMLResponse)
async def view_logs(request: Request, source_id: str):
    """View logs for a specific source"""
    # TODO: Implement actual log viewing
    return templates.TemplateResponse(
        "base.html",
        {
            "request": request,
            "now": datetime.now(),
            "message": f"Logs for source {source_id} - Coming soon!"
        }
    )


@app.get("/api/sources")
async def api_sources():
    """API endpoint to get all sources as JSON"""
    sources = get_live_sources() or get_mock_sources()
    return [source.dict() for source in sources]


@app.get("/api/sources/{source_id}")
async def api_source_detail(source_id: str):
    """API endpoint to get a specific source"""
    sources = get_live_sources() or get_mock_sources()
    source = next((s for s in sources if s.source_id == source_id), None)
    
    if source:
        return source.dict()
    else:
        return {"error": "Source not found"}, 404


@app.get("/api/status")
async def api_status():
    """Get listener manager status"""
    if listener_manager:
        return listener_manager.get_status()
    return {"error": "Listener manager not initialized"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
