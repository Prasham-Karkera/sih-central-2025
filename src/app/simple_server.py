"""
Simple FastAPI Server - Static Data Only
No database dependency, pure dummy data for UI development
"""

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Dict, Any
import random

app = FastAPI(title="Ironclad SIEM", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Paths
TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"

# Jinja2 Templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# Mount static files if exists
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

# === Dummy Data Generators ===

def generate_servers() -> List[Dict[str, Any]]:
    """Generate dummy server data."""
    servers = [
        {
            "source_id": 1,
            "id": 1,
            "hostname": "web-server-01",
            "display_name": "Production Web Server",
            "ip_address": "192.168.1.100",
            "source_type": "network",
            "type": "nginx",
            "protocol": "syslog",
            "status": "online",
            "log_count": 1523,
            "total_events": 1523,
            "events_per_minute": 12,
            "alert_count": 3,
            "cpu_usage": 45.2,
            "memory_usage": 67.8,
            "disk_usage": 55.3,
            "network_in": "2.5 MB/s",
            "network_out": "1.8 MB/s",
            "uptime": "30d 12h 45m",
            "last_seen": datetime.now().isoformat(),
            "first_seen": (datetime.now() - timedelta(days=30)).isoformat()
        },
        {
            "source_id": 2,
            "id": 2,
            "hostname": "dc-server-01",
            "display_name": "Domain Controller",
            "ip_address": "192.168.1.10",
            "source_type": "server",
            "type": "windows",
            "protocol": "wec",
            "status": "online",
            "log_count": 5087,
            "total_events": 5087,
            "events_per_minute": 42,
            "alert_count": 12,
            "cpu_usage": 78.5,
            "memory_usage": 82.3,
            "disk_usage": 73.2,
            "network_in": "5.2 MB/s",
            "network_out": "3.1 MB/s",
            "uptime": "60d 8h 22m",
            "last_seen": datetime.now().isoformat(),
            "first_seen": (datetime.now() - timedelta(days=60)).isoformat()
        },
        {
            "source_id": 3,
            "id": 3,
            "hostname": "ubuntu-server-01",
            "display_name": "Ubuntu Web Server",
            "ip_address": "192.168.1.50",
            "source_type": "server",
            "type": "linux",
            "protocol": "syslog",
            "status": "online",
            "log_count": 892,
            "total_events": 892,
            "events_per_minute": 7,
            "alert_count": 1,
            "cpu_usage": 23.1,
            "memory_usage": 45.6,
            "disk_usage": 38.7,
            "network_in": "0.8 MB/s",
            "network_out": "0.5 MB/s",
            "uptime": "45d 16h 33m",
            "last_seen": datetime.now().isoformat(),
            "first_seen": (datetime.now() - timedelta(days=45)).isoformat()
        },
        {
            "source_id": 4,
            "id": 4,
            "hostname": "app-server-02",
            "display_name": "Application Server 2",
            "ip_address": "192.168.1.110",
            "source_type": "application",
            "type": "nginx",
            "protocol": "syslog",
            "status": "delayed",
            "log_count": 2341,
            "total_events": 2341,
            "events_per_minute": 19,
            "alert_count": 7,
            "cpu_usage": 91.3,
            "memory_usage": 88.7,
            "disk_usage": 82.1,
            "network_in": "8.5 MB/s",
            "network_out": "4.2 MB/s",
            "uptime": "20d 4h 17m",
            "last_seen": (datetime.now() - timedelta(minutes=15)).isoformat(),
            "first_seen": (datetime.now() - timedelta(days=20)).isoformat()
        },
        {
            "source_id": 5,
            "id": 5,
            "hostname": "win-workstation-03",
            "display_name": "Windows Workstation",
            "ip_address": "192.168.1.45",
            "source_type": "workstation",
            "type": "windows",
            "protocol": "wec",
            "status": "offline",
            "log_count": 156,
            "total_events": 156,
            "events_per_minute": 0,
            "alert_count": 0,
            "cpu_usage": 0,
            "memory_usage": 0,
            "disk_usage": 45.2,
            "network_in": "0 MB/s",
            "network_out": "0 MB/s",
            "uptime": "0h 0m",
            "last_seen": (datetime.now() - timedelta(hours=2)).isoformat(),
            "first_seen": (datetime.now() - timedelta(days=10)).isoformat()
        },
        {
            "source_id": 6,
            "id": 6,
            "hostname": "db-server-01",
            "display_name": "Database Server",
            "ip_address": "192.168.1.20",
            "source_type": "database",
            "type": "linux",
            "protocol": "syslog",
            "status": "online",
            "log_count": 3421,
            "total_events": 3421,
            "events_per_minute": 28,
            "alert_count": 5,
            "cpu_usage": 65.8,
            "memory_usage": 92.1,
            "disk_usage": 88.5,
            "network_in": "12.3 MB/s",
            "network_out": "8.7 MB/s",
            "uptime": "90d 3h 51m",
            "last_seen": datetime.now().isoformat(),
            "first_seen": (datetime.now() - timedelta(days=90)).isoformat()
        }
    ]
    return servers

def generate_logs(server_id: int, count: int = 50) -> List[Dict[str, Any]]:
    """Generate dummy log entries."""
    server_types = {1: "nginx", 2: "windows", 3: "linux", 4: "nginx", 5: "windows", 6: "linux"}
    log_type = server_types.get(server_id, "linux")
    
    messages = {
        "nginx": [
            'GET /api/users HTTP/1.1" 200',
            'POST /api/login HTTP/1.1" 401',
            'GET /admin/dashboard HTTP/1.1" 403',
            'GET /static/css/main.css HTTP/1.1" 200',
            'POST /api/data HTTP/1.1" 500'
        ],
        "windows": [
            "User login successful",
            "Service started: Windows Update",
            "Failed login attempt detected",
            "System boot completed",
            "Application error: Access denied"
        ],
        "linux": [
            "systemd[1]: Started User Manager",
            "sshd[1234]: Accepted password for user",
            "kernel: Out of memory warning",
            "CRON[5678]: Session opened for root",
            "sudo: authentication failure"
        ]
    }
    
    logs = []
    for i in range(count):
        logs.append({
            "id": i + 1,
            "timestamp": datetime.now() - timedelta(minutes=i*2),
            "log_type": log_type,
            "severity": random.choice(["info", "warning", "error", "critical"]),
            "message": random.choice(messages[log_type]),
            "user": random.choice(["admin", "user1", "system", "root", "-"]),
            "raw_line": f"[{log_type}] Sample log entry {i+1}"
        })
    
    return logs

def generate_alerts(server_id: int) -> List[Dict[str, Any]]:
    """Generate dummy alert data."""
    alert_titles = [
        "Suspicious SQL Injection Attempt",
        "Brute Force Login Detected",
        "Unauthorized Access Attempt",
        "Port Scanning Activity",
        "Malware Signature Detected",
        "Data Exfiltration Warning",
        "Privilege Escalation Attempt",
        "DDoS Attack Pattern"
    ]
    
    severity_levels = ["critical", "high", "medium", "low"]
    
    alerts = []
    for i in range(min(server_id * 2, 10)):
        alerts.append({
            "id": i + 1,
            "timestamp": datetime.now() - timedelta(hours=i*3),
            "severity": random.choice(severity_levels),
            "rule_title": random.choice(alert_titles),
            "title": random.choice(alert_titles),
            "description": f"Security alert triggered by Sigma rule detection on server",
            "status": random.choice(["new", "acknowledged", "resolved"]),
            "log_id": random.randint(1, 100)
        })
    
    return alerts

# === Routes ===

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Redirect to sources page."""
    return HTMLResponse('<script>window.location.href="/sources"</script>')

@app.get("/sources", response_class=HTMLResponse)
async def sources_page(request: Request):
    """Serve sources page with template."""
    servers = generate_servers()
    return templates.TemplateResponse("sources.html", {
        "request": request,
        "sources": servers,
        "now": datetime.now()
    })

@app.get("/logs/{source_id}", response_class=HTMLResponse)
async def source_detail_page(request: Request, source_id: int):
    """Serve source detail page."""
    servers = generate_servers()
    server = next((s for s in servers if s["source_id"] == source_id), None)
    
    if not server:
        return HTMLResponse("<h1>Source not found</h1>", status_code=404)
    
    # Add detailed data
    server["logs"] = generate_logs(source_id, 50)
    server["alerts"] = generate_alerts(source_id)
    
    return templates.TemplateResponse("source_detail.html", {
        "request": request,
        "source": server,
        "now": datetime.now()
    })

@app.get("/api/health")
async def health():
    """Health check."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "mode": "static_demo"
    }

@app.get("/api/sources")
async def get_sources():
    """Get all monitored sources."""
    servers = generate_servers()
    return {
        "sources": servers,
        "count": len(servers),
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/sources/{source_id}")
async def get_source_detail(source_id: int):
    """Get detailed information for a specific source."""
    servers = generate_servers()
    server = next((s for s in servers if s["id"] == source_id), None)
    
    if not server:
        return {"error": "Source not found"}, 404
    
    # Add detailed data
    server["logs"] = generate_logs(source_id, 50)
    server["alerts"] = generate_alerts(source_id)
    server["metrics"] = {
        "cpu_history": [random.uniform(20, 90) for _ in range(24)],
        "memory_history": [random.uniform(30, 95) for _ in range(24)],
        "network_in_history": [random.uniform(0.5, 15) for _ in range(24)],
        "network_out_history": [random.uniform(0.3, 10) for _ in range(24)]
    }
    
    return server

@app.get("/api/stats")
async def get_stats():
    """Get overall statistics."""
    servers = generate_servers()
    
    total_logs = sum(s["log_count"] for s in servers)
    total_alerts = sum(s["alert_count"] for s in servers)
    online_count = len([s for s in servers if s["status"] == "online"])
    
    return {
        "total_sources": len(servers),
        "online_sources": online_count,
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "critical_alerts": random.randint(2, 8),
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/alerts")
async def get_alerts():
    """Get all recent alerts."""
    all_alerts = []
    servers = generate_servers()
    
    for server in servers:
        server_alerts = generate_alerts(server["id"])
        for alert in server_alerts:
            alert["server_hostname"] = server["hostname"]
            alert["server_ip"] = server["ip_address"]
            all_alerts.append(alert)
    
    # Sort by timestamp
    all_alerts.sort(key=lambda x: x["timestamp"], reverse=True)
    
    return {
        "alerts": all_alerts[:50],
        "count": len(all_alerts),
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    import uvicorn
    
    print("="*60)
    print("🛡️  Ironclad SIEM - Static Demo Server")
    print("="*60)
    print("Server: http://localhost:8000")
    print("API Docs: http://localhost:8000/docs")
    print("Sources: http://localhost:8000/api/sources")
    print("="*60)
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
