"""
Background Task Management API

Simple wrapper to manage existing workers as background tasks.
"""
import asyncio
import threading
from typing import Dict, Any
from fastapi import APIRouter, BackgroundTasks

from src.workers.ingestion_worker import IngestionWorker
from src.workers.sigma_rule_worker import SigmaRuleWorker
from src.workers.parser_worker import ParserWorker

router = APIRouter(prefix="/api/tasks", tags=["tasks"])

# Global task state
class TaskState:
    def __init__(self):
        self.ingestion_worker: IngestionWorker = None
        self.sigma_worker: SigmaRuleWorker = None
        self.parser_worker: ParserWorker = None
        self.parser_thread: threading.Thread = None
        self.workers_running = False

task_state = TaskState()

# === Background Task Functions ===

async def start_all_workers():
    """Start all workers in background."""
    if task_state.workers_running:
        print("[Tasks] Workers already running")
        return
    
    print("[Tasks] Starting all workers...")
    
    # Start Ingestion Worker
    task_state.ingestion_worker = IngestionWorker(
        host="0.0.0.0",
        port=5140
    )
    task_state.ingestion_worker.start()
    print("[Tasks] ✓ Ingestion worker started on UDP 5140")
    
    # Start Sigma Worker
    task_state.sigma_worker = SigmaRuleWorker(
        rules_dir="./Sigma_Rules",
        poll_interval=5.0
    )
    task_state.sigma_worker.start()
    print("[Tasks] ✓ Sigma rule worker started")
    
    # Start Parser Worker (needs threading)
    task_state.parser_worker = ParserWorker(poll_interval=10.0)
    task_state.parser_thread = threading.Thread(target=task_state.parser_worker.run, daemon=True)
    task_state.parser_thread.start()
    print("[Tasks] ✓ Parser worker started")
    
    task_state.workers_running = True
    print("[Tasks] All workers active!")

async def stop_all_workers():
    """Stop all workers gracefully."""
    print("[Tasks] Stopping all workers...")
    
    if task_state.parser_worker:
        task_state.parser_worker.stop()
        print("[Tasks] Parser worker stopped")
    
    if task_state.sigma_worker:
        task_state.sigma_worker.stop()
        print("[Tasks] Sigma worker stopped")
    
    if task_state.ingestion_worker:
        task_state.ingestion_worker.stop()
        print("[Tasks] Ingestion worker stopped")
    
    task_state.workers_running = False
    print("[Tasks] All workers stopped")

# === API Endpoints ===

@router.get("/status")
async def get_task_status():
    """Get status of all background workers."""
    return {
        "workers_running": task_state.workers_running,
        "ingestion": {
            "running": task_state.ingestion_worker.is_running() if task_state.ingestion_worker else False,
            "stats": task_state.ingestion_worker.get_stats() if task_state.ingestion_worker else {}
        },
        "sigma": {
            "running": task_state.sigma_worker.is_running() if task_state.sigma_worker else False,
            "stats": task_state.sigma_worker.get_stats() if task_state.sigma_worker else {}
        },
        "parser": {
            "running": task_state.parser_worker.running if task_state.parser_worker else False,
            "stats": task_state.parser_worker.get_stats() if task_state.parser_worker else {}
        }
    }

@router.post("/start")
async def start_workers(background_tasks: BackgroundTasks):
    """Start all workers."""
    if task_state.workers_running:
        return {"status": "already_running", "message": "Workers are already active"}
    
    background_tasks.add_task(start_all_workers)
    return {"status": "starting", "message": "Workers are being started"}

@router.post("/stop")
async def stop_workers(background_tasks: BackgroundTasks):
    """Stop all workers."""
    if not task_state.workers_running:
        return {"status": "already_stopped", "message": "Workers are not running"}
    
    background_tasks.add_task(stop_all_workers)
    return {"status": "stopping", "message": "Workers are being stopped"}
