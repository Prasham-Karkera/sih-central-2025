import os
import sys
import logging
import threading
import re
import time
import webbrowser
import subprocess
from datetime import datetime, timezone
import platform
from collections import defaultdict, deque
from pathlib import Path

from flask import Flask, send_file, jsonify, request
from flask_socketio import SocketIO
from flask_cors import CORS
import socketserver

from drain3 import TemplateMiner
from drain3.file_persistence import FilePersistence
from log_collector import collect_all_logs

# ----------------- CONFIG -----------------

WEB_HOST = "0.0.0.0"
WEB_PORT = 3000

ROUTER_IP = "192.168.7.1"
ROUTER_NAME = "Home_TPLink_Router"
SYSLOG_PORT = 2514

# Data Directories
DATA_DIR = Path("data")
ROUTER_LOG_DIR = DATA_DIR / "router_logs"
PLUGIN_DIR = DATA_DIR / "web_plugins"  # <--- NEW: Stores uploaded HTML plugins

DATA_DIR.mkdir(parents=True, exist_ok=True)
ROUTER_LOG_DIR.mkdir(parents=True, exist_ok=True)
PLUGIN_DIR.mkdir(parents=True, exist_ok=True)

# ----------------- HELPER FOR PYINSTALLER -----------------
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# ----------------- FLASK & SOCKETIO INIT -----------------

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - [%(levelname)s] - (%(threadName)-10s) - %(message)s",
)

# ----------------- ROUTES -----------------
@app.route('/')
def index():
    file_path = resource_path("index.html")
    if not os.path.exists(file_path):
        return f"Error: index.html not found at {file_path}", 404
    return send_file(file_path)

# --- NEW API: Upload Plugin ---
# --- NEW API: Upload Plugin ---
@app.route('/api/plugins/upload', methods=['POST'])
def upload_plugin():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    if file:
        filename = file.filename
        ext = os.path.splitext(filename)[1].lower()

        if ext == '.py':
            # Save Python plugins to the root 'plugins' folder for PluginManager
            save_dir = Path("plugins")
            save_dir.mkdir(exist_ok=True)
            save_path = save_dir / filename
            file.save(save_path)
            
            print(f"[PLUGIN] New Backend Plugin uploaded: {filename}")
            # PluginManager watcher will pick this up and emit 'backend_plugin_added'
            return jsonify({"message": "Backend Plugin uploaded", "name": filename, "type": "backend"})
            
        else:
            # Default to HTML/Web plugins
            save_path = PLUGIN_DIR / filename
            file.save(save_path)
            
            # Read content to send back immediately
            try:
                with open(save_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Notify all connected clients via SocketIO
                print(f"[PLUGIN] New UI Plugin uploaded: {filename}")
                socketio.emit('plugin_added', {'name': filename, 'content': content})
                
                return jsonify({"message": "Plugin uploaded", "name": filename, "type": "frontend"})
            except Exception as e:
                return jsonify({"error": str(e)}), 500

# --- NEW API: List Plugins (For Startup) ---
@app.route('/api/plugins/list', methods=['GET'])
def list_plugins():
    plugins = []
    if PLUGIN_DIR.exists():
        for file_path in PLUGIN_DIR.glob("*.html"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    plugins.append({
                        'name': file_path.name,
                        'content': f.read()
                    })
            except Exception as e:
                print(f"[ERROR] Could not read plugin {file_path}: {e}")
    return jsonify(plugins)

# --- NEW API: List Backend Plugins ---
@app.route('/api/plugins/backend/list', methods=['GET'])
def list_backend_plugins():
    if plugin_manager:
        plugins = [{'name': p.name, 'type': 'backend'} for p in plugin_manager.plugins]
        return jsonify(plugins)
    return jsonify([])

# --- NEW: Background Watcher for HTML Plugins ---
def watch_html_plugins():
    """Polls the plugin directory for new HTML files."""
    known_files = set()
    
    # Initial population to avoid spamming on startup (since list_plugins handles startup)
    if PLUGIN_DIR.exists():
        known_files = set(f.name for f in PLUGIN_DIR.glob("*.html"))
        
    print("[PLUGIN WATCHER] Started watching for .html files...")
    
    while True:
        time.sleep(2)
        if not PLUGIN_DIR.exists():
            continue
            
        try:
            current_files = set(f.name for f in PLUGIN_DIR.glob("*.html"))
            new_files = current_files - known_files
            
            for filename in new_files:
                file_path = PLUGIN_DIR / filename
                try:
                    # Wait a brief moment to ensure write is complete
                    time.sleep(0.5)
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    print(f"[PLUGIN WATCHER] New HTML Plugin detected: {filename}")
                    socketio.emit('plugin_added', {'name': filename, 'content': content})
                    known_files.add(filename)
                except Exception as e:
                    print(f"[PLUGIN WATCHER ERROR] Failed to read {filename}: {e}")
            
            # Update known files to handle deletions (if we want to re-add later)
            known_files = current_files
            
        except Exception as e:
            print(f"[PLUGIN WATCHER LOOP ERROR] {e}")

# ----------------- LOG STORE CLASSES -----------------

class LogStore:
    def __init__(self):
        self._lock = threading.Lock()
        self.total_logs = 0
        self.log_type_counts = {}
        self.side_counts = {"Local": 0, "Remote": 0}
        
        self.template_miner = TemplateMiner(FilePersistence("data/drain3_state.bin"))
        
        threading.Thread(target=self._stats_printer, daemon=True).start()
        logging.info("Drain3 parsing engine initialized")

        self.failed_login_attempts = defaultdict(deque)
        self.sudo_history = defaultdict(deque)
        self.portscan_attempts = defaultdict(set)

    def process_and_store_log(self, source_ip, raw_message, side="Local"):
        text = str(raw_message).lower()
        log_type = "unknown"
        
        if any(k in text for k in ["tp-link", "archer", "tl-", "tplink"]):
            log_type = "tplink_router"
        elif re.search(r"(sshd|failed password|sudo:)", text):
            log_type = "linux_auth"
        elif re.search(r"(deny|block|drop|ufw|iptables|firewall)", text):
            log_type = "firewall_network"
        elif platform.system() == "Linux":
            log_type = "linux_syslog"

        ts = datetime.now(timezone.utc).isoformat() + "Z"

        with self._lock:
            self.total_logs += 1
            self.log_type_counts[log_type] = self.log_type_counts.get(log_type, 0) + 1
            if side == "Local":
                self.side_counts["Local"] += 1
            else:
                self.side_counts["Remote"] += 1

        # Console log for debugging
        # print(f"[{source_ip}] {ts} {raw_message[:100]}")

        socketio.emit("new_log", {
            "timestamp": ts,
            "source_ip": source_ip or "Local",
            "message": str(raw_message)[:200],
            "log_type": log_type,
            "side": side,
        })
        
        # Basic Detections
        event_time = datetime.utcnow()
        if "failed password" in text:
            hist = self.failed_login_attempts[source_ip]
            hist.append(event_time)
            while hist and (event_time - hist[0]).total_seconds() > 300:
                hist.popleft()
            if len(hist) > 5:
                alert = f"Brute-force: {len(hist)} failed logins from {source_ip}"
                socketio.emit("new_alert", {"type": "BruteForce", "msg": alert, "source_ip": source_ip})

    def _stats_printer(self):
        while True:
            time.sleep(60)
            with self._lock:
                total = self.total_logs
            # print(f"[STATS] Total Logs: {total}")

log_store = LogStore()

# ----------------- PLUGIN SYSTEM INIT (BACKEND LOGIC) -----------------
plugin_manager = None
try:
    from plugin_manager import PluginManager
    print("[BOOT] Initializing Plugin System...")
    plugin_manager = PluginManager(app=app, socketio=socketio, log_store=log_store)
    plugin_manager.load_plugins()
except ImportError:
    print("[BOOT] plugin_manager.py not found. Running in core mode.")
except Exception as e:
    print(f"[BOOT ERROR] Plugin System Failed: {e}")

# ----------------- SYSLOG SERVER -----------------

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0].strip()
        source_ip = self.client_address[0]
        message = data.decode("utf-8", errors="ignore")
        log_store.process_and_store_log(source_ip, message, side="Remote")

def start_syslog_server():
    try:
        server = socketserver.ThreadingUDPServer(("0.0.0.0", SYSLOG_PORT), SyslogUDPHandler)
        print(f"Syslog receiver started on UDP/{SYSLOG_PORT}")
        server.serve_forever()
    except OSError as e:
        print(f"[ERROR] Could not bind UDP/{SYSLOG_PORT}: {e}")

# ----------------- ENTRY POINT -----------------

def launch_tplink_collector():
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        script_path = os.path.join(base_dir, "tplink_collector.py")
        if os.path.exists(script_path):
            print(f"[LAUNCH] Starting TPLink Collector: {script_path}")
            subprocess.Popen([sys.executable, script_path])
    except Exception as e:
        print(f"[ERROR] Failed to launch TPLink Collector: {e}")

def main():
    threading.Thread(target=collect_all_logs, daemon=True).start()
    threading.Thread(target=start_syslog_server, daemon=True).start()
    threading.Thread(target=watch_html_plugins, daemon=True).start() # <--- Start Watcher
    launch_tplink_collector()

    print(f"[SERVER] Starting Web Dashboard at http://127.0.0.1:{WEB_PORT}")
    
    def open_browser():
        time.sleep(1.5)
        webbrowser.open(f"http://127.0.0.1:{WEB_PORT}")
    
    threading.Thread(target=open_browser, daemon=True).start()
    
    socketio.run(app, host=WEB_HOST, port=WEB_PORT)

if __name__ == "__main__":
    main()