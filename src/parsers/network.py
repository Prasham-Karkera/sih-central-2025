import os
import datetime
import json
import re
import sqlite3
from fastapi import FastAPI, Query, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware

# Sigma Rule Engine integration
from src.workers.sigma_rule_engine import SigmaRuleEngine

# --- DB Connection Helper ---
def get_db_connection():
    return sqlite3.connect('ironclad_logs.db')

# --- IroncladParser Implementation ---
class IroncladParser:
    sigma_engine = None

    def _init_(self):
        self.conn = get_db_connection()
        # Initialize SigmaRuleEngine if not already
        if IroncladParser.sigma_engine is None:
            IroncladParser.sigma_engine = SigmaRuleEngine(r"./Sigma_Rules")
            IroncladParser.sigma_engine.load_rules()

        # Linux log pattern
        self.linux_header_pattern = (
            r"(?P<timestamp>"
            r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d][Z\+\-\:0-9]|" 
            r"^\S+\s+\S+\s+\S+|" 
            r"^\S+" 
            r")"
            r"\s+"
            r"(?P<hostname>\S+)"
            r"\s+"
            r"(?P<app_name>[^:\[\s]+)"
            r"(?:\[(?P<pid>\d+)\])?"
            r":\s+"
            r"(?P<raw_message>.*)"
        )

        # Nginx log pattern
        self.nginx_pattern = (
            r"(?P<remote_addr>[\d\.]+)\s+" 
            r"-\s+(?P<remote_user>\S+)\s+" 
            r"\[(?P<time_local>.*?)\]\s+" 
            r'"(?P<request_method>\S+)\s+' 
            r'(?P<request_uri>\S+)\s+' 
            r'(?P<server_protocol>[^\"]+)"\s+' 
            r'(?P<status>\d+)\s+' 
            r'(?P<body_bytes_sent>\d+)\s+' 
            r'"(?P<http_referer>[^\"]*)"\s+' 
            r'"(?P<http_user_agent>[^\"]*)"'
        )

        # Zeek conn.log pattern
        self.zeek_conn_pattern = (
            r'(?P<ts>\d+\.\d+)\s+'
            r'(?P<uid>\S+)\s+'
            r'(?P<orig_h>\S+)\s+'
            r'(?P<orig_p>\d+)\s+'
            r'(?P<resp_h>\S+)\s+'
            r'(?P<resp_p>\d+)\s+'
            r'(?P<proto>\S+)\s+'
            r'(?P<service>\S+)\s+'
            r'(?P<duration>\S+)\s+'
            r'(?P<orig_bytes>\S+)\s+'
            r'(?P<resp_bytes>\S+)\s+'
            r'(?P<conn_state>\S+)\s+'
            r'(?P<local_orig>\S+)\s+'
            r'(?P<missed_bytes>\d+)\s+'
            r'(?P<history>\S+)\s+'
            r'(?P<orig_pkts>\d+)\s+'
            r'(?P<orig_ip_bytes>\d+)\s+'
            r'(?P<resp_pkts>\d+)\s+'
            r'(?P<resp_ip_bytes>\d+)'
        )

    # ------------------ DB helpers ------------------
    def get_or_create_server(self, hostname, ip_address, server_type):
        cur = self.conn.cursor()
        cur.execute("SELECT id FROM server WHERE hostname=? AND ip_address=? AND server_type=?", 
                    (hostname, ip_address, server_type))
        row = cur.fetchone()
        if row:
            return row[0]
        cur.execute("INSERT INTO server (hostname, ip_address, server_type) VALUES (?, ?, ?)", 
                    (hostname, ip_address, server_type))
        self.conn.commit()
        return cur.lastrowid

    def insert_log_entry(self, server_id, recv_time, log_source, content):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO log_entry (server_id, recv_time, log_source, content) VALUES (?, ?, ?, ?)", 
                    (server_id, recv_time, log_source, content))
        self.conn.commit()
        log_entry_id = cur.lastrowid

        # --- Sigma Rule Matching ---
        log_entry = {
            'id': log_entry_id,
            'timestamp': recv_time,
            'log_type': log_source,
            'raw_line': content,
            'hostname': None,
            'ip_address': None
        }
        alerts = IroncladParser.sigma_engine.match_log(log_entry)
        if alerts:
            for alert in alerts:
                cur.execute(
                    """
                    INSERT INTO alert (log_entry_id, server_id, rule_id, severity, title, description, alert_metadata, triggered_at, resolved)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        log_entry_id,
                        server_id,
                        alert.get('rule_id'),
                        alert.get('severity'),
                        alert.get('rule_title'),
                        alert.get('rule_description'),
                        json.dumps(alert),
                        alert.get('timestamp'),
                        0
                    )
                )
            self.conn.commit()
        return log_entry_id

    # ------------------ Log Parsing ------------------
    @staticmethod
    def parse_windows_message_field(message_str):
        if not message_str:
            return {}
        extracted_data = {}
        current_section = ""
        lines = message_str.replace('\r', '').split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                if not value:
                    current_section = key.replace(" ", "")
                else:
                    clean_key = key.replace(" ", "_")
                    if current_section:
                        final_key = f"{current_section}_{clean_key}"
                    else:
                        final_key = clean_key
                    extracted_data[final_key] = value
        return extracted_data

    def process_batch(self, batch_data):
        if not batch_data:
            return
        text_logs = []
        for item in batch_data:
            raw_line = item.get("line", "").strip()
            src_ip = item.get("src_ip", "")
            recv_time = item.get("recv_time", "")
            if raw_line.startswith("{"):
                # JSON log (Windows)
                try:
                    parsed_obj = json.loads(raw_line)
                    hostname = parsed_obj.get("hostname", "")
                    log_source = "windows"
                    server_id = self.get_or_create_server(hostname, src_ip, log_source)
                    self.insert_log_entry(server_id, recv_time, log_source, raw_line)
                except json.JSONDecodeError:
                    text_logs.append(item)
            else:
                text_logs.append(item)

        for item in text_logs:
            raw_line = item.get("line", "").strip()
            src_ip = item.get("src_ip", "")
            recv_time = item.get("recv_time", "")

            # --- Nginx logs ---
            nginx_match = re.match(self.nginx_pattern, raw_line)
            if nginx_match:
                details = nginx_match.groupdict()
                hostname = src_ip
                log_source = "nginx"
                server_id = self.get_or_create_server(hostname, src_ip, log_source)
                self.insert_log_entry(server_id, recv_time, log_source, raw_line)
                continue

            # --- Linux logs ---
            linux_match = re.match(self.linux_header_pattern, raw_line)
            if linux_match:
                details = linux_match.groupdict()
                details["raw_message"] = details.get("raw_message", "")
                hostname = details.get("hostname", src_ip)
                log_source = "linux"
                server_id = self.get_or_create_server(hostname, src_ip, log_source)
                self.insert_log_entry(server_id, recv_time, log_source, raw_line)
                # Optional SSH detection
                ssh_pattern = r"(?P<ssh_action>Accepted|Failed)\s+(?:password|publickey)\s+for\s+(?:invalid\s+user\s+)?(?P<ssh_user>\S+)\s+from\s+(?P<ssh_ip>\S+)"
                ssh_match = re.search(ssh_pattern, details["raw_message"])
                if ssh_match:
                    details.update(ssh_match.groupdict())
                continue

            # --- Zeek conn.log ---
            zeek_match = re.match(self.zeek_conn_pattern, raw_line)
            if zeek_match:
                details = zeek_match.groupdict()
                hostname = details.get("orig_h")
                log_source = "zeek_conn"
                server_id = self.get_or_create_server(hostname, details.get("orig_h"), log_source)
                self.insert_log_entry(server_id, recv_time, log_source, json.dumps(details))
                continue

# ------------------ FastAPI & CORS ------------------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------ File Ingestion ------------------
def parse_and_ingest_file(file_path, log_source, hostname=None, ip_address=None):
    parser = IroncladParser()
    batch = []
    now = datetime.datetime.now().isoformat()
    ext = os.path.splitext(file_path)[1].lower()

    # Windows JSON logs
    if log_source == "windows" and ext == ".json":
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                    batch.append({
                        'recv_time': now,
                        'src_ip': 'file_upload',
                        'line': json.dumps(event)
                    })
                except Exception as e:
                    print(f"[WARN] Could not parse JSON line: {e}")
        parser.process_batch(batch)
        return {"status": "success", "message": f"Ingested {len(batch)} windows log events from {file_path}"}

    # Linux / Nginx logs
    elif log_source in ["linux", "nginx"] and ext in [".log", ".csv"]:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                batch.append({
                    'recv_time': now,
                    'src_ip': 'file_upload',
                    'line': line
                })
        parser.process_batch(batch)
        return {"status": "success", "message": f"Ingested {len(batch)} {log_source} log lines from {file_path}"}

    # Zeek conn.log
    elif log_source == "zeek_conn" and ext in [".log", ".conn", ".txt"]:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                batch.append({
                    'recv_time': now,
                    'src_ip': 'file_upload',
                    'line': line
                })
        parser.process_batch(batch)
        return {"status": "success", "message": f"Ingested {len(batch)} Zeek conn.log events"}

    else:
        return {"status": "error", "message": f"Unsupported file type or log_source: {ext}, {log_source}"}

# ------------------ FastAPI Endpoint ------------------
@app.post("/ingest_logs/")
async def ingest_logs(
    file: UploadFile = File(...),
    log_source: str = Form(...)
):
    file_location = f"collected_logs/processed/{file.filename}"
    os.makedirs(os.path.dirname(file_location), exist_ok=True)
    with open(file_location, "wb") as f:
        f.write(await file.read())
    result = parse_and_ingest_file(file_location, log_source)
    return result



with new parser for conn.log