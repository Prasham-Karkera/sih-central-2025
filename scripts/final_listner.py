import socket
import threading
import os
import asyncio
import queue
import time
import datetime
import json
import polars as pl
import sqlite3
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncio.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv

# --- CONFIGURATION ---
HOST = "0.0.0.0"
SYSLOG_PORT = 5140
SNMP_PORT = 1162
LOG_DIR = "./collected_logs"
BATCH_SIZE = 1000        
BATCH_TIMEOUT = 5.0      


# Ensure directories exist
for sub in ["raw", "processed/windows", "processed/linux", "processed/nginx", "traps"]:
    os.makedirs(os.path.join(LOG_DIR, sub), exist_ok=True)

# --- SQLITE DB SETUP ---
DB_PATH = "./collected_logs/ironclad_logs.db"

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cur = conn.cursor()
    # Create tables
    cur.executescript('''
    CREATE TABLE IF NOT EXISTS server (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        hostname TEXT,
        ip_address TEXT,
        server_type TEXT
    );
    CREATE TABLE IF NOT EXISTS log_entry (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER,
        recv_time TEXT,
        log_source TEXT,
        content TEXT,
        FOREIGN KEY(server_id) REFERENCES server(id)
    );
    CREATE TABLE IF NOT EXISTS linux_log_details (
        log_entry_id INTEGER,
        timestamp TEXT,
        app_name TEXT,
        pid INTEGER,
        raw_message TEXT,
        ssh_action TEXT,
        ssh_user TEXT,
        ssh_ip TEXT,
        FOREIGN KEY(log_entry_id) REFERENCES log_entry(id)
    );
    CREATE TABLE IF NOT EXISTS nginx_log_details (
        log_entry_id INTEGER,
        remote_addr TEXT,
        remote_user TEXT,
        time_local TEXT,
        request_method TEXT,
        request_uri TEXT,
        server_protocol TEXT,
        status INTEGER,
        body_bytes_sent INTEGER,
        http_referer TEXT,
        http_user_agent TEXT,
        FOREIGN KEY(log_entry_id) REFERENCES log_entry(id)
    );
    CREATE TABLE IF NOT EXISTS windows_log_details (
        log_entry_id INTEGER,
        content TEXT,
        FOREIGN KEY(log_entry_id) REFERENCES log_entry(id)
    );
    ''')
    conn.commit()
    conn.close()

init_db()

# Shared Queue 
log_queue = queue.Queue()

# --- PART 1: PARSER ENGINE ---

class IroncladParser:
    def __init__(self):
        # ...existing code...
        self.conn = get_db_connection()
        self.linux_header_pattern = (
            r"(?P<timestamp>"
            r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*[Z\+\-\:0-9]*|" 
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

    def get_or_create_server(self, hostname, ip_address, server_type):
        cur = self.conn.cursor()
        cur.execute("SELECT id FROM server WHERE hostname=? AND ip_address=? AND server_type=?", (hostname, ip_address, server_type))
        row = cur.fetchone()
        if row:
            return row[0]
        cur.execute("INSERT INTO server (hostname, ip_address, server_type) VALUES (?, ?, ?)", (hostname, ip_address, server_type))
        self.conn.commit()
        return cur.lastrowid

    def insert_log_entry(self, server_id, recv_time, log_source, content):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO log_entry (server_id, recv_time, log_source, content) VALUES (?, ?, ?, ?)", (server_id, recv_time, log_source, content))
        self.conn.commit()
        return cur.lastrowid

    def insert_linux_details(self, log_entry_id, details):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO linux_log_details (log_entry_id, timestamp, app_name, pid, raw_message, ssh_action, ssh_user, ssh_ip) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (log_entry_id, details.get('timestamp'), details.get('app_name'), details.get('pid'), details.get('raw_message'), details.get('ssh_action'), details.get('ssh_user'), details.get('ssh_ip')))
        self.conn.commit()

    def insert_nginx_details(self, log_entry_id, details):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO nginx_log_details (log_entry_id, remote_addr, remote_user, time_local, request_method, request_uri, server_protocol, status, body_bytes_sent, http_referer, http_user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (log_entry_id, details.get('remote_addr'), details.get('remote_user'), details.get('time_local'), details.get('request_method'), details.get('request_uri'), details.get('server_protocol'), details.get('status'), details.get('body_bytes_sent'), details.get('http_referer'), details.get('http_user_agent')))
        self.conn.commit()

    def insert_windows_details(self, log_entry_id, content):
        cur = self.conn.cursor()
        cur.execute("INSERT INTO windows_log_details (log_entry_id, content) VALUES (?, ?)", (log_entry_id, content))
        self.conn.commit()

    @staticmethod
    def parse_windows_message_field(message_str):
        """
        Parses the multi-line Windows Event 'message' string into a flat dictionary.
        """
        if not message_str:
            return {}

        extracted_data = {}
        current_section = ""
        
        # Split by newlines (handle \r\n and \n)
        lines = message_str.replace('\r', '').split('\n')

        for line in lines:
            line = line.strip()
            if not line:
                continue

            if ':' in line:
                # Split only on the FIRST colon found
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()

                if not value:
                    # Header detected (e.g. "Subject:")
                    current_section = key.replace(" ", "")
                else:
                    # Key-Value pair detected
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

        json_logs = []
        text_logs = []

        for item in batch_data:
            raw_line = item.get("line", "").strip()
            src_ip = item.get("src_ip", "")
            recv_time = item.get("recv_time", "")

            # Windows JSON log
            if raw_line.startswith("{"):
                try:
                    parsed_obj = json.loads(raw_line)
                    hostname = parsed_obj.get("hostname", "")
                    log_source = "windows"
                    server_id = self.get_or_create_server(hostname, src_ip, log_source)
                    log_entry_id = self.insert_log_entry(server_id, recv_time, log_source, raw_line)
                    self.insert_windows_details(log_entry_id, raw_line)
                except json.JSONDecodeError:
                    text_logs.append(item)
            else:
                text_logs.append(item)

        # Linux/Nginx logs
        for item in text_logs:
            raw_line = item.get("line", "").strip()
            src_ip = item.get("src_ip", "")
            recv_time = item.get("recv_time", "")
            # Try to parse as nginx
            import re
            nginx_match = re.match(self.nginx_pattern, raw_line)
            if nginx_match:
                details = nginx_match.groupdict()
                hostname = src_ip  # Nginx logs may not have hostname, use src_ip
                log_source = "nginx"
                server_id = self.get_or_create_server(hostname, src_ip, log_source)
                log_entry_id = self.insert_log_entry(server_id, recv_time, log_source, raw_line)
                self.insert_nginx_details(log_entry_id, details)
            else:
                # Try to parse as linux
                linux_match = re.match(self.linux_header_pattern, raw_line)
                if linux_match:
                    details = linux_match.groupdict()
                    details["raw_message"] = details.get("raw_message", "")
                    hostname = details.get("hostname", src_ip)
                    log_source = "linux"
                    server_id = self.get_or_create_server(hostname, src_ip, log_source)
                    log_entry_id = self.insert_log_entry(server_id, recv_time, log_source, raw_line)
                    # SSH enrichment
                    ssh_pattern = r"(?P<ssh_action>Accepted|Failed)\s+(?:password|publickey)\s+for\s+(?:invalid\s+user\s+)?(?P<ssh_user>\S+)\s+from\s+(?P<ssh_ip>\S+)"
                    ssh_match = re.search(ssh_pattern, details["raw_message"])
                    if ssh_match:
                        details.update(ssh_match.groupdict())
                    self.insert_linux_details(log_entry_id, details)

    def _process_windows_json(self, log_list):
        """
        Handles dynamic JSON from Windows and saves as JSON.
        """
        try:
            # Polars will automatically infer schema from the dict keys (including new parsed fields)
            df = pl.DataFrame(log_list)

            # --- SIGMA NORMALIZATION ---
            # Rename Windows native XML fields to Sigma standard fields
            rename_map = {
                "CommandLine": "cmdline",
                "ParentProcessName": "parent",
                "NewProcessName": "name",
                "Image": "image",
                "TargetUserName": "user",
                "TargetFilename": "target_file",
                "LogName": "channel" # Ensure channel name is standard
            }
            
            existing_cols = set(df.columns)
            valid_renames = {k: v for k, v in rename_map.items() if k in existing_cols}
            
            if valid_renames:
                df = df.rename(valid_renames)

            # --- CLEANUP PARENT/NAME PATHS ---
            if "parent" in df.columns:
                df = df.with_columns(
                    pl.col("parent").str.split("\\").list.last().alias("parent_name")
                )
            
            # Write to JSON (NDJSON format)
            self._write_json(df, "windows")
            
        except Exception as e:
            print(f"[Parser Error - Windows] {e}")

    def _process_text_logs(self, log_list):
        """
        Handles standard Regex parsing for Linux/Nginx (Saves as CSV)
        """
        df = pl.DataFrame(log_list)
        
        df_nginx = df.filter(pl.col("line").str.contains(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-"))
        df_linux = df.filter(~pl.col("line").str.contains(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-"))

        if not df_nginx.is_empty():
            parsed = df_nginx.with_columns(
                pl.col("line").str.extract_groups(self.nginx_pattern).alias("http")
            ).unnest("http")
            self._write_csv(parsed, "nginx")

        if not df_linux.is_empty():
            parsed = df_linux.with_columns(
                pl.col("line").str.extract_groups(self.linux_header_pattern).alias("meta")
            ).unnest("meta")
            parsed = self._enrich_ssh(parsed)
            self._write_csv(parsed, "linux")

    def _enrich_ssh(self, df):
        ssh_pattern = r"(?P<ssh_action>Accepted|Failed)\s+(?:password|publickey)\s+for\s+(?:invalid\s+user\s+)?(?P<ssh_user>\S+)\s+from\s+(?P<ssh_ip>\S+)"
        return df.with_columns(
            pl.when(pl.col("app_name") == "sshd")
            .then(pl.col("raw_message").str.extract_groups(ssh_pattern))
            .otherwise(None)
            .alias("ssh_details")
        ).unnest("ssh_details")

    def _write_csv(self, df, category):
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{LOG_DIR}/processed/{category}/batch_{ts}.csv"
        df.write_csv(filename)
        print(f"[Parser] Wrote {len(df)} rows to {category} (CSV)")

    def _write_json(self, df, category):
        """
        Writes a batch of logs to a JSON file.
        Uses NDJSON (Newline Delimited JSON) format.
        """
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{LOG_DIR}/processed/{category}/batch_{ts}.json"
        
        # UPDATED: Changed to write_ndjson for cleaner format
        df.write_ndjson(filename)
        
        print(f"[Parser] Wrote {len(df)} records to {category} (JSON)")

# --- PART 2: THREAD WORKERS ---

def worker_processor():
    parser = IroncladParser()
    buffer = []
    last_flush = time.time()

    print("[Worker] Processor thread started.")
    
    while True:
        try:
            item = log_queue.get(timeout=1.0)
            buffer.append(item)
        except queue.Empty:
            pass

        time_since_flush = time.time() - last_flush
        if (len(buffer) >= BATCH_SIZE) or (buffer and time_since_flush >= BATCH_TIMEOUT):
            parser.process_batch(buffer)
            buffer = []
            last_flush = time.time()

def worker_syslog_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, SYSLOG_PORT))
    print(f"[Syslog] Listening on UDP {HOST}:{SYSLOG_PORT}")
    
    # Ensure raw file exists or append
    raw_file = open(f"{LOG_DIR}/raw/syslog_stream.log", "a", encoding="utf-8")

    while True:
        try:
            data, addr = sock.recvfrom(65535)
            message = data.decode("utf-8", errors="replace").strip()
            recv_time = datetime.datetime.now().isoformat()

            raw_file.write(f"{recv_time} [{addr[0]}] {message}\n")
            raw_file.flush()

            log_queue.put({
                "recv_time": recv_time, 
                "src_ip": addr[0], 
                "line": message
            })
            
        except Exception as e:
            print(f"[Syslog Error] {e}")

# --- PART 3: SNMP TRAP LISTENER ---
def process_snmp_trap(snmpEngine, stateReference, contextEngineId, contextName, varBinds, cbCtx):
    transportDomain, transportAddress = snmpEngine.msgAndPduDsp.getTransportInfo(stateReference)
    source_ip = transportAddress[0]
    output_file = f"{LOG_DIR}/traps/network_traps.txt"
    timestamp = datetime.datetime.now().isoformat()
    print(f"[SNMP] Trap from {source_ip}")
    with open(output_file, "a", encoding="utf-8") as f:
        f.write(f"--- {timestamp} TRAP FROM {source_ip} ---\n")
        for name, val in varBinds:
            f.write(f"{name.prettyPrint()} = {val.prettyPrint()}\n")
        f.write("\n")

def start_snmp_listener():
    print(f"[SNMP] Listening on UDP {HOST}:{SNMP_PORT}")
    snmpEngine = engine.SnmpEngine()
    config.add_transport(
        snmpEngine,
        udp.DOMAIN_NAME,
        udp.UdpTransport().open_server_mode((HOST, SNMP_PORT))
    )
    config.add_v1_system(snmpEngine, 'my-area', 'public')
    ntfrcv.NotificationReceiver(snmpEngine, process_snmp_trap)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_forever()

if __name__ == "__main__":
    print("--- IRONCLAD INGESTER STARTED (Windows JSON Mode) ---")
    
    t_processor = threading.Thread(target=worker_processor, daemon=True)
    t_processor.start()

    t_syslog = threading.Thread(target=worker_syslog_listener, daemon=True)
    t_syslog.start()

    try:
        start_snmp_listener()
    except KeyboardInterrupt:
        print("\nStopping services...")