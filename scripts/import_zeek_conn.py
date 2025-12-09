"""
Import Zeek conn.log into the database.

Usage:
  uv run python scripts/import_zeek_conn.py conn.log.txt

Parses each line, inserts a Server (orig_h), a LogEntry (log_source='zeek_conn'),
then a ZeekConnDetails row with structured fields.
"""

from src.db.models import Server, LogEntry, ZeekConnDetails
from src.db.setup import SessionLocal, init_db
import sys
import json
import re
from datetime import datetime
from pathlib import Path

# Ensure src imports
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


CONN_PATTERN = re.compile(
    r"(?P<ts>\d+\.\d+)\s+"
    r"(?P<uid>\S+)\s+"
    r"(?P<orig_h>\S+)\s+"
    r"(?P<orig_p>\d+)\s+"
    r"(?P<resp_h>\S+)\s+"
    r"(?P<resp_p>\d+)\s+"
    r"(?P<proto>\S+)\s+"
    r"(?P<service>\S+)\s+"
    r"(?P<duration>\S+)\s+"
    r"(?P<orig_bytes>\S+)\s+"
    r"(?P<resp_bytes>\S+)\s+"
    r"(?P<conn_state>\S+)\s+"
    r"(?P<local_orig>\S+)\s+"
    r"(?P<missed_bytes>\d+)\s+"
    r"(?P<history>\S+)\s+"
    r"(?P<orig_pkts>\d+)\s+"
    r"(?P<orig_ip_bytes>\d+)\s+"
    r"(?P<resp_pkts>\d+)\s+"
    r"(?P<resp_ip_bytes>\d+)(?:\s+\(empty\)|\s+\S+)?$"
)


def get_or_create_server(db, hostname: str, ip: str, server_type: str) -> int:
    srv = db.query(Server).filter_by(hostname=hostname,
                                     ip_address=ip, server_type=server_type).first()
    if srv:
        return srv.id
    srv = Server(hostname=hostname or ip or "unknown",
                 ip_address=ip, server_type=server_type)
    db.add(srv)
    db.commit()
    db.refresh(srv)
    return srv.id


def main(path: str):
    init_db()
    db = SessionLocal()
    inserted = 0
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = CONN_PATTERN.match(line)
            if not m:
                continue
            d = m.groupdict()
            # Convert values
            try:
                ts_epoch = float(d["ts"])
                ts_dt = datetime.utcfromtimestamp(ts_epoch)
            except Exception:
                ts_dt = None
            for k in ("orig_p", "resp_p", "missed_bytes", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"):
                try:
                    d[k] = int(d[k])
                except Exception:
                    d[k] = None
            for k in ("orig_bytes", "resp_bytes"):
                v = d.get(k)
                if v == "-":
                    d[k] = None
                else:
                    try:
                        d[k] = int(v)
                    except Exception:
                        d[k] = None

            # Upsert server & insert log entry
            server_id = get_or_create_server(db, hostname=d.get(
                "orig_h"), ip=d.get("orig_h"), server_type="zeek_conn")
            log = LogEntry(server_id=server_id, recv_time=ts_dt,
                           log_source="zeek_conn", content=json.dumps(d))
            db.add(log)
            db.commit()
            db.refresh(log)

            details = ZeekConnDetails(
                log_entry_id=log.id,
                ts=ts_dt,
                uid=d.get("uid"),
                orig_h=d.get("orig_h"),
                orig_p=d.get("orig_p"),
                resp_h=d.get("resp_h"),
                resp_p=d.get("resp_p"),
                proto=d.get("proto"),
                service=d.get("service"),
                duration=d.get("duration"),
                orig_bytes=d.get("orig_bytes"),
                resp_bytes=d.get("resp_bytes"),
                conn_state=d.get("conn_state"),
                local_orig=d.get("local_orig"),
                missed_bytes=d.get("missed_bytes"),
                history=d.get("history"),
                orig_pkts=d.get("orig_pkts"),
                orig_ip_bytes=d.get("orig_ip_bytes"),
                resp_pkts=d.get("resp_pkts"),
                resp_ip_bytes=d.get("resp_ip_bytes"),
                tunnel_parents=None,
            )
            db.add(details)
            db.commit()
            inserted += 1
    db.close()
    print(f"[Import] Inserted {inserted} Zeek conn rows")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/import_zeek_conn.py <conn.log.txt>")
        sys.exit(1)
    main(sys.argv[1])
