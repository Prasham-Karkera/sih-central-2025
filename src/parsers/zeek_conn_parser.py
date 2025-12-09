"""
Zeek Conn Parser

Parses Zeek conn.log lines into structured fields based on schema.
Integrates with BaseParser used by IngestionWorker's ParserManager.
"""

import re
from typing import Dict, Any, Optional, List
from pathlib import Path
import polars as pl
from datetime import datetime

from src.base.base_parser import BaseParser


class ZeekConnParser(BaseParser):
    """Parser for Zeek conn.log entries."""

    def __init__(self, output_dir: str = "./collected_logs/processed/zeek_conn"):
        self.output_dir = output_dir
        Path(output_dir).mkdir(parents=True, exist_ok=True)

        # Regex pattern mapping the conn.log fields (space or tab separated)
        self.conn_pattern = re.compile(
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

    def get_log_type(self) -> str:
        return "zeek_conn"

    def can_parse(self, raw_log: str) -> bool:
        raw_log = raw_log.strip()
        if not raw_log or raw_log.startswith("#"):
            return False
        # Starts with epoch float and matches expected columns
        return self.conn_pattern.match(raw_log) is not None

    def parse(self, raw_log: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        m = self.conn_pattern.match(raw_log.strip())
        if not m:
            return None
        d = m.groupdict()

        # Normalize numeric fields and epoch timestamp
        try:
            d["ts_epoch"] = float(d.get("ts", 0.0))
            d["timestamp"] = datetime.utcfromtimestamp(
                d["ts_epoch"]).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            d["timestamp"] = None
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

        if metadata:
            d.update(metadata)
        # required for ingestion worker save step
        d["hostname"] = d.get("orig_h")
        return d

    def parse_batch(self, logs: List[Dict[str, Any]]) -> Optional[pl.DataFrame]:
        rows: List[Dict[str, Any]] = []
        for log in logs:
            raw_line = log.get("line", "")
            if not self.can_parse(raw_line):
                continue
            md = {"src_ip": log.get("src_ip"),
                  "recv_time": log.get("recv_time")}
            parsed = self.parse(raw_line, md)
            if parsed:
                rows.append(parsed)
        if not rows:
            return None
        return pl.DataFrame(rows)
