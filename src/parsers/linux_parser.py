"""
Linux Parser Module

Handles parsing of Linux syslog format logs with SSH event enrichment.
Supports multiple timestamp formats and common Linux system services.
"""

import re
import datetime
import os
from typing import Dict, List, Any, Optional
from pathlib import Path
import polars as pl
from src.base.base_parser import BaseParser


class LinuxParser(BaseParser):
    """
    Parser for Linux syslog format logs.
    
    Features:
    - Syslog header parsing (timestamp, hostname, app, pid)
    - Multiple timestamp format support
    - SSH event detection and enrichment
    - Service-specific message parsing
    """
    
    def __init__(self, output_dir: str = "./collected_logs/processed/linux"):
        """Initialize Linux parser with regex patterns.
        
        Args:
            output_dir: Directory path for writing parsed log files
        """
        self.output_dir = output_dir
        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Main syslog header pattern
        self.header_pattern = re.compile(
            r"(?P<timestamp>"
            r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}[\.\d]*[Z\+\-\:0-9]*|"  # ISO format
            r"^\S+\s+\S+\s+\S+|"  # BSD syslog format (e.g., "Dec 06 14:30:45")
            r"^\S+"  # Fallback for other formats
            r")"
            r"\s+"
            r"(?P<hostname>\S+)"
            r"\s+"
            r"(?P<app_name>[^:\[\s]+)"
            r"(?:\[(?P<pid>\d+)\])?"
            r":\s+"
            r"(?P<raw_message>.*)"
        )
        
        # SSH event pattern for enrichment
        self.ssh_pattern = re.compile(
            r"(?P<ssh_action>Accepted|Failed)\s+"
            r"(?:password|publickey)\s+for\s+"
            r"(?:invalid\s+user\s+)?"
            r"(?P<ssh_user>\S+)\s+from\s+"
            r"(?P<ssh_ip>\S+)"
        )
    
    def get_log_type(self) -> str:
        """Return log type identifier."""
        return "linux"
    
    def can_parse(self, raw_log: str) -> bool:
        """
        Check if log matches Linux syslog format.
        
        Args:
            raw_log: Raw log line
            
        Returns:
            True if log matches syslog pattern
        """
        raw_log = raw_log.strip()
        
        # Reject if it looks like JSON
        if raw_log.startswith("{"):
            return False
        
        # Reject if it looks like Nginx (starts with IP address)
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+-", raw_log):
            return False
        
        # Check if it matches syslog header pattern
        return self.header_pattern.match(raw_log) is not None
    
    def parse(self, raw_log: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        Parse a single Linux syslog line.
        
        Args:
            raw_log: Raw syslog line
            metadata: Optional metadata (src_ip, recv_time)
            
        Returns:
            Parsed dictionary or None if parsing fails
        """
        match = self.header_pattern.match(raw_log.strip())
        
        if not match:
            return None
        
        parsed = match.groupdict()
        
        # Add metadata if provided
        if metadata:
            parsed.update(metadata)
        
        # Convert PID to integer if present
        if parsed.get("pid"):
            try:
                parsed["pid"] = int(parsed["pid"])
            except (ValueError, TypeError):
                parsed["pid"] = None
        
        # Enrich with SSH data if applicable
        return self.enrich(parsed)
    
    def parse_batch(self, logs: List[Dict[str, Any]]) -> Optional[pl.DataFrame]:
        """
        Parse a batch of Linux logs into a DataFrame.
        
        Args:
            logs: List of log dictionaries with 'line', 'src_ip', 'recv_time'
            
        Returns:
            Polars DataFrame with parsed and enriched data, or None if no logs match
        """
        parsed_logs = []
        
        for log in logs:
            raw_line = log.get("line", "").strip()
            
            if not self.can_parse(raw_line):
                continue
            
            metadata = {
                "src_ip": log.get("src_ip", ""),
                "recv_time": log.get("recv_time", "")
            }
            
            parsed = self.parse(raw_line, metadata)
            if parsed:
                parsed_logs.append(parsed)
        
        if not parsed_logs:
            return None
        
        # Create DataFrame
        df = pl.DataFrame(parsed_logs)
        
        # Apply batch-level SSH enrichment
        df = self._enrich_ssh_batch(df)
        
        return df
    
    def enrich(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a single parsed Linux log entry.
        
        Currently handles SSH event extraction.
        
        Args:
            parsed_data: Parsed log dictionary
            
        Returns:
            Enriched dictionary with SSH fields if applicable
        """
        raw_message = parsed_data.get("raw_message", "")
        app_name = parsed_data.get("app_name", "")
        
        # Only enrich SSH logs
        if app_name == "sshd" and raw_message:
            ssh_match = self.ssh_pattern.search(raw_message)
            if ssh_match:
                ssh_data = ssh_match.groupdict()
                parsed_data.update(ssh_data)
        
        return parsed_data
    
    def _enrich_ssh_batch(self, df: pl.DataFrame) -> pl.DataFrame:
        """
        Apply SSH enrichment to entire DataFrame using Polars operations.
        
        More efficient than row-by-row enrichment for large batches.
        
        Args:
            df: Polars DataFrame with parsed Linux logs
            
        Returns:
            DataFrame with SSH enrichment columns added
        """
        if "app_name" not in df.columns or "raw_message" not in df.columns:
            return df
        
        # Extract SSH details using regex on raw_message
        ssh_pattern_str = (
            r"(?P<ssh_action>Accepted|Failed)\s+"
            r"(?:password|publickey)\s+for\s+"
            r"(?:invalid\s+user\s+)?"
            r"(?P<ssh_user>\S+)\s+from\s+"
            r"(?P<ssh_ip>\S+)"
        )
        
        # Apply SSH parsing only to sshd logs
        df = df.with_columns(
            pl.when(pl.col("app_name") == "sshd")
            .then(pl.col("raw_message").str.extract_groups(ssh_pattern_str))
            .otherwise(None)
            .alias("ssh_details")
        )
        
        # Unnest SSH details into separate columns
        if "ssh_details" in df.columns:
            df = df.unnest("ssh_details")
        
        return df
    
    def write_to_file(self, df: pl.DataFrame, format: str = "csv") -> str:
        """Write parsed Linux logs to file.
        
        Args:
            df: Polars DataFrame with parsed logs
            format: Output format ('csv' or 'json')
            
        Returns:
            Path to the written file
        """
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if format == "json":
            filename = os.path.join(self.output_dir, f"batch_{timestamp}.json")
            df.write_ndjson(filename)
        else:  # csv
            filename = os.path.join(self.output_dir, f"batch_{timestamp}.csv")
            df.write_csv(filename)
        
        print(f"[LinuxParser] Wrote {len(df)} records to {filename}")
        return filename
