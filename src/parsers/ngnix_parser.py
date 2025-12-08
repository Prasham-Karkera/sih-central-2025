"""
Nginx Parser Module

Handles parsing of Nginx access and error logs.
Supports combined log format and custom formats.
"""

import re
import datetime
import os
from typing import Dict, List, Any, Optional
from pathlib import Path
import polars as pl
from src.base.base_parser import BaseParser


class NginxParser(BaseParser):
    """
    Parser for Nginx access logs.
    
    Features:
    - Combined log format parsing
    - HTTP request method/URI/protocol extraction
    - Status code and response size parsing
    - User agent and referer extraction
    """
    
    def __init__(self, output_dir: str = "./collected_logs/processed/nginx"):
        """Initialize Nginx parser with regex pattern for combined log format.
        
        Args:
            output_dir: Directory path for writing parsed log files
        """
        self.output_dir = output_dir
        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Nginx combined log format pattern (with optional referer and user-agent)
        self.access_pattern = re.compile(
            r"(?P<remote_addr>[\d\.]+)\s+"
            r"-\s+(?P<remote_user>\S+)\s+"
            r"\[(?P<time_local>.*?)\]\s+"
            r'"(?P<request_method>\S+)\s+'
            r'(?P<request_uri>\S+)\s+'
            r'(?P<server_protocol>[^"]+)"\s+'
            r'(?P<status>\d+)\s+'
            r'(?P<body_bytes_sent>\d+)'
            r'(?:\s+"(?P<http_referer>[^"]*)"\s+"(?P<http_user_agent>[^"]*)")?'
        )
    
    def get_log_type(self) -> str:
        """Return log type identifier."""
        return "nginx"
    
    def can_parse(self, raw_log: str) -> bool:
        """
        Check if log matches Nginx access log format.
        
        Args:
            raw_log: Raw log line
            
        Returns:
            True if log matches Nginx pattern (starts with IP address and has bracketed timestamp)
        """
        raw_log = raw_log.strip()
        
        # Nginx access logs: IP - user [timestamp] "request" status size
        # Check for IP at start and bracketed timestamp
        return (re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+", raw_log) is not None 
                and "[" in raw_log and "]" in raw_log and '"' in raw_log)
    
    def parse(self, raw_log: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        Parse a single Nginx access log line.
        
        Args:
            raw_log: Raw Nginx log line
            metadata: Optional metadata (src_ip, recv_time)
            
        Returns:
            Parsed dictionary or None if parsing fails
        """
        match = self.access_pattern.match(raw_log.strip())
        
        if not match:
            return None
        
        parsed = match.groupdict()
        
        # Add metadata if provided
        if metadata:
            parsed.update(metadata)
        
        # Convert numeric fields
        try:
            parsed["status"] = int(parsed["status"])
            parsed["body_bytes_sent"] = int(parsed["body_bytes_sent"])
        except (ValueError, TypeError, KeyError):
            pass
        
        return self.enrich(parsed)
    
    def parse_batch(self, logs: List[Dict[str, Any]]) -> Optional[pl.DataFrame]:
        """
        Parse a batch of Nginx logs into a DataFrame.
        
        Args:
            logs: List of log dictionaries with 'line', 'src_ip', 'recv_time'
            
        Returns:
            Polars DataFrame with parsed data, or None if no logs match
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
        
        # Apply normalization
        df = self.normalize(df)
        
        return df
    
    def enrich(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich parsed Nginx log data.
        
        Potential enrichments:
        - Parse request_uri for query parameters
        - Categorize status codes (2xx success, 4xx client error, 5xx server error)
        - Parse user agent for browser/OS/device info
        - GeoIP lookup for remote_addr
        - Convert time_local to standard timestamp
        
        Args:
            parsed_data: Parsed log dictionary
            
        Returns:
            Enriched dictionary
        """
        # Parse timestamp from time_local (06/Dec/2025:04:17:07 +0000)
        time_local = parsed_data.get("time_local")
        if time_local:
            try:
                from datetime import datetime
                # Parse nginx timestamp format
                dt = datetime.strptime(time_local.split()[0], "%d/%b/%Y:%H:%M:%S")
                parsed_data["timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, IndexError):
                pass
        
        # Add hostname from remote_addr if not provided
        if "hostname" not in parsed_data:
            parsed_data["hostname"] = parsed_data.get("remote_addr", "unknown")
        
        # Add status category
        status = parsed_data.get("status")
        if status:
            if 200 <= status < 300:
                parsed_data["status_category"] = "success"
            elif 300 <= status < 400:
                parsed_data["status_category"] = "redirect"
            elif 400 <= status < 500:
                parsed_data["status_category"] = "client_error"
            elif 500 <= status < 600:
                parsed_data["status_category"] = "server_error"
            else:
                parsed_data["status_category"] = "unknown"
        
        return parsed_data
    
    def normalize(self, df: pl.DataFrame) -> pl.DataFrame:
        """
        Apply normalization to Nginx fields.
        
        Args:
            df: Polars DataFrame with raw Nginx fields
            
        Returns:
            Normalized DataFrame
        """
        # Add any Nginx-specific normalizations here
        # For now, pass through as Nginx field names are already clear
        return df
    
    def write_to_file(self, df: pl.DataFrame, format: str = "csv") -> str:
        """Write parsed Nginx logs to file.
        
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
        
        print(f"[NginxParser] Wrote {len(df)} records to {filename}")
        return filename
