"""
Windows Parser Module

Handles parsing of Windows Event Log JSON format with dynamic schema support.
Includes Sigma normalization for security-focused field standardization.
"""

import json
import re
import datetime
import os
from typing import Dict, List, Any, Optional
from pathlib import Path
import polars as pl
from src.base.base_parser import BaseParser


class WindowsParser(BaseParser):
    """
    Parser for Windows Event Logs in JSON format.
    
    Features:
    - JSON detection and parsing
    - Dynamic schema handling
    - Sigma field normalization
    - Message field extraction
    - Path cleanup for process names
    """
    
    def __init__(self, output_dir: str = "./collected_logs/processed/windows"):
        """Initialize Windows parser with Sigma normalization mappings.
        
        Args:
            output_dir: Directory path for writing parsed log files
        """
        self.sigma_field_mapping = {
            "CommandLine": "cmdline",
            "ParentProcessName": "parent",
            "NewProcessName": "name",
            "Image": "image",
            "TargetUserName": "user",
            "TargetFilename": "target_file",
            "LogName": "channel",
            # Additional mappings for real log format
            "CallerProcessName": "process_name",
            "SubjectUserName": "subject_user",
        }
        self.output_dir = output_dir
        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    def get_log_type(self) -> str:
        """Return log type identifier."""
        return "windows"
    
    def can_parse(self, raw_log: str) -> bool:
        """
        Check if log is Windows JSON format.
        
        Args:
            raw_log: Raw log line
            
        Returns:
            True if line starts with '{' and is valid JSON
        """
        raw_log = raw_log.strip()
        if not raw_log.startswith("{"):
            return False
        
        try:
            json.loads(raw_log)
            return True
        except json.JSONDecodeError:
            return False
    
    def parse(self, raw_log: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        Parse a single Windows JSON log line.
        
        Args:
            raw_log: Raw JSON log line
            metadata: Optional metadata (src_ip, recv_time)
            
        Returns:
            Parsed dictionary or None if parsing fails
        """
        try:
            parsed = json.loads(raw_log.strip())
            
            # Add metadata if provided
            if metadata:
                parsed.update(metadata)
            
            # Parse nested message field if present
            if "message" in parsed and isinstance(parsed["message"], str):
                message_data = self._parse_message_field(parsed["message"])
                parsed.update(message_data)
            
            return self.enrich(parsed)
            
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            return None
    
    def parse_batch(self, logs: List[Dict[str, Any]]) -> Optional[pl.DataFrame]:
        """
        Parse a batch of Windows logs into a DataFrame.
        
        Args:
            logs: List of log dictionaries with 'line', 'src_ip', 'recv_time'
            
        Returns:
            Polars DataFrame with parsed and normalized data, or None if no logs match
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
        
        # Create DataFrame with dynamic schema
        df = pl.DataFrame(parsed_logs)
        
        # Apply normalization
        df = self.normalize(df)
        
        return df
    
    def enrich(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich parsed Windows log data.
        
        Currently a pass-through, can be extended for:
        - GeoIP lookup
        - Threat intelligence enrichment
        - User/host correlation
        
        Args:
            parsed_data: Parsed log dictionary
            
        Returns:
            Enriched dictionary
        """
        return parsed_data
    
    def normalize(self, df: pl.DataFrame) -> pl.DataFrame:
        """
        Apply Sigma normalization to Windows Event Log fields.
        
        Sigma is a generic signature format for SIEM systems.
        This method renames Windows-specific fields to Sigma standard names.
        
        Args:
            df: Polars DataFrame with raw Windows fields
            
        Returns:
            DataFrame with Sigma-normalized field names
        """
        existing_cols = set(df.columns)
        
        # Only rename fields that exist in the DataFrame AND don't conflict with existing columns
        valid_renames = {}
        for old_name, new_name in self.sigma_field_mapping.items():
            if old_name in existing_cols and new_name not in existing_cols:
                valid_renames[old_name] = new_name
        
        if valid_renames:
            df = df.rename(valid_renames)
        
        # Cleanup: Extract process name from full path
        if "parent" in df.columns:
            df = df.with_columns(
                pl.col("parent")
                .str.split("\\")
                .list.last()
                .alias("parent_name")
            )
        
        if "name" in df.columns:
            df = df.with_columns(
                pl.col("name")
                .str.split("\\")
                .list.last()
                .alias("process_name")
            )
        
        if "process_name" in df.columns and "process_name" != "name":
            # Also extract basename from process_name field if it exists
            df = df.with_columns(
                pl.col("process_name")
                .str.split("\\")
                .list.last()
                .alias("process_basename")
            )
        
        return df
    
    @staticmethod
    def _parse_message_field(message_str: str) -> Dict[str, Any]:
        """
        Parse the multi-line Windows Event 'message' field into a flat dictionary.
        
        Windows Event messages often contain structured data in a human-readable format:
        
        Example:
            Subject:
                Security ID: S-1-5-21-...
                Account Name: SYSTEM
            Process Information:
                Process ID: 0x1234
        
        Args:
            message_str: Multi-line message string
            
        Returns:
            Dictionary with extracted key-value pairs
        """
        if not message_str:
            return {}
        
        extracted_data = {}
        current_section = ""
        
        # Normalize line endings
        lines = message_str.replace('\r', '').split('\n')
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            if ':' not in line:
                continue
            
            # Split on first colon only
            key, value = line.split(':', 1)
            key = key.strip()
            value = value.strip()
            
            if not value:
                # This is a section header (e.g., "Subject:")
                current_section = key.replace(" ", "")
            else:
                # This is a key-value pair
                clean_key = key.replace(" ", "_")
                
                if current_section:
                    # Prefix with section name
                    final_key = f"{current_section}_{clean_key}"
                else:
                    final_key = clean_key
                
                extracted_data[final_key] = value
        
        return extracted_data
    
    def write_to_file(self, df: pl.DataFrame, format: str = "json") -> str:
        """Write parsed Windows logs to file.
        
        Args:
            df: Polars DataFrame with parsed logs
            format: Output format ('json' or 'csv')
            
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
        
        print(f"[WindowsParser] Wrote {len(df)} records to {filename}")
        return filename
