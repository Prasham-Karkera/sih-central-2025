"""
Base Parser Module

Provides abstract base class for all log parsers in the system.
Each parser must implement methods to parse individual logs and batches.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import polars as pl


class BaseParser(ABC):
    """
    Abstract base class for all log parsers.
    
    Each concrete parser must implement:
    - parse(): Parse a single log line
    - parse_batch(): Parse multiple logs into a DataFrame
    - get_log_type(): Return the log type identifier
    - can_parse(): Detect if this parser can handle a log
    """
    
    @abstractmethod
    def parse(self, raw_log: str, metadata: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
        """
        Parse a single log line into structured data.
        
        Args:
            raw_log: The raw log line as a string
            metadata: Optional metadata (src_ip, recv_time, etc.)
            
        Returns:
            Dictionary with parsed fields, or None if parsing fails
        """
        pass
    
    @abstractmethod
    def parse_batch(self, logs: List[Dict[str, Any]]) -> Optional[pl.DataFrame]:
        """
        Parse a batch of logs into a Polars DataFrame.
        
        Args:
            logs: List of log dictionaries with 'line', 'src_ip', 'recv_time'
            
        Returns:
            Polars DataFrame with parsed and enriched data, or None if no logs match
        """
        pass
    
    @abstractmethod
    def get_log_type(self) -> str:
        """
        Return the log type identifier.
        
        Returns:
            String identifier ('windows', 'linux', 'nginx', etc.)
        """
        pass
    
    @abstractmethod
    def can_parse(self, raw_log: str) -> bool:
        """
        Check if this parser can handle the given log line.
        
        Args:
            raw_log: The raw log line to check
            
        Returns:
            True if this parser can handle the log, False otherwise
        """
        pass
    
    def enrich(self, parsed_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Optional enrichment step for parsed data.
        Override in subclasses to add custom enrichment logic.
        
        Args:
            parsed_data: Dictionary with parsed fields
            
        Returns:
            Enriched dictionary
        """
        return parsed_data
    
    def normalize(self, df: pl.DataFrame) -> pl.DataFrame:
        """
        Optional normalization step for batch processing.
        Override in subclasses to apply field renaming or transformations.
        
        Args:
            df: Polars DataFrame with parsed data
            
        Returns:
            Normalized DataFrame
        """
        return df
