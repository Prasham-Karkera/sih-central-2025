"""
Parser Manager

Manages multiple parsers and auto-detects the correct one for each log.
"""

from typing import List, Optional, Dict, Any
from src.base.base_parser import BaseParser
from src.parsers.windows_parser import WindowsParser
from src.parsers.linux_parser import LinuxParser
from src.parsers.ngnix_parser import NginxParser


class ParserManager:
    """
    Manages parser registry and auto-detection.
    
    Tries parsers in order until one matches.
    """
    
    def __init__(self, output_dir: str = "./collected_logs/processed"):
        """
        Initialize parser manager with default parsers.
        
        Args:
            output_dir: Base directory for parsed log files
        """
        self.output_dir = output_dir
        
        # Register parsers in priority order
        self.parsers: List[BaseParser] = [
            WindowsParser(output_dir=f"{output_dir}/windows"),
            NginxParser(output_dir=f"{output_dir}/nginx"),
            LinuxParser(output_dir=f"{output_dir}/linux")  # Default fallback
        ]
        
        print(f"[ParserManager] Registered {len(self.parsers)} parsers: "
              f"{', '.join(p.get_log_type() for p in self.parsers)}")
    
    def parse(self, raw_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Parse log using auto-detection.
        
        Args:
            raw_data: {recv_time, src_ip, line}
            
        Returns:
            Parsed dict with 'log_type' field or None
        """
        raw_line = raw_data.get("line", "")
        
        if not raw_line:
            return None
        
        # Try each parser
        for parser in self.parsers:
            if parser.can_parse(raw_line):
                metadata = {
                    "recv_time": raw_data.get("recv_time"),
                    "src_ip": raw_data.get("src_ip")
                }
                
                parsed = parser.parse(raw_line, metadata)
                
                if parsed:
                    # Add log type and raw line
                    parsed["log_type"] = parser.get_log_type()
                    parsed["raw_line"] = raw_line
                    return parsed
        
        # No parser matched
        print(f"[ParserManager] No parser matched: {raw_line[:80]}...")
        return None
    
    def get_parser_by_type(self, log_type: str) -> Optional[BaseParser]:
        """Get parser by log type name."""
        for parser in self.parsers:
            if parser.get_log_type() == log_type:
                return parser
        return None
    
    def register_parser(self, parser: BaseParser, priority: int = None):
        """
        Register a new parser.
        
        Args:
            parser: Parser instance
            priority: Insert position (None = append to end)
        """
        if priority is not None:
            self.parsers.insert(priority, parser)
        else:
            self.parsers.append(parser)
        
        print(f"[ParserManager] Registered {parser.get_log_type()} parser")
    
    def list_parsers(self) -> List[str]:
        """Get list of registered parser types."""
        return [p.get_log_type() for p in self.parsers]


# Example usage
if __name__ == "__main__":
    manager = ParserManager()
    
    # Test Windows log
    test_data = {
        "recv_time": "2025-12-06T10:00:00",
        "src_ip": "10.78.233.207",
        "line": '{"timestamp":"2025-12-06 04:06:30","hostname":"HP-LAP704","channel":"Security","event_id":4799}'
    }
    
    parsed = manager.parse(test_data)
    if parsed:
        print(f"\nParsed as: {parsed.get('log_type')}")
        print(f"Hostname: {parsed.get('hostname')}")
