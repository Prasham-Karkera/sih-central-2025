"""
UDP Listener

Simple UDP socket wrapper for receiving log messages.
"""

import socket
from typing import Optional, Dict, Any
from datetime import datetime


class UdpListener:
    """
    Generic UDP listener for log messages.
    
    Receives raw data over UDP and returns structured data.
    Can receive syslog, JSON logs, or any text-based data.
    """
    
    def __init__(self, host: str = "0.0.0.0", port: int = 5140, timeout: float = 1.0):
        """
        Initialize listener.
        
        Args:
            host: Bind address
            port: UDP port
            timeout: Socket timeout in seconds (for non-blocking)
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket = None
        self._running = False
    
    def start(self):
        """Open UDP socket and start listening."""
        if self._running:
            print(f"[UdpListener] Already running on {self.host}:{self.port}")
            return
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.settimeout(self.timeout)
        
        self._running = True
        print(f"[UdpListener] Started on UDP {self.host}:{self.port}")
    
    def receive(self) -> Optional[Dict[str, Any]]:
        """
        Receive one UDP message.
        
        Returns:
            Dict with {recv_time, src_ip, line} or None if timeout
        """
        if not self._running:
            raise RuntimeError("Listener not started. Call start() first.")
        
        try:
            data, addr = self.socket.recvfrom(65535)
            message = data.decode("utf-8", errors="replace").strip()
            
            return {
                "recv_time": datetime.now().isoformat(),
                "src_ip": addr[0],
                "line": message
            }
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[UdpListener] Error: {e}")
            return None
    
    def stop(self):
        """Close socket."""
        if self.socket:
            self.socket.close()
            self._running = False
            print("[UdpListener] Stopped")
    
    def __enter__(self):
        """Context manager support."""
        self.start()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup."""
        self.stop()


# Example usage
if __name__ == "__main__":
    with UdpListener(host="0.0.0.0", port=5140) as listener:
        print("Listening for UDP logs... (Ctrl+C to stop)")
        try:
            while True:
                data = listener.receive()
                if data:
                    print(f"[{data['src_ip']}] {data['line'][:80]}...")
        except KeyboardInterrupt:
            print("\nStopped")
