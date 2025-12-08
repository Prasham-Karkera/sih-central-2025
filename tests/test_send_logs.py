"""Test script to send logs to SIEM."""
import socket
import time
import json
from datetime import datetime

UDP_IP = "127.0.0.1"
UDP_PORT = 5140

def send_log(log_line):
    """Send a single log via UDP."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(log_line.encode('utf-8'), (UDP_IP, UDP_PORT))
    sock.close()

def main():
    print("=" * 60)
    print("SIEM Log Sender - Testing")
    print("=" * 60)
    print(f"Target: {UDP_IP}:{UDP_PORT}")
    print("=" * 60)
    
    # Test logs
    logs = [
        # Linux logs
        "[192.168.1.10] <13>Dec  6 10:30:15 web-server sshd[12345]: Accepted password for admin from 192.168.1.100 port 54321",
        "[192.168.1.10] <14>Dec  6 10:30:20 web-server systemd[1]: Started user session",
        "[192.168.1.10] <11>Dec  6 10:30:25 web-server kernel: [  120.456] Out of memory",
        
        # Windows logs (JSON)
        json.dumps({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": "DC01",
            "channel": "Security",
            "event_id": 4624,
            "message": "An account was successfully logged on",
            "user_name": "Administrator"
        }),
        json.dumps({
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": "WEB-SERVER",
            "channel": "System",
            "event_id": 7036,
            "message": "The Windows Update service entered the running state"
        }),
        
        # Nginx logs
        '[192.168.1.20] 203.0.113.45 - - [06/Dec/2025:10:30:30 +0000] "GET /api/users HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        '[192.168.1.20] 198.51.100.78 - - [06/Dec/2025:10:30:35 +0000] "POST /api/login HTTP/1.1" 401 56 "-" "curl/7.68.0"',
        '[192.168.1.20] 192.0.2.100 - - [06/Dec/2025:10:30:40 +0000] "GET /admin/config HTTP/1.1" 403 234 "-" "Mozilla/5.0"',
    ]
    
    print(f"\nSending {len(logs)} test logs...\n")
    
    for i, log in enumerate(logs, 1):
        print(f"[{i}/{len(logs)}] Sending: {log[:80]}...")
        send_log(log)
        time.sleep(0.5)  # Small delay between logs
    
    print("\n" + "=" * 60)
    print("✓ All logs sent successfully!")
    print("=" * 60)
    print("\nCheck the dashboard at: http://localhost:8000")
    print("Check the database: logs.db")

if __name__ == "__main__":
    main()
