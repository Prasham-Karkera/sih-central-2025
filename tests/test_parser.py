"""
Test module for log parsers

Tests the WindowsParser and LinuxParser functionality with sample log data.
"""

import sys
from pathlib import Path

# Add project root to sys.path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.parsers import WindowsParser, LinuxParser


def test_linux():
    """Test Linux syslog parser with real log data from syslog_messages.log"""
    
    parser = LinuxParser()
    
    # Real test cases from the actual log file (stripped of [IP] prefix and <priority>)
    test_logs = [
        # Standard systemd log
        "Dec  4 17:06:42 Hp-lap704 systemd-resolved[157]: Clock change detected. Flushing caches.",
        
        # Custom application log
        "Dec  4 17:10:17 Hp-lap704 dark-knight499: its workinglogger TEST TEST TEST",
        
        # Sudo command log
        "Dec  4 17:11:38 Hp-lap704 sudo: dark-knight499 : TTY=pts/2 ; PWD=/mnt/c/Users/Harsh ; USER=root ; COMMAND=/usr/bin/apt install nginx -y",
        
        # PAM authentication log
        "Dec  4 17:11:38 Hp-lap704 sudo: pam_unix(sudo:session): session opened for user root(uid=0) by (uid=1000)",
        
        # CRON log
        "Dec  6 04:17:07 Hp-lap704 CRON[947]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
        
        # systemd-resolved with repeated message
        "Dec  6 04:16:59 Hp-lap704 systemd-resolved[124]: message repeated 25 times: [ Clock change detected. Flushing caches.]",
        
        # CRON command execution
        "Dec  6 04:17:07 Hp-lap704 CRON[948]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)",
    ]
    
    print("=" * 70)
    print("LINUX PARSER TESTS")
    print("=" * 70)
    
    for i, log in enumerate(test_logs, 1):
        print(f"\n[Test {i}] Original log:")
        print(f"  {log[:100]}..." if len(log) > 100 else f"  {log}")
        
        # Test can_parse
        can_parse = parser.can_parse(log)
        print(f"\n  Can parse: {can_parse}")
        
        if can_parse:
            # Test parse
            parsed = parser.parse(log, metadata={"src_ip": "192.168.0.109", "recv_time": "2024-12-04T17:00:00"})
            
            if parsed:
                print(f"  ✓ Parsed successfully:")
                print(f"    - Timestamp: {parsed.get('timestamp', 'N/A')}")
                print(f"    - Hostname: {parsed.get('hostname', 'N/A')}")
                print(f"    - App: {parsed.get('app_name', 'N/A')}")
                print(f"    - PID: {parsed.get('pid', 'N/A')}")
                print(f"    - Message: {parsed.get('raw_message', 'N/A')[:60]}...")
                
                # Check for SSH enrichment
                if parsed.get('ssh_action'):
                    print(f"    - SSH Action: {parsed.get('ssh_action')}")
                    print(f"    - SSH User: {parsed.get('ssh_user')}")
                    print(f"    - SSH IP: {parsed.get('ssh_ip')}")
            else:
                print(f"  ✗ Parsing failed")
    
    # Test batch parsing
    print("\n" + "=" * 70)
    print("BATCH PARSING TEST")
    print("=" * 70)
    
    batch_logs = [
        {"line": log, "src_ip": "192.168.0.109", "recv_time": "2024-12-04T17:00:00"}
        for log in test_logs
    ]
    
    df = parser.parse_batch(batch_logs)
    if df is not None:
        print(f"\n✓ Parsed {len(df)} logs into DataFrame")
        print(f"  Columns: {df.columns}")
        print(f"  Shape: {df.shape}")
        
        # Test file writing
        print("\n" + "=" * 70)
        print("FILE WRITING TEST")
        print("=" * 70)
        
        # Write as CSV
        csv_path = parser.write_to_file(df, format="csv")
        print(f"  ✓ CSV written to: {csv_path}")
        
        # Write as JSON
        json_path = parser.write_to_file(df, format="json")
        print(f"  ✓ JSON written to: {json_path}")
    else:
        print("\n✗ Batch parsing failed")


def test_windows():
    """Test Windows Event Log JSON parser."""
    
    parser = WindowsParser()
    
    # Sample Windows Event Log JSON entries
    test_logs = [
        # Security Event - Logon
        '''{
            "hostname": "WIN-SERVER01",
            "EventID": 4624,
            "LogName": "Security",
            "TimeCreated": "2024-12-04T10:30:45.123Z",
            "EventRecordID": 12345,
            "Level": "Information",
            "Computer": "WIN-SERVER01.domain.local",
            "message": "An account was successfully logged on.\\n\\nSubject:\\n\\tSecurity ID: S-1-5-18\\n\\tAccount Name: SYSTEM\\n\\tAccount Domain: NT AUTHORITY\\n\\nLogon Information:\\n\\tLogon Type: 3\\n\\tRestricted Admin Mode: -\\n\\tUser: john.doe\\n\\tLogon Process: NtLmSsp"
        }''',
        
        # Process Creation Event
        '''{
            "hostname": "WIN-WORKSTATION02",
            "EventID": 4688,
            "LogName": "Security",
            "CommandLine": "powershell.exe -NoProfile -ExecutionPolicy Bypass",
            "NewProcessName": "C:\\\\Windows\\\\System32\\\\WindowsPowerShell\\\\v1.0\\\\powershell.exe",
            "ParentProcessName": "C:\\\\Windows\\\\System32\\\\cmd.exe",
            "TargetUserName": "administrator",
            "TimeCreated": "2024-12-04T11:15:30.456Z"
        }''',
        
        # File Access Event
        '''{
            "hostname": "WIN-FILESERVER",
            "EventID": 5145,
            "LogName": "Security",
            "TargetFilename": "C:\\\\Data\\\\confidential.docx",
            "TargetUserName": "bob.smith",
            "Image": "C:\\\\Windows\\\\explorer.exe",
            "TimeCreated": "2024-12-04T14:20:10.789Z"
        }''',
        
        # Real log from your script - Group Membership Enumeration
        '''{"timestamp":"2025-12-06 04:06:30","hostname":"HP-LAP704","channel":"Security","event_id":4799,"level":"Information","message":"A security-enabled local group membership was enumerated.\\r\\n\\r\\nSubject:\\r\\n\\tSecurity ID:\\t\\tS-1-5-21-64021822-3933034794-494143053-1009\\r\\n\\tAccount Name:\\t\\tHarsh\\r\\n\\tAccount Domain:\\t\\tHP-LAP704\\r\\n\\tLogon ID:\\t\\t0xC4589\\r\\n\\r\\nGroup:\\r\\n\\tSecurity ID:\\t\\tS-1-5-32-544\\r\\n\\tGroup Name:\\t\\tAdministrators\\r\\n\\tGroup Domain:\\t\\tBuiltin\\r\\n\\r\\nProcess Information:\\r\\n\\tProcess ID:\\t\\t0x278c\\r\\n\\tProcess Name:\\t\\tC:\\\\Windows\\\\System32\\\\taskhostw.exe","TargetUserName":"Administrators","TargetDomainName":"Builtin","TargetSid":"S-1-5-32-544","SubjectUserSid":"S-1-5-21-64021822-3933034794-494143053-1009","SubjectUserName":"Harsh","SubjectDomainName":"HP-LAP704","SubjectLogonId":"0xc4589","CallerProcessId":"0x278c","CallerProcessName":"C:\\\\Windows\\\\System32\\\\taskhostw.exe"}'''
    ]
    
    print("\n" + "=" * 70)
    print("WINDOWS PARSER TESTS")
    print("=" * 70)
    
    for i, log in enumerate(test_logs, 1):
        print(f"\n[Test {i}] Windows Event JSON")
        
        # Test can_parse
        can_parse = parser.can_parse(log)
        print(f"  Can parse: {can_parse}")
        
        if can_parse:
            # Test parse
            parsed = parser.parse(log, metadata={"src_ip": "10.0.0.50", "recv_time": "2024-12-04T10:00:00"})
            
            if parsed:
                print(f"  ✓ Parsed successfully:")
                print(f"    - Hostname: {parsed.get('hostname', 'N/A')}")
                print(f"    - EventID: {parsed.get('EventID', parsed.get('event_id', 'N/A'))}")
                print(f"    - LogName/Channel: {parsed.get('channel', parsed.get('LogName', 'N/A'))}")
                print(f"    - TimeCreated: {parsed.get('TimeCreated', parsed.get('timestamp', 'N/A'))}")
                
                # Check for Sigma normalized fields
                if 'cmdline' in parsed:
                    print(f"    - CommandLine (Sigma): {parsed['cmdline'][:60]}...")
                if 'name' in parsed:
                    print(f"    - Process Name (Sigma): {parsed['name']}")
                if 'parent' in parsed:
                    print(f"    - Parent Process (Sigma): {parsed['parent']}")
                if 'user' in parsed:
                    print(f"    - User (Sigma): {parsed['user']}")
                if 'target_file' in parsed:
                    print(f"    - Target File (Sigma): {parsed['target_file']}")
                
                # Check for real log fields
                if 'SubjectUserName' in parsed:
                    print(f"    - Subject User: {parsed['SubjectUserName']}")
                if 'CallerProcessName' in parsed:
                    print(f"    - Caller Process: {parsed['CallerProcessName']}")
                
                # Check for message parsing
                if 'Subject_Security_ID' in parsed:
                    print(f"    - Parsed Message: Found {sum(1 for k in parsed if k.startswith('Subject_'))} Subject fields")
                if 'Group_Security_ID' in parsed:
                    print(f"    - Parsed Message: Found {sum(1 for k in parsed if k.startswith('Group_'))} Group fields")
            else:
                print(f"  ✗ Parsing failed")
    
    # Test batch parsing
    print("\n" + "=" * 70)
    print("BATCH PARSING TEST")
    print("=" * 70)
    
    batch_logs = [
        {"line": log, "src_ip": "10.0.0.50", "recv_time": "2024-12-04T10:00:00"}
        for log in test_logs
    ]
    
    df = parser.parse_batch(batch_logs)
    if df is not None:
        print(f"\n✓ Parsed {len(df)} Windows events into DataFrame")
        print(f"  Columns: {df.columns}")
        print(f"  Shape: {df.shape}")
        
        # Check for Sigma normalized columns
        sigma_cols = [col for col in df.columns if col in ['cmdline', 'parent', 'name', 'user', 'image', 'channel']]
        if sigma_cols:
            print(f"  Sigma normalized fields: {sigma_cols}")
        
        # Test file writing
        print("\n" + "=" * 70)
        print("FILE WRITING TEST")
        print("=" * 70)
        
        # Write as JSON (default for Windows)
        json_path = parser.write_to_file(df, format="json")
        print(f"  ✓ JSON written to: {json_path}")
        
        # Write as CSV (alternative)
        csv_path = parser.write_to_file(df, format="csv")
        print(f"  ✓ CSV written to: {csv_path}")
    else:
        print("\n✗ Batch parsing failed")


if __name__ == "__main__":
    print("\n" + "🔍 STARTING PARSER TESTS " + "🔍")
    print("=" * 70)
    
    test_linux()
    test_windows()
    
    print("\n" + "=" * 70)
    print("✅ ALL TESTS COMPLETED")
    print("=" * 70 + "\n")
