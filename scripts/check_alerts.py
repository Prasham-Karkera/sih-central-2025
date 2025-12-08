"""
Check Sigma Alerts

Query and display Sigma alerts from the database.
"""

import sqlite3
from pathlib import Path
from datetime import datetime

def check_alerts(db_path: str = "./ironchad_logs.db"):
    """Check and display Sigma alerts."""
    
    if not Path(db_path).exists():
        print(f"❌ Database not found: {db_path}")
        return
    
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    
    print("\n" + "="*80)
    print(f"SIGMA ALERTS REPORT")
    print("="*80)
    
    # Get alert count
    cur.execute("SELECT COUNT(*) FROM sigma_alert")
    total_alerts = cur.fetchone()[0]
    
    print(f"\n📊 Total Alerts: {total_alerts}")
    
    if total_alerts == 0:
        print("\n✅ No alerts found. System is clean!")
        print("\nTo generate alerts:")
        print("  1. Send malicious logs: python send_malicious_logs.py")
        print("  2. Wait for ingestion: ~5 seconds")
        print("  3. Run Sigma worker: python -m src.workers.sigma_rule_worker")
        return
    
    # Get alerts by severity
    print("\n" + "="*80)
    print("ALERTS BY SEVERITY")
    print("="*80)
    
    cur.execute("""
        SELECT severity, COUNT(*) as count
        FROM sigma_alert
        GROUP BY severity
        ORDER BY 
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END
    """)
    
    for row in cur.fetchall():
        severity = row[0].upper()
        count = row[1]
        
        emoji = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🔵',
            'INFORMATIONAL': '⚪'
        }.get(severity, '⚪')
        
        print(f"  {emoji} {severity:15} {count:>5} alerts")
    
    # Get recent alerts
    print("\n" + "="*80)
    print("RECENT ALERTS (Last 20)")
    print("="*80)
    
    cur.execute("""
        SELECT 
            a.id,
            a.timestamp,
            a.severity,
            a.rule_title,
            l.log_type,
            s.hostname,
            substr(l.raw_line, 1, 60) as preview
        FROM sigma_alert a
        JOIN log_entry l ON a.log_entry_id = l.id
        LEFT JOIN server s ON l.server_id = s.id
        ORDER BY a.timestamp DESC
        LIMIT 20
    """)
    
    rows = cur.fetchall()
    
    if rows:
        print(f"\n{'ID':<6} {'Time':<20} {'Sev':<10} {'Rule':<40} {'Host':<20}")
        print("-" * 100)
        
        for row in rows:
            alert_id = row[0]
            timestamp = row[1]
            severity = row[2].upper()
            rule_title = row[3][:38] + '..' if len(row[3]) > 40 else row[3]
            hostname = row[5] or 'Unknown'
            
            emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🔵'
            }.get(severity, '⚪')
            
            print(f"{alert_id:<6} {timestamp:<20} {emoji} {severity:<8} {rule_title:<40} {hostname:<20}")
    
    # Get top triggered rules
    print("\n" + "="*80)
    print("TOP TRIGGERED RULES")
    print("="*80)
    
    cur.execute("""
        SELECT 
            rule_title,
            severity,
            COUNT(*) as count
        FROM sigma_alert
        GROUP BY rule_title, severity
        ORDER BY count DESC
        LIMIT 10
    """)
    
    rows = cur.fetchall()
    
    if rows:
        print(f"\n{'Rule':<50} {'Severity':<12} {'Count':<10}")
        print("-" * 75)
        
        for row in rows:
            rule_title = row[0][:48] + '..' if len(row[0]) > 50 else row[0]
            severity = row[1].upper()
            count = row[2]
            
            print(f"{rule_title:<50} {severity:<12} {count:<10}")
    
    # Get affected hosts
    print("\n" + "="*80)
    print("AFFECTED HOSTS")
    print("="*80)
    
    cur.execute("""
        SELECT 
            s.hostname,
            s.ip_address,
            COUNT(DISTINCT a.id) as alert_count,
            MAX(a.severity) as max_severity
        FROM sigma_alert a
        JOIN log_entry l ON a.log_entry_id = l.id
        LEFT JOIN server s ON l.server_id = s.id
        GROUP BY s.hostname, s.ip_address
        ORDER BY alert_count DESC
    """)
    
    rows = cur.fetchall()
    
    if rows:
        print(f"\n{'Hostname':<30} {'IP Address':<20} {'Alerts':<10} {'Max Severity':<15}")
        print("-" * 80)
        
        for row in rows:
            hostname = row[0] or 'Unknown'
            ip = row[1] or 'N/A'
            alerts = row[2]
            severity = (row[3] or 'unknown').upper()
            
            print(f"{hostname:<30} {ip:<20} {alerts:<10} {severity:<15}")
    
    conn.close()
    
    print("\n" + "="*80)
    print("✅ Alert Report Complete")
    print("="*80)
    
    # Show SQL queries for manual inspection
    print("\n💡 Useful SQL Queries:")
    print("  # Get all critical alerts:")
    print("    SELECT * FROM sigma_alert WHERE severity = 'critical';")
    print("\n  # Get alerts for specific host:")
    print("    SELECT a.*, l.raw_line FROM sigma_alert a")
    print("    JOIN log_entry l ON a.log_entry_id = l.id")
    print("    JOIN server s ON l.server_id = s.id")
    print("    WHERE s.hostname = 'your-hostname';")
    print("\n  # Get alerts by rule:")
    print("    SELECT * FROM sigma_alert WHERE rule_title LIKE '%SQL%';")
    print()

if __name__ == "__main__":
    check_alerts()
