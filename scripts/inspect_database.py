"""
Database Inspector - View all tables and recent data
"""

from src.db import SessionLocal
from src.db.models import (
    Server, LogEntry, LinuxLogDetails, WindowsLogDetails,
    NginxLogDetails, Alert, AlertRule
)
from sqlalchemy import func
from datetime import datetime
from collections import Counter

def print_section(title, emoji="📊"):
    print(f"\n{emoji} {title}")
    print("=" * 80)

def print_subsection(title):
    print(f"\n  {title}")
    print("  " + "-" * 76)

print("=" * 80)
print("🔍 DATABASE INSPECTOR - ENHANCED")
print("=" * 80)

db = SessionLocal()

try:
    # OVERVIEW STATS
    print_section("OVERVIEW", "📊")
    total_servers = db.query(Server).count()
    total_logs = db.query(LogEntry).count()
    total_alerts = db.query(Alert).count()
    active_alerts = db.query(Alert).filter_by(resolved=False).count()
    total_rules = db.query(AlertRule).count()
    
    print(f"  Servers:       {total_servers}")
    print(f"  Log Entries:   {total_logs}")
    print(f"  Alerts:        {total_alerts} ({active_alerts} active)")
    print(f"  Alert Rules:   {total_rules}")
    
    # SERVERS
    print_section("SERVERS", "📡")
    servers = db.query(Server).all()
    if servers:
        for server in servers:
            log_count = db.query(LogEntry).filter_by(server_id=server.id).count()
            alert_count = db.query(Alert).filter_by(server_id=server.id).count()
            print(f"  [{server.id}] {server.hostname} ({server.ip_address})")
            print(f"      Type: {server.server_type} | Logs: {log_count} | Alerts: {alert_count}")
    else:
        print("  No servers registered")
    
    # LOG ENTRIES
    print_section("LOG ENTRIES", "📝")
    
    # By source
    linux_count = db.query(LogEntry).filter_by(log_source="linux").count()
    windows_count = db.query(LogEntry).filter_by(log_source="windows").count()
    nginx_count = db.query(LogEntry).filter_by(log_source="nginx").count()
    
    print(f"  Total Logs: {total_logs}")
    print(f"  ├─ 🐧 Linux:   {linux_count:>5} ({linux_count*100//total_logs if total_logs else 0}%)")
    print(f"  ├─ 🪟 Windows: {windows_count:>5} ({windows_count*100//total_logs if total_logs else 0}%)")
    print(f"  └─ 🌐 Nginx:   {nginx_count:>5} ({nginx_count*100//total_logs if total_logs else 0}%)")
    
    # Parsed vs unparsed
    linux_parsed = db.query(LinuxLogDetails).count()
    windows_parsed = db.query(WindowsLogDetails).count()
    nginx_parsed = db.query(NginxLogDetails).count()
    total_parsed = linux_parsed + windows_parsed + nginx_parsed
    
    print(f"\n  Parsed Details: {total_parsed}/{total_logs} ({total_parsed*100//total_logs if total_logs else 0}%)")
    print(f"  ├─ Linux:   {linux_parsed}/{linux_count}")
    print(f"  ├─ Windows: {windows_parsed}/{windows_count}")
    print(f"  └─ Nginx:   {nginx_parsed}/{nginx_count}")
    
    print_subsection("Recent Log Entries (Last 10)")
    recent_logs = db.query(LogEntry).order_by(LogEntry.recv_time.desc()).limit(10).all()
    for log in recent_logs:
        timestamp = log.recv_time.strftime("%Y-%m-%d %H:%M:%S") if log.recv_time else "N/A"
        content = log.content[:60] + "..." if len(log.content) > 60 else log.content
        server = db.query(Server).filter_by(id=log.server_id).first()
        server_name = server.hostname if server else "Unknown"
        print(f"    [{log.id:>4}] {timestamp} | {log.log_source:7} | {server_name:15} | {content}")
    
    # LINUX LOG DETAILS
    print_section("LINUX LOG DETAILS", "🐧")
    print(f"  Parsed: {linux_parsed}/{linux_count}")
    
    if linux_parsed > 0:
        # Stats by app
        apps = db.query(LinuxLogDetails.app_name).all()
        app_counter = Counter([a[0] for a in apps if a[0]])
        print("\n  Top Applications:")
        for app, count in app_counter.most_common(5):
            print(f"    • {app}: {count}")
        
        # SSH activity
        ssh_logs = db.query(LinuxLogDetails).filter(LinuxLogDetails.ssh_action.isnot(None)).all()
        if ssh_logs:
            print(f"\n  SSH Activity: {len(ssh_logs)} events")
            actions = Counter([log.ssh_action for log in ssh_logs])
            for action, count in actions.items():
                print(f"    • {action}: {count}")
        
        print_subsection("Recent Linux Logs (Last 5)")
        recent_linux = db.query(LinuxLogDetails).order_by(LinuxLogDetails.log_entry_id.desc()).limit(5).all()
        for detail in recent_linux:
            print(f"    [Log {detail.log_entry_id}] {detail.app_name or 'N/A'}[{detail.pid or 'N/A'}]")
            if detail.ssh_action:
                print(f"      🔐 SSH: {detail.ssh_action} | User: {detail.ssh_user} | From: {detail.ssh_ip}")
            msg = detail.raw_message[:70] + "..." if detail.raw_message and len(detail.raw_message) > 70 else detail.raw_message
            print(f"      {msg}")
    
    # WINDOWS LOG DETAILS
    print_section("WINDOWS LOG DETAILS", "🪟")
    print(f"  Parsed: {windows_parsed}/{windows_count}")
    
    if windows_parsed > 0:
        print_subsection("Recent Windows Logs (Last 5)")
        recent_windows = db.query(WindowsLogDetails).order_by(WindowsLogDetails.log_entry_id.desc()).limit(5).all()
        for detail in recent_windows:
            content = detail.content[:80] + "..." if detail.content and len(detail.content) > 80 else detail.content
            print(f"    [Log {detail.log_entry_id}]")
            print(f"      {content}")
    
    # NGINX LOG DETAILS
    print_section("NGINX LOG DETAILS", "🌐")
    print(f"  Parsed: {nginx_parsed}/{nginx_count}")
    
    if nginx_parsed > 0:
        # Stats
        methods = db.query(NginxLogDetails.request_method).all()
        method_counter = Counter([m[0] for m in methods if m[0]])
        
        statuses = db.query(NginxLogDetails.status).all()
        status_counter = Counter([s[0] for s in statuses if s[0]])
        
        print("\n  HTTP Methods:")
        for method, count in method_counter.most_common():
            print(f"    • {method}: {count}")
        
        print("\n  Status Codes:")
        for status, count in sorted(status_counter.items()):
            emoji = "✅" if status < 300 else "⚠️" if status < 400 else "❌"
            print(f"    {emoji} {status}: {count}")
        
        print_subsection("Recent Nginx Requests (Last 5)")
        recent_nginx = db.query(NginxLogDetails).order_by(NginxLogDetails.log_entry_id.desc()).limit(5).all()
        for detail in recent_nginx:
            print(f"    [Log {detail.log_entry_id}] {detail.request_method} {detail.request_uri}")
            print(f"      Status: {detail.status} | IP: {detail.remote_addr} | Bytes: {detail.body_bytes_sent}")
    
    # ALERT RULES
    print_section("ALERT RULES", "⚙️")
    rules = db.query(AlertRule).all()
    print(f"  Total Rules: {len(rules)}")
    
    if rules:
        # By source
        rule_sources = Counter([r.log_source or 'ALL' for r in rules])
        print("\n  By Source:")
        for source, count in rule_sources.items():
            print(f"    • {source}: {count}")
        
        # By severity
        rule_severity = Counter([r.severity for r in rules])
        print("\n  By Severity:")
        severity_order = ['critical', 'high', 'medium', 'low']
        for sev in severity_order:
            if sev in rule_severity:
                emoji = "🔴" if sev == 'critical' else "🟠" if sev == 'high' else "🟡" if sev == 'medium' else "🟢"
                print(f"    {emoji} {sev.capitalize()}: {rule_severity[sev]}")
        
        # Enabled/Disabled
        enabled_count = sum(1 for r in rules if r.enabled)
        disabled_count = len(rules) - enabled_count
        print(f"\n  Status: ✅ {enabled_count} enabled | ❌ {disabled_count} disabled")
        
        print_subsection("All Rules")
        for rule in rules:
            enabled = "✅" if rule.enabled else "❌"
            source = rule.log_source or "ALL"
            print(f"    {enabled} [{rule.id:>3}] {rule.severity:>8} | {source:>8} | {rule.name}")
    
    # ALERTS
    print_section("ALERTS", "🚨")
    resolved_alerts = db.query(Alert).filter_by(resolved=True).count()
    
    print(f"  Total:    {total_alerts}")
    print(f"  Active:   🔴 {active_alerts}")
    print(f"  Resolved: ✅ {resolved_alerts}")
    
    if total_alerts > 0:
        # By severity
        alert_severity = db.query(Alert.severity, func.count()).group_by(Alert.severity).all()
        print("\n  By Severity:")
        severity_totals = {}
        for severity, count in alert_severity:
            severity_totals[severity] = count
            emoji = "🔴" if severity == 'critical' else "🟠" if severity == 'high' else "🟡" if severity == 'medium' else "🟢"
            print(f"    {emoji} {severity.capitalize():8}: {count:>4}")
        
        # By log source
        alert_sources = db.query(LogEntry.log_source, func.count(Alert.id)).join(Alert, LogEntry.id == Alert.log_entry_id).group_by(LogEntry.log_source).all()
        print("\n  By Log Source:")
        for source, count in alert_sources:
            emoji = "🐧" if source == 'linux' else "🪟" if source == 'windows' else "🌐"
            print(f"    {emoji} {source.capitalize():8}: {count:>4}")
        
        # By server
        alert_servers = db.query(Alert.server_id, func.count()).group_by(Alert.server_id).all()
        print("\n  By Server:")
        for server_id, count in alert_servers:
            server = db.query(Server).filter_by(id=server_id).first()
            server_name = server.hostname if server else f"ID:{server_id}"
            print(f"    • {server_name:20}: {count:>4} alerts")
        
        # Critical alerts warning
        critical_count = severity_totals.get('critical', 0)
        high_count = severity_totals.get('high', 0)
        if critical_count > 0 or high_count > 0:
            print(f"\n  ⚠️  ATTENTION REQUIRED:")
            if critical_count > 0:
                print(f"    🔴 {critical_count} CRITICAL alerts need immediate action!")
            if high_count > 0:
                print(f"    🟠 {high_count} HIGH severity alerts pending")
        
        print_subsection("Recent Alerts (Last 10)")
        recent_alerts = db.query(Alert).order_by(Alert.triggered_at.desc()).limit(10).all()
        for alert in recent_alerts:
            status = "🔴" if not alert.resolved else "✅"
            timestamp = alert.triggered_at.strftime("%Y-%m-%d %H:%M:%S") if alert.triggered_at else "N/A"
            server = db.query(Server).filter_by(id=alert.server_id).first()
            server_name = server.hostname if server else "Unknown"
            log_entry = db.query(LogEntry).filter_by(id=alert.log_entry_id).first()
            log_source = log_entry.log_source if log_entry else "unknown"
            
            severity_emoji = "🔴" if alert.severity == 'critical' else "🟠" if alert.severity == 'high' else "🟡" if alert.severity == 'medium' else "🟢"
            source_emoji = "🐧" if log_source == 'linux' else "🪟" if log_source == 'windows' else "🌐"
            print(f"    {status} [{alert.id:>3}] {severity_emoji} {alert.severity.upper():8} | {source_emoji} {log_source:7} | {timestamp}")
            print(f"        Server: {server_name}")
            print(f"        {alert.title}")
            if alert.description and len(alert.description) > 0:
                desc = alert.description[:100] + "..." if len(alert.description) > 100 else alert.description
                print(f"        📝 {desc}")
            
            # Show metadata if available
            if alert.alert_metadata:
                try:
                    import json
                    metadata = json.loads(alert.alert_metadata)
                    if 'matched_fields' in metadata and metadata['matched_fields']:
                        fields = list(metadata['matched_fields'].keys())[:3]
                        print(f"        🔍 Matched: {', '.join(fields)}")
                except:
                    pass
            print()
    
    # SUMMARY STATISTICS
    print_section("SUMMARY", "📊")
    
    # Threat level assessment
    threat_level = "🟢 LOW"
    critical_count = db.query(Alert).filter_by(severity='critical', resolved=False).count()
    high_count = db.query(Alert).filter_by(severity='high', resolved=False).count()
    
    if critical_count > 5:
        threat_level = "🔴 CRITICAL"
    elif critical_count > 0 or high_count > 10:
        threat_level = "🟠 HIGH"
    elif high_count > 0:
        threat_level = "🟡 MEDIUM"
    
    print(f"  Current Threat Level: {threat_level}")
    print(f"  Active Monitoring: {total_servers} servers, {total_logs} logs processed")
    if total_logs > 0:
        print(f"  Detection Rate: {total_alerts}/{total_logs} logs ({total_alerts*100//total_logs}% triggered alerts)")
    
    # Health status
    print(f"\n  System Health:")
    if total_logs > 0:
        parse_rate = (linux_parsed + windows_parsed + nginx_parsed)*100//total_logs
        parse_status = "✅ Good" if parse_rate > 80 else "⚠️ Needs Attention" if parse_rate > 50 else "❌ Poor"
        print(f"    Parser: {parse_status} ({parse_rate}% coverage)")
    
    rule_status = "✅ Active" if total_rules > 0 else "❌ No Rules"
    print(f"    Rules: {rule_status} ({total_rules} rules configured)")
    
    alert_status = "✅ Working" if total_alerts > 0 else "⚠️ No Alerts"
    print(f"    Alerts: {alert_status} ({active_alerts} active)")

finally:
    db.close()

print("\n" + "=" * 80)
print("✅ INSPECTION COMPLETE")
print("=" * 80)

