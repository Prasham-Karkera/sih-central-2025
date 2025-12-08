"""
Example Usage of Repository Pattern

Demonstrates how to use the database repositories in your workers and listeners.
"""

from src.db import (
    # Database initialization
    init_db,
    
    # Server operations
    get_or_create_server,
    
    # Log operations
    insert_raw_log,
    get_unparsed_linux_logs,
    get_unparsed_windows_logs,
    
    # Parsed details
    insert_linux_details,
    insert_windows_details,
    insert_nginx_details,
    
    # Alert operations
    create_alert,
    get_recent_alerts,
    
    # Rule operations
    get_active_rules_for_source,
)


def example_listener_usage():
    """
    Example: How a listener would use the repository.
    
    When receiving a log from syslog:
    """
    # 1. Register or get server
    server_id = get_or_create_server(
        hostname="webserver-01",
        ip="192.168.1.100",
        server_type="linux"
    )
    
    # 2. Insert raw log
    log_id = insert_raw_log(
        server_id=server_id,
        log_source="linux",
        content="Jan 15 10:23:45 webserver-01 sshd[1234]: Accepted publickey for admin from 192.168.1.50"
    )
    
    print(f"✅ Stored log with ID: {log_id}")


def example_parser_worker():
    """
    Example: How a parser worker would process logs.
    
    Parser workers fetch unparsed logs and add details.
    """
    # 1. Get unparsed Linux logs
    logs = get_unparsed_linux_logs(limit=50)
    
    for log in logs:
        # 2. Parse the log (using your parser)
        parsed = {
            "timestamp": "2024-01-15 10:23:45",
            "app_name": "sshd",
            "pid": 1234,
            "raw_message": log.content,
            "ssh_action": "Accepted",
            "ssh_user": "admin",
            "ssh_ip": "192.168.1.50"
        }
        
        # 3. Store parsed details
        insert_linux_details(log.id, parsed)
        
        print(f"✅ Parsed log {log.id}")


def example_alert_engine():
    """
    Example: How alert engine would create alerts.
    
    Alert engine checks rules and creates alerts.
    """
    # 1. Get active rules for Linux logs
    rules = get_active_rules_for_source("linux")
    
    print(f"Found {len(rules)} active rules for Linux")
    
    # 2. Get unparsed logs
    logs = get_unparsed_linux_logs(limit=10)
    
    for log in logs:
        # 3. Check each rule (simplified example)
        if "failed password" in log.content.lower():
            # 4. Create alert
            alert_id = create_alert(
                log_entry_id=log.id,
                server_id=log.server_id,
                rule_id=1,  # Rule ID from database
                severity="high",
                title="SSH Failed Login Attempt",
                description="Multiple failed password attempts detected",
                metadata={
                    "attempts": 5,
                    "source_ip": "192.168.1.100",
                    "target_user": "root"
                }
            )
            
            print(f"🚨 Created alert {alert_id}")


def example_dashboard_api():
    """
    Example: How dashboard API would fetch data.
    
    API endpoints can easily fetch data.
    """
    # Get recent critical alerts
    alerts = get_recent_alerts(limit=20, severity="critical", resolved=False)
    
    print(f"Found {len(alerts)} unresolved critical alerts:")
    for alert in alerts:
        print(f"  - {alert.title} (Server: {alert.server_id})")


def example_windows_usage():
    """
    Example: Windows log handling.
    """
    # 1. Register Windows server
    server_id = get_or_create_server(
        hostname="DC01",
        ip="10.0.0.5",
        server_type="windows"
    )
    
    # 2. Insert raw log
    log_id = insert_raw_log(
        server_id=server_id,
        log_source="windows",
        content='<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">...'
    )
    
    # 3. Parse and store details
    event_data = {
        "EventID": 4624,
        "Channel": "Security",
        "Computer": "DC01",
        "Message": "An account was successfully logged on"
    }
    
    insert_windows_details(log_id, event_data)
    
    print(f"✅ Stored Windows event {log_id}")


def example_nginx_usage():
    """
    Example: Nginx log handling.
    """
    # 1. Register nginx server
    server_id = get_or_create_server(
        hostname="nginx-lb-01",
        ip="10.0.0.10",
        server_type="nginx"
    )
    
    # 2. Insert raw log
    log_id = insert_raw_log(
        server_id=server_id,
        log_source="nginx",
        content='192.168.1.1 - - [15/Jan/2024:10:23:45 +0000] "GET /api/users HTTP/1.1" 200 1234'
    )
    
    # 3. Parse and store details
    parsed = {
        "remote_addr": "192.168.1.1",
        "time_local": "2024-01-15 10:23:45",
        "request_method": "GET",
        "request_uri": "/api/users",
        "status": 200,
        "body_bytes_sent": 1234,
        "http_user_agent": "Mozilla/5.0"
    }
    
    insert_nginx_details(log_id, parsed)
    
    print(f"✅ Stored Nginx log {log_id}")


if __name__ == "__main__":
    # Initialize database
    print("=" * 60)
    print("REPOSITORY PATTERN EXAMPLES")
    print("=" * 60)
    
    # Run examples
    print("\n1. LISTENER USAGE:")
    example_listener_usage()
    
    print("\n2. PARSER WORKER:")
    example_parser_worker()
    
    print("\n3. ALERT ENGINE:")
    example_alert_engine()
    
    print("\n4. DASHBOARD API:")
    example_dashboard_api()
    
    print("\n5. WINDOWS LOGS:")
    example_windows_usage()
    
    print("\n6. NGINX LOGS:")
    example_nginx_usage()
    
    print("\n" + "=" * 60)
    print("✅ ALL EXAMPLES COMPLETED!")
    print("=" * 60)
