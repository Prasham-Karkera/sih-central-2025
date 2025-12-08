"""Test database query methods."""
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.db.database import DatabaseManager

def test_queries():
    """Test all database query methods."""
    db = DatabaseManager(":memory:")
    
    print("✓ Database initialized")
    
    # Add test server (using private method for testing)
    server_id = db._get_or_create_server("test-host", "192.168.1.1")
    print(f"✓ Test server created: {server_id}")
    
    # Add test logs
    test_logs = [
        {
            "timestamp": "2025-12-06 10:00:00",
            "hostname": "test-host",
            "ip_address": "192.168.1.1",
            "log_type": "linux",
            "raw_line": "Test log 1",
            "parsed_data": '{"message":"test"}',
            "facility": "syslog",
            "severity": "info",
            "program": "test",
            "pid": 123,
            "message": "Test message"
        },
        {
            "timestamp": "2025-12-06 11:00:00",
            "hostname": "test-host",
            "ip_address": "192.168.1.1",
            "log_type": "windows",
            "raw_line": "Test log 2",
            "parsed_data": '{"event_id":4624}',
            "channel": "Security",
            "event_id": 4624,
            "message": "Login event"
        },
        {
            "timestamp": "2025-12-06 12:00:00",
            "hostname": "test-host",
            "ip_address": "192.168.1.1",
            "log_type": "nginx",
            "raw_line": "Test log 3",
            "parsed_data": '{"status_code":200}',
            "method": "GET",
            "path": "/api/test",
            "status_code": 200,
            "bytes": 1234
        }
    ]
    
    for log in test_logs:
        db.save(log)
    
    print(f"✓ {len(test_logs)} test logs saved")
    
    # Test get_stats()
    stats = db.get_stats()
    assert stats["total_logs"] == 3
    assert stats["total_servers"] == 1
    print(f"✓ get_stats: {stats}")
    
    # Test get_recent_logs()
    recent = db.get_recent_logs(limit=2)
    assert len(recent) == 2
    assert recent[0]["log_type"] == "nginx"  # Most recent
    print(f"✓ get_recent_logs: {len(recent)} logs")
    
    # Test get_recent_logs with filter
    linux_logs = db.get_recent_logs(log_type="linux")
    assert len(linux_logs) == 1
    print(f"✓ get_recent_logs(log_type='linux'): {len(linux_logs)} logs")
    
    # Test get_log_by_id()
    log = db.get_log_by_id(1)
    assert log is not None
    assert log["log_type"] == "linux"
    assert "facility" in log
    assert log["facility"] == "syslog"
    print(f"✓ get_log_by_id(1): {log['log_type']} with facility={log['facility']}")
    
    # Test search_logs()
    results = db.search_logs(text="Test")
    assert len(results) == 3
    print(f"✓ search_logs('Test'): {len(results)} logs")
    
    # Test get_servers_with_stats()
    servers = db.get_servers_with_stats()
    assert len(servers) == 1
    assert servers[0]["log_count"] == 3
    print(f"✓ get_servers_with_stats: {servers[0]['hostname']} with {servers[0]['log_count']} logs")
    
    # Test get_server_logs()
    server_logs = db.get_server_logs(server_id)
    assert len(server_logs) == 3
    print(f"✓ get_server_logs({server_id}): {len(server_logs)} logs")
    
    # Test get_timeseries_stats()
    timeseries = db.get_timeseries_stats(hours=24)
    print(f"✓ get_timeseries_stats: {len(timeseries)} time buckets")
    
    print("\n🎉 All query methods working correctly!")

if __name__ == "__main__":
    test_queries()
