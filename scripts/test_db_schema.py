"""
Test Complete Database Schema

Verify all tables, indexes, and methods work correctly.
"""

from src.db.database import DatabaseManager

def test_schema():
    """Test database schema."""
    
    print("="*80)
    print("DATABASE SCHEMA TEST")
    print("="*80)
    
    db = DatabaseManager("./test_schema.db")
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # List all tables
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
    tables = [row[0] for row in cursor.fetchall()]
    
    print(f"\n✓ Tables Created: {len(tables)}")
    for table in tables:
        print(f"  • {table}")
    
    # Check required tables
    required_tables = [
        'server',
        'log_entry',
        'linux_log_details',
        'windows_log_details',
        'nginx_log_details',
        'sigma_alert'
    ]
    
    missing = set(required_tables) - set(tables)
    if missing:
        print(f"\n❌ Missing tables: {missing}")
        return False
    else:
        print(f"\n✓ All required tables present")
    
    # List all indexes
    cursor.execute("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'")
    indexes = [row[0] for row in cursor.fetchall()]
    
    print(f"\n✓ Indexes Created: {len(indexes)}")
    for idx in indexes:
        print(f"  • {idx}")
    
    # Test sigma_alert table structure
    cursor.execute("PRAGMA table_info(sigma_alert)")
    alert_columns = {row[1]: row[2] for row in cursor.fetchall()}
    
    print(f"\n✓ sigma_alert columns:")
    for col, type in alert_columns.items():
        print(f"  • {col}: {type}")
    
    db.close()
    
    print("\n" + "="*80)
    print("✅ SCHEMA TEST PASSED")
    print("="*80)
    
    return True

def test_methods():
    """Test database methods."""
    
    print("\n" + "="*80)
    print("DATABASE METHODS TEST")
    print("="*80)
    
    db = DatabaseManager("./test_methods.db")
    
    # Test saving log
    print("\n1. Testing save()...")
    test_log = {
        "timestamp": "2025-12-06 10:00:00",
        "recv_time": "2025-12-06 10:00:00",
        "hostname": "test-server",
        "src_ip": "192.168.1.100",
        "log_type": "linux",
        "raw_line": "Test log entry",
        "facility": "auth",
        "severity": "info",
        "program": "sshd",
        "pid": 1234,
        "message": "Test message"
    }
    
    log_id = db.save(test_log)
    print(f"   ✓ Saved log ID: {log_id}")
    
    # Test get_stats
    print("\n2. Testing get_stats()...")
    stats = db.get_stats()
    print(f"   ✓ Total logs: {stats['total_logs']}")
    print(f"   ✓ Total servers: {stats['total_servers']}")
    print(f"   ✓ By type: {stats['by_type']}")
    
    # Test get_recent_logs
    print("\n3. Testing get_recent_logs()...")
    logs = db.get_recent_logs(limit=10)
    print(f"   ✓ Retrieved {len(logs)} logs")
    
    # Test get_logs_for_sigma_processing
    print("\n4. Testing get_logs_for_sigma_processing()...")
    sigma_logs = db.get_logs_for_sigma_processing(last_processed_id=0, batch_size=50)
    print(f"   ✓ Retrieved {len(sigma_logs)} logs for Sigma processing")
    if sigma_logs:
        print(f"   ✓ Sample log: ID={sigma_logs[0]['id']}, Type={sigma_logs[0]['log_type']}")
    
    # Test alert stats (should be empty)
    print("\n5. Testing get_alert_stats()...")
    alert_stats = db.get_alert_stats()
    print(f"   ✓ Total alerts: {alert_stats['total_alerts']}")
    print(f"   ✓ By severity: {alert_stats['by_severity']}")
    
    # Test get_recent_alerts
    print("\n6. Testing get_recent_alerts()...")
    alerts = db.get_recent_alerts(limit=10)
    print(f"   ✓ Retrieved {len(alerts)} alerts")
    
    db.close()
    
    print("\n" + "="*80)
    print("✅ METHODS TEST PASSED")
    print("="*80)
    
    return True

if __name__ == "__main__":
    success = test_schema()
    if success:
        test_methods()
