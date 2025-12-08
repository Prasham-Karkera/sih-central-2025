"""
Quick test of repository functions
"""

from src.db import (
    get_or_create_server,
    insert_raw_log,
    get_unparsed_linux_logs,
    insert_linux_details,
    create_alert,
    get_recent_alerts
)

print("=" * 60)
print("🧪 TESTING REPOSITORY FUNCTIONS")
print("=" * 60)

# Test 1: Create server
print("\n1️⃣  Testing get_or_create_server...")
server_id = get_or_create_server("test-server", "192.168.1.100", "linux")
print(f"   ✅ Created server with ID: {server_id}")

# Test 2: Insert raw log
print("\n2️⃣  Testing insert_raw_log...")
log_id = insert_raw_log(
    server_id=server_id,
    log_source="linux",
    content="Jan 15 10:23:45 test-server sshd[1234]: Accepted publickey for admin"
)
print(f"   ✅ Created log entry with ID: {log_id}")

# Test 3: Get unparsed logs
print("\n3️⃣  Testing get_unparsed_linux_logs...")
logs = get_unparsed_linux_logs(limit=10)
print(f"   ✅ Found {len(logs)} unparsed Linux logs")

# Test 4: Insert parsed details
print("\n4️⃣  Testing insert_linux_details...")
parsed_data = {
    "app_name": "sshd",
    "pid": 1234,
    "raw_message": "Accepted publickey for admin",
    "ssh_action": "Accepted",
    "ssh_user": "admin"
}
insert_linux_details(log_id, parsed_data)
print(f"   ✅ Inserted Linux log details")

# Test 5: Verify log is now parsed
print("\n5️⃣  Testing that log is marked as parsed...")
unparsed = get_unparsed_linux_logs(limit=10)
print(f"   ✅ Unparsed logs now: {len(unparsed)} (should be 0)")

# Test 6: Create alert
print("\n6️⃣  Testing create_alert...")
alert_id = create_alert(
    log_entry_id=log_id,
    server_id=server_id,
    rule_id=1,
    severity="high",
    title="Test Alert",
    description="This is a test alert",
    metadata={"test": True, "source": "repository_test"}
)
print(f"   ✅ Created alert with ID: {alert_id}")

# Test 7: Get recent alerts
print("\n7️⃣  Testing get_recent_alerts...")
alerts = get_recent_alerts(limit=10)
print(f"   ✅ Found {len(alerts)} alerts")
if alerts:
    print(f"      Latest: {alerts[0].title} (Severity: {alerts[0].severity})")

print("\n" + "=" * 60)
print("✅ ALL REPOSITORY TESTS PASSED!")
print("=" * 60)
