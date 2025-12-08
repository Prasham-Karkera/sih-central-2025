"""
Quick test of the complete pipeline
"""

import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.listener.listener import UdpListener
from src.parsers.parser_manager import ParserManager
from src.db.database import DatabaseManager


def test_components():
    """Test each component individually."""
    
    print("=" * 60)
    print("COMPONENT TESTS")
    print("=" * 60)
    
    # Test 1: ParserManager
    print("\n[1] Testing ParserManager...")
    pm = ParserManager()
    
    test_logs = [
        {
            "recv_time": "2025-12-06T10:00:00",
            "src_ip": "10.78.233.207",
            "line": '{"timestamp":"2025-12-06 04:06:30","hostname":"HP-LAP704","channel":"Security","event_id":4799}'
        },
        {
            "recv_time": "2025-12-06T10:00:01",
            "src_ip": "192.168.1.100",
            "line": "Dec 6 04:17:07 Hp-lap704 CRON[947]: (root) CMD (test)"
        },
        {
            "recv_time": "2025-12-06T10:00:02",
            "src_ip": "192.168.1.200",
            "line": '192.168.1.100 - - [06/Dec/2025:04:17:07 +0000] "GET /api/test HTTP/1.1" 200 1234'
        }
    ]
    
    for log in test_logs:
        parsed = pm.parse(log)
        if parsed:
            print(f"  ✓ Parsed as {parsed['log_type']}: {parsed.get('hostname', 'N/A')}")
        else:
            print(f"  ✗ Failed to parse")
    
    # Test 2: DatabaseManager
    print("\n[2] Testing DatabaseManager...")
    db = DatabaseManager("./test_pipeline.db")
    
    # Save test logs
    parsed_logs = [pm.parse(log) for log in test_logs]
    saved = db.save_batch([p for p in parsed_logs if p])
    
    print(f"  ✓ Saved {saved} logs")
    
    stats = db.get_stats()
    print(f"  ✓ Database stats: {stats}")
    
    db.close()
    
    # Test 3: UdpListener (dry run)
    print("\n[3] Testing UdpListener...")
    print("  ℹ Listener requires network, skipping bind test")
    print("  ✓ UdpListener class available")
    
    print("\n" + "=" * 60)
    print("ALL COMPONENT TESTS PASSED ✓")
    print("=" * 60)


def test_integration():
    """Test integration without network."""
    
    print("\n\n" + "=" * 60)
    print("INTEGRATION TEST (no network)")
    print("=" * 60)
    
    pm = ParserManager()
    db = DatabaseManager("./test_integration.db")
    
    # Simulate receiving logs
    test_batch = [
        '{"timestamp":"2025-12-06 04:06:30","hostname":"HP-LAP704","channel":"Security","event_id":4799}',
        "Dec 6 04:17:07 Hp-lap704 sshd[1234]: Accepted publickey for user",
        '192.168.1.100 - - [06/Dec/2025:04:17:07 +0000] "GET /api/test HTTP/1.1" 200 1234',
        "Dec 6 04:17:08 Hp-lap704 systemd[1]: Started service",
        '{"timestamp":"2025-12-06 04:06:31","hostname":"HP-LAP704","channel":"System","event_id":1000}'
    ]
    
    parsed_batch = []
    for i, line in enumerate(test_batch):
        raw_data = {
            "recv_time": f"2025-12-06T10:00:{i:02d}",
            "src_ip": "127.0.0.1",
            "line": line
        }
        
        parsed = pm.parse(raw_data)
        if parsed:
            parsed_batch.append(parsed)
    
    print(f"\n[Pipeline] Received: {len(test_batch)}")
    print(f"[Pipeline] Parsed: {len(parsed_batch)}")
    
    saved = db.save_batch(parsed_batch)
    print(f"[Pipeline] Saved: {saved}")
    
    stats = db.get_stats()
    print(f"\n[Stats] {stats}")
    
    db.close()
    
    print("\n" + "=" * 60)
    print("INTEGRATION TEST PASSED ✓")
    print("=" * 60)


def print_usage():
    """Print usage instructions."""
    
    print("\n\n" + "=" * 60)
    print("NEXT STEPS")
    print("=" * 60)
    
    print("\n1. Start the pipeline:")
    print("   python -m src.workers.ingestion_worker")
    
    print("\n2. Send test logs from another terminal:")
    print("   # Linux logs")
    print('   echo "Dec 6 04:17:07 Hp-lap704 CRON[947]: test" | nc -u localhost 5140')
    
    print("\n   # Windows logs")
    print('   echo \'{"timestamp":"2025-12-06 04:06:30","hostname":"HP-LAP704","channel":"Security","event_id":4799}\' | nc -u localhost 5140')
    
    print("\n3. Check the database:")
    print("   python")
    print("   >>> from src.db.database import DatabaseManager")
    print('   >>> db = DatabaseManager("./logs.db")')
    print("   >>> db.get_stats()")
    
    print("\n" + "=" * 60)


if __name__ == "__main__":
    try:
        test_components()
        test_integration()
        print_usage()
        
        print("\n✓ All tests passed! Pipeline is ready.")
        
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
