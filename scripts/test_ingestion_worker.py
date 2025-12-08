"""
Test Ingestion Worker with Repository Pattern
"""

from src.workers.ingestion_worker import IngestionWorker
from src.db import get_recent_logs
import time

# Initialize database first
from src.db import init_db
init_db()

print("=" * 60)
print("🧪 TESTING INGESTION WORKER")
print("=" * 60)

# Create worker (but don't run main loop)
worker = IngestionWorker(
    host="0.0.0.0",
    port=514,
    batch_size=5,  # Small batch for testing
    batch_timeout=2.0,
    output_dir="./collected_logs/processed"
)

# Simulate processing some logs
print("\n1️⃣  Simulating log ingestion...")

test_logs = [
    {
        "hostname": "webserver-01",
        "source_ip": "192.168.1.100",
        "log_source": "linux",
        "raw_line": "Jan 15 10:23:45 webserver sshd[1234]: Accepted publickey for admin",
        "timestamp": None
    },
    {
        "hostname": "dc01",
        "source_ip": "10.0.0.5",
        "log_source": "windows",
        "raw_line": "<Event>...</Event>",
        "timestamp": None
    },
    {
        "hostname": "nginx-lb-01",
        "source_ip": "10.0.0.10",
        "log_source": "nginx",
        "raw_line": '192.168.1.1 - - [15/Jan/2024:10:23:45] "GET /api HTTP/1.1" 200',
        "timestamp": None
    }
]

# Add to batch
for log_data in test_logs:
    worker.batch.append(log_data)

print(f"   Added {len(test_logs)} logs to batch")

# Flush batch
print("\n2️⃣  Flushing batch to database...")
worker._flush_batch()

# Verify logs were saved
print("\n3️⃣  Verifying logs in database...")
recent_logs = get_recent_logs(limit=10)
print(f"   ✅ Found {len(recent_logs)} logs in database")

for log in recent_logs:
    print(f"      - [{log.log_source}] {log.content[:50]}...")

# Print stats
print("\n4️⃣  Worker Stats:")
print(f"   Saved: {worker.stats['saved']}")
print(f"   Errors: {worker.stats['errors']}")
print(f"   Batches: {worker.stats['batches']}")

print("\n" + "=" * 60)
print("✅ INGESTION WORKER TEST COMPLETE!")
print("=" * 60)
