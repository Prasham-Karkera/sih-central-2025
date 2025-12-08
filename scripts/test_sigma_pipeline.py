"""
Test Sigma Pipeline End-to-End

1. Start Sigma Worker
2. Send malicious logs
3. Wait for processing
4. Check generated alerts
"""

import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.workers.sigma_rule_worker import SigmaRuleWorker
from scripts.send_malicious_logs import send_malicious_logs
from scripts.inspect_database import inspect_database


def test_sigma_pipeline():
    """Run complete Sigma detection pipeline test."""
    
    print("="*80)
    print("SIGMA PIPELINE TEST")
    print("="*80)
    
    # Step 1: Check database before test
    print("\n[Step 1] Database State BEFORE Test")
    print("-"*80)
    inspect_database()
    
    input("\nPress Enter to start Sigma Worker...")
    
    # Step 2: Start Sigma Worker
    print("\n[Step 2] Starting Sigma Worker")
    print("-"*80)
    worker = SigmaRuleWorker(
        db_path="./ironchad_logs.db",
        rules_dir="./Sigma_Rules",
        poll_interval=2.0,  # Poll every 2 seconds
        batch_size=50
    )
    
    # Start in background
    worker.start()
    
    # Give it time to initialize
    time.sleep(3)
    
    input("\nPress Enter to send malicious logs...")
    
    # Step 3: Send malicious logs
    print("\n[Step 3] Sending Malicious Logs")
    print("-"*80)
    send_malicious_logs()
    
    print("\n[Step 4] Waiting for Sigma Worker to Process...")
    print("-"*80)
    print("Worker will poll every 2 seconds and match against Sigma rules")
    
    # Wait for processing (3 poll cycles = 6 seconds)
    for i in range(6, 0, -1):
        print(f"  Waiting {i} seconds...", end="\r")
        time.sleep(1)
    print()
    
    # Step 5: Check alerts generated
    print("\n[Step 5] Checking Generated Alerts")
    print("-"*80)
    inspect_database()
    
    # Step 6: Show statistics
    print("\n[Step 6] Sigma Worker Statistics")
    print("-"*80)
    print(f"  Logs Processed:    {worker.stats['logs_processed']}")
    print(f"  Alerts Generated:  {worker.stats['alerts_generated']}")
    print(f"  Rules Matched:     {worker.stats['rules_matched']}")
    print(f"  Errors:            {worker.stats['errors']}")
    print(f"  Started At:        {worker.stats['started_at']}")
    
    # Stop worker
    print("\n[Step 7] Stopping Sigma Worker")
    print("-"*80)
    worker.stop()
    time.sleep(1)
    
    print("\n" + "="*80)
    print("TEST COMPLETE")
    print("="*80)
    print("\nCheck the alerts in the database:")
    print("  SELECT * FROM sigma_alert ORDER BY timestamp DESC;")
    print("\nOr run: uv run -m scripts.check_alerts")


if __name__ == "__main__":
    test_sigma_pipeline()
