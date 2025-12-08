"""Test Sigma Rule Worker."""
import sys
import time
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.workers.sigma_rule_worker import SigmaRuleWorker

def test_sigma_worker():
    """Test Sigma rule worker with database."""
    print("=" * 60)
    print("Testing Sigma Rule Worker")
    print("=" * 60)
    
    # Create and start worker
    worker = SigmaRuleWorker(
        db_path="./src/app/ironchad_logs.db",
        rules_dir="./Sigma_Rules",
        poll_interval=2.0,
        batch_size=50
    )
    
    # Start worker
    worker.start()
    
    print("\nWorker started. Monitoring for 30 seconds...")
    print("Send some logs and watch for alerts!\n")
    
    try:
        # Monitor for 30 seconds
        for i in range(15):
            time.sleep(2)
            stats = worker.get_stats()
            
            print(f"\r[{i*2}s] Processed: {stats['logs_processed']} | "
                  f"Alerts: {stats['alerts_generated']} | "
                  f"Errors: {stats['errors']}", end='', flush=True)
        
        print("\n\n" + "=" * 60)
        print("Final Statistics:")
        print("=" * 60)
        
        stats = worker.get_stats()
        print(f"Logs Processed: {stats['logs_processed']}")
        print(f"Alerts Generated: {stats['alerts_generated']}")
        print(f"Rules Matched: {stats['rules_matched']}")
        print(f"Errors: {stats['errors']}")
        
        if 'engine' in stats:
            engine_stats = stats['engine']
            print(f"\nRules Loaded:")
            print(f"  Linux: {engine_stats['linux_rules']}")
            print(f"  Windows: {engine_stats['windows_rules']}")
            print(f"  Nginx: {engine_stats['nginx_rules']}")
            print(f"  Total: {engine_stats['total_rules']}")
        
        print("\n" + "=" * 60)
        print("Check alerts with:")
        print("  SELECT * FROM sigma_alert ORDER BY timestamp DESC LIMIT 10;")
        print("=" * 60)
    
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    
    finally:
        worker.stop()
        print("\nWorker stopped")

if __name__ == "__main__":
    test_sigma_worker()
