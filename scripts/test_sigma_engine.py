"""
Test Sigma Rule Engine

Test loading and matching Sigma rules.
"""

from src.workers.sigma_rule_engine import SigmaRuleEngine

def test_rule_loading():
    """Test loading Sigma rules from directory."""
    
    print("="*80)
    print("TEST 1: Loading Sigma Rules")
    print("="*80)
    
    engine = SigmaRuleEngine(rules_dir="./Sigma_Rules")
    engine.load_rules()
    
    # Count total rules
    total_rules = sum(len(rules) for rules in engine.rules.values())
    
    print(f"\n✓ Total rules loaded: {total_rules}")
    print(f"✓ Windows rules: {len(engine.rules['windows'])}")
    print(f"✓ Linux rules: {len(engine.rules['linux'])}")
    print(f"✓ Nginx rules: {len(engine.rules['nginx'])}")
    
    # Show sample rule
    for log_type, rules in engine.rules.items():
        if rules:
            sample_rule = rules[0]
            print(f"\n📋 Sample {log_type.capitalize()} Rule:")
            print(f"  Title: {sample_rule.title}")
            print(f"  ID: {sample_rule.id}")
            print(f"  Level: {sample_rule.level}")
            print(f"  LogSource: {sample_rule.logsource}")
            break

def test_rule_matching():
    """Test matching rules against sample logs."""
    
    print("\n" + "="*80)
    print("TEST 2: Matching Rules Against Logs")
    print("="*80)
    
    engine = SigmaRuleEngine(rules_dir="./Sigma_Rules")
    engine.load_rules()
    
    # Test logs that should trigger rules
    test_cases = [
        {
            "name": "SQL Injection Attack",
            "log": {
                "log_type": "nginx",
                "path": "/login.php",
                "query_string": "id=1' OR '1'='1",
                "status_code": 200,
                "raw_line": "GET /login.php?id=1' OR '1'='1"
            }
        },
        {
            "name": "XSS Attack",
            "log": {
                "log_type": "nginx",
                "path": "/search",
                "query_string": "q=<script>alert(1)</script>",
                "status_code": 200,
                "raw_line": "GET /search?q=<script>alert(1)</script>"
            }
        },
        {
            "name": "Windows Failed Login",
            "log": {
                "log_type": "windows",
                "event_id": 4625,
                "channel": "Security",
                "message": "An account failed to log on"
            }
        },
        {
            "name": "Linux SSH Brute Force",
            "log": {
                "log_type": "linux",
                "program": "sshd",
                "message": "Failed password for invalid user admin from 192.168.1.100"
            }
        },
        {
            "name": "Path Traversal",
            "log": {
                "log_type": "nginx",
                "path": "/../../../etc/passwd",
                "status_code": 404,
                "raw_line": "GET /../../../etc/passwd"
            }
        }
    ]
    
    for test_case in test_cases:
        print(f"\n📝 Test: {test_case['name']}")
        print(f"   Log Type: {test_case['log'].get('log_type')}")
        
        matches = engine.match_log(test_case['log'])
        
        if matches:
            print(f"   ✅ MATCHED {len(matches)} rule(s):")
            for match in matches:
                print(f"      - {match['rule_title']} (Level: {match['severity']})")
        else:
            print(f"   ⚠️  No rules matched (this is OK if no matching rules exist)")

if __name__ == "__main__":
    test_rule_loading()
    test_rule_matching()
    
    print("\n" + "="*80)
    print("✅ Sigma Engine Tests Complete")
    print("="*80)
