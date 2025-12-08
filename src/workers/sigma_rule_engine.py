"""
Sigma Rule Engine

Core engine for loading and matching Sigma rules against log entries.
Supports field mapping, condition evaluation, and alert generation.
"""

import re
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass
from datetime import datetime


@dataclass
class SigmaRule:
    """Represents a loaded Sigma rule."""
    id: str
    title: str
    description: str
    level: str  # critical, high, medium, low, informational
    status: str  # stable, experimental, test
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    falsepositives: List[str]
    references: List[str]
    author: str
    file_path: str
    
    def get_log_type(self) -> Optional[str]:
        """Determine log type from logsource."""
        product = self.logsource.get('product', '').lower()
        service = self.logsource.get('service', '').lower()
        
        if 'linux' in product or 'syslog' in service:
            return 'linux'
        elif 'windows' in product:
            return 'windows'
        elif 'nginx' in service or 'web' in product:
            return 'nginx'
        
        return None


class SigmaRuleEngine:
    """
    Sigma Rule Engine for detecting security events in logs.
    
    Features:
    - Load rules from YAML files
    - Field mapping for different log types
    - Condition evaluation (selection, filter, condition logic)
    - Alert generation with rule metadata
    """
    
    def __init__(self, rules_dir: str = "./Sigma_Rules"):
        """
        Initialize Sigma rule engine.
        
        Args:
            rules_dir: Directory containing Sigma rule YAML files
        """
        self.rules_dir = Path(rules_dir)
        self.rules: Dict[str, List[SigmaRule]] = {
            'linux': [],
            'windows': [],
            'nginx': []
        }
        self.total_rules = 0
        
        # Field mapping for different log types
        self.field_mappings = {
            'linux': {
                'CommandLine': 'message',
                'ProcessName': 'program',
                'User': 'user',
                'SourceIp': 'source_ip',
                'DestinationIp': 'destination_ip',
                'Message': 'message',
            },
            'windows': {
                'CommandLine': 'command_line',
                'ProcessName': 'process_name',
                'ParentProcessName': 'parent_process_name',
                'User': 'user_name',
                'EventID': 'event_id',
                'Channel': 'channel',
                'Message': 'message',
            },
            'nginx': {
                'Url': 'path',
                'RequestMethod': 'method',
                'StatusCode': 'status_code',
                'UserAgent': 'user_agent',
                'SourceIp': 'remote_addr',
                'Referer': 'referer',
            }
        }
    
    def load_rules(self) -> int:
        """
        Load all Sigma rules from the rules directory.
        
        Returns:
            Number of rules loaded
        """
        if not self.rules_dir.exists():
            print(f"[SigmaEngine] Rules directory not found: {self.rules_dir}")
            return 0
        
        loaded = 0
        
        # Load rules by type
        for log_type in ['Linux', 'Windows', 'Nginx']:
            type_dir = self.rules_dir / log_type
            
            if not type_dir.exists():
                continue
            
            # Find all YAML files
            for rule_file in type_dir.rglob("*.yml"):
                # Skip disabled rules
                if '.disabled' in rule_file.suffix:
                    continue
                
                try:
                    rule = self._load_rule_file(rule_file)
                    if rule:
                        rule_type = log_type.lower()
                        self.rules[rule_type].append(rule)
                        loaded += 1
                
                except Exception as e:
                    print(f"[SigmaEngine] Error loading {rule_file.name}: {e}")
        
        self.total_rules = loaded
        print(f"[SigmaEngine] Loaded {loaded} rules:")
        for log_type, rules in self.rules.items():
            if rules:
                print(f"  {log_type}: {len(rules)} rules")
        
        return loaded
    
    def _load_rule_file(self, rule_file: Path) -> Optional[SigmaRule]:
        """Load a single Sigma rule from YAML file."""
        with open(rule_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        if not data or 'detection' not in data:
            return None
        
        return SigmaRule(
            id=data.get('id', rule_file.stem),
            title=data.get('title', 'Unknown'),
            description=data.get('description', ''),
            level=data.get('level', 'medium'),
            status=data.get('status', 'experimental'),
            logsource=data.get('logsource', {}),
            detection=data.get('detection', {}),
            falsepositives=data.get('falsepositives', []),
            references=data.get('references', []),
            author=data.get('author', 'Unknown'),
            file_path=str(rule_file)
        )
    
    def match_log(self, log_entry: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Match a log entry against all relevant Sigma rules.
        
        Args:
            log_entry: Parsed log entry with fields
        
        Returns:
            List of alerts (rule matches)
        """
        log_type = log_entry.get('log_type')
        if not log_type or log_type not in self.rules:
            return []
        
        alerts = []
        
        for rule in self.rules[log_type]:
            if self._evaluate_rule(rule, log_entry, log_type):
                alert = self._create_alert(rule, log_entry)
                alerts.append(alert)
        
        return alerts
    
    def _evaluate_rule(self, rule: SigmaRule, log_entry: Dict[str, Any], log_type: str) -> bool:
        """
        Evaluate if a log entry matches a Sigma rule.
        
        Args:
            rule: Sigma rule to evaluate
            log_entry: Log entry to check
            log_type: Type of log (linux/windows/nginx)
        
        Returns:
            True if rule matches
        """
        detection = rule.detection
        
        # Get condition (default to 'selection')
        condition = detection.get('condition', 'selection')
        
        # Simple condition evaluation (supports: selection, selection and not filter)
        if condition == 'selection':
            return self._evaluate_selection(detection.get('selection', {}), log_entry, log_type)
        
        elif 'and not' in condition:
            # Example: "selection and not filter"
            parts = condition.split(' and not ')
            if len(parts) == 2:
                selection_match = self._evaluate_selection(
                    detection.get(parts[0].strip(), {}),
                    log_entry,
                    log_type
                )
                filter_match = self._evaluate_selection(
                    detection.get(parts[1].strip(), {}),
                    log_entry,
                    log_type
                )
                return selection_match and not filter_match
        
        elif 'or' in condition:
            # Example: "selection1 or selection2"
            parts = condition.split(' or ')
            for part in parts:
                part = part.strip()
                if self._evaluate_selection(detection.get(part, {}), log_entry, log_type):
                    return True
            return False
        
        elif 'and' in condition:
            # Example: "selection1 and selection2"
            parts = condition.split(' and ')
            for part in parts:
                part = part.strip()
                if not self._evaluate_selection(detection.get(part, {}), log_entry, log_type):
                    return False
            return True
        
        return False
    
    def _evaluate_selection(self, selection: Dict[str, Any], log_entry: Dict[str, Any], log_type: str) -> bool:
        """
        Evaluate a selection block against log entry.
        
        Args:
            selection: Selection criteria from rule (can be dict or list)
            log_entry: Log entry to check
            log_type: Type of log for field mapping
        
        Returns:
            True if all selection criteria match
        """
        if not selection:
            return False
        
        # Handle list of selections (OR logic between list items)
        if isinstance(selection, list):
            for item in selection:
                if isinstance(item, dict) and self._evaluate_selection(item, log_entry, log_type):
                    return True
            return False
        
        # Handle dict selection
        if not isinstance(selection, dict):
            return False
        
        field_map = self.field_mappings.get(log_type, {})
        
        for field, values in selection.items():
            # Handle field modifiers (e.g., |contains, |startswith, |endswith)
            modifier = None
            if '|' in field:
                field, modifier = field.split('|', 1)
            
            # Map Sigma field to log field
            log_field = field_map.get(field, field.lower())
            
            # Get value from log entry or parsed_data
            log_value = log_entry.get(log_field)
            
            # Try parsed_data if field not found
            if log_value is None and 'parsed_data' in log_entry:
                try:
                    import json
                    parsed = json.loads(log_entry['parsed_data'])
                    log_value = parsed.get(log_field)
                except:
                    pass
            
            # Also try raw_line for text matching
            if log_value is None:
                log_value = log_entry.get('raw_line', '')
            
            if log_value is None:
                return False
            
            # Convert to string for matching
            log_value_str = str(log_value)
            
            # Check if values match
            if isinstance(values, list):
                # List of values (OR logic)
                matched = False
                for value in values:
                    if self._match_value(log_value_str, str(value), modifier):
                        matched = True
                        break
                if not matched:
                    return False
            else:
                # Single value
                if not self._match_value(log_value_str, str(values), modifier):
                    return False
        
        return True
    
    def _match_value(self, log_value: str, rule_value: str, modifier: Optional[str] = None) -> bool:
        """
        Match a log value against a rule value with optional modifier.
        
        Args:
            log_value: Value from log entry
            rule_value: Value from rule
            modifier: Optional modifier (contains, startswith, endswith, re)
        
        Returns:
            True if values match
        """
        log_value = log_value.lower()
        rule_value = rule_value.lower()
        
        if modifier == 'contains':
            return rule_value in log_value
        elif modifier == 'startswith':
            return log_value.startswith(rule_value)
        elif modifier == 'endswith':
            return log_value.endswith(rule_value)
        elif modifier == 're':
            try:
                return bool(re.search(rule_value, log_value, re.IGNORECASE))
            except:
                return False
        else:
            # Exact match or wildcard
            if '*' in rule_value:
                pattern = rule_value.replace('*', '.*')
                try:
                    return bool(re.search(f'^{pattern}$', log_value, re.IGNORECASE))
                except:
                    return False
            else:
                return log_value == rule_value
    
    def _create_alert(self, rule: SigmaRule, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create an alert from a rule match.
        
        Args:
            rule: Matched Sigma rule
            log_entry: Log entry that matched
        
        Returns:
            Alert dictionary
        """
        return {
            'timestamp': datetime.now().isoformat(),
            'alert_id': f"{rule.id}_{log_entry.get('id', 'unknown')}",
            'rule_id': rule.id,
            'rule_title': rule.title,
            'rule_description': rule.description,
            'severity': rule.level,
            'log_id': log_entry.get('id'),
            'log_type': log_entry.get('log_type'),
            'hostname': log_entry.get('hostname'),
            'ip_address': log_entry.get('ip_address'),
            'raw_line': log_entry.get('raw_line', '')[:500],  # Truncate
            'matched_fields': self._extract_matched_fields(log_entry),
            'false_positives': rule.falsepositives,
            'references': rule.references
        }
    
    def _extract_matched_fields(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant fields from log entry for alert."""
        fields = {}
        
        # Common fields to include
        for key in ['timestamp', 'hostname', 'program', 'message', 
                    'event_id', 'channel', 'method', 'path', 'status_code']:
            if key in log_entry:
                fields[key] = log_entry[key]
        
        return fields
    
    def get_stats(self) -> Dict[str, Any]:
        """Get rule engine statistics."""
        return {
            'total_rules': self.total_rules,
            'linux_rules': len(self.rules['linux']),
            'windows_rules': len(self.rules['windows']),
            'nginx_rules': len(self.rules['nginx']),
            'rules_dir': str(self.rules_dir)
        }
