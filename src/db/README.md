# 🔥 Database Layer - Repository Pattern

Production-grade database architecture for the IronClad SIEM system.

## 📁 Structure

```
src/db/
├── __init__.py              # Main exports
├── setup.py                 # Database setup & initialization
├── models.py                # SQLAlchemy models
├── example_usage.py         # Usage examples
│
└── repository/              # Repository pattern
    ├── __init__.py          # Repository exports
    ├── server_repo.py       # Server operations
    ├── log_repo.py          # Log entry operations
    ├── linux_repo.py        # Linux log details
    ├── windows_repo.py      # Windows log details
    ├── nginx_repo.py        # Nginx log details
    ├── alert_repo.py        # Alert operations
    └── rule_repo.py         # Alert rule operations
```

## 🎯 Why Repository Pattern?

✅ **Clean Separation** - Business logic stays separate from DB queries  
✅ **Easy Testing** - Mock repositories instead of database  
✅ **Maintainable** - Each file handles one domain  
✅ **Scalable** - Easy to switch from SQLite → PostgreSQL  
✅ **Professional** - Industry-standard architecture  

## 🚀 Quick Start

### 1. Initialize Database

```python
from src.db import init_db

# Create all tables
init_db()
```

### 2. Use in Listener (Raw Log Storage)

```python
from src.db import get_or_create_server, insert_raw_log

# Register server
server_id = get_or_create_server(
    hostname="webserver-01",
    ip="192.168.1.100",
    server_type="linux"
)

# Store raw log
log_id = insert_raw_log(
    server_id=server_id,
    log_source="linux",
    content="Jan 15 10:23:45 webserver sshd[1234]: Accepted publickey..."
)
```

### 3. Use in Parser Worker

```python
from src.db import get_unparsed_linux_logs, insert_linux_details

# Get unparsed logs
logs = get_unparsed_linux_logs(limit=50)

for log in logs:
    # Parse log
    parsed = parse_linux_log(log.content)
    
    # Store parsed details
    insert_linux_details(log.id, parsed)
```

### 4. Use in Alert Engine

```python
from src.db import get_active_rules_for_source, create_alert

# Get rules
rules = get_active_rules_for_source("linux")

# Create alert if rule matches
alert_id = create_alert(
    log_entry_id=log.id,
    server_id=log.server_id,
    rule_id=rule.id,
    severity="critical",
    title="Brute Force Attack Detected",
    description="Multiple failed login attempts",
    metadata={"attempts": 10, "source_ip": "1.2.3.4"}
)
```

### 5. Use in Dashboard API

```python
from src.db import get_recent_alerts

# Get unresolved critical alerts
alerts = get_recent_alerts(
    limit=20,
    severity="critical",
    resolved=False
)
```

## 📊 Database Schema

### Core Tables

#### `server`
- Tracks all monitored servers
- Fields: hostname, ip_address, server_type

#### `log_entry`
- Stores raw log entries
- Fields: server_id, recv_time, log_source, content

#### `*_log_details`
- Stores parsed log details for each source
- Tables: linux_log_details, windows_log_details, nginx_log_details

#### `alert_rule`
- Defines detection rules
- Fields: name, log_source, severity, enabled, rule_content

#### `alert`
- Stores triggered alerts
- Fields: log_entry_id, server_id, rule_id, severity, title, metadata

## 🔧 Repository Functions

### Server Operations
- `get_or_create_server(hostname, ip, server_type)` → server_id

### Log Operations
- `insert_raw_log(server_id, log_source, content, recv_time=None)` → log_id
- `get_unparsed_linux_logs(limit=50)` → List[LogEntry]
- `get_unparsed_windows_logs(limit=50)` → List[LogEntry]
- `get_unparsed_nginx_logs(limit=50)` → List[LogEntry]

### Parsed Details
- `insert_linux_details(log_entry_id, parsed)`
- `insert_windows_details(log_entry_id, event_json)`
- `insert_nginx_details(log_entry_id, parsed)`

### Alert Operations
- `create_alert(log_entry_id, server_id, rule_id, severity, title, description, metadata)` → alert_id
- `get_recent_alerts(limit=100, severity=None, resolved=None)` → List[Alert]
- `resolve_alert(alert_id)` → bool

### Rule Operations
- `get_active_rules_for_source(log_source)` → List[AlertRule]
- `get_all_rules()` → List[AlertRule]

## 🎨 Usage Examples

See `example_usage.py` for complete working examples:

```bash
cd src/db
python example_usage.py
```

## 🔄 Migration from Old Code

### Before (Old DatabaseManager)
```python
db_manager = DatabaseManager()
server_id = db_manager.get_or_create_server(hostname, ip)
db_manager.insert_log_entry(server_id, "linux", content, {})
```

### After (Repository Pattern)
```python
from src.db import get_or_create_server, insert_raw_log

server_id = get_or_create_server(hostname, ip, "linux")
log_id = insert_raw_log(server_id, "linux", content)
```

**Much cleaner!** ✨

## 🧪 Testing

Each repository is easy to test:

```python
def test_server_repo():
    server_id = get_or_create_server("test-host", "1.2.3.4", "linux")
    assert server_id > 0
    
    # Second call should return same ID
    server_id2 = get_or_create_server("test-host", "1.2.3.4", "linux")
    assert server_id == server_id2
```

## 📝 Best Practices

1. **Always use repositories** - Never write raw SQL in workers/listeners
2. **Keep sessions short** - Repositories handle open/close automatically
3. **Use type hints** - Makes code easier to understand
4. **Handle errors** - Repositories use try/finally for cleanup
5. **Test independently** - Mock repositories in unit tests

## 🎯 Next Steps

1. ✅ Database layer complete
2. 🔨 Implement parser workers (use `get_unparsed_*_logs`)
3. 🔨 Implement alert engine (use `get_active_rules_for_source`)
4. 🔨 Build dashboard API (use `get_recent_alerts`)
5. 🔨 Add authentication
6. 🔨 Add real-time notifications

## 💡 Pro Tips

- **Thread-Safe**: Each function creates its own session
- **Auto-Cleanup**: Sessions always close via `finally` blocks
- **Type-Safe**: All functions use Python type hints
- **Documented**: Every function has docstrings
- **Extensible**: Easy to add new repositories

---

**Built with ❤️ for production SIEM systems**
