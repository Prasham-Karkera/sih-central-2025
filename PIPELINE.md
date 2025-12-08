# Log Ingestion Pipeline

Simple 3-layer architecture: **Listen → Parse → Save**

## Architecture

```
UdpListener (port 5140)
    ↓
ParserManager (auto-detect: Windows/Linux/Nginx)
    ↓
DatabaseManager (SQLite + batch files)
```

## Quick Start

### 1. Start the Pipeline

```bash
python -m src.workers.ingestion_worker
```

This will:
- Listen on UDP port 5140
- Auto-detect log types
- Batch logs (100 or 5 seconds)
- Save to `logs.db` SQLite database

### 2. Send Test Logs

**Windows Logs:**
```powershell
echo '{"timestamp":"2025-12-06 04:06:30","hostname":"HP-LAP704","channel":"Security","event_id":4799}' | Out-File -Encoding ASCII temp.txt
.\scripts\windows_sender.ps1 -LogFile temp.txt
```

**Linux Logs:**
```bash
echo "Dec 6 04:17:07 Hp-lap704 CRON[947]: (root) CMD (test)" | nc -u localhost 5140
```

**Nginx Logs:**
```bash
echo '192.168.1.100 - - [06/Dec/2025:04:17:07 +0000] "GET /api/test HTTP/1.1" 200 1234' | nc -u localhost 5140
```

### 3. Check Database

```python
from src.db.database import DatabaseManager

db = DatabaseManager("./logs.db")
stats = db.get_stats()
print(stats)
# Output: {'total_logs': 150, 'total_servers': 3, 'by_type': {'windows': 50, 'linux': 80, 'nginx': 20}}
```

## Components

### UdpListener
- Generic UDP socket wrapper
- Listens on `0.0.0.0:5140`
- Returns: `{recv_time, src_ip, line}`

### ParserManager
- Auto-detects log type
- Priority: Windows → Nginx → Linux (fallback)
- Returns: `{log_type, hostname, timestamp, ...fields}`

### DatabaseManager
- SQLite with normalized schema
- Thread-safe connections
- Batch operations for performance

## Configuration

Edit `src/workers/ingestion_worker.py`:

```python
worker = IngestionWorker(
    host="0.0.0.0",
    port=5140,
    batch_size=100,        # Max logs per batch
    batch_timeout=5.0,     # Max seconds before flush
    db_path="./logs.db",
    output_dir="./collected_logs/processed"
)
```

## Database Schema

```sql
server: id, hostname, ip_address, first_seen, last_seen
log_entry: id, timestamp, recv_time, server_id, log_type, raw_line
linux_log_details: log_entry_id, facility, severity, program, pid, message
windows_log_details: log_entry_id, channel, event_id, message, user_name
nginx_log_details: log_entry_id, method, path, status_code, bytes, user_agent
```

## Statistics

The worker prints stats every 100 logs:

```
============================================================
[Stats] Received: 500
[Stats] Parsed:   485
[Stats] Saved:    485
[Stats] Errors:   15
[Stats] Batches:  5
[Stats] DB Total: 485
[Stats] By Type:  {'windows': 200, 'linux': 250, 'nginx': 35}
============================================================
```

## Adding New Parsers

1. Create parser class inheriting from `BaseParser`
2. Implement: `can_parse()`, `parse()`, `get_log_type()`
3. Register in `ParserManager.__init__()`

```python
from src.base.base_parser import BaseParser

class MyParser(BaseParser):
    def can_parse(self, raw_line: str) -> bool:
        return raw_line.startswith("MYFORMAT:")
    
    def parse(self, raw_line: str, metadata: dict = None) -> dict:
        # Parse logic
        return {"field": "value"}
    
    def get_log_type(self) -> str:
        return "myformat"
```

## Troubleshooting

**Port already in use:**
```bash
# Windows
netstat -ano | findstr :5140
taskkill /PID <pid> /F

# Linux
sudo lsof -i :5140
sudo kill <pid>
```

**No logs parsed:**
- Check log format matches parser regex
- Enable verbose logging in parsers
- Check `can_parse()` logic

**Database locked:**
- Only one writer at a time
- Use batch operations
- Check thread-safe connections

## Next Steps

- [ ] Add authentication/encryption for UDP
- [ ] Implement log rotation
- [ ] Add Elasticsearch output
- [ ] Create web dashboard
- [ ] Add alerting rules
- [ ] Implement rate limiting
