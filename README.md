# Ironclad Log Ingestion
    
This project provides a unified log ingestion system for collecting, parsing, and storing logs from multiple sources (Linux, Windows, Nginx, etc.) across multiple servers. The logs are normalized and stored in a SQLite database for efficient querying and analysis.

## Features
- Listens for syslog (Linux), SNMP traps, and Windows event logs
- Parses and normalizes logs from different sources
- Supports multiple servers of each type
- Stores logs in a normalized SQLite database schema

## How It Works
- The listener receives logs via UDP (syslog) and SNMP traps
- Each log is parsed according to its source type
- Parsed logs are stored in the database, linked to their originating server
- Windows logs are stored as full JSON bodies; Linux and Nginx logs are parsed into structured fields

## Database Schema

### Table: `server`
| Column Name   | Type         | Description                                 |
|---------------|-------------|---------------------------------------------|
| id            | INTEGER PK  | Unique server ID                            |
| hostname      | VARCHAR     | Hostname of the server                      |
| ip_address    | VARCHAR     | IP address of the server                    |
| server_type   | VARCHAR     | Type: 'linux', 'windows', 'nginx', etc.     |

### Table: `log_entry`
| Column Name   | Type         | Description                                 |
|---------------|-------------|---------------------------------------------|
| id            | INTEGER PK  | Unique log entry ID                         |
| server_id     | INTEGER FK  | References server(id)                       |
| recv_time     | DATETIME    | Time the log was received                   |
| log_source    | VARCHAR     | Source type: 'linux', 'windows', 'nginx'    |
| content       | TEXT/JSON   | Raw log line or full Windows JSON           |

### Table: `linux_log_details`
| Column Name   | Type         | Description                                 |
|---------------|-------------|---------------------------------------------|
| log_entry_id  | INTEGER FK  | References log_entry(id)                    |
| timestamp     | DATETIME    | Timestamp from log                          |
| app_name      | VARCHAR     | Application name                            |
| pid           | INTEGER     | Process ID (nullable)                       |
| raw_message   | TEXT        | Raw message                                 |
| ssh_action    | VARCHAR     | SSH action (nullable)                       |
| ssh_user      | VARCHAR     | SSH user (nullable)                         |
| ssh_ip        | VARCHAR     | SSH source IP (nullable)                    |

### Table: `nginx_log_details`
| Column Name      | Type         | Description                               |
|------------------|-------------|-------------------------------------------|
| log_entry_id     | INTEGER FK  | References log_entry(id)                  |
| remote_addr      | VARCHAR     | Client IP address                         |
| remote_user      | VARCHAR     | Remote user                               |
| time_local       | DATETIME    | Local time                                |
| request_method   | VARCHAR     | HTTP method                               |
| request_uri      | VARCHAR     | Requested URI                             |
| server_protocol  | VARCHAR     | Protocol                                  |
| status           | INTEGER     | HTTP status code                          |
| body_bytes_sent  | INTEGER     | Bytes sent                                |
| http_referer     | VARCHAR     | HTTP referer                              |
| http_user_agent  | VARCHAR     | User agent                                |

### Table: `windows_log_details`
| Column Name   | Type         | Description                                 |
|---------------|-------------|---------------------------------------------|
| log_entry_id  | INTEGER FK  | References log_entry(id)                    |
| content       | JSON        | Full Windows event JSON body                |

## Usage
1. Run `final_listner.py` to start the ingestion service on your Python server.
2. On each Windows server, use the following PowerShell script to ship logs to the ingestion server:

```powershell
# --- CONFIGURATION ---
$TargetIP = "192.168.0.192"  # Change to your Python IP
$Port = 5140
# We now monitor multiple channels
$LogChannels = @("Security", "Application", "System")

# --- SETUP ---
$UdpClient = New-Object System.Net.Sockets.UdpClient
$TargetEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($TargetIP), $Port)
$Hostname = $env:COMPUTERNAME
$LastCheckTime = Get-Date

Write-Host "--- MULTI-CHANNEL LOG SHIPPER STARTED ---" -ForegroundColor Green
Write-Host "Target: $TargetIP : $Port"
Write-Host "Monitoring: $($LogChannels -join ', ')"

# --- MAIN LOOP ---
while ($true) {
	$events = Get-WinEvent -FilterHashTable @{
		LogName   = $LogChannels
		StartTime = $LastCheckTime
	} -ErrorAction SilentlyContinue | Sort-Object TimeCreated

	if ($events) {
		foreach ($event in $events) {
			$logObj = [ordered]@{
				timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
				hostname  = $Hostname
				channel   = $event.LogName
				event_id  = $event.Id
				level     = $event.LevelDisplayName
				message   = $event.Message
			}

			try {
				$xml = [xml]$event.ToXml()
				$eventData = $xml.Event.EventData.Data
				if ($eventData) {
					foreach ($dataPoint in $eventData) {
						if ($dataPoint.Name -and $dataPoint.'#text') {
							$logObj[$dataPoint.Name] = $dataPoint.'#text'
						}
					}
				}
			}
			catch {}

			$jsonPayload = $logObj | ConvertTo-Json -Compress -Depth 2
			$bytes = [System.Text.Encoding]::UTF8.GetBytes($jsonPayload)
			try {
				[void]$UdpClient.Send($bytes, $bytes.Length, $TargetEndpoint)
				$color = switch ($event.LogName) {
					"Security" { "Cyan" }
					"System"   { "Yellow" }
					"Application" { "Magenta" }
					Default { "White" }
				}
				Write-Host "[$($event.LogName)] ID: $($event.Id)" -ForegroundColor $color
			}
			catch {
				Write-Host "Send Failed" -ForegroundColor Red
			}
			$LastCheckTime = $event.TimeCreated
		}
	}
	Start-Sleep -Milliseconds 500
}
```

3. Logs will be parsed and stored in `collected_logs/ironclad_logs.db` on the Python server.
4. Query the database using any SQLite client for analysis.

## Extending
- Add new log sources by extending the parser and schema
- Integrate with other databases or analytics platforms as needed

---
For questions or improvements, please open an issue or contribute!
