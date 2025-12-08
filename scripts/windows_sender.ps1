# --- CONFIGURATION ---
$TargetIP = "192.168.137.247"  # Change to your Python IP
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
    # Get events from ALL defined channels that happened since the last check
    # We sort by TimeCreated so we process them in chronological order
    $events = Get-WinEvent -FilterHashTable @{
        LogName   = $LogChannels
        StartTime = $LastCheckTime
    } -ErrorAction SilentlyContinue | Sort-Object TimeCreated

    if ($events) {
        foreach ($event in $events) {
            # 1. Create Base Object
            # We use $event.LogName dynamically now to catch if it's System vs Security
            $logObj = [ordered]@{
                timestamp = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                hostname  = $Hostname
                channel   = $event.LogName
                event_id  = $event.Id
                level     = $event.LevelDisplayName
                message   = $event.Message
            }

            # 2. Universal XML Parsing
            # Extracts hidden data fields regardless of the source log
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
            catch {
                # Some system events might not convert to XML cleanly; we skip extended fields for those
            }

            # 3. Send to Python
            $jsonPayload = $logObj | ConvertTo-Json -Compress -Depth 2
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($jsonPayload)

            try {
                [void]$UdpClient.Send($bytes, $bytes.Length, $TargetEndpoint)

                # Color code output based on Channel for easy debugging
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

            # Update time so we don't re-read this event
            $LastCheckTime = $event.TimeCreated
        }
    }

    # Tiny pause to save CPU
    Start-Sleep -Milliseconds 500
}
 