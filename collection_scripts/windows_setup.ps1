# ---------------------------
# ARGUMENT HANDLING
# ---------------------------

# If IP and Port are not passed, ask interactively
if ($args.Count -lt 2) {
    Write-Host "No IP/Port provided. Please enter details." -ForegroundColor Yellow
    
    $TargetIP = Read-Host "Enter Target IP"
    $Port     = Read-Host "Enter Target Port"

    # Validate port is number
    if (-not ($Port -as [int])) {
        Write-Host "Port must be a number!" -ForegroundColor Red
        exit
    }

    $Port = [int]$Port
}
else {
    # Read from command-line arguments
    $TargetIP = $args[0]
    $Port     = [int]$args[1]
}

# ---------------------------
# CONFIGURATION
# ---------------------------
$LogChannels = @("Security", "Application", "System")

$UdpClient = New-Object System.Net.Sockets.UdpClient
$TargetEndpoint = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($TargetIP), $Port)

$Hostname = $env:COMPUTERNAME
$LastCheckTime = Get-Date

Write-Host "---------------------------------------------" -ForegroundColor Green
Write-Host " Windows Log Shipper Started" -ForegroundColor Green
Write-Host " Target: $TargetIP`:$Port"
Write-Host " Monitoring: $($LogChannels -join ', ')"
Write-Host "---------------------------------------------" -ForegroundColor Green

# ---------------------------
# MAIN LOOP
# ---------------------------
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

            # Extended XML fields extraction
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
            } catch {}

            # Convert to JSON
            $jsonPayload = $logObj | ConvertTo-Json -Compress -Depth 2
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($jsonPayload)

            try {
                [void]$UdpClient.Send($bytes, $bytes.Length, $TargetEndpoint)

                $color = switch ($event.LogName) {
                    "Security" { "Cyan" }
                    "System" { "Yellow" }
                    "Application" { "Magenta" }
                    default { "White" }
                }

                Write-Host "[$($event.LogName)] Event ID: $($event.Id)" -ForegroundColor $color

            } catch {
                Write-Host "Send Failed!" -ForegroundColor Red
            }

            $LastCheckTime = $event.TimeCreated
        }
    }

    Start-Sleep -Milliseconds 500
}
