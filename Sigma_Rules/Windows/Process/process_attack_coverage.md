# Windows Process Attack Coverage

This document summarizes the detection logic for malicious and suspicious activity in Windows process logs, as implemented by the Sigma rules in this project. Each attack type is mapped to a corresponding Sigma rule, with a brief explanation of its detection logic and its contribution to the overall security monitoring objectives.

## Attack Types & Detection Logic

### 1. Execution of Known Malicious or Suspicious Processes
- **Detection:** Identifies execution of malware, hacking tools, or unauthorized binaries by process name or path (e.g., mimikatz, procdump, cobaltstrike).
- **Contribution:** Enables early detection of commodity malware and offensive security tools, reducing dwell time.

### 2. Privilege Escalation
- **Detection:** Flags processes running as SYSTEM or with unexpected elevated privileges, and unusual parent-child relationships (e.g., Office spawning SYSTEM shells).
- **Contribution:** Detects attempts to gain unauthorized privileges, a key step in most attacks.

### 3. Persistence Mechanisms
- **Detection:** Monitors for processes related to scheduled tasks, services, registry autoruns, or startup folders.
- **Contribution:** Identifies attacker attempts to maintain access after initial compromise.

### 4. Process Injection or Masquerading
- **Detection:** Looks for suspicious or mismatched parent-child process relationships, and command lines or executable paths that do not match process names.
- **Contribution:** Detects stealthy techniques used to evade defenses and blend in with legitimate processes.

### 5. Reverse Shells and Remote Access Tools
- **Detection:** Flags shell processes (cmd.exe, powershell.exe) with network-related command lines or suspicious parents.
- **Contribution:** Enables detection of remote access and command-and-control channels.

### 6. Lateral Movement Tools
- **Detection:** Detects execution of tools like psexec, wmic, mstsc, or remote desktop clients.
- **Contribution:** Surfaces attacker attempts to move laterally within the network.

### 7. Unusual User Activity
- **Detection:** Identifies processes started by unexpected users (e.g., SYSTEM processes started by non-SYSTEM users).
- **Contribution:** Highlights potential account misuse or privilege escalation.

### 8. Unusual Binary Locations
- **Detection:** Flags execution of binaries from temp folders, user profiles, or other non-standard directories.
- **Contribution:** Detects malware and tools dropped in non-standard locations to evade detection.

### 9. Credential Dumping or Collection
- **Detection:** Monitors for execution of known credential dumping tools or suspicious access to sensitive files (e.g., mimikatz, procdump, lsass access).
- **Contribution:** Detects attempts to steal credentials for further compromise.

### 10. Suspicious Scripting or Interpreter Usage
- **Detection:** Flags execution of scripting engines (powershell.exe, cscript.exe, wscript.exe) with suspicious scripts or arguments (e.g., base64, IEX, DownloadString).
- **Contribution:** Surfaces fileless attacks and living-off-the-land techniques.

### 11. Process Hiding or Tampering
- **Detection:** Detects processes with names similar to system processes but running from unusual locations.
- **Contribution:** Identifies attempts to masquerade as legitimate system processes.

### 12. Suspicious Parent-Child Relationships
- **Detection:** Flags Office or browser processes spawning command shells or scripting engines.
- **Contribution:** Detects initial access and exploitation via phishing or drive-by downloads.

### 13. Unusual Process Status or Behavior
- **Detection:** Monitors for processes rapidly spawning and terminating, or stuck in unresponsive states.
- **Contribution:** Surfaces process abuse, instability, or resource exhaustion attacks.

## Overall Project Contribution

By implementing these Sigma rules for Windows process logs, the project achieves:
- **Comprehensive Threat Coverage:** Detects a wide range of attack techniques mapped to MITRE ATT&CK, including both common and advanced threats.
- **Early Detection & Response:** Enables rapid identification of malicious activity, reducing attacker dwell time and impact.
- **Defense-in-Depth:** Complements network and syslog-based detection, providing layered visibility across the attack chain.
- **Operational Value:** Supports SOC analysts and incident responders with actionable alerts and context-rich detections.
- **Adaptability:** Sigma rules are easily extendable and can be mapped to various SIEM and log analysis platforms.

This approach ensures robust monitoring of Windows environments, helping organizations detect, investigate, and respond to threats more effectively.