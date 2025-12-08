# Linux Process Attack Detection Coverage

This document summarizes all process-based attack types covered by Sigma rules in this project and explains their contribution to comprehensive Linux security monitoring.

## Process Attack Types Covered

1. **Execution of Known Malicious or Suspicious Processes**
   - Detects execution of malware, hacking tools, or unauthorized binaries by process name or path.
   - _Contribution_: Prevents and alerts on known threats and tool usage.

2. **Privilege Escalation**
   - Detects processes running as root or with unusual parent-child relationships.
   - _Contribution_: Flags attempts to gain unauthorized privileges.

3. **Persistence Mechanisms**
   - Detects processes related to cron jobs, systemd services, or startup scripts.
   - _Contribution_: Identifies attackers trying to maintain long-term access.

4. **Process Injection or Masquerading**
   - Detects suspicious or mismatched parent-child process relationships or command lines.
   - _Contribution_: Reveals stealthy code injection or process masquerading.

5. **Reverse Shells and Remote Access Tools**
   - Detects shell processes with network-related command lines or suspicious parents.
   - _Contribution_: Identifies attempts to gain remote shell access.

6. **Lateral Movement Tools**
   - Detects execution of tools like ssh, scp, rsh, or remote desktop clients.
   - _Contribution_: Flags attempts to move laterally within the network.

7. **Unusual User Activity**
   - Detects processes started by unexpected users.
   - _Contribution_: Prevents abuse of compromised or misused accounts.

8. **Unusual Binary Locations**
   - Detects execution of binaries from /tmp, /dev/shm, or other non-standard directories.
   - _Contribution_: Prevents execution of malware from temporary or hidden locations.

9. **Credential Dumping or Collection**
   - Detects execution of known credential dumping tools or suspicious access to sensitive files.
   - _Contribution_: Prevents theft of credentials and sensitive data.

10. **Suspicious Scripting or Interpreter Usage**
    - Detects execution of python, perl, ruby, or other interpreters with suspicious scripts or arguments.
    - _Contribution_: Flags script-based attacks and obfuscated payloads.

11. **Process Hiding or Tampering**
    - Detects processes with names similar to system processes but running from unusual locations.
    - _Contribution_: Reveals attempts to hide or disguise malicious processes.

12. **Unusual Process Status**
    - Detects processes stuck in zombie or uninterruptible states.
    - _Contribution_: Identifies exploitation, resource exhaustion, or system instability.

13. **Suspicious Parent-Child Process Relationships**
    - Detects shells or interpreters spawned by web servers, database processes, or SSH.
    - _Contribution_: Flags web shells, post-exploitation, and privilege escalation techniques.

---

## Overall Contribution to the Project

By covering this wide range of process attack types, the project achieves:
- **Comprehensive Process Threat Detection:** Monitors for both common and advanced process-based attack techniques.
- **Early Warning:** Provides early alerts for suspicious process activity, allowing for rapid response.
- **Defense in Depth:** Complements network and log-based detection for holistic security.
- **Forensic Readiness:** Ensures critical process events are logged and can be investigated after an incident.
- **Compliance:** Helps meet security monitoring requirements for various standards.

This approach significantly enhances the security posture of Linux systems by leveraging process logs and Sigma rules for automated, scalable, and actionable threat detection.
