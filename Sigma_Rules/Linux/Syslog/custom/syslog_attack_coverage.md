
This document summarizes all the attack types covered by Sigma rules in this project and explains their contribution to comprehensive Linux security monitoring.

## Attack Types Covered

1. **Disabling Security Tools**
   - Detects attempts to stop or disable firewalls and security agents (e.g., iptables, firewalld, falcon-sensor).
   - _Contribution_: Prevents attackers from evading detection and weakening system defenses.

2. **Suspicious DNS Errors**
   - Detects fatal or suspicious DNS server errors that may indicate exploitation attempts.
   - _Contribution_: Identifies initial access or exploitation of DNS services.

3. **Privilege Escalation Attempts**
   - Detects suspicious or failed sudo/su attempts.
   - _Contribution_: Alerts on attempts to gain unauthorized root or elevated privileges.

4. **Persistence Mechanisms**
   - Detects creation/modification of cron jobs or systemd services.
   - _Contribution_: Identifies attackers trying to maintain long-term access.

5. **Lateral Movement**
   - Detects unusual SSH logins or remote execution attempts.
   - _Contribution_: Flags attempts to move laterally within the network.

6. **Data Exfiltration**
   - Detects use of tools like netcat, curl, wget for data transfer.
   - _Contribution_: Prevents sensitive data from being exfiltrated.

7. **Malware or Rootkit Activity**
   - Detects suspicious process names or kernel module activity.
   - _Contribution_: Identifies possible malware or rootkit installation.

8. **Log Tampering**
   - Detects deletion/modification of logs or stopping of logging services.
   - _Contribution_: Prevents attackers from covering their tracks.

9. **Exploitation Attempts**
   - Detects buffer overflows, segmentation faults, or repeated failed access.
   - _Contribution_: Flags exploitation of vulnerabilities.

10. **Suspicious File or Directory Changes**
    - Detects creation of hidden files or changes to critical system files.
    - _Contribution_: Prevents unauthorized changes to sensitive files.

11. **Network Attacks**
    - Detects port scanning or unusual network activity.
    - _Contribution_: Identifies reconnaissance and network-based attacks.

12. **Unauthorized Software Installation**
    - Detects installation/execution of unapproved packages or binaries.
    - _Contribution_: Prevents introduction of malicious or unwanted software.

13. **Brute Force Attacks**
    - Detects repeated failed login attempts and account lockouts.
    - _Contribution_: Flags password guessing and brute force attempts.

14. **Suspicious User Creation or Privilege Changes**
    - Detects new user accounts or privilege escalation via group changes.
    - _Contribution_: Prevents unauthorized user creation and privilege abuse.

15. **Suspicious Scheduled Task Creation**
    - Detects creation of unusual or hidden cron/at jobs.
    - _Contribution_: Identifies persistence mechanisms.

16. **Suspicious Binary Execution**
    - Detects execution of binaries from non-standard locations or interpreters with suspicious scripts.
    - _Contribution_: Flags execution of potentially malicious code.

17. **Reverse Shell Activity**
    - Detects outbound connections from shell processes or common reverse shell patterns.
    - _Contribution_: Prevents attackers from gaining remote shell access.

18. **Kernel Exploit Attempts**
    - Detects kernel panic, oops, or exploit signatures.
    - _Contribution_: Identifies exploitation of kernel vulnerabilities.

19. **Unusual Network Configuration Changes**
    - Detects changes to network interfaces, routes, or firewall rules.
    - _Contribution_: Prevents unauthorized network reconfiguration.

20. **Suspicious Mount or Device Activity**
    - Detects mounting of external devices or loop devices.
    - _Contribution_: Flags attempts to introduce or access unauthorized storage.

21. **Time Manipulation**
    - Detects changes to system time or NTP service tampering.
    - _Contribution_: Prevents attackers from hiding their activity by altering timestamps.

22. **Process Injection or Debugging**
    - Detects use of ptrace, gdb, or strace on critical processes.
    - _Contribution_: Flags attempts to inject code or debug sensitive processes.

---

## Overall Contribution to the Project

By covering this wide range of attack types, the project achieves:
- **Comprehensive Threat Detection:** Monitors for both common and advanced attack techniques.
- **Early Warning:** Provides early alerts for suspicious activity, allowing for rapid response.
- **Defense in Depth:** Complements other security controls by detecting attacks that bypass traditional defenses.
- **Forensic Readiness:** Ensures critical events are logged and can be investigated after an incident.
- **Compliance:** Helps meet security monitoring requirements for various standards.

This holistic approach significantly enhances the security posture of Linux systems by leveraging syslog and Sigma rules for automated, scalable, and actionable threat detection.
