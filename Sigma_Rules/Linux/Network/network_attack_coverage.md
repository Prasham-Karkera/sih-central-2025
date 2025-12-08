# Linux Network Attack Detection Coverage

This document summarizes all network-based attack types covered by Sigma rules in this project and explains their contribution to comprehensive Linux security monitoring.

## Network Attack Types Covered

1. **Unusual Outbound Connections**
   - Detects outbound connections to rare or foreign IPs (potential data exfiltration or C2 communication).
   - _Contribution_: Helps identify compromised hosts communicating with external threats.

2. **Port Scanning or Lateral Movement**
   - Detects multiple connections to many internal hosts or ports (internal reconnaissance or lateral movement).
   - _Contribution_: Flags attackers mapping the network or moving laterally.

3. **Suspicious Listening Services**
   - Detects unexpected processes listening on non-standard ports (potential backdoors or malware).
   - _Contribution_: Reveals unauthorized or malicious services.

4. **Reverse Shells**
   - Detects shell processes making outbound connections (reverse shells).
   - _Contribution_: Identifies attempts to gain remote shell access.

5. **Malware or Unauthorized Tools**
   - Detects known malicious or unauthorized process names establishing network connections.
   - _Contribution_: Prevents use of hacking tools and malware.

6. **Data Exfiltration Tools Usage**
   - Detects outbound connections from processes like netcat, curl, wget, or custom binaries.
   - _Contribution_: Prevents sensitive data from being exfiltrated.

7. **Brute Force or Credential Stuffing**
   - Detects repeated connections to authentication services from the same remote IP.
   - _Contribution_: Flags password guessing and brute force attempts.

8. **Command and Control (C2) Activity**
   - Detects persistent connections to known C2 infrastructure or suspicious remote addresses.
   - _Contribution_: Identifies ongoing attacker control over compromised systems.

9. **Lateral Movement via Remote Execution**
   - Detects connections from system management tools to other internal systems.
   - _Contribution_: Flags attempts to move laterally using remote execution.

10. **Unusual Protocol Usage**
    - Detects UDP connections on ports typically used for TCP, or vice versa.
    - _Contribution_: Reveals protocol misuse or covert channels.

11. **DNS Tunneling or Exfiltration**
    - Detects high-volume or suspicious DNS queries (potential tunneling or exfiltration).
    - _Contribution_: Prevents data exfiltration via DNS.

12. **ARP Spoofing/Poisoning**
    - Detects duplicate or rapidly changing ARP entries (potential MITM attacks).
    - _Contribution_: Identifies man-in-the-middle attempts.

13. **DHCP Attacks**
    - Detects rogue DHCP server responses or multiple DHCP offers.
    - _Contribution_: Prevents network takeover attempts.

14. **SMB/Windows File Sharing Abuse**
    - Detects unusual SMB connections from Linux hosts.
    - _Contribution_: Flags lateral movement or data theft via SMB.

15. **ICMP Tunneling or Scanning**
    - Detects high volume or unusual ICMP traffic (covert channels or recon).
    - _Contribution_: Identifies covert channels or network mapping.

16. **Unusual VPN or Proxy Usage**
    - Detects VPN/proxy process connections (potential exfiltration or bypass).
    - _Contribution_: Prevents unauthorized tunneling or bypassing controls.

17. **Network Service Enumeration**
    - Detects repeated connections to a range of service ports (service discovery).
    - _Contribution_: Flags attackers discovering available services.

18. **Unusual Peer-to-Peer (P2P) Traffic**
    - Detects P2P protocols or known P2P ports.
    - _Contribution_: Prevents data exfiltration or malware C2 via P2P.

19. **Unencrypted Sensitive Protocols**
    - Detects use of unencrypted protocols (FTP, Telnet, HTTP) for sensitive data transfer.
    - _Contribution_: Prevents exposure of sensitive data in cleartext.

20. **Outbound Connections to Blacklisted/Threat-Intel IPs**
    - Detects connections to IPs/domains known for malware, phishing, or C2.
    - _Contribution_: Blocks communication with known malicious infrastructure.

21. **Unusual Traffic Volume or Patterns**
    - Detects sudden spikes in network traffic (potential DDoS or exfiltration).
    - _Contribution_: Identifies large-scale attacks or data theft.

22. **IPv6 Tunneling or Abuse**
    - Detects unexpected IPv6 traffic in IPv4-only environments.
    - _Contribution_: Prevents bypass of network controls using IPv6 tunnels.

---

## Overall Contribution to the Project

By covering this wide range of network attack types, the project achieves:
- **Comprehensive Network Threat Detection:** Monitors for both common and advanced network attack techniques.
- **Early Warning:** Provides early alerts for suspicious network activity, allowing for rapid response.
- **Defense in Depth:** Complements host-based and application-based detection for holistic security.
- **Forensic Readiness:** Ensures critical network events are logged and can be investigated after an incident.
- **Compliance:** Helps meet security monitoring requirements for various standards.

This approach significantly enhances the security posture of Linux systems by leveraging network logs and Sigma rules for automated, scalable, and actionable threat detection.
