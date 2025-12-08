# Nginx Sigma Rule Attack Detection Summary

This document summarizes all web attacks for which Sigma rules have been written, along with the detection logic used for each in Nginx access logs.

---

## 1. SQL Injection
**Detection:** Requests containing SQL keywords, operators, or suspicious patterns (e.g., 'UNION SELECT', 'OR 1=1', '--', 'sleep(').

## 2. Cross-Site Scripting (XSS)
**Detection:** Requests with script tags, event handlers, or encoded payloads (e.g., '<script>', 'onerror=', '%3Cscript%3E').

## 3. Directory Traversal
**Detection:** Requests containing '../', '..\', or attempts to access sensitive files (e.g., '/etc/passwd', 'boot.ini').

## 4. Remote File Inclusion (RFI)
**Detection:** Requests with 'http://', 'https://', 'ftp://', or 'php://' in parameters, indicating attempts to include remote files.

## 5. Command Injection
**Detection:** Requests with shell command patterns (e.g., ';', '|', '&&', 'wget', 'curl', 'nc', 'bash').

## 6. Brute Force Login
**Detection:** Multiple login attempts from the same IP within a short timeframe (aggregation logic).

## 7. Web Shell Upload
**Detection:** Requests attempting to upload files with web shell signatures (e.g., '.php', 'shell', 'cmd').

## 8. Path Probing
**Detection:** Requests probing for common admin or sensitive paths (e.g., '/admin', '/config', '/backup').

## 9. HTTP Method Abuse
**Detection:** Use of uncommon or dangerous HTTP methods (e.g., PUT, DELETE, TRACE).

## 10. User-Agent Spoofing
**Detection:** Requests with suspicious or known malicious user agents (e.g., 'curl', 'python', 'sqlmap').

## 11. DDoS/Scanning
**Detection:** High number of requests from the same IP within a short timeframe (aggregation logic).

## 12. Local File Inclusion (LFI)
**Detection:** Requests attempting to include local files via parameters (e.g., '/etc/passwd', 'file=', 'include=').

## 13. Authentication Bypass
**Detection:** Requests to login/auth endpoints with successful status codes, excluding logout actions.

## 14. CSRF (Cross-Site Request Forgery)
**Detection:** Suspicious POST/PUT/DELETE requests with empty or missing Referer headers.

## 15. Credential Stuffing
**Detection:** Multiple login attempts with different usernames from the same IP (aggregation logic).

## 16. Sensitive Data Exposure
**Detection:** Requests for sensitive files (e.g., '.env', '.git', '.htaccess', '.bak', 'config.php').

## 17. API Abuse
**Detection:** Excessive API calls to sensitive endpoints from the same IP (aggregation logic).

## 18. Advanced XSS (Reflected/Stored)
**Detection:** Requests with encoded payloads, script tags, or suspicious JavaScript in parameters.

## 19. HTTP Response Splitting
**Detection:** Requests containing CRLF injection patterns (e.g., '%0d%0a', '\r\n', 'Set-Cookie:', 'Location:').

## 20. Open Redirects
**Detection:** Requests with suspicious redirect parameters (e.g., 'redirect=', 'url=', 'next=', 'return=').

## 21. File Download/Exfiltration
**Detection:** Large or repeated downloads of sensitive files (e.g., '.zip', '.tar', '.sql', '.db') from the same IP (aggregation logic).

## 22. Automated Tools/Scanners
**Detection:** Requests with user agents or patterns matching known tools (e.g., sqlmap, Nikto, Acunetix, wpscan).

## 23. Misconfigured CORS
**Detection:** Requests exploiting CORS misconfigurations (e.g., suspicious Origin headers, 'Access-Control-Allow-Origin:').

## 24. WebDAV Exploitation
**Detection:** Use of WebDAV methods (e.g., PROPFIND, MKCOL, COPY, MOVE, LOCK, UNLOCK).

## 25. Session Fixation
**Detection:** Manipulation of session IDs in requests (e.g., 'sessionid=', 'phpsessid=', 'jsessionid=').

## 26. Host Header Attacks
**Detection:** Manipulation of Host header to internal IPs, cloud metadata endpoints, or attacker domains.

## 27. SSRF (Server-Side Request Forgery)
**Detection:** Requests targeting internal IPs or cloud metadata endpoints (e.g., '127.0.0.1', '169.254.169.254', 'metadata.google.internal').

## 28. XML External Entity (XXE)
**Detection:** Requests with XML payloads or DTD references (e.g., '<!DOCTYPE', '<!ENTITY', 'SYSTEM "file://').

## 29. HTTP Smuggling
**Detection:** Abnormal use of Transfer-Encoding or Content-Length headers in requests.

## 30. JWT Manipulation
**Detection:** Tampering with JWT tokens in requests (e.g., 'eyJ', 'jwt=', 'alg:none', 'Authorization: Bearer').

---

Each rule is implemented in YAML format in the `Sigma_Rules/Nginx` folder and leverages keyword matching, header analysis, and aggregation logic where appropriate.
