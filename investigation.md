## Overview

Investigation of a simulated compromise on host `prod-app01` / `web_server`, using Splunk to correlate SSH authentication logs (`syslog`) and web server access logs (`access_combined`). The attacker used three independent techniques against the same target within a single intrusion window: SSH credential brute-forcing, SQL injection, and an insecure file upload leading to remote command execution and data exfiltration.

## Environment

| Item | Value |
|---|---|
| Index | `practice_log` |
| Sourcetypes | `syslog` (SSH/auth), `access_combined` (web access) |
| Hosts | `prod-app01` (auth log), `web_server` (web log) |
| Log date | 2026-09-22 |
| Attacker IP | `185.220.101.47` |

## Methodology

Total volume check to confirm data was indexed correctly before starting analysis:

```spl
index="practice_log" | stats count
```
**Result:** 1813 events total, combined across both log sources.

<img width="567" height="199" alt="Screenshot (502)" src="https://github.com/user-attachments/assets/93abcd77-6648-4d39-8a51-d3d247e6c525" />

---

### 1. SSH brute-force detection

```spl
index="practice_log" sourcetype="syslog" "failed"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count earliest(_time) as first_seen latest(_time) as last_seen by src_ip
| eval first_seen=strftime(first_seen,"%Y-%m-%d %H:%M:%S")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| table src_ip, count, first_seen, last_seen
```
**Result:** IP `185.220.101.47` generated 95 failed login attempts within a short window, well outside normal login behavior and consistent with an automated credential-stuffing/brute-force flood.

<img width="1241" height="342" alt="Screenshot (492)" src="https://github.com/user-attachments/assets/6ae85093-a1c1-423b-993d-e3fe190f3440" />


---

### 2. Successful login after brute-force

```spl
index="practice_log" "accepted" 185.220.101.47
| rex "for (?<user>\w+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| table _time, user, src_ip
```
**Result:** After 95 failed attempts, the same IP successfully authenticated once, as user `admin`.

<img width="1482" height="160" alt="Screenshot (493)" src="https://github.com/user-attachments/assets/5a79fd46-76f1-48f5-9039-35cd78e245f9" />

---

### 3. Post-login privilege escalation

```spl
index="practice_log" sourcetype="syslog" "sudo"
| table _time, _raw
```
**Result:** Immediately following the successful login, `sudo` was used to read `/etc/shadow` and to create a new user account, `svc-backup`, with a set password — indicating the attacker established a persistent backdoor account.

<img width="1395" height="232" alt="Screenshot (496)" src="https://github.com/user-attachments/assets/cc149001-4d4f-4015-bc78-2b01bbf01c3a" />

---

### 4. SQL injection against the web application

```spl
index="practice_log" host="web_server" "login.php" ("UNION" OR "OR" OR "SELECT")
| table _time, clientip
```
**Result:** The same source IP sent SQL injection payloads against `login.php`, attempting to manipulate the backend database query.

<img width="1091" height="262" alt="Screenshot (498)" src="https://github.com/user-attachments/assets/fb4cc781-6f72-4308-a41b-99dbf27f5998" />

---

### 5. Evidence of a successful data dump

```spl
index="practice_log" host="web_server" 
| sort -bytes 
| head 5 
| table _time, clientip, uri, status, bytes
```
**Result:** Among the top 5 largest responses in the web log, the login.php SQL injection request stands out from normal traffic, consistent with a successful UNION SELECT returning table contents (usernames/password hashes). The single largest response overall is the web shell's exfiltration request, covered separately in section 7.

<img width="1485" height="333" alt="Screenshot (505)" src="https://github.com/user-attachments/assets/eb3ba898-4ae6-4ae5-9124-2653bcbbb21b" />

---

### 6. Web shell upload and use

```spl
index="practice_log" host="web_server" ("upload" OR "cmd")
| table _time, clientip, method, uri, status, bytes
```
**Result:** The attacker uploaded a file via `upload.php`, then issued OS commands (`whoami`, `cat /etc/passwd`) through a planted script (`shell.php?cmd=...`), a classic web shell pattern giving direct command execution on the host, independent of the database layer.

<img width="1481" height="268" alt="Screenshot (500)" src="https://github.com/user-attachments/assets/e4a76388-640b-4a07-8169-e3d8340fba42" />

---

### 7. Data exfiltration

```spl
index="practice_log" sourcetype="access_combined"
| table _time, bytes, _raw
| sort -bytes
| head 5
```
**Result:** A single request executed `tar -czf - /var/www/data` through the web shell, returning a ~9 MB response. The application directory compressed and streamed out over HTTP.

<img width="1485" height="472" alt="Screenshot (504)" src="https://github.com/user-attachments/assets/04825176-d1f1-4c13-b7bb-dbd646ba47c3" />

---

## Timeline

| Time | Event |
|---|---|
| 01:40 | SSH brute-force begins against `prod-app01` |
| 01:49 | Brute-force succeeds and attacker logs in as `admin` |
| 01:50 | `sudo` used to read `/etc/shadow` and create backdoor user `svc-backup` |
| 02:10 | SQL injection payloads sent to `login.php` |
| 02:11 | One SQLi request returns an oversized response — credential data dumped |
| 02:12 | File uploaded via `upload.php`; web shell (`shell.php`) planted and used to run OS commands |
| 02:13 | ~9 MB exfiltrated via `tar` command run through the web shell |

## Findings summary

Three separate vulnerabilities were exploited by the same attacker in one intrusion, not a single chain where each step enabled the next:

| Technique | Vulnerability exploited | What it gave the attacker |
|---|---|---|
| SSH brute force | Weak/guessable `admin` password | Server login + ability to escalate via `sudo` |
| SQL injection | Unsanitized input in `login.php` | Read access to the application database (credentials) |
| Insecure file upload | No restriction on executable file types | Direct OS command execution, used for exfiltration |

No evidence in the logs links these techniques causally (e.g. no sign the SSH access was used to reach the upload endpoint, or that stolen credentials were reused). The connection between them is circumstantial: same source IP, same host, same time window.

## Recommendations

- Enforce account lockout / rate limiting on SSH after repeated failures; disable password auth in favor of key-based auth
- Use parameterized queries / prepared statements to eliminate the `login.php` SQL injection vector
- Restrict upload endpoints to non-executable file types, and serve uploaded files from a location with no script execution permissions
- Alert on unusually large outbound HTTP response sizes
- Audit `sudo` usage and newly created accounts, especially outside of change windows

---

*Logs analyzed in Splunk (index practice_log). SPL queries and results above reproduce the investigation steps for reference. All data is synthetic and generated for practice purposes.*
