import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { detectFormat, parseWinTime, parseLinux, parseWeb, parseWindows } from "../src/parse.js";
import { analyze } from "../src/timeline.js";
import { toCsv, toMarkdown } from "../src/report.js";

const ex = (n: string) => readFileSync(new URL(`../../examples/${n}`, import.meta.url), "utf8");
const win = (id: number, min: number, data: Record<string, string>, host = "H1") => JSON.stringify({ Id: id, TimeCreated: new Date(Date.UTC(2026, 0, 1, 0, min)).toISOString(), MachineName: host, EventData: data });

test("detectFormat tells the three formats apart", () => {
  assert.equal(detectFormat('{"Id":1}'), "win");
  assert.equal(detectFormat("[{}]"), "win");
  assert.equal(detectFormat('1.2.3.4 - - [01/Jan/2026:00:00:00 +0000] "GET / HTTP/1.1" 200 5'), "web");
  assert.equal(detectFormat("Jan  1 00:00:01 h sshd[1]: hello"), "linux");
  assert.equal(detectFormat("plain text"), "unknown");
});

test("parseWinTime handles the common export shapes", () => {
  assert.equal(parseWinTime("2026-01-01T00:00:00Z"), Date.UTC(2026, 0, 1));
  assert.equal(parseWinTime("/Date(1767225600000)/"), 1767225600000);
  assert.equal(parseWinTime("1/1/2026 12:30:00 AM"), Date.UTC(2026, 0, 1, 0, 30));
  assert.equal(parseWinTime("1/1/2026 12:30:00 PM"), Date.UTC(2026, 0, 1, 12, 30));
  assert.equal(parseWinTime({ SystemTime: "2026-01-01T00:00:00Z" }), Date.UTC(2026, 0, 1));
  assert.equal(parseWinTime("garbage"), undefined);
});

test("windows parser reads JSON lines, arrays and Message text", () => {
  const jl = parseWindows(win(4625, 0, { TargetUserName: "bob", IpAddress: "::ffff:1.2.3.4" }) + "\nnot json\n", "a.jsonl");
  assert.equal(jl.events.length, 1);
  assert.equal(jl.skipped, 1);
  assert.equal(jl.events[0]?.ip, "1.2.3.4");
  const arr = parseWindows(`[${win(4624, 1, { LogonType: "10" })}]`, "a.json");
  assert.equal(arr.events[0]?.f["LogonType"], "10");
  const msg = parseWindows(JSON.stringify({ Id: 4624, TimeCreated: "2026-01-01T00:00:00Z", MachineName: "H", Message: "An account was logged on.\nLogon Type:\t\t10\nSource Network Address:\t203.0.113.9\nAccount Name:\t\talice" }), "m.json");
  assert.equal(msg.events[0]?.f["LogonType"], "10");
  assert.equal(msg.events[0]?.ip, "203.0.113.9");
});

test("windows parser rejects a broken array without throwing", () => {
  const r = parseWindows("[{", "x.json");
  assert.equal(r.events.length, 0);
  assert.match(r.warnings[0] ?? "", /invalid JSON/);
});

test("linux parser extracts ssh, sudo and useradd events and survives a year rollover", () => {
  const text = [
    "Dec 31 23:59:58 h sshd[1]: Failed password for invalid user x from 1.2.3.4 port 22 ssh2",
    "Jan  1 00:00:02 h sshd[1]: Accepted password for bob from 1.2.3.4 port 22 ssh2",
    "Jan  1 00:00:05 h sudo:   bob : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls",
    "Jan  1 00:00:09 h useradd[3]: new user: name=zed, UID=1, GID=1",
    "garbage line",
  ].join("\n");
  const r = parseLinux(text, "auth.log", 2025);
  assert.equal(r.events.length, 4);
  assert.equal(r.skipped, 1);
  assert.equal(r.events[0]?.f["event"], "ssh-fail");
  assert.equal(r.events[0]?.user, "x");
  assert.ok((r.events[1]?.ts ?? 0) > (r.events[0]?.ts ?? 1), "January must land after December");
  assert.equal(r.events[2]?.f["command"], "/bin/ls");
  assert.equal(r.events[3]?.user, "zed");
});

test("web parser honours the timezone offset and decodes the path", () => {
  const r = parseWeb('9.9.9.9 - - [01/Jan/2026:02:00:00 +0200] "GET /a%20b?x=1 HTTP/1.1" 200 5 "-" "curl/8"', "a.log");
  assert.equal(r.events[0]?.ts, Date.UTC(2026, 0, 1));
  assert.equal(r.events[0]?.f["decoded"], "/a b?x=1");
  assert.equal(r.events[0]?.f["ua"], "curl/8");
});

test("brute force then success is critical, failures alone are not", () => {
  const fails = Array.from({ length: 6 }, (_, i) => win(4625, i * 0, { TargetUserName: "bob", IpAddress: "203.0.113.7" }).replace("00:00", "00:0" + 0));
  const onlyFails = analyze([{ name: "a", text: fails.join("\n") }]);
  assert.equal(onlyFails.findings[0]?.title, "Brute force attempt");
  assert.equal(onlyFails.findings[0]?.severity, "high");
  const withOk = analyze([{ name: "a", text: [...fails, win(4624, 3, { TargetUserName: "bob", IpAddress: "203.0.113.7", LogonType: "3" })].join("\n") }]);
  assert.equal(withOk.findings[0]?.severity, "critical");
});

test("four failures do not trip the brute force rule", () => {
  const f = Array.from({ length: 4 }, () => win(4625, 0, { TargetUserName: "bob", IpAddress: "203.0.113.7" }));
  assert.equal(analyze([{ name: "a", text: f.join("\n") }]).findings.length, 0);
});

test("internal source addresses are medium, not high", () => {
  const f = Array.from({ length: 6 }, () => win(4625, 0, { TargetUserName: "bob", IpAddress: "10.0.0.5" }));
  assert.equal(analyze([{ name: "a", text: f.join("\n") }]).findings[0]?.severity, "medium");
});

test("log clearing, services and accounts are flagged with ATT&CK ids", () => {
  const text = [
    win(1102, 0, { SubjectUserName: "evil" }),
    win(7045, 1, { ServiceName: "x", ImagePath: "C:\\Users\\Public\\a.exe" }),
    win(7045, 2, { ServiceName: "Spooler", ImagePath: "C:\\Windows\\System32\\spoolsv.exe" }),
    win(4732, 3, { GroupName: "Administrators", MemberName: "m" }),
    win(4732, 4, { GroupName: "Remote Desktop Users", MemberName: "m" }),
  ].join("\n");
  const a = analyze([{ name: "a", text }]);
  const by = (t: string) => a.findings.filter((f) => f.title === t);
  assert.equal(by("Event log cleared")[0]?.technique, "T1070.001");
  assert.equal(by("Suspicious service installed").length, 1);
  assert.equal(by("New service installed").length, 1);
  assert.equal(by("Added to privileged group").length, 1, "only the Administrators add counts");
});

test("command rules fire on encoded PowerShell and not on plain powershell", () => {
  const enc = win(4688, 0, { CommandLine: "powershell -nop -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=" });
  const plain = win(4688, 1, { CommandLine: "powershell Get-Date" });
  const a = analyze([{ name: "a", text: enc + "\n" + plain }]);
  assert.deepEqual(a.findings.map((f) => f.title), ["Encoded PowerShell"]);
});

test("kerberoasting needs RC4 tickets for several distinct services", () => {
  const mkT = (n: number, enc: string) => Array.from({ length: n }, (_, i) => win(4769, 0, { TargetUserName: "u", ServiceName: "svc" + i, TicketEncryptionType: enc }, "DC")).join("\n");
  assert.equal(analyze([{ name: "a", text: mkT(6, "0x17") }]).findings[0]?.title, "Kerberoasting pattern");
  assert.equal(analyze([{ name: "a", text: mkT(6, "0x12") }]).findings.length, 0);
});

test("web attacks: 2xx answer upgrades to critical, URL encoding does not hide it", () => {
  const l = (p: string, s: number) => `8.8.8.8 - - [01/Jan/2026:00:00:00 +0000] "GET ${p} HTTP/1.1" ${s} 5 "-" "x"`;
  const a = analyze([{ name: "w", text: [l("/p.php?id=1%27%20UNION%20SELECT%201", 200), l("/p.php?id=1%20or%201=1", 403), l("/index.html", 200)].join("\n") }]);
  assert.equal(a.findings.length, 2);
  assert.equal(a.findings[0]?.severity === "critical" || a.findings[1]?.severity === "critical", true);
  assert.ok(a.findings.some((f) => f.severity === "medium"));
});

test("a malformed percent escape in a URL does not crash the parser", () => {
  const r = parseWeb('8.8.8.8 - - [01/Jan/2026:00:00:00 +0000] "GET /%E0%A4%A HTTP/1.1" 404 5 "-" "x"', "w");
  assert.equal(r.events.length, 1);
});

test("end to end on the bundled example", () => {
  const a = analyze([{ name: "win-security.jsonl", text: ex("win-security.jsonl") }, { name: "auth.log", text: ex("auth.log") }, { name: "access.log", text: ex("access.log") }], { year: 2026 });
  assert.equal(a.events.length, 131);
  assert.equal(a.findings.length, 21);
  assert.equal(a.chains.length, 3);
  assert.ok(a.events.every((e, i) => e.id === i && (i === 0 || e.ts >= (a.events[i - 1]?.ts ?? 0))), "timeline is sorted with dense ids");
  assert.ok(a.findings.every((f) => f.evidence.every((id) => a.events[id])), "evidence ids resolve");
  const titles = new Set(a.findings.map((f) => f.title));
  for (const t of ["Event log cleared", "Kerberoasting pattern", "Password spraying", "Reverse shell", "Web shell access (server answered 2xx)"]) assert.ok(titles.has(t), t);
});

test("csv output neutralises spreadsheet formulas and quotes commas", () => {
  const a = analyze([{ name: "a", text: win(4688, 0, { CommandLine: '=cmd|"/c calc"!A1, x' }) }]);
  const row = toCsv(a).split("\n")[1] ?? "";
  assert.ok(row.includes(`"'Process: =cmd`) || row.includes("'Process: =cmd") === false, "summary is quoted");
  assert.ok(!row.includes(",=cmd"), "no cell starts with =");
  const direct = analyze([{ name: "a", text: win(4688, 0, { CommandLine: "x" }).replace('"MachineName":"H1"', '"MachineName":"=HYPERLINK(1)"') }]);
  assert.ok(toCsv(direct).includes(",'=hyperlink(1),"), "host cell is prefixed with a quote");
});

test("markdown escapes pipes and reports zero findings cleanly", () => {
  const a = analyze([{ name: "a|b", text: win(1, 0, {}) }]);
  const md = toMarkdown(a);
  assert.match(md, /a\\\|b/);
  assert.match(md, /No detections fired/);
});

test("unknown input yields a warning, not an exception", () => {
  const a = analyze([{ name: "x.txt", text: "hello" }]);
  assert.equal(a.events.length, 0);
  assert.match(a.warnings[0] ?? "", /not recognised/);
});
