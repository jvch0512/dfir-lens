import { SEVERITY_RANK, type Ev, type Finding, type Severity } from "./types.js";

const MIN = 60_000;
const MAX_EVIDENCE = 40;

interface Rule {
  id: string;
  run(events: Ev[]): Finding[];
}

function mk(rule: string, title: string, severity: Severity, tactic: string, technique: string, evs: Ev[], detail: string): Finding {
  const sorted = [...evs].sort((a, b) => a.ts - b.ts);
  const first = sorted[0] as Ev;
  const last = sorted[sorted.length - 1] as Ev;
  return { rule, title, severity, tactic, technique, host: first.host, start: first.ts, end: last.ts, evidence: sorted.slice(0, MAX_EVIDENCE).map((e) => e.id), detail };
}

const isFail = (e: Ev) => (e.source === "win" && e.code === "4625") || e.f["event"] === "ssh-fail" || e.f["event"] === "ssh-invalid-user";
const isSuccess = (e: Ev) => (e.source === "win" && e.code === "4624" && e.f["LogonType"] !== "5") || e.f["event"] === "ssh-accept";
const PRIVATE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1|fe80:)/;
const isExternal = (ip?: string) => !!ip && ip !== "-" && !PRIVATE.test(ip);

/** Sliding window over events sorted by time; yields maximal clusters of >= min events inside `span`. */
function clusters(evs: Ev[], span: number, min: number): Ev[][] {
  const out: Ev[][] = [];
  let i = 0;
  while (i < evs.length) {
    let j = i;
    while (j + 1 < evs.length && (evs[j + 1] as Ev).ts - (evs[j] as Ev).ts <= span) j++;
    if (j - i + 1 >= min) {
      out.push(evs.slice(i, j + 1));
      i = j + 1;
    } else i++;
  }
  return out;
}

function groupBy<T>(xs: T[], key: (x: T) => string | undefined): Map<string, T[]> {
  const m = new Map<string, T[]>();
  for (const x of xs) {
    const k = key(x);
    if (k === undefined) continue;
    const a = m.get(k);
    if (a) a.push(x);
    else m.set(k, [x]);
  }
  return m;
}

const bruteForce: Rule = {
  id: "brute-force",
  run(events) {
    const out: Finding[] = [];
    const fails = events.filter((e) => isFail(e) && e.ip);
    for (const [ip, list] of groupBy(fails, (e) => e.ip + "|" + e.host)) {
      for (const c of clusters(list, 5 * MIN, 5)) {
        const users = new Set(c.map((e) => e.user));
        if (users.size >= 5) continue; // spraying is reported by its own rule
        const end = (c[c.length - 1] as Ev).ts;
        const win = events.find((e) => isSuccess(e) && e.ip === ip.split("|")[0] && e.host === (c[0] as Ev).host && e.ts >= end && e.ts <= end + 30 * MIN);
        const ev = win ? [...c, win] : c;
        out.push(
          win
            ? mk(this.id, "Brute force followed by successful logon", "critical", "Credential Access", "T1110.001", ev, `${c.length} failed logons from ${c[0]?.ip} then a success for ${win.user ?? "?"}. Treat the account as compromised.`)
            : mk(this.id, "Brute force attempt", isExternal(c[0]?.ip) ? "high" : "medium", "Credential Access", "T1110.001", ev, `${c.length} failed logons from ${c[0]?.ip} within 5 minutes against ${[...users].join(", ")}.`),
        );
      }
    }
    return out;
  },
};

const spray: Rule = {
  id: "password-spray",
  run(events) {
    const out: Finding[] = [];
    const fails = events.filter((e) => isFail(e) && e.ip && e.user);
    for (const [, list] of groupBy(fails, (e) => e.ip + "|" + e.host)) {
      for (const c of clusters(list, 10 * MIN, 5)) {
        const users = new Set(c.map((e) => e.user));
        if (users.size < 5) continue;
        out.push(mk(this.id, "Password spraying", "high", "Credential Access", "T1110.003", c, `${c[0]?.ip} tried ${users.size} different accounts (${c.length} attempts) within 10 minutes.`));
      }
    }
    return out;
  },
};

const logClear: Rule = {
  id: "log-cleared",
  run(events) {
    return events.filter((e) => e.source === "win" && (e.code === "1102" || e.code === "104")).map((e) => mk(this.id, "Event log cleared", "high", "Defense Evasion", "T1070.001", [e], `Audit log was cleared${e.user ? " by " + (e.f["SubjectUserName"] ?? e.user) : ""}. Anything before this point on ${e.host} may be missing.`));
  },
};

const SUSPECT_PATH = /(\\temp\\|\\appdata\\|\\users\\public\\|\\programdata\\|powershell|cmd(\.exe)?\s*\/c|\\\\[^\\]+\\|rundll32|mshta|%comspec%)/i;

const service: Rule = {
  id: "service-install",
  run(events) {
    return events
      .filter((e) => e.source === "win" && (e.code === "7045" || e.code === "4697"))
      .map((e) => {
        const path = e.f["ImagePath"] ?? e.f["ServiceFileName"] ?? "";
        const bad = SUSPECT_PATH.test(path);
        return mk(this.id, bad ? "Suspicious service installed" : "New service installed", bad ? "high" : "medium", "Persistence", "T1543.003", [e], `Service ${e.f["ServiceName"] ?? "?"} runs ${path || "?"}.`);
      });
  },
};

const task: Rule = {
  id: "scheduled-task",
  run(events) {
    return events.filter((e) => e.source === "win" && e.code === "4698").map((e) => mk(this.id, "Scheduled task created", SUSPECT_PATH.test(e.f["TaskContent"] ?? e.f["TaskName"] ?? "") ? "high" : "medium", "Persistence", "T1053.005", [e], `Task ${e.f["TaskName"] ?? "?"} created by ${e.f["SubjectUserName"] ?? "?"}.`));
  },
};

const ADMIN_GROUPS = /^(administrators|domain admins|enterprise admins|schema admins|sudo|wheel|root|admin)$/i;

const account: Rule = {
  id: "account-change",
  run(events) {
    const out: Finding[] = [];
    for (const e of events) {
      if ((e.source === "win" && e.code === "4720") || e.f["event"] === "useradd") {
        out.push(mk(this.id, "Local account created", "medium", "Persistence", "T1136.001", [e], `Account ${e.user ?? "?"} created${e.f["SubjectUserName"] ? " by " + e.f["SubjectUserName"] : ""}.`));
      }
      const group = e.f["GroupName"] ?? e.f["group"];
      if (((e.source === "win" && ["4732", "4728", "4756"].includes(e.code)) || e.f["event"] === "group-add") && group && ADMIN_GROUPS.test(group)) {
        out.push(mk(this.id, "Added to privileged group", "high", "Privilege Escalation", "T1098", [e], `${e.f["MemberName"] ?? e.user ?? "A member"} was added to ${group}.`));
      }
    }
    return out;
  },
};

const CMD_RULES: { re: RegExp; title: string; sev: Severity; tactic: string; tech: string }[] = [
  { re: /powershell[^|]*\s-(e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}/i, title: "Encoded PowerShell", sev: "high", tactic: "Execution", tech: "T1059.001" },
  { re: /(invoke-mimikatz|mimikatz|sekurlsa|lsadump::)/i, title: "Credential dumping tool", sev: "critical", tactic: "Credential Access", tech: "T1003.001" },
  { re: /(procdump[^|]*lsass|comsvcs\.dll[^|]*minidump|rundll32[^|]*comsvcs)/i, title: "LSASS memory dump", sev: "critical", tactic: "Credential Access", tech: "T1003.001" },
  { re: /(certutil[^|]*-urlcache|bitsadmin[^|]*\/transfer|curl[^|]*\|\s*(ba)?sh|wget[^|]*\|\s*(ba)?sh|invoke-webrequest[^|]*-outfile|iwr\s)/i, title: "Ingress tool transfer", sev: "high", tactic: "Command and Control", tech: "T1105" },
  { re: /(vssadmin[^|]*delete\s+shadows|wbadmin[^|]*delete|bcdedit[^|]*recoveryenabled\s+no)/i, title: "Backup and recovery inhibited", sev: "critical", tactic: "Impact", tech: "T1490" },
  { re: /(wevtutil[^|]*\scl\s|clear-eventlog)/i, title: "Log clearing command", sev: "high", tactic: "Defense Evasion", tech: "T1070.001" },
  { re: /(set-mppreference[^|]*-disable|sc\s+(stop|config)\s+windefend|netsh\s+advfirewall[^|]*off)/i, title: "Defenses disabled", sev: "high", tactic: "Defense Evasion", tech: "T1562.001" },
  { re: /(\/dev\/tcp\/|nc(at)?\s+[^|]*-e\s|bash\s+-i\s+>&)/i, title: "Reverse shell", sev: "critical", tactic: "Command and Control", tech: "T1059.004" },
  { re: /(chmod\s+(\+s|u\+s|4755)|\/etc\/shadow|authorized_keys)/i, title: "Sensitive file or setuid change", sev: "high", tactic: "Persistence", tech: "T1098.004" },
];

const commands: Rule = {
  id: "suspicious-command",
  run(events) {
    const out: Finding[] = [];
    for (const e of events) {
      const cmd = e.f["CommandLine"] ?? e.f["command"] ?? "";
      if (!cmd) continue;
      for (const r of CMD_RULES) if (r.re.test(cmd)) out.push(mk(this.id, r.title, r.sev, r.tactic, r.tech, [e], clip(cmd)));
    }
    // reconnaissance burst: several discovery tools in a couple of minutes
    const disc = events.filter((e) => /\b(whoami|net\s+(user|group|localgroup)|nltest|ipconfig\s+\/all|systeminfo|tasklist|arp\s+-a|id\b|uname\s+-a)/i.test(e.f["CommandLine"] ?? e.f["command"] ?? ""));
    for (const [, list] of groupBy(disc, (e) => e.host)) {
      for (const c of clusters(list, 3 * MIN, 4)) out.push(mk("discovery-burst", "Discovery commands in quick succession", "medium", "Discovery", "T1087", c, `${c.length} enumeration commands within 3 minutes.`));
    }
    return out;
  },
};

function clip(s: string): string {
  return s.length > 200 ? s.slice(0, 200) + "..." : s;
}

const rdp: Rule = {
  id: "remote-logon",
  run(events) {
    const out: Finding[] = [];
    for (const e of events) {
      if (e.source === "win" && e.code === "4624" && e.f["LogonType"] === "10" && isExternal(e.ip)) out.push(mk(this.id, "RDP logon from a public address", "high", "Initial Access", "T1133", [e], `${e.user ?? "?"} logged on over RDP from ${e.ip}.`));
      if (e.f["event"] === "ssh-accept" && isExternal(e.ip) && e.f["method"] === "password") out.push(mk(this.id, "SSH password logon from a public address", "medium", "Initial Access", "T1078", [e], `${e.user ?? "?"} logged on from ${e.ip} with a password.`));
    }
    return out;
  },
};

const kerberoast: Rule = {
  id: "kerberoasting",
  run(events) {
    const t = events.filter((e) => e.source === "win" && e.code === "4769" && /^0x0*17$/i.test(e.f["TicketEncryptionType"] ?? "") && !/\$$/.test(e.f["ServiceName"] ?? "") && !/^krbtgt$/i.test(e.f["ServiceName"] ?? ""));
    const out: Finding[] = [];
    for (const [, list] of groupBy(t, (e) => e.host + "|" + (e.user ?? ""))) {
      for (const c of clusters(list, 10 * MIN, 5)) {
        const svc = new Set(c.map((e) => e.f["ServiceName"]));
        if (svc.size >= 4) out.push(mk(this.id, "Kerberoasting pattern", "high", "Credential Access", "T1558.003", c, `${svc.size} service tickets with RC4 encryption requested within 10 minutes.`));
      }
    }
    return out;
  },
};

const WEB_ATTACKS: { re: RegExp; title: string; tech: string }[] = [
  { re: /(\.\.\/|\.\.\\|%2e%2e%2f|\/etc\/passwd|c:\\windows\\win\.ini)/i, title: "Path traversal attempt", tech: "T1190" },
  { re: /(union\s+select|or\s+1=1|sleep\(\d|information_schema|'--)/i, title: "SQL injection attempt", tech: "T1190" },
  { re: /(<script|onerror=|javascript:)/i, title: "Cross-site scripting attempt", tech: "T1190" },
  { re: /(\$\{jndi:|\$\(|`[^`]+`|;\s*(cat|id|wget|curl)\b|\|\s*(sh|bash)\b)/i, title: "Command or JNDI injection attempt", tech: "T1190" },
  { re: /\/(c99|r57|shell|cmd|wso|b374k)\.(php|jsp|aspx)|\.php\?(cmd|c|exec)=/i, title: "Web shell access", tech: "T1505.003" },
];

const web: Rule = {
  id: "web-attack",
  run(events) {
    const out: Finding[] = [];
    const w = events.filter((e) => e.source === "web");
    for (const e of w) {
      const target = e.f["decoded"] ?? "";
      for (const a of WEB_ATTACKS) {
        if (!a.re.test(target)) continue;
        const ok = /^2\d\d$/.test(e.f["status"] ?? "");
        out.push(mk(this.id, ok ? a.title + " (server answered 2xx)" : a.title, ok ? "critical" : "medium", a.tech === "T1505.003" ? "Persistence" : "Initial Access", a.tech, [e], `${e.f["method"]} ${clip(target)} from ${e.ip} returned ${e.f["status"]}.`));
        break;
      }
    }
    const errs = w.filter((e) => /^4\d\d$/.test(e.f["status"] ?? ""));
    for (const [ip, list] of groupBy(errs, (e) => e.ip)) {
      for (const c of clusters(list, 2 * MIN, 20)) out.push(mk("web-scan", "Web scanning", "low", "Discovery", "T1595.002", c, `${ip} produced ${c.length} client errors within 2 minutes.`));
    }
    return out;
  },
};

export const RULES: Rule[] = [bruteForce, spray, logClear, service, task, account, commands, rdp, kerberoast, web];

/** Collapse repeats of the same rule/title on the same host that overlap or touch. */
function dedupe(fs: Finding[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];
  for (const f of fs) {
    const key = [f.rule, f.title, f.host, f.evidence.slice(0, 3).join(",")].join("|");
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

export function detect(events: Ev[]): Finding[] {
  const all: Finding[] = [];
  for (const r of RULES) all.push(...r.run(events));
  return dedupe(all).sort((a, b) => a.start - b.start || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
}
