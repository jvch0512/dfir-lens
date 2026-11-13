import { LIMITS, type Ev, type ParseResult, type Source } from "./types.js";

type RawEvent = Omit<Ev, "id">;

const MONTHS: Record<string, number> = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

function clip(s: string, n = 400): string {
  return s.length > n ? s.slice(0, n) + "..." : s;
}

// ---------- format detection ----------

export type Format = "win" | "linux" | "web" | "unknown";

const WEB_RE = /^(\S+) \S+ \S+ \[([^\]]+)\] "([A-Z]+) (\S+)[^"]*" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?/;
const SYSLOG_RE = /^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) ([^\s:\[]+)(?:\[(\d+)\])?: (.*)$/;

export function detectFormat(text: string): Format {
  const first = text.split(/\r?\n/).find((l) => l.trim() !== "")?.trim() ?? "";
  if (first.startsWith("[") || first.startsWith("{")) return "win";
  if (WEB_RE.test(first)) return "web";
  if (SYSLOG_RE.test(first)) return "linux";
  return "unknown";
}

// ---------- Windows ----------

/** Accepts ISO strings, PowerShell "/Date(ms)/", {SystemTime}, and "M/D/YYYY h:mm:ss AM" (read as UTC). */
export function parseWinTime(v: unknown): number | undefined {
  if (v && typeof v === "object" && "SystemTime" in (v as object)) return parseWinTime((v as { SystemTime: unknown }).SystemTime);
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v !== "string") return undefined;
  const d = /^\/Date\((-?\d+)(?:[+-]\d{4})?\)\/$/.exec(v);
  if (d) return Number(d[1]);
  const us = /^(\d{1,2})\/(\d{1,2})\/(\d{4}) (\d{1,2}):(\d{2}):(\d{2})(?: (AM|PM))?$/i.exec(v);
  if (us) {
    let h = Number(us[4]);
    if (us[7]) h = (h % 12) + (us[7].toUpperCase() === "PM" ? 12 : 0);
    return Date.UTC(Number(us[3]), Number(us[1]) - 1, Number(us[2]), h, Number(us[5]), Number(us[6]));
  }
  const t = Date.parse(v);
  return Number.isNaN(t) ? undefined : t;
}

const MESSAGE_LABELS: Record<string, string> = {
  "Logon Type": "LogonType",
  "Source Network Address": "IpAddress",
  "Account Name": "TargetUserName",
  "Process Command Line": "CommandLine",
  "New Process Name": "NewProcessName",
  "Service Name": "ServiceName",
  "Service File Name": "ImagePath",
  "Task Name": "TaskName",
  "Ticket Encryption Type": "TicketEncryptionType",
  "Group Name": "GroupName",
};

function flat(o: unknown, out: Record<string, string>, depth = 0): void {
  if (!o || typeof o !== "object" || depth > 4) return;
  for (const [k, v] of Object.entries(o as Record<string, unknown>)) {
    if (v !== null && typeof v === "object") flat(v, out, depth + 1);
    else if (v !== undefined && !(k in out)) out[k] = String(v);
  }
}

function winFields(r: Record<string, unknown>): Record<string, string> {
  const f: Record<string, string> = {};
  flat(r["EventData"] ?? (r["Event"] as Record<string, unknown> | undefined)?.["EventData"], f);
  flat(r["event_data"], f);
  const msg = typeof r["Message"] === "string" ? (r["Message"] as string) : typeof r["message"] === "string" ? (r["message"] as string) : "";
  if (msg) {
    for (const line of msg.split(/\r?\n/)) {
      const m = /^\s*([A-Za-z ]+):\s+(\S.*)$/.exec(line);
      const key = m?.[1] && MESSAGE_LABELS[m[1].trim()];
      if (m?.[2] && key) f[key] = m[2].trim(); // later occurrences win: "New Logon" follows "Subject" in 4624
    }
  }
  return f;
}

export function parseWindows(text: string, file: string): ParseResult {
  const warnings: string[] = [];
  let records: { rec: unknown; line: number }[] = [];
  let skipped = 0;
  const trimmed = text.trim();
  if (trimmed.startsWith("[")) {
    try {
      const arr = JSON.parse(trimmed) as unknown;
      if (!Array.isArray(arr)) throw new Error("not an array");
      records = arr.map((rec, i) => ({ rec, line: i + 1 }));
    } catch (e) {
      return { events: [], skipped: 0, warnings: [`${file}: invalid JSON array (${(e as Error).message})`] };
    }
  } else {
    text.split(/\r?\n/).forEach((l, i) => {
      if (!l.trim()) return;
      if (l.length > LIMITS.maxLine * 4) {
        skipped++;
        return;
      }
      try {
        records.push({ rec: JSON.parse(l), line: i + 1 });
      } catch {
        skipped++;
      }
    });
  }
  const events: RawEvent[] = [];
  for (const { rec, line } of records) {
    if (events.length >= LIMITS.maxEvents) {
      warnings.push(`${file}: stopped at ${LIMITS.maxEvents} events`);
      break;
    }
    if (!rec || typeof rec !== "object") {
      skipped++;
      continue;
    }
    const r = rec as Record<string, unknown>;
    const sys = ((r["Event"] as Record<string, unknown> | undefined)?.["System"] ?? r["System"] ?? {}) as Record<string, unknown>;
    const idRaw = r["Id"] ?? r["EventId"] ?? r["EventID"] ?? sys["EventID"] ?? (r["event"] as Record<string, unknown> | undefined)?.["code"];
    const ts = parseWinTime(r["TimeCreated"] ?? r["TimeGenerated"] ?? sys["TimeCreated"] ?? r["@timestamp"]);
    if (idRaw === undefined || ts === undefined) {
      skipped++;
      continue;
    }
    const idText = typeof idRaw === "object" ? String((idRaw as Record<string, unknown>)["#text"] ?? "") : String(idRaw);
    const host = String(r["MachineName"] ?? r["Computer"] ?? sys["Computer"] ?? "unknown").toLowerCase();
    const f = winFields(r);
    const user = f["TargetUserName"] ?? f["SubjectUserName"];
    const ip = f["IpAddress"] && f["IpAddress"] !== "-" ? f["IpAddress"].replace(/^::ffff:/, "") : undefined;
    const msg = String(r["Message"] ?? "").split(/\r?\n/)[0] ?? "";
    const ev: RawEvent = { ts, source: "win", host, code: idText, summary: clip(describeWin(idText, f) || msg || `Event ${idText}`), f, line, file };
    if (user) ev.user = user;
    if (ip) ev.ip = ip;
    events.push(ev);
  }
  return { events, skipped, warnings };
}

function describeWin(id: string, f: Record<string, string>): string {
  const who = f["TargetUserName"] ?? f["SubjectUserName"] ?? "?";
  switch (id) {
    case "4624": return `Logon type ${f["LogonType"] ?? "?"} for ${who}${f["IpAddress"] ? " from " + f["IpAddress"] : ""}`;
    case "4625": return `Failed logon for ${who}${f["IpAddress"] ? " from " + f["IpAddress"] : ""}`;
    case "4688": return `Process: ${f["CommandLine"] ?? f["NewProcessName"] ?? "?"}`;
    case "1": return `Sysmon process: ${f["CommandLine"] ?? f["Image"] ?? "?"}`;
    case "4720": return `User account created: ${who}`;
    case "4732": case "4728": case "4756": return `Member added to group ${f["GroupName"] ?? f["TargetUserName"] ?? "?"}`;
    case "7045": case "4697": return `Service installed: ${f["ServiceName"] ?? "?"} -> ${f["ImagePath"] ?? f["ServiceFileName"] ?? "?"}`;
    case "4698": return `Scheduled task created: ${f["TaskName"] ?? "?"}`;
    case "1102": case "104": return "Event log cleared";
    case "4719": return "Audit policy changed";
    case "4769": return `Kerberos service ticket for ${f["ServiceName"] ?? "?"} (enc ${f["TicketEncryptionType"] ?? "?"})`;
    default: return "";
  }
}

// ---------- Linux auth.log ----------

export function parseLinux(text: string, file: string, year: number, host?: string): ParseResult {
  const events: RawEvent[] = [];
  let skipped = 0;
  const lines = text.split(/\r?\n/);
  let lastTs = -Infinity;
  let rolloverYear = year;
  lines.forEach((l, i) => {
    if (!l.trim()) return;
    const m = SYSLOG_RE.exec(l.length > LIMITS.maxLine ? l.slice(0, LIMITS.maxLine) : l);
    const mon = m?.[1] !== undefined ? MONTHS[m[1]] : undefined;
    if (!m || mon === undefined || events.length >= LIMITS.maxEvents) {
      skipped++;
      return;
    }
    let ts = Date.UTC(rolloverYear, mon, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]));
    // a log that runs Dec -> Jan crosses a year boundary: syslog lines carry no year
    if (ts < lastTs - 180 * 86_400_000) {
      rolloverYear++;
      ts = Date.UTC(rolloverYear, mon, Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]));
    }
    lastTs = Math.max(lastTs, ts);
    const prog = m[7] ?? "";
    const msg = m[9] ?? "";
    const f: Record<string, string> = { program: prog, message: msg };
    let user: string | undefined;
    let ip: string | undefined;
    const fail = /Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+) port/.exec(msg);
    const ok = /Accepted (\S+) for (\S+) from (\S+) port/.exec(msg);
    const inv = /Invalid user (\S*) from (\S+)/.exec(msg);
    if (fail) {
      f["event"] = "ssh-fail";
      user = fail[1];
      ip = fail[2];
    } else if (ok) {
      f["event"] = "ssh-accept";
      f["method"] = ok[1] ?? "";
      user = ok[2];
      ip = ok[3];
    } else if (inv) {
      f["event"] = "ssh-invalid-user";
      user = inv[1];
      ip = inv[2];
    } else if (/useradd/.test(prog) && /new user: name=([^,]+)/.test(msg)) {
      f["event"] = "useradd";
      user = /new user: name=([^,]+)/.exec(msg)?.[1];
    } else if (/(usermod|gpasswd)/.test(prog) && /add '?([^' ]+)'? to (?:shadow )?group '?(\w+)/.test(msg)) {
      const g = /add '?([^' ]+)'? to (?:shadow )?group '?(\w+)/.exec(msg);
      f["event"] = "group-add";
      f["group"] = g?.[2] ?? "";
      user = g?.[1];
    } else if (prog === "sudo" && /COMMAND=/.test(msg)) {
      f["event"] = "sudo";
      f["runas"] = /USER=(\S+)/.exec(msg)?.[1] ?? "";
      f["command"] = /COMMAND=(.*)$/.exec(msg)?.[1] ?? "";
      user = /^\s*(\S+) :/.exec(msg)?.[1];
    } else if (/passwd/.test(prog) && /password changed for (\S+)/.test(msg)) {
      f["event"] = "passwd";
      user = /password changed for (\S+)/.exec(msg)?.[1];
    }
    const ev: RawEvent = { ts, source: "linux", host: (host ?? m[6] ?? "unknown").toLowerCase(), code: prog, summary: clip(msg), f, line: i + 1, file };
    if (user) ev.user = user;
    if (ip) ev.ip = ip;
    events.push(ev);
  });
  return { events, skipped, warnings: [] };
}

// ---------- web access log ----------

export function parseWeb(text: string, file: string, host = "web"): ParseResult {
  const events: RawEvent[] = [];
  let skipped = 0;
  text.split(/\r?\n/).forEach((l, i) => {
    if (!l.trim()) return;
    const m = WEB_RE.exec(l.length > LIMITS.maxLine ? l.slice(0, LIMITS.maxLine) : l);
    if (!m || events.length >= LIMITS.maxEvents) {
      skipped++;
      return;
    }
    const t = /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$/.exec(m[2] ?? "");
    const mon = t?.[2] !== undefined ? MONTHS[t[2]] : undefined;
    if (!t || mon === undefined) {
      skipped++;
      return;
    }
    const off = (t[7] === "-" ? -1 : 1) * (Number(t[8]) * 60 + Number(t[9])) * 60_000;
    const ts = Date.UTC(Number(t[3]), mon, Number(t[1]), Number(t[4]), Number(t[5]), Number(t[6])) - off;
    const path = m[4] ?? "";
    let decoded = path;
    try {
      decoded = decodeURIComponent(path.replace(/\+/g, " "));
    } catch {
      /* keep the raw path */
    }
    events.push({
      ts, source: "web", host, code: m[5] ?? "", summary: clip(`${m[3]} ${path} -> ${m[5]}`), user: undefined, ip: m[1],
      f: { method: m[3] ?? "", path, decoded, status: m[5] ?? "", ua: m[8] ?? "", referer: m[7] ?? "" }, line: i + 1, file,
    } as RawEvent);
  });
  for (const e of events) if (e.user === undefined) delete e.user;
  return { events, skipped, warnings: [] };
}

// ---------- entry point ----------

export interface ParseOptions {
  year?: number;
  host?: string;
}

export function parseAny(text: string, file: string, opts: ParseOptions = {}): ParseResult & { format: Format } {
  if (text.length > LIMITS.maxBytes) return { events: [], skipped: 0, warnings: [`${file}: larger than ${LIMITS.maxBytes / 1048576} MiB, skipped`], format: "unknown" };
  const format = detectFormat(text);
  const year = opts.year ?? new Date().getUTCFullYear();
  const r =
    format === "win" ? parseWindows(text, file)
    : format === "linux" ? parseLinux(text, file, year, opts.host)
    : format === "web" ? parseWeb(text, file, opts.host)
    : { events: [], skipped: 0, warnings: [`${file}: format not recognised (expected Windows event JSON/JSONL, syslog auth.log or a combined access log)`] };
  return { ...r, format };
}

export type { Source };
