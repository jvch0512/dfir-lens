import type { Analysis } from "./timeline.js";
import { SEVERITY_RANK } from "./types.js";

export function iso(ts: number): string {
  return new Date(ts).toISOString().replace(".000Z", "Z");
}

export function mdEscape(s: string): string {
  return s.replace(/\|/g, "\\|").replace(/[\r\n]+/g, " ");
}

export function toMarkdown(a: Analysis): string {
  const L: string[] = [];
  L.push("# DFIR timeline report", "");
  L.push(`${a.events.length} events from ${a.files.length} file(s), ${a.findings.length} findings.`, "");
  if (a.events.length) L.push(`Range: ${iso(a.events[0]!.ts)} to ${iso(a.events[a.events.length - 1]!.ts)} (UTC)`, "");
  L.push("## Inputs", "", "| File | Format | Events | Skipped |", "|---|---|---:|---:|");
  for (const f of a.files) L.push(`| ${mdEscape(f.name)} | ${f.format} | ${f.events} | ${f.skipped} |`);
  if (a.chains.length) {
    L.push("", "## Attack chains", "");
    for (const c of a.chains) L.push(`- **${c.host}** ${iso(c.start)} to ${iso(c.end)}: ${c.tactics.join(" > ")} (${c.findings} findings, ${c.severity})`);
  }
  L.push("", "## Findings", "");
  const sorted = [...a.findings].sort((x, y) => SEVERITY_RANK[y.severity] - SEVERITY_RANK[x.severity] || x.start - y.start);
  if (!sorted.length) L.push("No detections fired.");
  for (const f of sorted) {
    L.push(`### [${f.severity.toUpperCase()}] ${f.title}`, "", `- When: ${iso(f.start)}${f.end > f.start ? " to " + iso(f.end) : ""}`, `- Host: ${f.host}`, `- ATT&CK: ${f.tactic}, ${f.technique}`, `- Detail: ${f.detail}`, "- Evidence:");
    for (const id of f.evidence.slice(0, 5)) {
      const e = a.events[id]!;
      L.push(`  - ${e.file}:${e.line} ${iso(e.ts)} ${mdEscape(e.summary)}`);
    }
    if (f.evidence.length > 5) L.push(`  - and ${f.evidence.length - 5} more`);
    L.push("");
  }
  if (a.warnings.length) L.push("## Warnings", "", ...a.warnings.map((w) => `- ${w}`), "");
  return L.join("\n");
}

export function toJson(a: Analysis): string {
  return JSON.stringify({ files: a.files, chains: a.chains, findings: a.findings.map((f) => ({ ...f, start: iso(f.start), end: iso(f.end) })), eventCount: a.events.length }, null, 2);
}

/** Events as CSV with formula-injection protection for spreadsheet users. */
export function toCsv(a: Analysis): string {
  const cell = (s: string) => {
    const safe = /^[=+\-@\t\r]/.test(s) ? "'" + s : s;
    return /[",\n]/.test(safe) ? '"' + safe.replace(/"/g, '""') + '"' : safe;
  };
  const rows = ["time,source,host,code,user,ip,summary,file,line"];
  for (const e of a.events) rows.push([iso(e.ts), e.source, e.host, e.code, e.user ?? "", e.ip ?? "", e.summary, e.file, String(e.line)].map(cell).join(","));
  return rows.join("\n") + "\n";
}
