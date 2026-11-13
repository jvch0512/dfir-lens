import { parseAny, type ParseOptions } from "./parse.js";
import { detect } from "./detect.js";
import { TACTIC_ORDER, SEVERITY_RANK, type Ev, type Finding } from "./types.js";

export interface Input {
  name: string;
  text: string;
}

export interface Analysis {
  events: Ev[];
  findings: Finding[];
  files: { name: string; format: string; events: number; skipped: number }[];
  warnings: string[];
  chains: Chain[];
}

export interface Chain {
  host: string;
  start: number;
  end: number;
  tactics: string[];
  findings: number;
  severity: Finding["severity"];
}

export function analyze(inputs: Input[], opts: ParseOptions = {}): Analysis {
  const raw: Omit<Ev, "id">[] = [];
  const files: Analysis["files"] = [];
  const warnings: string[] = [];
  for (const inp of inputs) {
    const r = parseAny(inp.text, inp.name, opts);
    raw.push(...r.events);
    warnings.push(...r.warnings);
    files.push({ name: inp.name, format: r.format, events: r.events.length, skipped: r.skipped });
  }
  raw.sort((a, b) => a.ts - b.ts || a.file.localeCompare(b.file) || a.line - b.line);
  const events: Ev[] = raw.map((e, id) => ({ ...e, id }));
  const findings = detect(events);
  return { events, findings, files, warnings, chains: buildChains(findings) };
}

/**
 * A chain is a run of findings on one host where each finding starts within
 * `gap` of the previous one. It reads as one intrusion episode.
 */
export function buildChains(findings: Finding[], gap = 6 * 3600_000): Chain[] {
  const byHost = new Map<string, Finding[]>();
  for (const f of findings) (byHost.get(f.host) ?? byHost.set(f.host, []).get(f.host)!).push(f);
  const out: Chain[] = [];
  for (const [host, list] of byHost) {
    list.sort((a, b) => a.start - b.start);
    let cur: Finding[] = [];
    const flush = () => {
      const tactics = [...new Set(cur.map((f) => f.tactic))].sort((a, b) => TACTIC_ORDER.indexOf(a) - TACTIC_ORDER.indexOf(b));
      if (cur.length >= 2 && tactics.length >= 2) {
        const sev = cur.reduce((m, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[m] ? f.severity : m), cur[0]!.severity);
        out.push({ host, start: cur[0]!.start, end: Math.max(...cur.map((f) => f.end)), tactics, findings: cur.length, severity: sev });
      }
      cur = [];
    };
    for (const f of list) {
      if (cur.length && f.start - Math.max(...cur.map((x) => x.end)) > gap) flush();
      cur.push(f);
    }
    flush();
  }
  return out.sort((a, b) => a.start - b.start);
}
