export type Source = "win" | "linux" | "web";
export type Severity = "low" | "medium" | "high" | "critical";

export interface Ev {
  /** Position in the merged, sorted timeline. */
  id: number;
  ts: number; // epoch ms, UTC
  source: Source;
  host: string;
  /** Windows event id, program name for Linux, HTTP status for web. */
  code: string;
  summary: string;
  user?: string;
  ip?: string;
  /** Normalised fields the rules read. */
  f: Record<string, string>;
  /** 1-based line (or record) number in the input file, and the file name. */
  line: number;
  file: string;
}

export interface Finding {
  rule: string;
  title: string;
  severity: Severity;
  tactic: string;
  technique: string;
  host: string;
  start: number;
  end: number;
  evidence: number[]; // Ev ids
  detail: string;
}

export interface ParseResult {
  events: Omit<Ev, "id">[];
  skipped: number;
  warnings: string[];
}

export const SEVERITY_RANK: Record<Severity, number> = { low: 1, medium: 2, high: 3, critical: 4 };

/** ATT&CK tactics in the order an intrusion usually moves through them. */
export const TACTIC_ORDER = ["Initial Access", "Execution", "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Command and Control", "Exfiltration", "Impact"];

export const LIMITS = { maxBytes: 64 * 1024 * 1024, maxEvents: 500_000, maxLine: 16 * 1024 };
