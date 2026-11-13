#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { analyze } from "./timeline.js";
import { toCsv, toJson, toMarkdown } from "./report.js";

const USAGE = `dfir-lens analyze [--format md|json|csv] [--year YYYY] [--host NAME] FILE...

Reads Windows event exports (JSON array or JSON lines), syslog auth.log and
combined web access logs. Prints a timeline report. Nothing leaves this machine.`;

function main(argv: string[]): number {
  const args = argv.slice(2);
  if (args[0] !== "analyze" || args.includes("--help")) {
    console.log(USAGE);
    return args.includes("--help") ? 0 : 2;
  }
  let format = "md";
  let year: number | undefined;
  let host: string | undefined;
  const files: string[] = [];
  for (let i = 1; i < args.length; i++) {
    const a = args[i]!;
    if (a === "--format") format = args[++i] ?? "";
    else if (a === "--year") year = Number(args[++i]);
    else if (a === "--host") host = args[++i];
    else if (a.startsWith("--")) {
      console.error(`unknown flag ${a}`);
      return 2;
    } else files.push(a);
  }
  if (!["md", "json", "csv"].includes(format) || (year !== undefined && !Number.isInteger(year)) || !files.length) {
    console.log(USAGE);
    return 2;
  }
  const inputs = files.map((f) => ({ name: basename(f), text: readFileSync(f, "utf8") }));
  const a = analyze(inputs, { ...(year !== undefined ? { year } : {}), ...(host ? { host } : {}) });
  process.stdout.write((format === "json" ? toJson(a) : format === "csv" ? toCsv(a) : toMarkdown(a)) + (format === "md" ? "" : "\n"));
  return a.findings.some((f) => f.severity === "critical") ? 1 : 0;
}

process.exitCode = main(process.argv);
