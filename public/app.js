import { analyze } from "/lib/timeline.js";
import { toMarkdown, toCsv, iso } from "/lib/report.js";

const $ = (id) => document.getElementById(id);
const SEV = ["critical", "high", "medium", "low"];
const state = { a: null, off: new Set(), sel: null };

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text; // textContent only: log content is attacker controlled
  return e;
}

async function readFiles(files) {
  const inputs = [];
  for (const f of files) inputs.push({ name: f.name, text: await f.text() });
  run(inputs);
}

function run(inputs) {
  const year = Number($("year").value) || new Date().getUTCFullYear();
  state.a = analyze(inputs, { year });
  state.off.clear();
  state.sel = null;
  render();
}

function render() {
  const a = state.a;
  $("summary").hidden = $("results").hidden = false;
  $("warn").textContent = a.warnings.join(" | ");
  const stats = $("stats");
  stats.replaceChildren();
  const counts = Object.fromEntries(SEV.map((s) => [s, a.findings.filter((f) => f.severity === s).length]));
  for (const [n, l] of [[a.events.length, "events"], [a.findings.length, "findings"], [counts.critical, "critical"], [counts.high, "high"], [a.chains.length, "chains"]]) {
    const d = el("div", "stat");
    d.append(el("b", "", String(n)), el("span", "", l));
    stats.append(d);
  }
  const chains = $("chains");
  chains.replaceChildren();
  for (const c of a.chains) {
    const d = el("div", "chain sev-" + c.severity);
    d.append(el("strong", "", c.host), el("small", "", `  ${iso(c.start)} to ${iso(c.end)}  ${c.findings} findings`));
    const t = el("div", "tactics");
    for (const x of c.tactics) t.append(el("span", "tactic", x));
    d.append(t);
    chains.append(d);
  }
  const fl = $("sev-filters");
  fl.replaceChildren();
  for (const s of SEV) {
    const b = el("button", state.off.has(s) ? "off" : "", `${s} ${counts[s]}`);
    b.type = "button";
    b.addEventListener("click", () => {
      state.off.has(s) ? state.off.delete(s) : state.off.add(s);
      render();
    });
    fl.append(b);
  }
  const ul = $("findings");
  ul.replaceChildren();
  a.findings.forEach((f, i) => {
    if (state.off.has(f.severity)) return;
    const li = el("li", f.severity + (state.sel === i ? " sel" : ""));
    li.tabIndex = 0;
    li.append(el("span", "sev " + f.severity, f.severity), el("strong", "", f.title));
    li.append(el("div", "meta", `${iso(f.start)}  ${f.host}  ${f.tactic} ${f.technique}`), el("div", "", f.detail));
    const pick = () => {
      state.sel = i;
      render();
      const first = document.querySelector(".row.hit");
      if (first) first.scrollIntoView({ block: "center" });
    };
    li.addEventListener("click", pick);
    li.addEventListener("keydown", (e) => e.key === "Enter" && pick());
    ul.append(li);
  });
  renderTimeline();
}

function renderTimeline() {
  const a = state.a;
  const q = $("q").value.trim().toLowerCase();
  const hit = new Set(state.sel === null ? [] : a.findings[state.sel].evidence);
  const box = $("timeline");
  box.replaceChildren();
  let shown = 0;
  const frag = document.createDocumentFragment();
  for (const e of a.events) {
    const hay = `${e.host} ${e.user ?? ""} ${e.ip ?? ""} ${e.code} ${e.summary}`.toLowerCase();
    if (q && !hay.includes(q) && !hit.has(e.id)) continue;
    if (shown++ >= 3000) break;
    const r = el("div", "row" + (hit.has(e.id) ? " hit" : ""));
    r.setAttribute("role", "row");
    r.append(el("span", "t", iso(e.ts)), el("span", "s-" + e.source, e.source), el("span", "", e.host), el("span", "", `${e.code}  ${e.summary}`));
    frag.append(r);
  }
  box.append(frag);
  $("tl-count").textContent = `(${shown >= 3000 ? "first 3000 of " : ""}${a.events.length})`;
}

function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

const drop = $("drop");
for (const ev of ["dragenter", "dragover"]) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("over"); });
for (const ev of ["dragleave", "drop"]) drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("over"); });
drop.addEventListener("drop", (e) => readFiles(e.dataTransfer.files));
$("file").addEventListener("change", (e) => readFiles(e.target.files));
$("q").addEventListener("input", renderTimeline);
$("dl-md").addEventListener("click", () => download("dfir-report.md", toMarkdown(state.a), "text/markdown"));
$("dl-csv").addEventListener("click", () => download("dfir-timeline.csv", toCsv(state.a), "text/csv"));
$("sample").addEventListener("click", async () => {
  const names = ["win-security.jsonl", "auth.log", "access.log"];
  const inputs = [];
  for (const n of names) inputs.push({ name: n, text: await (await fetch("/examples/" + n)).text() });
  run(inputs);
});
