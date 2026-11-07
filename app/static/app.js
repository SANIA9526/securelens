// SecureLens frontend. All dynamic content is written with textContent (never innerHTML),
// because scanned code and AI output are untrusted.
"use strict";

const $ = (sel) => document.querySelector(sel);
const SEVERITIES = ["critical", "high", "medium", "low"];

const state = { filename: null, result: null };

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") node.className = v;
    else if (k === "dataset") Object.assign(node.dataset, v);
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    node.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return node;
}

async function api(path, opts = {}) {
  const res = await fetch(path, opts);
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch {}
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return res.json();
}

// ------------------------------------------------------------ editor + gutter
const code = $("#code"), gutter = $("#gutter"), marked = $("#marked");

function lineSeverities() {
  const map = new Map();
  if (!state.result) return map;
  const rank = (s) => SEVERITIES.indexOf(s);
  for (const f of state.result.findings) {
    if (f.false_positive || !f.line) continue;
    const cur = map.get(f.line);
    if (!cur || rank(f.severity) < rank(cur)) map.set(f.line, f.severity);
  }
  return map;
}

function renderGutter() {
  const count = Math.max(1, code.value.split("\n").length);
  const sev = lineSeverities();
  gutter.replaceChildren(...Array.from({ length: count }, (_, i) =>
    el("div", { "data-sev": sev.get(i + 1) }, i + 1)));
}

function renderMarked() {
  const sev = lineSeverities();
  const lines = code.value.split("\n");
  marked.replaceChildren(...lines.map((text, i) => {
    const n = i + 1;
    return el("div", {
      class: "ln", id: `L${n}`, "data-sev": sev.get(n),
      onclick: sev.get(n) ? () => openFindingForLine(n) : null,
    }, text || " ");
  }));
}

function syncScroll(src) { gutter.scrollTop = src.scrollTop; }
code.addEventListener("scroll", () => syncScroll(code));
marked.addEventListener("scroll", () => syncScroll(marked));
code.addEventListener("input", () => { state.filename = null; renderGutter(); });

function setMarkedMode(on) {
  code.hidden = on;
  marked.hidden = !on;
  $("#edit").hidden = !on;
  if (on) renderMarked(); else code.focus();
  gutter.scrollTop = 0;
}
$("#edit").addEventListener("click", () => setMarkedMode(false));

function jumpToLine(n) {
  const line = document.getElementById(`L${n}`);
  if (!line) return;
  marked.scrollTop = line.offsetTop - marked.clientHeight / 3;
  line.classList.remove("flash"); void line.offsetWidth; line.classList.add("flash");
}

function openFindingForLine(n) {
  const item = document.querySelector(`.finding[data-line="${n}"]`);
  if (!item) return;
  showTab("findings");
  toggleFinding(item, true);
  item.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// ------------------------------------------------------------ samples & files
async function loadSample(name) {
  const s = await api(`/api/samples/${name}`);
  code.value = s.code;
  state.filename = s.filename;
  $("#language").value = s.language;
  state.result = null;
  setMarkedMode(false);
  renderGutter();
}
$("#load-py").addEventListener("click", () => loadSample("python"));
$("#load-js").addEventListener("click", () => loadSample("javascript"));

$("#file").addEventListener("change", async (e) => {
  const file = e.target.files[0];
  if (!file) return;
  if (file.size > 200_000) { alert("Files over 200 KB can't be scanned."); return; }
  code.value = await file.text();
  state.filename = file.name;
  $("#language").value = "";
  state.result = null;
  setMarkedMode(false);
  renderGutter();
  e.target.value = "";
});

// ------------------------------------------------------------ scanning
function show(id) {
  for (const v of ["#empty", "#loading", "#results"]) $(v).hidden = v !== id;
}

$("#scan").addEventListener("click", async () => {
  if (!code.value.trim()) { code.focus(); return; }
  const btn = $("#scan");
  const useAi = $("#use-ai").checked && !$("#use-ai").disabled;
  btn.disabled = true;
  btn.textContent = "Scanning…";
  $("#loading-text").textContent = useAi
    ? "Running static rules, then asking Claude to verify findings and write fixes. This takes 15–40 seconds."
    : "Running static rules…";
  show("#loading");
  try {
    state.result = await api("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        code: code.value,
        language: $("#language").value || null,
        filename: state.filename,
        use_ai: useAi,
      }),
    });
    renderResults();
    setMarkedMode(true);
    renderGutter();
    loadHistory();
  } catch (err) {
    show("#empty");
    $("#empty").replaceChildren(el("h2", {}, "Scan failed"), el("p", {}, err.message + ". Check the server log and try again."));
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan code";
  }
});

function renderResults() {
  const r = state.result;
  show("#results");
  $("#risk").textContent = r.risk_score;
  $("#risk").style.color = r.risk_score >= 60 ? "var(--critical)" : r.risk_score >= 25 ? "var(--high)" : "var(--ink)";

  $("#counts").replaceChildren(...SEVERITIES.map((s) =>
    el("li", { "data-sev": s, class: r.summary[s] ? "" : "zero" }, el("b", {}, r.summary[s]), s)));

  $("#assessment").textContent = r.ai.overall_assessment || "";
  const fps = r.findings.filter((f) => f.false_positive).length;
  const aiExtra = r.findings.filter((f) => f.source === "ai").length;
  $("#mode-note").textContent = r.ai.mode === "ai"
    ? `Reviewed by ${r.ai.model}. Claude added ${aiExtra} finding${aiExtra === 1 ? "" : "s"} the rules missed and dismissed ${fps} false positive${fps === 1 ? "" : "s"}.`
    : r.ai.reason === "ANTHROPIC_API_KEY not set"
      ? "Static rules only. Set ANTHROPIC_API_KEY to have Claude verify findings, catch logic flaws and write a patched file."
      : `Static rules only (${r.ai.reason}).`;
  if (r.parse_error) $("#mode-note").textContent += ` ${r.parse_error}; fell back to pattern rules.`;

  const list = r.findings.map(renderFinding);
  $("#findings").replaceChildren(...(list.length ? list : [el("li", { class: "empty" }, "No issues found. Nice.")]));

  const hasPatch = Boolean(r.ai.patched_code);
  $("#tab-patched").disabled = !hasPatch;
  $("#patched").textContent = r.ai.patched_code || "";
  showTab("findings");
}

function renderFinding(f) {
  const body = el("div", { class: "f-body", hidden: true },
    el("h3", {}, f.ai_explanation ? "How it could be exploited" : "Why it matters"),
    el("p", {}, f.ai_explanation || f.description),
    f.snippet ? [el("h3", {}, "Flagged code"), el("pre", { class: "code-block" }, f.snippet)] : null,
    f.ai_fix
      ? [el("h3", {}, "Suggested fix"), el("pre", { class: "code-block" }, f.ai_fix)]
      : f.recommendation ? [el("h3", {}, "How to fix"), el("p", {}, f.recommendation)] : null,
  );
  const item = el("li", { class: "finding" + (f.false_positive ? " fp" : ""), "data-sev": f.severity, "data-line": f.line },
    el("button", { type: "button", "aria-expanded": "false", onclick: (e) => toggleFinding(item) },
      el("span", { class: "sev" }, f.severity),
      el("span", { class: "f-title" }, f.title,
        f.source === "ai" ? el("span", { class: "badge" }, "found by Claude") : null,
        f.false_positive ? el("span", { class: "badge fp" }, "false positive") : null),
      el("span", { class: "f-line" }, f.line ? `line ${f.line}` : ""),
      el("span", { class: "f-meta" }, [f.cwe, f.owasp].filter(Boolean).join("  ·  ")),
    ),
    body,
  );
  return item;
}

function toggleFinding(item, forceOpen) {
  const btn = item.querySelector("button");
  const body = item.querySelector(".f-body");
  const open = forceOpen ?? body.hidden;
  body.hidden = !open;
  btn.setAttribute("aria-expanded", String(open));
  if (open && item.dataset.line && Number(item.dataset.line) > 0) jumpToLine(Number(item.dataset.line));
}

// ------------------------------------------------------------ tabs
function showTab(name) {
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  document.querySelectorAll("[data-pane]").forEach((p) => (p.hidden = p.dataset.pane !== name));
}
document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => showTab(b.dataset.tab)));

$("#copy-patch").addEventListener("click", async () => {
  await navigator.clipboard.writeText($("#patched").textContent);
  $("#copy-patch").textContent = "Copied";
  setTimeout(() => ($("#copy-patch").textContent = "Copy"), 1500);
});

// ------------------------------------------------------------ history
async function loadHistory() {
  const { stats, scans } = await api("/api/scans?limit=10");
  $("#stats").textContent = `${stats.scans} scans · ${stats.findings} findings · average risk ${stats.avg_risk}`;
  const rows = scans.map((s) => el("tr", { tabindex: "0", onclick: () => openScan(s.id), onkeydown: (e) => e.key === "Enter" && openScan(s.id) },
    el("td", {}, s.id),
    el("td", {}, s.filename || "pasted code"),
    el("td", {}, s.language),
    el("td", {}, s.finding_count),
    el("td", {}, s.risk_score),
    el("td", {}, s.ai_mode === "ai" ? "Claude" : "Static"),
    el("td", {}, new Date(s.created_at).toLocaleString()),
  ));
  $("#history").replaceChildren(...(rows.length ? rows : [el("tr", {}, el("td", { colspan: "7", class: "muted" }, "Scans you run will be listed here."))]));
}

async function openScan(id) {
  const s = await api(`/api/scans/${id}`);
  code.value = s.code;
  state.filename = s.filename;
  state.result = s.result;
  renderResults();
  setMarkedMode(true);
  renderGutter();
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ------------------------------------------------------------ init
(async function init() {
  renderGutter();
  try {
    const h = await api("/api/health");
    const s = $("#ai-status");
    if (h.ai_enabled) {
      s.textContent = `Claude review on`;
      s.classList.add("on");
    } else {
      s.textContent = "Static rules only: set ANTHROPIC_API_KEY for AI review";
      $("#use-ai").checked = false;
      $("#use-ai").disabled = true;
    }
  } catch { $("#ai-status").textContent = "Server unreachable"; }
  loadHistory().catch(() => {});
})();
