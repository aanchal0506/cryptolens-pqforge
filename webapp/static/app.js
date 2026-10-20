// CryptoLens UI. All text from the server goes through textContent, never innerHTML.
const $ = (id) => document.getElementById(id);

function el(tag, props = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const kid of kids.flat()) node.append(kid instanceof Node ? kid : document.createTextNode(kid ?? ""));
  return node;
}

const pretty = (s) => String(s).replaceAll("_", " ");
const pct = (p, digits = 0) => (p * 100).toFixed(digits) + "%";

const STAGES = [
  ["1", "Ingestion"], ["2a", "AST features"], ["2b", "Neural encoding"], ["3", "Fusion + classification"],
  ["3b", "Arbiter"], ["4", "Migration prompt + LLM"], ["5", "Verification"], ["6", "Report + CI gate"],
];
// Order and wording of the risk classes, worst first.
const RISKS = [
  ["broken_by_shor", "Broken by Shor"], ["already_deprecated", "Already deprecated"],
  ["weakened_by_grover", "Weakened by Grover"], ["needs_review", "Needs review"], ["quantum_safe", "Quantum safe"],
];
const STATE_TEXT = {
  migrated_verified: "Migrated and verified", safe: "Already safe", migration_failed: "Migration failed",
  needs_human_review: "Needs review", pending: "Not migrated",
};

let lastResult = null;
let activeFilter = "all";
let selectedIndex = -1;

// ---- tabs -------------------------------------------------------------------------------
document.querySelectorAll(".tab").forEach((btn) => btn.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach((b) => {
    b.classList.toggle("active", b === btn);
    if (b === btn) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
  });
  for (const name of ["analyze", "evaluation", "quantum"]) $("tab-" + name).hidden = btn.dataset.tab !== name;
    if (btn.dataset.tab === "evaluation") loadEvaluation();
    if (btn.dataset.tab === "quantum" && !quantumRan) { quantumRan = true; runQuantum(); }
}));

// ---- pipeline stepper -------------------------------------------------------------------
function drawStepper(trace = []) {
  const byId = Object.fromEntries(trace.map((t) => [t.stage, t]));
  const list = $("stepper");
  list.replaceChildren(...STAGES.map(([id, title]) =>
    el("li", { "data-id": id }, el("span", { class: "badge" }, id),
       el("div", {}, el("b", {}, title), el("small", {}, byId[id] ? byId[id].summary : "Waiting for a run")))));
  return list;
}
async function animateStepper(trace) {
  const list = drawStepper(trace);
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  for (const li of list.children) {
    if (!reduce) await new Promise((r) => setTimeout(r, 120));
    li.classList.add("done");
  }
}

// ---- analyze ----------------------------------------------------------------------------
function showError(msg) { $("error").hidden = !msg; $("error").textContent = msg || ""; }

async function analyze() {
  showError("");
  $("btn-run").disabled = true;
  $("btn-run").textContent = "Analyzing...";
  try {
    const res = await fetch("/api/analyze", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: $("code").value, migrate: $("opt-migrate").checked, backend: "template" }),
    });
    const data = await res.json();
    if (!res.ok) { showError(data.error || "The request failed."); return; }
    lastResult = data;
    activeFilter = "all";
    await animateStepper(data.trace);
    renderResults(data);
  } catch (err) {
    showError("Could not reach the server: " + err.message);
  } finally {
    $("btn-run").disabled = false;
    $("btn-run").textContent = "Analyze";
  }
}

function migrationState(f) {
  if (f.decision.risk === "quantum_safe") return "safe";
  if (f.verified) return "migrated_verified";
  if (f.attempts.length) return "migration_failed";
  if (["abstain", "ambiguous", "contested"].includes(f.decision.status)) return "needs_human_review";
  return "pending";
}
// unknown and needs_review share one colour and one filter
const riskKey = (r) => (r === "unknown" ? "needs_review" : r);

function renderResults(data) {
  $("results").hidden = false;
  renderGate(data);
  renderRiskBar(data);
  renderLedger();
  const first = visibleFindings()[0];
  if (first) selectFinding(first.index);
  else $("detail").replaceChildren(el("p", { class: "muted" }, "Nothing to show here. Pick another filter."));
}

function renderGate(data) {
  const f = data.findings;
  const attempted = f.filter((x) => x.attempts.length).length;
  const verified = f.filter((x) => x.verified).length;
  const safe = f.filter((x) => x.decision.risk === "quantum_safe").length;
  const passed = data.gate.passed;
  const parts = [`${f.length} crypto ${f.length === 1 ? "unit" : "units"} found`];
  if (attempted) parts.push(`${verified} of ${attempted} migrations verified`);
  if (safe) parts.push(`${safe} already quantum safe`);
  const box = $("gate");
  box.className = "gate " + (passed ? "pass" : "fail");
  const kids = [
    el("div", { class: "verdict" }, passed ? "Gate passed" : "Gate failed"),
    el("div", {}, el("div", { class: "headline" }, f.length ? parts.join(", ") : "No cryptography found in this code"),
       el("div", { class: "detail-line" }, `${data.units_total} code units scanned in ${data.seconds} s` +
         (data.model_loaded ? " with the trained classifier." : " with the rule layer only."))),
  ];
  if (!passed && data.gate.reasons.length) {
    const n = data.gate.reasons.length;
    const details = el("details", { open: "" }, el("summary", {}, `${n} ${n === 1 ? "finding blocks" : "findings block"} the gate`),
      el("ul", {}, data.gate.reasons.map((r) => el("li", {}, r))));
    if (n > 6) details.removeAttribute("open");
    kids.push(details);
  }
  box.replaceChildren(...kids);
}

function renderRiskBar(data) {
  const counts = {};
  data.findings.forEach((f) => { const k = riskKey(f.decision.risk); counts[k] = (counts[k] || 0) + 1; });
  const total = data.findings.length;
  $("riskbar").replaceChildren(...RISKS.filter(([k]) => counts[k]).map(([k, label]) =>
    el("span", { class: "r-" + k, style: `flex:${counts[k]}`, title: `${label}: ${counts[k]}` })));
  $("riskbar").style.display = total ? "flex" : "none";
  const make = (key, label, n) => el("button", {
    class: "filter", "aria-pressed": String(activeFilter === key),
    onclick: () => { activeFilter = key; renderRiskBar(lastResult); renderLedger();
      const first = visibleFindings()[0]; if (first) selectFinding(first.index); },
  }, label, el("b", {}, String(n)));
  $("filters").replaceChildren(make("all", "All", total),
    ...RISKS.filter(([k]) => counts[k]).map(([k, label]) => make(k, label, counts[k])));
}

function visibleFindings() {
  return lastResult.findings.map((f, index) => ({ f, index }))
    .filter(({ f }) => activeFilter === "all" || riskKey(f.decision.risk) === activeFilter);
}

function renderLedger() {
  const rows = visibleFindings();
  if (!rows.length) {
    $("ledger").replaceChildren(el("p", { class: "empty" }, lastResult.findings.length
      ? "No findings match this filter." : "No cryptographic primitives were found, so there is nothing to migrate."));
    return;
  }
  $("ledger").replaceChildren(...rows.map(({ f, index }) => {
    const d = f.decision, state = migrationState(f), risk = riskKey(d.risk);
    return el("button", { class: "row r-" + risk, "data-index": String(index), "aria-selected": String(index === selectedIndex),
        onclick: () => selectFinding(index) },
      el("div", {}, el("div", { class: "unit" }, f.unit),
         el("div", { class: "meta" }, el("span", {}, `line ${f.start}`), el("span", {}, d.families.join(", ") || "no family"),
            el("span", {}, `${d.source}, ${d.status}`))),
      el("div", { class: "swap" },
         el("div", { class: "change" },
            f.threats.length > 1 ? el("span", { class: "to" }, `${f.threats.length} threats: ${f.threats.map((t) => t.algorithm).join(", ")}`)
            : d.target ? [el("del", {}, d.algorithm || "unclassified"), el("span", {}, "→"), el("span", { class: "to" }, d.target)]
                     : el("span", { class: "to" }, d.algorithm || "unclassified")),
         el("span", { class: "pill" }, pretty(d.risk))),
      el("div", { class: "state s-" + state }, STATE_TEXT[state]));
  }));
}

// ---- finding detail ---------------------------------------------------------------------
function selectFinding(i) {
  selectedIndex = i;
  document.querySelectorAll(".row").forEach((r) => r.setAttribute("aria-selected", String(r.dataset.index === String(i))));
  const f = lastResult.findings[i];
  const d = f.decision;
  const ran = f.threats.filter((t) => t.attempts.length);
  const none = (text) => el("p", { class: "muted" }, text);
  const tabs = {
    Classification: () => classificationView(f),
    Prompt: () => ran.length ? perThreat(f, ran, (t, last) => promptView(last)) : none("No migration was run for this unit."),
    Migration: () => ran.length ? perThreat(f, ran, (t, last) => migrationView(f, t, last)) : none("No migration was run for this unit."),
    Verification: () => ran.length ? perThreat(f, ran, (t) => verificationView(t)) : none("Nothing to verify yet."),
    "Final code": () => f.final_code ? finalView(f) : none("No migration was run for this unit."),
  };
  const area = el("div");
  const bar = el("div", { class: "dtabs" });
  const show = (name) => {
    [...bar.children].forEach((b) => b.setAttribute("aria-pressed", String(b.textContent === name)));
    area.replaceChildren(tabs[name]());
  };
  Object.keys(tabs).forEach((name) => bar.append(el("button", { onclick: () => show(name) }, name)));
  $("detail").replaceChildren(
    el("h2", {}, f.unit),
    el("p", { class: "sub" }, `${f.file}, lines ${f.start} to ${f.end}`),
    bar, area);
  show("Classification");
}

function barRow(label, p, text) {
  return el("div", { class: "bar" }, el("span", { class: "label" }, label),
    el("div", { class: "track" }, el("i", { style: `width:${Math.max(0, Math.min(1, p)) * 100}%` })),
    el("span", { class: "value" }, text ?? pct(p)));
}

function classificationView(f) {
  const d = f.decision, wrap = el("div");
  if (f.threats.length > 1) {
    wrap.append(el("p", {}, `${f.threats.length} separate threats in this unit. Each gets its own prompt, fix and check:`));
    wrap.append(el("ul", {}, f.threats.map((t) => el("li", {},
      el("b", {}, `${t.family}: ${t.algorithm || "unclassified"}`),
      t.target ? [" → ", el("b", {}, t.target)] : "", `  (${pretty(t.risk)}, line ${t.line})`))));
  } else {
    wrap.append(el("p", {}, el("b", {}, d.algorithm || "Unclassified"),
      d.target ? [" should move to ", el("b", {}, d.target), "."] : " needs no migration."));
  }
  wrap.append(el("h4", {}, "Why it must change"));
  f.threats.forEach((t) => {
    if (!t.why) return;
    wrap.append(el("div", { class: "why" },
      el("b", {}, `${t.family}: ${t.algorithm || "unclassified"}` + (t.target ? ` → ${t.target}` : "")),
      el("p", {}, el("span", { class: "tag" }, "Before"), " " + t.why.problem),
      t.why.replacement ? el("p", {}, el("span", { class: "tag" }, "After"), " " + t.why.replacement) : ""));
  });
  wrap.append(el("p", { class: "muted" },
    `Decided by the ${d.source} layer. Status: ${d.status}. Confidence: ${pct(d.confidence)}. ${d.note || ""}`));
  const probs = d.model && d.model.family_probs;
  if (probs) {
    wrap.append(el("h4", {}, "Model confidence by family"));
    Object.entries(probs).sort((a, b) => b[1] - a[1]).slice(0, 5)
      .forEach(([name, p]) => wrap.append(barRow(pretty(name), p)));
  } else {
    wrap.append(el("p", { class: "muted" }, "No trained model was loaded, so only the rule layer decided."));
  }
  wrap.append(el("h4", {}, "Code analysed"), el("pre", {}, f.code));
  return wrap;
}

function finalView(f) {
  const copy = el("button", { class: "copy", onclick: async (e) => {
    try { await navigator.clipboard.writeText(f.final_code); e.target.textContent = "Copied"; }
    catch { e.target.textContent = "Copy failed"; }
    setTimeout(() => { e.target.textContent = "Copy"; }, 1500);
  } }, "Copy");
  const bad = f.threats.filter((t) => t.attempts.length && !t.verified).length;
  return el("div", {},
    el("p", { class: "muted" }, bad
      ? `${bad} threat(s) could not be verified and are listed as comments. The rest are included below.`
      : "Every verified fix for this unit in one block. Hash fixes are inside the original code; cipher, signature and key-exchange fixes are labelled helper sections."),
    el("h4", {}, "Final post-quantum code", copy), el("pre", {}, f.final_code));
}

// One block per threat: a unit with three weak primitives shows three prompts, three fixes, three checks.
function perThreat(f, threats, render) {
  const wrap = el("div");
  threats.forEach((t, n) => {
    const last = t.attempts[t.attempts.length - 1];
    if (f.threats.length > 1) {
      wrap.append(el("h3", { class: "threat-head" },
        `Threat ${n + 1} of ${f.threats.length}: ${t.family}, ${t.algorithm || "unclassified"}`,
        el("span", { class: "pill" }, t.verified ? "verified" : "not verified")));
    }
    wrap.append(render(t, last));
  });
  return wrap;
}

function promptView(last) {
  const wrap = el("div");
  last.messages.forEach((m) => wrap.append(el("div", { class: "msg" }, el("div", { class: "role" }, m.role), el("pre", {}, m.content))));
  return wrap;
}

function migrationView(f, t, last) {
  const copy = el("button", { class: "copy", onclick: async (e) => {
    try { await navigator.clipboard.writeText(last.code); e.target.textContent = "Copied"; }
    catch { e.target.textContent = "Copy failed"; }
    setTimeout(() => { e.target.textContent = "Copy"; }, 1500);
  } }, "Copy");
  return el("div", {},
    el("p", { class: "muted" }, `Backend: ${last.backend}. ${last.note} Attempts: ${t.attempts.length}.`),
    el("div", { class: "two" },
      el("div", {}, el("h4", {}, "Before"), el("pre", {}, f.code)),
      el("div", {}, el("h4", {}, "After", copy), el("pre", {}, last.code))));
}

function verificationView(t) {
  const wrap = el("div");
  t.attempts.forEach((a) => {
    wrap.append(el("h4", {}, `Attempt ${a.attempt}: ${a.verification.validator} validator ${a.verification.passed ? "passed" : "failed"}`));
    a.verification.checks.forEach((c) => wrap.append(el("div", { class: "check-row" },
      el("span", { class: c.passed ? "ok" : "no" }, c.passed ? "Pass" : "Fail"),
      el("b", {}, c.name), el("span", { class: "muted" }, c.detail))));
  });
  return wrap;
}

async function loadEvaluation() {
  const body = $("eval-body");
  const res = await fetch("/api/metrics");
  const m = await res.json();
  if (!res.ok) { body.replaceChildren(el("h2", {}, "Evaluation"), el("p", { class: "error" }, m.error)); return; }
  const out = [];
  if (m.dataset.standin) {
    out.push(el("div", { class: "banner" }, "These numbers come from a synthetic stand-in dataset of template-generated code. " +
      "They show that the pipeline works end to end, not how accurate it is on real code. " +
      "Put the paper's dataset in data/ and run training again."));
  }
  out.push(el("h2", {}, "Family classification on held-out data"),
    el("p", { class: "muted lead" }, `${m.dataset.entries} dataset entries plus ${m.dataset.negatives_added} non-crypto functions. ` +
      `${m.dataset.train} for training, ${m.dataset.test} for testing. Encoder: ${m.dataset.encoder}.`));
  out.push(el("div", { class: "metric-head" }, el("span", {}, "Method"), el("span", {}, "Accuracy"), el("span", {}), el("span", {}, "Macro F1"), el("span", {})));
  const names = { rules_only: "Rules only", model_only: "Model only", hybrid: "Hybrid" };
  for (const key of ["rules_only", "model_only", "hybrid"]) {
    const s = m.family[key];
    out.push(el("div", { class: "metric-row" }, el("b", {}, names[key]),
      el("div", { class: "track" }, el("i", { style: `width:${s.accuracy * 100}%` })), el("span", { class: "num" }, s.accuracy.toFixed(3)),
      el("div", { class: "track" }, el("i", { style: `width:${s.macro_f1 * 100}%` })), el("span", { class: "num" }, s.macro_f1.toFixed(3))));
  }
  out.push(el("p", { class: "muted" }, `Abstain rate: rules only ${pct(m.abstain_rate.rules_only, 1)}, hybrid ${pct(m.abstain_rate.hybrid, 1)}. ` +
    `Algorithm accuracy of the model against rule-derived (weak) labels: ${Number(m.algorithm_vs_weak_labels.model_only).toFixed(3)}.`));

  // per-family table and confusion matrix, side by side
  const labels = m.confusion_hybrid.labels, mat = m.confusion_hybrid.matrix;
  const max = Math.max(1, ...mat.flat());
  const perFamily = el("div", {}, el("h3", {}, "Per family (hybrid)"),
    el("div", { class: "table-scroll" }, el("table", {},
      el("thead", {}, el("tr", {}, el("th", {}, "Family"), ["Precision", "Recall", "F1", "Tests"].map((h) => el("th", { class: "num" }, h)))),
      el("tbody", {}, labels.filter((l) => m.per_family_hybrid[l]).map((l) => {
        const r = m.per_family_hybrid[l];
        return el("tr", {}, el("td", {}, pretty(l)), el("td", { class: "num" }, r.precision.toFixed(2)),
          el("td", { class: "num" }, r.recall.toFixed(2)), el("td", { class: "num" }, r["f1-score"].toFixed(2)),
          el("td", { class: "num" }, String(Math.round(r.support))));
      })))));
  const head = el("tr", {}, el("td", {}, "true \\ predicted"), labels.map((l) => el("td", {}, pretty(l))));
  const rows = mat.map((r, i) => el("tr", {}, el("td", {}, el("b", {}, pretty(labels[i]))),
    r.map((v) => el("td", { style: `background:rgba(43,63,208,${(v / max) * 0.8})${v / max > 0.45 ? ";color:#fff" : ""}` }, v ? String(v) : ""))));
  const confusion = el("div", {}, el("h3", {}, "Confusion matrix (hybrid)"),
    el("div", { class: "table-scroll" }, el("table", { class: "heat" }, head, rows)));
  out.push(el("div", { class: "eval-grid" }, perFamily, confusion));
  body.replaceChildren(...out);
}

// ---- quantum demo tab --------------------------------------------------------------------
// ---- quantum demo tab --------------------------------------------------------------------
const reduceMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const sleep = (ms) => new Promise((r) => setTimeout(r, reduceMotion() ? 0 : ms));
let quantumRan = false;
let quantumRun = 0;           // a newer run cancels an older animation

// A numbered step that starts dimmed and lights up when its turn comes.
function qstep(n, title, ...body) {
  const box = el("div", { class: "qstep wait" }, el("div", { class: "qnum" }, String(n)),
    el("div", { class: "qbody" }, el("h4", {}, title), ...body));
  return box;
}
const light = (box) => { box.classList.remove("wait"); box.classList.add("on"); };

function buildShor(s) {
  const chips = el("div", { class: "chips" });
  const note2 = el("p", { class: "muted", hidden: "" });
  const hist = el("div", { class: "hist" });
  const histNote = el("p", { class: "muted", hidden: "" });
  const maxCount = Math.max(1, ...s.histogram.map((h) => h.count));
  const bars = s.histogram.map((h) => {
    const fill = el("i", { style: "height:0%" });
    hist.append(el("div", { class: "hcol" }, el("span", { class: "hnum" }, "0"),
      el("div", { class: "hbar" }, fill), el("span", { class: "hlab" }, h.phase.toFixed(3))));
    return { fill, num: hist.lastChild.firstChild, h };
  });
  const result = el("div", { class: "qresult", hidden: "" });
  const steps = [
    qstep(1, "Pick a number to test",
      el("p", {}, `Goal: factor 15. Take a = ${s.a}. The trick: the list a^x mod 15 repeats, and the length r of the repeat reveals the factors.`)),
    qstep(2, `Watch the pattern of ${s.a}^x mod 15`, chips, note2),
    qstep(3, "The quantum circuit (Qiskit)",
      el("p", { class: "muted" }, `${s.qubits} qubits: 3 counting qubits (top) and 4 working qubits. ${s.gates} operations. Superposition tries every x at once; the inverse QFT turns the repeat length into measurable peaks.`),
      el("pre", { class: "circuit" }, s.circuit_text)),
    qstep(4, `Measure the counting qubits ${s.shots} times`, hist, histNote),
    qstep(5, "Turn the period into factors", result),
  ];
  return { steps, async play(guard) {
    light(steps[0]); await sleep(700); if (guard()) return;
    light(steps[1]);
    for (let i = 0; i < s.powers.length; i++) {
      const chip = el("span", { class: "chip" + (s.powers[i] === 1 ? " one" : "") }, String(s.powers[i]));
      chips.append(chip); await sleep(170); if (guard()) return;
    }
    note2.hidden = false;
    note2.textContent = s.order
      ? `The values repeat every r = ${s.order} steps (highlighted: back to 1). A normal computer must walk the list. For a 2048-bit RSA number r is astronomically long, so that is hopeless. A quantum computer finds r in one go.`
      : "No usable period for this choice of a. Try another base.";
    await sleep(600); if (guard()) return;
    light(steps[2]); await sleep(900); if (guard()) return;
    light(steps[3]); await sleep(300);
    for (let f = 1; f <= 20; f++) {         // the counts "build up" like shots arriving
      bars.forEach((b) => {
        b.fill.style.height = (b.h.count / maxCount) * (f / 20) * 100 + "%";
        b.num.textContent = String(Math.round(b.h.count * f / 20));
      });
      await sleep(60); if (guard()) return;
    }
    histNote.hidden = false;
    histNote.textContent = s.order
      ? `Peaks appear only at multiples of 1/r (${[...Array(s.order).keys()].map((k) => `${k}/${s.order}`).join(", ")}). Their spacing tells us r = ${s.order}.`
      : "";
    await sleep(700); if (guard()) return;
    light(steps[4]);
    if (s.factors && s.gcds) {
      result.hidden = false;
      result.append(el("div", { class: "math" },
        el("div", {}, `${s.a}^(${s.order}/2) mod 15 = ${s.half_power}`),
        el("div", {}, `gcd(${s.half_power} - 1, 15) = ${s.gcds[0]}`),
        el("div", {}, `gcd(${s.half_power} + 1, 15) = ${s.gcds[1]}`)),
        el("span", { class: "bignum" }, `15 = ${s.factors.join(" × ")}`));
    } else {
      result.hidden = false;
      result.append(el("p", { class: "muted" }, "This base gives no factors (odd period). Real Shor simply retries with another base."));
    }
  } };
}

function buildGrover(g) {
  const cols = 2 ** Math.ceil(g.key_bits / 2);
  const grid = el("div", { class: "keygrid", style: `grid-template-columns:repeat(${cols}, var(--cell))` });
  const cells = [];
  for (let i = 0; i < g.search_space; i++) {
    const c = el("div", { class: "kcell" + (i === g.secret_index ? " secret" : ""),
      title: i.toString(2).padStart(g.key_bits, "0") });
    cells.push(c); grid.append(c);
  }
  grid.style.setProperty("--cell", g.search_space > 64 ? "13px" : "26px");
  const readout = el("div", { class: "readout" });
  const meter = el("div", { class: "track big" }, el("i", { style: "width:0%" }));
  const caption = el("p", { class: "muted" });
  const paint = (k) => {
    g.history[k].forEach((p, i) => { cells[i].style.opacity = String(0.1 + 0.9 * Math.min(1, p)); });
    const p = g.history[k][g.secret_index];
    meter.firstChild.style.width = p * 100 + "%";
    readout.replaceChildren(el("span", { class: "bignum" }, pct(p, 1)),
      el("small", {}, `chance that the secret key ${g.secret} is what we would measure now (iteration ${k} of ${g.iterations})`));
    caption.textContent = k === 0
      ? `Start: all ${g.search_space} keys are equally likely (1 in ${g.search_space}).`
      : "The oracle flips the sign of the secret key; the diffuser then boosts every key that was flipped. The secret grows, the rest shrink.";
  };
  paint(0);
  const steps = [
    qstep(1, `Hide a ${g.key_bits}-bit key among ${g.search_space}`,
      el("p", {}, `Your secret is ${g.secret}. Each square below is one possible key; the outlined square is the secret. Brightness is the chance that measuring would give that key.`)),
    qstep(2, "Amplify the secret, one iteration at a time", grid, readout, meter, caption),
    qstep(3, "One iteration as a circuit (Qiskit)",
      el("p", { class: "muted" }, `${g.qubits} qubits. Left to right: the first column puts all keys in superposition, the rest is the oracle and diffuser. The loop is repeated ${g.iterations} times.`),
      el("pre", { class: "circuit" }, g.circuit_text)),
    qstep(4, "What it costs",
      el("p", {}, `A normal computer needs about ${g.classical_expected_guesses} guesses on average. Grover used ${g.iterations} iterations: roughly the square root. `
        + "That is a speed-up, not a break. It halves the effective key length, which is why AES-128 is flagged and AES-256 is not.")),
  ];
  return { steps, async play(guard) {
    light(steps[0]); await sleep(700); if (guard()) return;
    light(steps[1]); await sleep(900); if (guard()) return;
    for (let k = 1; k <= g.iterations; k++) { paint(k); await sleep(1100); if (guard()) return; }
    light(steps[2]); await sleep(700); if (guard()) return;
    light(steps[3]);
  } };
}

async function runQuantum() {
  const run = ++quantumRun;
  const guard = () => run !== quantumRun;
  const err = $("q-error"); err.hidden = true;
  $("btn-quantum").disabled = true; $("btn-quantum").textContent = "Simulating...";
  try {
    const res = await fetch("/api/quantum", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ a: $("q-a").value, secret: $("q-secret").value }) });
    const d = await res.json();
    if (!res.ok) { err.textContent = d.error; err.hidden = false; return; }
    const shor = buildShor(d.shor), grover = buildGrover(d.grover);
    const card = (title, tag, built) => el("section", { class: "qcard2" },
      el("h3", {}, title), el("p", { class: "tag" }, tag), ...built.steps);

    const table = el("div", { class: "table-scroll" }, el("table", {},
      el("thead", {}, el("tr", {}, ["Primitive", "Classical bits", "Against Grover", "Verdict"].map((h, i) => el("th", { class: i === 1 || i === 2 ? "num" : "" }, h)))),
      el("tbody", {}, d.grover_table.map((r) => el("tr", {}, el("td", {}, r.primitive), el("td", { class: "num" }, String(r.classical_bits)),
        el("td", { class: "num" }, String(r.vs_grover_bits)), el("td", {}, r.verdict))))));

    const sc = d.scale;
    const link = el("section", { class: "qlink" },
      el("h3", {}, "How this connects to the scanner"),
      el("div", { class: "qmap" },
        el("div", {}, el("b", {}, "Shor's algorithm"), el("p", {}, "RSA, DSA, Diffie-Hellman, elliptic curves"), el("p", { class: "to" }, "→ labelled Broken by Shor → ML-DSA-87 / ML-KEM-1024")),
        el("div", {}, el("b", {}, "Grover's algorithm"), el("p", {}, "AES-128, hashes, HMAC"), el("p", { class: "to" }, "→ labelled Weakened by Grover → AES-256-GCM / SHA3"))),
      el("p", { class: "muted" }, `Scale check: these demos use ${sc.toy_qubits} qubits. Breaking RSA-${sc.rsa_bits} with Shor needs about ${sc.logical_qubits.toLocaleString()} error-corrected logical qubits (2n + 3). `
        + "Published estimates of the physical qubits needed range from about 20 million (2019) down to under a million (Gidney, arXiv:2505.15917, 2025). "
        + "Nobody can do this today. Migration is planned now because data recorded today can be decrypted later."));

    $("q-out").replaceChildren(el("div", { class: "qgrid2" }, card("Shor: factoring 15", "Breaks RSA, elliptic curves and Diffie-Hellman", shor),
      card("Grover: searching for a key", "Weakens AES and hash functions", grover)),
      link, el("h3", {}, "Key strength after Grover"), table);
    $("btn-quantum").textContent = "Running circuits...";
    await Promise.all([shor.play(guard), grover.play(guard)]);
  } catch (e) {
    err.textContent = "Could not reach the server: " + e.message; err.hidden = false;
  } finally { $("btn-quantum").disabled = false; $("btn-quantum").textContent = "Run again"; }
}
$("btn-quantum").addEventListener("click", runQuantum);
// ---- wiring -----------------------------------------------------------------------------
$("btn-run").addEventListener("click", analyze);
$("code").addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") analyze(); });
$("btn-sample").addEventListener("click", async () => { $("code").value = (await (await fetch("/api/sample")).json()).code; });
$("btn-clear").addEventListener("click", () => { $("code").value = ""; showError(""); $("code").focus(); });
$("file").addEventListener("change", async (e) => { const f = e.target.files[0]; if (f) $("code").value = await f.text(); });
$("btn-cbom").addEventListener("click", () => {
  if (!lastResult) return;
  const url = URL.createObjectURL(new Blob([JSON.stringify(lastResult.cbom, null, 2)], { type: "application/json" }));
  el("a", { href: url, download: "cbom.json" }).click();
  URL.revokeObjectURL(url);
});
drawStepper();