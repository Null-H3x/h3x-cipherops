/* H3X Constraints Dash — identify → route → run */

const state = {
  session: null,
  offset: 0,
  limit: 100,
  total: 0,
  classification: null,
  routedIndex: null,
  lastConfig: null,
  selectedFinding: null,
  actionableKinds: new Set(["pt_difference", "equality", "keystream_pin", "assignment", "stream_pin"]),
};

const $ = (id) => document.getElementById(id);

function log(msg) {
  const el = $("log");
  const ts = new Date().toISOString().slice(11, 19);
  el.textContent += `[${ts}] ${msg}\n`;
  el.scrollTop = el.scrollHeight;
}

function setStatus(kind, text) {
  const pill = $("status-pill");
  pill.className = `pill pill-${kind}`;
  pill.textContent = text;
}

function getCiphertext() {
  return $("ciphertext").value.trim();
}

function resetInferred() {
  $("inferred-propagator").textContent = "unknown";
  $("inferred-propagator").classList.add("unknown");
  $("inferred-deck-size").textContent = "unknown";
  $("inferred-deck-size").classList.add("unknown");
  $("inferred-route").textContent = "—";
  $("inferred-route").classList.add("unknown");
  state.routedIndex = null;
}

function setInferred(route) {
  const prop = route?.propagator;
  const deck = route?.deck_size;

  const propEl = $("inferred-propagator");
  propEl.textContent = prop && prop !== "none" ? prop.replace(/_/g, " ") : "unknown";
  propEl.classList.toggle("unknown", !prop || prop === "none");

  const deckEl = $("inferred-deck-size");
  if (deck != null) {
    deckEl.textContent = String(deck);
    deckEl.classList.remove("unknown");
  } else {
    deckEl.textContent = "unknown";
    deckEl.classList.add("unknown");
  }

  const routeEl = $("inferred-route");
  routeEl.textContent = route?.label || "—";
  routeEl.classList.toggle("unknown", !route?.label);
}

function parsePins() {
  const raw = $("pins-json").value.trim();
  if (!raw) return [];
  return JSON.parse(raw);
}

function isActionableFinding(row) {
  if (!row) return false;
  if (row.kind === "assignment") return row.data?.field === "pt";
  if (row.kind === "stream_pin") return row.data?.role === "seed";
  return state.actionableKinds.has(row.kind);
}

function mergePins(existing, incoming) {
  const keyed = new Map();
  for (const pin of [...existing, ...incoming]) {
    keyed.set(`${pin.msg ?? "all"}:${pin.pos}`, pin);
  }
  return [...keyed.values()];
}

function setPinsJson(pins, hintText) {
  const field = $("pins-json");
  field.value = JSON.stringify(pins, null, 2);
  field.classList.add("pins-json-highlight");
  setTimeout(() => field.classList.remove("pins-json-highlight"), 1800);
  if (hintText) {
    const hint = $("pins-json-hint");
    hint.textContent = hintText;
    hint.classList.add("flash");
    setTimeout(() => hint.classList.remove("flash"), 2500);
  }
  field.scrollIntoView({ behavior: "smooth", block: "center" });
}

async function fetchCribHint(finding, anchorPt) {
  let existingPins = [];
  try { existingPins = parsePins(); } catch { existingPins = []; }

  const res = await fetch("/api/crib-from-finding", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      finding,
      deck_size: state.lastConfig?.deck_size ?? 83,
      anchor_pt: anchorPt,
      existing_pins: existingPins,
    }),
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Crib hint failed");
  return data;
}

function showFindingDetail(row) {
  state.selectedFinding = row;
  $("finding-detail").textContent = JSON.stringify(row, null, 2);

  const actions = $("crib-actions");
  if (!isActionableFinding(row)) {
    actions.classList.add("hidden");
    return;
  }

  actions.classList.remove("hidden");
  $("crib-hint").textContent = "Loading crib suggestion…";
  fetchCribHint(row, Number($("crib-anchor-pt").value) || 10)
    .then((data) => {
      $("crib-hint").textContent = data.hint || "";
      state.lastCribHint = data;
    })
    .catch((err) => {
      $("crib-hint").textContent = err.message;
    });
}

async function applyCribFromSelected(merge = true) {
  const row = state.selectedFinding;
  if (!row || !isActionableFinding(row)) return;

  const anchorPt = Number($("crib-anchor-pt").value) || 10;
  const data = await fetchCribHint(row, anchorPt);
  if (!data.actionable || !data.pins?.length) {
    log(`Crib: not actionable for ${row.kind}`);
    return;
  }

  let pins = data.pins;
  if (merge) {
    let existing = [];
    try { existing = parsePins(); } catch { /* keep empty */ }
    pins = data.merged_pins || mergePins(existing, data.pins);
  }

  setPinsJson(pins, data.hint);
  log(`Crib pins applied from ${row.kind} @ pos ${row.data?.pos ?? "?"}`);
  log(`  ${data.hint}`);
}

function applyCribFromSuggestion(exampleText) {
  const trimmed = exampleText.trim();
  if (!trimmed.startsWith("[")) return false;
  try {
    const pins = JSON.parse(trimmed);
    if (!Array.isArray(pins)) return false;
    let merged = pins;
    try { merged = mergePins(parsePins(), pins); } catch { /* use pins only */ }
    setPinsJson(merged, "Applied from stop suggestion");
    log("Crib pins applied from stop suggestion");
    return true;
  } catch {
    return false;
  }
}

function renderStop(stop) {
  const panel = $("stop-panel");
  if (!stop) {
    panel.classList.add("hidden");
    $("stat-stop").textContent = "—";
    return;
  }

  panel.classList.remove("hidden");
  panel.className = `stop-panel status-${stop.status}`;
  $("stat-stop").textContent = stop.status.replace(/_/g, " ");
  $("stop-headline").textContent = stop.headline;
  $("stop-detail").textContent = stop.detail || "";

  const list = $("stop-suggestions");
  list.innerHTML = "";
  if (!stop.suggestions?.length) {
    list.innerHTML = '<li class="sugg-meta">No further inputs required at this fixpoint.</li>';
    return;
  }

  stop.suggestions.forEach((s) => {
    const li = document.createElement("li");
    li.innerHTML = `
      <span class="sugg-priority ${s.priority}">${s.priority}</span>
      <span class="sugg-action">${s.action}</span>
      ${s.detail ? `<span class="sugg-meta">${s.detail}</span>` : ""}
      ${s.example ? `<span class="sugg-meta sugg-example">e.g. ${s.example}</span>` : ""}
    `;
    if (s.example && s.example.trim().startsWith("[")) {
      li.classList.add("sugg-clickable");
      li.title = "Click to apply example crib pins";
      li.addEventListener("click", () => applyCribFromSuggestion(s.example));
    }
    list.appendChild(li);
  });
}

function applyStatusFromStop(stop) {
  if (!stop) {
    setStatus("idle", "IDLE");
    return;
  }
  const map = {
    complete: ["ok", "GROUNDED"],
    needs_information: ["run", "NEEDS INFO"],
    conflict: ["err", "CONFLICT"],
    validation_failed: ["err", "REJECTED"],
    max_rounds: ["run", "MAX ROUNDS"],
  };
  const [kind, label] = map[stop.status] || ["idle", "IDLE"];
  setStatus(kind, label);
}

function renderSummary(data) {
  const s = data.summary || {};
  $("stat-corpus").textContent = data.config?.slug || "—";
  $("stat-prop").textContent = data.config?.propagator || s.propagator || "—";
  $("stat-findings").textContent = data.findings_count ?? data.total ?? "—";
  $("stat-validated").textContent = s.final_validated_count ?? data.validated_count ?? "—";
  $("stat-conflicts").textContent = s.remaining_conflicts ?? "—";
  $("stat-converged").textContent = s.converged ? "yes" : "no";

  const stop = s.stop || data.stop;
  renderStop(stop);
  applyStatusFromStop(stop);

  const timeline = $("round-timeline");
  timeline.innerHTML = "";
  (s.rounds || []).forEach((r) => {
    const chip = document.createElement("div");
    chip.className = `round-chip ${r.converged ? "done" : ""} ${r.rejected_count ? "warn" : ""}`;
    chip.textContent = `R${r.round}: ${r.findings_count} findings · +${r.new_pins} pins · val ${r.validated_count}`;
    timeline.appendChild(chip);
  });
}

function renderFindings(rows) {
  const body = $("findings-body");
  body.innerHTML = "";

  if (!rows.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty">No findings match filters.</td></tr>';
    return;
  }

  rows.forEach((row, idx) => {
    const tr = document.createElement("tr");
    tr.dataset.idx = String(idx);
    if (isActionableFinding(row)) tr.classList.add("actionable");
    const confClass = `badge badge-${row.confidence || "propagated"}`;
    tr.innerHTML = `
      <td>${row.round ?? "—"}</td>
      <td class="kind">${row.kind}</td>
      <td><span class="${confClass}">${row.confidence}</span></td>
      <td>${row.source}</td>
      <td class="data-preview">${JSON.stringify(row.data || {})}</td>
    `;
    tr.addEventListener("click", () => {
      body.querySelectorAll("tr").forEach((r) => r.classList.remove("selected"));
      tr.classList.add("selected");
      showFindingDetail(row);
    });
    tr.addEventListener("dblclick", () => {
      showFindingDetail(row);
      applyCribFromSelected(true).catch((e) => log(`Crib error: ${e.message}`));
    });
    body.appendChild(tr);
  });
}

async function fetchFindings() {
  if (!state.session) return;

  const params = new URLSearchParams({
    session: state.session,
    offset: String(state.offset),
    limit: String(state.limit),
  });

  const kind = $("filter-kind").value;
  const confidence = $("filter-confidence").value;
  const round = $("filter-round").value;
  const q = $("filter-q").value.trim();

  if (kind) params.set("kind", kind);
  if (confidence) params.set("confidence", confidence);
  if (round !== "") params.set("round", round);
  if (q) params.set("q", q);

  const res = await fetch(`/api/findings?${params}`);
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Failed to load findings");

  state.total = data.total;
  if (data.config) state.lastConfig = data.config;
  renderFindings(data.rows);
  renderSummary(data);

  const page = Math.floor(state.offset / state.limit) + 1;
  const pages = Math.max(1, Math.ceil(state.total / state.limit));
  $("page-info").textContent = `${page} / ${pages} (${state.total} rows)`;
  $("page-prev").disabled = state.offset <= 0;
  $("page-next").disabled = state.offset + state.limit >= state.total;
}

function populateFiltersFromRun(data) {
  const kindSelect = $("filter-kind");
  const roundSelect = $("filter-round");
  const kinds = new Set();
  (data.preview || []).forEach((r) => kinds.add(r.kind));
  kindSelect.innerHTML = '<option value="">All kinds</option>';
  [...kinds].sort().forEach((k) => {
    const opt = document.createElement("option");
    opt.value = k;
    opt.textContent = k;
    kindSelect.appendChild(opt);
  });

  roundSelect.innerHTML = '<option value="">All rounds</option>';
  (data.summary?.rounds || []).forEach((r) => {
    const opt = document.createElement("option");
    opt.value = String(r.round);
    opt.textContent = `Round ${r.round}`;
    roundSelect.appendChild(opt);
  });
}

async function handleRunResponse(data) {
  state.session = data.session;
  state.offset = 0;
  state.lastConfig = data.config;

  if (data.actionable_kinds) {
    state.actionableKinds = new Set(data.actionable_kinds);
  }

  if (data.route) {
    state.routedIndex = data.route.hypothesis_index;
    setInferred(data.route);
  }

  log(`Done: ${data.findings_count} findings, ${data.validated_count} validated, converged=${data.summary?.converged}`);
  const stop = data.summary?.stop;
  if (stop) {
    log(`STOP: ${stop.headline}`);
    (stop.suggestions || []).forEach((s) => log(`  → [${s.priority}] ${s.action}`));
  }

  populateFiltersFromRun(data);
  renderSummary(data);
  if (data.plaintext_view) {
    renderPlaintextView(data.plaintext_view);
  } else {
    await fetchPlaintextView();
  }
  await fetchFindings();
  updateBruteHint(data.summary?.stop);
  if (!data.summary?.stop) setStatus("ok", "READY");
}

function renderPlaintextView(view) {
  state.plaintextView = view;
  const cov = $("plaintext-coverage");
  const box = $("plaintext-messages");
  const fullEl = $("plaintext-full-decrypt");

  if (!view || !view.messages?.length) {
    cov.textContent = "No assignments yet";
    box.innerHTML = '<p class="classify-status">Ground pt pins or run shared-keystream cribs to fill positions.</p>';
    fullEl.classList.add("hidden");
    return;
  }

  const c = view.coverage || {};
  cov.textContent = `${c.known ?? 0} / ${c.total ?? 0} positions (${Math.round((c.ratio ?? 0) * 100)}%)`;

  box.innerHTML = "";
  view.messages.forEach((msg) => {
    const block = document.createElement("div");
    block.className = "pt-msg-block";
    block.innerHTML = `
      <div class="pt-msg-head">
        <span class="pt-msg-label">${msg.label}</span>
        <span class="pt-msg-meta">${msg.known}/${msg.length} known</span>
      </div>
      <pre class="pt-msg-text">${msg.text || "—"}</pre>
    `;
    box.appendChild(block);
  });

  if (view.full_decrypt?.text) {
    fullEl.classList.remove("hidden");
    fullEl.innerHTML = `
      <div class="pt-msg-head">
        <span class="pt-msg-label">Full decrypt (verified seed: ${view.full_decrypt.seed})</span>
      </div>
      <pre class="pt-msg-text pt-full">${view.full_decrypt.text}</pre>
    `;
  } else {
    fullEl.classList.add("hidden");
    fullEl.innerHTML = "";
  }
}

async function fetchPlaintextView() {
  if (!state.session) return;
  const res = await fetch(`/api/plaintext-view?session=${encodeURIComponent(state.session)}`);
  const data = await res.json();
  if (res.ok) renderPlaintextView(data.plaintext_view);
}

function updateBruteHint(stop) {
  const el = $("brute-status");
  if (!stop) {
    el.textContent = "Optional — try after route → run";
    return;
  }
  if (stop.status === "needs_information") {
    el.textContent = "Recommended — loop needs more key / plaintext information";
    el.classList.add("brute-warn");
  } else if (stop.status === "complete") {
    el.textContent = "Optional — verify or explore alternate keys";
    el.classList.remove("brute-warn");
  } else {
    el.textContent = "Resolve stop status first, then brute if needed";
    el.classList.remove("brute-warn");
  }
}

async function runBruteForce() {
  const ct = getCiphertext();
  if (!ct) {
    log("Brute: paste alphabetic ciphertext first");
    return;
  }
  $("brute-status").textContent = "Running…";
  setStatus("run", "BRUTING");
  try {
    const res = await fetch("/api/brute-force", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session: state.session,
        classification: state.classification,
        ciphertext: ct,
        lane: $("brute-lane").value,
        seed_length: Number($("brute-seed-length").value) || 3,
        top_n: Number($("brute-top-n").value) || 8,
        gak_seed_min: Number($("brute-gak-min").value) || 0,
        gak_seed_max: Number($("brute-gak-max").value) || 500,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Brute failed");
    state.lastBrute = data;
    renderBruteResults(data);
    log(`Brute [${data.lane}]: ${data.count} candidate(s)`);
    $("brute-status").textContent = `${data.lane} · ${data.count} hit(s)`;
    setStatus("idle", "BRUTE OK");
  } catch (err) {
    log(`Brute error: ${err.message}`);
    $("brute-status").textContent = "Error";
    setStatus("err", "ERROR");
  }
}

function renderBruteResults(data) {
  const notes = $("brute-notes");
  const box = $("brute-results");
  notes.textContent = data.notes || "";
  box.innerHTML = "";
  if (!data.candidates?.length) {
    box.innerHTML = '<p class="classify-status">No survivors — widen range or add plaintext trial.</p>';
    return;
  }
  data.candidates.forEach((c, idx) => {
    const card = document.createElement("div");
    card.className = "brute-card";
    const preview = c.plaintext_preview || c.plaintext || "";
    card.innerHTML = `
      <div class="brute-card-head">
        <span class="brute-label">${c.label}</span>
        <span class="brute-score">${c.score != null ? `score ${c.score}` : c.detail || ""}</span>
      </div>
      ${preview ? `<pre class="brute-preview">${preview}</pre>` : ""}
      <button type="button" class="btn btn-ghost brute-apply" data-idx="${idx}">Apply → re-run loop</button>
    `;
    card.querySelector(".brute-apply").addEventListener("click", () => applyBruteCandidate(idx));
    box.appendChild(card);
  });
}

async function applyBruteCandidate(index) {
  const c = state.lastBrute?.candidates?.[index];
  if (!c) return;
  if (state.routedIndex == null) {
    log("Apply brute: route a hypothesis first");
    return;
  }
  log(`Apply brute candidate: ${c.label}`);
  setStatus("run", "RUNNING");
  let pins = [];
  try { pins = parsePins(); } catch { pins = []; }
  const body = {
    session: state.session,
    classification: state.classification,
    hypothesis_index: state.routedIndex,
    ciphertext: getCiphertext(),
    pins,
    max_rounds: Number($("max-rounds").value) || 10,
  };
  if (c.hypothesis_patch) body.hypothesis_override = c.hypothesis_patch;
  if (c.plaintext) body.plaintext_trial = c.plaintext;
  try {
    const res = await fetch("/api/route-run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Re-run failed");
    await handleRunResponse(data);
  } catch (err) {
    log(`ERROR: ${err.message}`);
    setStatus("err", "ERROR");
  }
}

function canRouteRun(h) {
  if (!h) return false;
  if (h.propagator && h.propagator !== "none") return true;
  if (h.dash_mode === "noita") return true;
  if (h.dash_mode === "fingerprinted" && h.dataset_slug) return true;
  return false;
}

async function routeAndRun(hypothesisIndex) {
  if (!state.classification?.hypotheses?.[hypothesisIndex]) {
    log("Route → run: classify first");
    return;
  }

  const h = state.classification.hypotheses[hypothesisIndex];
  if (!canRouteRun(h)) {
    log(`Route skipped: ${h.label} has no constraint propagator (decode or corpus tool only)`);
    return;
  }

  setStatus("run", "RUNNING");
  log(`Route → run: ${h.label}`);

  let pins = [];
  try { pins = parsePins(); } catch (err) {
    log(`ERROR: invalid crib pins JSON — ${err.message}`);
    setStatus("err", "ERROR");
    return;
  }

  try {
    const res = await fetch("/api/route-run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        session: state.session,
        classification: state.classification,
        hypothesis_index: hypothesisIndex,
        ciphertext: getCiphertext(),
        pins,
        max_rounds: Number($("max-rounds").value) || 10,
      }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Route → run failed");
    await handleRunResponse(data);
  } catch (err) {
    log(`ERROR: ${err.message}`);
    setStatus("err", "ERROR");
  }
}

function renderClassification(data) {
  state.classification = data;
  const profileEl = $("classify-profile");
  const hypsEl = $("classify-hypotheses");
  const statusEl = $("classify-status");

  if (!data || !data.hypotheses?.length) {
    profileEl.innerHTML = "";
    hypsEl.innerHTML = '<p class="classify-status">No hypotheses — paste ciphertext and identify.</p>';
    statusEl.textContent = "No signal";
    resetInferred();
    return;
  }

  const p = data.profile || {};
  const chips = [];
  if (p.symbol_class) chips.push(`class: ${p.symbol_class}`);
  if (p.index_of_coincidence != null) chips.push(`IC: ${p.index_of_coincidence}`);
  if (p.shannon_entropy_bits != null) chips.push(`H: ${p.shannon_entropy_bits}`);
  if (p.ic_band) chips.push(`band: ${p.ic_band}`);
  if (p.deck_size) chips.push(`deck hint: ${p.deck_size}`);
  if (p.num_messages) chips.push(`msgs: ${p.num_messages}`);
  if (p.kasiski_periods?.length) chips.push(`kasiski: ${p.kasiski_periods.join(",")}`);

  profileEl.innerHTML = chips.map((c) => `<span class="classify-chip">${c}</span>`).join("");
  statusEl.textContent = data.top
    ? `${data.hypotheses.length} hypotheses · top: ${data.top.label} (${Math.round(data.top.confidence * 100)}%)`
    : "Classified";

  hypsEl.innerHTML = "";
  data.hypotheses.forEach((h, idx) => {
    const card = document.createElement("div");
    const isRouted = state.routedIndex === idx;
    card.className = `hyp-card${idx === 0 ? " top" : ""}${isRouted ? " routed" : ""}`;
    const reasons = (h.reasoning || []).map((r) => `<li>${r}</li>`).join("");
    const actions = (h.actions || []).map((a) => `<li>${a}</li>`).join("");
    const prop = h.dash_propagator || h.propagator;
    const meta = [
      prop && prop !== "none" ? `prop: ${prop.replace(/_/g, " ")}` : "prop: —",
      h.deck_size ? `deck: ${h.deck_size}` : "deck: unknown",
      h.dash_mode && h.dash_mode !== "custom" ? `mode: ${h.dash_mode}` : null,
    ].filter(Boolean).join(" · ");

    let btnHtml = "";
    if (canRouteRun(h)) {
      btnHtml = `<button type="button" class="btn btn-primary hyp-route" data-idx="${idx}">Route → run</button>`;
    } else {
      btnHtml = `<span class="hyp-no-run">No propagator — manual decode / corpus only</span>`;
    }

    card.innerHTML = `
      <div class="hyp-card-header">
        <span class="hyp-label">${h.label}</span>
        <span class="hyp-conf">${Math.round(h.confidence * 100)}%</span>
      </div>
      <p class="hyp-meta">${meta}</p>
      <ul class="hyp-reason">${reasons}</ul>
      <ul class="hyp-actions">${actions}</ul>
      ${btnHtml}
    `;
    const btn = card.querySelector(".hyp-route");
    if (btn) btn.addEventListener("click", () => routeAndRun(idx));
    hypsEl.appendChild(card);
  });
}

async function runClassification() {
  const ct = getCiphertext();
  if (!ct) {
    log("Identify: paste ciphertext in Source first");
    $("classify-status").textContent = "Ciphertext required";
    return;
  }

  resetInferred();
  $("classify-status").textContent = "Classifying…";
  setStatus("run", "SCANNING");

  try {
    const res = await fetch("/api/classify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ciphertext: ct }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Classify failed");
    renderClassification(data);
    log(`Classification: ${data.top?.label || "done"} (${data.hypotheses?.length || 0} hypotheses)`);
    log("Pick a hypothesis in Classification and click Route → run.");
    setStatus("idle", "IDENTIFIED");
  } catch (err) {
    $("classify-status").textContent = "Error";
    log(`Classification error: ${err.message}`);
    setStatus("err", "ERROR");
  }
}

function bindEvents() {
  $("classify-btn").addEventListener("click", runClassification);

  $("ciphertext").addEventListener("input", () => {
    if (state.classification) {
      state.classification = null;
      state.routedIndex = null;
      resetInferred();
      $("classify-profile").innerHTML = "";
      $("classify-hypotheses").innerHTML = "";
      $("classify-status").textContent = "Ciphertext changed — identify again";
    }
  });

  $("apply-crib-btn").addEventListener("click", () => {
    applyCribFromSelected(true).catch((e) => log(`Crib error: ${e.message}`));
  });
  $("crib-anchor-pt").addEventListener("change", () => {
    if (state.selectedFinding) showFindingDetail(state.selectedFinding);
  });

  ["filter-kind", "filter-confidence", "filter-round"].forEach((id) => {
    $(id).addEventListener("change", () => {
      state.offset = 0;
      fetchFindings().catch((e) => log(e.message));
    });
  });

  let searchTimer;
  $("filter-q").addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.offset = 0;
      fetchFindings().catch((e) => log(e.message));
    }, 300);
  });

  $("page-prev").addEventListener("click", () => {
    state.offset = Math.max(0, state.offset - state.limit);
    fetchFindings().catch((e) => log(e.message));
  });

  $("page-next").addEventListener("click", () => {
    state.offset += state.limit;
    fetchFindings().catch((e) => log(e.message));
  });

  $("brute-run-btn").addEventListener("click", runBruteForce);
}

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  resetInferred();
  setStatus("idle", "IDLE");
  log("Constraints Dash ready. Paste ciphertext → Identify → Route → run in Classification.");
});
