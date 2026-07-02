/* H3X Constraints Dash — identify → route → prepare → run */

const state = {
  session: null,
  offset: 0,
  limit: 100,
  total: 0,
  classification: null,
  routedIndex: null,
  lastConfig: null,
  selectedFinding: null,
  lastPrepare: null,
  lastError: null,
  actionableKinds: new Set(["pt_difference", "equality", "keystream_pin", "assignment", "stream_pin"]),
};

const $ = (id) => document.getElementById(id);

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function verboseWrite(level, message, detail) {
  const el = $("verbose-log");
  if (!el) return;
  const ts = new Date().toISOString().slice(11, 19);
  const cls = level === "error" ? "v-err" : level === "warn" ? "v-warn" : level === "ok" ? "v-ok" : "v-dim";
  let line = `[${ts}] <span class="${cls}">${escapeHtml(message)}</span>`;
  if (detail !== undefined) {
    const text = typeof detail === "string" ? detail : JSON.stringify(detail, null, 2);
    line += `\n<span class="v-dim">${escapeHtml(text)}</span>`;
  }
  el.innerHTML += `${line}\n`;
  if ($("verbose-autoscroll")?.checked) {
    el.scrollTop = el.scrollHeight;
  }
  if (level === "error") state.lastError = message;
}

async function apiFetch(path, options = {}) {
  const method = options.method || "GET";
  verboseWrite("info", `${method} ${path}`);
  try {
    const res = await fetch(path, options);
    const text = await res.text();
    let data;
    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = { raw: text };
    }
    if (!res.ok) {
      const errMsg = data.error || res.statusText || `HTTP ${res.status}`;
      verboseWrite("error", `${method} ${path} → ${res.status}`, errMsg);
      throw new Error(errMsg);
    }
    verboseWrite("ok", `${method} ${path} → ${res.status}`);
    return data;
  } catch (err) {
    if (!(err instanceof Error) || !err.message) {
      verboseWrite("error", `${method} ${path}`, String(err));
    }
    throw err;
  }
}

function clearVerbose() {
  const el = $("verbose-log");
  if (el) el.textContent = "Cleared.\n";
  state.lastError = null;
}

function log(msg) {
  const el = $("log");
  if (!el) return;
  const ts = new Date().toISOString().slice(11, 19);
  el.textContent += `[${ts}] ${msg}\n`;
  el.scrollTop = el.scrollHeight;
}

function setStatus(kind, text) {
  const pill = $("status-pill");
  if (!pill) return;
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
  if (!field) {
    verboseWrite("warn", "Crib pins field (#pins-json) not found in page");
    return;
  }
  field.value = JSON.stringify(pins, null, 2);
  field.classList.add("pins-json-highlight");
  setTimeout(() => field.classList.remove("pins-json-highlight"), 1800);
  if (hintText) {
    const hint = $("pins-json-hint");
    if (hint) {
      hint.textContent = hintText;
      hint.classList.add("flash");
      setTimeout(() => hint.classList.remove("flash"), 2500);
    }
  }
  field.scrollIntoView({ behavior: "smooth", block: "center" });
}

async function fetchCribHint(finding, anchorPt) {
  let existingPins = [];
  try { existingPins = parsePins(); } catch { existingPins = []; }

  const res = await apiFetch("/api/crib-from-finding", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      finding,
      deck_size: state.lastConfig?.deck_size ?? 83,
      anchor_pt: anchorPt,
      existing_pins: existingPins,
    }),
  });
  return res;
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
      <span class="sugg-priority ${escapeHtml(s.priority)}">${escapeHtml(s.priority)}</span>
      <span class="sugg-action">${escapeHtml(s.action)}</span>
      ${s.detail ? `<span class="sugg-meta">${escapeHtml(s.detail)}</span>` : ""}
      ${s.example ? `<span class="sugg-meta sugg-example">e.g. ${escapeHtml(s.example)}</span>` : ""}
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
      <td>${escapeHtml(row.round ?? "—")}</td>
      <td class="kind">${escapeHtml(row.kind)}</td>
      <td><span class="${confClass}">${escapeHtml(row.confidence)}</span></td>
      <td>${escapeHtml(row.source)}</td>
      <td class="data-preview">${escapeHtml(JSON.stringify(row.data || {}))}</td>
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

  const res = await apiFetch(`/api/findings?${params}`);
  const data = res;

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

function renderPrepare(prepare) {
  state.lastPrepare = prepare;
  const stepsEl = $("prepare-steps");
  const notesEl = $("prepare-notes");
  const depthEl = $("prepare-depth");
  const cribsEl = $("prepare-cribs");
  const statusEl = $("prepare-status");

  if (!stepsEl) {
    verboseWrite("warn", "Prepare panel missing from page — refresh browser cache");
    return;
  }

  if (!prepare) {
    stepsEl.innerHTML = '<p class="classify-status">Route a hypothesis to run prepare.</p>';
    if (notesEl) notesEl.textContent = "";
    if (depthEl) depthEl.classList.add("hidden");
    if (cribsEl) cribsEl.classList.add("hidden");
    if (statusEl) statusEl.textContent = "Waiting for route";
    return;
  }

  if (statusEl) {
    statusEl.textContent = prepare.peeled
      ? "Preflight complete · encoding peeled"
      : `Preflight complete · ${prepare.pins?.length ?? 0} pin(s)`;
  }

  stepsEl.innerHTML = "";
  (prepare.steps || []).forEach((step) => {
    const card = document.createElement("div");
    card.className = "prepare-step";
    const skipped = step.skipped ? "skipped" : step.error ? "error" : step.applied ? "ok" : "info";
    card.classList.add(`prepare-${skipped}`);
    const stepName = typeof step.name === "string" ? step.name : "step";
    const detailRaw = step.applied
      || step.reason
      || (typeof step.notes === "string" ? step.notes : "")
      || step.error
      || step.encoding
      || "";
    card.innerHTML = `
      <span class="prepare-step-num">${escapeHtml(step.step ?? "?")}</span>
      <span class="prepare-step-name">${escapeHtml(stepName.replace(/_/g, " "))}</span>
      <span class="prepare-step-detail">${escapeHtml(detailRaw)}</span>
    `;
    stepsEl.appendChild(card);
  });

  if (notesEl) notesEl.textContent = (prepare.notes || []).join(" · ");

  const depth = prepare.depth_preview;
  if (depthEl && depth && depth.top_crib_drag_depths?.length) {
    depthEl.classList.remove("hidden");
    depthEl.innerHTML = `
      <p class="prepare-subhead">Depth map · ${escapeHtml(depth.num_messages)} msgs · header ${depth.header_detected ? "✓" : "—"}</p>
      <p class="prepare-meta">Crib-drag depths: ${escapeHtml(depth.top_crib_drag_depths.slice(0, 10).join(", "))}</p>
    `;
  } else if (depthEl) {
    depthEl.classList.add("hidden");
    depthEl.innerHTML = "";
  }

  const cribs = prepare.crib_candidates || [];
  if (cribsEl && cribs.length) {
    cribsEl.classList.remove("hidden");
    cribsEl.innerHTML = '<p class="prepare-subhead">Dictionary cribs</p>';
    cribs.slice(0, 5).forEach((c, idx) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn btn-ghost prepare-crib-btn";
      btn.textContent = `${c.word}@${c.offset} (${c.score})`;
      btn.addEventListener("click", () => {
        let merged = c.pins;
        try { merged = mergePins(parsePins(), c.pins); } catch { /* use c.pins */ }
        setPinsJson(merged, c.detail);
        log(`Prepare: applied crib ${c.word}@${c.offset}`);
      });
      cribsEl.appendChild(btn);
    });
  } else if (cribsEl) {
    cribsEl.classList.add("hidden");
    cribsEl.innerHTML = "";
  }

  if (prepare.pins?.length) {
    let merged = prepare.pins;
    try { merged = mergePins(parsePins(), prepare.pins); } catch { /* use prepare pins */ }
    setPinsJson(merged, "Preflight pins merged into crib JSON");
  }
}

async function handleRunResponse(data) {
  state.session = data.session;
  state.offset = 0;
  state.lastConfig = data.config;

  if (data.route) {
    state.routedIndex = data.route.hypothesis_index;
    setInferred(data.route);
  }

  if (data.prepare) {
    renderPrepare(data.prepare);
    verboseWrite("ok", "Prepare complete", data.prepare.notes);
    log(`Prepare: ${data.prepare.notes?.join("; ") || "done"}`);
  }

  if (data.reclassified && data.classification) {
    state.classification = data.classification;
    renderClassification(data.classification);
    verboseWrite("info", "Re-classified after encoding peel");
    if (data.prepare?.ciphertext) {
      const ctField = $("ciphertext");
      if (ctField) ctField.value = data.prepare.ciphertext;
    }
  }

  if (data.actionable_kinds) {
    state.actionableKinds = new Set(data.actionable_kinds);
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
    try {
      await fetchPlaintextView();
    } catch (err) {
      verboseWrite("warn", "Plaintext view fetch skipped", err.message);
    }
  }
  try {
    await fetchFindings();
  } catch (err) {
    verboseWrite("error", "Findings fetch failed", err.message);
    throw err;
  }
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
      <pre class="pt-msg-text">${escapeHtml(msg.text || "—")}</pre>
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
  const res = await apiFetch(`/api/plaintext-view?session=${encodeURIComponent(state.session)}`);
  renderPlaintextView(res.plaintext_view);
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
    const data = await apiFetch("/api/brute-force", {
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
        <span class="brute-label">${escapeHtml(c.label)}</span>
        <span class="brute-score">${c.score != null ? `score ${escapeHtml(c.score)}` : escapeHtml(c.detail || "")}</span>
      </div>
      ${preview ? `<pre class="brute-preview">${escapeHtml(preview)}</pre>` : ""}
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
    const data = await apiFetch("/api/route-run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    await handleRunResponse(data);
  } catch (err) {
    log(`ERROR: ${err.message}`);
    verboseWrite("error", "Apply brute re-run failed", err.message);
    setStatus("err", "ERROR");
  }
}

function canRouteRun(h) {
  if (!h) return false;
  if (h.needs_conversion) return true;
  if (h.propagator && h.propagator !== "none") return true;
  if (h.dash_propagator && h.dash_propagator !== "none") return true;
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

  setStatus("run", "PREPARING");
  log(`Route → prepare → run: ${h.label}`);

  let pins = [];
  try { pins = parsePins(); } catch (err) {
    log(`ERROR: invalid crib pins JSON — ${err.message}`);
    setStatus("err", "ERROR");
    return;
  }

  try {
    const data = await apiFetch("/api/route-run", {
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
    await handleRunResponse(data);
  } catch (err) {
    log(`ERROR: ${err.message}`);
    verboseWrite("error", "Route → prepare → run failed", err.message);
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
  if (p.scan_mode) chips.push("full scan");
  if (p.has_more_layers) chips.push("peel encoding first");
  if (p.peel_first) chips.push(`peel: ${p.peel_first}`);
  if (p.index_of_coincidence != null) chips.push(`IC: ${p.index_of_coincidence}`);
  if (p.ic_band) chips.push(`band: ${p.ic_band}`);
  if (p.coset_lift != null) chips.push(`coset lift: ${p.coset_lift}`);
  if (p.kasiski_period != null) chips.push(`kasiski: ${p.kasiski_period}`);
  if (p.shannon_entropy_bits != null) chips.push(`H: ${p.shannon_entropy_bits}`);
  if (p.deck_size) chips.push(`deck: ${p.deck_size}`);
  if (data.num_messages) chips.push(`msgs: ${data.num_messages}`);

  if (data.has_more && p.inner_preview) {
    chips.push(`inner: ${p.inner_preview.slice(0, 40)}…`);
  }

  profileEl.innerHTML = chips.map((c) => `<span class="classify-chip">${escapeHtml(c)}</span>`).join("");
  statusEl.textContent = data.top
    ? `Full scan · ${data.hypotheses.length} hits · top: ${data.top.label} (${Math.round(data.top.confidence * 100)}%)`
    : "Classified";

  hypsEl.innerHTML = "";
  data.hypotheses.forEach((h, idx) => {
    const card = document.createElement("div");
    const isRouted = state.routedIndex === idx;
    card.className = `hyp-card${idx === 0 ? " top" : ""}${isRouted ? " routed" : ""}`;
    const reasons = (h.reasoning || []).map((r) => `<li>${escapeHtml(r)}</li>`).join("");
    const actions = (h.actions || []).map((a) => `<li>${escapeHtml(a)}</li>`).join("");
    const prop = h.dash_propagator || h.propagator;
    const meta = [
      prop && prop !== "none" ? `prop: ${prop.replace(/_/g, " ")}` : "prop: —",
      h.deck_size ? `deck: ${h.deck_size}` : "deck: unknown",
      h.dash_mode && h.dash_mode !== "custom" ? `mode: ${h.dash_mode}` : null,
    ].filter(Boolean).join(" · ");

    const metrics = h.metrics || {};
    const metricLine = Object.entries(metrics)
      .slice(0, 4)
      .map(([k, v]) => `${escapeHtml(k)}: ${escapeHtml(v)}`)
      .join(" · ");

    let btnHtml = "";
    if (canRouteRun(h)) {
      const label = h.needs_conversion ? "Peel → prepare → run" : "Route → prepare → run";
      btnHtml = `<button type="button" class="btn btn-primary hyp-route" data-idx="${idx}">${label}</button>`;
      if (h.needs_conversion) {
        btnHtml += `<span class="hyp-no-run">encoding layer — will decode and re-scan</span>`;
      }
    } else {
      btnHtml = `<span class="hyp-no-run">No propagator — manual decode / corpus only</span>`;
    }

    card.innerHTML = `
      <div class="hyp-card-header">
        <span class="hyp-label">${escapeHtml(h.label)}</span>
        <span class="hyp-conf">${Math.round(h.confidence * 100)}%</span>
      </div>
      <p class="hyp-meta">${escapeHtml(meta)}</p>
      ${metricLine ? `<p class="hyp-meta hyp-metrics">${metricLine}</p>` : ""}
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
    const data = await apiFetch("/api/classify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ciphertext: ct }),
    });
    renderClassification(data);
    verboseWrite("ok", "Classification complete", { top: data.top?.label, count: data.hypotheses?.length });
    log(`Classification: ${data.top?.label || "done"} (${data.hypotheses?.length || 0} hypotheses)`);
    log("Pick a hypothesis in Classification and click Route → prepare → run.");
    setStatus("idle", "IDENTIFIED");
  } catch (err) {
    $("classify-status").textContent = "Error";
    log(`Classification error: ${err.message}`);
    verboseWrite("error", "Classification failed", err.message);
    setStatus("err", "ERROR");
  }
}

function bindEvents() {
  $("classify-btn")?.addEventListener("click", runClassification);

  $("ciphertext")?.addEventListener("input", () => {
    if (state.classification) {
      state.classification = null;
      state.routedIndex = null;
      resetInferred();
      $("classify-profile").innerHTML = "";
      $("classify-hypotheses").innerHTML = "";
      $("classify-status").textContent = "Ciphertext changed — identify again";
    }
  });

  $("apply-crib-btn")?.addEventListener("click", () => {
    applyCribFromSelected(true).catch((e) => log(`Crib error: ${e.message}`));
  });
  $("crib-anchor-pt")?.addEventListener("change", () => {
    if (state.selectedFinding) showFindingDetail(state.selectedFinding);
  });

  ["filter-kind", "filter-confidence", "filter-round"].forEach((id) => {
    $(id)?.addEventListener("change", () => {
      state.offset = 0;
      fetchFindings().catch((e) => log(e.message));
    });
  });

  let searchTimer;
  $("filter-q")?.addEventListener("input", () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.offset = 0;
      fetchFindings().catch((e) => log(e.message));
    }, 300);
  });

  $("page-prev")?.addEventListener("click", () => {
    state.offset = Math.max(0, state.offset - state.limit);
    fetchFindings().catch((e) => log(e.message));
  });

  $("page-next")?.addEventListener("click", () => {
    state.offset += state.limit;
    fetchFindings().catch((e) => log(e.message));
  });

  $("brute-run-btn")?.addEventListener("click", runBruteForce);
  $("verbose-clear")?.addEventListener("click", clearVerbose);
}

document.addEventListener("DOMContentLoaded", () => {
  window.addEventListener("error", (event) => {
    verboseWrite("error", "JS error", `${event.message} @ ${event.filename}:${event.lineno}`);
  });
  window.addEventListener("unhandledrejection", (event) => {
    verboseWrite("error", "Unhandled promise", event.reason?.message || String(event.reason));
  });

  bindEvents();
  resetInferred();
  setStatus("idle", "IDLE");
  log("Constraints Dash ready. Paste ciphertext → Identify → Route → prepare → run.");
  verboseWrite("info", "Constraints Dash ready");

  apiFetch("/api/health")
    .then((data) => verboseWrite("ok", "API health", data))
    .catch((err) => verboseWrite("error", "API health check failed", err.message));
});
