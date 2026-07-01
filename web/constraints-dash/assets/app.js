/* H3X Constraints Dash — in-browser findings explorer */

const state = {
  session: null,
  offset: 0,
  limit: 100,
  total: 0,
  sources: null,
  kinds: new Set(),
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

function showSourcePanel(mode) {
  ["preset", "fingerprinted", "custom"].forEach((m) => {
    $(`panel-${m}`)?.classList.toggle("hidden", m !== mode);
  });
  $("panel-noita")?.classList.toggle("hidden", mode !== "noita");
}

function updatePropagatorFields() {
  const prop = $("propagator").value;
  $("stream-fields").classList.toggle("hidden", prop !== "stream_extension");
  $("gak-fields").classList.toggle("hidden", prop !== "dynamic_perm");
  $("deck-fields").classList.toggle("hidden", prop !== "shared_keystream");
}

function parsePins() {
  const raw = $("pins-json").value.trim();
  if (!raw) return [];
  return JSON.parse(raw);
}

function buildPayload() {
  const mode = $("source-mode").value;
  const payload = {
    session: state.session,
    max_rounds: Number($("max-rounds").value) || 10,
    pins: parsePins(),
  };

  if (mode === "preset") {
    payload.source = "preset";
    payload.preset_slug = $("preset-slug").value;
    return payload;
  }

  if (mode === "fingerprinted") {
    payload.source = "fingerprinted";
    payload.dataset_slug = $("fp-slug").value;
    const rid = $("fp-record-id").value.trim();
    if (rid) payload.record_id = rid;
    return payload;
  }

  if (mode === "noita") {
    payload.source = "noita";
    return payload;
  }

  payload.source = "custom";
  payload.propagator = $("propagator").value;
  payload.ciphertext = $("ciphertext").value.trim();

  const pt = $("plaintext").value.trim();
  if (pt) payload.plaintext = pt;

  if (payload.propagator === "stream_extension") {
    payload.hypothesis = {
      family: "autokey",
      variant: "standard",
      extension: $("extension").value,
      seed: $("seed").value.trim(),
      seed_length: Number($("seed-length").value) || 3,
    };
  } else if (payload.propagator === "dynamic_perm") {
    const center = Number($("prng-seed").value) || 42;
    payload.hypothesis = { mode: $("gak-mode").value, prng_seed: center };
    payload.seed_candidates = [center - 1, center, center + 1];
  } else {
    payload.deck_size = Number($("deck-size").value) || 83;
    payload.hypothesis = { combiner: "add" };
  }

  return payload;
}

function renderSummary(data) {
  const s = data.summary || {};
  $("stat-corpus").textContent = data.config?.slug || "—";
  $("stat-prop").textContent = data.config?.propagator || s.propagator || "—";
  $("stat-findings").textContent = data.findings_count ?? data.total ?? "—";
  $("stat-validated").textContent = s.final_validated_count ?? data.validated_count ?? "—";
  $("stat-conflicts").textContent = s.remaining_conflicts ?? "—";
  $("stat-converged").textContent = s.converged ? "yes" : "no";

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
      $("finding-detail").textContent = JSON.stringify(row, null, 2);
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
  renderFindings(data.rows);
  renderSummary(data);

  const page = Math.floor(state.offset / state.limit) + 1;
  const pages = Math.max(1, Math.ceil(state.total / state.limit));
  $("page-info").textContent = `${page} / ${pages} (${state.total} rows)`;
  $("page-prev").disabled = state.offset <= 0;
  $("page-next").disabled = state.offset + state.limit >= state.total;
}

async function runAnalysis() {
  setStatus("run", "RUNNING");
  log("Starting validated propagation loop…");

  try {
    const payload = buildPayload();
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Analysis failed");

    state.session = data.session;
    state.offset = 0;

    log(`Done: ${data.findings_count} findings, ${data.validated_count} validated, converged=${data.summary?.converged}`);

    // Populate kind / round filters from preview + summary
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

    renderSummary(data);
    await fetchFindings();
    setStatus("ok", "READY");
  } catch (err) {
    log(`ERROR: ${err.message}`);
    setStatus("err", "ERROR");
  }
}

async function loadSources() {
  const res = await fetch("/api/sources");
  const data = await res.json();
  state.sources = data;

  const presetSelect = $("preset-slug");
  presetSelect.innerHTML = "";
  (data.presets || []).forEach((p) => {
    const opt = document.createElement("option");
    opt.value = p.slug;
    opt.textContent = `${p.slug} (${p.propagator})`;
    presetSelect.appendChild(opt);
  });

  const fpSelect = $("fp-slug");
  fpSelect.innerHTML = "";
  (data.fingerprinted || []).forEach((p) => {
    const opt = document.createElement("option");
    opt.value = p.slug;
    opt.textContent = `${p.slug} · ${p.propagator}`;
    fpSelect.appendChild(opt);
  });

  log(`Loaded ${data.presets?.length || 0} presets, ${data.fingerprinted?.length || 0} fingerprinted datasets.`);
}

function loadAutokeySample() {
  $("source-mode").value = "custom";
  showSourcePanel("custom");
  $("propagator").value = "stream_extension";
  updatePropagatorFields();
  $("ciphertext").value = "Dlc jbmse jtyxe tkk oijym akwf olv ehdj dne.";
  $("plaintext").value = "The quick brown fox jumps over the lazy dog.";
  $("seed").value = "KEY";
  $("seed-length").value = "3";
  log("Loaded autokey-standard-01 sample ciphertext.");
}

function bindEvents() {
  $("source-mode").addEventListener("change", (e) => {
    const mode = e.target.value;
    if (mode === "noita") showSourcePanel("noita");
    else showSourcePanel(mode);
  });

  $("propagator").addEventListener("change", updatePropagatorFields);
  $("run-btn").addEventListener("click", runAnalysis);
  $("load-sample-btn").addEventListener("click", loadAutokeySample);

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
}

document.addEventListener("DOMContentLoaded", async () => {
  bindEvents();
  updatePropagatorFields();
  showSourcePanel("preset");
  await loadSources();
  setStatus("idle", "IDLE");
  log("Constraints Dash ready.");
});
