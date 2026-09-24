"use strict";

const $ = (id) => document.getElementById(id);
const element = (tag, text, className) => {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
};
const percent = (v) => (v * 100).toFixed(1) + "%";
const number = (v) => Number(v).toLocaleString();
const reducedMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

function loadDecisionLog() {
  try {
    const saved = JSON.parse(sessionStorage.getItem("nida_decisions") || "[]");
    return Array.isArray(saved)
      ? saved.filter((entry) => entry && typeof entry.flow_id === "string" &&
          typeof entry.recorded_at === "string" &&
          ["approved_for_follow_up", "dismissed"].includes(entry.decision)).slice(-100)
      : [];
  } catch (_) {
    return [];
  }
}

const state = {
  socket: null,
  paused: false,
  total: 0,
  attacks: 0,
  review: 0,
  anomalies: 0,
  counts: {},
  rows: [],
  history: [],
  selected: null,
  decisionLog: loadDecisionLog(),
  offset: 0,
  presentationMode: (() => {
    try { return localStorage.getItem("nida_mode") || "understand"; }
    catch (_) { return "understand"; }
  })(),
};

function finishLoading() {
  document.documentElement.classList.remove("booting");
  $("loading-screen").setAttribute("aria-hidden", "true");
}

function setTheme(theme) {
  const dark = theme === "dark";
  document.documentElement.dataset.theme = dark ? "dark" : "light";
  $("theme-toggle").setAttribute("aria-pressed", String(dark));
  $("theme-toggle").setAttribute("aria-label", `Switch to ${dark ? "light" : "dark"} mode`);
  $("theme-label").textContent = dark ? "Light" : "Dark";
  $("theme-icon").textContent = dark ? "☀" : "☾";
  document.querySelector('meta[name="theme-color"]').content = dark ? "#10171b" : "#f3f0e8";
  try { localStorage.setItem("nida_theme", dark ? "dark" : "light"); } catch (_) { /* Storage may be blocked. */ }
}

async function getJSON(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.detail || "HTTP " + response.status);
  }
  return response.json();
}

function status(message, dotClass = "muted") {
  $("connection").textContent = message;
  $("connection-dot").className = "status-dot " + dotClass;
}

function error(message) {
  const banner = $("error");
  banner.hidden = !message;
  banner.textContent = message || "";
}

function connect() {
  if (state.socket) {
    state.socket.onclose = null;
    state.socket.close();
  }
  const protocol = location.protocol === "https:" ? "wss:" : "ws:";
  const speed = $("speed").value;
  const category = $("scenario").value;
  const url = `${protocol}//${location.host}/ws/stream?interval=${speed}&category=${category}&offset=${state.offset}`;
  status("Connecting…", "muted");
  const ws = new WebSocket(url);
  state.socket = ws;

  ws.onopen = () => status("Replaying benchmark", "live");
  ws.onmessage = (event) => {
    try {
      const row = JSON.parse(event.data);
      if (row.error) {
        status("Replay unavailable", "muted");
        error(row.error);
        finishLoading();
        return;
      }
      handleRow(row);
    } catch (err) {
      console.error("Malformed message from replay stream", err);
    }
  };
  ws.onclose = (event) => {
    if (state.paused) {
      status("Replay paused", "muted");
      return;
    }
    if (event.code === 1013) {
      status("Server busy", "muted");
      error("Maximum concurrent stream limit reached on server. Try again shortly.");
      finishLoading();
      return;
    }
    status("Disconnected · retrying", "muted");
    setTimeout(() => {
      if (!state.paused) connect();
    }, 1500);
  };
}

function disconnect() {
  if (state.socket) {
    state.socket.onclose = null;
    state.socket.close();
    state.socket = null;
  }
}

function handleRow(row) {
  state.total += 1;
  state.offset = row.next_offset || state.offset + 1;
  if (row.predicted_attack_cat !== "Normal") state.attacks += 1;
  if (row.review_recommended) state.review += 1;
  if (row.is_anomaly_candidate) state.anomalies += 1;
  state.counts[row.predicted_attack_cat] =
    (state.counts[row.predicted_attack_cat] || 0) + 1;
  state.rows.unshift(row);
  if (state.rows.length > 80) state.rows.pop();
  state.history.push(row.risk_score);
  if (state.history.length > 60) state.history.shift();

  $("total").textContent = number(state.total);
  $("attacks").textContent = number(state.review);
  $("attack-rate").textContent =
    percent(state.review / state.total) + " queued for review";
  $("anomalies").textContent = number(state.anomalies);
  $("latency").textContent = row.inference_ms.toFixed(1);

  renderPulse();
  renderDistribution();
  renderRows();

  // If no flow selected yet, select the first one
  if (!state.selected) {
    selectFlow(row);
  }
  finishLoading();
}

function renderRows() {
  const query = $("search").value.trim().toLowerCase();
  const riskFilter = $("risk-filter").value;
  const rows = state.rows.filter((row) => {
    if (riskFilter === "review" && !row.review_recommended) return false;
    if (
      riskFilter !== "review" &&
      Number(riskFilter) > 0 &&
      row.risk_score < Number(riskFilter)
    )
      return false;
    if (!query) return true;
    return (
      row.predicted_attack_cat.toLowerCase().includes(query) ||
      row.protocol.toLowerCase().includes(query) ||
      (row.service && row.service.toLowerCase().includes(query)) ||
      row.true_label.toLowerCase().includes(query) ||
      row.event_id.toLowerCase().includes(query)
    );
  });

  const fragment = document.createDocumentFragment();
  for (const row of rows) {
    const tr = element("tr");
    tr.tabIndex = 0;
    tr.classList.toggle("selected", state.selected?.event_id === row.event_id);
    tr.setAttribute(
      "aria-label",
      row.predicted_attack_cat + ", risk " + row.risk_score + ", inspect flow",
    );

    // Col 1: Flow / Time
    const id = element("td");
    id.append(
      element("span", "#" + row.event_id.replace("replay-", ""), "flow-id"),
    );
    id.append(
      element(
        "span",
        new Date(row.timestamp).toISOString().slice(11, 19) + " UTC",
        "flow-time",
      ),
    );

    // Col 2: Verdict
    const verdict = element("td");
    verdict.append(element("span", row.predicted_attack_cat, "verdict-label"));
    if (row.is_anomaly_candidate) {
      verdict.append(element("span", " · Anomaly", "badge-anomaly-inline"));
    }

    // Col 3: Protocol
    const proto = element("td", (row.protocol || row.proto || "tcp").toUpperCase(), "mono-cell");

    // Col 4: Service
    const service = element("td", row.service || "—", "mono-cell");

    // Col 5: Decision / Queue
    const queue = element(
      "td",
      row.review_recommended ? "Review queue" : "Routine",
      row.review_recommended ? "queue-flag review tech-col" : "queue-flag routine tech-col",
    );

    // Col 6: Risk
    const risk = element("td");
    risk.append(
      element(
        "span",
        row.risk_score + " " + row.risk_level.toUpperCase(),
        "badge " + row.risk_level,
      ),
    );

    // Col 7: Ground Truth
    const truth = element(
      "td",
      row.true_label,
      row.true_label === row.predicted_attack_cat
        ? "truth-match"
        : "truth-mismatch",
    );

    tr.append(id, verdict, proto, service, queue, risk, truth);

    tr.onclick = () => selectFlow(row);
    tr.onkeydown = (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectFlow(row);
      }
    };
    fragment.append(tr);
  }
  $("flows").replaceChildren(fragment);
  const countStr = rows.length + " visible / " + state.rows.length + " retained";
  $("visible-count").textContent = countStr;
  const uCount = $("understand-visible-count");
  if (uCount) uCount.textContent = countStr;

  $("empty").hidden = rows.length > 0;
  $("empty").textContent = state.rows.length
    ? "No flows match these filters."
    : "Waiting for replay data…";
}

function renderPulse() {
  const points = state.history.map((value, i) => [
    (i * 900) / 59,
    81 - value * 0.76,
  ]);
  $("pulse-line").setAttribute(
    "points",
    points.map((p) => p.join(",")).join(" "),
  );
  $("pulse-area").setAttribute(
    "d",
    points.length
      ? "M0,86 L" +
          points.map((p) => p.join(",")).join(" L") +
          " L" +
          points.at(-1)[0] +
          ",86 Z"
      : "",
  );
}

function renderDistribution() {
  const rows = Object.entries(state.counts).sort((a, b) => b[1] - a[1]);
  const fragment = document.createDocumentFragment();
  for (const [name, count] of rows.slice(0, 7)) {
    const row = element("div", undefined, "dist-row");
    const bar = element("div", undefined, "dist-bar");
    const fill = element("span");
    fill.style.width = (100 * count) / Math.max(1, rows[0][1]) + "%";
    bar.append(fill);
    row.append(element("span", name), bar, element("span", number(count)));
    fragment.append(row);
  }
  $("distribution").replaceChildren(fragment);
}

function setPresentationMode(mode) {
  state.presentationMode = mode;
  try { localStorage.setItem("nida_mode", mode); } catch (_) { /* Storage may be blocked. */ }

  const isTech = mode === "technical";
  $("mode-understand-btn").classList.toggle("active", !isTech);
  $("mode-understand-btn").setAttribute("aria-selected", !isTech);
  $("mode-technical-btn").classList.toggle("active", isTech);
  $("mode-technical-btn").setAttribute("aria-selected", isTech);

  $("view-understand").hidden = isTech;
  $("view-technical").hidden = !isTech;
  document.body.classList.toggle("mode-technical", isTech);

  if (state.selected) {
    selectFlow(state.selected);
  }
}

function selectFlow(row) {
  state.selected = row;
  updateGuidedWalkthrough(row);
  inspect(row);
  renderRows();
  renderDecisionDesk();
}

function renderDecisionDesk() {
  const row = state.selected;
  $("decision-approve").disabled = !row;
  $("decision-dismiss").disabled = !row;
  $("decision-proposal").textContent = row?.recommended_action || "Choose a connection to review.";
  $("decision-reason").textContent = row
    ? `${row.event_id || "Custom record"} · ${row.predicted_attack_cat || "Unknown"} · risk ${row.risk_score ?? "—"}/100 · ${row.review_recommended ? "queued for review" : "below review threshold"}. Model output is a lead, not proof.`
    : "The model evidence and review policy provide context.";
  const recent = row && [...state.decisionLog].reverse().find((entry) => entry.flow_id === (row.event_id || "custom-flow"));
  $("decision-status").textContent = recent
    ? `${recent.decision === "approved_for_follow_up" ? "Follow-up approved" : "Dismissed"} for this record at ${recent.recorded_at.slice(11, 19)} UTC. No action executed.`
    : "No decision recorded for this record.";
  $("decision-count").textContent = `(${state.decisionLog.length})`;
  const items = state.decisionLog.slice(-5).reverse().map((entry) =>
    element("li", `${entry.flow_id}: ${entry.decision === "approved_for_follow_up" ? "follow-up approved" : "dismissed"} · ${entry.recorded_at.slice(11, 19)} UTC${entry.analyst_note ? ` · ${entry.analyst_note}` : ""}`),
  );
  $("decision-log").replaceChildren(...items);
}

function recordDecision(decision) {
  const row = state.selected;
  if (!row) return;
  state.decisionLog.push({
    recorded_at: new Date().toISOString(),
    flow_id: row.event_id || "custom-flow",
    model_id: row.model_id || $("model-id").textContent,
    predicted_attack_cat: row.predicted_attack_cat,
    risk_score: row.risk_score,
    review_recommended: row.review_recommended,
    proposed_action: row.recommended_action,
    decision,
    analyst_note: $("decision-note").value.trim(),
    execution: "none",
  });
  state.decisionLog = state.decisionLog.slice(-100);
  try { sessionStorage.setItem("nida_decisions", JSON.stringify(state.decisionLog)); }
  catch (_) { /* Export remains available when storage is blocked. */ }
  $("decision-note").value = "";
  renderDecisionDesk();
}

function updateGuidedWalkthrough(row) {
  if (!row) return;

  const raw = row.explanation?.raw_features || row._rawPayload || {};
  const flowId = row.event_id ? row.event_id.replace("replay-", "#") : "Custom record";
  const protocol = String(row.protocol || raw.proto || "Unknown").toUpperCase();
  $("guided-flow-id").textContent = flowId;

  const verdict = String(row.predicted_attack_cat || "Unknown");
  const flagged = verdict !== "Normal";
  const verdictBadge = $("guided-verdict-badge");
  verdictBadge.textContent = verdict;
  verdictBadge.className = `badge ${flagged ? row.risk_level : "low"}`;
  const riskBadge = $("guided-risk-badge");
  riskBadge.textContent = `Risk ${row.risk_score ?? "—"} / 100`;
  riskBadge.className = `badge ${row.risk_level || ""}`;

  $("guided-step-decision").textContent = flagged
    ? `The model classified this record as ${verdict}.`
    : "The model classified this record as Normal.";

  const observations = [`Protocol: ${protocol}`];
  if (raw.service && raw.service !== "-") observations.push(`Service: ${raw.service}`);
  if (raw.dur != null && Number.isFinite(Number(raw.dur))) {
    const duration = Number(raw.dur);
    observations.push(`Duration: ${duration > 0 && duration < 0.001 ? "<0.001" : duration.toFixed(3)} s`);
  }
  if (raw.sbytes != null && Number.isFinite(Number(raw.sbytes))) observations.push(`Source bytes: ${number(raw.sbytes)}`);
  $("guided-step-observation").textContent = observations.join(" · ");

  $("guided-step-significance").textContent = row.review_recommended
    ? "The review policy queued this record for a human analyst."
    : row.is_anomaly_candidate
      ? "The anomaly detector found it unusual, even though the classifier said Normal."
      : "This record did not meet the review policy threshold.";
  $("guided-candidate-note").hidden = !row.is_anomaly_candidate;
  $("guided-step-action").textContent = row.recommended_action || "Review the record and its evidence.";

  if (row._narrative) {
    renderNarrative(row._narrative);
  } else {
    $("briefing-narrative-card").hidden = true;
    $("briefing-narrative-text").textContent = "";
    $("briefing-provider-badge").textContent = "Built-in explanation";
    $("briefing-action-text").textContent = row.recommended_action || "—";
    $("briefing-narrate-status").textContent = "";
  }
}

function renderNarrative(narrative) {
  if (!narrative) return;
  const isBuiltin = Boolean(narrative.is_builtin);
  const isUnavailable = narrative.unavailable || narrative.provider === "none" || isBuiltin;

  // Briefing / Understand Card
  const briefingCard = $("briefing-narrative-card");
  if (briefingCard) {
    briefingCard.hidden = false;
    briefingCard.classList.toggle("narrative-builtin", isBuiltin);
    briefingCard.classList.toggle("narrative-unavailable", isUnavailable && !isBuiltin);
    if (isBuiltin && state.selected) {
      const row = state.selected;
      const verdict = row.predicted_attack_cat || "Unknown";
      const decision = row.review_recommended
        ? "The review policy queued it for a person to check."
        : "It did not meet the review policy threshold.";
      $("briefing-narrative-text").textContent =
        `The model marked this connection as ${verdict}. Its risk score is ${row.risk_score}/100. ${decision} This is a signal to investigate, not proof of an attack.`;
    } else {
      $("briefing-narrative-text").textContent = narrative.summary;
    }
    $("briefing-provider-badge").textContent = isBuiltin
      ? "Built-in explanation (Rule-based)"
      : narrative.provider;
    // Provider prose cannot replace the model's deterministic follow-up action.
    $("briefing-action-text").textContent = state.selected?.recommended_action || "Review the record and its evidence.";
  }

  // Analyst / Technical Card
  const analystCard = $("analyst-narrative-card");
  if (analystCard) {
    analystCard.hidden = false;
    analystCard.classList.toggle("narrative-builtin", isBuiltin);
    analystCard.classList.toggle("narrative-unavailable", isUnavailable && !isBuiltin);
    $("analyst-narrative-text").textContent = narrative.summary;
    $("analyst-provider-badge").textContent = isBuiltin
      ? "Built-in explanation (Rule-based)"
      : narrative.provider;
  }
}

function extractModelFeatures(row) {
  const raw = row.explanation?.raw_features || row._rawPayload;
  if (raw && typeof raw === "object" && Object.keys(raw).length >= 40) {
    const clean = { ...raw };
    delete clean.id;
    delete clean.label;
    delete clean.attack_cat;
    return clean;
  }
  const payload = { ...row };
  const metadataKeys = [
    "id", "label", "attack_cat", "event_id", "row_index", "next_offset", "cycle",
    "timestamp", "source", "true_label", "protocol", "_narrative", "_rawPayload",
    "model_id", "predicted_attack_cat", "confidence", "class_probabilities",
    "attack_probability", "anomaly_score", "anomaly_percentile", "risk_score",
    "risk_level", "risk_components", "is_anomaly_candidate", "review_recommended",
    "review_threshold", "warnings", "recommended_action", "explanation", "inference_ms",
    "narrative", "narrative_status", "builtin_explanation"
  ];
  for (const k of metadataKeys) {
    delete payload[k];
  }
  return payload;
}

async function requestNarrative() {
  const row = state.selected;
  if (!row) return;

  const btnBriefing = $("briefing-narrate-btn");
  const btnAnalyst = $("analyst-narrate-btn");
  const statusBriefing = $("briefing-narrate-status");
  const statusAnalyst = $("analyst-narrate-status");

  btnBriefing.disabled = true;
  if (btnAnalyst) btnAnalyst.disabled = true;
  statusBriefing.textContent = "Analyzing flow…";
  if (statusAnalyst) statusAnalyst.textContent = "Analyzing flow…";

  try {
    const payload = extractModelFeatures(row);

    const data = await getJSON("/predict?narrate=true", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (state.selected !== row) return;

    if (data.narrative && data.narrative_status === "ok") {
      row._narrative = data.narrative;
      statusBriefing.textContent = "AI explanation ready";
      if (statusAnalyst) statusAnalyst.textContent = "AI explanation ready";
    } else if (data.narrative_status === "not_configured") {
      row._narrative = data.builtin_explanation || {
        summary: "AI narrative not configured. Review technical evidence.",
        recommended_action: row.recommended_action || "Follow standard security review protocol.",
        provider: "Built-in explanation (Rule-based)",
        is_builtin: true,
      };
      statusBriefing.textContent = "AI not configured";
      if (statusAnalyst) statusAnalyst.textContent = "AI not configured";
    } else {
      row._narrative = data.builtin_explanation || {
        summary: "AI service unavailable. Review technical evidence.",
        recommended_action: row.recommended_action || "Follow standard security review protocol.",
        provider: "Built-in explanation (Rule-based)",
        is_builtin: true,
      };
      statusBriefing.textContent = "AI service unavailable";
      if (statusAnalyst) statusAnalyst.textContent = "AI service unavailable";
    }
    if (state.selected === row) renderNarrative(row._narrative);
  } catch (err) {
    if (state.selected === row) {
      statusBriefing.textContent = "Could not analyze this flow";
      if (statusAnalyst) statusAnalyst.textContent = "Could not analyze this flow";
    }
    if (row.builtin_explanation && state.selected === row) {
      renderNarrative(row.builtin_explanation);
    }
  } finally {
    btnBriefing.disabled = false;
    if (btnAnalyst) btnAnalyst.disabled = false;
  }
}

function buildContributionsFragment(features) {
  const maximum = Math.max(
    ...features.map((f) => Math.abs(f.contribution)),
    0.00001,
  );
  const fragment = document.createDocumentFragment();
  for (const feature of features) {
    const line = element("div", undefined, "contribution");
    const track = element("div", undefined, "contribution-track");
    const fill = element(
      "div",
      undefined,
      "contribution-fill" + (feature.contribution < 0 ? " negative" : ""),
    );
    fill.style.width = (100 * Math.abs(feature.contribution)) / maximum + "%";
    track.append(fill);
    const name = element("span", feature.feature, "contribution-name");
    name.title = feature.feature;
    line.append(
      name,
      track,
      element(
        "span",
        (feature.contribution >= 0 ? "+" : "") +
          feature.contribution.toFixed(2),
        "contribution-value",
      ),
    );
    fragment.append(line);
  }
  return fragment;
}

function inspect(row) {
  if (!row) return;
  $("inspection-empty").hidden = true;
  $("inspection").hidden = false;
  $("selected-verdict").textContent = row.predicted_attack_cat;
  $("selected-risk").textContent = row.risk_score;
  $("selected-source").textContent =
    percent(row.confidence) +
    " model confidence · " +
    (row.source === "benchmark_replay" ? row.event_id : "submitted flow") +
    (row.review_recommended ? " · [REVIEW RECOMMENDED]" : " · below review threshold");

  // Ground truth comparison
  const truthBox = $("selected-truth-comparison");
  if (truthBox && row.true_label) {
    const isMatch = row.true_label === row.predicted_attack_cat;
    truthBox.textContent = ` · True class: ${row.true_label} (${isMatch ? "Match ✓" : "Mismatch ⚠"})`;
    truthBox.className = "truth-comparison " + (isMatch ? "truth-match" : "truth-mismatch");
  }

  $("selected-candidate").hidden = !row.is_anomaly_candidate;
  $("classifier-points").textContent =
    row.risk_components.classifier.toFixed(1) + " / 60";
  $("anomaly-points").textContent =
    row.risk_components.anomaly.toFixed(1) + " / 40";
  $("classifier-bar").value = row.risk_components.classifier;
  $("anomaly-bar").value = row.risk_components.anomaly;

  $("tech-raw-anomaly").textContent = row.anomaly_score != null ? row.anomaly_score.toFixed(4) : "—";
  $("tech-anomaly-pct").textContent = row.anomaly_percentile != null ? percent(row.anomaly_percentile) : "—";

  $("action").textContent = row.recommended_action;
  $("warnings").textContent = row.warnings ? row.warnings.join(" · ") : "";
  const features = row.explanation?.features || [];
  $("contributions").replaceChildren(buildContributionsFragment(features));
  $("raw-evidence").textContent = JSON.stringify(row, null, 2);

  if (row._narrative) {
    renderNarrative(row._narrative);
  } else {
    $("analyst-narrative-card").hidden = true;
    $("analyst-narrate-status").textContent = "";
  }
}

function resetReplay() {
  disconnect();
  state.offset = 0;
  if (!state.paused) connect();
}

$("pause").onclick = () => {
  state.paused = !state.paused;
  $("pause").textContent = state.paused ? "Resume replay" : "Pause replay";
  if (state.paused) {
    disconnect();
    status("Replay paused");
  } else connect();
};

$("mode-understand-btn").onclick = () => setPresentationMode("understand");
$("mode-technical-btn").onclick = () => setPresentationMode("technical");
$("hero-technical-btn").onclick = () => {
  setPresentationMode("technical");
  $("view-technical").scrollIntoView({ behavior: reducedMotion() ? "auto" : "smooth" });
};
$("decision-approve").onclick = () => recordDecision("approved_for_follow_up");
$("decision-dismiss").onclick = () => recordDecision("dismissed");
$("theme-toggle").onclick = () => setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");

// Guided Archetype buttons
async function selectArchetype(category, buttonId) {
  document.querySelectorAll(".archetype-btn").forEach((btn) => btn.classList.remove("active"));
  $(buttonId).classList.add("active");

  // Check if a row of this category exists in retained rows
  const match = state.rows.find((r) => r.predicted_attack_cat === category || r.true_label === category);
  if (match) {
    selectFlow(match);
    return;
  }

  // Otherwise, load sample from API
  try {
    const data = await getJSON("/sample?category=" + encodeURIComponent(category));
    const scored = await getJSON("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data.features),
    });
    scored.true_label = data.true_label;
    scored.event_id = "sample-" + category.toLowerCase();
    scored.source = "benchmark_sample";
    selectFlow(scored);
  } catch (err) {
    console.error("Could not load archetype", err);
  }
}

$("archetype-normal").onclick = () => selectArchetype("Normal", "archetype-normal");
$("archetype-generic").onclick = () => selectArchetype("Generic", "archetype-generic");
$("archetype-recon").onclick = () => selectArchetype("Reconnaissance", "archetype-recon");

$("briefing-narrate-btn").onclick = requestNarrative;
const btnAnalyst = $("analyst-narrate-btn");
if (btnAnalyst) btnAnalyst.onclick = requestNarrative;

$("scenario").onchange = resetReplay;
$("speed").onchange = () => {
  disconnect();
  if (!state.paused) connect();
};
$("search").oninput = renderRows;
$("risk-filter").onchange = renderRows;

$("export").onclick = () => {
  const payload = {
    exported_at: new Date().toISOString(),
    source: "benchmark_replay",
    model_id: $("model-id").textContent,
    scope:
      "Session totals and latest 80 retained flows; replay cycles may repeat dataset rows",
    totals: {
      flows: state.total,
      attack_predictions: state.attacks,
      review_queue: state.review,
      anomaly_candidates: state.anomalies,
    },
    predictions: state.counts,
    retained_flows: state.rows,
    analyst_decisions: state.decisionLog,
  };
  const url = URL.createObjectURL(
    new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" }),
  );
  const link = element("a");
  link.href = url;
  link.download = "nida-session.json";
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
};

async function loadSample() {
  $("load-sample").disabled = true;
  try {
    const data = await getJSON(
      "/sample?category=" + encodeURIComponent($("sample-class").value),
    );
    $("payload").value = JSON.stringify(data.features, null, 2);
    $("input-status").textContent =
      "Benchmark example loaded · true label: " + data.true_label;
  } catch (err) {
    $("input-status").textContent = err.message;
  } finally {
    $("load-sample").disabled = false;
  }
}

$("load-sample").onclick = loadSample;

$("score").onclick = async () => {
  $("score").disabled = true;
  $("input-status").textContent = "Analyzing…";
  try {
    const payload = JSON.parse($("payload").value);
    const result = await getJSON("/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    result._rawPayload = payload;
    selectFlow(result);
    $("input-status").textContent =
      result.predicted_attack_cat +
      " · risk " +
      result.risk_score +
      " · evidence shown in Flow investigation.";
    $("technical-inspector-heading").scrollIntoView({
      behavior: matchMedia("(prefers-reduced-motion: reduce)").matches
        ? "auto"
        : "smooth",
      block: "start",
    });
  } catch (err) {
    $("input-status").textContent = "Flow rejected: " + err.message;
  } finally {
    $("score").disabled = false;
  }
};

function renderMetrics(metrics) {
  $("hero-raw-fpr").textContent = percent(metrics.binary_detection.false_positive_rate);
  $("hero-queue-fpr").textContent = percent(metrics.review_policy.test_false_positive_rate);
  $("hero-mobile-raw").textContent = percent(metrics.binary_detection.false_positive_rate);
  $("hero-mobile-fpr").textContent = percent(metrics.review_policy.test_false_positive_rate);
  $("hero-recall").textContent = percent(metrics.review_policy.test_recall);
  $("hero-precision").textContent = percent(metrics.review_policy.test_precision);
  $("eval-accuracy").textContent = percent(metrics.accuracy);
  $("eval-f1").textContent = metrics.macro_f1.toFixed(3);
  $("eval-recall").textContent = percent(metrics.binary_detection.recall);
  $("eval-fpr").textContent = percent(
    metrics.binary_detection.false_positive_rate,
  );
  $("evaluation-context").textContent =
    number(metrics.test_rows) +
    " test flows · majority baseline: " +
    percent(metrics.majority_baseline.accuracy) +
    " · " +
    number(metrics.data_audit.removed_train_rows_overlapping_test) +
    " overlapping training rows removed before fitting.";
  $("review-policy").textContent =
    "Review queue policy: attack score ≥ " +
    percent(metrics.review_policy.attack_score_threshold) +
    " or anomaly candidate. Held-out recall: " +
    percent(metrics.review_policy.test_recall) +
    "; false positive rate: " +
    percent(metrics.review_policy.test_false_positive_rate) +
    ". Threshold chosen on validation normals; not tuned on test labels.";
  const fragment = document.createDocumentFragment();
  for (const category of metrics.classes) {
    const data = metrics.class_report[category];
    const row = element("tr");
    row.append(
      element("td", category),
      element("td", percent(data.precision)),
      element("td", percent(data.recall), data.recall < 0.5 ? "orange-text" : ""),
      element("td", data["f1-score"].toFixed(3)),
      element("td", number(data.support)),
    );
    fragment.append(row);
  }
  $("class-metrics").replaceChildren(fragment);
  const table = element("table", undefined, "confusion-table");
  const head = element("tr");
  head.append(element("th", "True / predicted"));
  metrics.classes.forEach((c) => head.append(element("th", c)));
  table.append(head);
  metrics.confusion_matrix.forEach((counts, i) => {
    const row = element("tr");
    row.append(element("th", metrics.classes[i]));
    counts.forEach((count, j) =>
      row.append(element("td", number(count), i === j ? "diagonal" : "")),
    );
    table.append(row);
  });
  $("confusion").replaceChildren(table);
}

function initScrollReveals() {
  if (reducedMotion() || !('IntersectionObserver' in window)) return;
  const targets = document.querySelectorAll(
    ".guided-section, .feed-panel, .decision-desk, .metrics-grid, .activity-panel, .inspector-dossier, .distribution-panel, .input-panel, .evidence-panel",
  );
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        entry.target.classList.remove("reveal-pending");
        entry.target.classList.add("reveal-visible");
        observer.unobserve(entry.target);
      }
    }
  }, { threshold: 0.08 });
  for (const target of targets) {
    target.classList.add("reveal-pending");
    observer.observe(target);
  }
  document.documentElement.classList.add("motion-ready");
}

async function init() {
  setTheme(document.documentElement.dataset.theme);
  renderDecisionDesk();
  initScrollReveals();
  const tick = () => {
    $("clock").textContent = new Date().toISOString().slice(11, 19) + " UTC";
  };
  tick();
  setInterval(tick, 1000);

  // Initialize presentation mode from preference
  setPresentationMode(state.presentationMode);

  try {
    const [health, metrics, limitations] = await Promise.all([
      getJSON("/health"),
      getJSON("/metrics"),
      getJSON("/limitations"),
    ]);
    $("model-id").textContent = health.model_id;
    for (const name of health.classes) {
      $("scenario").append(new Option(name, name));
      if (name !== "Normal") $("sample-class").append(new Option(name, name));
    }
    renderMetrics(metrics);
    $("limitations").textContent =
      "Weak or low-support classes: " +
      limitations.low_confidence_classes
        .map(
          (c) =>
            c.attack_cat +
            " (recall " +
            percent(c.recall) +
            ", n=" +
            c.test_support +
            ")",
        )
        .join("; ") +
      ".";
    if (health.replay_available) {
      connect();
      await loadSample();
    } else {
      status("Replay unavailable");
      error(
        "Replay CSV unavailable. You can still submit flows through the inference API.",
      );
      finishLoading();
    }
  } catch (err) {
    status("API unavailable");
    error(
      "Could not initialize workspace: " +
        err.message +
        ". Start the server and reload.",
    );
    finishLoading();
  }
}

addEventListener("pagehide", disconnect);
init();
