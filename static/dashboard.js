"use strict";
const $ = (id) => document.getElementById(id);
const state = {
  socket: null,
  timer: null,
  paused: false,
  offset: 0,
  retries: 0,
  rows: [],
  counts: {},
  total: 0,
  attacks: 0,
  review: 0,
  anomalies: 0,
  history: [],
  selected: null,
  generation: 0,
  view: "analyst",
};
const number = (n) => Number(n).toLocaleString();
const percent = (n) => (100 * Number(n)).toFixed(1) + "%";
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function error(message) {
  $("error").textContent = message;
  $("error").hidden = !message;
}
async function getJSON(path, options) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok)
    throw new Error(
      typeof data.detail === "string"
        ? data.detail
        : JSON.stringify(data.detail || data),
    );
  return data;
}
function status(text, connected = false) {
  $("connection").textContent = text;
  $("connection-dot").classList.toggle("muted", !connected);
}
function connect() {
  clearTimeout(state.timer);
  if (state.paused) return;
  const generation = ++state.generation;
  status("Connecting");
  const query = new URLSearchParams({
    category: $("scenario").value,
    interval: $("speed").value,
    offset: String(state.offset),
  });
  const socket = new WebSocket(
    (location.protocol === "https:" ? "wss://" : "ws://") +
      location.host +
      "/ws/stream?" +
      query,
  );
  state.socket = socket;
  socket.onopen = () => {
    if (generation !== state.generation) return;
    state.retries = 0;
    status("Replay connected", true);
    error("");
  };
  socket.onmessage = (event) => {
    if (generation !== state.generation || state.paused) return;
    try {
      const data = JSON.parse(event.data);
      if (data.error) {
        error(data.error);
        return;
      }
      if (data.source !== "benchmark_replay" || !data.class_probabilities)
        throw new Error("Invalid stream event");
      state.offset = data.next_offset;
      accept(data);
    } catch (err) {
      error("Could not process replay event: " + err.message);
    }
  };
  socket.onclose = (event) => {
    if (generation !== state.generation || state.paused) return;
    if (event.code === 1008) {
      status("Invalid replay settings");
      error("Replay settings were rejected. Reload the page.");
      return;
    }
    status("Disconnected · retrying");
    const delay = Math.min(1000 * 2 ** state.retries++, 15000);
    state.timer = setTimeout(connect, delay);
  };
  socket.onerror = () => {
    if (generation === state.generation) status("Connection interrupted");
  };
}
function disconnect() {
  state.generation++;
  clearTimeout(state.timer);
  if (state.socket) {
    state.socket.close();
    state.socket = null;
  }
}
function accept(data) {
  state.total++;
  if (data.predicted_attack_cat !== "Normal") state.attacks++;
  if (data.is_anomaly_candidate) state.anomalies++;
  if (data.review_recommended) state.review++;
  state.counts[data.predicted_attack_cat] =
    (state.counts[data.predicted_attack_cat] || 0) + 1;
  state.rows.unshift(data);
  if (state.rows.length > 80) state.rows.pop();
  state.history.push(data.risk_score);
  if (state.history.length > 60) state.history.shift();
  $("total").textContent = number(state.total);
  $("attacks").textContent = number(state.review);
  $("anomalies").textContent = number(state.anomalies);
  $("attack-rate").textContent =
    number(state.attacks) +
    " attack predictions · " +
    percent(state.review / state.total) +
    " queued";
  $("latency").textContent = data.inference_ms.toFixed(0);
  renderRows();
  renderDistribution();
  renderPulse();
  if (!state.selected) inspect(data);
}
function renderRows() {
  const text = $("search").value.toLowerCase().trim();
  const reviewOnly = $("risk-filter").value === "review";
  const minimum = reviewOnly ? 0 : Number($("risk-filter").value);
  const rows = state.rows.filter(
    (row) =>
      row.risk_score >= minimum &&
      (!reviewOnly || row.review_recommended) &&
      (row.predicted_attack_cat + " " + row.protocol + " " + row.service)
        .toLowerCase()
        .includes(text),
  );
  const fragment = document.createDocumentFragment();
  for (const row of rows) {
    const tr = element("tr");
    tr.tabIndex = 0;
    tr.classList.toggle("selected", state.selected?.event_id === row.event_id);
    tr.setAttribute(
      "aria-label",
      row.predicted_attack_cat + ", risk " + row.risk_score + ", inspect flow",
    );
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
    const verdict = element("td");
    verdict.append(element("span", row.predicted_attack_cat));
    if (row.is_anomaly_candidate)
      verdict.append(element("span", " · anomaly", "purple"));
    const risk = element("td");
    risk.append(
      element(
        "span",
        row.risk_score + " " + row.risk_level,
        "badge " + row.risk_level,
      ),
    );
    tr.append(
      id,
      verdict,
      element("td", row.protocol.toUpperCase(), "micro"),
      risk,
      element(
        "td",
        row.true_label,
        row.true_label === row.predicted_attack_cat
          ? "truth-match"
          : "truth-mismatch",
      ),
    );
    tr.onclick = () => inspect(row);
    tr.onkeydown = (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        inspect(row);
      }
    };
    fragment.append(tr);
  }
  $("flows").replaceChildren(fragment);
  $("visible-count").textContent =
    rows.length + " visible / " + state.rows.length + " retained";
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
function switchView(mode) {
  state.view = mode;
  const isBriefing = mode === "briefing";
  $("view-analyst-btn").classList.toggle("active", !isBriefing);
  $("view-analyst-btn").setAttribute("aria-selected", !isBriefing);
  $("view-briefing-btn").classList.toggle("active", isBriefing);
  $("view-briefing-btn").setAttribute("aria-selected", isBriefing);
  $("workspace-mode-label").textContent = isBriefing ? "Executive briefing" : "Detection workspace";

  document.body.classList.toggle("mode-briefing-active", isBriefing);
  $("inspector-heading").closest(".inspector").hidden = isBriefing;
  $("briefing-panel").hidden = !isBriefing;
  $("distribution").closest(".distribution").hidden = isBriefing;

  if (state.selected) {
    inspect(state.selected);
  }
}

function renderNarrative(narrative) {
  if (!narrative) return;
  const isUnavailable = narrative.unavailable || narrative.provider === "none";

  $("briefing-narrative-card").classList.toggle("narrative-unavailable", isUnavailable);
  $("briefing-narrative-text").textContent = narrative.summary;
  $("briefing-provider-badge").textContent = isUnavailable ? "Offline fallback" : narrative.provider;
  if (narrative.recommended_action) {
    $("briefing-action-text").textContent = narrative.recommended_action;
  }

  $("analyst-narrative-card").hidden = false;
  $("analyst-narrative-card").classList.toggle("narrative-unavailable", isUnavailable);
  $("analyst-narrative-text").textContent = narrative.summary;
  $("analyst-provider-badge").textContent = isUnavailable ? "Offline fallback" : narrative.provider;
}

async function requestNarrative() {
  if (!state.selected) return;
  const row = state.selected;

  const btnBriefing = $("briefing-narrate-btn");
  const btnAnalyst = $("analyst-narrate-btn");
  const statusBriefing = $("briefing-narrate-status");
  const statusAnalyst = $("analyst-narrate-status");

  if (row._narrative) {
    renderNarrative(row._narrative);
    return;
  }

  btnBriefing.disabled = true;
  btnAnalyst.disabled = true;
  statusBriefing.textContent = "Generating narrative…";
  statusAnalyst.textContent = "Generating narrative…";

  try {
    const rawFeatures = row.explanation?.raw_features || row._rawPayload;
    const payload = rawFeatures ? { ...rawFeatures } : { ...row };
    const nonFeatures = [
      "id", "label", "attack_cat", "event_id", "row_index", "next_offset", "cycle",
      "timestamp", "source", "true_label", "protocol", "service", "_narrative",
      "model_id", "predicted_attack_cat", "confidence", "class_probabilities",
      "attack_probability", "anomaly_score", "anomaly_percentile", "risk_score",
      "risk_level", "risk_components", "is_anomaly_candidate", "review_recommended",
      "review_threshold", "warnings", "recommended_action", "explanation", "inference_ms",
      "narrative", "narrative_status"
    ];
    for (const k of nonFeatures) {
      delete payload[k];
    }

    const data = await getJSON("/predict?narrate=true", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (data.narrative && data.narrative_status === "ok") {
      row._narrative = data.narrative;
      statusBriefing.textContent = "Narrative ready";
      statusAnalyst.textContent = "Narrative ready";
    } else {
      row._narrative = {
        summary: "AI narrative unavailable — no API key configured",
        recommended_action: row.recommended_action || "Follow standard security review protocol.",
        provider: "none",
        unavailable: true,
      };
      statusBriefing.textContent = "Offline mode";
      statusAnalyst.textContent = "Offline mode";
    }
    renderNarrative(row._narrative);
  } catch (err) {
    row._narrative = {
      summary: "AI narrative generation failed — see technical evidence.",
      recommended_action: row.recommended_action || "Follow standard security review protocol.",
      provider: "none",
      unavailable: true,
    };
    renderNarrative(row._narrative);
    statusBriefing.textContent = "Offline mode";
    statusAnalyst.textContent = "Offline mode";
  } finally {
    btnBriefing.disabled = false;
    btnAnalyst.disabled = false;
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
  state.selected = row;
  $("inspection-empty").hidden = true;
  $("inspection").hidden = false;
  $("selected-verdict").textContent = row.predicted_attack_cat;
  $("selected-risk").textContent = row.risk_score;
  $("selected-source").textContent =
    percent(row.confidence) +
    " model score · " +
    (row.source === "benchmark_replay" ? row.event_id : "submitted flow") +
    (row.review_recommended ? " · REVIEW QUEUE" : " · below review threshold");
  $("selected-candidate").hidden = !row.is_anomaly_candidate;
  $("classifier-points").textContent =
    row.risk_components.classifier.toFixed(1) + " / 60";
  $("anomaly-points").textContent =
    row.risk_components.anomaly.toFixed(1) + " / 40";
  $("classifier-bar").value = row.risk_components.classifier;
  $("anomaly-bar").value = row.risk_components.anomaly;
  $("action").textContent = row.recommended_action;
  $("warnings").textContent = row.warnings.join(" · ");
  const features = row.explanation?.features || [];
  $("contributions").replaceChildren(buildContributionsFragment(features));
  $("raw-evidence").textContent = JSON.stringify(row, null, 2);

  // Update Briefing View
  $("briefing-empty").hidden = true;
  $("briefing-content").hidden = false;
  $("briefing-verdict-text").textContent = row.predicted_attack_cat;
  $("briefing-flow-ref").textContent =
    "#" + (row.event_id ? row.event_id.replace("replay-", "") : "custom") +
    (row.protocol ? " · " + row.protocol.toUpperCase() : "");
  $("briefing-risk-pill").textContent = row.risk_score + " / 100 · " + row.risk_level.toUpperCase() + " RISK";
  $("briefing-risk-pill").className = "badge " + row.risk_level;
  $("briefing-confidence-chip").textContent = "Confidence: " + percent(row.confidence);
  $("briefing-queue-chip").textContent = row.review_recommended ? "Queue: Review required" : "Queue: Monitored";
  $("briefing-queue-chip").className = "chip " + (row.review_recommended ? "chip-review" : "chip-normal");
  $("briefing-candidate-chip").hidden = !row.is_anomaly_candidate;
  $("briefing-action-text").textContent = row.recommended_action;

  $("briefing-classifier-pts").textContent =
    row.risk_components.classifier.toFixed(1) + " / 60";
  $("briefing-anomaly-pts").textContent =
    row.risk_components.anomaly.toFixed(1) + " / 40";
  $("briefing-classifier-bar").value = row.risk_components.classifier;
  $("briefing-anomaly-bar").value = row.risk_components.anomaly;
  $("briefing-contributions").replaceChildren(buildContributionsFragment(features));

  if (row._narrative) {
    renderNarrative(row._narrative);
  } else {
    $("briefing-narrative-card").className = "narrative-card";
    $("briefing-narrative-text").textContent =
      'Click "Explain in plain English" to translate this detection into an executive summary.';
    $("briefing-provider-badge").textContent = "Grounded";
    $("briefing-narrate-status").textContent = "";
    $("analyst-narrative-card").hidden = true;
    $("analyst-narrate-status").textContent = "";
  }

  renderRows();
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
$("view-analyst-btn").onclick = () => switchView("analyst");
$("view-briefing-btn").onclick = () => switchView("briefing");
$("briefing-narrate-btn").onclick = requestNarrative;
$("analyst-narrate-btn").onclick = requestNarrative;
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
    inspect(result);
    $("input-status").textContent =
      result.predicted_attack_cat +
      " · risk " +
      result.risk_score +
      " · evidence shown in Flow investigation.";
    $("inspector-heading").scrollIntoView({
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
      element("td", percent(data.recall), data.recall < 0.5 ? "orange" : ""),
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
async function init() {
  const tick = () => {
    $("clock").textContent = new Date().toISOString().slice(11, 19) + " UTC";
  };
  tick();
  setInterval(tick, 1000);
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
    }
  } catch (err) {
    status("API unavailable");
    error(
      "Could not initialize workspace: " +
        err.message +
        ". Start the server and reload.",
    );
  }
}
addEventListener("pagehide", disconnect);
init();
