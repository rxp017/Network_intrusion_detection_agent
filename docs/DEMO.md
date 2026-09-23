# Three-Minute Judging Demo: NIDA

> **One-sentence summary for a beginner:** NIDA is an explainable decision-support dashboard that inspects network connection summaries from the UNSW-NB15 benchmark, classifies attack types with XGBoost, flags unusual traffic with Isolation Forest, and presents human-readable feature evidence so security analysts can triage alerts without guessing.

---

## Before Presenting

1. Run `python main.py` in your terminal.
2. Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser.
3. Confirm that replay streams connect immediately. The demo runs **100% offline** with zero internet connection, database, or API keys required.

---

## Demo Script

### 0:00–0:40 — "Understand" Mode & Project Framing

1. **State the core problem**:
   > *"In modern security operations, alerts without evidence create alert fatigue. NIDA demonstrates how to combine supervised attack classification, unsupervised anomaly detection, and exact feature attribution into an explainable triage interface."*
2. **Point to the persistent disclaimer banner**:
   > *"First, an honest research boundary: this is a benchmark replay of 400 held-out flows from UNSW-NB15. It is not capturing live packets, and statistical anomalies are not guaranteed zero-day exploits."*
3. **Walk through Understand Mode (Default)**:
   - Read the first-screen question, **Which connections deserve a closer look?**, and the record → model → human-review sequence.
   - In **What happened in this record?**, click **Generic attack**. Show the recorded features, model verdict, review decision, and suggested human action.
   - Note that the risk score is a triage signal, not proof of an attack. Switch to **Technical** for evaluation results and score breakdown.
   - Click **Generate explanation**:
     - *If offline (no API keys)*: Point to the badge `Built-in explanation (Rule-based)` and status `AI not configured`.
     - *If API keys are configured in `.env`*: Point to `AI explanation ready`. The outbound LLM call does not stop the replay stream.

---

### 0:40–1:40 — "Technical" Mode: Evidence Dossier & Attributions

1. **Switch presentation modes**:
   - Click **Technical** in the topbar segmented control.
   - Point out that **the currently inspected flow is seamlessly preserved across mode switches**.
2. **Explore the Evidence Dossier**:
   - Point to the **Ground Truth Comparison** badge (`True class: Generic · Match ✓` or `Mismatch ⚠`).
   - Show the **Prediction mix** as browser-session counts. Use the held-out per-class table and confusion matrix for actual evaluation.
   - Show the **Risk Decomposition**:
     $$\text{Risk Score} = 60 \times (1 - P(\text{Normal})) + 40 \times \text{anomaly\_percentile}$$
     Emphasize that this is an operational triage heuristic, **not** a calibrated probability of real-world harm.
   - Show the **Per-Flow TreeSHAP Contributions**:
     Point to the margin disclaimer: *TreeSHAP feature contributions explain the classifier's mathematical margin in log-odds space, not physical causation.*
   - Expand the **Raw JSON Evidence** drawer to show the complete 42-feature schema row.

---

### 1:40–2:20 — Custom Flow Workbench & Input Validation

1. Scroll to **Custom Flow Workbench**.
2. Under **Load benchmark example**, select **Normal** and click **Load example**.
3. Click **Analyze flow** to inspect the live scored output.
4. Modify one valid feature value, such as `sbytes`, and click **Analyze flow** again:
   > *"This is a sensitivity experiment. Compare the verdict, risk score, and TreeSHAP contributions; the direction of change is not guaranteed."*
5. Highlight strict schema validation:
   - Clear the textarea to `{}` or delete the `"service"` key, and click **Analyze flow**.
   - Show that the server returns an **HTTP 422 Unprocessable Entity** error with `Flow rejected`:
   > *"NIDA never silently imputes missing network features into confident false guesses."*

---

### 2:20–3:00 — Reproducible Benchmark Audit & Session Export

1. Scroll to **Reproducible Benchmark Audit**:
   - Highlight the **82,332 held-out test split evaluation**: 72.89% multiclass accuracy, 89.42% review queue recall at a 4.52% false positive rate.
   - Point to the **Known Weak Classes box**:
     > *"We practice intellectual honesty: Analysis has an 8.27% recall, Backdoor has a 9.26% recall, and Worms has only 44 test flows in UNSW-NB15. We explicitly warn the reviewer about these blind spots."*
   - Expand the **Confusion Matrix** showing true vs. predicted counts across all 10 classes.
2. In the replay feed toolbar, filter by **Review queue only** and click **Export session ↓**:
   - Open the downloaded JSON session file to show browser-session totals and the latest 80 retained rows with model ID, replay timestamps, scores, TreeSHAP evidence, and benchmark labels. Artifact hashes are documented separately in `artifacts/manifest.json`.
3. **Closing sentence**:
   > *"From raw 42-feature input to classification, anomaly detection, TreeSHAP evidence, and human review policy—NIDA keeps the entire investigation path inspectable, reproducible, and grounded in truth."*

---

## Anticipated Questions & Grounded Answers

**Q: Is this a live network intrusion detection system?**
> **No.** NIDA is a decision-support research prototype. It replays precomputed UNSW-NB15 connection summaries and accepts JSON feature rows via REST. It does not sniff raw packets, monitor network interfaces, or discover connected hardware.

**Q: Does it detect zero-day exploits?**
> **No.** The benign-only Isolation Forest flags statistical outliers that deviate from normal training traffic baselines. Statistical deviation is a lead for human review, not proof of an unobserved exploit.

**Q: Why is multiclass accuracy 72.9% instead of 99%?**
> This is a 10-class task, not just attack versus Normal. NIDA removes feature-identical training rows that overlap the test set and reports the weak classes. Do not compare the number directly with a paper using a different split or evaluation protocol.

**Q: Can NIDA block malicious IP addresses automatically?**
> **No.** NIDA is intentionally designed for human decision support. Its operational review threshold recommends suspicious flows to human analysts; it never makes automated firewall or blocking decisions.

**Q: Does the AI narrative layer send my network data to external cloud providers?**
> **By default, no.** NIDA's core demo works offline with a deterministic built-in explanation. If an operator configures Groq or Gemini and clicks the explanation button, the server sends a prompt containing the verdict, scores, review flag, and selected feature contributions to that provider. Keep API keys on the server; do not paste private data or keys into the workbench.
