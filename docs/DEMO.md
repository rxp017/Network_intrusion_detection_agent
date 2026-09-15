# Three-minute judging demo

## Before presenting

Run `python main.py`, open http://127.0.0.1:8000, and confirm the model ID and replay connection. Install dependencies in advance. The dashboard itself needs no internet connection.

## 0:00–0:25 — Define the problem

“An alert without evidence gives an analyst more work. NIDA puts the verdict, its contributing features, and the cost of false alarms in one place.”

Point to the source banner: “This is labelled benchmark replay. It is not live capture.”

## 0:25–1:10 — Follow a flow

1. Choose **Generic** in Scenario and allow several records to arrive.
2. **Pause replay**, select a row, and compare prediction with ground truth.
3. Show risk components, signed TreeSHAP contributions, and the suggested analyst action.
4. Expand raw evidence. Explain that SHAP describes the model's margin, not whether an attack actually occurred.

Predictions can be wrong. If they differ from ground truth, use that as a visible failure case; do not claim every sample will match.

## 1:10–1:50 — Interrogate it

1. In **Interrogate the model**, load a Normal example.
2. Analyze it. Then change one numeric feature and analyze again.
3. Compare the evidence. Call it a sensitivity experiment, not a realistic attack simulation.
4. Submit `{}` once to show that incomplete flows are rejected rather than silently imputed into a confident prediction.

## 1:50–2:35 — Show the tradeoff

Open **Model evidence**.

“Raw predictions have high attack recall but too many false alarms. Our validation-derived review policy achieves 89.4% attack recall at 4.5% false positives on held-out flows. Raw results and weak classes are still visible.”

Show the baseline, per-class recall, and confusion matrix. State that the balanced 400-flow replay is not the evaluation population.

## 2:35–3:00 — Close with a concrete artifact

Filter **Review queue only**, export the session, and show that the export contains model ID, scores, evidence, and source labels.

“The complete path is inspectable: input schema → model verdict → explanation → review policy → human investigation. We can reproduce the benchmark, including where it fails.”

## Questions to expect

**Is this a live IDS?** No. It accepts already extracted feature rows through REST and replays benchmark flows through WebSocket. Live feature extraction is future work.

**Does it detect zero-days?** That is not established. The anomaly engine flags unusual normal-class flows for investigation.

**What is original here?** The implemented contribution is the integrated investigation workflow, per-flow evidence, validation-derived queue policy, and reproducible evaluation. XGBoost and Isolation Forest are established algorithms.

**Why not claim higher accuracy?** The project removes feature overlap and training duplicates and reports weak classes. The classifier is imperfect; the review policy has a measurable recall/false-alarm tradeoff.

**Can this run in production?** Not yet. It needs representative live validation, a consistent feature extractor, authentication, durable storage, monitoring, and operational review.
