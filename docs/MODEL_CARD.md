# Model card

## Intended use

Interactive research and hackathon demonstrations of explainable network-flow triage. Inputs are precomputed UNSW-NB15-style feature rows, not raw packets. Outputs support human investigation. No automated enforcement is implemented.

## Training and provenance

- Publisher benchmark: UNSW-NB15, 175,341 training / 82,332 test flows.
- Retrieval: pinned public mirror, not an authenticated publisher download. See [data sources](DATA_SOURCES.md).
- Features: 39 numeric + protocol, service, state; one-hot categories and StandardScaler learned only from the fit split.
- Identifiers and labels are removed before encoding.
- 10,279 feature-identical training rows overlapping test are removed. 65,324 duplicate training feature rows are then removed, keeping the first source occurrence. Conflicting labels on identical features are consequently represented by the first occurrence; this is a limitation of that cleanup rule.
- Fit / validation: 79,790 / 19,948, stratified with seed 42. Removing duplicates before this split prevents identical feature rows appearing on both sides.
- The original test split retains its 28,386 duplicate feature rows to preserve the published evaluation population. Thus metrics describe flows, not 82,332 statistically independent observations.
- Test features are inspected only for schema checks and overlap exclusion. Test targets are not used for fitting, hyperparameter selection, or threshold choice. This duplicate-cleaned protocol is different from papers that train on the entire unfiltered split.

## Models and selection

XGBoost: 240 trees, depth 6, learning rate 0.12, histogram training, 0.85 row and feature subsampling. Two predetermined weighting strategies are compared on validation macro F1: unweighted (0.7074) and square-root balanced (0.7336). The latter is selected.

Isolation Forest: 160 trees, trained exclusively on normal fit rows. The anomaly cutoff is the 1st percentile of raw anomaly scores on 10,289 validation normals. An anomaly candidate additionally requires the classifier to predict Normal.

Review policy: attack score at or above the validation-normal 99th percentile (0.9418844), or an anomaly candidate. Calibration and model selection share the validation partition; reported test results use neither training nor validation rows.

The test set was evaluated during development. It is a held-out benchmark, not a blinded external audit. A new independent dataset is required before claims of generalization.

## Results and interpretation

Source of truth: [evaluation.json](../artifacts/evaluation.json). Independently reloaded and recomputed: [verification/evaluation.json](../verification/evaluation.json).

| Operating point | Attack recall | False-positive rate | Precision |
|---|---:|---:|---:|
| Any non-Normal class prediction | 98.86% | 33.41% | 78.38% |
| Analyst review policy | 89.42% | 4.52% | 96.04% |

Multiclass accuracy: 72.89%; macro F1: 0.538; majority baseline: 44.94%. The review policy changes queue membership, not class predictions.

- Analysis recall: 8.27%; Backdoor recall: 9.26%. Do not present this as reliable classification of those attacks.
- Worms has 44 test rows; its 61.36% recall is based on a small sample.
- Anomaly-only false positives among held-out normals: 1.14%; the joint Normal-plus-anomaly candidate rate: 1.02%.
- Review recall of 89.42% means about 10.58% of labelled attack flows do not enter the queue. A low score is not proof of safety.
- Scores are not probability-calibrated. Risk is a weighted heuristic; a score of 80 does not mean an 80% probability of an attack.

## Explanations

Per-flow TreeSHAP comes directly from XGBoost's native contribution calculation. All contributions plus the base value sum to the predicted class's raw margin; tests check this property. The dashboard displays the six largest absolute contributions, including negative ones.

Global gain is separately exposed for model-wide inspection. Neither global gain nor SHAP establishes causality, exploit identity, or correctness.

## Limitations and failure modes

1. A 2015 lab benchmark does not establish performance on modern encrypted enterprise traffic.
2. These engineered features require an upstream flow extractor consistent with the benchmark. No such live capture adapter is included.
3. A normal-class outlier is a candidate for investigation, not evidence of a zero-day exploit.
4. Dataset imbalance and label ambiguity degrade several classes. Operational prevalence changes precision.
5. Unseen categorical values use all-zero encoding and are disclosed; extreme-but-valid numeric values may be out of distribution.
6. The two engines and XAI run on CPU; timings are local sequential measurements, not throughput or concurrency guarantees.
7. Serialized sklearn objects must be trusted. Hashes detect corruption relative to the bundled manifest; they do not authenticate a maliciously replaced bundle.
8. The application has no authentication, durable incident store, packet capture, SIEM integration, or automated containment.
9. Narrative text is LLM-generated prose describing the model's own output; it is not an independent judgment and should be read alongside the raw evidence panel, not in place of it.

## Next experiments

Before operational use: acquire authorized contemporary traffic, define false-alarm budgets with analysts, evaluate on a second network/dataset, assess probability calibration, measure end-to-end ingestion latency, add authenticated ingestion and durable audit records, and validate the feature extractor. Do not optimize repeated experiments on this held-out test split.
