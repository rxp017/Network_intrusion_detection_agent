"""Independently recompute held-out metrics and time loaded-model inference."""

import hashlib
import json
import platform
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, f1_score

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from model import ROOT, STRIPPED_COLUMNS, ModelBundle  # noqa: E402


def main():
    model = ModelBundle()
    source = model.metadata["dataset_source"]
    path = ROOT / "data" / "raw" / source["actual_split_files"]["testing"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == source["actual_split_hashes"]["testing"]
    frame = pd.read_csv(path)
    features = model.encode_batch(frame)
    probabilities = model.classifier.predict_proba(features)
    prediction = np.asarray(model.classes)[probabilities.argmax(axis=1)]
    anomalies = model.isoforest.decision_function(features)
    attack = 1 - probabilities[:, model.classes.index("Normal")]
    candidate = (prediction == "Normal") & (anomalies < model.metadata["anomaly_threshold"])
    review = (attack >= model.metadata["review_threshold"]) | candidate
    actual = {
        "accuracy": float(accuracy_score(frame.attack_cat, prediction)),
        "macro_f1": float(f1_score(frame.attack_cat, prediction, average="macro")),
        "review_recall": float(review[frame.label == 1].mean()),
        "review_false_positive_rate": float(review[frame.label == 0].mean()),
    }
    assert np.isclose(actual["accuracy"], model.evaluation["accuracy"])
    assert np.isclose(actual["macro_f1"], model.evaluation["macro_f1"])
    assert np.isclose(actual["review_recall"], model.evaluation["review_policy"]["test_recall"])
    assert np.isclose(
        actual["review_false_positive_rate"], model.evaluation["review_policy"]["test_false_positive_rate"]
    )
    replay = pd.read_csv(ROOT / "data" / "replay.csv").drop(columns=list(STRIPPED_COLUMNS)).head(100)
    latencies = []
    for row in replay.to_dict("records"):
        start = time.perf_counter()
        model.score_row(row)
        latencies.append(1000 * (time.perf_counter() - start))
    output = {
        "model_id": model.model_id,
        "test_rows": len(frame),
        "recomputed": actual,
        "runtime": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "cpu": platform.processor(),
        },
        "single_flow_with_shap_ms": {
            "samples": len(latencies),
            "median": float(np.median(latencies)),
            "p95": float(np.percentile(latencies, 95)),
        },
        "measurement_scope": "Local sequential inference, includes encoding and TreeSHAP; not a network throughput benchmark.",
    }
    target = ROOT / "verification" / "evaluation.json"
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
