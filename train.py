"""Reproducible benchmark training. No test-set tuning; see docs/MODEL_CARD.md."""

import argparse
import hashlib
import json
import platform
import shutil
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
import xgboost as xgb
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from model import ROOT, STRIPPED_COLUMNS, FeatureEncoder

SEED = 42


def save_json(path, obj):
    Path(path).write_text(json.dumps(obj, indent=2, allow_nan=False), encoding="utf-8", newline="\n")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def validate(frame, name):
    if frame.empty or not {"label", "attack_cat", "proto", "service", "state"}.issubset(frame):
        raise ValueError(f"{name}: empty or missing required columns")
    if frame.isna().any().any():
        raise ValueError(f"{name}: missing values must be resolved explicitly")
    frame["attack_cat"] = frame["attack_cat"].str.strip()
    if not (frame["label"] == (frame["attack_cat"] != "Normal").astype(int)).all():
        raise ValueError(f"{name}: binary and multiclass targets disagree")
    numeric = frame.drop(columns=["proto", "service", "state", "attack_cat"])
    if not np.isfinite(numeric.to_numpy(dtype=float)).all() or (numeric < 0).any().any():
        raise ValueError(f"{name}: non-finite or negative features")
    return frame


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=ROOT / "data" / "raw")
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts")
    parser.add_argument("--replay-output", type=Path, default=ROOT / "data" / "replay.csv")
    args = parser.parse_args()
    started = time.perf_counter()
    paths = {s: args.data_dir / f"UNSW_NB15_{s}-set.csv" for s in ("training", "testing")}
    frames = {s: validate(pd.read_csv(p), s) for s, p in paths.items()}
    if len(frames["training"]) == 82332 and len(frames["testing"]) == 175341:
        print("Mirror filenames reversed; using published 175341/82332 split sizes.", flush=True)
        frames["training"], frames["testing"] = frames["testing"], frames["training"]
        paths["training"], paths["testing"] = paths["testing"], paths["training"]
    train, test = frames["training"], frames["testing"]
    print(f"Loaded training={len(train):,}; test={len(test):,}", flush=True)
    if len(train) != 175341 or len(test) != 82332:
        raise ValueError(
            "Expected published split sizes: 175341 training, 82332 test. Refusing demo or swapped splits."
        )
    features = [c for c in train if c not in STRIPPED_COLUMNS]
    if len(features) != 42 or set(features) != set(test.columns) - set(STRIPPED_COLUMNS):
        raise ValueError("Expected matching 42-feature schemas")
    train_hashes = pd.util.hash_pandas_object(train[features], index=False)
    test_hashes = pd.util.hash_pandas_object(test[features], index=False)
    overlap = test_hashes.isin(set(train_hashes))
    # Remove exact feature duplicates crossing the split BEFORE fitting any model.
    train = train.loc[~train_hashes.isin(set(test_hashes))].copy()
    removed = len(frames["training"]) - len(train)
    duplicate_train_rows = int(train.duplicated(features).sum())
    train = train.drop_duplicates(features).copy()
    fit, calibration = train_test_split(train, test_size=0.2, random_state=SEED, stratify=train.attack_cat)
    encoder = FeatureEncoder().fit(fit)
    x_fit, x_cal, x_test = [encoder.transform(f) for f in (fit, calibration, test)]
    label_encoder = LabelEncoder().fit(fit.attack_cat)
    classes = list(label_encoder.classes_)
    y_fit = label_encoder.transform(fit.attack_cat)
    counts = fit.attack_cat.value_counts()
    weights = np.sqrt(len(fit) / (len(classes) * fit.attack_cat.map(counts).to_numpy()))
    print("Training classifier on fit partition (80%); test set is never used for fitting.", flush=True)
    candidates = []
    validation_trials = []
    for name, candidate_weights in (("unweighted", None), ("sqrt_balanced", weights)):
        candidate = xgb.XGBClassifier(
            n_estimators=240,
            max_depth=6,
            learning_rate=0.12,
            subsample=0.85,
            colsample_bytree=0.85,
            tree_method="hist",
            n_jobs=4,
            random_state=SEED,
            eval_metric="mlogloss",
        )
        candidate.fit(x_fit, y_fit, sample_weight=candidate_weights)
        cal_prediction = label_encoder.inverse_transform(candidate.predict(x_cal).astype(int))
        score = float(f1_score(calibration.attack_cat, cal_prediction, average="macro"))
        validation_trials.append({"weighting": name, "validation_macro_f1": score})
        candidates.append(candidate)
        print(f"Validation {name}: macro F1={score:.4f}", flush=True)
    selected_index = int(np.argmax([t["validation_macro_f1"] for t in validation_trials]))
    classifier = candidates[selected_index]
    forest = IsolationForest(n_estimators=160, contamination="auto", n_jobs=2, random_state=SEED)
    forest.fit(x_fit.loc[fit.label == 0])
    normal_cal = x_cal.loc[calibration.label == 0]
    # Retain the complete calibration distribution for identical serving percentiles.
    reference = np.sort(forest.decision_function(normal_cal))
    threshold = float(np.quantile(reference, 0.01))
    cal_attack_scores = 1 - classifier.predict_proba(normal_cal)[:, classes.index("Normal")]
    review_threshold = float(np.quantile(cal_attack_scores, 0.99))
    print("Evaluating untouched test split.", flush=True)
    probas = classifier.predict_proba(x_test)
    predictions = label_encoder.inverse_transform(probas.argmax(axis=1))
    anomaly = forest.decision_function(x_test)
    binary_truth = (test.label == 1).to_numpy()
    binary_predictions = predictions != "Normal"
    tn, fp, fn, tp = confusion_matrix(binary_truth, binary_predictions, labels=[False, True]).ravel()
    report = classification_report(
        test.attack_cat, predictions, labels=classes, output_dict=True, zero_division=0
    )
    normal = ~binary_truth
    candidates = (predictions == "Normal") & (anomaly < threshold)
    review = (1 - probas[:, classes.index("Normal")] >= review_threshold) | candidates
    review_tp, review_fp = int(np.sum(review & binary_truth)), int(np.sum(review & normal))
    majority = str(fit.attack_cat.mode()[0])
    majority_accuracy = float(np.mean(test.attack_cat == majority))
    evaluation = {
        "dataset": "UNSW-NB15 public mirror, published train/test split",
        "test_rows": len(test),
        "fit_rows": len(fit),
        "calibration_rows": len(calibration),
        "accuracy": float(accuracy_score(test.attack_cat, predictions)),
        "macro_f1": report["macro avg"]["f1-score"],
        "weighted_f1": report["weighted avg"]["f1-score"],
        "majority_baseline": {"class": majority, "accuracy": majority_accuracy},
        "binary_detection": {
            "precision": float(tp / max(tp + fp, 1)),
            "recall": float(tp / max(tp + fn, 1)),
            "false_positive_rate": float(fp / max(fp + tn, 1)),
            "roc_auc": float(roc_auc_score(binary_truth, 1 - probas[:, classes.index("Normal")])),
            "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
        },
        "anomaly": {
            "threshold": threshold,
            "target_calibration_fpr": 0.01,
            "normal_calibration_rows": len(reference),
            "test_anomaly_only_fpr": float(np.mean(anomaly[normal] < threshold)),
            "test_joint_candidate_fpr": float(np.mean(candidates[normal])),
            "test_joint_candidate_count": int(candidates.sum()),
        },
        "review_policy": {
            "rule": "P(attack) >= validation-normal 99th percentile OR anomaly candidate",
            "attack_score_threshold": review_threshold,
            "target_classifier_calibration_fpr": 0.01,
            "test_recall": float(review_tp / binary_truth.sum()),
            "test_false_positive_rate": float(review_fp / normal.sum()),
            "test_precision": float(review_tp / max(review_tp + review_fp, 1)),
            "test_review_count": int(review.sum()),
            "note": "Queue policy does not change raw class predictions or certify unqueued flows as safe.",
        },
        "classes": classes,
        "class_report": report,
        "selection": {
            "criterion": "Highest validation macro F1; no test-set model selection",
            "trials": validation_trials,
            "selected": validation_trials[selected_index]["weighting"],
        },
        "confusion_matrix": confusion_matrix(test.attack_cat, predictions, labels=classes).tolist(),
        "data_audit": {
            "original_train_rows": len(frames["training"]),
            "test_rows_overlapping_original_train": int(overlap.sum()),
            "removed_train_rows_overlapping_test": removed,
            "remaining_cross_split_overlap": 0,
            "removed_within_train_duplicate_feature_rows": duplicate_train_rows,
            "train_duplicate_feature_rows": int(train.duplicated(features).sum()),
            "test_duplicate_feature_rows": int(test.duplicated(features).sum()),
        },
        "calibration_accuracy": float(
            accuracy_score(
                calibration.attack_cat, label_encoder.inverse_transform(classifier.predict(x_cal).astype(int))
            )
        ),
    }
    source = json.loads((args.data_dir / "source.json").read_text(encoding="utf-8"))
    source["actual_split_hashes"] = {s: digest(p) for s, p in paths.items()}
    source["actual_split_files"] = {s: p.name for s, p in paths.items()}
    metadata = {
        "classes": classes,
        "seed": SEED,
        "dataset_source": source,
        "normal_calibration_scores": reference.tolist(),
        "anomaly_threshold": threshold,
        "review_threshold": review_threshold,
        "risk_formula": "round(60 * (1 - P(Normal)) + 40 * benign_anomaly_percentile)",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "versions": {
            "python": platform.python_version(),
            "sklearn": sklearn.__version__,
            "xgboost": xgb.__version__,
            "numpy": np.__version__,
            "pandas": pd.__version__,
        },
    }
    importance = pd.Series(classifier.feature_importances_, index=encoder.columns).sort_values(
        ascending=False
    )
    global_features = [{"feature": k, "importance": float(v)} for k, v in importance.head(12).items()]
    limitations = {
        "deployment": "Research prototype; benchmark replay, no live packet capture or automatic blocking.",
        "probabilities": "Uncalibrated classifier scores; risk is an analyst prioritization heuristic.",
        "novelty": "Anomaly candidates are not validated zero-day detections.",
        "explanations": "TreeSHAP is additive in class raw margin, not probability or causation.",
        "low_confidence_classes": [
            {"attack_cat": c, "test_support": int(report[c]["support"]), "recall": report[c]["recall"]}
            for c in classes
            if report[c]["support"] < 100 or report[c]["recall"] < 0.5
        ],
        "generalization": "A 2015 lab benchmark cannot establish performance on today's production networks.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    # Stage the entire bundle before replacing files; manifest is published last.
    with tempfile.TemporaryDirectory(dir=args.output.parent, prefix="training-") as temp:
        stage = Path(temp)
        joblib.dump(encoder, stage / "encoder.pkl")
        joblib.dump(forest, stage / "isoforest.pkl")
        classifier.save_model(stage / "classifier.ubj")
        save_json(stage / "metadata.json", metadata)
        save_json(stage / "evaluation.json", evaluation)
        save_json(
            stage / "explainability.json", {"scope": "Global model gain", "top_features": global_features}
        )
        save_json(stage / "limitations.json", limitations)
        manifest = {"format": 2, "sha256": {p.name: digest(p) for p in sorted(stage.iterdir())}}
        args.output.mkdir(parents=True, exist_ok=True)
        for path in stage.iterdir():
            shutil.copy2(path, args.output / path.name)
        save_json(args.output / "manifest.json", manifest)
    # A deterministic representative sample; selected by ground truth for demo coverage.
    replay = test.groupby("attack_cat", group_keys=False).sample(n=40, random_state=SEED)
    replay = replay.sample(frac=1, random_state=SEED)
    args.replay_output.parent.mkdir(parents=True, exist_ok=True)
    replay.to_csv(args.replay_output, index=False, lineterminator="\n")
    save_json(
        args.replay_output.with_suffix(".json"),
        {
            "source": "40 held-out rows per ground-truth class, shuffled with seed 42",
            "balanced_demo_sample": True,
            "rows": len(replay),
            "sha256": digest(args.replay_output),
            "not_for_metrics": True,
        },
    )
    print(
        json.dumps(
            {k: evaluation[k] for k in ("accuracy", "macro_f1", "binary_detection", "data_audit")}, indent=2
        )
    )
    print(f"Training and evaluation completed in {time.perf_counter() - started:.1f}s", flush=True)


if __name__ == "__main__":
    main()
