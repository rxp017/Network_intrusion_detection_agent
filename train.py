#!/usr/bin/env python3
"""
train.py -- end-to-end training pipeline for UNSW-NB15 intrusion detection.

Run it from the directory that contains the two dataset files:

    python train.py

Expected inputs (working directory):
    UNSW_NB15_training-set.csv
    UNSW_NB15_testing-set.csv

What it produces (all under ./artifacts/):
    scaler.pkl             fitted StandardScaler for the numeric features
    columns.json           final post-encoding training column order
    numeric_columns.json   (convenience) raw columns the scaler applies to
    classifier.pkl         XGBoost multiclass 'attack_cat' classifier
    label_encoder.pkl      (convenience) int <-> attack_cat name mapping
    isoforest.pkl          IsolationForest fitted on normal traffic only;
                           .decision_function() = anomaly score
                           (more negative = more anomalous)
    class_report.json      per-class precision/recall/f1 on the test set
    explainability.json    top-8 features per attack_cat
    limitations.json       classes with fewer than 50 test samples

Dependencies: pandas, numpy, scikit-learn, xgboost, joblib. No deep learning.
Hyper-parameters are deliberately conservative so the whole script finishes
well inside 5 minutes on a laptop CPU.
"""

import json
import os
import sys
import time

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.ensemble import IsolationForest
from sklearn.metrics import accuracy_score, classification_report
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.utils.class_weight import compute_sample_weight

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
TRAIN_CSV = "UNSW_NB15_training-set.csv"
TEST_CSV = "UNSW_NB15_testing-set.csv"
ARTIFACT_DIR = "artifacts"

TARGET_BINARY = "label"        # 0 = normal, 1 = attack
TARGET_MULTI = "attack_cat"   # multiclass target, includes "Normal"
NORMAL_CLASS = "Normal"

RANDOM_STATE = 42
TOP_K_FEATURES = 8            # features per class in explainability.json
LOW_SUPPORT_THRESHOLD = 50    # test samples below this -> limitations.json

_T0 = time.time()


def log(msg):
    """Timestamped progress print."""
    print(f"[{time.time() - _T0:7.1f}s] {msg}", flush=True)


def artifact(fname):
    return os.path.join(ARTIFACT_DIR, fname)


def save_json(obj, path):
    """json.dump with transparent numpy-scalar conversion."""
    def _to_native(o):
        if isinstance(o, np.generic):        # np.float32 / np.int64 / ...
            return o.item()
        raise TypeError(f"{type(o).__name__} is not JSON serializable")

    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, default=_to_native)
    log(f"Saved {path}")


# --------------------------------------------------------------------------
# 1) Loading and validation
# --------------------------------------------------------------------------
def load_csv(path):
    """Load one UNSW-NB15 CSV; exit with a clear message on failure."""
    try:
        df = pd.read_csv(path)
    except FileNotFoundError:
        print(f"\nERROR: '{path}' was not found in the working directory "
              f"({os.getcwd()}).\n"
              "This script expects both UNSW-NB15 files to sit next to it:\n"
              f"  - {TRAIN_CSV}\n"
              f"  - {TEST_CSV}\n"
              "Download them (UNSW Canberra / Kaggle mirror), place them "
              "here, and re-run.")
        sys.exit(1)
    except (pd.errors.ParserError, pd.errors.EmptyDataError) as exc:
        print(f"\nERROR: '{path}' could not be parsed as a CSV: {exc}")
        sys.exit(1)
    log(f"Loaded {path}: {len(df):,} rows x {df.shape[1]} columns")
    return df


def drop_id_and_validate(df, name):
    """Drop 'id' if present; require both target columns or exit cleanly."""
    if "id" in df.columns:
        df = df.drop(columns="id")
        log(f"{name}: dropped 'id' column")

    missing = [c for c in (TARGET_BINARY, TARGET_MULTI) if c not in df.columns]
    if missing:
        print(f"\nERROR: {name} is missing required target column(s): "
              f"{missing}")
        print(f"All available columns in the {name} ({len(df.columns)}):")
        for c in df.columns:
            print(f"    - {c!r}")
        print(f"\nBoth '{TARGET_BINARY}' (binary) and '{TARGET_MULTI}' "
              "(multiclass) are required; cannot continue.")
        sys.exit(1)
    return df


# --------------------------------------------------------------------------
# 2) Feature engineering (auto-detected, nothing hardcoded)
# --------------------------------------------------------------------------
def _is_categorical_dtype(series):
    kind = str(series.dtype)
    return kind in ("object", "category", "str") or kind.startswith("string")


def build_feature_matrices(train_df, test_df):
    """
    Split features from targets, one-hot encode categorical features
    (auto-detected by dtype) and scale numeric ones. The scaler is fitted
    on TRAIN only (no test leakage). The test set is reindexed to the exact
    final training column list; missing dummy columns are filled with 0.
    """
    feature_cols = [c for c in train_df.columns
                    if c not in (TARGET_BINARY, TARGET_MULTI)]

    missing_in_test = [c for c in feature_cols if c not in test_df.columns]
    if missing_in_test:
        print(f"ERROR: test set is missing training feature column(s): "
              f"{missing_in_test}")
        sys.exit(1)

    cat_cols = [c for c in feature_cols if _is_categorical_dtype(train_df[c])]
    num_cols = [c for c in feature_cols if c not in cat_cols]
    log(f"Auto-detected {len(cat_cols)} categorical feature(s) {cat_cols} "
        f"and {len(num_cols)} numeric feature(s)")

    X_train_raw = train_df[feature_cols]
    X_test_raw = test_df[feature_cols]

    # ---- scale numeric columns (fit on train only) ----------------------
    scaler = StandardScaler()
    Xtr_num = pd.DataFrame(scaler.fit_transform(X_train_raw[num_cols]),
                           columns=num_cols, index=X_train_raw.index)
    Xte_num = pd.DataFrame(scaler.transform(X_test_raw[num_cols]),
                          columns=num_cols, index=X_test_raw.index)

    # ---- one-hot encode categorical columns ------------------------------
    Xtr_dum = pd.get_dummies(X_train_raw[cat_cols], columns=cat_cols,
                             dtype=float)
    Xte_dum = pd.get_dummies(X_test_raw[cat_cols], columns=cat_cols,
                             dtype=float)

    X_train = pd.concat([Xtr_num, Xtr_dum], axis=1)
    final_columns = list(X_train.columns)      # canonical column order

    # ---- align the test set to the training columns ---------------------
    X_test_pre = pd.concat([Xte_num, Xte_dum], axis=1)
    filled_cols = [c for c in final_columns if c not in X_test_pre.columns]
    dropped_cols = [c for c in X_test_pre.columns
                    if c not in set(final_columns)]
    X_test = X_test_pre.reindex(columns=final_columns, fill_value=0)
    if filled_cols:
        log(f"Filled {len(filled_cols)} dummy column(s) absent from the "
            f"test set with 0 (e.g., {filled_cols[:5]})")
    if dropped_cols:
        log(f"Dropped {len(dropped_cols)} test-only dummy column(s) "
            f"(categories unseen in training, e.g., {dropped_cols[:5]})")

    # ---- safety net: no NaN may reach the models ------------------------
    for name, X in (("training", X_train), ("test", X_test)):
        n_nan = int(X.isna().sum().sum())
        if n_nan:
            log(f"WARNING: filled {n_nan:,} missing value(s) in {name} "
                "features with 0")
    X_train = X_train.fillna(0.0).astype(np.float32)
    X_test = X_test.fillna(0.0).astype(np.float32)

    log(f"Feature matrices: train {X_train.shape}, test {X_test.shape}")
    return X_train, X_test, final_columns, scaler, num_cols


# --------------------------------------------------------------------------
# Main pipeline
# --------------------------------------------------------------------------
def main():
    os.makedirs(ARTIFACT_DIR, exist_ok=True)

    # ---- step 1: load ----------------------------------------------------
    log("Step 1/7: loading UNSW-NB15 CSVs")
    train_df = load_csv(TRAIN_CSV)
    test_df = load_csv(TEST_CSV)
    train_df = drop_id_and_validate(train_df, "training set")
    test_df = drop_id_and_validate(test_df, "test set")

    # defensive trim of the multiclass target strings
    for df in (train_df, test_df):
        df[TARGET_MULTI] = df[TARGET_MULTI].astype(str).str.strip()

    y_label_train = train_df[TARGET_BINARY]
    y_label_test = test_df[TARGET_BINARY]
    y_attack_train = train_df[TARGET_MULTI]
    y_attack_test = test_df[TARGET_MULTI]

    # ---- step 2: features ------------------------------------------------
    log("Step 2/7: encoding categorical features + scaling numeric ones")
    X_train, X_test, final_columns, scaler, num_cols = \
        build_feature_matrices(train_df, test_df)

    joblib.dump(scaler, artifact("scaler.pkl"))
    save_json(final_columns, artifact("columns.json"))
    # convenience for inference: which columns scaler.pkl must be applied
    # to (every other column in columns.json is a 0/1 dummy)
    save_json(num_cols, artifact("numeric_columns.json"))

    # ---- step 3: XGBoost on attack_cat ------------------------------------
    log("Step 3/7: training XGBoost classifier on 'attack_cat'")
    t = time.time()
    # Explicit label encoding keeps compatibility across xgboost versions;
    # the fitted encoder is saved so integer predictions map back to names.
    label_enc = LabelEncoder()
    y_train_enc = label_enc.fit_transform(y_attack_train)
    log(f"{len(label_enc.classes_)} classes: "
        f"{', '.join(map(str, label_enc.classes_))}")

    # class imbalance: 'balanced' sample weights (rarer classes upweighted)
    sample_weight = compute_sample_weight("balanced", y_attack_train)
    log(f"Sample weights: min={sample_weight.min():.3f}, "
        f"max={sample_weight.max():.3f}")

    classifier = xgb.XGBClassifier(
        n_estimators=200,        # conservative for the <5 min CPU budget;
        max_depth=6,             # raise these for more accuracy if you like
        learning_rate=0.2,
        subsample=0.8,
        colsample_bytree=0.8,
        tree_method="hist",      # fast histogram split finding on CPU
        n_jobs=-1,
        random_state=RANDOM_STATE,
    )
    classifier.fit(X_train, y_train_enc, sample_weight=sample_weight)
    joblib.dump(classifier, artifact("classifier.pkl"))
    joblib.dump(label_enc, artifact("label_encoder.pkl"))
    log(f"XGBoost fit done in {time.time() - t:.1f}s")

    # ---- step 4: IsolationForest on normal traffic ------------------------
    log("Step 4/7: training IsolationForest on normal (label == 0) traffic")
    t = time.time()
    normal_train_mask = (y_label_train == 0)
    n_normal = int(normal_train_mask.sum())
    if n_normal == 0:
        print("ERROR: training set contains no rows with label == 0 "
              "(normal traffic); IsolationForest cannot be trained.")
        sys.exit(1)
    isoforest = IsolationForest(
        n_estimators=200,
        contamination="auto",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    isoforest.fit(X_train.loc[normal_train_mask])   # normal rows ONLY
    joblib.dump(isoforest, artifact("isoforest.pkl"))
    log(f"IsolationForest fitted on {n_normal:,} normal rows in "
        f"{time.time() - t:.1f}s")

    # Sanity check on the held-out test set. decision_function() is the
    # anomaly score used at inference: more negative = more anomalous.
    anomaly_scores = isoforest.decision_function(X_test)
    normal_test = (y_label_test == 0).to_numpy()
    if normal_test.any() and (~normal_test).any():
        log("Anomaly-score sanity check on test set: mean score "
            f"normal={anomaly_scores[normal_test].mean():+.4f} | "
            f"attack={anomaly_scores[~normal_test].mean():+.4f} "
            "(more negative = more anomalous)")

    # ---- anomaly bounds & zero-day calibration -----------------------------
    # 1. Compute anomaly_bounds from the training set's normal rows
    normal_train_scores = isoforest.decision_function(X_train.loc[normal_train_mask])
    b_min, b_max = float(np.min(normal_train_scores)), float(np.max(normal_train_scores))
    anomaly_bounds = {"min": b_min, "max": b_max}
    save_json(anomaly_bounds, artifact("anomaly_bounds.json"))

    # 2. Compute zero-day heuristic false-positive rate on held-out normal test rows
    normal_test_scores = isoforest.decision_function(X_test.loc[y_label_test == 0])
    denom = (b_max - b_min) if b_max > b_min else 1.0
    norm_normal_test = np.clip((b_max - normal_test_scores) / denom, 0.0, 1.0)
    zero_day_fpr = float(np.mean(norm_normal_test >= 0.75))
    n_normal_test = int(len(normal_test_scores))
    zero_day_calibration = {
        "threshold": 0.75,
        "false_positive_rate_on_held_out_normal": zero_day_fpr,
        "sample_size": n_normal_test,
    }

    # ---- step 5: evaluate --------------------------------------------------
    log("Step 5/7: evaluating classifier on the test set")
    y_pred = label_enc.inverse_transform(
        np.asarray(classifier.predict(X_test), dtype=int))
    accuracy = accuracy_score(y_attack_test, y_pred)
    print(f"\nTest accuracy: {accuracy:.4f}\n")

    report_labels = sorted(set(map(str, label_enc.classes_))
                           | set(map(str, y_attack_test.unique())))
    print(classification_report(y_attack_test, y_pred,
                                labels=report_labels, zero_division=0))
    report_dict = classification_report(y_attack_test, y_pred,
                                        labels=report_labels,
                                        zero_division=0, output_dict=True)
    save_json(report_dict, artifact("class_report.json"))

    # ---- step 6: per-class top features ------------------------------------
    log("Step 6/7: ranking top features per attack class")
    # score(feature) = global XGBoost importance(feature)
    #               * |mean(feature | class) - mean(feature | reference)|
    # Reference is the 'Normal' rows for attack classes. For the 'Normal'
    # class itself the difference to itself would be identically zero, so
    # its reference is the mean over all attack rows instead.
    global_importance = pd.Series(classifier.feature_importances_,
                                  index=final_columns, dtype=float)
    class_means = X_train.groupby(y_attack_train.to_numpy()).mean()

    if NORMAL_CLASS in class_means.index:
        normal_mean = class_means.loc[NORMAL_CLASS]
    else:
        log(f"WARNING: no '{NORMAL_CLASS}' class in training data; using "
            "overall feature means as the reference instead")
        normal_mean = X_train.mean(axis=0)

    is_attack = (y_attack_train.to_numpy() != NORMAL_CLASS)
    attacks_mean = (X_train[is_attack].mean(axis=0)
                    if is_attack.any() else None)

    explainability = {}
    for cls in map(str, label_enc.classes_):
        if cls == NORMAL_CLASS:
            if attacks_mean is not None:
                scores = global_importance * \
                    (class_means.loc[cls] - attacks_mean).abs()
            else:                       # degenerate: no attack rows at all
                scores = global_importance
        else:
            scores = global_importance * \
                (class_means.loc[cls] - normal_mean).abs()
        top = scores.sort_values(ascending=False).head(TOP_K_FEATURES)
        explainability[cls] = [{"feature": feat, "importance": float(val)}
                                for feat, val in top.items()]
        preview = ", ".join(f"{feat} ({val:.3f})"
                            for feat, val in top.head(3).items())
        log(f"  {cls:<15} top-3: {preview}")
    save_json(explainability, artifact("explainability.json"))

    # ---- step 7: low-support classes ---------------------------------------
    log("Step 7/7: flagging classes with low test support")
    train_counts = y_attack_train.value_counts()
    test_counts = y_attack_test.value_counts()
    all_classes = sorted(set(map(str, label_enc.classes_))
                         | set(map(str, y_attack_test.unique())))

    low_confidence = []
    for cls in all_classes:
        support = int(test_counts.get(cls, 0))
        if support < LOW_SUPPORT_THRESHOLD:
            low_confidence.append({"attack_cat": cls, "test_support": support})
    save_json({"low_confidence_classes": low_confidence,
               "zero_day_calibration": zero_day_calibration},
              artifact("limitations.json"))
    if low_confidence:
        print(f"\nLow-confidence classes (< {LOW_SUPPORT_THRESHOLD} test "
              "samples):")
        for item in low_confidence:
            print(f"  - {item['attack_cat']}: {item['test_support']} "
                  "test samples")
    else:
        print(f"\nAll classes have >= {LOW_SUPPORT_THRESHOLD} test samples.")

    # ---- final summary ------------------------------------------------------
    print("\n" + "=" * 66)
    print("FINAL SUMMARY")
    print("=" * 66)
    print(f"Classes found ({len(all_classes)}): "
          f"{', '.join(all_classes)}\n")
    print(f"{'attack_cat':<16}{'train rows':>12}{'test rows':>12}")
    print("-" * 40)
    for cls in all_classes:
        print(f"{cls:<16}"
              f"{int(train_counts.get(cls, 0)):>12,}"
              f"{int(test_counts.get(cls, 0)):>12,}")
    print("-" * 40)
    print(f"{'TOTAL':<16}{len(train_df):>12,}{len(test_df):>12,}")

    print(f"\nXGBoost multiclass test accuracy : {accuracy:.4f}")
    print(f"IsolationForest trained on       : {n_normal:,} normal rows "
          "(anomaly score = decision_function, lower = more anomalous)")
    print(f"IsolationForest anomaly bounds   : min={anomaly_bounds['min']:+.4f}, "
          f"max={anomaly_bounds['max']:+.4f} (from training normal rows)")
    print(f"Zero-day heuristic test FPR      : {zero_day_fpr:.4f} "
          f"({zero_day_fpr * 100:.2f}% of {n_normal_test:,} normal test rows score >= 0.75)")

    artifacts = [
        ("scaler.pkl", "fitted StandardScaler for numeric features"),
        ("columns.json", "final post-encoding column order"),
        ("numeric_columns.json", "columns scaler.pkl applies to (extra)"),
        ("label_encoder.pkl", "attack_cat <-> int mapping (extra)"),
        ("classifier.pkl", "XGBoost attack_cat classifier"),
        ("isoforest.pkl", "IsolationForest on normal traffic"),
        ("anomaly_bounds.json", "min/max anomaly scores on normal rows"),
        ("class_report.json", "per-class precision/recall/f1"),
        ("explainability.json", "top-8 features per class"),
        ("limitations.json", "classes with low test support"),
    ]
    print("\nArtifacts written to './artifacts':")
    for fname, desc in artifacts:
        path = artifact(fname)
        if os.path.exists(path):
            size_kb = os.path.getsize(path) / 1024.0
            print(f"  - {fname:<22}{size_kb:>10,.1f} KB   {desc}")
        else:
            print(f"  - {fname:<22}{'MISSING':>10}   {desc}")

    log("All done.")


if __name__ == "__main__":
    main() 