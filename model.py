"""
model.py -- artifact loading + scoring logic for the UNSW-NB15 demo API.

Loads everything train.py wrote to ./artifacts/ and exposes a single scoring
entry point, ModelBundle.score_row(), that every API endpoint shares. ALL
feature engineering lives here (encode_batch), so serving-time encoding can
never drift from what the models were trained on.

Loaded artifacts:
    scaler.pkl           StandardScaler fitted on the training numeric cols
    columns.json         canonical post-encoding column order
    classifier.pkl       XGBoost attack_cat classifier (must be unpickled
                         with the same sklearn/xgboost versions as training)
    isoforest.pkl        IsolationForest fitted on normal traffic only
    class_report.json    test-set metrics (informational, logged at startup)
    explainability.json  per-class top features
    limitations.json     low-test-support classes
    label_encoder.pkl    attack_cat <-> int mapping (extra file saved by
                         train.py). Its class order defines the order of the
                         classifier's predict_proba columns, so it is needed
                         to name the returned probabilities; if absent we
                         fall back to explainability.json key order, which
                         train.py wrote in the same order.
"""

import json
import os

import joblib
import numpy as np
import pandas as pd

NORMAL_CLASS = "Normal"

# Never treated as features, even if present in an incoming row.
STRIPPED_COLUMNS = ("id", "label", "attack_cat")

# ---------------------------------------------------------------------------
# Tunables (with documented provenance)
# ---------------------------------------------------------------------------
# Fallback bounds for normalizing the IsolationForest anomaly score, used
# ONLY when artifacts/anomaly_bounds.json is not readable at startup. These are
# conservative defaults, not measurements: sklearn's
# IsolationForest.decision_function() returns values in roughly (-1, 1) and
# normal traffic typically lands in about [-0.2, 0.3]. When anomaly_bounds.json
# is present, ModelBundle loads the true min/max saved by train.py from the
# training set's normal rows (label == 0) and uses those numbers instead.
DEFAULT_ANOMALY_BOUNDS = (-0.2, 0.3)

# "High anomaly" cutoff on the normalized 0-1 anomaly score for the zero-day
# heuristic. Tunable: 0.75 ~ "more anomalous than ~75% of the normal training
# scores' observed range".
ZERO_DAY_ANOMALY_THRESHOLD = 0.75


def _load_json(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


class ModelBundle:
    """All trained artifacts plus one shared scoring path."""

    def __init__(self, artifacts_dir="artifacts"):
        self.artifacts_dir = artifacts_dir
        self._load_artifacts()
        # min/max decision_function over the training set's NORMAL rows;
        # used to map the raw anomaly score into 0-1 (see _normalize_anomaly)
        self.anomaly_bounds = self._compute_anomaly_bounds()

    # ------------------------------ loading ------------------------------
    def _load_artifacts(self):
        def path(name):
            return os.path.join(self.artifacts_dir, name)

        required = ["scaler.pkl", "columns.json", "classifier.pkl",
                    "isoforest.pkl", "class_report.json",
                    "explainability.json", "limitations.json"]
        missing = [f for f in required if not os.path.exists(path(f))]
        if missing:
            raise FileNotFoundError(
                f"Missing artifact(s) {missing} under "
                f"'{self.artifacts_dir}/'. Run train.py first.")

        self.scaler = joblib.load(path("scaler.pkl"))
        self.columns = _load_json(path("columns.json"))   # canonical order
        self.classifier = joblib.load(path("classifier.pkl"))
        self.isoforest = joblib.load(path("isoforest.pkl"))
        self.class_report = _load_json(path("class_report.json"))
        self.explainability = _load_json(path("explainability.json"))
        self.limitations = _load_json(path("limitations.json"))

        # Class names in the exact order XGBoost's predict_proba columns
        # were fitted. Preferred source: the LabelEncoder saved by train.py;
        # fallback: explainability.json preserves that same insertion order.
        if os.path.exists(path("label_encoder.pkl")):
            encoder = joblib.load(path("label_encoder.pkl"))
            self.classes = [str(c) for c in encoder.classes_]
        else:
            self.classes = list(self.explainability.keys())
        n_model = getattr(self.classifier, "n_classes_", len(self.classes))
        if n_model != len(self.classes):
            raise RuntimeError(
                f"Classifier class count ({n_model}) does not match the loaded class "
                f"names ({len(self.classes)}) -- artifacts are out of sync; re-run train.py.")

        clf_classes = getattr(self.classifier, "classes_", None)
        if clf_classes is not None:
            sorted_classes = np.sort(np.asarray(clf_classes))
            expected = np.arange(len(self.classes))
            if len(sorted_classes) != len(expected):
                raise RuntimeError(
                    f"Classifier class count ({len(sorted_classes)}) does not match "
                    f"the loaded class names ({len(expected)}) -- artifacts are out of sync; re-run train.py.")
            if not np.array_equal(sorted_classes, expected):
                raise RuntimeError(
                    "Classifier class order mismatch: classifier.classes_ "
                    f"{sorted_classes.tolist()} does not match expected integer "
                    f"range 0..{len(expected)-1} -- artifacts are out of sync; re-run train.py.")

        # Numeric feature columns, taken from the fitted scaler itself:
        # StandardScaler records the DataFrame column names it was fit on,
        # so nothing is hardcoded and no extra file is strictly required.
        feature_names = getattr(self.scaler, "feature_names_in_", None)
        if feature_names is None:
            alt = path("numeric_columns.json")  # convenience file from train.py
            if not os.path.exists(alt):
                raise RuntimeError(
                    "Cannot determine numeric columns: scaler has no "
                    "'feature_names_in_' and numeric_columns.json is absent.")
            feature_names = _load_json(alt)
        self.numeric_cols = [str(c) for c in feature_names]
        self.numeric_set = set(self.numeric_cols)

    # ------------------------- feature engineering -----------------------
    def encode_batch(self, raw_rows):
        """
        Replicate train.py's pipeline on RAW rows (a DataFrame with the
        CSV's columns, or a list of dicts / single dict wrapped in a list):
          1. drop id/label/attack_cat if present;
          2. coerce numeric columns (per the scaler's recorded feature
             names) and scale them with the loaded scaler;
          3. one-hot encode everything else exactly like
             pandas.get_dummies (column naming '<col>_<value>');
          4. reindex to columns.json -- missing dummy columns filled with
             0, unknown extra columns dropped, order enforced exactly.
        """
        df = pd.DataFrame(raw_rows)
        df = df.drop(columns=[c for c in STRIPPED_COLUMNS if c in df.columns])

        num_present = [c for c in self.numeric_cols if c in df.columns]
        num = (df[num_present]
               .apply(pd.to_numeric, errors="coerce")   # bad values -> NaN
               .reindex(columns=self.numeric_cols))     # missing cols stay NaN
        num_scaled = (pd.DataFrame(self.scaler.transform(num),
                                   columns=self.numeric_cols, index=num.index)
                      .fillna(0.0))                     # fill NaN in scaled space

        cat_cols = [c for c in df.columns if c not in self.numeric_set]
        dummies = (pd.get_dummies(df[cat_cols], columns=cat_cols, dtype=float)
                   if cat_cols else pd.DataFrame(index=df.index))

        X = pd.concat([num_scaled, dummies], axis=1)
        return (X.reindex(columns=self.columns, fill_value=0.0)
                 .fillna(0.0)
                 .astype(np.float32))

    # ------------------------ anomaly normalization ----------------------
    def _compute_anomaly_bounds(self):
        """
        Load min and max of isoforest.decision_function() over the TRAINING
        set's normal rows (label == 0) from artifacts/anomaly_bounds.json.
        These define the 0-1 mapping: raw == min -> 1.0 (anomalous end of the
        normal range), raw == max -> 0.0. Falls back to DEFAULT_ANOMALY_BOUNDS
        if the file is missing or invalid.
        """
        bounds_path = os.path.join(self.artifacts_dir, "anomaly_bounds.json")
        try:
            bounds = _load_json(bounds_path)
            return (float(bounds["min"]), float(bounds["max"]))
        except (FileNotFoundError, KeyError, json.JSONDecodeError):
            print(f"[model] WARNING: cannot read anomaly bounds from "
                  f"'{bounds_path}'; using fallback anomaly bounds "
                  f"{DEFAULT_ANOMALY_BOUNDS} (provenance in module comments).")
            return DEFAULT_ANOMALY_BOUNDS

    def _normalize_anomaly(self, raw_score):
        """decision_function -> 0-1; more negative -> closer to 1."""
        lo, hi = self.anomaly_bounds
        if hi <= lo:                      # degenerate: constant normal scores
            return 1.0 if raw_score <= lo else 0.0
        return float(np.clip((hi - raw_score) / (hi - lo), 0.0, 1.0))

    # ------------------------------ scoring ------------------------------
    def score_row(self, raw_row: dict) -> dict:
        """
        Score ONE raw feature row (same keys/values as a CSV row, minus
        id/label/attack_cat). Shared response shape for every endpoint:
            predicted_attack_cat, class_probabilities, anomaly_score,
            risk_score, risk_level, is_potential_zero_day
        """
        if not isinstance(raw_row, dict):
            raise TypeError("raw_row must be a dict of raw feature values")

        X = self.encode_batch([raw_row])

        # --- XGBoost: attack_cat prediction + class probabilities --------
        proba = self.classifier.predict_proba(X)[0]
        class_probabilities = {cls: float(p)
                               for cls, p in zip(self.classes, proba)}
        predicted = self.classes[int(np.argmax(proba))]

        # --- IsolationForest: raw anomaly score (more negative = worse) ---
        anomaly_score = float(self.isoforest.decision_function(X)[0])
        anomaly_norm = self._normalize_anomaly(anomaly_score)

        # --- risk score: 100 * (0.6 * max prob over non-Normal classes
        #                      + 0.4 * normalized anomaly score) ------------
        attack_probs = [p for cls, p in zip(self.classes, proba)
                        if cls != NORMAL_CLASS]
        max_attack_prob = float(max(attack_probs)) if attack_probs else 0.0
        risk_score = int(round(100 * (0.6 * max_attack_prob
                                     + 0.4 * anomaly_norm)))

        if risk_score < 25:
            risk_level = "low"
        elif risk_score < 50:
            risk_level = "medium"
        elif risk_score < 75:
            risk_level = "high"
        else:
            risk_level = "critical"

        # --- zero-day heuristic: anomaly detector fires while the
        # classifier still says "Normal" ------------------------------------
        is_potential_zero_day = bool(
            predicted == NORMAL_CLASS
            and anomaly_norm >= ZERO_DAY_ANOMALY_THRESHOLD)

        return {
            "predicted_attack_cat": str(predicted),
            "class_probabilities": class_probabilities,
            "anomaly_score": anomaly_score,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "is_potential_zero_day": is_potential_zero_day,
        }