"""Shared encoding, validated inference and per-flow TreeSHAP evidence."""

import hashlib
import json
import math
from pathlib import Path
from time import perf_counter

import joblib
import numpy as np
import pandas as pd
import xgboost as xgb
from sklearn.preprocessing import StandardScaler

ROOT = Path(__file__).resolve().parent
STRIPPED_COLUMNS = ("id", "label", "attack_cat")
CATEGORICAL = ("proto", "service", "state")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


class FeatureEncoder:
    """One implementation used by training, evaluation and serving."""

    def fit(self, frame):
        self.numeric_cols = [c for c in frame if c not in (*STRIPPED_COLUMNS, *CATEGORICAL)]
        self.categories = {c: sorted(frame[c].astype(str).unique().tolist()) for c in CATEGORICAL}
        self.scaler = StandardScaler().fit(frame[self.numeric_cols])
        self.columns = self.numeric_cols + [
            f"{c}_{v}" for c, values in self.categories.items() for v in values
        ]
        return self

    def transform(self, frame):
        numeric = self.scaler.transform(frame[self.numeric_cols].astype(float))
        categorical = [
            (frame[c].astype(str).to_numpy() == v).astype(float)
            for c, values in self.categories.items()
            for v in values
        ]
        values = np.column_stack([numeric, *categorical]).astype(np.float32)
        if not np.isfinite(values).all():
            raise ValueError("Features must encode to finite float32 values")
        return pd.DataFrame(values, columns=self.columns, index=frame.index)


class ModelBundle:
    def __init__(self, artifacts_dir=ROOT / "artifacts"):
        self.path = Path(artifacts_dir)
        self.manifest = read_json(self.path / "manifest.json")
        # Integrity, not authenticity: only deserialize trusted local bundles.
        required = {
            "encoder.pkl",
            "isoforest.pkl",
            "classifier.ubj",
            "metadata.json",
            "evaluation.json",
            "explainability.json",
            "limitations.json",
        }
        if not required.issubset(self.manifest["sha256"]):
            raise ValueError("Artifact manifest is incomplete; run train.py")
        for name, expected in self.manifest["sha256"].items():
            if Path(name).name != name:
                raise ValueError("Invalid artifact name")
            if hashlib.sha256((self.path / name).read_bytes()).hexdigest() != expected:
                raise ValueError(f"Artifact integrity failure: {name}; restore or retrain")
        self.encoder = joblib.load(self.path / "encoder.pkl")
        self.isoforest = joblib.load(self.path / "isoforest.pkl")
        self.classifier = xgb.XGBClassifier()
        self.classifier.load_model(self.path / "classifier.ubj")
        self.classifier.set_params(n_jobs=2)
        self.metadata = read_json(self.path / "metadata.json")
        self.classes = self.metadata["classes"]
        self.evaluation = read_json(self.path / "evaluation.json")
        self.explainability = read_json(self.path / "explainability.json")
        self.limitations = read_json(self.path / "limitations.json")
        self.numeric_cols = self.encoder.numeric_cols
        self.columns = self.encoder.columns
        self.required_features = self.numeric_cols + list(CATEGORICAL)
        self.reference_scores = np.asarray(self.metadata["normal_calibration_scores"])
        self.model_id = self.manifest["sha256"]["classifier.ubj"][:12]
        if (
            self.classifier.n_features_in_ != len(self.columns)
            or len(self.classes) != self.classifier.n_classes_
        ):
            raise ValueError("Artifact schema mismatch")

    def validate_row(self, row):
        if not isinstance(row, dict):
            raise ValueError("Each flow must be a JSON object")
        missing = sorted(set(self.required_features) - row.keys())
        extra = sorted(row.keys() - set(self.required_features) - set(STRIPPED_COLUMNS))
        if missing or extra:
            raise ValueError(f"Invalid feature schema. Missing: {missing}; unknown: {extra}")
        clean, warnings = {}, []
        for name in self.numeric_cols:
            value = row[name]
            if isinstance(value, (bool, str)) or value is None:
                raise ValueError(f"{name} must be a finite non-negative number")
            try:
                value = float(value)
            except (TypeError, ValueError, OverflowError) as exc:
                raise ValueError(f"{name} must be numeric") from exc
            if not math.isfinite(value) or value < 0 or value > 1e15:
                raise ValueError(f"{name} must be between 0 and 1e15 and finite")
            clean[name] = value
        for name in CATEGORICAL:
            value = row[name]
            if not isinstance(value, str) or not value.strip() or len(value) > 64:
                raise ValueError(f"{name} must be a nonempty string of at most 64 characters")
            clean[name] = value.strip()
            if clean[name] not in self.encoder.categories[name]:
                warnings.append(f"Unseen {name}: {clean[name]}; encoded as all zeros")
        if set(row).intersection(STRIPPED_COLUMNS):
            warnings.append("id, label and attack_cat are metadata and never used for inference")
        return clean, warnings

    def encode_batch(self, rows):
        frame = rows if isinstance(rows, pd.DataFrame) else pd.DataFrame(rows)
        return self.encoder.transform(frame)

    def score_row(self, raw_row, explain=True):
        start = perf_counter()
        row, warnings = self.validate_row(raw_row)
        features = self.encode_batch([row])
        proba = self.classifier.predict_proba(features)[0]
        predicted_index = int(np.argmax(proba))
        predicted = self.classes[predicted_index]
        raw_anomaly = float(self.isoforest.decision_function(features)[0])
        anomaly = float(np.mean(self.reference_scores >= raw_anomaly))
        attack_probability = float(1 - proba[self.classes.index("Normal")])
        classifier_points, anomaly_points = 60 * attack_probability, 40 * anomaly
        risk = int(round(classifier_points + anomaly_points))
        suspect = predicted == "Normal" and raw_anomaly < self.metadata["anomaly_threshold"]
        review = attack_probability >= self.metadata["review_threshold"] or suspect
        for item in self.limitations["low_confidence_classes"]:
            if item["attack_cat"] == predicted:
                warnings.append(
                    f"Limited reliability for {predicted}: held-out recall {item['recall']:.1%}, support {item['test_support']}"
                )
        result = {
            "model_id": self.model_id,
            "predicted_attack_cat": predicted,
            "confidence": float(proba[predicted_index]),
            "class_probabilities": {c: float(p) for c, p in zip(self.classes, proba, strict=True)},
            "attack_probability": attack_probability,
            "anomaly_score": raw_anomaly,
            "anomaly_percentile": anomaly,
            "risk_score": risk,
            "risk_level": "low"
            if risk < 25
            else "medium"
            if risk < 50
            else "high"
            if risk < 75
            else "critical",
            "risk_components": {"classifier": classifier_points, "anomaly": anomaly_points},
            "is_anomaly_candidate": suspect,
            "review_recommended": bool(review),
            "review_threshold": self.metadata["review_threshold"],
            "warnings": warnings,
            "recommended_action": self.action(predicted, suspect),
        }
        if explain:
            contributions = self.classifier.get_booster().predict(xgb.DMatrix(features), pred_contribs=True)[
                0, predicted_index
            ]
            indices = np.argsort(np.abs(contributions[:-1]))[-6:][::-1]
            result["explanation"] = {
                "method": "TreeSHAP",
                "scope": "This flow; predicted-class raw margin (not probability or causation)",
                "base_margin": float(contributions[-1]),
                "margin": float(contributions.sum()),
                "features": [
                    {
                        "feature": self.columns[i],
                        "contribution": float(contributions[i]),
                        "encoded_value": float(features.iloc[0, i]),
                    }
                    for i in indices
                ],
                "raw_features": row,
            }
        result["inference_ms"] = round((perf_counter() - start) * 1000, 2)
        return result

    @staticmethod
    def action(predicted, suspect):
        if suspect:
            return "Investigate unusual behavior; correlate host and DNS logs. Novelty is not proof of an attack."
        if predicted == "Normal":
            return "Continue monitoring; this prediction does not certify the flow as safe."
        if predicted in ("DoS", "Generic"):
            return "Verify traffic volume and destination impact; review rate limits with an analyst."
        if predicted == "Reconnaissance":
            return "Correlate connection attempts and confirm whether scanning is authorized."
        return "Correlate endpoint and service logs; validate evidence before containment."
