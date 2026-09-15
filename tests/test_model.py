import json
import shutil

import numpy as np
import pandas as pd
import pytest
import xgboost as xgb

from model import ROOT, ModelBundle


def test_inference_and_shap_additivity(bundle, flow):
    result = bundle.score_row(flow)
    assert sum(result["class_probabilities"].values()) == pytest.approx(1, abs=1e-5)
    assert 0 <= result["risk_score"] <= 100
    assert result["risk_score"] == round(sum(result["risk_components"].values()))
    margins = bundle.classifier.get_booster().predict(
        xgb.DMatrix(bundle.encode_batch([flow])), output_margin=True
    )[0]
    selected = bundle.classes.index(result["predicted_attack_cat"])
    assert result["explanation"]["margin"] == pytest.approx(margins[selected], abs=1e-4)
    assert result["explanation"]["features"]
    assert result["review_recommended"] == (
        result["attack_probability"] >= result["review_threshold"] or result["is_anomaly_candidate"]
    )


def test_labels_do_not_leak(bundle, flow):
    first = bundle.score_row(flow, False)
    second = bundle.score_row({**flow, "attack_cat": "Worms", "label": 1, "id": 99999}, False)
    assert first["class_probabilities"] == second["class_probabilities"]
    assert first["risk_score"] == second["risk_score"]


@pytest.mark.parametrize("bad", [None, True, "12", -1, float("nan"), float("inf"), 1e100, [], {}])
def test_invalid_numeric_features(bundle, flow, bad):
    with pytest.raises(ValueError):
        bundle.score_row({**flow, "dur": bad})


@pytest.mark.parametrize("bad", [None, "", " " * 10, "x" * 65, 3, []])
def test_invalid_categorical_features(bundle, flow, bad):
    with pytest.raises(ValueError):
        bundle.score_row({**flow, "proto": bad})


def test_unseen_category_is_disclosed(bundle, flow):
    result = bundle.score_row({**flow, "proto": "unknown-protocol"}, False)
    assert any("Unseen proto" in warning for warning in result["warnings"])


def test_batch_and_single_encoding_agree(bundle, flow):
    combined = bundle.encode_batch([flow, {**flow, "proto": "new-protocol"}])
    np.testing.assert_array_equal(combined.iloc[0], bundle.encode_batch([flow]).iloc[0])
    assert not set(("id", "label", "attack_cat")).intersection(bundle.columns)


def test_manifest_detects_corruption_before_pickle(tmp_path):
    shutil.copytree(ROOT / "artifacts", tmp_path / "artifacts")
    (tmp_path / "artifacts" / "encoder.pkl").write_bytes(b"corrupted")
    with pytest.raises(ValueError, match="integrity failure"):
        ModelBundle(tmp_path / "artifacts")


def test_model_evidence_consistency(bundle):
    evaluation = bundle.evaluation
    assert evaluation["test_rows"] == 82332
    assert sum(map(sum, evaluation["confusion_matrix"])) == evaluation["test_rows"]
    assert evaluation["accuracy"] > evaluation["majority_baseline"]["accuracy"]
    assert evaluation["data_audit"]["remaining_cross_split_overlap"] == 0
    assert evaluation["data_audit"]["train_duplicate_feature_rows"] == 0
    assert len(bundle.reference_scores) == evaluation["anomaly"]["normal_calibration_rows"]
    assert np.quantile(bundle.reference_scores, 0.01) == pytest.approx(bundle.metadata["anomaly_threshold"])


def test_replay_sample_integrity():
    import hashlib

    path = ROOT / "data" / "replay.csv"
    info = json.loads(path.with_suffix(".json").read_text())
    assert hashlib.sha256(path.read_bytes()).hexdigest() == info["sha256"]
    frame = pd.read_csv(path)
    assert len(frame) == 400
    assert frame.attack_cat.value_counts().eq(40).all()
    assert b"\r\n" not in path.read_bytes(), "Replay hashes must survive Git LF normalization"
