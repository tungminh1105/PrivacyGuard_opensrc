"""Unit tests for PrivacyGuard Phase D models and evaluation pipeline.

Validates:
- Rule-based detector output bounds [0.0, 1.0] and causal flow sensitivity.
- Isolation Forest fitting, scaling, score normalization, and binary prediction.
- Autoencoder architecture forward pass, loss optimization, and reconstruction error scoring.
- Evaluation metrics (precision, recall, F1, FPR, AUC, latency, and per-scenario metrics).
"""

from __future__ import annotations

import math
import numpy as np
import pytest
import torch

from models.rules import RuleBasedDetector
from models.iforest import IsolationForestDetector
from models.autoencoder import AutoencoderDetector, MLPAutoencoder
from eval.metrics import (
    compute_binary_metrics,
    compute_detection_latencies,
    compute_per_scenario_metrics,
)


def _generate_synthetic_data(n_samples: int = 50, n_dims: int = 17, seed: int = 42) -> np.ndarray:
    """Generate dummy benign vectors (17 dimensions)."""
    rng = np.random.default_rng(seed)
    # Typical benign profile: low file creates, low sensitive, normal net connects
    X = rng.uniform(0.0, 2.0, size=(n_samples, n_dims))
    X[:, 1] = 0.0  # n_sensitive_files = 0
    X[:, 2] = 0.0  # ratio_sensitive_events = 0
    X[:, 16] = 0.0 # has_causal_flow = 0
    return X


def test_rule_based_detector_scores_and_bounds():
    """Verify RuleBasedDetector produces scores in [0.0, 1.0] and reacts to causal flows."""
    detector = RuleBasedDetector(threshold=0.5)

    # 1. Pure benign vector (no files, no sensitive, normal network)
    benign_vec = np.zeros(17, dtype=float)
    benign_vec[4] = 1.0  # n_net_connect = 1
    benign_vec[5] = 512.0  # total_bytes_sent = 512

    score_benign = detector.score(benign_vec)[0]
    assert 0.0 <= score_benign <= 1.0
    assert score_benign == 0.0  # No sensitive files and no causal flow -> score 0.0
    assert detector.predict(benign_vec)[0] == 0

    # 2. Exfiltration vector (sensitive file + causal flow + outbound net)
    leak_vec = np.zeros(17, dtype=float)
    leak_vec[0] = 5.0    # n_file_create
    leak_vec[1] = 3.0    # n_sensitive_files
    leak_vec[2] = 0.8    # ratio_sensitive_events
    leak_vec[4] = 2.0    # n_net_connect
    leak_vec[5] = 50000.0  # total_bytes_sent
    leak_vec[7] = 1.0    # n_new_dest
    leak_vec[16] = 1.0   # has_causal_flow

    score_leak = detector.score(leak_vec)[0]
    assert 0.0 <= score_leak <= 1.0
    assert score_leak >= 0.7
    assert detector.predict(leak_vec)[0] == 1


def test_isolation_forest_detector_fit_and_score():
    """Verify IsolationForestDetector trains on benign samples and outputs normalized scores."""
    X_train = _generate_synthetic_data(n_samples=60, n_dims=17, seed=10)
    detector = IsolationForestDetector(n_estimators=50, random_state=42)

    detector.fit(X_train)
    assert detector.is_fitted

    # Test scoring benign sample
    scores_train = detector.score(X_train)
    assert len(scores_train) == 60
    assert np.all(scores_train >= 0.0)
    assert np.all(scores_train <= 1.0)
    assert not np.isnan(scores_train).any()

    # Test scoring an anomalous outlier
    outlier = np.ones((1, 17), dtype=float) * 100.0
    outlier[0, 16] = 1.0  # causal flow
    score_outlier = detector.score(outlier)[0]
    assert 0.0 <= score_outlier <= 1.0
    assert detector.predict(outlier)[0] in (0, 1)


def test_autoencoder_architecture_and_forward_pass():
    """Verify PyTorch MLPAutoencoder layer dimensions and tensor reconstruction shape."""
    model = MLPAutoencoder(layer_dims=[17, 8, 4, 8, 17])
    dummy_input = torch.randn(8, 17)
    reconstruction = model(dummy_input)

    assert reconstruction.shape == (8, 17)
    assert not torch.isnan(reconstruction).any()


def test_autoencoder_detector_training_and_reconstruction_error():
    """Verify AutoencoderDetector trains for 5 epochs without shape errors and computes MSE score."""
    X_train = _generate_synthetic_data(n_samples=50, n_dims=17, seed=20)
    detector = AutoencoderDetector(
        layer_dims=[17, 8, 4, 8, 17],
        epochs=5,
        batch_size=16,
        lr=1e-3,
        quantile_threshold=95.0,
    )

    detector.fit(X_train)
    assert detector.is_fitted

    # Check benign reconstruction scores
    scores_benign = detector.score(X_train)
    assert len(scores_benign) == 50
    assert np.all(scores_benign >= 0.0)
    assert np.all(scores_benign <= 1.0)
    assert not np.isnan(scores_benign).any()

    # An extreme outlier should have higher reconstruction error
    outlier = np.ones((2, 17), dtype=float) * 50.0
    scores_outlier = detector.score(outlier)
    assert len(scores_outlier) == 2
    assert scores_outlier[0] >= np.percentile(scores_benign, 50)


def test_evaluation_binary_metrics_calculation():
    """Verify compute_binary_metrics accurately computes precision, recall, F1, FPR, and AUC."""
    y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    y_pred = np.array([0, 0, 0, 1, 1, 1, 1, 0])
    y_score = np.array([0.1, 0.2, 0.15, 0.6, 0.8, 0.9, 0.85, 0.4])

    metrics = compute_binary_metrics(y_true, y_pred, y_score)

    assert metrics["tp"] == 3
    assert metrics["fp"] == 1
    assert metrics["tn"] == 3
    assert metrics["fn"] == 1
    assert math.isclose(metrics["precision"], 3 / 4)
    assert math.isclose(metrics["recall"], 3 / 4)
    assert math.isclose(metrics["fpr"], 1 / 4)
    assert metrics["f1"] == 0.75
    assert metrics["roc_auc"] > 0.5


def test_detection_latency_calculation():
    """Verify compute_detection_latencies correctly identifies time to first alert."""
    meta_list = [
        {"run_id": "run_01", "label": 1, "t_start": 100.0, "t_end": 115.0},
        {"run_id": "run_01", "label": 1, "t_start": 115.0, "t_end": 130.0},
        {"run_id": "run_02", "label": 1, "t_start": 200.0, "t_end": 215.0},
        {"run_id": "system", "label": 0, "t_start": 50.0, "t_end": 110.0},
    ]
    # run_01 detected at first window (t_end=115.0 -> latency 15s)
    # run_02 detected at window (t_end=215.0 -> latency 15s)
    y_pred = np.array([1, 1, 1, 0])

    res = compute_detection_latencies(meta_list, y_pred)
    assert res["detected_runs_ratio"] == 1.0
    assert math.isclose(res["avg_latency_sec"], 15.0)


def test_per_scenario_breakdown_computation():
    """Verify compute_per_scenario_metrics formats all 9 scenarios accurately."""
    meta_list = [
        {"scenario": "1", "label": 1},
        {"scenario": "1", "label": 1},
        {"scenario": "7", "label": 0},
        {"scenario": "8", "label": 0},
    ]
    preds = {
        "RuleBased": np.array([1, 1, 0, 0]),
        "IsolationForest": np.array([1, 0, 0, 0]),
    }

    breakdown = compute_per_scenario_metrics(meta_list, preds)
    assert len(breakdown) == 9

    sc1 = next(r for r in breakdown if r["scenario"] == 1)
    assert sc1["n_samples"] == 2
    assert sc1["true_label"] == 1
    assert sc1["RuleBased_rate"] == 1.0
    assert sc1["IsolationForest_rate"] == 0.5

    sc7 = next(r for r in breakdown if r["scenario"] == 7)
    assert sc7["n_samples"] == 1
    assert sc7["true_label"] == 0
    assert sc7["RuleBased_rate"] == 1.0  # Correct benign classification
