"""Evaluation metrics module for PrivacyGuard (Phase D).

Computes:
- Precision, Recall, F1-Score, False Positive Rate (FPR)
- PR-AUC, ROC-AUC
- Confusion matrix (TN, FP, FN, TP)
- Detection Latency (time to first alert per leak run)
- Per-scenario detection metrics and error diagnostics
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple
import numpy as np
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
    auc,
)

logger = logging.getLogger(__name__)

SCENARIO_NAMES = {
    1: "Scenario 1: Bulk Exfiltration",
    2: "Scenario 2: Slow Trickle Exfiltration",
    3: "Scenario 3: Compressed Archive Exfiltration",
    4: "Scenario 4: Subprocess Exfiltration",
    5: "Scenario 5: Port 443 Exfiltration",
    6: "Scenario 6: Periodic Beaconing",
    7: "Scenario 7: Benign Cloud Sync",
    8: "Scenario 8: Network-only Control",
    9: "Scenario 9: File-read-only Control",
}


def compute_binary_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    y_score: Optional[np.ndarray] = None,
) -> Dict[str, float]:
    """Compute standard classification and ranking metrics."""
    y_t = np.asarray(y_true, dtype=int)
    y_p = np.asarray(y_pred, dtype=int)

    if len(y_t) == 0:
        return {
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "fpr": 0.0,
            "pr_auc": 0.0,
            "roc_auc": 0.0,
            "tn": 0,
            "fp": 0,
            "fn": 0,
            "tp": 0,
        }

    # Confusion matrix
    cm = confusion_matrix(y_t, y_p, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    # Rates
    precision = float(precision_score(y_t, y_p, zero_division=0))
    recall = float(recall_score(y_t, y_p, zero_division=0))
    f1 = float(f1_score(y_t, y_p, zero_division=0))
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    # AUCs
    pr_auc_val = 0.0
    roc_auc_val = 0.0
    if y_score is not None and len(np.unique(y_t)) > 1:
        try:
            prec_arr, rec_arr, _ = precision_recall_curve(y_t, y_score)
            pr_auc_val = float(auc(rec_arr, prec_arr))
        except Exception:
            pr_auc_val = 0.0

        try:
            roc_auc_val = float(roc_auc_score(y_t, y_score))
        except Exception:
            roc_auc_val = 0.0

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "pr_auc": pr_auc_val,
        "roc_auc": roc_auc_val,
        "tn": int(tn),
        "fp": int(fp),
        "fn": int(fn),
        "tp": int(tp),
    }


def compute_detection_latencies(
    meta_list: List[Dict[str, Any]],
    y_pred: np.ndarray,
) -> Dict[str, float]:
    """Calculate time from run start to first detection window for each leak run."""
    run_first_alert: Dict[str, float] = {}
    run_start_times: Dict[str, float] = {}

    for i, meta in enumerate(meta_list):
        run_id = meta.get("run_id")
        label = meta.get("label", 0)
        t_start = meta.get("t_start", 0.0)
        t_end = meta.get("t_end", 0.0)

        if label == 1 and run_id and run_id != "system":
            if run_id not in run_start_times:
                run_start_times[run_id] = t_start
            else:
                run_start_times[run_id] = min(run_start_times[run_id], t_start)

            if y_pred[i] == 1:
                if run_id not in run_first_alert:
                    run_first_alert[run_id] = t_end
                else:
                    run_first_alert[run_id] = min(run_first_alert[run_id], t_end)

    latencies = []
    for r_id, start_t in run_start_times.items():
        if r_id in run_first_alert:
            lat = max(0.0, run_first_alert[r_id] - start_t)
            latencies.append(lat)

    if latencies:
        return {
            "avg_latency_sec": float(np.mean(latencies)),
            "min_latency_sec": float(np.min(latencies)),
            "max_latency_sec": float(np.max(latencies)),
            "detected_runs_ratio": float(len(latencies) / max(1, len(run_start_times))),
        }
    return {
        "avg_latency_sec": 0.0,
        "min_latency_sec": 0.0,
        "max_latency_sec": 0.0,
        "detected_runs_ratio": 0.0,
    }


def compute_per_scenario_metrics(
    meta_list: List[Dict[str, Any]],
    predictions_by_model: Dict[str, np.ndarray],
) -> List[Dict[str, Any]]:
    """Compute breakdown per scenario (1 to 9) for each model."""
    scenarios = list(range(1, 10))
    rows: List[Dict[str, Any]] = []

    scenario_notes = {
        1: "Bulk send + sensitive docs: easily detected by causal flow and network volume.",
        2: "Slow trickle chunks: detected via provenance causal flow connecting file to network.",
        3: "Zip compression: creates temp file, causal flow links fake docs to zip to socket.",
        4: "Subprocess spawn: parent-child process hierarchy propagates causal flow to child.",
        5: "Port 443: detected by causal flow despite common HTTPS port destination.",
        6: "Periodic beacon: small file touch followed by periodic heartbeats.",
        7: "Benign cloud sync: negative control (label 0), copies to fake_cloud without external socket.",
        8: "Network-only control: negative control (label 0), network traffic without sensitive files.",
        9: "File-read-only control: negative control (label 0), Sysmon sees no network connection.",
    }

    for sc_id in scenarios:
        sc_str = str(sc_id)
        indices = [i for i, m in enumerate(meta_list) if str(m.get("scenario")) == sc_str]
        n_samples = len(indices)
        true_label = 1 if sc_id <= 6 else 0

        row: Dict[str, Any] = {
            "scenario": sc_id,
            "scenario_name": SCENARIO_NAMES.get(sc_id, f"Scenario {sc_id}"),
            "true_label": true_label,
            "n_samples": n_samples,
        }

        for model_name, preds in predictions_by_model.items():
            if n_samples > 0:
                sc_preds = preds[indices]
                if true_label == 1:
                    # Detection rate (True Positive Rate)
                    rate = float(np.mean(sc_preds == 1))
                else:
                    # Correct benign classification rate (True Negative Rate)
                    rate = float(np.mean(sc_preds == 0))
            else:
                rate = 0.0
            row[f"{model_name}_rate"] = round(rate, 4)

        row["notes"] = scenario_notes.get(sc_id, "")
        rows.append(row)

    return rows
