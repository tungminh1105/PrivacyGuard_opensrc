"""Run evaluation experiments comparing Rules, Isolation Forest, and Autoencoder.

Generates:
- results/summary.csv
- results/per_scenario.csv
"""

from __future__ import annotations

import argparse
import csv
import logging
import os
import sys
import time
from typing import Any, Dict, List
import numpy as np

# Ensure project root in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from eval.dataset import DatasetGenerator
from eval.metrics import (
    compute_binary_metrics,
    compute_detection_latencies,
    compute_per_scenario_metrics,
)
from models.rules import RuleBasedDetector
from models.iforest import IsolationForestDetector
from models.autoencoder import AutoencoderDetector

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [Eval] %(message)s",
)


def run_pipeline(
    db_path: str = "data/privacyguard.db",
    gt_path: str = "data/ground_truth.csv",
    results_dir: str = "results",
    runs_per_scenario: int = 12,
    seed: int = 42,
) -> Tuple[Dict[str, Dict[str, float]], List[Dict[str, Any]]]:
    """Run full Phase D evaluation pipeline."""
    os.makedirs(results_dir, exist_ok=True)

    # 1. Generate / load dataset
    logger.info("Initializing DatasetGenerator (runs_per_scenario=%d)...", runs_per_scenario)
    gen = DatasetGenerator(
        db_path=db_path,
        gt_path=gt_path,
        seed=seed,
    )
    dataset = gen.build_dataset(runs_per_scenario=runs_per_scenario)

    train_data = dataset["train"]
    val_data = dataset["val"]
    test_data = dataset["test"]

    X_train, y_train = train_data["X"], train_data["y"]
    X_val, y_val = val_data["X"], val_data["y"]
    X_test, y_test = test_data["X"], test_data["y"]

    logger.info(
        "Data summary: Train=%d (benign: %d, leak: %d), Val=%d (benign: %d, leak: %d), Test=%d (benign: %d, leak: %d)",
        len(y_train), int(np.sum(y_train == 0)), int(np.sum(y_train == 1)),
        len(y_val), int(np.sum(y_val == 0)), int(np.sum(y_val == 1)),
        len(y_test), int(np.sum(y_test == 0)), int(np.sum(y_test == 1)),
    )

    # 2. Initialize models
    rules = RuleBasedDetector(threshold=0.5)
    iforest = IsolationForestDetector(n_estimators=200, random_state=seed)
    autoencoder = AutoencoderDetector(
        layer_dims=[17, 8, 4, 8, 17],
        epochs=60,
        batch_size=32,
        lr=1e-3,
        quantile_threshold=95.0,
    )

    models = {
        "RuleBased": rules,
        "IsolationForest": iforest,
        "Autoencoder": autoencoder,
    }

    # 3. Train models on benign train set only
    logger.info("Training models on benign training set...")
    for name, model in models.items():
        t0 = time.time()
        if name == "Autoencoder":
            model.fit(X_train, y_train, X_val=X_val[y_val == 0] if np.sum(y_val == 0) > 0 else X_train)
        else:
            model.fit(X_train, y_train)
        t_fit = time.time() - t0
        logger.info("Model '%s' trained in %.2f seconds.", name, t_fit)

    # 4. Calibrate thresholds on validation set
    logger.info("Calibrating thresholds on validation set...")
    val_benign_idx = (y_val == 0)
    for name, model in models.items():
        val_scores = model.score(X_val)
        if name == "Autoencoder":
            # Score is calibrated such that 0.5 is at the 95th percentile of benign reconstruction error
            model.set_threshold(0.5)
        elif name == "RuleBased":
            model.set_threshold(0.5)
        elif name == "IsolationForest":
            if np.sum(val_benign_idx) > 0:
                benign_val_scores = val_scores[val_benign_idx]
                calibrated_th = float(np.percentile(benign_val_scores, 95))
                model.set_threshold(calibrated_th)
        logger.info("Model '%s' calibrated threshold: %.4f", name, model.threshold)

    # 5. Evaluate on test set
    logger.info("Evaluating models on test set...")
    summary_results: Dict[str, Dict[str, float]] = {}
    test_preds: Dict[str, np.ndarray] = {}

    for name, model in models.items():
        scores = model.score(X_test)
        preds = model.predict(X_test)
        test_preds[name] = preds

        metrics = compute_binary_metrics(y_test, preds, scores)
        latencies = compute_detection_latencies(test_data["meta"], preds)

        metrics["avg_detection_latency_sec"] = latencies["avg_latency_sec"]
        metrics["detected_runs_ratio"] = latencies["detected_runs_ratio"]
        metrics["threshold"] = model.threshold
        summary_results[name] = metrics

    # 6. Compute per-scenario breakdown
    per_scenario_rows = compute_per_scenario_metrics(test_data["meta"], test_preds)

    # 7. Write results/summary.csv
    summary_path = os.path.join(results_dir, "summary.csv")
    summary_headers = [
        "detector",
        "precision",
        "recall",
        "f1",
        "fpr",
        "pr_auc",
        "roc_auc",
        "avg_detection_latency_sec",
        "threshold",
        "tp",
        "fp",
        "tn",
        "fn",
    ]
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=summary_headers)
        writer.writeheader()
        for name, m in summary_results.items():
            row = {"detector": name}
            for k in summary_headers[1:]:
                row[k] = round(m.get(k, 0.0), 4) if isinstance(m.get(k), float) else m.get(k, 0)
            writer.writerow(row)
    logger.info("Saved summary results to %s", summary_path)

    # 8. Write results/per_scenario.csv
    per_sc_path = os.path.join(results_dir, "per_scenario.csv")
    if per_scenario_rows:
        sc_headers = list(per_scenario_rows[0].keys())
        with open(per_sc_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=sc_headers)
            writer.writeheader()
            for r in per_scenario_rows:
                writer.writerow(r)
        logger.info("Saved per-scenario results to %s", per_sc_path)

    return summary_results, per_scenario_rows


def main():
    parser = argparse.ArgumentParser(description="PrivacyGuard Phase D Experiments")
    parser.add_argument("--runs", type=int, default=12, help="Number of runs per scenario")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--db", type=str, default="data/privacyguard.db", help="SQLite DB path")
    parser.add_argument("--gt", type=str, default="data/ground_truth.csv", help="Ground truth path")
    parser.add_argument("--out", type=str, default="results", help="Output directory")
    args = parser.parse_args()

    summary_results, per_scenario_rows = run_pipeline(
        db_path=args.db,
        gt_path=args.gt,
        results_dir=args.out,
        runs_per_scenario=args.runs,
        seed=args.seed,
    )

    print("\n" + "=" * 80)
    print("                     PRIVACYGUARD EVALUATION SUMMARY")
    print("=" * 80)
    print(f"{'Detector':<18} | {'Precision':<9} | {'Recall':<7} | {'F1-Score':<8} | {'FPR':<7} | {'PR-AUC':<7} | {'ROC-AUC':<7} | {'Latency(s)':<10}")
    print("-" * 80)
    for det, m in summary_results.items():
        print(
            f"{det:<18} | {m['precision']:<9.4f} | {m['recall']:<7.4f} | {m['f1']:<8.4f} | {m['fpr']:<7.4f} | {m['pr_auc']:<7.4f} | {m['roc_auc']:<7.4f} | {m['avg_detection_latency_sec']:<10.2f}"
        )
    print("=" * 80)

    print("\n" + "=" * 80)
    print("                    PER-SCENARIO DETECTION BREAKDOWN")
    print("=" * 80)
    for r in per_scenario_rows:
        lbl = "LEAK (1)" if r["true_label"] == 1 else "BENIGN (0)"
        print(f"[{r['scenario']}] {r['scenario_name']} | True: {lbl} | Samples: {r['n_samples']}")
        print(f"    - RuleBased Acc/Det: {r.get('RuleBased_rate', 0.0):.1%}")
        print(f"    - IsolationForest Acc/Det: {r.get('IsolationForest_rate', 0.0):.1%}")
        print(f"    - Autoencoder Acc/Det: {r.get('Autoencoder_rate', 0.0):.1%}")
        print(f"    - Notes: {r.get('notes', '')}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    main()
