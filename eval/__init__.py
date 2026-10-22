"""Evaluation package for PrivacyGuard Phase D."""

from eval.dataset import DatasetGenerator, parse_ground_truth
from eval.metrics import (
    compute_binary_metrics,
    compute_detection_latencies,
    compute_per_scenario_metrics,
)

__all__ = [
    "DatasetGenerator",
    "parse_ground_truth",
    "compute_binary_metrics",
    "compute_detection_latencies",
    "compute_per_scenario_metrics",
]
