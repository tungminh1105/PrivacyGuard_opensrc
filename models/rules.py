"""Rule-based anomaly and exfiltration detector for PrivacyGuard (Phase D).

Implements deterministic expert rules combining sensitive file activity,
network transmission volume, new destination indicators, and provenance causal flows.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional
import numpy as np

from models.base import BaseAnomalyDetector
from core.features import FEATURE_NAMES

logger = logging.getLogger(__name__)


class RuleBasedDetector(BaseAnomalyDetector):
    """Rule-based baseline detector evaluating domain heuristic criteria."""

    def __init__(
        self,
        name: str = "RuleBasedDetector",
        threshold: float = 0.5,
        causal_weight: float = 0.45,
        sensitive_weight: float = 0.25,
        network_weight: float = 0.20,
        new_dest_weight: float = 0.10,
        signed_discount: float = 0.20,
    ):
        super().__init__(name=name, threshold=threshold)
        self.causal_weight = causal_weight
        self.sensitive_weight = sensitive_weight
        self.network_weight = network_weight
        self.new_dest_weight = new_dest_weight
        self.signed_discount = signed_discount
        self._feat_idx: Dict[str, int] = {name: i for i, name in enumerate(FEATURE_NAMES)}

    def _get_feat(self, row: np.ndarray, name: str) -> float:
        idx = self._feat_idx.get(name)
        if idx is not None and idx < len(row):
            return float(row[idx])
        return 0.0

    def fit(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> RuleBasedDetector:
        """Calibrate threshold on benign data if provided."""
        if X is not None and len(X) > 0:
            scores = self.score(X)
            # Calibrate threshold to 99th percentile of benign scores, bounded at least 0.5
            p99 = float(np.percentile(scores, 99))
            self.threshold = max(0.5, p99 + 0.05) if p99 < 0.95 else 0.5
        self.is_fitted = True
        return self

    def score(self, X: np.ndarray) -> np.ndarray:
        """Compute rule anomaly score in [0.0, 1.0] for each sample in X."""
        X_arr = np.asarray(X, dtype=float)
        if X_arr.ndim == 1:
            X_arr = X_arr.reshape(1, -1)

        scores = np.zeros(len(X_arr), dtype=float)

        for i, row in enumerate(X_arr):
            n_file_create = self._get_feat(row, "n_file_create")
            n_sensitive = self._get_feat(row, "n_sensitive_files")
            ratio_sens = self._get_feat(row, "ratio_sensitive_events")
            n_net = self._get_feat(row, "n_net_connect")
            bytes_sent = self._get_feat(row, "total_bytes_sent")
            n_new_dest = self._get_feat(row, "n_new_dest")
            is_signed = self._get_feat(row, "is_signed_process")
            causal_flow = self._get_feat(row, "has_causal_flow")

            # Condition 0: Network activity is required for exfiltration
            if n_net <= 0 and bytes_sent <= 0:
                scores[i] = 0.0
                continue

            # Condition 1: Without sensitive files and without causal flow, normal network is benign
            if n_sensitive <= 0 and causal_flow <= 0 and ratio_sens <= 0:
                scores[i] = 0.0
                continue

            s = 0.0

            # Signal 1: Direct causal flow from sensitive file to network socket
            if causal_flow > 0.5:
                s += self.causal_weight

            # Signal 2: Sensitive file access presence and ratio
            if n_sensitive > 0:
                s += self.sensitive_weight * min(1.0, 0.5 + 0.5 * ratio_sens)
            elif ratio_sens > 0:
                s += self.sensitive_weight * min(1.0, ratio_sens)

            # Signal 3: Outbound network transmission
            if bytes_sent > 1024 or n_net > 0:
                s += self.network_weight

            # Signal 4: Unseen destination IP
            if n_new_dest > 0:
                s += self.new_dest_weight

            # Signal 5: Signed process discount
            if is_signed > 0.5:
                s = max(0.0, s - self.signed_discount)

            scores[i] = float(np.clip(s, 0.0, 1.0))

        return scores
