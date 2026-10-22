"""Isolation Forest Anomaly Detector for PrivacyGuard (Phase D).

Unsupervised one-class learning trained strictly on benign system behavior windows.
"""

from __future__ import annotations

import logging
from typing import Optional
import numpy as np
from sklearn.ensemble import IsolationForest

from models.base import BaseAnomalyDetector
from models.autoencoder import RobustFeatureScaler

logger = logging.getLogger(__name__)


class IsolationForestDetector(BaseAnomalyDetector):
    """Isolation Forest unsupervised anomaly detector."""

    def __init__(
        self,
        name: str = "IsolationForestDetector",
        n_estimators: int = 200,
        contamination: str | float = "auto",
        random_state: int = 42,
        threshold: float = 0.5,
    ):
        super().__init__(name=name, threshold=threshold)
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.scaler = RobustFeatureScaler()
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self._score_min: float = 0.0
        self._score_max: float = 1.0

    def fit(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> IsolationForestDetector:
        """Fit scaler and Isolation Forest on benign feature vectors."""
        X_arr = np.asarray(X, dtype=float)
        if len(X_arr) == 0:
            logger.warning("Empty feature matrix provided to IsolationForest fit.")
            self.is_fitted = True
            return self

        # 1. Scale benign training data with robust scaling
        X_scaled = self.scaler.fit_transform(X_arr)

        # 2. Fit Isolation Forest
        self.model.fit(X_scaled)

        # 3. Calibrate score range on training set
        raw_scores = -self.model.score_samples(X_scaled)
        self._score_min = float(np.min(raw_scores))
        p99 = float(np.percentile(raw_scores, 99))
        self._score_max = max(p99 * 1.5, self._score_min + 0.1)

        # Default threshold at 95th percentile of benign scores normalized
        norm_scores = self._normalize_scores(raw_scores)
        self.threshold = float(np.percentile(norm_scores, 95))
        self.is_fitted = True
        return self

    def _normalize_scores(self, raw_scores: np.ndarray) -> np.ndarray:
        """Normalize raw scores into [0.0, 1.0]."""
        spread = max(1e-6, self._score_max - self._score_min)
        norm = (raw_scores - self._score_min) / spread
        return np.clip(norm, 0.0, 1.0)

    def score(self, X: np.ndarray) -> np.ndarray:
        """Compute anomaly score for each sample in X."""
        X_arr = np.asarray(X, dtype=float)
        if X_arr.ndim == 1:
            X_arr = X_arr.reshape(1, -1)

        if not self.is_fitted:
            logger.warning("IsolationForestDetector scored before fitting; returning zeros.")
            return np.zeros(len(X_arr), dtype=float)

        X_scaled = self.scaler.transform(X_arr)
        raw_scores = -self.model.score_samples(X_scaled)
        return self._normalize_scores(raw_scores)
