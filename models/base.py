"""Base detector interface for PrivacyGuard Phase D."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional
import numpy as np


class BaseAnomalyDetector(ABC):
    """Common interface for PrivacyGuard anomaly detection models."""

    def __init__(self, name: str = "BaseDetector", threshold: float = 0.5):
        self.name = name
        self.threshold = threshold
        self.is_fitted: bool = False

    @abstractmethod
    def fit(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> BaseAnomalyDetector:
        """Fit detector on benign feature matrix X (N, D)."""
        pass

    @abstractmethod
    def score(self, X: np.ndarray) -> np.ndarray:
        """Compute continuous anomaly score for each sample in X (N, D).
        
        Higher score indicates higher probability of anomaly / exfiltration.
        Returns:
            np.ndarray of shape (N,) with float scores.
        """
        pass

    def predict(self, X: np.ndarray, threshold: Optional[float] = None) -> np.ndarray:
        """Predict binary classification: 1 (Anomaly/Exfiltration) or 0 (Benign)."""
        th = threshold if threshold is not None else self.threshold
        scores = self.score(X)
        return (scores >= th).astype(int)

    def set_threshold(self, threshold: float) -> None:
        """Set decision threshold."""
        self.threshold = float(threshold)
