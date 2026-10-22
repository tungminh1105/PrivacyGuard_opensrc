"""Deep Learning Autoencoder Anomaly Detector for PrivacyGuard (Phase D).

PyTorch-based lightweight MLP Autoencoder trained on benign feature windows.
Detects data exfiltration and anomalies based on high reconstruction error (MSE).
"""

from __future__ import annotations

import logging
from typing import List, Optional, Tuple
import numpy as np
import torch
import torch.nn as nn
from torch.utils.data import DataLoader, TensorDataset

from models.base import BaseAnomalyDetector

logger = logging.getLogger(__name__)


class RobustFeatureScaler:
    """Scaler applying log1p to count/byte features and bounding minimum standard deviation."""

    def __init__(self, log_cols: Optional[List[int]] = None, min_scale: float = 0.1):
        self.log_cols = log_cols or [0, 1, 3, 4, 5, 6, 7, 10, 12]
        self.min_scale = min_scale
        self.mean_: Optional[np.ndarray] = None
        self.scale_: Optional[np.ndarray] = None

    def fit(self, X: np.ndarray) -> RobustFeatureScaler:
        X_tf = np.asarray(X, dtype=float).copy()
        if X_tf.ndim == 1:
            X_tf = X_tf.reshape(1, -1)
        if self.log_cols:
            valid_cols = [c for c in self.log_cols if c < X_tf.shape[1]]
            X_tf[:, valid_cols] = np.log1p(np.maximum(0.0, X_tf[:, valid_cols]))
        self.mean_ = np.mean(X_tf, axis=0)
        scale = np.std(X_tf, axis=0)
        self.scale_ = np.maximum(scale, self.min_scale)
        return self

    def transform(self, X: np.ndarray) -> np.ndarray:
        X_tf = np.asarray(X, dtype=float).copy()
        if X_tf.ndim == 1:
            X_tf = X_tf.reshape(1, -1)
        if self.log_cols:
            valid_cols = [c for c in self.log_cols if c < X_tf.shape[1]]
            X_tf[:, valid_cols] = np.log1p(np.maximum(0.0, X_tf[:, valid_cols]))
        mean = self.mean_ if self.mean_ is not None else 0.0
        scale = self.scale_ if self.scale_ is not None else 1.0
        return (X_tf - mean) / scale

    def fit_transform(self, X: np.ndarray) -> np.ndarray:
        return self.fit(X).transform(X)


class MLPAutoencoder(nn.Module):
    """Lightweight MLP Autoencoder network (e.g., 17 -> 8 -> 4 -> 8 -> 17)."""

    def __init__(self, layer_dims: Optional[List[int]] = None):
        super().__init__()
        dims = layer_dims or [17, 8, 4, 8, 17]
        if len(dims) < 3:
            raise ValueError(f"Autoencoder requires at least 3 layer dims, got {dims}")

        # Encoder: first half down to bottleneck
        mid = len(dims) // 2
        enc_layers: List[nn.Module] = []
        for i in range(mid):
            enc_layers.append(nn.Linear(dims[i], dims[i + 1]))
            if i + 1 < mid:
                enc_layers.append(nn.ReLU())
        self.encoder = nn.Sequential(*enc_layers)

        # Decoder: bottleneck up to reconstruction
        dec_layers: List[nn.Module] = []
        for i in range(mid, len(dims) - 1):
            dec_layers.append(nn.Linear(dims[i], dims[i + 1]))
            if i + 1 < len(dims) - 1:
                dec_layers.append(nn.ReLU())
        self.decoder = nn.Sequential(*dec_layers)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        latent = self.encoder(x)
        reconstruction = self.decoder(latent)
        return reconstruction


class AutoencoderDetector(BaseAnomalyDetector):
    """Autoencoder anomaly detector using reconstruction error."""

    def __init__(
        self,
        name: str = "AutoencoderDetector",
        layer_dims: Optional[List[int]] = None,
        lr: float = 1e-3,
        epochs: int = 50,
        batch_size: int = 32,
        quantile_threshold: float = 95.0,
        device: Optional[str] = None,
    ):
        super().__init__(name=name, threshold=0.5)
        self.layer_dims = layer_dims or [17, 8, 4, 8, 17]
        self.lr = lr
        self.epochs = epochs
        self.batch_size = batch_size
        self.quantile_threshold = quantile_threshold
        self.scaler = RobustFeatureScaler()
        self.threshold_mse: float = 1.0

        if device:
            self.device = torch.device(device)
        else:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

        self.net = MLPAutoencoder(self.layer_dims).to(self.device)

    def fit(
        self,
        X: np.ndarray,
        y: Optional[np.ndarray] = None,
        X_val: Optional[np.ndarray] = None,
    ) -> AutoencoderDetector:
        """Fit scaler and train autoencoder on benign feature samples."""
        X_arr = np.asarray(X, dtype=float)
        if len(X_arr) == 0:
            logger.warning("Empty feature matrix provided to Autoencoder fit.")
            self.is_fitted = True
            return self

        # 1. Fit robust scaler on benign training data
        X_scaled = self.scaler.fit_transform(X_arr)

        dataset = TensorDataset(torch.tensor(X_scaled, dtype=torch.float32))
        loader = DataLoader(dataset, batch_size=min(self.batch_size, len(X_arr)), shuffle=True)

        optimizer = torch.optim.Adam(self.net.parameters(), lr=self.lr, weight_decay=1e-5)
        criterion = nn.MSELoss()

        self.net.train()
        for epoch in range(self.epochs):
            for (batch_x,) in loader:
                batch_x = batch_x.to(self.device)
                optimizer.zero_grad()
                pred = self.net(batch_x)
                loss = criterion(pred, batch_x)
                loss.backward()
                optimizer.step()

        self.is_fitted = True

        # 2. Compute calibration on validation or training benign set
        val_data = X_val if X_val is not None and len(X_val) > 0 else X_arr
        raw_val_errors = self._compute_reconstruction_error(val_data)
        self.threshold_mse = max(1e-4, float(np.percentile(raw_val_errors, self.quantile_threshold)))
        self.threshold = 0.5
        return self

    def _compute_reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        """Compute MSE reconstruction error per sample."""
        X_arr = np.asarray(X, dtype=float)
        if X_arr.ndim == 1:
            X_arr = X_arr.reshape(1, -1)

        X_scaled = self.scaler.transform(X_arr)
        t_x = torch.tensor(X_scaled, dtype=torch.float32).to(self.device)

        self.net.eval()
        with torch.no_grad():
            reconstruction = self.net(t_x)
            diff = (reconstruction - t_x).cpu().numpy()
            mse = np.mean(diff ** 2, axis=1)
        return mse

    def score(self, X: np.ndarray) -> np.ndarray:
        """Compute normalized anomaly score based on reconstruction error."""
        X_arr = np.asarray(X, dtype=float)
        if len(X_arr) == 0:
            return np.zeros(0, dtype=float)

        if not self.is_fitted:
            logger.warning("AutoencoderDetector scored before fitting; returning zeros.")
            return np.zeros(len(X_arr), dtype=float)

        raw_errors = self._compute_reconstruction_error(X_arr)
        # Sigmoid-like smooth calibration: score=0.5 when raw_errors == threshold_mse
        scale_denom = max(1e-4, self.threshold_mse)
        scores = 1.0 - 1.0 / (1.0 + (raw_errors / scale_denom))
        return np.clip(scores, 0.0, 1.0)
