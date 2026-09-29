"""
Unsupervised Anomaly Detection Framework.
Implements Isolation Forest and One-Class SVM models to establish normal administrative baselines.
"""
from typing import Dict, Tuple, Union
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
import joblib
from config import ISOLATION_FOREST_PARAMS, SVM_PARAMS, MODELS_DIR

ISO_MODEL_PATH = MODELS_DIR / "trained_isolation_forest.joblib"
SVM_MODEL_PATH = MODELS_DIR / "trained_one_class_svm.joblib"


class BehavioralAnomalyDetector:
    """Unsupervised behavioral anomaly detector for administrative sessions."""

    def __init__(self, algorithm: str = "isolation_forest"):
        self.algorithm = algorithm
        if algorithm == "isolation_forest":
            self.model = IsolationForest(**ISOLATION_FOREST_PARAMS)
        elif algorithm == "one_class_svm":
            self.model = OneClassSVM(**SVM_PARAMS)
        else:
            raise ValueError(f"Unknown algorithm: {algorithm}")

        self.is_trained = False
        self.score_min = None
        self.score_max = None

    def train(self, x_scaled: np.ndarray) -> "BehavioralAnomalyDetector":
        """Trains the unsupervised model on benign baseline administrative telemetry."""
        self.model.fit(x_scaled)
        self.is_trained = True

        # Compute empirical range of baseline scores for normalization
        if self.algorithm == "isolation_forest":
            # decision_function: positive is inlier, negative is outlier
            scores = self.model.decision_function(x_scaled)
        else:
            scores = self.model.decision_function(x_scaled)

        self.score_min = float(np.percentile(scores, 0.5))
        self.score_max = float(np.percentile(scores, 99.5))

        self.save()
        return self

    def predict_anomaly(self, x_scaled: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Returns:
            is_anomaly: array of booleans (True if outlier)
            anomaly_intensity: array of floats between 0.0 (very normal) and 1.0 (severe anomaly)
        """
        if not self.is_trained:
            self.load()

        predictions = self.model.predict(x_scaled)  # -1 for anomaly, 1 for inlier
        raw_scores = self.model.decision_function(x_scaled)

        # Invert score so higher = more anomalous
        # decision_function: high positive = deep inlier, negative = deep outlier
        # We clip and normalize between 0.0 and 1.0
        normalized_intensity = []
        for s in raw_scores:
            # Map score: if s <= score_min -> 1.0 (extreme anomaly)
            # if s >= score_max -> 0.0 (completely benign)
            denominator = (self.score_max - self.score_min) if (self.score_max != self.score_min) else 1.0
            norm = (self.score_max - s) / denominator
            norm = float(np.clip(norm, 0.0, 1.0))
            normalized_intensity.append(norm)

        is_anomaly = (predictions == -1)
        return is_anomaly, np.array(normalized_intensity)

    def save(self):
        """Serializes trained model to disk."""
        target_path = ISO_MODEL_PATH if self.algorithm == "isolation_forest" else SVM_MODEL_PATH
        payload = {
            "model": self.model,
            "algorithm": self.algorithm,
            "is_trained": self.is_trained,
            "score_min": self.score_min,
            "score_max": self.score_max
        }
        joblib.dump(payload, target_path)

    def load(self):
        """Loads serialized model from disk."""
        target_path = ISO_MODEL_PATH if self.algorithm == "isolation_forest" else SVM_MODEL_PATH
        if target_path.exists():
            payload = joblib.load(target_path)
            self.model = payload["model"]
            self.algorithm = payload["algorithm"]
            self.is_trained = payload["is_trained"]
            self.score_min = payload["score_min"]
            self.score_max = payload["score_max"]
        else:
            raise FileNotFoundError(f"Trained model not found at {target_path}. Run training first.")
