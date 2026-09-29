"""
Feature Engineering and Preprocessing Pipeline for Zero-Trust Behavioral Authentication.
"""
from typing import Dict, List, Tuple, Union
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler
import joblib
from config import CORE_FEATURES, MODELS_DIR

SCALER_PATH = MODELS_DIR / "feature_scaler.joblib"


class FeaturePipeline:
    """Handles feature validation, robust scaling, and deviation computation."""

    def __init__(self):
        self.features = CORE_FEATURES
        self.scaler = RobustScaler()
        self.is_fitted = False
        self.feature_means = {}
        self.feature_stds = {}

    def fit(self, df: pd.DataFrame) -> "FeaturePipeline":
        """Fits scaler and computes baseline distribution statistics."""
        x = df[self.features].values
        self.scaler.fit(x)
        self.is_fitted = True

        for col in self.features:
            self.feature_means[col] = float(df[col].mean())
            self.feature_stds[col] = float(df[col].std()) if df[col].std() > 0 else 1.0

        # Persist fitted artifacts
        self.save()
        return self

    def transform(self, data: Union[pd.DataFrame, Dict, List[Dict]]) -> np.ndarray:
        """Transforms raw input features into scaled numpy matrix."""
        if not self.is_fitted:
            self.load()

        if isinstance(data, dict):
            df = pd.DataFrame([data])
        elif isinstance(data, list):
            df = pd.DataFrame(data)
        else:
            df = data.copy()

        # Ensure all columns exist, default to median/0 if missing
        for col in self.features:
            if col not in df.columns:
                df[col] = self.feature_means.get(col, 0.0)

        x = df[self.features].values
        return self.scaler.transform(x)

    def fit_transform(self, df: pd.DataFrame) -> np.ndarray:
        return self.fit(df).transform(df)

    def explain_deviations(self, record: Dict) -> List[Dict]:
        """
        Computes how many standard deviations each telemetry metric deviates
        from the normal administrative baseline (Z-Score like deviation).
        Provides transparent Explainable AI (XAI) for the security analyst / panel.
        """
        explanations = []
        for col in self.features:
            val = float(record.get(col, 0.0))
            mean = self.feature_means.get(col, val)
            std = self.feature_stds.get(col, 1.0)
            z_score = (val - mean) / std if std > 0 else 0.0

            # Determine human-readable description
            severity = "NORMAL"
            if abs(z_score) > 3.0:
                severity = "CRITICAL"
            elif abs(z_score) > 2.0:
                severity = "HIGH"
            elif abs(z_score) > 1.2:
                severity = "ELEVATED"

            explanations.append({
                "feature": col,
                "value": round(val, 2),
                "baseline_mean": round(mean, 2),
                "z_deviation": round(z_score, 2),
                "severity": severity
            })

        # Sort highest deviation first
        explanations.sort(key=lambda item: abs(item["z_deviation"]), reverse=True)
        return explanations

    def save(self):
        """Serializes pipeline state to disk."""
        payload = {
            "scaler": self.scaler,
            "feature_means": self.feature_means,
            "feature_stds": self.feature_stds,
            "is_fitted": self.is_fitted,
            "features": self.features
        }
        joblib.dump(payload, SCALER_PATH)

    def load(self):
        """Loads serialized pipeline state."""
        if SCALER_PATH.exists():
            payload = joblib.load(SCALER_PATH)
            self.scaler = payload["scaler"]
            self.feature_means = payload["feature_means"]
            self.feature_stds = payload["feature_stds"]
            self.is_fitted = payload["is_fitted"]
            self.features = payload["features"]
        else:
            raise FileNotFoundError(f"Feature scaler not found at {SCALER_PATH}. Run training first.")
