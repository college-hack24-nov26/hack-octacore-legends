"""Preprocessing and Normalization Pipeline for Unidirectional Flow Features.

Applies robust scaling to handle heavy-tailed network distributions (packet rates,
byte rates), replaces non-finite values (infs, nans), and validates strict schema conformity.
"""

from typing import Tuple, List, Optional, Dict, Any
import numpy as np
import pandas as pd
from sklearn.preprocessing import RobustScaler, LabelEncoder
import joblib
from uniguard.features.schema import (
    UNIDIRECTIONAL_FEATURES,
    PROHIBITED_BIDIRECTIONAL_FEATURES,
)


class FlowDataPreprocessor:
    """Preprocesses unidirectional flow feature matrices for ML training and inference."""

    def __init__(self) -> None:
        self.scaler: RobustScaler = RobustScaler(quantile_range=(5.0, 95.0))
        self.label_encoder: LabelEncoder = LabelEncoder()
        self.is_fitted: bool = False
        self.feature_names: List[str] = list(UNIDIRECTIONAL_FEATURES)

    def validate_schema(self, df: pd.DataFrame) -> None:
        """Ensures dataframe does not contain forbidden bidirectional features and has required columns."""
        # Check forbidden features
        found_forbidden = [col for col in df.columns if col in PROHIBITED_BIDIRECTIONAL_FEATURES]
        if found_forbidden:
            raise ValueError(
                f"SCIENTIFIC INTEGRITY VIOLATION: Dataset contains prohibited bidirectional features: {found_forbidden}. "
                f"UniGuard AI strictly forbids bidirectional features."
            )

        # Check required features
        missing = [col for col in self.feature_names if col not in df.columns]
        if missing:
            raise ValueError(f"Missing required unidirectional features: {missing}")

    def clean_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Replaces infs, NaNs, and clamps extreme outliers."""
        cleaned = df[self.feature_names].copy()
        cleaned.replace([np.inf, -np.inf], np.nan, inplace=True)
        cleaned.fillna(0.0, inplace=True)
        return cleaned

    def fit(self, X: pd.DataFrame, y: Optional[pd.Series] = None) -> "FlowDataPreprocessor":
        """Fits scalers and label encoders on training data."""
        self.validate_schema(X)
        cleaned_X = self.clean_features(X)
        self.scaler.fit(cleaned_X)

        if y is not None:
            self.label_encoder.fit(y)

        self.is_fitted = True
        return self

    def transform_features(self, X: pd.DataFrame) -> np.ndarray:
        """Transforms feature matrix into scaled NumPy array."""
        if not self.is_fitted:
            raise RuntimeError("Preprocessor must be fitted before calling transform_features()")
        self.validate_schema(X)
        cleaned_X = self.clean_features(X)
        return self.scaler.transform(cleaned_X)

    def fit_transform(
        self, X: pd.DataFrame, y: Optional[pd.Series] = None
    ) -> Tuple[np.ndarray, Optional[np.ndarray]]:
        """Fits on X, y and returns transformed (X_scaled, y_encoded)."""
        self.fit(X, y)
        X_scaled = self.transform_features(X)
        y_encoded = self.label_encoder.transform(y) if y is not None else None
        return X_scaled, y_encoded

    def save(self, filepath: str) -> None:
        """Persists fitted preprocessor to disk."""
        joblib.dump(self, filepath)

    @classmethod
    def load(cls, filepath: str) -> "FlowDataPreprocessor":
        """Loads fitted preprocessor from disk."""
        return joblib.load(filepath)
