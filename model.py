# model.py
import joblib
import numpy as np
from typing import Dict, List, Optional
from config import MODEL_PATH, SCALER_PATH, FEATURES_IN_ORDER, USE_PROBA,THRESHOLD

class Detector:
    def __init__(self):
        self.model = joblib.load(MODEL_PATH)
        self.scaler = joblib.load(SCALER_PATH) if SCALER_PATH and SCALER_PATH.exists() else None

    def vectorize(self, feat_map: Dict[str, float]) -> np.ndarray:
        # Produce [1, n_features] in the exact order expected
        x = np.array([feat_map[name] for name in FEATURES_IN_ORDER], dtype=float).reshape(1, -1)
        if self.scaler is not None:
            x = self.scaler.transform(x)
        return x

    def score(self, feat_map: Dict[str, float]) -> Dict[str, float]:
        x = self.vectorize(feat_map)
        if USE_PROBA and hasattr(self.model, "predict_proba"):
            proba = float(self.model.predict_proba(x)[0, 1])
            pred = 1 if proba >= THRESHOLD else 0
            return {"pred": pred, "proba": proba}
        else:
            pred = int(self.model.predict(x)[0])
            return {"pred": pred, "proba": float(pred)}
