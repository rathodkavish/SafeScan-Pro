"""
backend/models/url_classifier.py
Loads the pre-trained phishing detection model and scaler.

Handles two on-disk formats:
  A) Separate files  — url_model.pkl (raw model) + url_scaler.pkl (raw scaler)
  B) Dict file       — url_model.pkl is a dict with 'model' and optionally 'scaler'

If no saved model is found, trains a lightweight RandomForest on dummy data
so the server can start. The real model should be produced by train_model.py.
"""

import os
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler


class URLClassifier:

    def __init__(self):
        base = os.path.dirname(os.path.abspath(__file__))
        self.model_dir  = os.path.join(base, "trained_models")
        self.model_path = os.path.join(self.model_dir, "url_model.pkl")
        self.scaler_path = os.path.join(self.model_dir, "url_scaler.pkl")
        self.model  = None
        self.scaler = None

    # ── Fallback training (dummy data — for dev only) ────────────────────────
    def train(self):
        """Train on random dummy data so the server can start without a real model."""
        n_features = 30  # must match feature_extractor.FEATURE_ORDER length
        safe     = np.random.randint(1, 20, (300, n_features))
        phishing = np.random.randint(20, 100, (300, n_features))

        X = np.vstack([safe, phishing])
        y = np.array([0] * 300 + [1] * 300)

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X_scaled, y)

        os.makedirs(self.model_dir, exist_ok=True)
        joblib.dump(self.model,  self.model_path)
        joblib.dump(self.scaler, self.scaler_path)

        print("[WARN] ML model trained on DUMMY data (run train_model.py for real model)")

    # ── Load model (handles both formats) ────────────────────────────────────
    def load(self):
        if not os.path.exists(self.model_path):
            print("[WARN] No trained model found -- training fallback model...")
            self.train()
            return

        raw = joblib.load(self.model_path)

        # Format B: dict with 'model' key (from train_model.py)
        if isinstance(raw, dict) and "model" in raw:
            self.model = raw["model"]
            # Scaler may be embedded in the dict or saved separately
            if "scaler" in raw and raw["scaler"] is not None:
                self.scaler = raw["scaler"]
            elif os.path.exists(self.scaler_path):
                self.scaler = joblib.load(self.scaler_path)
            else:
                self.scaler = None
            acc = raw.get("accuracy", "?")
            print(f"[OK] ML model loaded (dict format, accuracy={acc}%)")
        else:
            # Format A: raw model object
            self.model = raw
            if os.path.exists(self.scaler_path):
                self.scaler = joblib.load(self.scaler_path)
            else:
                self.scaler = None
            print("[OK] ML model loaded (raw format)")

    # ── Predict ──────────────────────────────────────────────────────────────
    def predict(self, features):
        """
        Accepts a list of numeric features (length must match model's n_features).
        Returns dict with is_phishing (bool) and confidence (0-100).
        """
        try:
            X = np.array(features).reshape(1, -1)

            # Apply scaler if available
            if self.scaler is not None:
                X = self.scaler.transform(X)

            prob = float(self.model.predict_proba(X)[0][1])

            return {
                "is_phishing": bool(prob > 0.5),
                "confidence":  round(prob * 100, 2),
            }
        except Exception as e:
            print(f"[ERR] ML predict failed: {e}")
            return {
                "is_phishing": False,
                "confidence":  0.0,
                "error":       str(e),
            }


# Global instance
url_classifier = URLClassifier()
