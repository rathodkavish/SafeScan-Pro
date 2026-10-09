"""
SafeScan Pro - Model Training Script
Run this once to train and save the phishing detection model.
Usage: python3 train_model.py

Saves TWO files:
  - models/trained_models/url_model.pkl   (dict with model + scaler + metadata)
  - models/trained_models/url_scaler.pkl  (raw scaler for backward compat)
"""

import pandas as pd
import numpy as np
import joblib
import os
from sklearn.tree import DecisionTreeClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

print("=" * 55)
print("  SafeScan Pro — Phishing URL Model Training")
print("=" * 55)

# ── Step 1: Load Dataset ─────────────────────────────────
BASE_DIR     = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, 'phishing_dataset.csv')
OUTPUT_DIR   = os.path.join(BASE_DIR, 'models', 'trained_models')
MODEL_PATH   = os.path.join(OUTPUT_DIR, 'url_model.pkl')
SCALER_PATH  = os.path.join(OUTPUT_DIR, 'url_scaler.pkl')

os.makedirs(OUTPUT_DIR, exist_ok=True)

print(f"\n[1/6] Loading dataset from: {DATASET_PATH}")
df = pd.read_csv(DATASET_PATH)
print(f"      Total rows    : {len(df)}")
print(f"      Phishing URLs : {df['label'].sum()}")
print(f"      Safe URLs     : {(df['label'] == 0).sum()}")
print(f"      Features      : {len(df.columns) - 1}")

# ── Step 2: Split Features & Labels ──────────────────────
print("\n[2/6] Splitting features and labels...")
X = df.drop('label', axis=1)
y = df['label']

FEATURE_NAMES = list(X.columns)
print(f"      Feature names: {FEATURE_NAMES}")
print(f"      Feature count: {len(FEATURE_NAMES)}")

# ── Step 3: Scale Features ────────────────────────────────
print("\n[3/6] Applying StandardScaler...")
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)
print("      Scaling complete.")

# ── Step 4: Train/Test Split ──────────────────────────────
print("\n[4/6] Splitting into train (80%) and test (20%) sets...")
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)
print(f"      Training samples : {len(X_train)}")
print(f"      Testing samples  : {len(X_test)}")

# ── Step 5: Train Model ───────────────────────────────────
print("\n[5/6] Training DecisionTreeClassifier...")
model = DecisionTreeClassifier(
    max_depth=12,
    min_samples_split=10,
    min_samples_leaf=5,
    criterion='gini',
    random_state=42
)
model.fit(X_train, y_train)
print("      Training complete.")

# ── Step 6: Evaluate ──────────────────────────────────────
print("\n[6/6] Evaluating model on test set...")
y_pred = model.predict(X_test)
acc    = accuracy_score(y_test, y_pred)

print(f"\n{'='*55}")
print(f"  MODEL ACCURACY: {acc * 100:.2f}%")
print(f"{'='*55}")
print("\nClassification Report:")
print(classification_report(y_test, y_pred,
      target_names=['Safe (0)', 'Phishing (1)']))

cm = confusion_matrix(y_test, y_pred)
print("Confusion Matrix:")
print(f"  True Safe (correct)     : {cm[0][0]}")
print(f"  False Phishing (wrong)  : {cm[0][1]}")
print(f"  False Safe (wrong)      : {cm[1][0]}")
print(f"  True Phishing (correct) : {cm[1][1]}")

# ── Save Model (dict format — compatible with url_classifier.py) ─────────────
model_bundle = {
    'model':         model,
    'scaler':        scaler,
    'feature_names': FEATURE_NAMES,
    'accuracy':      round(acc * 100, 2),
    'trained_on':    len(X_train),
}
joblib.dump(model_bundle, MODEL_PATH)

# Also save scaler separately for backward compatibility
joblib.dump(scaler, SCALER_PATH)

print(f"\n[SAVED] Model saved to: {MODEL_PATH}")
print(f"        Scaler saved to: {SCALER_PATH}")
print(f"        Accuracy : {acc * 100:.2f}%")
print(f"        Features : {len(FEATURE_NAMES)}")
print("\nYou can now start the Flask backend — it will load this model automatically.")
print("=" * 55)
