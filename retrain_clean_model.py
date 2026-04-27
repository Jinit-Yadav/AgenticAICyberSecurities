#!/usr/bin/env python3
"""
RETRAIN MODEL WITHOUT DATA LEAKAGE
Run this FIRST: python retrain_clean_model.py
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib
import warnings
warnings.filterwarnings('ignore')

print("=" * 80)
print("🔄 RETRAINING MODEL WITHOUT DATA LEAKAGE")
print("=" * 80)

# Load data
print("\n📊 Loading dataset...")
df = pd.read_csv('artifacts/ml_ready_dataset.csv')
print(f"   Shape: {df.shape}")

# ============================================================================
# REMOVE ALL LEAKAGE FEATURES
# ============================================================================
print("\n🔧 Removing leakage features...")

leakage_features = [
    'threat_score', 'is_high_risk_tool', 'is_recon_tool', 
    'is_high_severity_category', 'is_real_attack', 'is_cic_data',
    'is_unsw_data', 'is_normal_traffic', 'is_recon_activity',
    'attack_category_encoded', 'severity_encoded', 'tool_encoded'
]

existing_leakage = [col for col in leakage_features if col in df.columns]
df_clean = df.drop(columns=existing_leakage)
print(f"   Removed {len(existing_leakage)} leakage features")
print(f"   Remaining features: {len(df_clean.columns)}")

# ============================================================================
# PREPARE FEATURES
# ============================================================================
print("\n🔧 Preparing features...")

# Remove timestamp if exists
if 'timestamp' in df_clean.columns:
    df_clean = df_clean.drop(columns=['timestamp'])

# Separate features and target
X = df_clean.drop('is_threat', axis=1)
y = df_clean['is_threat']

# Remove constant columns
constant_cols = [col for col in X.columns if X[col].nunique() == 1]
if constant_cols:
    X = X.drop(columns=constant_cols)
    print(f"   Removed {len(constant_cols)} constant columns")

print(f"   Final features: {X.shape[1]}")
print(f"   Features: {list(X.columns[:10])}...")

# ============================================================================
# TRAIN/TEST SPLIT
# ============================================================================
print("\n🔧 Creating train/test split...")
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"   Train: {len(X_train):,} samples")
print(f"   Test: {len(X_test):,} samples")

# ============================================================================
# SCALE FEATURES
# ============================================================================
print("\n🔧 Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)
print("   Scaling complete")

# ============================================================================
# TRAIN MODEL
# ============================================================================
print("\n🔧 Training LightGBM model...")
from lightgbm import LGBMClassifier

model = LGBMClassifier(
    n_estimators=100,
    max_depth=8,
    learning_rate=0.1,
    random_state=42,
    verbose=-1
)

model.fit(X_train_scaled, y_train)
print("   Training complete")

# ============================================================================
# EVALUATE
# ============================================================================
print("\n📊 Model Evaluation")
print("-" * 60)

y_pred = model.predict(X_test_scaled)
y_pred_proba = model.predict_proba(X_test_scaled)[:, 1]

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print(f"   Accuracy:  {accuracy:.4f}")
print(f"   Precision: {precision:.4f}")
print(f"   Recall:    {recall:.4f}")
print(f"   F1-Score:  {f1:.4f}")

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
tn, fp, fn, tp = cm.ravel()

print(f"\n   Confusion Matrix:")
print(f"   TN: {tn:,} (Normal correct)")
print(f"   FP: {fp:,} (False alarms)")
print(f"   FN: {fn:,} (Missed threats)")
print(f"   TP: {tp:,} (Threats caught)")

# ============================================================================
# TEST WITH REALISTIC SAMPLES
# ============================================================================
print("\n🧪 Testing with realistic samples...")

# Create a simple test function
def predict_traffic(features_dict):
    """Predict using the clean model"""
    # Create feature vector in correct order
    feature_vector = []
    for col in X.columns:
        feature_vector.append(features_dict.get(col, 0))
    
    # Scale and predict
    scaled = scaler.transform([feature_vector])
    pred = model.predict(scaled)[0]
    proba = model.predict_proba(scaled)[0][1]
    return pred, proba

# Test normal traffic (using median values of normal samples)
normal_samples = X_train[y_train == 0].median().to_dict()
normal_pred, normal_proba = predict_traffic(normal_samples)

print(f"\n   Normal Traffic Test:")
print(f"   Prediction: {'THREAT' if normal_pred == 1 else 'NORMAL'}")
print(f"   Confidence: {(1-normal_proba)*100 if normal_pred == 0 else normal_proba*100:.1f}%")

# Test attack traffic (using median values of attack samples)
attack_samples = X_train[y_train == 1].median().to_dict()
attack_pred, attack_proba = predict_traffic(attack_samples)

print(f"\n   Attack Traffic Test:")
print(f"   Prediction: {'THREAT' if attack_pred == 1 else 'NORMAL'}")
print(f"   Confidence: {attack_proba*100:.1f}%")

# ============================================================================
# SAVE CLEAN MODEL
# ============================================================================
print("\n💾 Saving clean model...")

joblib.dump(model, 'artifacts/clean_model.pkl')
joblib.dump(scaler, 'artifacts/clean_scaler.pkl')
joblib.dump(X.columns.tolist(), 'artifacts/clean_features.pkl')

print(f"   ✅ Clean model saved to: artifacts/clean_model.pkl")
print(f"   ✅ Scaler saved to: artifacts/clean_scaler.pkl")
print(f"   ✅ Features saved to: artifacts/clean_features.pkl")

print("\n" + "=" * 80)
print("✅ CLEAN MODEL READY!")
print("=" * 80)
print("\nNow run: python debug_systems.py")