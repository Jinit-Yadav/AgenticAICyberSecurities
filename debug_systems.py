#!/usr/bin/env python3
"""
UPDATED DEBUG SCRIPT - Uses clean model without leakage
Run: python debug_systems.py
"""

import pandas as pd
import numpy as np
import joblib
import os
from pathlib import Path

PROJECT_ROOT = Path.cwd()
ARTIFACTS_DIR = PROJECT_ROOT / 'artifacts'

print("=" * 80)
print("🔍 DEBUG WITH CLEAN MODEL (No Data Leakage)")
print("=" * 80)

# ============================================================================
# CHECK FOR CLEAN MODEL
# ============================================================================
print("\n📁 Checking for clean model artifacts...")

clean_model_path = ARTIFACTS_DIR / 'clean_model.pkl'
clean_scaler_path = ARTIFACTS_DIR / 'clean_scaler.pkl'
clean_features_path = ARTIFACTS_DIR / 'clean_features.pkl'

if not clean_model_path.exists():
    print("\n❌ Clean model not found!")
    print("   Please run: python retrain_clean_model.py first")
    exit(1)

print("✅ Clean model artifacts found")

# ============================================================================
# LOAD CLEAN MODEL
# ============================================================================
print("\n🤖 Loading clean model...")

model = joblib.load(clean_model_path)
scaler = joblib.load(clean_scaler_path)
features = joblib.load(clean_features_path)

print(f"   Model: {type(model).__name__}")
print(f"   Features: {len(features)}")

# ============================================================================
# LOAD AND PREPARE DATA
# ============================================================================
print("\n📊 Preparing data without leakage...")

df = pd.read_csv(ARTIFACTS_DIR / 'ml_ready_dataset.csv')

# Remove leakage features
leakage_features = [
    'threat_score', 'is_high_risk_tool', 'is_recon_tool', 
    'is_high_severity_category', 'is_real_attack', 'is_cic_data',
    'is_unsw_data', 'is_normal_traffic', 'is_recon_activity',
    'attack_category_encoded', 'severity_encoded', 'tool_encoded'
]

existing_leakage = [col for col in leakage_features if col in df.columns]
df_clean = df.drop(columns=existing_leakage)

# Remove timestamp
if 'timestamp' in df_clean.columns:
    df_clean = df_clean.drop(columns=['timestamp'])

# Separate features and target
X = df_clean.drop('is_threat', axis=1)
y = df_clean['is_threat']

# Keep only features that match our clean model
X = X[[col for col in features if col in X.columns]]
print(f"   Clean data shape: {X.shape}")
print(f"   Features match: {len(features)}/{X.shape[1]}")

# ============================================================================
# TEST PREDICTIONS
# ============================================================================
print("\n🧪 Testing predictions on sample data...")

# Take a small sample for testing
sample_size = 10000
X_sample = X.head(sample_size)
y_sample = y.head(sample_size)

# Scale and predict
X_scaled = scaler.transform(X_sample)
y_pred = model.predict(X_scaled)
y_proba = model.predict_proba(X_scaled)[:, 1]

# Calculate metrics
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

accuracy = accuracy_score(y_sample, y_pred)
precision = precision_score(y_sample, y_pred)
recall = recall_score(y_sample, y_pred)
f1 = f1_score(y_sample, y_pred)
cm = confusion_matrix(y_sample, y_pred)

print(f"\n📊 Performance Metrics (sample of {sample_size:,} records):")
print(f"   Accuracy:  {accuracy:.4f}")
print(f"   Precision: {precision:.4f}")
print(f"   Recall:    {recall:.4f}")
print(f"   F1-Score:  {f1:.4f}")

tn, fp, fn, tp = cm.ravel()
print(f"\n📈 Confusion Matrix:")
print(f"   True Negatives: {tn:,}")
print(f"   False Positives: {fp:,}")
print(f"   False Negatives: {fn:,}")
print(f"   True Positives: {tp:,}")

# ============================================================================
# TEST INDIVIDUAL SAMPLES
# ============================================================================
print("\n🎯 Testing individual samples...")

# Find a normal sample (is_threat=0)
normal_samples = X[y == 0]
if len(normal_samples) > 0:
    normal_sample = normal_samples.iloc[0:1]
    normal_scaled = scaler.transform(normal_sample)
    normal_pred = model.predict(normal_scaled)[0]
    normal_proba = model.predict_proba(normal_scaled)[0][1]
    
    print(f"\n   Normal Traffic Sample:")
    print(f"   Expected: NORMAL")
    print(f"   Predicted: {'THREAT' if normal_pred == 1 else 'NORMAL'}")
    print(f"   Confidence: {(1-normal_proba)*100 if normal_pred == 0 else normal_proba*100:.1f}%")

# Find an attack sample (is_threat=1)
attack_samples = X[y == 1]
if len(attack_samples) > 0:
    attack_sample = attack_samples.iloc[0:1]
    attack_scaled = scaler.transform(attack_sample)
    attack_pred = model.predict(attack_scaled)[0]
    attack_proba = model.predict_proba(attack_scaled)[0][1]
    
    print(f"\n   Attack Traffic Sample:")
    print(f"   Expected: THREAT")
    print(f"   Predicted: {'THREAT' if attack_pred == 1 else 'NORMAL'}")
    print(f"   Confidence: {attack_proba*100:.1f}%")

# ============================================================================
# FINAL VERDICT
# ============================================================================
print("\n" + "=" * 80)
print("✅ DEBUG COMPLETE")
print("=" * 80)

if accuracy > 0.95:
    print("\n⚠️ WARNING: Accuracy still >95% - check if more leakage exists")
elif accuracy > 0.85:
    print("\n✅ GOOD: Realistic accuracy for cybersecurity (85-95%)")
else:
    print("\n⚠️ Low accuracy - model may need more features or data")

print("\n📊 REALISTIC EXPECTATIONS FOR CYBERSECURITY:")
print("   • Accuracy: 85-95% (not 99.9%)")
print("   • False Positive Rate: 2-8%")
print("   • False Negative Rate: 2-8%")
print("   • F1-Score: 0.85-0.95")

if normal_pred == 0 and attack_pred == 1:
    print("\n✅ MODEL WORKING CORRECTLY!")
    print("   The clean model distinguishes normal from attack traffic")
else:
    print("\n❌ MODEL STILL HAS ISSUES")
    print("   Check that leakage features were properly removed")