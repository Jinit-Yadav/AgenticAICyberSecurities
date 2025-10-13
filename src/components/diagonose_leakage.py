import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import matplotlib.pyplot as plt
import seaborn as sns

def diagnose_data_leakage():
    """Diagnose potential data leakage issues"""
    
    # Load your ML-ready dataset
    df = pd.read_csv('artifacts/ml_ready_dataset.csv')
    
    print("🔍 DATA LEAKAGE DIAGNOSIS")
    print("=" * 60)
    
    # 1. Check correlation with target
    print("\n1. 📊 FEATURE CORRELATION WITH TARGET:")
    correlations = df.corr()['is_threat'].abs().sort_values(ascending=False)
    
    for feature, corr in correlations.head(10).items():
        if feature != 'is_threat':
            print(f"   • {feature}: {corr:.4f}")
    
    # 2. Check for perfect predictors
    print("\n2. 🎯 CHECKING FOR PERFECT PREDICTORS:")
    suspicious_features = []
    
    for column in df.columns:
        if column != 'is_threat':
            # Check if any single feature can perfectly predict the target
            unique_combinations = df.groupby(column)['is_threat'].nunique()
            if (unique_combinations == 1).any():
                suspicious_features.append(column)
                print(f"   ⚠️  {column} has perfect correlation with target in some values")
    
    # 3. Check specific suspicious features
    print("\n3. 🔎 ANALYZING SUSPICIOUS FEATURES:")
    
    # Check is_normal_traffic vs is_threat
    if 'is_normal_traffic' in df.columns:
        cross_tab = pd.crosstab(df['is_normal_traffic'], df['is_threat'])
        print(f"   is_normal_traffic vs is_threat:")
        print(f"   {cross_tab}")
        print(f"   This should be INVERSE of target!")
    
    # Check threat_score distribution
    if 'threat_score' in df.columns:
        threat_stats = df.groupby('is_threat')['threat_score'].describe()
        print(f"\n   threat_score by target class:")
        print(f"   {threat_stats}")
    
    # 4. Test with feature removal
    print("\n4. 🧪 TESTING WITH SUSPICIOUS FEATURES REMOVED:")
    
    # Remove obviously leaky features
    features_to_remove = ['is_normal_traffic', 'threat_score', 'attack_category_encoded']
    safe_features = [col for col in df.columns if col not in features_to_remove and col != 'is_threat']
    
    if safe_features:
        X_safe = df[safe_features]
        y = df['is_threat']
        
        X_train, X_test, y_train, y_test = train_test_split(X_safe, y, test_size=0.2, random_state=42)
        
        # Train simple model
        model = RandomForestClassifier(n_estimators=10, random_state=42, n_jobs=-1)
        model.fit(X_train, y_train)
        
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"   Model accuracy WITHOUT suspicious features: {accuracy:.4f}")
        print(f"   Number of safe features used: {len(safe_features)}")
    
    return suspicious_features

def create_safe_features():
    """Create a version without potentially leaky features"""
    
    df = pd.read_csv('artifacts/ml_ready_dataset.csv')
    
    # Remove features that might directly encode the target
    leaky_features = [
        'is_normal_traffic',  # This is literally the inverse of is_threat!
        'threat_score',       # Your engineered score might be too perfect
        'attack_category_encoded',  # Might directly encode threat/normal
        'is_high_severity_category', # Derived from attack category
        'is_real_attack',     # Might be too correlated
        'is_cic_data',        # Dataset source might leak info
        'is_unsw_data'        # Dataset source might leak info
    ]
    
    safe_features = [col for col in df.columns if col not in leaky_features and col != 'is_threat']
    
    print(f"\n🛡️ SAFE FEATURE SET:")
    print(f"   Original features: {len(df.columns) - 1}")
    print(f"   Safe features: {len(safe_features)}")
    print(f"   Removed {len(leaky_features)} potentially leaky features")
    
    # Create safe dataset
    safe_df = df[safe_features + ['is_threat']]
    safe_df.to_csv('artifacts/safe_ml_dataset.csv', index=False)
    
    return safe_features

def train_with_safe_features():
    """Train model with safe features only"""
    
    safe_df = pd.read_csv('artifacts/safe_ml_dataset.csv')
    
    X = safe_df.drop('is_threat', axis=1)
    y = safe_df['is_threat']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    print(f"\n🎯 TRAINING WITH SAFE FEATURES:")
    print(f"   Features: {X.shape[1]}")
    print(f"   Training samples: {X_train.shape[0]:,}")
    print(f"   Test samples: {X_test.shape[0]:,}")
    
    # Train model
    model = RandomForestClassifier(
        n_estimators=50,
        max_depth=15,
        min_samples_split=100,
        min_samples_leaf=50,
        n_jobs=-1,
        random_state=42
    )
    
    model.fit(X_train, y_train)
    
    # Evaluate
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]
    
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
    
    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    auc = roc_auc_score(y_test, y_pred_proba)
    
    print(f"\n📊 REALISTIC PERFORMANCE:")
    print(f"   Accuracy: {accuracy:.4f}")
    print(f"   Precision: {precision:.4f}")
    print(f"   Recall: {recall:.4f}")
    print(f"   F1-Score: {f1:.4f}")
    print(f"   AUC: {auc:.4f}")
    
    # Confusion matrix
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    
    print(f"\n🎯 Confusion Matrix:")
    print(f"   True Negatives: {tn:,}")
    print(f"   False Positives: {fp:,}")
    print(f"   False Negatives: {fn:,}")
    print(f"   True Positives: {tp:,}")
    
    # Save the realistic model
    joblib.dump(model, 'artifacts/realistic_cyber_threat_model.pkl')
    print(f"\n💾 Realistic model saved: artifacts/realistic_cyber_threat_model.pkl")
    
    return model, accuracy

if __name__ == "__main__":
    print("🔍 CYBER THREAT MODEL - DATA LEAKAGE DIAGNOSIS")
    print("=" * 60)
    
    # Step 1: Diagnose the issue
    suspicious_features = diagnose_data_leakage()
    
    # Step 2: Create safe features
    safe_features = create_safe_features()
    
    # Step 3: Train with safe features
    model, accuracy = train_with_safe_features()
    
    print(f"\n🎯 INTERPRETATION:")
    if accuracy > 0.95:
        print("   ⚠️  Still suspiciously high - there might be more leakage")
    elif accuracy > 0.85:
        print("   ✅ Good performance - more realistic")
    else:
        print("   📉 Performance dropped significantly - features might be weak")