#!/usr/bin/env python3
"""
CLEAN MODEL TRAINER - NO DATA LEAKAGE
Run: python clean_trainer.py
"""

import os
import sys
import pandas as pd
import numpy as np
import joblib
import time
from dataclasses import dataclass
from sklearn.ensemble import VotingClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import SelectKBest, f_classif
import warnings
warnings.filterwarnings('ignore')

# Fix import paths
current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(os.path.dirname(current_dir))
sys.path.append(project_root)

try:
    from src.logger import logging
    from src.exception import CustomException
except ImportError:
    from logger import logging
    from exception import CustomException

@dataclass
class CleanModelTrainerConfig:
    """
    Configuration for Clean Model Training (No Data Leakage)
    """
    trained_model_path: str = os.path.join('artifacts', 'clean_model.pkl')
    ensemble_model_path: str = os.path.join('artifacts', 'clean_ensemble.pkl')
    model_performance_path: str = os.path.join('artifacts', 'clean_model_performance.json')
    feature_importance_path: str = os.path.join('artifacts', 'clean_feature_importance.csv')
    training_report_path: str = os.path.join('artifacts', 'clean_training_report.txt')

class CleanCybersecurityModel:
    """
    CLEAN model training WITHOUT data leakage
    """
    
    def __init__(self):
        self.models = {}
        self.best_model = None
        self.best_score = 0
        self.scaler = StandardScaler()
        self.feature_selector = None
        self.selected_features = []
        self.feature_importance_df = None
        
        # Define leakage features to remove
        self.leakage_features = [
            'threat_score', 'is_high_risk_tool', 'is_recon_tool', 
            'is_high_severity_category', 'is_real_attack', 'is_cic_data',
            'is_unsw_data', 'is_normal_traffic', 'is_recon_activity',
            'attack_category_encoded', 'severity_encoded', 'tool_encoded',
            'tool_threat_score', 'category_threat_score', 'severity_threat_score'
        ]
        
    def load_and_clean_data(self):
        """
        Load data and remove ALL leakage features
        """
        print("🚀 LOADING AND CLEANING DATA (REMOVING LEAKAGE)")
        print("=" * 80)
        
        # Load the ML-ready dataset
        data_path = 'artifacts/ml_ready_dataset.csv'
        
        if not os.path.exists(data_path):
            raise CustomException(f"Data not found at {data_path}. Run data_transformation first!")
        
        print(f"✅ Loading data from: {data_path}")
        df = pd.read_csv(data_path, low_memory=False)
        print(f"   Original shape: {df.shape}")
        print(f"   Original features: {len(df.columns)}")
        
        # Check for target column
        if 'is_threat' not in df.columns:
            raise CustomException("Target column 'is_threat' not found!")
        
        # Remove leakage features
        print(f"\n🔧 Removing {len(self.leakage_features)} potential leakage features...")
        existing_leakage = [col for col in self.leakage_features if col in df.columns]
        df_clean = df.drop(columns=existing_leakage)
        print(f"   Removed {len(existing_leakage)} leakage features")
        print(f"   Remaining features: {len(df_clean.columns)}")
        
        # Remove timestamp if exists
        if 'timestamp' in df_clean.columns:
            df_clean = df_clean.drop(columns=['timestamp'])
            print(f"   Removed timestamp column")
        
        # Display remaining feature categories
        print(f"\n📊 REMAINING FEATURE CATEGORIES:")
        feature_cols = [col for col in df_clean.columns if col != 'is_threat']
        
        time_features = [col for col in feature_cols if any(x in col.lower() for x in ['hour', 'day', 'weekend', 'night'])]
        ip_features = [col for col in feature_cols if any(x in col.lower() for x in ['ip', 'request', 'target'])]
        port_features = [col for col in feature_cols if 'port' in col.lower()]
        protocol_features = [col for col in feature_cols if any(x in col.lower() for x in ['tcp', 'udp', 'icmp', 'protocol'])]
        cic_features = [col for col in feature_cols if any(x in col.lower() for x in ['dur', 'pkt', 'byte', 'rate', 'sttl', 'dttl'])]
        service_features = [col for col in feature_cols if 'service' in col.lower()]
        
        print(f"   • Time-based Features: {len(time_features)}")
        print(f"   • IP Behavior Features: {len(ip_features)}")
        print(f"   • Port Features: {len(port_features)}")
        print(f"   • Protocol Features: {len(protocol_features)}")
        print(f"   • CIC Flow Features: {len(cic_features)}")
        print(f"   • Service Features: {len(service_features)}")
        
        return df_clean
    
    def prepare_features(self, df):
        """
        Prepare features WITHOUT data leakage
        """
        print("\n🔧 PREPARING FEATURES (NO DATA LEAKAGE)")
        print("=" * 50)
        
        # Separate features and target
        X = df.drop('is_threat', axis=1)
        y = df['is_threat']
        
        # Remove constant columns
        print("\n   📊 Removing constant columns...")
        constant_cols = [col for col in X.columns if X[col].nunique() == 1]
        if constant_cols:
            X = X.drop(columns=constant_cols)
            print(f"   • Removed {len(constant_cols)} constant columns")
        else:
            print(f"   • No constant columns found")
        
        # Remove high missing value columns (>50% missing)
        missing_threshold = 0.5
        missing_cols = [col for col in X.columns if X[col].isnull().mean() > missing_threshold]
        if missing_cols:
            X = X.drop(columns=missing_cols)
            print(f"   • Removed {len(missing_cols)} columns with >50% missing values")
        
        # Fill remaining missing values
        print(f"\n   📊 Handling missing values...")
        numeric_cols = X.select_dtypes(include=[np.number]).columns
        X[numeric_cols] = X[numeric_cols].fillna(X[numeric_cols].median())
        
        print(f"\n   Final feature count: {X.shape[1]}")
        print(f"   Features: {list(X.columns[:15])}...")
        
        return X, y
    
    def create_train_test_split(self, X, y):
        """
        Create train/test split with stratification
        """
        print("\n📊 CREATING TRAIN/TEST SPLIT")
        print("=" * 50)
        
        # Use stratified split to maintain class balance
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"   Training set: {len(X_train):,} samples")
        print(f"   Test set: {len(X_test):,} samples")
        print(f"   Training threats: {y_train.sum():,} ({y_train.mean()*100:.1f}%)")
        print(f"   Test threats: {y_test.sum():,} ({y_test.mean()*100:.1f}%)")
        
        return X_train, X_test, y_train, y_test
    
    def select_features(self, X_train, y_train, X_test, n_features=25):
        """
        Feature selection using ANOVA F-test
        """
        print(f"\n🎯 FEATURE SELECTION (Top {n_features} features)")
        print("=" * 50)
        
        # Limit features to avoid overfitting
        k_features = min(n_features, X_train.shape[1])
        self.feature_selector = SelectKBest(score_func=f_classif, k=k_features)
        X_train_selected = self.feature_selector.fit_transform(X_train, y_train)
        X_test_selected = self.feature_selector.transform(X_test)
        
        # Get selected feature names
        self.selected_features = X_train.columns[self.feature_selector.get_support()].tolist()
        
        print(f"   • Selected {len(self.selected_features)} features (from {X_train.shape[1]})")
        print(f"   • Removed {X_train.shape[1] - len(self.selected_features)} features")
        print(f"\n   Top 10 selected features:")
        for i, feat in enumerate(self.selected_features[:10], 1):
            print(f"      {i:2d}. {feat}")
        
        return X_train_selected, X_test_selected
    
    def scale_features(self, X_train, X_test):
        """
        Standardize features
        """
        print("\n⚖️ FEATURE SCALING")
        print("=" * 50)
        
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        print(f"   • Scaler fitted on {X_train.shape[1]} features")
        print(f"   • Training shape: {X_train_scaled.shape}")
        print(f"   • Test shape: {X_test_scaled.shape}")
        
        return X_train_scaled, X_test_scaled
    
    def define_models(self):
        """
        Define optimized models for cybersecurity detection
        """
        print("\n🤖 INITIALIZING MODELS")
        print("=" * 50)
        
        self.models = {
            'XGBoost': {
                'model': XGBClassifier(
                    random_state=42, 
                    n_jobs=-1, 
                    verbosity=0,
                    eval_metric='logloss',
                    use_label_encoder=False
                ),
                'params': {
                    'n_estimators': [100, 200],
                    'max_depth': [6, 8],
                    'learning_rate': [0.05, 0.1],
                    'subsample': [0.8, 0.9],
                    'colsample_bytree': [0.8, 0.9],
                },
                'reason': "Best-in-class for structured data"
            },
            'LightGBM': {
                'model': LGBMClassifier(
                    random_state=42, 
                    n_jobs=-1, 
                    verbose=-1,
                    force_col_wise=True
                ),
                'params': {
                    'n_estimators': [100, 200],
                    'max_depth': [6, 8],
                    'learning_rate': [0.05, 0.1],
                    'num_leaves': [31, 50],
                    'subsample': [0.8, 0.9],
                },
                'reason': "Fast training with excellent accuracy"
            }
        }
        
        print("\n   🎯 MODEL SELECTION STRATEGY:")
        for name, config in self.models.items():
            print(f"   • {name}: {config['reason']}")
    
    def hyperparameter_tuning(self, X_train, y_train):
        """
        Hyperparameter tuning with cross-validation
        """
        print("\n⚡ HYPERPARAMETER TUNING")
        print("=" * 50)
        print("   Strategy: RandomizedSearchCV with 3-fold CV")
        print("   Optimization: F1-Score")
        print("   Iterations: 10 per model (optimized for speed)")
        
        tuned_models = {}
        
        for name, config in self.models.items():
            print(f"\n   🔧 Tuning {name}...")
            start_time = time.time()
            
            # Randomized search for efficiency
            search = RandomizedSearchCV(
                config['model'], 
                config['params'],
                n_iter=10,  # Reduced for faster training
                cv=3,
                scoring='f1',
                n_jobs=-1,
                random_state=42,
                verbose=0
            )
            
            search.fit(X_train, y_train)
            tuned_models[name] = search.best_estimator_
            
            end_time = time.time()
            print(f"      ✅ Best F1: {search.best_score_:.4f}")
            print(f"      ⏱️  Time: {end_time - start_time:.1f}s")
            print(f"      📋 Best params: {search.best_params_}")
        
        return tuned_models
    
    def build_ensemble(self, X_train, y_train, tuned_models):
        """
        Build voting ensemble from tuned models
        """
        print("\n🎭 BUILDING ENSEMBLE MODEL")
        print("=" * 50)
        print("   Strategy: Soft Voting (probabilistic combination)")
        
        # Prepare estimators for voting
        estimators = [(name.lower(), model) for name, model in tuned_models.items()]
        
        # Create soft voting classifier
        voting_clf = VotingClassifier(
            estimators=estimators,
            voting='soft',
            n_jobs=-1
        )
        
        # Train on full training set
        voting_clf.fit(X_train, y_train)
        
        # Combine all models
        all_models = {'Voting_Ensemble': voting_clf, **tuned_models}
        
        print(f"   ✅ Ensemble created with {len(estimators)} models")
        
        return all_models
    
    def evaluate_models(self, models, X_test, y_test):
        """
        Comprehensive model evaluation
        """
        print("\n📊 MODEL EVALUATION")
        print("=" * 80)
        
        results = {}
        best_model_name = None
        best_f1 = 0
        
        for name, model in models.items():
            # Make predictions
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
            
            # Calculate metrics
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred)
            recall = recall_score(y_test, y_pred)
            f1 = f1_score(y_test, y_pred)
            auc = roc_auc_score(y_test, y_pred_proba) if y_pred_proba is not None else 0
            
            results[name] = {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'auc': auc,
                'model': model
            }
            
            # Display results
            print(f"\n🏆 {name}:")
            print(f"   • Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
            print(f"   • Precision: {precision:.4f}")
            print(f"   • Recall:    {recall:.4f}")
            print(f"   • F1-Score:  {f1:.4f}")
            print(f"   • AUC:       {auc:.4f}")
            
            # Track best model
            if f1 > best_f1:
                best_f1 = f1
                best_model_name = name
                self.best_model = model
                self.best_score = f1
        
        # Detailed analysis for best model
        if self.best_model:
            y_pred_best = self.best_model.predict(X_test)
            cm = confusion_matrix(y_test, y_pred_best)
            tn, fp, fn, tp = cm.ravel()
            
            print(f"\n🎯 BEST MODEL: {best_model_name}")
            print(f"📈 CONFUSION MATRIX:")
            print(f"   • True Negatives (Correct Normal): {tn:,}")
            print(f"   • False Positives (False Alarms): {fp:,}")
            print(f"   • False Negatives (Missed Threats): {fn:,}")
            print(f"   • True Positives (Detected Threats): {tp:,}")
            
            # Operational metrics
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
            
            print(f"\n📊 OPERATIONAL METRICS:")
            print(f"   • False Positive Rate: {fpr:.4f} ({fpr*100:.2f}%)")
            print(f"   • False Negative Rate: {fnr:.4f} ({fnr*100:.2f}%)")
            print(f"   • Detection Rate: {recall:.4f} ({recall*100:.2f}%)")
        
        return results, best_model_name
    
    def analyze_feature_importance(self):
        """
        Analyze feature importance from the best model
        """
        if not self.selected_features:
            print("\n⚠️ No selected features available")
            return
        
        print("\n🔍 FEATURE IMPORTANCE ANALYSIS")
        print("=" * 80)
        
        # Try to get feature importance
        if hasattr(self.best_model, 'feature_importances_'):
            importances = self.best_model.feature_importances_
            
            self.feature_importance_df = pd.DataFrame({
                'feature': self.selected_features,
                'importance': importances
            }).sort_values('importance', ascending=False)
            
            print(f"\n📊 TOP 15 MOST IMPORTANT FEATURES:")
            for i, row in self.feature_importance_df.head(15).iterrows():
                print(f"   {i+1:2d}. {row['feature']}: {row['importance']:.4f}")
            
            # Save feature importance
            self.feature_importance_df.to_csv(
                CleanModelTrainerConfig.feature_importance_path, 
                index=False
            )
            print(f"\n✅ Feature importance saved to: {CleanModelTrainerConfig.feature_importance_path}")
        else:
            print("   ℹ️ Best model doesn't provide feature importances")
    
    def save_models_and_artifacts(self, results, best_model_name):
        """
        Save all trained models and preprocessing artifacts
        """
        print("\n💾 SAVING MODELS AND ARTIFACTS")
        print("=" * 50)
        
        # Create artifacts directory
        os.makedirs('artifacts', exist_ok=True)
        
        # Save best model
        joblib.dump(self.best_model, CleanModelTrainerConfig.trained_model_path)
        print(f"   ✅ Best model saved: {CleanModelTrainerConfig.trained_model_path}")
        
        # Save ensemble if it's the best
        if best_model_name == 'Voting_Ensemble':
            joblib.dump(self.best_model, CleanModelTrainerConfig.ensemble_model_path)
            print(f"   ✅ Ensemble model saved: {CleanModelTrainerConfig.ensemble_model_path}")
        
        # Save preprocessing objects
        joblib.dump(self.scaler, 'artifacts/clean_scaler.pkl')
        joblib.dump(self.feature_selector, 'artifacts/clean_selector.pkl')
        joblib.dump(self.selected_features, 'artifacts/clean_features.pkl')
        print(f"   ✅ Preprocessing objects saved (clean_scaler.pkl, clean_selector.pkl, clean_features.pkl)")
        
        # Save performance metrics
        self.save_performance_report(results, best_model_name)
        
        # Generate training report
        self.generate_training_report(results, best_model_name)
    
    def save_performance_report(self, results, best_model_name):
        """
        Save performance metrics to JSON
        """
        report = {
            'best_model': best_model_name,
            'best_f1_score': float(self.best_score),
            'features_used': len(self.selected_features),
            'leakage_features_removed': len(self.leakage_features),
            'model_performance': {}
        }
        
        for name, metrics in results.items():
            report['model_performance'][name] = {
                'accuracy': float(metrics['accuracy']),
                'precision': float(metrics['precision']),
                'recall': float(metrics['recall']),
                'f1_score': float(metrics['f1']),
                'auc': float(metrics['auc'])
            }
        
        import json
        with open(CleanModelTrainerConfig.model_performance_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"   ✅ Performance report saved: {CleanModelTrainerConfig.model_performance_path}")
    
    def generate_training_report(self, results, best_model_name):
        """
        Generate comprehensive training report
        """
        report_path = CleanModelTrainerConfig.training_report_path
        
        with open(report_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("CLEAN CYBERSECURITY THREAT DETECTION - TRAINING REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("DATA LEAKAGE PREVENTION:\n")
            f.write("-" * 40 + "\n")
            f.write(f"• Leakage features removed: {len(self.leakage_features)}\n")
            f.write(f"• Features used in training: {len(self.selected_features)}\n")
            f.write(f"• Train/Test split: 80/20 with stratification\n\n")
            
            f.write(f"BEST MODEL: {best_model_name}\n")
            f.write(f"BEST F1-SCORE: {self.best_score:.4f}\n\n")
            
            f.write("MODEL PERFORMANCE SUMMARY:\n")
            f.write("-" * 40 + "\n")
            for name, metrics in results.items():
                f.write(f"\n{name}:\n")
                f.write(f"  • Accuracy:  {metrics['accuracy']:.4f}\n")
                f.write(f"  • Precision: {metrics['precision']:.4f}\n")
                f.write(f"  • Recall:    {metrics['recall']:.4f}\n")
                f.write(f"  • F1-Score:  {metrics['f1']:.4f}\n")
                f.write(f"  • AUC:       {metrics['auc']:.4f}\n")
            
            if self.feature_importance_df is not None:
                f.write("\n" + "=" * 80 + "\n")
                f.write("TOP 10 FEATURES:\n")
                f.write("-" * 40 + "\n")
                for i, row in self.feature_importance_df.head(10).iterrows():
                    f.write(f"  {i+1}. {row['feature']}: {row['importance']:.4f}\n")
        
        print(f"   ✅ Training report saved: {report_path}")
    
    def run_training_pipeline(self):
        """
        Main training pipeline - NO DATA LEAKAGE
        """
        print("\n" + "=" * 80)
        print("🚀 CLEAN CYBERSECURITY MODEL TRAINING PIPELINE")
        print("=" * 80)
        print("✅ KEY FEATURES:")
        print("   • NO data leakage features")
        print("   • Proper train/test split")
        print("   • Feature selection on training only")
        print("   • Optimized for real-world performance")
        print("=" * 80)
        
        start_time = time.time()
        
        try:
            # Step 1: Load and clean data
            df = self.load_and_clean_data()
            
            # Step 2: Prepare features
            X, y = self.prepare_features(df)
            
            # Step 3: Create train/test split
            X_train, X_test, y_train, y_test = self.create_train_test_split(X, y)
            
            # Step 4: Feature selection
            X_train_selected, X_test_selected = self.select_features(X_train, y_train, X_test)
            
            # Step 5: Scale features
            X_train_scaled, X_test_scaled = self.scale_features(X_train_selected, X_test_selected)
            
            # Step 6: Define models
            self.define_models()
            
            # Step 7: Hyperparameter tuning
            tuned_models = self.hyperparameter_tuning(X_train_scaled, y_train)
            
            # Step 8: Build ensemble
            all_models = self.build_ensemble(X_train_scaled, y_train, tuned_models)
            
            # Step 9: Evaluate models
            results, best_model_name = self.evaluate_models(all_models, X_test_scaled, y_test)
            
            # Step 10: Analyze feature importance
            self.analyze_feature_importance()
            
            # Step 11: Save all artifacts
            self.save_models_and_artifacts(results, best_model_name)
            
            # Training complete
            end_time = time.time()
            total_time = (end_time - start_time) / 60  # Minutes
            
            print("\n" + "=" * 80)
            print("✅ CLEAN TRAINING PIPELINE COMPLETE!")
            print("=" * 80)
            print(f"⏱️  Total training time: {total_time:.2f} minutes")
            print(f"🏆 Best model: {best_model_name}")
            print(f"📈 Best F1-Score: {self.best_score:.4f}")
            
            # Performance assessment
            if self.best_score >= 0.90:
                print("🎉 EXCELLENT: Model ready for production!")
            elif self.best_score >= 0.85:
                print("⭐ GOOD: Suitable for deployment")
            elif self.best_score >= 0.80:
                print("✅ ACCEPTABLE: Monitor performance")
            else:
                print("⚠️ NEEDS IMPROVEMENT: Consider more features")
            
            print("=" * 80)
            
            return self.best_model, self.best_score
            
        except Exception as e:
            print(f"\n❌ Training failed: {str(e)}")
            import traceback
            traceback.print_exc()
            raise CustomException(f"Clean model training failed: {e}", sys)

# Main execution
if __name__ == "__main__":
    print("🎯 CLEAN CYBERSECURITY THREAT DETECTION SYSTEM")
    print("=" * 80)
    print("⚠️  This version has NO data leakage")
    print("   Removes features like threat_score, is_normal_traffic, etc.")
    print("=" * 80)
    
    try:
        # Initialize and run training
        trainer = CleanCybersecurityModel()
        best_model, best_score = trainer.run_training_pipeline()
        
        print("\n🎯 NEXT STEPS:")
        print("1. Model is ready for inference with clean data")
        print("2. Use clean_model.pkl for real-time predictions")
        print("3. Expected performance: 85-95% accuracy (realistic)")
        print("\n📁 All artifacts saved in 'artifacts/' directory:")
        print("   • clean_model.pkl - Best performing model (NO LEAKAGE)")
        print("   • clean_scaler.pkl - Feature scaler")
        print("   • clean_selector.pkl - Feature selector")
        print("   • clean_features.pkl - Feature names")
        print("   • clean_training_report.txt - Detailed training report")
        
    except Exception as e:
        print(f"\n❌ System error: {e}")
        sys.exit(1)