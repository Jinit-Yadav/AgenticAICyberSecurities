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
from sklearn.preprocessing import StandardScaler, PowerTransformer
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
class ModelTrainerConfig:
    """
    Configuration for Model Training in Cyber Security Detection System
    """
    trained_model_path: str = os.path.join('artifacts', 'ultimate_model.pkl')
    model_performance_path: str = os.path.join('artifacts', 'model_performance.json')
    feature_importance_path: str = os.path.join('artifacts', 'feature_importance.csv')
    training_report_path: str = os.path.join('artifacts', 'training_report.txt')

class AdvancedCybersecurityModel:
    def __init__(self):
        self.models = {}
        self.best_model = None
        self.best_score = 0
        self.scaler = StandardScaler()
        self.power_transformer = PowerTransformer(method='yeo-johnson')
        self.feature_selector = None
        self.selected_features = []
        self.feature_importance_df = None
        
    def load_transformed_data(self):
        """
        Load the ML-ready dataset from DataTransformation
        This is the SINGLE SOURCE OF TRUTH for features
        """
        print("🚀 LOADING PRE-TRANSFORMED DATA FROM DATATRANSFORMATION")
        print("=" * 80)
        
        # Try to load the transformed ML-ready dataset first
        transformed_path = 'artifacts/ml_ready_dataset.csv'
        balanced_path = 'artifacts/balanced_dataset.csv'
        
        if os.path.exists(transformed_path):
            print(f"✅ Loading transformed ML-ready dataset: {transformed_path}")
            df = pd.read_csv(transformed_path, low_memory=False)
            print(f"   Shape: {df.shape}")
            print(f"   Features: {len(df.columns)}")
            
            # Verify target column exists
            if 'is_threat' not in df.columns:
                raise CustomException("Target column 'is_threat' not found in transformed data!")
            
            # Display feature categories
            print(f"\n📊 FEATURE CATEGORIES IN TRANSFORMED DATA:")
            feature_cols = [col for col in df.columns if col != 'is_threat']
            
            # Categorize features
            threat_features = [col for col in feature_cols if 'threat' in col.lower()]
            time_features = [col for col in feature_cols if any(x in col.lower() for x in ['hour', 'day', 'weekend', 'night'])]
            ip_features = [col for col in feature_cols if any(x in col.lower() for x in ['ip', 'request', 'target'])]
            tool_features = [col for col in feature_cols if any(x in col.lower() for x in ['tool', 'risk', 'recon'])]
            port_features = [col for col in feature_cols if 'port' in col.lower()]
            protocol_features = [col for col in feature_cols if any(x in col.lower() for x in ['tcp', 'udp', 'icmp', 'protocol'])]
            cic_features = [col for col in feature_cols if any(x in col.lower() for x in ['dur', 'pkt', 'byte', 'rate'])]
            
            print(f"   • Threat Score Features: {len(threat_features)}")
            print(f"   • Time-based Features: {len(time_features)}")
            print(f"   • IP Behavior Features: {len(ip_features)}")
            print(f"   • Tool-based Features: {len(tool_features)}")
            print(f"   • Port Features: {len(port_features)}")
            print(f"   • Protocol Features: {len(protocol_features)}")
            print(f"   • CIC Flow Features: {len(cic_features)}")
            
            return df
            
        elif os.path.exists(balanced_path):
            print(f"⚠️ Transformed data not found. Using balanced dataset with minimal processing.")
            print(f"   Loading: {balanced_path}")
            df = pd.read_csv(balanced_path, low_memory=False)
            
            # Minimal required preprocessing
            print("   Applying minimal preprocessing...")
            
            # Ensure target is binary
            if 'is_threat' in df.columns:
                df['is_threat'] = df['is_threat'].astype(int)
            else:
                raise CustomException("No target column 'is_threat' found!")
            
            # Select only numeric columns for simplicity
            numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
            if 'is_threat' in numeric_cols:
                numeric_cols.remove('is_threat')
            
            df = df[['is_threat'] + numeric_cols]
            df = df.fillna(0)
            df = df.replace([np.inf, -np.inf], 0)
            
            print(f"   Minimal dataset shape: {df.shape}")
            return df
            
        else:
            raise CustomException(f"No data found at {transformed_path} or {balanced_path}")
    
    def prepare_features(self, X, y):
        """
        Prepare features for training WITHOUT data leakage
        This includes feature selection, transformation, and scaling
        """
        print("\n🔧 PREPARING FEATURES FOR TRAINING (NO DATA LEAKAGE)")
        print("=" * 50)
        
        # Split FIRST to prevent data leakage
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"   Training set: {X_train.shape[0]:,} samples")
        print(f"   Test set: {X_test.shape[0]:,} samples")
        print(f"   Features: {X.shape[1]}")
        
        # Step 1: Feature selection using ONLY training data
        print("\n   📊 Step 1: Feature Selection (ANOVA F-test)...")
        k_features = min(30, X_train.shape[1])
        self.feature_selector = SelectKBest(score_func=f_classif, k=k_features)
        X_train_selected = self.feature_selector.fit_transform(X_train, y_train)
        X_test_selected = self.feature_selector.transform(X_test)
        
        # Get selected feature names
        self.selected_features = X.columns[self.feature_selector.get_support()].tolist()
        print(f"   • Selected {len(self.selected_features)} features (from {X.shape[1]})")
        print(f"   • Removed {X.shape[1] - len(self.selected_features)} features")
        
        # Step 2: Power transformation using ONLY training data
        print("\n   📈 Step 2: Power Transformation (Yeo-Johnson)...")
        X_train_transformed = self.power_transformer.fit_transform(X_train_selected)
        X_test_transformed = self.power_transformer.transform(X_test_selected)
        
        # Step 3: Standardization using ONLY training data
        print("\n   ⚖️ Step 3: Standardization...")
        X_train_scaled = self.scaler.fit_transform(X_train_transformed)
        X_test_scaled = self.scaler.transform(X_test_transformed)
        
        print(f"\n✅ Feature preparation complete!")
        print(f"   Final training shape: {X_train_scaled.shape}")
        print(f"   Final test shape: {X_test_scaled.shape}")
        
        return X_train_scaled, X_test_scaled, y_train, y_test
    
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
                    eval_metric='logloss'
                ),
                'params': {
                    'n_estimators': [100, 200, 300],
                    'max_depth': [6, 8, 10],
                    'learning_rate': [0.05, 0.1, 0.15],
                    'subsample': [0.8, 0.9],
                    'colsample_bytree': [0.8, 0.9],
                    'min_child_weight': [1, 3]
                },
                'reason': "Best-in-class performance for structured cybersecurity data"
            },
            'LightGBM': {
                'model': LGBMClassifier(
                    random_state=42, 
                    n_jobs=-1, 
                    verbose=-1,
                    force_col_wise=True
                ),
                'params': {
                    'n_estimators': [100, 200, 300],
                    'max_depth': [6, 8, 10],
                    'learning_rate': [0.05, 0.1, 0.15],
                    'num_leaves': [31, 50, 70],
                    'subsample': [0.8, 0.9],
                    'colsample_bytree': [0.8, 0.9]
                },
                'reason': "Extremely fast training with excellent accuracy"
            }
        }
        
        # Print model strategy
        print("\n   🎯 MODEL SELECTION STRATEGY:")
        for name, config in self.models.items():
            print(f"   • {name}: {config['reason']}")
    
    def hyperparameter_tuning(self, X_train, y_train):
        """
        Hyperparameter tuning with cross-validation (NO LEAKAGE)
        """
        print("\n⚡ HYPERPARAMETER TUNING")
        print("=" * 50)
        print("   Strategy: RandomizedSearchCV with 3-fold CV")
        print("   Optimization: F1-Score (best for imbalanced data)")
        print("   Iterations: 15 per model")
        
        tuned_models = {}
        
        for name, config in self.models.items():
            print(f"\n   🔧 Tuning {name}...")
            start_time = time.time()
            
            # Randomized search for efficiency
            search = RandomizedSearchCV(
                config['model'], 
                config['params'],
                n_iter=15,
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
        print("   Benefits: Reduces overfitting, improves generalization")
        
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
            print(f"   • Accuracy:  {accuracy:.4f}")
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
            
            if len(cm) == 4:  # 2x2 matrix
                tn, fp, fn, tp = cm.ravel()
            else:
                # Handle case where one class is missing
                tn = cm[0,0] if cm.shape[0] > 0 else 0
                fp = cm[0,1] if cm.shape[1] > 1 else 0
                fn = cm[1,0] if cm.shape[0] > 1 else 0
                tp = cm[1,1] if cm.shape[1] > 1 else 0
            
            print(f"\n🎯 BEST MODEL: {best_model_name}")
            print(f"📈 CONFUSION MATRIX:")
            print(f"   • True Negatives (Normal): {tn:,}")
            print(f"   • False Positives (False Alarms): {fp:,}")
            print(f"   • False Negatives (Missed Threats): {fn:,}")
            print(f"   • True Positives (Detected Threats): {tp:,}")
            
            # Operational metrics
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
            
            print(f"\n📊 OPERATIONAL METRICS:")
            print(f"   • False Positive Rate: {fpr:.4f} ({fpr*100:.2f}%)")
            print(f"   • False Negative Rate: {fnr:.4f} ({fnr*100:.2f}%)")
            print(f"   • Detection Rate: {results[best_model_name]['recall']:.4f} ({results[best_model_name]['recall']*100:.2f}%)")
        
        return results, best_model_name
    
    def analyze_feature_importance(self):
        """
        Analyze feature importance from the best model
        """
        if not self.selected_features:
            print("\n⚠️ No selected features available for importance analysis")
            return
        
        print("\n🔍 FEATURE IMPORTANCE ANALYSIS")
        print("=" * 80)
        
        # Try to get feature importance from best model
        if hasattr(self.best_model, 'feature_importances_'):
            importances = self.best_model.feature_importances_
            
            # Create importance DataFrame
            self.feature_importance_df = pd.DataFrame({
                'feature': self.selected_features,
                'importance': importances
            }).sort_values('importance', ascending=False)
            
            # Display top features
            print(f"\n📊 TOP 15 MOST IMPORTANT FEATURES:")
            for i, row in self.feature_importance_df.head(15).iterrows():
                print(f"   {i+1:2d}. {row['feature']}: {row['importance']:.4f}")
            
            # Save feature importance
            self.feature_importance_df.to_csv(
                ModelTrainerConfig.feature_importance_path, 
                index=False
            )
            print(f"\n✅ Feature importance saved to: {ModelTrainerConfig.feature_importance_path}")
            
        elif hasattr(self.best_model, 'coef_'):
            # For linear models
            importances = np.abs(self.best_model.coef_[0])
            self.feature_importance_df = pd.DataFrame({
                'feature': self.selected_features,
                'importance': importances
            }).sort_values('importance', ascending=False)
            
            print(f"\n📊 TOP 15 MOST IMPORTANT FEATURES (Absolute Coefficients):")
            for i, row in self.feature_importance_df.head(15).iterrows():
                print(f"   {i+1:2d}. {row['feature']}: {row['importance']:.4f}")
        else:
            print("   ℹ️ Best model doesn't provide feature importances")
    
    def save_models_and_artifacts(self, results, best_model_name):
        """
        Save all trained models and preprocessing artifacts
        """
        print("\n💾 SAVING MODELS AND ARTIFACTS")
        print("=" * 50)
        
        # Create artifacts directory if not exists
        os.makedirs('artifacts', exist_ok=True)
        
        # Save best model
        joblib.dump(self.best_model, ModelTrainerConfig.trained_model_path)
        print(f"   ✅ Best model saved: {ModelTrainerConfig.trained_model_path}")
        
        # Save all models
        for name, result in results.items():
            model_path = f'artifacts/{name.lower().replace(" ", "_")}_model.pkl'
            joblib.dump(result['model'], model_path)
            print(f"   ✅ {name} model saved")
        
        # Save preprocessing objects
        joblib.dump(self.scaler, 'artifacts/final_scaler.pkl')
        joblib.dump(self.power_transformer, 'artifacts/power_transformer.pkl')
        joblib.dump(self.feature_selector, 'artifacts/feature_selector.pkl')
        joblib.dump(self.selected_features, 'artifacts/selected_features.pkl')
        print(f"   ✅ Preprocessing objects saved")
        
        # Save performance metrics
        results_df = pd.DataFrame(results).T
        results_df.to_csv(ModelTrainerConfig.model_performance_path.replace('.json', '.csv'))
        print(f"   ✅ Performance metrics saved")
        
        # Generate training report
        self.generate_training_report(results, best_model_name)
        
    def generate_training_report(self, results, best_model_name):
        """
        Generate comprehensive training report
        """
        report_path = ModelTrainerConfig.training_report_path
        
        with open(report_path, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("CYBERSECURITY THREAT DETECTION - TRAINING REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"Best Model: {best_model_name}\n")
            f.write(f"Best F1-Score: {self.best_score:.4f}\n\n")
            
            f.write("MODEL PERFORMANCE SUMMARY:\n")
            f.write("-" * 40 + "\n")
            for name, metrics in results.items():
                f.write(f"\n{name}:\n")
                f.write(f"  • Accuracy:  {metrics['accuracy']:.4f}\n")
                f.write(f"  • Precision: {metrics['precision']:.4f}\n")
                f.write(f"  • Recall:    {metrics['recall']:.4f}\n")
                f.write(f"  • F1-Score:  {metrics['f1']:.4f}\n")
                f.write(f"  • AUC:       {metrics['auc']:.4f}\n")
            
            f.write("\n" + "=" * 80 + "\n")
            f.write("FEATURE INFORMATION\n")
            f.write("=" * 80 + "\n")
            f.write(f"Total features considered: {len(self.selected_features) if self.selected_features else 0}\n")
            f.write(f"Features used in training: {len(self.selected_features) if self.selected_features else 0}\n")
            
            if self.feature_importance_df is not None:
                f.write("\nTOP 10 FEATURES:\n")
                for i, row in self.feature_importance_df.head(10).iterrows():
                    f.write(f"  {i+1}. {row['feature']}: {row['importance']:.4f}\n")
        
        print(f"   ✅ Training report saved: {report_path}")
    
    def run_training_pipeline(self):
        """
        Main training pipeline - CORRECTED VERSION
        """
        print("\n" + "=" * 80)
        print("🚀 STARTING CYBERSECURITY MODEL TRAINING PIPELINE")
        print("=" * 80)
        print("🎯 KEY IMPROVEMENTS:")
        print("   • Uses pre-transformed data from DataTransformation")
        print("   • NO data leakage (feature selection on training only)")
        print("   • Proper train/test split before any preprocessing")
        print("   • XGBoost + LightGBM ensemble for optimal performance")
        print("=" * 80)
        
        start_time = time.time()
        
        try:
            # Step 1: Load pre-transformed data
            df = self.load_transformed_data()
            
            # Step 2: Separate features and target
            X = df.drop('is_threat', axis=1)
            y = df['is_threat']
            
            print(f"\n📊 DATASET SUMMARY:")
            print(f"   • Total samples: {len(df):,}")
            print(f"   • Features: {X.shape[1]}")
            print(f"   • Threats: {y.sum():,} ({y.sum()/len(y)*100:.1f}%)")
            print(f"   • Normal: {len(y)-y.sum():,} ({(len(y)-y.sum())/len(y)*100:.1f}%)")
            
            # Step 3: Prepare features (WITHOUT data leakage)
            X_train, X_test, y_train, y_test = self.prepare_features(X, y)
            
            # Step 4: Define models
            self.define_models()
            
            # Step 5: Hyperparameter tuning
            tuned_models = self.hyperparameter_tuning(X_train, y_train)
            
            # Step 6: Build ensemble
            all_models = self.build_ensemble(X_train, y_train, tuned_models)
            
            # Step 7: Evaluate models
            results, best_model_name = self.evaluate_models(all_models, X_test, y_test)
            
            # Step 8: Analyze feature importance
            self.analyze_feature_importance()
            
            # Step 9: Save all artifacts
            self.save_models_and_artifacts(results, best_model_name)
            
            # Training complete
            end_time = time.time()
            total_time = (end_time - start_time) / 60  # Minutes
            
            print("\n" + "=" * 80)
            print("✅ TRAINING PIPELINE COMPLETE!")
            print("=" * 80)
            print(f"⏱️  Total training time: {total_time:.2f} minutes")
            print(f"🏆 Best model: {best_model_name}")
            print(f"📈 Best F1-Score: {self.best_score:.4f}")
            
            # Performance assessment
            if self.best_score >= 0.90:
                print("🎉 EXCEPTIONAL: Model exceeds production standards!")
            elif self.best_score >= 0.85:
                print("⭐ EXCELLENT: Ready for enterprise deployment!")
            elif self.best_score >= 0.80:
                print("✅ GOOD: Suitable for production use")
            elif self.best_score >= 0.75:
                print("📊 ACCEPTABLE: Monitor and retrain regularly")
            else:
                print("⚠️ NEEDS IMPROVEMENT: Consider more feature engineering")
            
            print("=" * 80)
            
            return self.best_model, self.best_score
            
        except Exception as e:
            print(f"\n❌ Training failed: {str(e)}")
            import traceback
            traceback.print_exc()
            raise CustomException(f"Model training failed: {e}", sys)

# Main execution
if __name__ == "__main__":
    print("🎯 OPTIMIZED CYBERSECURITY THREAT DETECTION SYSTEM")
    print("=" * 80)
    
    try:
        # Initialize and run training
        trainer = AdvancedCybersecurityModel()
        best_model, best_score = trainer.run_training_pipeline()
        
        print("\n🎯 NEXT STEPS:")
        print("1. Model is ready for inference")
        print("2. Use ultimate_model.pkl for real-time predictions")
        print("3. Monitor performance with new data")
        print("4. Retrain monthly or when false positive rates increase")
        print("\n📁 All artifacts saved in 'artifacts/' directory:")
        print("   • ultimate_model.pkl - Best performing model")
        print("   • final_scaler.pkl - Feature scaler")
        print("   • feature_selector.pkl - Feature selector")
        print("   • selected_features.pkl - Feature names")
        print("   • training_report.txt - Detailed training report")
        
    except Exception as e:
        print(f"\n❌ System error: {e}")
        sys.exit(1)