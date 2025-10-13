import pandas as pd
import numpy as np
import joblib
import time
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier, VotingClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV, RandomizedSearchCV
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix, classification_report
from sklearn.preprocessing import StandardScaler, PowerTransformer
from sklearn.feature_selection import SelectKBest, f_classif, RFE
from sklearn.decomposition import PCA
import warnings
warnings.filterwarnings('ignore')

class AdvancedCybersecurityModel:
    def __init__(self):
        self.models = {}
        self.best_model = None
        self.best_score = 0
        self.scaler = StandardScaler()
        self.feature_selector = None
        
    def create_ultimate_dataset(self):
        """
        Create the most comprehensive realistic dataset
        """
        print("🚀 CREATING ULTIMATE CYBERSECURITY DATASET")
        print("=" * 60)
        
        # Load original data
        original_df = pd.read_csv('artifacts/balanced_dataset.csv', low_memory=False)
        
        # Start with comprehensive safe features
        feature_columns = ['source_port', 'target_port', 'protocol', 'dur', 'spkts', 'dpkts', 
                          'sbytes', 'dbytes', 'rate', 'sttl', 'dttl', 'sloss', 'dloss', 
                          'is_threat']
        
        # Only use features that exist
        available_features = [f for f in feature_columns if f in original_df.columns]
        safe_df = original_df[available_features].copy()
        
        # Convert all features to numeric
        for col in safe_df.columns:
            if col != 'is_threat':
                safe_df[col] = pd.to_numeric(safe_df[col], errors='coerce')
        
        print("   🔧 Engineering ULTIMATE features...")
        
        # === COMPREHENSIVE FEATURE ENGINEERING ===
        
        # 1. Port and Protocol Features
        safe_df['target_port_category'] = pd.cut(safe_df['target_port'], 
                                               bins=[0, 1024, 49151, 65535], 
                                               labels=[0, 1, 2],
                                               include_lowest=True).fillna(2).astype(int)
        safe_df['source_port_category'] = pd.cut(safe_df['source_port'],
                                               bins=[0, 1024, 49151, 65535],
                                               labels=[0, 1, 2],
                                               include_lowest=True).fillna(2).astype(int)
        
        # Protocol encoding
        protocol_dummies = pd.get_dummies(safe_df['protocol'], prefix='protocol')
        safe_df = pd.concat([safe_df, protocol_dummies], axis=1)
        
        # 2. Statistical Moment Features
        safe_df['avg_packet_size'] = (safe_df['sbytes'] + safe_df['dbytes']) / (safe_df['spkts'] + safe_df['dpkts'] + 1e-8)
        safe_df['bytes_per_second'] = (safe_df['sbytes'] + safe_df['dbytes']) / (safe_df['dur'] + 1e-8)
        safe_df['packet_size_std'] = np.sqrt((safe_df['sbytes']**2 + safe_df['dbytes']**2) / 2)
        safe_df['packet_size_skew'] = abs(safe_df['sbytes'] - safe_df['dbytes']) / (safe_df['avg_packet_size'] + 1e-8)
        
        # 3. Ratio and Asymmetry Features
        safe_df['packet_ratio'] = np.log1p(safe_df['spkts']) / (np.log1p(safe_df['dpkts']) + 1e-8)
        safe_df['byte_ratio'] = np.log1p(safe_df['sbytes']) / (np.log1p(safe_df['dbytes']) + 1e-8)
        safe_df['asymmetry_score'] = abs(safe_df['spkts'] - safe_df['dpkts']) / (safe_df['spkts'] + safe_df['dpkts'] + 1e-8)
        safe_df['traffic_balance'] = 1 - safe_df['asymmetry_score']
        
        # 4. Rate and Intensity Features
        safe_df['packet_rate'] = (safe_df['spkts'] + safe_df['dpkts']) / (safe_df['dur'] + 1e-8)
        safe_df['burstiness'] = (safe_df['spkts'] * safe_df['sbytes'] + safe_df['dpkts'] * safe_df['dbytes']) / (safe_df['dur'] + 1e-8)
        safe_df['traffic_intensity'] = (safe_df['sbytes'] + safe_df['dbytes']) / (safe_df['dur'] + 1e-8)
        safe_df['connection_density'] = (safe_df['spkts'] + safe_df['dpkts']) / (safe_df['dur'] + 1e-8)
        
        # 5. Security-specific Features
        safe_df['is_well_known_port'] = safe_df['target_port'].apply(lambda x: 1 if 0 <= x <= 1023 else 0)
        safe_df['is_ephemeral_port'] = safe_df['source_port'].apply(lambda x: 1 if 49152 <= x <= 65535 else 0)
        safe_df['is_system_port'] = safe_df['target_port'].apply(lambda x: 1 if x in [21, 22, 23, 25, 53, 80, 110, 443, 993, 995] else 0)
        safe_df['suspicious_port'] = safe_df['target_port'].apply(lambda x: 1 if x in [4444, 5555, 6666, 6667, 12345, 27374, 31337] else 0)
        
        # 6. TTL-based Features (if available)
        if 'sttl' in safe_df.columns and 'dttl' in safe_df.columns:
            safe_df['ttl_difference'] = abs(safe_df['sttl'] - safe_df['dttl'])
            safe_df['ttl_ratio'] = safe_df['sttl'] / (safe_df['dttl'] + 1e-8)
        
        # 7. Loss-based Features (if available)
        if 'sloss' in safe_df.columns and 'dloss' in safe_df.columns:
            safe_df['total_loss'] = safe_df['sloss'] + safe_df['dloss']
            safe_df['loss_ratio'] = safe_df['sloss'] / (safe_df['dloss'] + 1e-8)
        
        # 8. Advanced Interaction Features
        safe_df['efficiency_score'] = (safe_df['sbytes'] + safe_df['dbytes']) / (safe_df['spkts'] + safe_df['dpkts'] + 1e-8)
        safe_df['protocol_port_interaction'] = safe_df['protocol'] * safe_df['target_port_category']
        safe_df['duration_traffic_interaction'] = safe_df['dur'] * safe_df['traffic_intensity']
        
        # 9. Log-transformed features for heavy-tailed distributions
        safe_df['log_duration'] = np.log1p(safe_df['dur'])
        safe_df['log_total_bytes'] = np.log1p(safe_df['sbytes'] + safe_df['dbytes'])
        safe_df['log_packet_rate'] = np.log1p(safe_df['packet_rate'])
        
        # 10. Binary encoded duration categories
        safe_df['is_short_connection'] = (safe_df['dur'] < 1).astype(int)
        safe_df['is_long_connection'] = (safe_df['dur'] > 10).astype(int)
        
        # Remove original high-risk features
        features_to_drop = ['source_port', 'target_port', 'sbytes', 'dbytes', 'spkts', 'dpkts']
        if 'sttl' in safe_df.columns:
            features_to_drop.extend(['sttl', 'dttl'])
        if 'sloss' in safe_df.columns:
            features_to_drop.extend(['sloss', 'dloss'])
            
        safe_df = safe_df.drop(columns=[f for f in features_to_drop if f in safe_df.columns])
        
        # Handle missing values and infinities
        safe_df = safe_df.fillna(0)
        safe_df = safe_df.replace([np.inf, -np.inf], 0)
        
        # Ensure target is integer
        safe_df['is_threat'] = safe_df['is_threat'].astype(int)
        
        print(f"📊 ULTIMATE dataset created:")
        print(f"   • Samples: {len(safe_df):,}")
        print(f"   • Features: {len(safe_df.columns) - 1}")
        
        safe_df.to_csv('artifacts/ultimate_dataset.csv', index=False)
        return safe_df

    def advanced_feature_engineering(self, X, y):
        """
        Apply advanced feature selection and engineering
        """
        print("   🎯 Advanced feature processing...")
        
        # Step 1: Statistical feature selection
        selector = SelectKBest(score_func=f_classif, k=min(30, X.shape[1]))
        X_selected = selector.fit_transform(X, y)
        selected_features = X.columns[selector.get_support()].tolist()
        
        print(f"   • Selected {len(selected_features)} features via ANOVA")
        
        # Step 2: Power transformation for non-normal features
        transformer = PowerTransformer(method='yeo-johnson')
        X_transformed = transformer.fit_transform(X_selected)
        
        # Step 3: Standardization
        X_scaled = self.scaler.fit_transform(X_transformed)
        
        self.feature_selector = selector
        self.selected_features = selected_features
        
        return pd.DataFrame(X_scaled, columns=selected_features), selected_features

    def define_models(self):
        """
        Define only efficient models (XGBoost and LightGBM)
        """
        print("   🤖 Initializing EFFICIENT models...")
        
        self.models = {
            'XGBoost': {
                'model': XGBClassifier(random_state=42, n_jobs=-1, verbosity=0),
                'params': {
                    'n_estimators': [100, 200],
                    'max_depth': [6, 8, 10],
                    'learning_rate': [0.05, 0.1, 0.2],
                    'subsample': [0.8, 0.9],
                    'colsample_bytree': [0.8, 0.9]
                }
            },
            'LightGBM': {
                'model': LGBMClassifier(random_state=42, n_jobs=-1, verbose=-1),
                'params': {
                    'n_estimators': [100, 200],
                    'max_depth': [6, 8, 10],
                    'learning_rate': [0.05, 0.1, 0.2],
                    'num_leaves': [31, 50],
                    'subsample': [0.8, 0.9]
                }
            }
            # Removed Random Forest, Gradient Boosting, Extra Trees for efficiency
        }

    def fast_hyperparameter_tuning(self, X_train, y_train):
        """
        Fast hyperparameter tuning with smaller search space
        """
        print("   ⚡ Fast hyperparameter tuning...")
        tuned_models = {}
        
        for name, config in self.models.items():
            print(f"      Tuning {name}...")
            start_time = time.time()
            
            # Use smaller search space
            search = RandomizedSearchCV(
                config['model'], config['params'],
                n_iter=10,  # Reduced from 20
                cv=3,
                scoring='f1',
                n_jobs=-1,
                random_state=42,
                verbose=0
            )
            
            search.fit(X_train, y_train)
            tuned_models[name] = search.best_estimator_
            
            end_time = time.time()
            print(f"        {name} best score: {search.best_score_:.4f} (Time: {end_time - start_time:.1f}s)")
        
        return tuned_models

    def train_ensemble(self, X_train, y_train, tuned_models):
        """
        Create ensemble models
        """
        print("   🎭 Building ensemble models...")
        
        # Individual tuned models
        individual_models = list(tuned_models.items())
        
        # Voting Classifier - Soft Voting (usually performs better)
        voting_soft = VotingClassifier(
            estimators=individual_models,
            voting='soft',
            n_jobs=-1
        )
        
        # Train voting classifier
        voting_soft.fit(X_train, y_train)
        
        return {
            'Voting_Soft': voting_soft,
            **tuned_models
        }

    def comprehensive_evaluation(self, models, X_test, y_test):
        """
        Comprehensive evaluation of all models
        """
        print("\n📊 COMPREHENSIVE MODEL EVALUATION")
        print("=" * 60)
        
        results = {}
        best_model_name = None
        best_f1 = 0
        
        for name, model in models.items():
            y_pred = model.predict(X_test)
            y_pred_proba = model.predict_proba(X_test)[:, 1] if hasattr(model, 'predict_proba') else None
            
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
            
            print(f"\n🏆 {name}:")
            print(f"   • Accuracy:  {accuracy:.4f}")
            print(f"   • Precision: {precision:.4f}")
            print(f"   • Recall:    {recall:.4f}")
            print(f"   • F1-Score:  {f1:.4f}")
            print(f"   • AUC:       {auc:.4f}")
            
            if f1 > best_f1:
                best_f1 = f1
                best_model_name = name
                self.best_model = model
                self.best_score = f1
        
        # Display confusion matrix for best model
        if self.best_model:
            y_pred_best = self.best_model.predict(X_test)
            cm = confusion_matrix(y_test, y_pred_best)
            tn, fp, fn, tp = cm.ravel()
            
            print(f"\n🎯 BEST MODEL: {best_model_name}")
            print(f"📈 Confusion Matrix:")
            print(f"   • True Negatives (Normal): {tn:,}")
            print(f"   • False Positives (False Alarms): {fp:,}")
            print(f"   • False Negatives (Missed Threats): {fn:,}")
            print(f"   • True Positives (Detected Threats): {tp:,}")
            
            # Calculate operational metrics
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            fnr = fn / (fn + tp) if (fn + tp) > 0 else 0
            
            print(f"\n📊 Operational Metrics:")
            print(f"   • False Positive Rate: {fpr:.4f}")
            print(f"   • False Negative Rate: {fnr:.4f}")
            print(f"   • Detection Rate: {recall:.4f}")
        
        return results, best_model_name

    def save_ultimate_model(self, results, best_model_name):
        """
        Save all models and metadata
        """
        print(f"\n💾 Saving ultimate model ecosystem...")
        
        # Save best model
        joblib.dump(self.best_model, 'artifacts/ultimate_model.pkl')
        
        # Save all tuned models
        for name, result in results.items():
            joblib.dump(result['model'], f'artifacts/{name.lower().replace(" ", "_")}_model.pkl')
        
        # Save preprocessing objects
        joblib.dump(self.scaler, 'artifacts/ultimate_scaler.pkl')
        joblib.dump(self.feature_selector, 'artifacts/feature_selector.pkl')
        joblib.dump(self.selected_features, 'artifacts/selected_features.pkl')
        
        # Save results summary
        results_df = pd.DataFrame(results).T
        results_df.to_csv('artifacts/model_comparison.csv')
        
        print(f"   ✅ Best model: {best_model_name} (F1: {self.best_score:.4f})")
        print(f"   ✅ All models saved to artifacts/")

    def run_ultimate_training(self):
        """
        Main training pipeline - OPTIMIZED VERSION
        """
        print("🚀 STARTING OPTIMIZED CYBERSECURITY TRAINING")
        print("=" * 60)
        print("Using XGBoost + LightGBM only for maximum efficiency")
        print("=" * 60)
        
        start_time = time.time()
        
        # Step 1: Create ultimate dataset
        ultimate_df = self.create_ultimate_dataset()
        
        # Prepare data
        X = ultimate_df.drop('is_threat', axis=1)
        y = ultimate_df['is_threat']
        
        # Step 2: Advanced feature engineering
        X_processed, selected_features = self.advanced_feature_engineering(X, y)
        
        # Step 3: Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_processed, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"\n🎯 TRAINING SETUP:")
        print(f"   • Training samples: {X_train.shape[0]:,}")
        print(f"   • Test samples: {X_test.shape[0]:,}")
        print(f"   • Selected features: {len(selected_features)}")
        
        # Step 4: Define only efficient models
        self.define_models()
        
        # Step 5: Fast hyperparameter tuning
        tuned_models = self.fast_hyperparameter_tuning(X_train, y_train)
        
        # Step 6: Build ensemble
        all_models = self.train_ensemble(X_train, y_train, tuned_models)
        
        # Step 7: Comprehensive evaluation
        results, best_model_name = self.comprehensive_evaluation(all_models, X_test, y_test)
        
        # Step 8: Save everything
        self.save_ultimate_model(results, best_model_name)
        
        end_time = time.time()
        total_time = (end_time - start_time) / 60  # Convert to minutes
        
        print(f"\n⏱️  TOTAL TRAINING TIME: {total_time:.1f} minutes")
        print("=" * 60)
        
        return self.best_model, self.best_score

# Additional analysis function
def feature_importance_analysis(model, feature_names, top_n=15):
    """
    Detailed feature importance analysis
    """
    if hasattr(model, 'feature_importances_'):
        importance_df = pd.DataFrame({
            'feature': feature_names,
            'importance': model.feature_importances_
        }).sort_values('importance', ascending=False)
        
        print(f"\n🔍 TOP {top_n} FEATURE IMPORTANCES:")
        print("-" * 40)
        for i, row in importance_df.head(top_n).iterrows():
            print(f"   {i+1:2d}. {row['feature']}: {row['importance']:.4f}")
        
        return importance_df

if __name__ == "__main__":
    print("🎯 OPTIMIZED CYBERSECURITY THREAT DETECTION")
    print("=" * 60)
    print("Using XGBoost + LightGBM Ensemble for Maximum Efficiency")
    print("=" * 60)
    
    # Initialize and run optimized training
    cyber_model = AdvancedCybersecurityModel()
    best_model, best_score = cyber_model.run_ultimate_training()
    
    # Feature importance analysis
    if hasattr(best_model, 'feature_importances_'):
        feature_importance_analysis(best_model, cyber_model.selected_features)
    
    # Final assessment
    print(f"\n🎉 OPTIMIZED TRAINING COMPLETE!")
    print("=" * 50)
    
    if best_score >= 0.85:
        print("🏆 WORLD-CLASS: Exceptional performance achieved!")
        print("   Ready for enterprise deployment")
    elif best_score >= 0.80:
        print("⭐ EXCELLENT: High-performing production model!")
        print("   Suitable for critical security operations")
    elif best_score >= 0.75:
        print("✅ VERY GOOD: Strong realistic performance!")
        print("   Effective for most security use cases")
    else:
        print("📊 GOOD: Solid baseline performance")
        print("   Can be deployed with monitoring")
    
    print(f"   Best F1-Score: {best_score:.4f}")
    print("=" * 50)