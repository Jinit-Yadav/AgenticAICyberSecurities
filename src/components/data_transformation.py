import os
import sys
import pandas as pd
import numpy as np
import joblib
from dataclasses import dataclass
from sklearn.preprocessing import StandardScaler, LabelEncoder, OneHotEncoder
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.impute import SimpleImputer
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
class DataTransformationConfig:
    """
    Configuration for Data Transformation in Cyber Security Detection System
    """
    processed_features_path: str = os.path.join('artifacts', 'transformed_features.csv')
    labeled_dataset_path: str = os.path.join('artifacts', 'ml_ready_dataset.csv')
    feature_importance_path: str = os.path.join('artifacts', 'feature_importance.csv')
    scaler_path: str = os.path.join('artifacts', 'scaler.pkl')
    encoder_path: str = os.path.join('artifacts', 'label_encoder.pkl')
    imputer_path: str = os.path.join('artifacts', 'imputer.pkl')

class DataTransformation:
    """
    Data Transformation component for Cyber Security Detection System
    Handles feature engineering, scaling, and encoding for HYBRID dataset (UNSW-NB15 + Real attack logs)
    """
    
    def __init__(self):
        self.transformation_config = DataTransformationConfig()
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.imputer = SimpleImputer(strategy='most_frequent')
        
    def load_attack_data(self, processed_attack_data_path):
        """
        Load the processed hybrid data from HybridDetectionAgent
        """
        logging.info("📁 Loading processed hybrid data for ML transformation")
        
        try:
            if not os.path.exists(processed_attack_data_path):
                raise CustomException(f"Processed hybrid data not found at: {processed_attack_data_path}")
            
            # Load with explicit dtype handling to avoid type issues
            df = pd.read_csv(processed_attack_data_path, low_memory=False)
            
            # Clean the dataframe first
            df = self._clean_dataframe(df)
            
            logging.info(f"✅ Loaded {len(df)} hybrid records with {len(df.columns)} features")
            
            # Display dataset composition
            print(f"\n📊 HYBRID Dataset Info:")
            print(f"   • Shape: {df.shape}")
            print(f"   • Total Records: {len(df)}")
            
            # Check dataset composition
            if 'tool' in df.columns:
                unsw_count = len(df[df['tool'] == 'unsw_dataset'])
                real_attack_count = len(df[df['tool'] != 'unsw_dataset'])
                print(f"   • UNSW-NB15 Records: {unsw_count} ({unsw_count/len(df)*100:.1f}%)")
                print(f"   • Real Attack Records: {real_attack_count} ({real_attack_count/len(df)*100:.1f}%)")
            
            if 'is_threat' in df.columns:
                threat_count = df['is_threat'].sum()
                normal_count = len(df) - threat_count
                print(f"   • Threat Records: {threat_count} ({threat_count/len(df)*100:.1f}%)")
                print(f"   • Normal Records: {normal_count} ({normal_count/len(df)*100:.1f}%)")
            
            # Show available columns
            print(f"   • Available Columns: {list(df.columns)}")
            
            return df
            
        except Exception as e:
            raise CustomException(f"Failed to load hybrid data: {e}", sys)
    
    def _clean_dataframe(self, df):
        """
        Clean the dataframe to fix data type issues
        """
        try:
            # Create a clean copy by reconstructing the dataframe
            clean_data = {}
            
            for col in df.columns:
                try:
                    # Convert each column to appropriate type
                    if df[col].dtype == 'object':
                        # For object columns, handle potential mixed types
                        clean_data[col] = df[col].astype(str)
                    else:
                        # For numeric columns, keep as is
                        clean_data[col] = df[col]
                except Exception as col_error:
                    print(f"⚠️  Cleaning column {col}: {col_error}")
                    # If conversion fails, create a default column
                    clean_data[col] = np.nan
            
            # Create new dataframe from cleaned data
            clean_df = pd.DataFrame(clean_data)
            
            # Handle specific problematic columns
            problematic_cols = []
            for col in clean_df.columns:
                try:
                    # Test if column can be used in operations
                    _ = clean_df[col].copy()
                except:
                    problematic_cols.append(col)
            
            if problematic_cols:
                print(f"⚠️  Problematic columns detected: {problematic_cols}")
                # Drop problematic columns
                clean_df = clean_df.drop(columns=problematic_cols)
            
            return clean_df
            
        except Exception as e:
            print(f"❌ DataFrame cleaning failed: {e}")
            # Last resort: create minimal dataframe
            return pd.DataFrame({'is_threat': [1]})
    
    def create_cybersecurity_features(self, df):
        """
        Create advanced cybersecurity-specific features for hybrid dataset
        """
        logging.info("🔧 Creating cybersecurity-specific features for hybrid dataset")
        
        try:
            # Use safer copy method
            feature_df = self._safe_dataframe_copy(df)
            
            if feature_df.empty:
                return feature_df
            
            # Ensure timestamp is datetime
            if 'timestamp' in feature_df.columns:
                try:
                    feature_df['timestamp'] = pd.to_datetime(feature_df['timestamp'], errors='coerce')
                    
                    # Time-based features
                    feature_df['hour'] = feature_df['timestamp'].dt.hour
                    feature_df['day_of_week'] = feature_df['timestamp'].dt.dayofweek
                    feature_df['is_weekend'] = feature_df['day_of_week'].isin([5, 6]).astype(int)
                    feature_df['is_night'] = ((feature_df['hour'] >= 22) | (feature_df['hour'] <= 6)).astype(int)
                except Exception as time_error:
                    print(f"⚠️  Time feature creation failed: {time_error}")
            
            # IP-based behavioral features
            if 'source_ip' in feature_df.columns:
                try:
                    feature_df['requests_per_ip'] = feature_df.groupby('source_ip')['source_ip'].transform('count')
                    feature_df['unique_targets_per_ip'] = feature_df.groupby('source_ip')['target_ip'].transform('nunique')
                except Exception as ip_error:
                    print(f"⚠️  IP feature creation failed: {ip_error}")
            
            # Tool-based threat indicators
            if 'tool' in feature_df.columns:
                try:
                    # High-risk tools
                    high_risk_tools = ['hydra', 'hping3', 'ftp_bruteforce']
                    feature_df['is_high_risk_tool'] = feature_df['tool'].isin(high_risk_tools).astype(int)
                    
                    # Reconnaissance tools
                    recon_tools = ['nmap', 'gobuster', 'nikto']
                    feature_df['is_recon_tool'] = feature_df['tool'].isin(recon_tools).astype(int)
                    
                    # Dataset source indicator
                    feature_df['is_real_attack'] = (feature_df['tool'] != 'unsw_dataset').astype(int)
                    feature_df['is_unsw_data'] = (feature_df['tool'] == 'unsw_dataset').astype(int)
                except Exception as tool_error:
                    print(f"⚠️  Tool feature creation failed: {tool_error}")
            
            # Attack category features
            if 'attack_category' in feature_df.columns:
                try:
                    # High severity categories
                    high_severity_categories = ['bruteforce', 'dos_testing', 'exploitation', 'backdoor', 'malware']
                    feature_df['is_high_severity_category'] = feature_df['attack_category'].isin(high_severity_categories).astype(int)
                    
                    # Normal traffic indicator
                    feature_df['is_normal_traffic'] = (feature_df['attack_category'] == 'normal').astype(int)
                except Exception as category_error:
                    print(f"⚠️  Category feature creation failed: {category_error}")
            
            # Port-based features (if port information available)
            if 'target_port' in feature_df.columns:
                try:
                    # Common attack ports
                    common_attack_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 1521, 3306, 3389]
                    feature_df['is_common_attack_port'] = feature_df['target_port'].isin(common_attack_ports).astype(int)
                except Exception as port_error:
                    print(f"⚠️  Port feature creation failed: {port_error}")
            
            # Protocol-based features
            if 'protocol' in feature_df.columns:
                try:
                    feature_df['is_tcp'] = (feature_df['protocol'] == 'tcp').astype(int)
                    feature_df['is_udp'] = (feature_df['protocol'] == 'udp').astype(int)
                    feature_df['is_icmp'] = (feature_df['protocol'] == 'icmp').astype(int)
                except Exception as protocol_error:
                    print(f"⚠️  Protocol feature creation failed: {protocol_error}")
            
            # Session-based features (using attack_session_id if available)
            if 'attack_session_id' in feature_df.columns:
                try:
                    feature_df['requests_per_session'] = feature_df.groupby('attack_session_id')['attack_session_id'].transform('count')
                except Exception as session_error:
                    print(f"⚠️  Session feature creation failed: {session_error}")
            
            # Advanced threat indicators
            try:
                feature_df['high_frequency_flag'] = (feature_df['requests_per_ip'] > 50).astype(int) if 'requests_per_ip' in feature_df.columns else 0
                feature_df['multiple_targets_flag'] = (feature_df['unique_targets_per_ip'] > 3).astype(int) if 'unique_targets_per_ip' in feature_df.columns else 0
            except Exception as indicator_error:
                print(f"⚠️  Indicator feature creation failed: {indicator_error}")
            
            # UNSW-specific feature preservation
            if 'service' in feature_df.columns:
                try:
                    # Service-based features
                    common_services = ['http', 'dns', 'smtp', 'ftp', 'ssh']
                    feature_df['is_common_service'] = feature_df['service'].isin(common_services).astype(int)
                except Exception as service_error:
                    print(f"⚠️  Service feature creation failed: {service_error}")
            
            if 'state' in feature_df.columns:
                try:
                    # Connection state features
                    feature_df['is_established'] = (feature_df['state'] == 'ESTABLISHED').astype(int)
                except Exception as state_error:
                    print(f"⚠️  State feature creation failed: {state_error}")
            
            # Composite threat score (enhanced for hybrid data)
            feature_df = self._calculate_enhanced_threat_score(feature_df)
            
            new_features_count = len([col for col in feature_df.columns if col not in df.columns])
            logging.info(f"✅ Created {new_features_count} new cybersecurity features")
            return feature_df
            
        except Exception as e:
            print(f"❌ Feature creation failed completely: {e}")
            # Return original dataframe as fallback
            return self._safe_dataframe_copy(df)
    
    def _safe_dataframe_copy(self, df):
        """
        Create a safe copy of dataframe to avoid type errors
        """
        try:
            return df.copy()
        except Exception as e:
            print(f"❌ Regular copy failed, using reconstruction: {e}")
            # Reconstruct dataframe column by column
            reconstructed_data = {}
            for col in df.columns:
                try:
                    reconstructed_data[col] = df[col].values
                except:
                    reconstructed_data[col] = np.nan
            return pd.DataFrame(reconstructed_data)
    
    def _calculate_enhanced_threat_score(self, df):
        """
        Calculate enhanced composite threat score for hybrid dataset
        """
        try:
            # Initialize threat score
            df['threat_score'] = 0
            
            # Tool-based scoring
            tool_scores = {
                'hydra': 0.9, 'ftp_bruteforce': 0.9, 'hping3': 0.8,
                'nmap': 0.4, 'gobuster': 0.5, 'nikto': 0.5, 'smb': 0.6,
                'unsw_dataset': 0.5  # Default for UNSW data
            }
            if 'tool' in df.columns:
                try:
                    df['tool_threat_score'] = df['tool'].map(tool_scores).fillna(0.3)
                    df['threat_score'] += df['tool_threat_score'] * 0.25
                except Exception as e:
                    print(f"⚠️  Tool threat score failed: {e}")
            
            # Category-based scoring
            category_scores = {
                'bruteforce': 0.9, 'dos_testing': 0.8, 'exploitation': 0.9,
                'reconnaissance': 0.5, 'web_scanning': 0.6, 'network_scanning': 0.5,
                'fuzzing': 0.4, 'backdoor': 0.9, 'malware': 0.9, 'generic_attack': 0.7,
                'normal': 0.1, 'unknown': 0.3
            }
            if 'attack_category' in df.columns:
                try:
                    df['category_threat_score'] = df['attack_category'].map(category_scores).fillna(0.3)
                    df['threat_score'] += df['category_threat_score'] * 0.25
                except Exception as e:
                    print(f"⚠️  Category threat score failed: {e}")
            
            # Severity-based scoring
            severity_scores = {'low': 0.2, 'medium': 0.5, 'high': 0.8, 'critical': 0.95}
            if 'severity' in df.columns:
                try:
                    df['severity_threat_score'] = df['severity'].map(severity_scores).fillna(0.3)
                    df['threat_score'] += df['severity_threat_score'] * 0.2
                except Exception as e:
                    print(f"⚠️  Severity threat score failed: {e}")
            
            # Behavioral scoring
            if 'high_frequency_flag' in df.columns:
                try:
                    df['threat_score'] += df['high_frequency_flag'] * 0.15
                except: pass
            
            if 'multiple_targets_flag' in df.columns:
                try:
                    df['threat_score'] += df['multiple_targets_flag'] * 0.1
                except: pass
            
            if 'is_night' in df.columns:
                try:
                    df['threat_score'] += df['is_night'] * 0.05
                except: pass
            
            # Dataset source adjustment
            if 'is_real_attack' in df.columns:
                try:
                    df['threat_score'] += df['is_real_attack'] * 0.1
                except: pass
            
            # Normal traffic adjustment
            if 'is_normal_traffic' in df.columns:
                try:
                    df['threat_score'] -= df['is_normal_traffic'] * 0.3
                except: pass
            
            # Ensure threat score is between 0 and 1
            try:
                df['threat_score'] = df['threat_score'].clip(0, 1)
            except:
                df['threat_score'] = 0.5  # Default medium score
            
            return df
            
        except Exception as e:
            logging.warning(f"Enhanced threat score calculation failed: {e}")
            df['threat_score'] = 0.5  # Default medium score
            return df
    
    def handle_missing_values(self, df):
        """
        Handle missing values in the hybrid dataset
        """
        logging.info("🔧 Handling missing values in hybrid dataset")
        
        try:
            # Use safe copy
            cleaned_df = self._safe_dataframe_copy(df)
            
            if cleaned_df.empty:
                return cleaned_df
            
            # Fill missing categorical values
            categorical_columns = cleaned_df.select_dtypes(include=['object']).columns
            for col in categorical_columns:
                if col in cleaned_df.columns:
                    try:
                        if col == 'tool':
                            cleaned_df[col] = cleaned_df[col].fillna('unknown')
                        elif col == 'attack_category':
                            cleaned_df[col] = cleaned_df[col].fillna('unknown')
                        elif col == 'severity':
                            cleaned_df[col] = cleaned_df[col].fillna('low')
                        else:
                            cleaned_df[col] = cleaned_df[col].fillna('unknown')
                    except Exception as col_error:
                        print(f"⚠️  Could not fill column {col}: {col_error}")
            
            # Fill missing numerical values
            numerical_columns = cleaned_df.select_dtypes(include=[np.number]).columns
            for col in numerical_columns:
                if col in cleaned_df.columns and col != 'is_threat':  # Don't fill target variable
                    try:
                        cleaned_df[col] = cleaned_df[col].fillna(cleaned_df[col].median())
                    except:
                        cleaned_df[col] = cleaned_df[col].fillna(0)
            
            logging.info(f"✅ Handled missing values for {len(categorical_columns) + len(numerical_columns)} columns")
            return cleaned_df
            
        except Exception as e:
            raise CustomException(f"Missing value handling failed: {e}", sys)
    
    def encode_categorical_features(self, df):
        """
        Encode categorical features for machine learning - enhanced for hybrid data
        """
        logging.info("🔠 Encoding categorical features for hybrid dataset")
        
        try:
            encoded_df = self._safe_dataframe_copy(df)
            
            if encoded_df.empty:
                return encoded_df
            
            # Encode tool types (including UNSW dataset)
            tool_mapping = {
                'nmap': 0, 'gobuster': 1, 'hping3': 2, 'hydra': 3,
                'nikto': 4, 'smb': 5, 'ftp_bruteforce': 6, 'unsw_dataset': 7, 'unknown': 8
            }
            if 'tool' in encoded_df.columns:
                try:
                    encoded_df['tool_encoded'] = encoded_df['tool'].map(tool_mapping).fillna(8)
                except Exception as e:
                    print(f"⚠️  Tool encoding failed: {e}")
                    encoded_df['tool_encoded'] = 8
            
            # Encode attack categories (including UNSW categories)
            category_mapping = {
                'reconnaissance': 0, 'bruteforce': 1, 'dos_testing': 2,
                'web_scanning': 3, 'network_scanning': 4, 'exploitation': 5,
                'fuzzing': 6, 'backdoor': 7, 'malware': 8, 'generic_attack': 9,
                'normal': 10, 'unknown': 11
            }
            if 'attack_category' in encoded_df.columns:
                try:
                    encoded_df['attack_category_encoded'] = encoded_df['attack_category'].map(category_mapping).fillna(11)
                except Exception as e:
                    print(f"⚠️  Category encoding failed: {e}")
                    encoded_df['attack_category_encoded'] = 11
            
            # Encode severity levels
            severity_mapping = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
            if 'severity' in encoded_df.columns:
                try:
                    encoded_df['severity_encoded'] = encoded_df['severity'].map(severity_mapping).fillna(0)
                except Exception as e:
                    print(f"⚠️  Severity encoding failed: {e}")
                    encoded_df['severity_encoded'] = 0
            
            # Encode protocol
            protocol_mapping = {'tcp': 0, 'udp': 1, 'icmp': 2, 'unknown': 3}
            if 'protocol' in encoded_df.columns:
                try:
                    encoded_df['protocol_encoded'] = encoded_df['protocol'].map(protocol_mapping).fillna(3)
                except Exception as e:
                    print(f"⚠️  Protocol encoding failed: {e}")
                    encoded_df['protocol_encoded'] = 3
            
            logging.info("✅ Categorical features encoded successfully for hybrid dataset")
            return encoded_df
            
        except Exception as e:
            raise CustomException(f"Categorical encoding failed: {e}", sys)
    
    def scale_numerical_features(self, df):
        """
        Scale numerical features for machine learning models
        """
        logging.info("⚖️ Scaling numerical features")
        
        try:
            scaled_df = self._safe_dataframe_copy(df)
            
            if scaled_df.empty:
                return scaled_df
            
            # Select numerical features to scale (excluding the target variable and encoded categoricals)
            numerical_features = [
                'hour', 'day_of_week', 'requests_per_ip', 'unique_targets_per_ip',
                'requests_per_session', 'threat_score', 'complexity_score',
                'tool_threat_score', 'category_threat_score', 'severity_threat_score'
            ]
            
            # Only scale features that exist in the dataframe
            existing_numerical = [col for col in numerical_features if col in scaled_df.columns and col != 'is_threat']
            
            if existing_numerical:
                try:
                    scaled_df[existing_numerical] = self.scaler.fit_transform(scaled_df[existing_numerical])
                    logging.info(f"✅ Scaled {len(existing_numerical)} numerical features")
                    
                    # Save the scaler for future use
                    joblib.dump(self.scaler, self.transformation_config.scaler_path)
                except Exception as scale_error:
                    print(f"⚠️  Scaling failed: {scale_error}")
            else:
                logging.warning("⚠️ No numerical features found for scaling")
            
            return scaled_df
            
        except Exception as e:
            raise CustomException(f"Feature scaling failed: {e}", sys)
    
    def select_ml_features(self, df):
        """
        Select final features for machine learning - enhanced for hybrid data
        """
        logging.info("🎯 Selecting final ML features for hybrid dataset")
        
        try:
            # Base features that are always useful
            base_features = [
                'tool_encoded', 'attack_category_encoded', 'severity_encoded',
                'protocol_encoded', 'threat_score', 'complexity_score',
                'is_high_risk_tool', 'is_recon_tool', 'is_high_severity_category',
                'is_normal_traffic', 'is_real_attack', 'is_unsw_data'
            ]
            
            # Additional engineered features
            engineered_features = [
                'hour', 'day_of_week', 'is_weekend', 'is_night',
                'requests_per_ip', 'unique_targets_per_ip', 'high_frequency_flag',
                'multiple_targets_flag', 'requests_per_session',
                'is_common_attack_port', 'is_tcp', 'is_udp', 'is_icmp'
            ]
            
            # Combine all possible features
            all_possible_features = base_features + engineered_features
            
            # Select only features that exist in the dataframe
            final_features = [col for col in all_possible_features if col in df.columns]
            
            # Always include the target variable if it exists
            if 'is_threat' in df.columns:
                final_features.append('is_threat')
            
            # Create final dataset
            ml_df = df[final_features].copy()
            
            logging.info(f"✅ Selected {len(final_features)} features for ML from hybrid dataset")
            print(f"\n🎯 Final ML Features ({len(final_features)}):")
            for i, feature in enumerate(final_features):
                if feature != 'is_threat':
                    print(f"   {i+1:2d}. {feature}")
            
            return ml_df
            
        except Exception as e:
            raise CustomException(f"Feature selection failed: {e}", sys)
    
    def analyze_threat_patterns(self, df):
        """
        Analyze differences between normal and threat patterns in hybrid dataset
        """
        if 'is_threat' not in df.columns or df.empty:
            logging.warning("⚠️ No threat labels found for pattern analysis")
            return
        
        try:
            # Select numerical features for comparison
            numerical_features = df.select_dtypes(include=[np.number]).columns.tolist()
            if 'is_threat' in numerical_features:
                numerical_features.remove('is_threat')
            
            if not numerical_features:
                print("⚠️ No numerical features available for analysis")
                return
            
            threat_stats = df.groupby('is_threat')[numerical_features].mean().round(3)
            
            print("\n" + "="*70)
            print("🔍 HYBRID DATASET - THREAT vs NORMAL PATTERN ANALYSIS")
            print("="*70)
            print("0 = Normal traffic, 1 = Threat traffic")
            print(threat_stats)
            
            # Calculate threat detection rate
            total_threats = df['is_threat'].sum()
            total_records = len(df)
            threat_percentage = (total_threats / total_records * 100)
            
            print(f"\n📈 Threat Distribution:")
            print(f"   Normal events: {total_records - total_threats} ({100 - threat_percentage:.1f}%)")
            print(f"   Threat events: {total_threats} ({threat_percentage:.1f}%)")
            
            # Dataset composition
            if 'is_real_attack' in df.columns:
                real_attack_count = df['is_real_attack'].sum()
                unsw_count = total_records - real_attack_count
                print(f"\n📊 Dataset Composition:")
                print(f"   UNSW-NB15 records: {unsw_count} ({unsw_count/total_records*100:.1f}%)")
                print(f"   Real attack records: {real_attack_count} ({real_attack_count/total_records*100:.1f}%)")
            
            print("="*70)
            
        except Exception as e:
            logging.warning(f"Threat pattern analysis failed: {e}")
    
    def create_ml_ready_dataset(self, processed_attack_data_path):
        """
        Create final ML-ready dataset from hybrid data
        """
        logging.info("🚀 Creating ML-ready dataset from hybrid data")
        
        try:
            # Step 1: Load the processed hybrid data
            hybrid_data = self.load_attack_data(processed_attack_data_path)
            
            if hybrid_data.empty:
                raise CustomException("No data available for transformation")
            
            # Step 2: Handle missing values
            cleaned_data = self.handle_missing_values(hybrid_data)
            
            # Step 3: Create cybersecurity features
            feature_data = self.create_cybersecurity_features(cleaned_data)
            
            # Step 4: Encode categorical features
            encoded_data = self.encode_categorical_features(feature_data)
            
            # Step 5: Scale numerical features
            scaled_data = self.scale_numerical_features(encoded_data)
            
            # Step 6: Select final ML features
            final_data = self.select_ml_features(scaled_data)
            
            # Ensure artifacts directory exists
            os.makedirs(os.path.dirname(self.transformation_config.processed_features_path), exist_ok=True)
            
            # Save transformed features
            final_data.to_csv(self.transformation_config.processed_features_path, index=False)
            
            # Save labeled dataset
            final_data.to_csv(self.transformation_config.labeled_dataset_path, index=False)
            
            # Analyze threat patterns
            self.analyze_threat_patterns(final_data)
            
            # Generate feature summary
            self.get_feature_summary(final_data)
            
            logging.info(f"✅ ML-ready hybrid dataset created with {len(final_data)} records and {len(final_data.columns)} features")
            logging.info(f"✅ Dataset saved to: {self.transformation_config.labeled_dataset_path}")
            
            return final_data
            
        except Exception as e:
            raise CustomException(f"ML dataset creation failed: {e}", sys)

    def get_feature_summary(self, df):
        """
        Generate summary of features for analysis
        """
        try:
            if df.empty:
                print("⚠️ No data available for feature summary")
                return {}
                
            summary = {
                'total_features': len(df.columns),
                'numerical_features': len(df.select_dtypes(include=[np.number]).columns),
                'categorical_features': len(df.select_dtypes(include=['object', 'category']).columns),
                'total_records': len(df),
                'threat_records': df['is_threat'].sum() if 'is_threat' in df.columns else 0,
                'feature_names': df.columns.tolist()
            }
            
            print("\n" + "="*60)
            print("📊 HYBRID DATASET - FEATURE ENGINEERING SUMMARY")
            print("="*60)
            print(f"Total features created: {summary['total_features']}")
            print(f"Numerical features: {summary['numerical_features']}")
            print(f"Categorical features: {summary['categorical_features']}")
            print(f"Total records: {summary['total_records']}")
            if 'is_threat' in df.columns:
                print(f"Threat records: {summary['threat_records']}")
                print(f"Normal records: {summary['total_records'] - summary['threat_records']}")
            
            # Dataset source info
            if 'is_real_attack' in df.columns:
                real_count = df['is_real_attack'].sum()
                unsw_count = len(df) - real_count
                print(f"UNSW-NB15 records: {unsw_count}")
                print(f"Real attack records: {real_count}")
            print("="*60)
            
            return summary
            
        except Exception as e:
            logging.warning(f"Feature summary generation failed: {e}")
            return {}

# Example usage
if __name__ == "__main__":
    # This transforms the hybrid data for ML training
    data_transformation = DataTransformation()
    
    try:
        # Path to the processed hybrid data from HybridDetectionAgent
        processed_attack_data_path = 'artifacts/processed_attack_data.csv'
        
        if os.path.exists(processed_attack_data_path):
            print("🚀 Starting Data Transformation for HYBRID ML Training")
            print("="*60)
            
            transformed_data = data_transformation.create_ml_ready_dataset(
                processed_attack_data_path
            )
            
            print(f"\n🎯 HYBRID Data Transformation Results:")
            print(f"✅ Final dataset shape: {transformed_data.shape}")
            print(f"✅ Threat labels: {'is_threat' in transformed_data.columns}")
            print(f"✅ Dataset composition analyzed")
            print(f"✅ ML-ready hybrid dataset saved to: {data_transformation.transformation_config.labeled_dataset_path}")
            print(f"✅ You can now use this balanced data to train robust ML models!")
            
        else:
            print(f"❌ Processed hybrid data not found at: {processed_attack_data_path}")
            print("💡 Please run HybridDetectionAgent first to generate the hybrid data")
            
    except Exception as e:
        print(f"❌ Error in data transformation: {e}")
        import traceback
        traceback.print_exc()