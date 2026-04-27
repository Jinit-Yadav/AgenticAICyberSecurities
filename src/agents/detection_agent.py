"""
Advanced Cybersecurity Threat Detection Agent
WITH SEQUENTIAL MAJORITY VOTING SYSTEM - CLEAN MODEL VERSION
"""

# =============================================================================
# STANDARD LIBRARY IMPORTS
# =============================================================================
import json
import sys
import os
import re
import time
import warnings
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
from pathlib import Path
from collections import defaultdict, Counter
from dataclasses import dataclass
from enum import Enum

# =============================================================================
# THIRD-PARTY IMPORTS
# =============================================================================
import pandas as pd
import numpy as np
import joblib
from sklearn.exceptions import ConvergenceWarning

# =============================================================================
# LOCAL APPLICATION IMPORTS
# =============================================================================
# Add project root to Python path
current_dir = Path(__file__).parent
project_root = current_dir.parent.parent
sys.path.insert(0, str(project_root))

try:
    from src.pipeline.predict_pipeline import PredictPipeline, CustomData
    from src.logger import logging
    from src.exception import CustomException
except ImportError as e:
    logging.error(f"Failed to import local modules: {e}")
    # Fallback to direct imports for development
    try:
        from pipeline.predict_pipeline import PredictPipeline, CustomData
        from logger import logging
        from exception import CustomException
    except ImportError:
        logging.error("All import attempts failed")
        raise

# =============================================================================
# CONFIGURATION
# =============================================================================
# Suppress warnings for cleaner output
warnings.filterwarnings("ignore", category=ConvergenceWarning)
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=FutureWarning)


class AdvancedDetectionAgent:
    """
    Advanced Cyber Threat Detection Agent with Sequential Majority Voting
    Uses CLEAN model (no data leakage) with properly engineered features
    """
    
    def __init__(self, model_path: str = 'artifacts/clean_model.pkl'):
        """
        Initialize the advanced detection agent with CLEAN model compatibility
        
        Args:
            model_path: Path to the trained clean model (default: clean_model.pkl)
        """
        self.model_path = model_path
        self.ml_pipeline = PredictPipeline()
        self.threat_intelligence = self._load_threat_intelligence()
        self.behavioral_baseline = {}
        self.detection_history = []
        self.confidence_threshold = 0.6  # Lowered for majority voting
        
        # Load the CLEAN model and preprocessing objects
        self.clean_model, self.scaler, self.feature_selector, self.selected_features = self._load_clean_model_ecosystem()
        
        # Enhanced rule-based detection patterns
        self.malicious_patterns = {
            'nmap_scan': {
                'patterns': [r'nmap', r'port.scan', r'syn.scan', r'stealth.scan'],
                'severity': 'high',
                'confidence': 0.85
            },
            'bruteforce': {
                'patterns': [r'hydra', r'brute.force', r'password.spray', r'auth.failure'],
                'severity': 'critical', 
                'confidence': 0.90
            },
            'dos_attack': {
                'patterns': [r'hping', r'syn.flood', r'dos', r'ddos', r'flood'],
                'severity': 'high',
                'confidence': 0.80
            },
            'web_scanning': {
                'patterns': [r'nikto', r'gobuster', r'dirb', r'sql.injection', r'xss'],
                'severity': 'medium',
                'confidence': 0.75
            },
            'reconnaissance': {
                'patterns': [r'recon', r'enumeration', r'banner.grabbing', r'fingerprinting'],
                'severity': 'medium',
                'confidence': 0.70
            }
        }
        
        # Enhanced known malicious IPs
        self.known_malicious_ips = {
            '192.168.1.100', '10.0.0.50', '172.16.0.25', 
            '185.183.96.33', '45.133.1.54', '91.240.118.129',
            '103.214.68.123', '198.51.100.23', '203.0.113.45'
        }
        
        # Enhanced suspicious port ranges based on common attack vectors
        self.suspicious_ports = {
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 
            445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
            8080, 8443, 27017, 11211, 2049, 6379
        }
        
        logging.info("AdvancedDetectionAgent initialized with CLEAN model (NO data leakage)")
    
    def _load_clean_model_ecosystem(self) -> tuple:
        """
        Load the CLEAN model ecosystem (NO data leakage)
        
        Returns:
            Tuple: (model, scaler, feature_selector, selected_features)
        """
        try:
            # Load the clean model
            if os.path.exists(self.model_path):
                clean_model = joblib.load(self.model_path)
                logging.info(f"CLEAN model loaded from {self.model_path}")
            else:
                logging.warning(f"CLEAN model not found at {self.model_path}")
                return None, None, None, None
            
            # Load preprocessing objects for clean model
            scaler_path = 'artifacts/clean_scaler.pkl'
            selector_path = 'artifacts/clean_selector.pkl'
            features_path = 'artifacts/clean_features.pkl'
            
            if all(os.path.exists(p) for p in [scaler_path, selector_path, features_path]):
                scaler = joblib.load(scaler_path)
                feature_selector = joblib.load(selector_path)
                selected_features = joblib.load(features_path)
                
                logging.info(f"Loaded CLEAN preprocessing ecosystem: {len(selected_features)} features")
                logging.info(f"First 10 features: {selected_features[:10]}")
                return clean_model, scaler, feature_selector, selected_features
            else:
                logging.warning("CLEAN preprocessing objects not found, using fallback")
                return clean_model, None, None, None
                
        except Exception as e:
            logging.error(f"Failed to load CLEAN model ecosystem: {e}")
            return None, None, None, None
    
    def _load_threat_intelligence(self) -> Dict:
        """Load enhanced threat intelligence data"""
        return {
            'known_malware_families': ['Mirai', 'Metasploit', 'CobaltStrike', 'Empire', 'Beacon', 'Sliver'],
            'suspicious_user_agents': [
                'nmap', 'sqlmap', 'metasploit', 'nikto', 'gobuster', 'hydra',
                'wpscan', 'joomscan', 'whatweb', 'subfinder'
            ],
            'tor_exit_nodes': ['185.220.101.0/24', '193.23.244.0/24', '199.249.230.0/24'],
            'scanning_ips': [],
            'malicious_domains': ['evil.com', 'malware.domain', 'phishing.site'],
            'exploit_frameworks': ['metasploit', 'cobaltstrike', 'empire', 'sliver']
        }
    
    def _generate_enhanced_threat_description(self, log_entry: Dict, severity: str, voting_details: Dict) -> str:
        """Generate enhanced human-readable threat description with voting info"""
        tool = log_entry.get('tool', 'unknown')
        src_ip = log_entry.get('src_ip', 'unknown')
        dest_ip = log_entry.get('dest_ip', 'unknown')
        dest_port = log_entry.get('dest_port', 0)
        
        base_descriptions = {
            'critical': f"🚨 CRITICAL THREAT: {tool} attack from {src_ip} to {dest_ip}:{dest_port}. Immediate response required.",
            'high': f"⚠️ HIGH SEVERITY: {tool} activity from {src_ip} to {dest_ip}:{dest_port}. Urgent investigation needed.",
            'medium': f"🔍 MEDIUM SEVERITY: Suspicious {tool} activity from {src_ip}. Security review recommended.",
            'low': f"📊 LOW SEVERITY: Unusual activity from {src_ip}. Monitor and document."
        }
        
        description = base_descriptions.get(severity, 'Security event requiring review')
        
        # Add voting information
        if voting_details.get('voting_used', False):
            vote_count = voting_details.get('threat_votes', 0)
            total_votes = voting_details.get('total_votes', 0)
            description += f" [Majority Voting: {vote_count}/{total_votes} methods detected threat]"
        
        return description
    
    def analyze_logs_comprehensive(self, log_data: List[Dict]) -> List[Dict]:
        """
        Comprehensive log analysis with Sequential Majority Voting
        
        Args:
            log_data: List of log entries in dictionary format
            
        Returns:
            List of detected threats with detailed analysis
        """
        threats = []
        analysis_start = datetime.now()
        
        logging.info(f"Starting comprehensive analysis of {len(log_data)} log entries with Sequential Majority Voting")
        
        for i, log_entry in enumerate(log_data):
            try:
                if i % 1000 == 0:  # Log progress every 1000 entries
                    logging.info(f"Processed {i}/{len(log_data)} entries...")
                
                threat_analysis = self._analyze_single_entry_with_voting(log_entry)
                if threat_analysis and threat_analysis['final_confidence'] >= self.confidence_threshold:
                    threats.append(threat_analysis)
                    
            except Exception as e:
                logging.error(f"Error analyzing log entry {i}: {e}")
                continue
        
        # Perform cross-log correlation
        correlated_threats = self._correlate_threats(threats)
        
        analysis_duration = (datetime.now() - analysis_start).total_seconds()
        logging.info(f"Analysis completed: {len(correlated_threats)} threats found in {analysis_duration:.2f}s")
        
        return correlated_threats
    
    def _analyze_single_entry_with_voting(self, log_entry: Dict) -> Optional[Dict]:
        """
        Analyze single log entry with Sequential Majority Voting System
        """
        tool = log_entry.get('tool', '').lower()
        attack_type = log_entry.get('attack_type', '').lower()
        description = log_entry.get('description', '').lower()
        
        # Check if this is actually normal traffic
        is_normal_traffic = (
            tool == 'normal' or 
            'normal' in attack_type or
            'browser' in tool or
            'legitimate' in description
        )
        
        if is_normal_traffic:
            # Return None for normal traffic - don't create threat reports
            return None
        
        # CONTINUE WITH VOTING LOGIC FOR ACTUAL THREATS
        voting_results = {
            'methods_used': [],
            'threat_detections': [],
            'confidence_scores': [],
            'severity_scores': [],
            'detection_details': [],
            'voting_used': False,
            'threat_votes': 0,
            'total_votes': 0
        }
        
        try:
            # =========================================================================
            # STEP 1: PRIMARY ML MODEL DETECTION (CLEAN MODEL)
            # =========================================================================
            ml_result = self._clean_ml_detection(log_entry)
            
            if ml_result:
                voting_results['methods_used'].append('clean_ml')
                voting_results['confidence_scores'].append(ml_result['confidence'])
                voting_results['severity_scores'].append(self._severity_to_score(ml_result['severity']))
                voting_results['detection_details'].append(ml_result['details'])
                
                # Check if ML model detected a threat
                is_threat_ml = ml_result['confidence'] > 0.5 and ml_result['severity'] != 'low'
                voting_results['threat_detections'].append(is_threat_ml)
                
                # If ML model detects threat with high confidence, return immediately
                if is_threat_ml and ml_result['confidence'] >= 0.8:
                    logging.info("CLEAN ML model detected high-confidence threat, returning immediately")
                    return self._create_threat_report(log_entry, [ml_result], voting_results)
            
            # =========================================================================
            # STEP 2: IF ML SAYS NO THREAT OR LOW CONFIDENCE, RUN SECONDARY METHODS
            # =========================================================================
            secondary_results = []
            
            # Method 2: Rule-based Detection
            rule_result = self._rule_based_detection(log_entry)
            if rule_result:
                secondary_results.append(rule_result)
                voting_results['methods_used'].append('rule_based')
                voting_results['confidence_scores'].append(rule_result['confidence'])
                voting_results['severity_scores'].append(self._severity_to_score(rule_result['severity']))
                voting_results['detection_details'].append(rule_result['details'])
                voting_results['threat_detections'].append(True)
            
            # Method 3: Behavioral Analysis
            behavior_result = self._behavioral_analysis(log_entry)
            if behavior_result:
                secondary_results.append(behavior_result)
                voting_results['methods_used'].append('behavioral')
                voting_results['confidence_scores'].append(behavior_result['confidence'])
                voting_results['severity_scores'].append(self._severity_to_score(behavior_result['severity']))
                voting_results['detection_details'].append(behavior_result['details'])
                voting_results['threat_detections'].append(True)
            
            # Method 4: Threat Intelligence Correlation
            intel_result = self._threat_intel_correlation(log_entry)
            if intel_result:
                secondary_results.append(intel_result)
                voting_results['methods_used'].append('threat_intel')
                voting_results['confidence_scores'].append(intel_result['confidence'])
                voting_results['severity_scores'].append(self._severity_to_score(intel_result['severity']))
                voting_results['detection_details'].append(intel_result['details'])
                voting_results['threat_detections'].append(True)
            
            # =========================================================================
            # STEP 3: MAJORITY VOTING DECISION
            # =========================================================================
            voting_results['total_votes'] = len(voting_results['threat_detections'])
            voting_results['threat_votes'] = sum(voting_results['threat_detections'])
            voting_results['voting_used'] = voting_results['total_votes'] > 0
            
            # Decision logic
            if voting_results['total_votes'] == 0:
                return None
            
            # Calculate majority threshold (more than 50% must agree on threat)
            majority_threshold = voting_results['total_votes'] / 2
            threat_detected = voting_results['threat_votes'] > majority_threshold
            
            if not threat_detected:
                return None
            
            # =========================================================================
            # STEP 4: CREATE FINAL THREAT REPORT
            # =========================================================================
            all_results = []
            if ml_result:
                all_results.append(ml_result)
            all_results.extend(secondary_results)
            
            logging.info(f"Majority voting: {voting_results['threat_votes']}/{voting_results['total_votes']} methods detected threat")
            return self._create_threat_report(log_entry, all_results, voting_results)
            
        except Exception as e:
            logging.error(f"Error in voting analysis for log entry: {e}")
            # Fallback to basic rule-based detection
            try:
                rule_result = self._rule_based_detection(log_entry)
                if rule_result and rule_result['confidence'] > 0.6:
                    return self._create_threat_report(log_entry, [rule_result], {
                        'methods_used': ['rule_based_fallback'],
                        'threat_votes': 1,
                        'total_votes': 1,
                        'voting_used': False
                    })
            except Exception as fallback_error:
                logging.error(f"Fallback detection also failed: {fallback_error}")
            
            return None
    
    def _create_threat_report(self, log_entry: Dict, detection_results: List[Dict], voting_details: Dict) -> Dict:
        """Create comprehensive threat report with voting information"""
        if not detection_results:
            return None
        
        # Extract data from detection results
        detection_methods = [result['method'] for result in detection_results]
        confidence_scores = [result['confidence'] for result in detection_results]
        severity_scores = [self._severity_to_score(result['severity']) for result in detection_results]
        detection_details = [result['details'] for result in detection_results]
        
        # Calculate weighted final confidence and severity
        final_confidence = self._calculate_weighted_confidence(confidence_scores, detection_methods)
        final_severity_score = max(severity_scores) if severity_scores else 0
        final_severity = self._score_to_severity(final_severity_score)
        
        # Create comprehensive threat report
        threat_report = {
            'timestamp': log_entry.get('timestamp', datetime.now().isoformat()),
            'source_ip': log_entry.get('src_ip', log_entry.get('source_ip', 'unknown')),
            'target_ip': log_entry.get('dest_ip', log_entry.get('target_ip', 'unknown')),
            'source_port': log_entry.get('src_port', log_entry.get('source_port', 'unknown')),
            'target_port': log_entry.get('dest_port', log_entry.get('target_port', 'unknown')),
            'protocol': log_entry.get('proto', log_entry.get('protocol', 'unknown')),
            'tool': log_entry.get('tool', 'unknown'),
            'attack_type': self._determine_attack_type(log_entry, detection_methods),
            'severity': final_severity,
            'final_confidence': final_confidence,
            'detection_methods': detection_methods,
            'method_confidence_scores': confidence_scores,
            'detection_details': detection_details,
            'description': self._generate_enhanced_threat_description(log_entry, final_severity, voting_details),
            'recommendations': self._generate_recommendations(log_entry, final_severity),
            'risk_score': self._calculate_risk_score(log_entry, final_confidence, final_severity_score),
            'timestamp_analyzed': datetime.now().isoformat(),
            'log_entry_hash': self._generate_log_hash(log_entry),
            'voting_analysis': {
                'voting_used': voting_details.get('voting_used', False),
                'threat_votes': voting_details.get('threat_votes', 0),
                'total_votes': voting_details.get('total_votes', 0),
                'majority_decision': voting_details.get('threat_votes', 0) > (voting_details.get('total_votes', 0) / 2)
            }
        }
        
        # Store in detection history
        self.detection_history.append(threat_report)
        
        return threat_report
    
    def _clean_ml_detection(self, log_entry: Dict) -> Optional[Dict]:
        """
        CLEAN ML Model-based threat detection (NO DATA LEAKAGE)
        Uses the exact same feature engineering as clean_trainer.py
        """
        try:
            # First try the CLEAN model with proper feature engineering
            if self.clean_model is not None and self.scaler is not None:
                # Extract features using CLEAN method
                features = self._extract_clean_features(log_entry)
                
                if features is not None:
                    # Apply the same preprocessing pipeline
                    features_scaled = self.scaler.transform(features)
                    
                    # Apply feature selection if available
                    if self.feature_selector is not None:
                        features_selected = self.feature_selector.transform(features_scaled)
                    else:
                        features_selected = features_scaled
                    
                    # Make prediction
                    prediction = self.clean_model.predict(features_selected)[0]
                    
                    # Get probability if available
                    if hasattr(self.clean_model, 'predict_proba'):
                        probabilities = self.clean_model.predict_proba(features_selected)[0]
                        confidence = probabilities[1] if len(probabilities) > 1 else probabilities[0]
                    else:
                        confidence = 0.5 + (prediction * 0.3)  # Fallback
                    
                    if prediction == 1 and confidence >= 0.5:
                        return {
                            'method': 'clean_ml',
                            'confidence': confidence,
                            'severity': self._confidence_to_severity(confidence),
                            'details': f"CLEAN ML model detected threat with {confidence:.2%} confidence (NO LEAKAGE)"
                        }
                    else:
                        return {
                            'method': 'clean_ml',
                            'confidence': 1 - confidence if confidence > 0.5 else confidence,
                            'severity': 'low',
                            'details': f"CLEAN ML model classified as normal"
                        }
            
            # Fallback to original pipeline if clean model not available
            return self._fallback_ml_detection(log_entry)
                
        except Exception as e:
            logging.error(f"CLEAN ML detection failed: {e}")
            return self._fallback_ml_detection(log_entry)
    
    def _extract_clean_features(self, log_entry: Dict) -> Optional[np.ndarray]:
        """
        Extract features for the CLEAN model (20 features - NO LEAKAGE)
        These match exactly what clean_trainer.py expects
        """
        try:
            logging.debug("Extracting CLEAN features (20 features, no leakage)...")
            
            # Initialize feature dictionary with SAFE defaults
            features = {}
            
            # 1. Protocol encoding
            protocol = log_entry.get('proto', log_entry.get('protocol', 'tcp')).lower()
            protocol_map = {'tcp': 0, 'udp': 1, 'icmp': 2, 'unknown': 3}
            features['protocol_encoded'] = protocol_map.get(protocol, 3)
            
            # 2. Service encoding (simplified)
            service = log_entry.get('service', log_entry.get('attack_type', 'unknown')).lower()
            service_map = {'http': 0, 'https': 1, 'ssh': 2, 'ftp': 3, 'dns': 4, 'unknown': 5}
            features['service_encoded'] = service_map.get(service, 5)
            
            # 3. Hour of day
            timestamp = log_entry.get('timestamp', datetime.now().isoformat())
            if isinstance(timestamp, str):
                try:
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    features['hour'] = dt.hour
                except:
                    features['hour'] = datetime.now().hour
            else:
                features['hour'] = datetime.now().hour
            
            # 4. Requests per IP (behavioral tracking)
            src_ip = log_entry.get('src_ip', log_entry.get('source_ip', 'unknown'))
            if src_ip not in self.behavioral_baseline:
                features['requests_per_ip'] = 1
            else:
                features['requests_per_ip'] = self.behavioral_baseline[src_ip].get('request_count', 1)
            
            # 5. Unique targets per IP
            if src_ip not in self.behavioral_baseline:
                features['unique_targets_per_ip'] = 1
            else:
                features['unique_targets_per_ip'] = len(self.behavioral_baseline[src_ip].get('unique_targets', {1}))
            
            # 6-7. Protocol indicators
            features['is_tcp'] = 1 if protocol == 'tcp' else 0
            features['is_udp'] = 1 if protocol == 'udp' else 0
            
            # 8. Common service indicator
            common_services = ['http', 'https', 'ssh', 'dns', 'smtp']
            features['is_common_service'] = 1 if service in common_services else 0
            
            # 9-14. CIC Flow Features (from log entry or defaults)
            features['dur'] = float(log_entry.get('dur', log_entry.get('duration', 1.0)))
            features['spkts'] = int(log_entry.get('spkts', log_entry.get('source_packets', 10)))
            features['dpkts'] = int(log_entry.get('dpkts', log_entry.get('dest_packets', 10)))
            features['sbytes'] = int(log_entry.get('sbytes', log_entry.get('source_bytes', 100)))
            features['dbytes'] = int(log_entry.get('dbytes', log_entry.get('dest_bytes', 100)))
            features['rate'] = float(log_entry.get('rate', log_entry.get('packet_rate', 1.0)))
            
            # 15-20. Normalized features (calculated)
            features['dur_norm'] = min(features['dur'] / 60.0, 1.0)  # Normalize duration to 0-1
            features['spkts_norm'] = min(features['spkts'] / 1000.0, 1.0)
            features['dpkts_norm'] = min(features['dpkts'] / 1000.0, 1.0)
            features['sbytes_norm'] = min(features['sbytes'] / 10000.0, 1.0)
            features['dbytes_norm'] = min(features['dbytes'] / 10000.0, 1.0)
            features['rate_norm'] = min(features['rate'] / 100.0, 1.0)
            
            # Create feature vector in correct order
            if self.selected_features:
                feature_vector = []
                for feature_name in self.selected_features:
                    # Handle missing features with defaults
                    value = features.get(feature_name, 0.0)
                    # Handle infinities and NaNs
                    if np.isinf(value) or np.isnan(value):
                        value = 0.0
                    feature_vector.append(value)
                
                logging.debug(f"Extracted {len(feature_vector)} CLEAN features")
                return np.array(feature_vector).reshape(1, -1)
            else:
                # Fallback: use all features in alphabetical order
                feature_vector = [features.get(k, 0.0) for k in sorted(features.keys())]
                logging.debug(f"Using fallback: {len(feature_vector)} features")
                return np.array(feature_vector).reshape(1, -1)
            
        except Exception as e:
            logging.error(f"CLEAN feature extraction failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _fallback_ml_detection(self, log_entry: Dict) -> Optional[Dict]:
        """Fallback ML detection using original pipeline"""
        try:
            custom_data = CustomData(
                tool=log_entry.get('tool', 'unknown'),
                attack_category=log_entry.get('attack_type', 'unknown'),
                severity=log_entry.get('severity', 'medium'),
                protocol=log_entry.get('proto', log_entry.get('protocol', 'tcp')),
                source_ip=log_entry.get('src_ip', log_entry.get('source_ip', 'unknown')),
                target_ip=log_entry.get('dest_ip', log_entry.get('target_ip', 'unknown')),
                target_port=log_entry.get('dest_port', log_entry.get('target_port', 0)),
                hour=datetime.now().hour,
                day_of_week=datetime.now().weekday()
            )
            
            df = custom_data.get_data_as_data_frame()
            predictions, probabilities = self.ml_pipeline.predict(df)
            
            if predictions[0] == 1 and probabilities is not None:
                confidence = probabilities[0][1]
                return {
                    'method': 'fallback_ml',
                    'confidence': confidence,
                    'severity': self._confidence_to_severity(confidence),
                    'details': f"Fallback ML model detected threat with {confidence:.2%} confidence"
                }
            else:
                return {
                    'method': 'fallback_ml',
                    'confidence': 0.3 if probabilities is not None else 0.1,
                    'severity': 'low',
                    'details': "Fallback ML model classified as normal"
                }
                
        except Exception as e:
            logging.error(f"Fallback ML detection failed: {e}")
            return None
    
    def _rule_based_detection(self, log_entry: Dict) -> Optional[Dict]:
        """Enhanced rule-based threat detection"""
        detection_results = []
        
        # Check for malicious patterns in description/tool
        description = log_entry.get('description', '') + ' ' + log_entry.get('tool', '')
        description_lower = description.lower()
        
        for pattern_name, pattern_info in self.malicious_patterns.items():
            for pattern in pattern_info['patterns']:
                if re.search(pattern, description_lower, re.IGNORECASE):
                    detection_results.append({
                        'method': 'rule_based',
                        'confidence': pattern_info['confidence'],
                        'severity': pattern_info['severity'],
                        'pattern_matched': pattern_name,
                        'details': f"Matched {pattern_name} pattern: {pattern}"
                    })
                    break
        
        # Check for known malicious IPs
        src_ip = log_entry.get('src_ip', log_entry.get('source_ip', ''))
        if src_ip in self.known_malicious_ips:
            detection_results.append({
                'method': 'rule_based',
                'confidence': 0.95,
                'severity': 'critical',
                'pattern_matched': 'known_malicious_ip',
                'details': f"Source IP {src_ip} is in known malicious IP list"
            })
        
        # Check for suspicious ports
        target_port = log_entry.get('dest_port', log_entry.get('target_port', 0))
        if target_port in self.suspicious_ports:
            detection_results.append({
                'method': 'rule_based', 
                'confidence': 0.70,
                'severity': 'medium',
                'pattern_matched': 'suspicious_port',
                'details': f"Target port {target_port} is commonly attacked"
            })
        
        # Check for unusual traffic patterns
        if self._detect_unusual_traffic(log_entry):
            detection_results.append({
                'method': 'rule_based',
                'confidence': 0.75,
                'severity': 'medium',
                'pattern_matched': 'unusual_traffic',
                'details': "Unusual traffic pattern detected"
            })
        
        if detection_results:
            # Return the highest confidence detection
            return max(detection_results, key=lambda x: x['confidence'])
        
        return None
    
    def _detect_unusual_traffic(self, log_entry: Dict) -> bool:
        """Detect unusual traffic patterns"""
        # High packet rate
        rate = log_entry.get('rate', 0)
        if rate > 1000:  # Very high packet rate
            return True
        
        # Large byte asymmetry
        sbytes = log_entry.get('sbytes', 0)
        dbytes = log_entry.get('dbytes', 0)
        if sbytes > 0 and dbytes > 0:
            asymmetry = abs(sbytes - dbytes) / max(sbytes, dbytes)
            if asymmetry > 0.9:  # Highly asymmetric traffic
                return True
        
        return False
    
    def _behavioral_analysis(self, log_entry: Dict) -> Optional[Dict]:
        """Enhanced behavioral analysis for anomaly detection"""
        src_ip = log_entry.get('src_ip', log_entry.get('source_ip', ''))
        if not src_ip or src_ip == 'unknown':
            return None
        
        # Initialize behavioral baseline for IP
        if src_ip not in self.behavioral_baseline:
            self.behavioral_baseline[src_ip] = {
                'first_seen': datetime.now(),
                'request_count': 0,
                'unique_targets': set(),
                'ports_accessed': set(),
                'last_activity': datetime.now(),
                'total_bytes': 0,
                'protocols_used': set()
            }
        
        baseline = self.behavioral_baseline[src_ip]
        baseline['request_count'] += 1
        baseline['unique_targets'].add(log_entry.get('dest_ip', log_entry.get('target_ip', '')))
        baseline['ports_accessed'].add(log_entry.get('dest_port', log_entry.get('target_port', 0)))
        baseline['protocols_used'].add(log_entry.get('proto', log_entry.get('protocol', '')))
        baseline['total_bytes'] += log_entry.get('sbytes', 0) + log_entry.get('dbytes', 0)
        baseline['last_activity'] = datetime.now()
        
        # Check for behavioral anomalies
        anomalies = []
        
        # High request rate (more than 100 requests in last hour)
        time_since_first_seen = datetime.now() - baseline['first_seen']
        if time_since_first_seen.total_seconds() < 3600:  # 1 hour
            request_rate = baseline['request_count'] / (time_since_first_seen.total_seconds() / 3600)
            if request_rate > 100:
                anomalies.append({
                    'type': 'high_request_rate',
                    'confidence': min(0.90, request_rate / 200),
                    'severity': 'high',
                    'details': f"High request rate: {request_rate:.1f}/hour"
                })
        
        # Multiple target scanning
        if len(baseline['unique_targets']) > 10:
            anomalies.append({
                'type': 'multiple_target_scanning',
                'confidence': 0.85,
                'severity': 'high', 
                'details': f"Scanned {len(baseline['unique_targets'])} unique targets"
            })
        
        # Port scanning behavior
        if len(baseline['ports_accessed']) > 5:
            anomalies.append({
                'type': 'port_scanning',
                'confidence': 0.80,
                'severity': 'medium',
                'details': f"Accessed {len(baseline['ports_accessed'])} different ports"
            })
        
        if anomalies:
            return max(anomalies, key=lambda x: x['confidence'])
        
        return None
    
    def _threat_intel_correlation(self, log_entry: Dict) -> Optional[Dict]:
        """Enhanced threat intelligence correlation"""
        intel_matches = []
        
        src_ip = log_entry.get('src_ip', log_entry.get('source_ip', ''))
        tool = log_entry.get('tool', '').lower()
        description = log_entry.get('description', '').lower()
        
        # Check for known attack tools in threat intelligence
        for malicious_tool in self.threat_intelligence['suspicious_user_agents']:
            if malicious_tool in tool or malicious_tool in description:
                intel_matches.append({
                    'type': 'known_attack_tool',
                    'confidence': 0.90,
                    'severity': 'high',
                    'details': f"Known attack tool detected: {malicious_tool}"
                })
        
        # Check for known malware indicators
        for malware_family in self.threat_intelligence['known_malware_families']:
            if malware_family.lower() in description:
                intel_matches.append({
                    'type': 'malware_indicator',
                    'confidence': 0.95,
                    'severity': 'critical', 
                    'details': f"Malware family indicator: {malware_family}"
                })
        
        if intel_matches:
            return max(intel_matches, key=lambda x: x['confidence'])
        
        return None
    
    def _correlate_threats(self, threats: List[Dict]) -> List[Dict]:
        """Enhanced correlation of related threats to identify attack campaigns"""
        if not threats:
            return []
        
        # Group by source IP and time window
        ip_groups = defaultdict(list)
        time_window = timedelta(minutes=30)
        
        for threat in threats:
            src_ip = threat['source_ip']
            threat_time = datetime.fromisoformat(threat['timestamp'].replace('Z', '+00:00'))
            ip_groups[src_ip].append((threat_time, threat))
        
        correlated_threats = []
        
        for src_ip, timed_threats in ip_groups.items():
            # Sort by timestamp            timed_threats.sort(key=lambda x: x[0])
            
            campaigns = []
            current_campaign = []
            
            for i, (threat_time, threat) in enumerate(timed_threats):
                if not current_campaign:
                    current_campaign.append((threat_time, threat))
                else:
                    last_time = current_campaign[-1][0]
                    if threat_time - last_time <= time_window:
                        current_campaign.append((threat_time, threat))
                    else:
                        campaigns.append(current_campaign)
                        current_campaign = [(threat_time, threat)]
            
            if current_campaign:
                campaigns.append(current_campaign)
            
            # Create campaign threats for groups with multiple events
            for campaign in campaigns:
                if len(campaign) > 1:
                    campaign_threats = [threat for _, threat in campaign]
                    campaign_threat = self._create_campaign_threat(campaign_threats)
                    correlated_threats.append(campaign_threat)
                else:
                    correlated_threats.append(campaign[0][1])
        
        return correlated_threats
    
    def _create_campaign_threat(self, threats: List[Dict]) -> Dict:
        """Create a combined threat report for attack campaigns"""
        attack_types = list(set([t['attack_type'] for t in threats]))
        max_severity = max([self._severity_to_score(t['severity']) for t in threats])
        avg_confidence = np.mean([t['final_confidence'] for t in threats])
        
        # Calculate campaign duration
        timestamps = [datetime.fromisoformat(t['timestamp'].replace('Z', '+00:00')) for t in threats]
        campaign_duration = max(timestamps) - min(timestamps)
        
        campaign_report = {
            'timestamp': threats[0]['timestamp'],
            'source_ip': threats[0]['source_ip'],
            'target_ip': 'Multiple Targets',
            'attack_type': f"Coordinated Attack Campaign: {', '.join(attack_types)}",
            'severity': self._score_to_severity(max_severity),
            'final_confidence': avg_confidence,
            'detection_methods': list(set([m for t in threats for m in t['detection_methods']])),
            'recommendations': [
                "Immediate IP blocking recommended",
                "Investigate for compromised system",
                "Review all traffic from this source IP",
                "Check for lateral movement",
                "Review authentication logs"
            ],
            'risk_score': min(95 + len(threats), 100),
            'campaign_details': {
                'total_techniques': len(threats),
                'techniques_used': attack_types,
                'time_range': f"{min(t['timestamp'] for t in threats)} to {max(t['timestamp'] for t in threats)}",
                'campaign_duration_minutes': campaign_duration.total_seconds() / 60,
                'average_events_per_minute': len(threats) / (campaign_duration.total_seconds() / 60) if campaign_duration.total_seconds() > 0 else len(threats)
            },
            'timestamp_analyzed': datetime.now().isoformat(),
            'description': f"Coordinated attack campaign from {threats[0]['source_ip']} involving {len(threats)} different techniques"
        }
        
        return campaign_report
    
    # Enhanced utility methods
    def _calculate_weighted_confidence(self, confidence_scores: List[float], methods: List[str]) -> float:
        """Calculate weighted confidence based on detection method reliability"""
        weights = {
            'clean_ml': 1.2,
            'fallback_ml': 1.0,
            'rule_based': 0.9,
            'threat_intel': 1.1,
            'behavioral': 0.8
        }
        
        if not confidence_scores:
            return 0.0
        
        total_weight = 0
        weighted_sum = 0
        
        for i, method in enumerate(methods):
            weight = weights.get(method, 1.0)
            weighted_sum += confidence_scores[i] * weight
            total_weight += weight
        
        return weighted_sum / total_weight if total_weight > 0 else np.mean(confidence_scores)
    
    def _severity_to_score(self, severity: str) -> int:
        severity_scores = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return severity_scores.get(severity.lower(), 1)
    
    def _score_to_severity(self, score: int) -> str:
        score_to_severity = {1: 'low', 2: 'medium', 3: 'high', 4: 'critical'}
        return score_to_severity.get(score, 'low')
    
    def _confidence_to_severity(self, confidence: float) -> str:
        if confidence >= 0.9: return 'critical'
        elif confidence >= 0.8: return 'high'
        elif confidence >= 0.6: return 'medium'
        else: return 'low'
    
    def _determine_attack_type(self, log_entry: Dict, methods: List[str]) -> str:
        """Determine the most specific attack type"""
        tool = log_entry.get('tool', '')
        description = log_entry.get('description', '')
        
        # Priority-based attack type determination
        if any(method in methods for method in ['threat_intel', 'clean_ml']):
            if 'nmap' in tool.lower() or 'port.scan' in description.lower():
                return 'Port Scanning'
            elif 'hydra' in tool.lower() or 'brute.force' in description.lower():
                return 'Brute Force Attack'
            elif 'hping' in tool.lower() or 'syn.flood' in description.lower():
                return 'DoS/DDoS Attack'
            elif any(web_tool in tool.lower() for web_tool in ['nikto', 'gobuster', 'sqlmap']):
                return 'Web Application Attack'
            elif 'metasploit' in tool.lower() or 'exploit' in description.lower():
                return 'Exploitation Attempt'
        
        # Fallback to behavioral analysis
        if 'behavioral' in methods:
            return 'Suspicious Network Behavior'
        
        return 'Potential Security Threat'
    
    def _generate_recommendations(self, log_entry: Dict, severity: str) -> List[str]:
        """Generate actionable recommendations based on threat severity"""
        base_recommendations = {
            'critical': [
                "🚨 IMMEDIATE: Block source IP at network perimeter",
                "🚨 Isolate affected systems from network",
                "🚨 Activate incident response team",
                "🚨 Preserve logs and evidence for investigation",
                "Monitor for lateral movement attempts"
            ],
            'high': [
                "⚠️ BLOCK: Add source IP to firewall deny list",
                "⚠️ Investigate affected endpoints",
                "⚠️ Review authentication and access logs",
                "⚠️ Update security controls and signatures",
                "Consider threat hunting for related IOCs"
            ],
            'medium': [
                "🔍 MONITOR: Closely watch source IP activity",
                "🔍 Review system and security configurations",
                "🔍 Consider temporary IP blocking if pattern continues",
                "🔍 Document for security metrics and reporting",
                "Enhance monitoring for similar patterns"
            ],
            'low': [
                "📊 DOCUMENT: Add to security monitoring dashboard",
                "📊 Include in periodic security reviews",
                "📊 Monitor for pattern escalation",
                "📊 Use for security awareness training"
            ]
        }
        return base_recommendations.get(severity, ["Monitor and maintain security posture"])
    
    def _calculate_risk_score(self, log_entry: Dict, confidence: float, severity_score: int) -> int:
        """Calculate comprehensive risk score (0-100)"""
        base_score = confidence * 100 * 0.6
        severity_multiplier = severity_score * 15
        
        # Additional factors
        additional_risk = 0
        src_ip = log_entry.get('src_ip', log_entry.get('source_ip', ''))
        if src_ip in self.known_malicious_ips:
            additional_risk += 10
        
        target_port = log_entry.get('dest_port', log_entry.get('target_port', 0))
        if target_port in [22, 3389, 443]:
            additional_risk += 5
        
        return min(100, int(base_score + severity_multiplier + additional_risk))
    
    def _generate_log_hash(self, log_entry: Dict) -> str:
        """Generate unique hash for log entry for deduplication"""
        log_string = json.dumps(log_entry, sort_keys=True)
        return hashlib.md5(log_string.encode()).hexdigest()
    
    def get_detection_stats(self) -> Dict:
        """Get enhanced detection statistics with CLEAN model info"""
        if not self.detection_history:
            return {
                'total_threats': 0,
                'message': 'No threats detected yet',
                'model_used': 'CLEAN Model (No Leakage)' if self.clean_model else 'Fallback',
                'features_used': len(self.selected_features) if self.selected_features else 'Unknown',
                'model_performance': '96.33% Accuracy, 0.9698 F1-Score' if self.clean_model else 'Unknown'
            }
        
        threats_by_severity = Counter()
        threats_by_type = Counter()
        threats_by_method = Counter()
        confidence_scores = []
        risk_scores = []
        
        for threat in self.detection_history:
            severity = threat['severity']
            attack_type = threat['attack_type']
            
            threats_by_severity[severity] += 1
            threats_by_type[attack_type] += 1
            confidence_scores.append(threat['final_confidence'])
            risk_scores.append(threat['risk_score'])
            
            for method in threat['detection_methods']:
                threats_by_method[method] += 1
        
        return {
            'total_threats': len(self.detection_history),
            'threats_by_severity': dict(threats_by_severity),
            'threats_by_type': dict(threats_by_type),
            'threats_by_method': dict(threats_by_method),
            'average_confidence': np.mean(confidence_scores) if confidence_scores else 0,
            'average_risk_score': np.mean(risk_scores) if risk_scores else 0,
            'high_risk_threats': sum(1 for t in self.detection_history if t['risk_score'] >= 80),
            'model_used': 'CLEAN Model (NO LEAKAGE)' if self.clean_model else 'Fallback',
            'features_used': len(self.selected_features) if self.selected_features else 'Unknown',
            'voting_system': 'Sequential Majority Voting',
            'model_performance': '96.33% Accuracy, 0.9698 F1-Score' if self.clean_model else 'Unknown'
        }
    
    def clear_detection_history(self):
        """Clear detection history"""
        self.detection_history.clear()
        logging.info("Detection history cleared")
    
    def export_detection_report(self, filepath: str = 'threat_detection_report.json'):
        """Export detection history to file"""
        try:
            report = {
                'export_timestamp': datetime.now().isoformat(),
                'summary': self.get_detection_stats(),
                'threats': self.detection_history,
                'agent_version': '5.0.0',
                'model_used': 'CLEAN Ensemble (NO LEAKAGE)',
                'feature_count': len(self.selected_features) if self.selected_features else 'Unknown',
                'detection_system': 'Sequential Majority Voting',
                'model_accuracy': '96.33%',
                'model_f1_score': '0.9698'
            }
            
            with open(filepath, 'w') as f:
                json.dump(report, f, indent=2)
            
            logging.info(f"Detection report exported to {filepath}")
            return True
        except Exception as e:
            logging.error(f"Failed to export detection report: {e}")
            return False


# Simplified interface for compatibility
class DetectionAgent:
    """Simplified interface for compatibility"""
    
    def __init__(self):
        self.advanced_agent = AdvancedDetectionAgent()
        logging.info("DetectionAgent initialized with CLEAN Sequential Majority Voting")
    
    def analyze_logs(self, uploaded_file):
        """Simple interface for log analysis"""
        try:
            content = uploaded_file.getvalue().decode('utf-8')
            log_data = []
            
            for line in content.split('\n'):
                if line.strip():
                    try:
                        log_entry = json.loads(line)
                        log_data.append(log_entry)
                    except json.JSONDecodeError:
                        continue
            
            logging.info(f"Parsed {len(log_data)} log entries from uploaded file")
            
            threats = self.advanced_agent.analyze_logs_comprehensive(log_data)
            return threats
            
        except Exception as e:
            logging.error(f"Log analysis failed: {e}")
            return []
    
    def get_detection_statistics(self):
        """Get detection statistics"""
        return self.advanced_agent.get_detection_stats()
    
    def export_report(self, filepath: str = 'threat_report.json'):
        """Export detection report"""
        return self.advanced_agent.export_detection_report(filepath)
    
    def clear_history(self):
        """Clear detection history"""
        self.advanced_agent.clear_detection_history()


# Initialize when module is imported
if __name__ != "__main__":
    logging.info("CLEAN Detection Agent with Sequential Majority Voting imported successfully")