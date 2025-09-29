import pandas as pd
import numpy as np
import json
import sys
import os
import joblib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple
import re

# Add project root to path
sys.path.append('.')

from src.pipeline.predict_pipeline import PredictPipeline, CustomData
from src.logger import logging
from src.exception import CustomException

class AdvancedDetectionAgent:
    """
    Advanced Cyber Threat Detection Agent with multiple detection methods:
    1. ML Model Detection (Primary)
    2. Rule-based Detection (Secondary) 
    3. Behavioral Analysis
    4. Threat Intelligence Correlation
    5. Confidence Scoring
    6. AI-Powered Explanations
    """
    
    def __init__(self, model_path: str = 'artifacts/cyber_threat_model.pkl'):
        self.ml_pipeline = PredictPipeline()
        self.threat_intelligence = self._load_threat_intelligence()
        self.behavioral_baseline = {}
        self.detection_history = []
        self.confidence_threshold = 0.7
        
        # Rule-based detection patterns
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
        
        # Known malicious IPs (would normally come from threat intel feeds)
        self.known_malicious_ips = {
            '192.168.1.100', '10.0.0.50', '172.16.0.25', 
            '185.183.96.33', '45.133.1.54', '91.240.118.129'
        }
        
        # Suspicious port ranges
        self.suspicious_ports = {
            21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 
            445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900
        }
    
    def _load_threat_intelligence(self) -> Dict:
        """Load threat intelligence data"""
        return {
            'known_malware_families': ['Mirai', 'Metasploit', 'CobaltStrike', 'Empire'],
            'suspicious_user_agents': [
                'nmap', 'sqlmap', 'metasploit', 'nikto', 'gobuster', 'hydra'
            ],
            'tor_exit_nodes': ['185.220.101.0/24', '193.23.244.0/24'],
            'scanning_ips': []  # Would be populated from external feeds
        }
    
    def _generate_ai_explanation(self, threat_report: Dict, log_entry: Dict) -> str:
        """Generate AI-powered explanation for the threat detection"""
        try:
            from src.agents.explanation_agent import SimpleExplanationAgent
            
            # Initialize explanation agent
            explanation_agent = SimpleExplanationAgent()
            
            # Build explanation prompt
            explanation_prompt = f"""
            Explain this cyber threat detection in simple terms:
            
            Threat Details:
            - Attack Type: {threat_report['attack_type']}
            - Severity: {threat_report['severity']}
            - Confidence: {threat_report['final_confidence']:.2%}
            - Source IP: {threat_report['source_ip']}
            - Target IP: {threat_report['target_ip']}
            - Protocol: {threat_report['protocol']}
            
            Detection Methods Used: {', '.join(threat_report['detection_methods'])}
            
            Key Features:
            - Duration: {log_entry.get('dur', 0):.2f}s
            - Source Packets: {log_entry.get('spkts', 0)}
            - Destination Packets: {log_entry.get('dpkts', 0)}
            - Source Bytes: {log_entry.get('sbytes', 0)}
            - Destination Bytes: {log_entry.get('dbytes', 0)}
            - Rate: {log_entry.get('rate', 0):.2f}
            
            Explain why this activity was flagged as a threat and what it means in practical terms.
            Provide a clear, actionable explanation for security analysts.
            """
            
            return explanation_agent.ask(explanation_prompt)
            
        except Exception as e:
            logging.warning(f"AI explanation failed: {e}")
            # Fallback to original description
            return self._generate_threat_description(log_entry, threat_report['severity'])
    
    def analyze_logs_comprehensive(self, log_data: List[Dict]) -> List[Dict]:
        """
        Comprehensive log analysis with multiple detection methods
        
        Args:
            log_data: List of log entries in dictionary format
            
        Returns:
            List of detected threats with detailed analysis
        """
        threats = []
        
        for log_entry in log_data:
            try:
                threat_analysis = self._analyze_single_entry_comprehensive(log_entry)
                if threat_analysis and threat_analysis['final_confidence'] >= self.confidence_threshold:
                    threats.append(threat_analysis)
                    
            except Exception as e:
                logging.error(f"Error analyzing log entry: {e}")
                continue
        
        # Perform cross-log correlation
        correlated_threats = self._correlate_threats(threats)
        
        return correlated_threats
    
    def _analyze_single_entry_comprehensive(self, log_entry: Dict) -> Optional[Dict]:
        """
        Comprehensive analysis of a single log entry using multiple methods
        """
        detection_methods = []
        confidence_scores = []
        severity_scores = []
        
        # Method 1: ML Model Detection
        ml_result = self._ml_detection(log_entry)
        if ml_result:
            detection_methods.append('ml_model')
            confidence_scores.append(ml_result['confidence'])
            severity_scores.append(self._severity_to_score(ml_result['severity']))
        
        # Method 2: Rule-based Detection
        rule_result = self._rule_based_detection(log_entry)
        if rule_result:
            detection_methods.append('rule_based')
            confidence_scores.append(rule_result['confidence'])
            severity_scores.append(self._severity_to_score(rule_result['severity']))
        
        # Method 3: Behavioral Analysis
        behavior_result = self._behavioral_analysis(log_entry)
        if behavior_result:
            detection_methods.append('behavioral')
            confidence_scores.append(behavior_result['confidence'])
            severity_scores.append(self._severity_to_score(behavior_result['severity']))
        
        # Method 4: Threat Intelligence Correlation
        intel_result = self._threat_intel_correlation(log_entry)
        if intel_result:
            detection_methods.append('threat_intel')
            confidence_scores.append(intel_result['confidence'])
            severity_scores.append(self._severity_to_score(intel_result['severity']))
        
        # If no threats detected, return None
        if not detection_methods:
            return None
        
        # Calculate final confidence and severity
        final_confidence = np.mean(confidence_scores) if confidence_scores else 0
        final_severity_score = max(severity_scores) if severity_scores else 0
        final_severity = self._score_to_severity(final_severity_score)
        
        # Create comprehensive threat report
        threat_report = {
            'timestamp': log_entry.get('timestamp', datetime.now().isoformat()),
            'source_ip': log_entry.get('src_ip', 'unknown'),
            'target_ip': log_entry.get('dest_ip', 'unknown'),
            'source_port': log_entry.get('src_port', 'unknown'),
            'target_port': log_entry.get('dest_port', 'unknown'),
            'protocol': log_entry.get('proto', 'unknown'),
            'tool': log_entry.get('tool', 'unknown'),
            'attack_type': self._determine_attack_type(log_entry, detection_methods),
            'severity': final_severity,
            'final_confidence': final_confidence,
            'detection_methods': detection_methods,
            'method_confidence_scores': confidence_scores,
            # CHANGED: Use AI explanation instead of basic description
            'description': self._generate_ai_explanation({
                'attack_type': self._determine_attack_type(log_entry, detection_methods),
                'severity': final_severity,
                'final_confidence': final_confidence,
                'source_ip': log_entry.get('src_ip', 'unknown'),
                'target_ip': log_entry.get('dest_ip', 'unknown'),
                'protocol': log_entry.get('proto', 'unknown'),
                'detection_methods': detection_methods
            }, log_entry),
            'recommendations': self._generate_recommendations(log_entry, final_severity),
            'risk_score': self._calculate_risk_score(log_entry, final_confidence, final_severity_score),
            'timestamp_analyzed': datetime.now().isoformat()
        }
        
        # Store in detection history
        self.detection_history.append(threat_report)
        
        return threat_report
    
    def _ml_detection(self, log_entry: Dict) -> Optional[Dict]:
        """ML Model-based threat detection"""
        try:
            # Convert to CustomData format
            custom_data = CustomData(
                tool=log_entry.get('tool', 'unknown'),
                attack_category=log_entry.get('attack_type', 'unknown'),
                severity=log_entry.get('severity', 'medium'),
                protocol=log_entry.get('proto', 'tcp'),
                source_ip=log_entry.get('src_ip', 'unknown'),
                target_ip=log_entry.get('dest_ip', 'unknown'),
                target_port=log_entry.get('dest_port', 0),
                hour=datetime.now().hour,
                day_of_week=datetime.now().weekday()
            )
            
            # Get prediction
            df = custom_data.get_data_as_data_frame()
            predictions, probabilities = self.ml_pipeline.predict(df)
            
            if predictions[0] == 1 and probabilities is not None:
                confidence = probabilities[0][1]
                return {
                    'method': 'ml_model',
                    'confidence': confidence,
                    'severity': self._confidence_to_severity(confidence),
                    'details': f"ML model detected threat with {confidence:.2%} confidence"
                }
                
        except Exception as e:
            logging.error(f"ML detection failed: {e}")
        
        return None
    
    def _rule_based_detection(self, log_entry: Dict) -> Optional[Dict]:
        """Rule-based threat detection"""
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
        src_ip = log_entry.get('src_ip', '')
        if src_ip in self.known_malicious_ips:
            detection_results.append({
                'method': 'rule_based',
                'confidence': 0.95,
                'severity': 'critical',
                'pattern_matched': 'known_malicious_ip',
                'details': f"Source IP {src_ip} is in known malicious IP list"
            })
        
        # Check for suspicious ports
        target_port = log_entry.get('dest_port', 0)
        if target_port in self.suspicious_ports:
            detection_results.append({
                'method': 'rule_based', 
                'confidence': 0.70,
                'severity': 'medium',
                'pattern_matched': 'suspicious_port',
                'details': f"Target port {target_port} is commonly attacked"
            })
        
        if detection_results:
            # Return the highest confidence detection
            return max(detection_results, key=lambda x: x['confidence'])
        
        return None
    
    def _behavioral_analysis(self, log_entry: Dict) -> Optional[Dict]:
        """Behavioral analysis for anomaly detection"""
        src_ip = log_entry.get('src_ip', '')
        
        # Initialize behavioral baseline for IP
        if src_ip not in self.behavioral_baseline:
            self.behavioral_baseline[src_ip] = {
                'first_seen': datetime.now(),
                'request_count': 0,
                'unique_targets': set(),
                'ports_accessed': set(),
                'last_activity': datetime.now()
            }
        
        baseline = self.behavioral_baseline[src_ip]
        baseline['request_count'] += 1
        baseline['unique_targets'].add(log_entry.get('dest_ip', ''))
        baseline['ports_accessed'].add(log_entry.get('dest_port', 0))
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
        """Threat intelligence correlation"""
        intel_matches = []
        
        src_ip = log_entry.get('src_ip', '')
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
        """Correlate related threats to identify attack campaigns"""
        if not threats:
            return []
        
        # Group by source IP
        ip_groups = {}
        for threat in threats:
            src_ip = threat['source_ip']
            if src_ip not in ip_groups:
                ip_groups[src_ip] = []
            ip_groups[src_ip].append(threat)
        
        correlated_threats = []
        
        for src_ip, ip_threats in ip_groups.items():
            if len(ip_threats) > 1:
                # Multiple threats from same IP - likely coordinated attack
                campaign_threat = self._create_campaign_threat(ip_threats)
                correlated_threats.append(campaign_threat)
            else:
                correlated_threats.extend(ip_threats)
        
        return correlated_threats
    
    def _create_campaign_threat(self, threats: List[Dict]) -> Dict:
        """Create a combined threat report for attack campaigns"""
        attack_types = list(set([t['attack_type'] for t in threats]))
        max_severity = max([self._severity_to_score(t['severity']) for t in threats])
        avg_confidence = np.mean([t['final_confidence'] for t in threats])
        
        campaign_report = {
            'timestamp': threats[0]['timestamp'],
            'source_ip': threats[0]['source_ip'],
            'target_ip': 'Multiple Targets',
            'attack_type': f"Coordinated Attack: {', '.join(attack_types)}",
            'severity': self._score_to_severity(max_severity),
            'final_confidence': avg_confidence,
            'detection_methods': list(set([m for t in threats for m in t['detection_methods']])),
            'recommendations': [
                "Immediate IP blocking recommended",
                "Investigate for compromised system",
                "Review all traffic from this source IP"
            ],
            'risk_score': 95,  # Very high for coordinated attacks
            'campaign_details': {
                'total_techniques': len(threats),
                'techniques_used': attack_types,
                'time_range': f"{min(t['timestamp'] for t in threats)} to {max(t['timestamp'] for t in threats)}"
            },
            'timestamp_analyzed': datetime.now().isoformat()
        }
        
        # Add AI explanation for campaign
        try:
            from src.agents.explanation_agent import SimpleExplanationAgent
            explanation_agent = SimpleExplanationAgent()
            
            campaign_prompt = f"""
            Explain this coordinated cyber attack campaign:
            
            Campaign Details:
            - Source IP: {campaign_report['source_ip']}
            - Attack Types: {', '.join(attack_types)}
            - Severity: {campaign_report['severity']}
            - Number of Techniques: {len(threats)}
            - Time Range: {campaign_report['campaign_details']['time_range']}
            
            Explain why this appears to be a coordinated attack and the potential risks involved.
            """
            
            campaign_report['description'] = explanation_agent.ask(campaign_prompt)
        except Exception as e:
            campaign_report['description'] = f"Coordinated attack campaign from {threats[0]['source_ip']} involving {len(threats)} different techniques"
        
        return campaign_report
    
    # Utility methods
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
        
        if 'nmap' in tool.lower():
            return 'Port Scanning'
        elif 'hydra' in tool.lower():
            return 'Brute Force Attack'
        elif 'hping' in tool.lower():
            return 'DoS Attack'
        elif any(web_tool in tool.lower() for web_tool in ['nikto', 'gobuster']):
            return 'Web Application Scanning'
        else:
            return 'Suspicious Activity'
    
    def _generate_threat_description(self, log_entry: Dict, severity: str) -> str:
        """Generate human-readable threat description (fallback method)"""
        base_descriptions = {
            'critical': f"CRITICAL: Immediate action required. {log_entry.get('description', 'Critical security threat detected')}",
            'high': f"HIGH: Urgent investigation needed. {log_entry.get('description', 'High-severity security event')}",
            'medium': f"MEDIUM: Security investigation recommended. {log_entry.get('description', 'Suspicious activity detected')}",
            'low': f"LOW: Monitor and review. {log_entry.get('description', 'Potential security concern')}"
        }
        return base_descriptions.get(severity, 'Security event detected')
    
    def _generate_recommendations(self, log_entry: Dict, severity: str) -> List[str]:
        """Generate actionable recommendations based on threat severity"""
        base_recommendations = {
            'critical': [
                "Immediately block source IP",
                "Isolate affected systems",
                "Initiate incident response procedure",
                "Notify security team immediately"
            ],
            'high': [
                "Block source IP at firewall",
                "Investigate affected systems",
                "Review logs for related activity",
                "Update security controls"
            ],
            'medium': [
                "Monitor source IP for further activity",
                "Review system configurations",
                "Consider IP blocking if pattern continues",
                "Document for security review"
            ],
            'low': [
                "Continue monitoring",
                "Review in next security assessment",
                "Document for trend analysis"
            ]
        }
        return base_recommendations.get(severity, ["Monitor and document"])
    
    def _calculate_risk_score(self, log_entry: Dict, confidence: float, severity_score: int) -> int:
        """Calculate comprehensive risk score (0-100)"""
        base_score = confidence * 100 * 0.6  # 60% weight to confidence
        severity_multiplier = severity_score * 10  # 40% weight to severity
        return min(100, int(base_score + severity_multiplier))
    
    def get_detection_stats(self) -> Dict:
        """Get detection statistics"""
        if not self.detection_history:
            return {}
        
        threats_by_severity = {}
        threats_by_type = {}
        
        for threat in self.detection_history:
            severity = threat['severity']
            attack_type = threat['attack_type']
            
            threats_by_severity[severity] = threats_by_severity.get(severity, 0) + 1
            threats_by_type[attack_type] = threats_by_type.get(attack_type, 0) + 1
        
        return {
            'total_threats': len(self.detection_history),
            'threats_by_severity': threats_by_severity,
            'threats_by_type': threats_by_type,
            'average_confidence': np.mean([t['final_confidence'] for t in self.detection_history]),
            'time_period': f"{self.detection_history[0]['timestamp']} to {self.detection_history[-1]['timestamp']}"
        }

# Simplified interface for your app
class DetectionAgent:
    """Simplified interface for the Streamlit app"""
    
    def __init__(self):
        self.advanced_agent = AdvancedDetectionAgent()
    
    def analyze_logs(self, uploaded_file):
        """Simple interface for log analysis"""
        try:
            # Read and parse uploaded file
            content = uploaded_file.getvalue().decode('utf-8')
            log_data = []
            
            for line in content.split('\n'):
                if line.strip():
                    try:
                        log_entry = json.loads(line)
                        log_data.append(log_entry)
                    except json.JSONDecodeError:
                        continue
            
            # Use advanced detection
            threats = self.advanced_agent.analyze_logs_comprehensive(log_data)
            return threats
            
        except Exception as e:
            logging.error(f"Log analysis failed: {e}")
            return []
    
    def analyze_sample_attacks(self):
        """Analyze sample attack data for demo"""
        # Load demo data
        demo_file = "demo/sample_logs/demo_attacks.json"
        log_data = []
        
        if os.path.exists(demo_file):
            with open(demo_file, 'r') as f:
                for line in f:
                    if line.strip():
                        try:
                            log_entry = json.loads(line)
                            log_data.append(log_entry)
                        except json.JSONDecodeError:
                            continue
        
        # Use advanced detection
        threats = self.advanced_agent.analyze_logs_comprehensive(log_data)
        return threats
    
    def get_detection_statistics(self):
        """Get detection statistics"""
        return self.advanced_agent.get_detection_stats()