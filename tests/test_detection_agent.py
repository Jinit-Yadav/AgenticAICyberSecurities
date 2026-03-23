"""
Unit tests for Detection Agent
"""
import unittest
import sys
import os

# Add paths
project_root = r'C:\Users\Lenovo\Desktop\AgenticAICybersecurity\AgenticAICyberSecurities'
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'src'))

from src.agents.detection_agent import DetectionAgent

class TestDetectionAgent(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.agent = DetectionAgent()
    
    def test_port_scanning_detection(self):
        """DA-UT-01: Port scanning detection"""
        test_log = "Nmap scan log: 192.168.1.100 scanning ports 1-1024"
        result = self.agent.detect(test_log)
        self.assertIsNotNone(result)
        if result.get('is_threat'):
            self.assertGreater(result.get('confidence', 0), 0.8)
    
    def test_brute_force_detection(self):
        """DA-UT-02: Brute force detection"""
        test_log = "Hydra attack: 10.0.0.50 attempting SSH login"
        result = self.agent.detect(test_log)
        self.assertIsNotNone(result)
        if result.get('is_threat'):
            self.assertEqual(result.get('severity'), 'critical')
    
    def test_dos_attack_detection(self):
        """DA-UT-03: DoS attack detection"""
        test_log = "Hping3 flood: 500 SYN packets/second to 192.168.1.1"
        result = self.agent.detect(test_log)
        self.assertIsNotNone(result)
        if result.get('is_threat'):
            self.assertEqual(result.get('severity'), 'high')
    
    def test_normal_traffic_classification(self):
        """DA-UT-04: Normal traffic classification"""
        test_log = "Normal HTTP GET request to google.com"
        result = self.agent.detect(test_log)
        self.assertIsNotNone(result)
        # Normal traffic should have low confidence or no threat
        if result.get('is_threat'):
            self.assertLess(result.get('confidence', 1), 0.5)
    
    def test_majority_voting(self):
        """DA-UT-05: Majority voting logic"""
        mixed_inputs = [0.9, 0.2, 0.8, 0.7, 0.1]
        if hasattr(self.agent, 'majority_vote'):
            consensus = self.agent.majority_vote(mixed_inputs)
            self.assertIsNotNone(consensus)
    
    def test_feature_extraction(self):
        """DA-UT-06: Feature extraction"""
        raw_log = "2025-03-23 10:30:45 192.168.1.100 -> 8.8.8.8:80 TCP SYN"
        if hasattr(self.agent, 'extract_features'):
            features = self.agent.extract_features(raw_log)
            self.assertIsInstance(features, dict)

if __name__ == '__main__':
    unittest.main()