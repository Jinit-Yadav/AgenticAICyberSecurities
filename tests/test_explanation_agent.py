"""
Unit tests for Explanation Agent
"""
import unittest
import sys
import os

# Add paths
project_root = r'C:\Users\Lenovo\Desktop\AgenticAICybersecurity\AgenticAICyberSecurities'
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'src'))

from src.agents.explanation_agent import ExplanationAgent

class TestExplanationAgent(unittest.TestCase):
    
    def setUp(self):
        self.agent = ExplanationAgent()
    
    def test_threat_info_extraction(self):
        """EA-UT-01: Threat info extraction"""
        detection_data = {
            'tool': 'nmap',
            'attack_type': 'port_scan',
            'source_ip': '192.168.1.100'
        }
        result = self.agent.extract_threat_info(detection_data)
        self.assertIsNotNone(result)
    
    def test_rag_context_retrieval(self):
        """EA-UT-02: RAG context retrieval"""
        query = "port scanning detection"
        context = self.agent.get_rag_context(query)
        self.assertIsNotNone(context)
    
    def test_expert_analysis_generation(self):
        """EA-UT-03: Expert analysis generation"""
        detection = {
            'attack_type': 'bruteforce',
            'severity': 'critical'
        }
        analysis = self.agent.generate_expert_analysis(detection)
        self.assertIsNotNone(analysis)
    
    def test_fallback_mode_operation(self):
        """EA-UT-04: Fallback mode operation"""
        # Test without API key
        analysis = self.agent.generate_fallback_explanation({})
        self.assertIsNotNone(analysis)

if __name__ == '__main__':
    unittest.main()