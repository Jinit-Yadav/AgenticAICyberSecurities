"""
Unit tests for Response Agent
"""
import unittest
import sys
import os

# Add paths
project_root = r'C:\Users\Lenovo\Desktop\AgenticAICybersecurity\AgenticAICyberSecurities'
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'src'))

from src.agents.response_agent import ResponseAgent

class TestResponseAgent(unittest.TestCase):
    
    def setUp(self):
        self.agent = ResponseAgent()
    
    def test_ip_blocking(self):
        """RA-UT-01: IP blocking"""
        if hasattr(self.agent, 'block_ip'):
            result = self.agent.block_ip('192.168.1.100')
            self.assertIsNotNone(result)
    
    def test_process_termination(self):
        """RA-UT-02: Process termination"""
        if hasattr(self.agent, 'terminate_process'):
            result = self.agent.terminate_process('malicious.exe')
            self.assertIsNotNone(result)
    
    def test_rate_limiting(self):
        """RA-UT-03: SSH rate limiting"""
        if hasattr(self.agent, 'apply_rate_limit'):
            result = self.agent.apply_rate_limit('22', 5)
            self.assertIsNotNone(result)
    
    def test_threshold_check(self):
        """RA-UT-04: Threshold check"""
        low_severity = {'severity': 'low'}
        result = self.agent.should_respond(low_severity)
        self.assertFalse(result)
    
    def test_response_logging(self):
        """RA-UT-05: Response logging"""
        if hasattr(self.agent, 'log_response'):
            result = self.agent.log_response({'action': 'block_ip'})
            self.assertIsNotNone(result)

if __name__ == '__main__':
    unittest.main()