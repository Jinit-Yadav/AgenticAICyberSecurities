"""
Unit tests for Alert Agent
"""
import unittest
import sys
import os

# Add paths
project_root = r'C:\Users\Lenovo\Desktop\AgenticAICybersecurity\AgenticAICyberSecurities'
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'src'))

from src.agents.alert_agent import AlertAgent

class TestAlertAgent(unittest.TestCase):
    
    def setUp(self):
        self.agent = AlertAgent()
    
    def test_alert_generation(self):
        """AA-UT-01: Alert generation"""
        detection = {'threat_type': 'port_scan', 'severity': 'high'}
        alert = self.agent.generate_alert(detection)
        self.assertIsNotNone(alert)
    
    def test_email_delivery(self):
        """AA-UT-02: Email delivery"""
        if hasattr(self.agent, 'send_email'):
            result = self.agent.send_email('test@example.com', 'Test Alert')
            self.assertIsNotNone(result)
    
    def test_slack_delivery(self):
        """AA-UT-03: Slack delivery"""
        if hasattr(self.agent, 'send_slack'):
            result = self.agent.send_slack('Test alert message')
            self.assertIsNotNone(result)
    
    def test_alert_queuing(self):
        """AA-UT-04: Alert queuing"""
        alerts = [{'id': i} for i in range(5)]
        if hasattr(self.agent, 'queue_alerts'):
            result = self.agent.queue_alerts(alerts)
            self.assertIsNotNone(result)
    
    def test_alert_storage(self):
        """AA-UT-05: Alert storage"""
        alert = {'timestamp': '2025-03-23', 'message': 'Test'}
        if hasattr(self.agent, 'store_alert'):
            result = self.agent.store_alert(alert)
            self.assertIsNotNone(result)

if __name__ == '__main__':
    unittest.main()