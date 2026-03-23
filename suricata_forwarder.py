"""
Real-time Suricata Alert Forwarder to CyberShield AI
"""
import json
import os
import time
import requests
from datetime import datetime
import sys

# Configuration
SURICATA_LOG_DIR = r"C:\Users\Lenovo\Desktop\AgenticAICybersecurity\AgenticAICyberSecurities\suricata_logs"
FLASK_URL = "http://localhost:5000"

class SuricataForwarder:
    def __init__(self):
        self.session = requests.Session()
        self.last_position = 0
        self.position_file = "suricata_position.txt"
        self.csrf_token = None
        
    def get_csrf_token(self):
        """Get CSRF token from Flask app"""
        try:
            response = self.session.get(f"{FLASK_URL}/detect-threat")
            if response.status_code == 200:
                # Look for CSRF token in response
                import re
                match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response.text)
                if match:
                    self.csrf_token = match.group(1)
                    return True
            return False
        except Exception as e:
            print(f"  Error getting CSRF token: {e}")
            return False
    
    def login(self):
        """Login to Flask app"""
        try:
            # First get CSRF token
            if not self.get_csrf_token():
                return False
            
            # Login with CSRF token
            login_data = {
                'username': 'testuser',
                'password': 'testpass123',
                'csrf_token': self.csrf_token
            }
            
            response = self.session.post(f"{FLASK_URL}/login", data=login_data)
            
            if response.status_code == 200 or response.status_code == 302:
                print("✅ Logged into CyberShield AI")
                return True
            else:
                print(f"❌ Login failed: {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Login error: {e}")
            return False
    
    def forward_alert(self, alert_data):
        """Forward alert to CyberShield AI"""
        try:
            # Prepare data for detection
            detection_data = {
                'source_ip': alert_data.get('src_ip', 'unknown'),
                'target_ip': alert_data.get('dest_ip', 'unknown'),
                'target_port': alert_data.get('dest_port', 0),
                'protocol': alert_data.get('proto', 'tcp'),
                'tool': 'suricata',
                'attack_category': self.map_alert_to_category(alert_data),
                'severity': self.map_severity(alert_data),
                'description': alert_data.get('alert', {}).get('signature', 'Unknown attack'),
                'csrf_token': self.csrf_token
            }
            
            # Forward to detection endpoint
            response = self.session.post(f"{FLASK_URL}/detect-threat", data=detection_data)
            
            if response.status_code == 200:
                print(f"  ✅ Alert forwarded: {detection_data['attack_category']}")
                return True
            else:
                print(f"  ❌ Forward failed: {response.status_code}")
                return False
                
        except Exception as e:
            print(f"  ❌ Forward error: {e}")
            return False
    
    def map_alert_to_category(self, alert):
        """Map Suricata alert to attack category"""
        signature = alert.get('alert', {}).get('signature', '').lower()
        
        if 'port scan' in signature:
            return 'port_scan'
        elif 'brute force' in signature or 'ssh' in signature:
            return 'bruteforce'
        elif 'syn flood' in signature or 'dos' in signature:
            return 'dos'
        elif 'web scan' in signature:
            return 'web_scan'
        else:
            return 'suspicious_activity'
    
    def map_severity(self, alert):
        """Map Suricata severity to CyberShield severity"""
        severity = alert.get('alert', {}).get('severity', 3)
        
        # Suricata severity: 1=high, 2=medium, 3=low
        if severity == 1:
            return 'critical'
        elif severity == 2:
            return 'high'
        else:
            return 'medium'
    
    def monitor_alerts(self):
        """Monitor Suricata eve.json for new alerts"""
        eve_file = os.path.join(SURICATA_LOG_DIR, 'eve.json')
        
        if not os.path.exists(eve_file):
            print(f"❌ Suricata log not found: {eve_file}")
            print("Make sure Suricata is running!")
            return
        
        # Load last position
        if os.path.exists(self.position_file):
            with open(self.position_file, 'r') as f:
                self.last_position = int(f.read().strip())
        
        print("="*70)
        print("SURICATA ALERT FORWARDER")
        print("="*70)
        print(f"Monitoring: {eve_file}")
        print("Forwarding alerts to CyberShield AI")
        print("Press Ctrl+C to stop")
        print("="*70)
        
        alert_count = 0
        
        try:
            while True:
                if os.path.exists(eve_file):
                    current_size = os.path.getsize(eve_file)
                    
                    if current_size > self.last_position:
                        with open(eve_file, 'r') as f:
                            f.seek(self.last_position)
                            new_lines = f.readlines()
                            self.last_position = f.tell()
                            
                            # Save position
                            with open(self.position_file, 'w') as pos_file:
                                pos_file.write(str(self.last_position))
                            
                            for line in new_lines:
                                try:
                                    alert = json.loads(line.strip())
                                    
                                    # Only process alerts
                                    if alert.get('event_type') == 'alert':
                                        alert_count += 1
                                        signature = alert.get('alert', {}).get('signature', 'Unknown')
                                        print(f"\n🚨 Alert #{alert_count}: {signature}")
                                        
                                        # Forward to CyberShield
                                        self.forward_alert(alert)
                                        
                                except json.JSONDecodeError:
                                    pass
                
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n\n✅ Forwarder stopped")
            print(f"Total alerts forwarded: {alert_count}")

def main():
    forwarder = SuricataForwarder()
    
    # Login first
    if not forwarder.login():
        print("❌ Failed to login. Please check credentials and that Flask app is running.")
        sys.exit(1)
    
    # Start monitoring
    forwarder.monitor_alerts()

if __name__ == "__main__":
    main()