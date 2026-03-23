"""
Suricata Integration for Agentic AI System
Monitors Suricata eve.json file and sends alerts to your Flask app
"""

import json
import time
import os
import requests
import threading
from datetime import datetime
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SuricataMonitor:
    def __init__(self, eve_file_path='C:/Program Files/Suricata/eve.json', 
                 flask_url='http://localhost:5000'):
        self.eve_file_path = eve_file_path
        self.flask_url = flask_url
        self.session = requests.Session()
        self.last_position = 0
        self.running = False
        self.attack_counter = 0
        
    def login_to_flask(self):
        """Login to Flask app to get session cookie"""
        try:
            # First try to login
            login_data = {
                'username': 'testuser',
                'password': 'testpass123'
            }
            
            # Get CSRF token first
            login_page = self.session.get(f'{self.flask_url}/login')
            import re
            csrf_match = re.search(r'name="csrf_token"\s+value="([^"]+)"', login_page.text)
            if csrf_match:
                login_data['csrf_token'] = csrf_match.group(1)
            
            response = self.session.post(f'{self.flask_url}/login', data=login_data)
            if response.status_code == 200 or 'dashboard' in response.url:
                logger.info("✅ Logged into Flask app")
                return True
            else:
                logger.warning("⚠️ Could not login to Flask app")
                return False
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False
    
    def convert_suricata_to_flask_format(self, alert):
        """Convert Suricata alert to format expected by Flask app"""
        
        # Extract alert details
        alert_info = alert.get('alert', {})
        src_ip = alert.get('src_ip', 'unknown')
        dest_ip = alert.get('dest_ip', 'unknown')
        dest_port = alert.get('dest_port', 0)
        proto = alert.get('proto', 'tcp')
        
        # Map Suricata signatures to attack types
        signature = alert_info.get('signature', '').lower()
        
        attack_mapping = {
            'port scan': 'port_scan',
            'nmap': 'port_scan',
            'syn scan': 'port_scan',
            'brute force': 'bruteforce',
            'hydra': 'bruteforce',
            'dos': 'dos',
            'ddos': 'dos',
            'syn flood': 'dos',
            'sql injection': 'sql_injection',
            'exploit': 'exploitation',
            'malware': 'malware',
            'trojan': 'malware'
        }
        
        attack_type = 'unknown'
        for key, value in attack_mapping.items():
            if key in signature:
                attack_type = value
                break
        
        # Determine severity based on alert severity
        severity_map = {1: 'critical', 2: 'high', 3: 'medium'}
        severity = severity_map.get(alert_info.get('severity', 3), 'medium')
        
        # Create detection data
        detection_data = {
            'source_ip': src_ip,
            'target_ip': dest_ip,
            'target_port': dest_port,
            'protocol': proto,
            'tool': 'suricata',
            'attack_category': attack_type,
            'severity': severity,
            'description': alert_info.get('signature', 'Suricata alert'),
            'suricata_alert_id': alert_info.get('signature_id', 0),
            'suricata_gid': alert_info.get('gid', 0),
            'suricata_rev': alert_info.get('rev', 0)
        }
        
        return detection_data
    
    def send_to_flask(self, detection_data):
        """Send detection to Flask app via API or direct form"""
        try:
            # Try API endpoint first
            response = self.session.post(f'{self.flask_url}/api/detect', 
                                         json=detection_data)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('threat_detected'):
                    logger.info(f"🚨 ATTACK DETECTED: {detection_data['attack_category']} from {detection_data['source_ip']}")
                    return True
                else:
                    logger.debug(f"Alert processed, no threat: {detection_data['attack_category']}")
                    return False
            else:
                # Fallback to form submission
                logger.debug(f"API failed ({response.status_code}), trying form...")
                
                # Get CSRF token for form
                csrf_token = self._get_csrf_token()
                if csrf_token:
                    detection_data['csrf_token'] = csrf_token
                
                response = self.session.post(f'{self.flask_url}/detect-threat', 
                                            data=detection_data)
                
                if response.status_code == 200:
                    logger.info(f"✅ Detection sent via form: {detection_data['attack_category']}")
                    return True
                else:
                    logger.error(f"Form submission failed: {response.status_code}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error sending to Flask: {e}")
            return False
    
    def _get_csrf_token(self):
        """Get CSRF token from Flask app"""
        try:
            response = self.session.get(f'{self.flask_url}/detect-threat')
            import re
            match = re.search(r'name="csrf_token"\s+value="([^"]+)"', response.text)
            if match:
                return match.group(1)
        except:
            pass
        return None
    
    def monitor_eve_file(self):
        """Monitor Suricata eve.json file for new alerts"""
        if not os.path.exists(self.eve_file_path):
            logger.warning(f"EVE file not found: {self.eve_file_path}")
            return
        
        logger.info(f"📡 Monitoring Suricata alerts from: {self.eve_file_path}")
        
        with open(self.eve_file_path, 'r') as f:
            # Seek to end of file
            f.seek(0, 2)
            
            while self.running:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                
                try:
                    alert_data = json.loads(line.strip())
                    
                    # Check if this is an alert
                    if alert_data.get('event_type') == 'alert':
                        detection_data = self.convert_suricata_to_flask_format(alert_data)
                        self.attack_counter += 1
                        logger.info(f"🎯 Suricata Alert #{self.attack_counter}: {detection_data['description']}")
                        
                        # Send to Flask
                        self.send_to_flask(detection_data)
                        
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    logger.error(f"Error processing line: {e}")
    
    def start(self):
        """Start monitoring"""
        if not self.login_to_flask():
            logger.error("Failed to login to Flask. Check credentials.")
            return
        
        self.running = True
        logger.info("🚀 Suricata Monitor Started")
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_eve_file)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        logger.info("🛑 Suricata Monitor Stopped")
        logger.info(f"📊 Total alerts processed: {self.attack_counter}")

if __name__ == "__main__":
    # Create monitor
    monitor = SuricataMonitor(
        eve_file_path='C:/Program Files/Suricata/eve.json',  # Update this path
        flask_url='http://localhost:5000'
    )
    
    # Start monitoring
    monitor.start()
    