"""
Forward Suricata alerts to CyberShield AI Flask app
"""

import json
import os
import time
import requests
from datetime import datetime

def parse_suricata_alert(line):
    """Parse Suricata alert line into CyberShield format"""
    
    # Example: 03/23/2025-12:00:00.123456  [**] [1:1000001:1] PORT SCAN DETECTED ON LOCALHOST [**] [Classification: (null)] [Priority: 3] {TCP} 127.0.0.1:12345 -> 127.0.0.1:22
    
    alert_data = {
        'tool': 'suricata',
        'attack_type': 'unknown',
        'severity': 'medium',
        'description': line,
        'timestamp': datetime.now().isoformat()
    }
    
    # Parse based on alert type
    if "PORT SCAN" in line:
        alert_data['attack_type'] = 'port_scan'
        alert_data['severity'] = 'high'
        alert_data['description'] = 'Port scanning activity detected by Suricata'
    elif "BRUTE FORCE" in line:
        alert_data['attack_type'] = 'bruteforce'
        alert_data['severity'] = 'critical'
        alert_data['description'] = 'Brute force attack detected by Suricata'
    elif "SYN FLOOD" in line:
        alert_data['attack_type'] = 'dos'
        alert_data['severity'] = 'critical'
        alert_data['description'] = 'SYN flood attack detected by Suricata'
    elif "WEB SCAN" in line:
        alert_data['attack_type'] = 'web_scan'
        alert_data['severity'] = 'medium'
        alert_data['description'] = 'Web application scan detected by Suricata'
    
    # Extract IPs if present
    import re
    ip_pattern = r'(\d+\.\d+\.\d+\.\d+):(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+)'
    match = re.search(ip_pattern, line)
    if match:
        alert_data['source_ip'] = match.group(1)
        alert_data['source_port'] = match.group(2)
        alert_data['target_ip'] = match.group(3)
        alert_data['target_port'] = match.group(4)
    
    return alert_data

def send_to_flask(alert_data, session):
    """Send alert to CyberShield Flask app"""
    
    # Get CSRF token
    try:
        # Try to get detection page for CSRF token
        resp = session.get('http://localhost:5000/detect-threat')
        csrf_token = None
        
        # Simple extraction (you may need BeautifulSoup for proper parsing)
        if 'csrf_token' in resp.text:
            import re
            match = re.search(r'name="csrf_token"\s+value="([^"]+)"', resp.text)
            if match:
                csrf_token = match.group(1)
        
        # Prepare data
        data = {
            'source_ip': alert_data.get('source_ip', 'unknown'),
            'target_ip': alert_data.get('target_ip', 'unknown'),
            'target_port': alert_data.get('target_port', '80'),
            'protocol': 'tcp',
            'tool': alert_data['tool'],
            'attack_category': alert_data['attack_type'],
            'severity': alert_data['severity'],
            'description': alert_data['description']
        }
        
        if csrf_token:
            data['csrf_token'] = csrf_token
        
        # Send detection
        response = session.post('http://localhost:5000/detect-threat', data=data)
        
        if response.status_code == 200:
            print(f"   ✅ Alert forwarded to CyberShield")
            return True
        else:
            print(f"   ⚠️  Failed to forward: {response.status_code}")
            return False
            
    except Exception as e:
        print(f"   ❌ Error forwarding: {e}")
        return False

def monitor_suricata():
    """Monitor Suricata logs and forward to Flask"""
    
    log_path = r"C:\Users\Lenovo\Desktop\AgenticAICybersecurity\AgenticAICyberSecurities\suricata_logs\fast.log"
    
    if not os.path.exists(log_path):
        print(f"❌ Suricata log not found: {log_path}")
        print("Make sure Suricata is running!")
        return
    
    print("="*60)
    print("SURICATA TO CYBERSHIELD FORWARDER")
    print("="*60)
    print("Monitoring Suricata logs...")
    print("Forwarding alerts to CyberShield AI")
    print("="*60 + "\n")
    
    # Create session and login
    session = requests.Session()
    
    # Login to CyberShield
    print("🔐 Logging into CyberShield...")
    try:
        login_data = {'username': 'testuser', 'password': 'testpass123'}
        response = session.post('http://localhost:5000/login', data=login_data)
        if response.status_code == 200 or response.status_code == 302:
            print("   ✅ Login successful\n")
        else:
            print(f"   ⚠️  Login failed: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Connection error: {e}")
        return
    
    last_size = 0
    
    try:
        while True:
            if os.path.exists(log_path):
                current_size = os.path.getsize(log_path)
                
                if current_size > last_size:
                    with open(log_path, 'r') as f:
                        f.seek(last_size)
                        new_lines = f.readlines()
                        
                        for line in new_lines:
                            line = line.strip()
                            if line and "[**]" in line:  # Alert line
                                print(f"\n🚨 Suricata Alert Detected!")
                                print(f"   {line[:100]}...")
                                
                                # Parse and forward
                                alert_data = parse_suricata_alert(line)
                                print(f"   Type: {alert_data['attack_type']}")
                                print(f"   Severity: {alert_data['severity']}")
                                
                                send_to_flask(alert_data, session)
                        
                        last_size = current_size
            
            time.sleep(2)
            
    except KeyboardInterrupt:
        print("\n\n✅ Monitor stopped")

if __name__ == "__main__":
    monitor_suricata()