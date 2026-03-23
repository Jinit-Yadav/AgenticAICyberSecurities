"""
Display and parse Suricata alerts in real-time
"""

import json
import os
import time
from datetime import datetime

def read_alerts():
    """Read and parse Suricata alerts"""
    log_path = r"C:\Users\Lenovo\Desktop\AgenticAICybersecurity\AgenticAICyberSecurities\suricata_logs\fast.log"
    
    if not os.path.exists(log_path):
        print(f"❌ Log file not found: {log_path}")
        print("Make sure Suricata is running and generating logs")
        return []
    
    with open(log_path, 'r') as f:
        lines = f.readlines()
    
    return lines

def parse_eve_alerts():
    """Parse detailed alerts from eve.json"""
    log_path = r"C:\Users\Lenovo\Desktop\AgenticAICybersecurity\AgenticAICyberSecurities\suricata_logs\eve.json"
    
    if not os.path.exists(log_path):
        return []
    
    alerts = []
    with open(log_path, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    data = json.loads(line)
                    if data.get('event_type') == 'alert':
                        alerts.append(data)
                except:
                    pass
    
    return alerts

def main():
    print("="*60)
    print("SURICATA ALERT MONITOR")
    print("="*60)
    print("Press Ctrl+C to stop\n")
    
    last_size = 0
    log_path = r"C:\Users\Lenovo\Desktop\AgenticAICybersecurity\AgenticAICyberSecurities\suricata_logs\fast.log"
    
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
                            if line:
                                print(f"\n🚨 ALERT DETECTED!")
                                print(f"   {line}")
                                
                                # Parse the alert
                                if "PORT SCAN" in line:
                                    print("   📡 Type: Port Scan Attack")
                                    print("   ⚠️  Action: Block source IP")
                                elif "BRUTE FORCE" in line:
                                    print("   🔐 Type: Brute Force Attack")
                                    print("   ⚠️  Action: Enable rate limiting")
                                elif "SYN FLOOD" in line:
                                    print("   🌊 Type: DoS/SYN Flood Attack")
                                    print("   ⚠️  Action: Activate DDoS protection")
                                elif "WEB SCAN" in line:
                                    print("   🌐 Type: Web Application Scan")
                                    print("   ⚠️  Action: Enable WAF rules")
                        
                        last_size = current_size
            
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n✅ Monitoring stopped")
        
        # Show summary
        eve_alerts = parse_eve_alerts()
        if eve_alerts:
            print(f"\n📊 Summary: {len(eve_alerts)} alerts detected")
            for alert in eve_alerts[:5]:
                print(f"   - {alert.get('alert', {}).get('signature', 'Unknown')}")

if __name__ == "__main__":
    main()