"""
Test the Response Agent's IP blocking capability
"""

import requests
import time
import platform
import subprocess

def test_ip_blocking():
    """Test if the system can block an IP"""
    
    print("="*60)
    print("TESTING IP BLOCKING FUNCTIONALITY")
    print("="*60)
    
    # Test IP (use a safe one - not your actual IP)
    test_ip = "203.0.113.5"  # TEST-NET-3 (safe for documentation)
    
    # 1. Check current firewall rules
    system = platform.system()
    print(f"\n[1] System: {system}")
    
    if system == "Linux":
        result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True)
        print(f"Current iptables rules (INPUT chain):")
        for line in result.stdout.split('\n'):
            if 'Chain INPUT' in line or 'DROP' in line:
                print(f"    {line}")
    
    # 2. Send detection that should trigger blocking
    print(f"\n[2] Sending detection for IP {test_ip}...")
    
    detection_data = {
        'source_ip': test_ip,
        'target_ip': '192.168.1.1',
        'target_port': 22,
        'protocol': 'tcp',
        'tool': 'hydra',
        'attack_category': 'bruteforce',
        'severity': 'critical',
        'description': 'Test brute force attack'
    }
    
    # You need to be logged in first
    session = requests.Session()
    
    # Login first (if your app is running)
    try:
        login_data = {'username': 'testuser', 'password': 'testpass123'}
        session.post('http://localhost:5000/login', data=login_data)
        
        # Send detection
        response = session.post('http://localhost:5000/detect-threat', data=detection_data)
        
        if response.status_code == 200:
            print("    ✅ Detection sent successfully")
        else:
            print(f"    ❌ Detection failed: {response.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("    ⚠️  Could not connect to Flask app. Make sure it's running.")
        print("    Start it with: python application.py")
    
    # 3. Check if IP was blocked
    print(f"\n[3] Checking if {test_ip} was blocked...")
    
    if system == "Linux":
        result = subprocess.run(['iptables', '-L', '-n'], capture_output=True, text=True)
        if test_ip in result.stdout:
            print(f"    ✅ IP {test_ip} is blocked in iptables")
        else:
            print(f"    ❌ IP {test_ip} not found in iptables")
    
    # 4. Check database
    print(f"\n[4] Checking database for blocked IP...")
    try:
        import sqlite3
        conn = sqlite3.connect('responses.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM blocked_ips WHERE ip_address = ?", (test_ip,))
        rows = cursor.fetchall()
        if rows:
            print(f"    ✅ IP found in blocked_ips table")
            for row in rows:
                print(f"       Reason: {row[2]}")
        else:
            print(f"    ❌ IP not found in database")
        conn.close()
    except Exception as e:
        print(f"    ⚠️  Could not check database: {e}")

if __name__ == "__main__":
    test_ip_blocking()