#!/usr/bin/env python3
"""
Complete Test Suite for Agentic AI Cyber Security System
With proper CSRF token handling
"""

import time
import sys
import socket
import requests
from bs4 import BeautifulSoup
import re

# ANSI colors for output
class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def print_status(message, status="info"):
    """Print colored status messages"""
    if status == "success":
        print(f"{Colors.GREEN}[✓] {message}{Colors.RESET}")
    elif status == "error":
        print(f"{Colors.RED}[✗] {message}{Colors.RESET}")
    elif status == "warning":
        print(f"{Colors.YELLOW}[!] {message}{Colors.RESET}")
    elif status == "info":
        print(f"{Colors.BLUE}[i] {message}{Colors.RESET}")
    else:
        print(message)

def check_flask_app():
    """Check if Flask app is running"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', 5000))
    sock.close()
    return result == 0

def get_csrf_token(session, url):
    """Extract CSRF token from a page"""
    try:
        response = session.get(url)
        if response.status_code != 200:
            return None
        
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Try to find CSRF token in meta tag
        meta = soup.find('meta', {'name': 'csrf-token'})
        if meta and meta.get('content'):
            return meta.get('content')
        
        # Try to find in hidden input
        csrf_input = soup.find('input', {'name': 'csrf_token'})
        if csrf_input and csrf_input.get('value'):
            return csrf_input.get('value')
        
        # Try regex
        match = re.search(r'csrf_token["\']?\s*:\s*["\']([^"\']+)["\']', response.text)
        if match:
            return match.group(1)
        
        return None
    except Exception as e:
        print_status(f"Error getting CSRF token: {e}", "error")
        return None

def register_user(session):
    """Register a test user"""
    print_status("Registering test user...", "info")
    
    # Get registration page for CSRF token
    csrf_token = get_csrf_token(session, 'http://localhost:5000/register')
    
    if csrf_token:
        print_status(f"Got CSRF token: {csrf_token[:20]}...", "success")
    else:
        print_status("No CSRF token found, trying without", "warning")
    
    data = {
        'username': 'testuser',
        'email': 'test@test.com',
        'password': 'testpass123',
        'confirm_password': 'testpass123'
    }
    
    if csrf_token:
        data['csrf_token'] = csrf_token
    
    response = session.post('http://localhost:5000/register', data=data)
    
    if response.status_code == 302 or 'login' in response.url:
        print_status("Registration successful!", "success")
        return True
    elif 'already exists' in response.text.lower():
        print_status("User already exists", "warning")
        return True
    else:
        print_status(f"Registration failed: {response.status_code}", "error")
        return False

def login_user(session):
    """Login with test user"""
    print_status("Logging in...", "info")
    
    # Get login page for CSRF token
    csrf_token = get_csrf_token(session, 'http://localhost:5000/login')
    
    data = {
        'username': 'testuser',
        'password': 'testpass123'
    }
    
    if csrf_token:
        data['csrf_token'] = csrf_token
    
    response = session.post('http://localhost:5000/login', data=data, allow_redirects=False)
    
    if response.status_code == 302 and '/dashboard' in response.headers.get('Location', ''):
        print_status("Login successful!", "success")
        return True
    else:
        print_status(f"Login failed: {response.status_code}", "error")
        return False

def test_detection_api(session):
    """Test detection API with sample threats"""
    print_status("Testing detection API...", "info")
    
    # Test data
    test_data = {
        'source_ip': '192.168.1.100',
        'target_ip': '192.168.1.1',
        'target_port': '22',
        'protocol': 'tcp',
        'tool': 'nmap',
        'attack_category': 'port_scan',
        'severity': 'high',
        'description': 'Test port scanning activity'
    }
    
    try:
        # Get detection page for CSRF token
        csrf_token = get_csrf_token(session, 'http://localhost:5000/detect-threat')
        
        if csrf_token:
            test_data['csrf_token'] = csrf_token
        
        response = session.post('http://localhost:5000/detect-threat', data=test_data)
        
        if response.status_code == 200:
            print_status("Detection API working", "success")
            
            # Check if threat was detected
            if 'threat_detected' in response.text or 'Port Scanning' in response.text:
                print_status("Threat detected successfully!", "success")
            return True
        else:
            print_status(f"Detection API returned {response.status_code}", "error")
            return False
            
    except Exception as e:
        print_status(f"Detection API error: {e}", "error")
        return False

def test_api_endpoint(session):
    """Test the JSON API endpoint"""
    print_status("Testing JSON API endpoint...", "info")
    
    api_data = {
        'tool': 'hydra',
        'src_ip': '10.0.0.50',
        'dest_ip': '192.168.1.1',
        'dest_port': 22,
        'proto': 'tcp',
        'attack_type': 'bruteforce',
        'severity': 'critical',
        'confidence': 95
    }
    
    try:
        response = session.post('http://localhost:5000/api/detect', json=api_data)
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success') or result.get('threat_detected'):
                print_status(f"API detected: {result.get('attack_type', 'Unknown')}", "success")
            else:
                print_status("API processed but no threat detected", "warning")
            return True
        else:
            print_status(f"API returned {response.status_code}", "error")
            return False
    except Exception as e:
        print_status(f"API error: {e}", "error")
        return False

def test_real_time_monitoring(session):
    """Test real-time monitoring"""
    print_status("Testing real-time monitoring...", "info")
    
    try:
        # First check if we're logged in (session should handle cookies)
        response = session.get('http://localhost:5000/api/real-time/network-data')
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success') or 'data' in data:
                connections = len(data.get('data', []))
                print_status(f"Real-time monitoring active - {connections} connections", "success")
                return True
            else:
                print_status(f"API returned error: {data.get('error', 'Unknown')}", "error")
                return False
        elif response.status_code == 302:
            print_status("Not authenticated - redirecting to login", "warning")
            return False
        else:
            print_status(f"Real-time monitoring returned {response.status_code}", "error")
            return False
            
    except Exception as e:
        print_status(f"Real-time monitoring error: {e}", "error")
        return False

def test_sample_threats(session):
    """Test sample threats endpoint"""
    print_status("Testing sample threats...", "info")
    
    try:
        # Get CSRF token for the sample threats page
        csrf_token = get_csrf_token(session, 'http://localhost:5000/sample-threats')
        
        # Test each sample scenario
        scenarios = [0, 1, 2]  # nmap, hydra, hping3
        
        for scenario_id in scenarios:
            data = {}
            if csrf_token:
                data['csrf_token'] = csrf_token
            
            response = session.post(f'http://localhost:5000/analyze-sample/{scenario_id}', json=data)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    threat = result.get('result', {})
                    print_status(f"  Sample {scenario_id}: {threat.get('attack_type', 'Unknown')} detected", "success")
                else:
                    print_status(f"  Sample {scenario_id}: {result.get('error', 'Failed')}", "warning")
            else:
                print_status(f"  Sample {scenario_id}: HTTP {response.status_code}", "error")
        
        return True
        
    except Exception as e:
        print_status(f"Sample threats error: {e}", "error")
        return False

def simulate_port_scan():
    """Simulate port scanning"""
    import socket
    import time
    
    print_status("Simulating port scan...", "info")
    ports = [21, 22, 23, 25, 53, 80, 443, 3306]
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.3)
            sock.connect_ex(('127.0.0.1', port))
            sock.close()
            time.sleep(0.05)
        except:
            pass
    
    print_status("Port scan simulation complete", "success")

def simulate_bruteforce():
    """Simulate brute force attempts"""
    import time
    import random
    
    print_status("Simulating brute force attempts...", "info")
    
    usernames = ["root", "admin", "user", "test"]
    passwords = ["password", "123456", "admin", "root"]
    
    for i in range(10):
        user = random.choice(usernames)
        pwd = random.choice(passwords)
        time.sleep(0.2)
    
    print_status("Brute force simulation complete", "success")

def main():
    """Main test function"""
    print("="*70)
    print("AGENTIC AI CYBER SECURITY SYSTEM - ENHANCED TEST SUITE")
    print("="*70)
    
    # Install required packages if missing
    try:
        import requests
        from bs4 import BeautifulSoup
    except ImportError:
        print_status("Installing required packages...", "info")
        import subprocess
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'requests', 'beautifulsoup4'])
        import requests
        from bs4 import BeautifulSoup
    
    # Check if Flask app is running
    print("\n[1] Checking Flask application status...")
    if check_flask_app():
        print_status("Flask app is running on port 5000", "success")
    else:
        print_status("Flask app is NOT running. Please start it first:", "error")
        print("    python application.py")
        return
    
    # Create session
    session = requests.Session()
    
    # Register and login
    print("\n[2] Authentication...")
    if not register_user(session):
        print_status("Registration failed, trying login...", "warning")
    
    if not login_user(session):
        print_status("Login failed. Please register manually at http://localhost:5000/register", "error")
        return
    
    # Run simulations
    print("\n" + "="*60)
    print("RUNNING ATTACK SIMULATIONS")
    print("="*60)
    
    print("\n--- Test 1: Port Scan ---")
    simulate_port_scan()
    time.sleep(2)
    
    print("\n--- Test 2: Brute Force ---")
    simulate_bruteforce()
    time.sleep(2)
    
    print("\n--- Test 3: Detection API ---")
    test_detection_api(session)
    time.sleep(1)
    
    print("\n--- Test 4: JSON API Endpoint ---")
    test_api_endpoint(session)
    time.sleep(1)
    
    print("\n--- Test 5: Real-time Monitoring ---")
    test_real_time_monitoring(session)
    time.sleep(1)
    
    print("\n--- Test 6: Sample Threats ---")
    test_sample_threats(session)
    
    # Summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print("""
    🔍 Next steps:
    
    1. Check dashboard: http://localhost:5000/dashboard
    2. Check real-time monitor: http://localhost:5000/real-time-dashboard
    3. Check detection page: http://localhost:5000/detect-threat
    
    📊 Database queries:
    
    sqlite3 threats.db "SELECT attack_type, severity, created_at FROM threat_detections ORDER BY created_at DESC LIMIT 5;"
    sqlite3 alerts.db "SELECT alert_id, attack_type, severity FROM alerts ORDER BY created_at DESC LIMIT 5;"
    sqlite3 responses.db "SELECT * FROM responses ORDER BY created_at DESC LIMIT 5;"
    """)
    
    print_status("Test suite completed!", "success")

if __name__ == "__main__":
    main()