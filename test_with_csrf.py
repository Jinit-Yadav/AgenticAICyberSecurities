"""
Test script that properly handles CSRF tokens
"""

import requests
from bs4 import BeautifulSoup
import re

def get_csrf_token(session, url):
    """Extract CSRF token from a page"""
    response = session.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Try to find CSRF token in meta tag
    meta = soup.find('meta', {'name': 'csrf-token'})
    if meta:
        return meta.get('content')
    
    # Try to find in input field
    csrf_input = soup.find('input', {'name': 'csrf_token'})
    if csrf_input:
        return csrf_input.get('value')
    
    # Try to find in form
    form = soup.find('form')
    if form:
        csrf_input = form.find('input', {'name': 'csrf_token'})
        if csrf_input:
            return csrf_input.get('value')
    
    return None

def register_user():
    """Register a new user"""
    session = requests.Session()
    
    print("📝 Getting registration page...")
    csrf_token = get_csrf_token(session, 'http://localhost:5000/register')
    
    if csrf_token:
        print(f"   ✅ CSRF token obtained: {csrf_token[:20]}...")
    else:
        print("   ⚠️  No CSRF token found, trying without...")
    
    data = {
        'username': 'testuser',
        'email': 'test@test.com',
        'password': 'testpass123',
        'confirm_password': 'testpass123'
    }
    
    if csrf_token:
        data['csrf_token'] = csrf_token
    
    print("📝 Submitting registration...")
    response = session.post('http://localhost:5000/register', data=data)
    
    if response.status_code == 302 or 'login' in response.url:
        print("   ✅ Registration successful!")
        return session
    else:
        print(f"   ❌ Registration failed: {response.status_code}")
        return None

def login_user(session=None):
    """Login with existing user"""
    if session is None:
        session = requests.Session()
    
    print("🔐 Getting login page...")
    csrf_token = get_csrf_token(session, 'http://localhost:5000/login')
    
    data = {
        'username': 'testuser',
        'password': 'testpass123'
    }
    
    if csrf_token:
        data['csrf_token'] = csrf_token
    
    print("🔐 Submitting login...")
    response = session.post('http://localhost:5000/login', data=data)
    
    if 'dashboard' in response.url or response.status_code == 302:
        print("   ✅ Login successful!")
        return session
    else:
        print("   ❌ Login failed")
        return None

def test_detection(session):
    """Test threat detection"""
    print("\n🎯 Testing threat detection...")
    
    # Get detection page for CSRF token
    csrf_token = get_csrf_token(session, 'http://localhost:5000/detect-threat')
    
    data = {
        'source_ip': '192.168.1.100',
        'target_ip': '192.168.1.1',
        'target_port': '22',
        'protocol': 'tcp',
        'tool': 'nmap',
        'attack_category': 'port_scan',
        'severity': 'high',
        'description': 'Test port scanning activity'
    }
    
    if csrf_token:
        data['csrf_token'] = csrf_token
    
    response = session.post('http://localhost:5000/detect-threat', data=data)
    
    if response.status_code == 200:
        print("   ✅ Detection request successful!")
        
        # Check if threat was detected
        if 'Port Scanning' in response.text or 'threat' in response.text.lower():
            print("   ✅ System detected the threat!")
        else:
            print("   ⚠️  Threat may not have been detected")
    else:
        print(f"   ❌ Detection failed: {response.status_code}")

def test_api_detect(session):
    """Test API detection endpoint"""
    print("\n🔌 Testing API detection...")
    
    # API endpoint doesn't require CSRF
    detection_data = {
        'tool': 'hydra',
        'src_ip': '10.0.0.50',
        'dest_ip': '192.168.1.1',
        'dest_port': 22,
        'proto': 'tcp',
        'attack_type': 'bruteforce',
        'severity': 'critical',
        'confidence': 95,
        'risk_score': 92
    }
    
    response = session.post('http://localhost:5000/api/detect', json=detection_data)
    
    if response.status_code == 200:
        result = response.json()
        if result.get('threat_detected'):
            print(f"   ✅ API detected threat: {result.get('attack_type')} (Confidence: {result.get('confidence')}%)")
        else:
            print("   ⚠️  API did not detect threat")
    else:
        print(f"   ❌ API error: {response.status_code}")

def check_dashboard(session):
    """Check if dashboard loads"""
    print("\n📊 Checking dashboard...")
    
    response = session.get('http://localhost:5000/dashboard')
    
    if response.status_code == 200:
        print("   ✅ Dashboard accessible")
        
        # Check for threat data
        if 'threats' in response.text.lower() or 'detection' in response.text.lower():
            print("   ✅ Dashboard shows threat data")
    else:
        print(f"   ❌ Dashboard error: {response.status_code}")

def main():
    print("="*60)
    print("AGENTIC AI SYSTEM - CSRF-FRIENDLY TEST")
    print("="*60)
    
    # Install BeautifulSoup if needed
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        print("📦 Installing beautifulsoup4...")
        import subprocess
        subprocess.check_call(['pip', 'install', 'beautifulsoup4'])
        from bs4 import BeautifulSoup
    
    # Try to register (may fail if user exists)
    session = register_user()
    
    # If registration failed, try to login
    if not session:
        print("\n⚠️  Registration may have failed (user might already exist)")
        print("   Trying to login instead...")
        session = login_user()
    
    if session:
        print("\n" + "="*60)
        print("RUNNING TESTS")
        print("="*60)
        
        # Run tests
        test_detection(session)
        test_api_detect(session)
        check_dashboard(session)
        
        print("\n" + "="*60)
        print("TEST COMPLETE")
        print("="*60)
        print("\n💡 Next steps:")
        print("   1. Open browser: http://localhost:5000/dashboard")
        print("   2. Login with: testuser / testpass123")
        print("   3. Check real-time monitoring: http://localhost:5000/real-time-dashboard")
    else:
        print("\n❌ Could not register or login")
        print("\n💡 Alternative: Create user manually:")
        print("   1. Open browser: http://localhost:5000/register")
        print("   2. Fill the form (handles CSRF automatically)")

if __name__ == "__main__":
    main()