"""
Security Testing Script
"""
import requests
import time

BASE_URL = "http://localhost:5000"

def test_sql_injection():
    """SEC-01: SQL Injection test"""
    print("\n[SEC-01] Testing SQL Injection protection...")
    
    malicious_inputs = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users--"
    ]
    
    session = requests.Session()
    session.post(f"{BASE_URL}/register", data={
        'username': 'testuser',
        'email': 'test@test.com',
        'password': 'test123'
    })
    
    for malicious in malicious_inputs:
        response = session.post(f"{BASE_URL}/login", data={
            'username': malicious,
            'password': 'anything'
        })
        
        # Should not allow login with SQL injection
        if response.status_code == 200 and "dashboard" in response.url:
            print(f"   ❌ SQL Injection possible: {malicious}")
            return False
    
    print("   ✅ SQL Injection protection working")
    return True

def test_csrf_protection():
    """SEC-02: CSRF Protection test"""
    print("\n[SEC-02] Testing CSRF protection...")
    
    # Try to submit form without CSRF token
    response = requests.post(f"{BASE_URL}/detect-threat", data={
        'source_ip': '1.2.3.4',
        'attack_category': 'port_scan'
    })
    
    if response.status_code == 403:
        print("   ✅ CSRF protection working")
        return True
    else:
        print("   ❌ CSRF protection missing")
        return False

def test_rate_limiting():
    """SEC-03: Rate Limiting test"""
    print("\n[SEC-03] Testing rate limiting...")
    
    session = requests.Session()
    
    # Make many rapid requests
    success_count = 0
    rate_limited = False
    
    for i in range(150):
        response = session.get(f"{BASE_URL}/login")
        if response.status_code == 429:
            rate_limited = True
            break
        elif response.status_code == 200:
            success_count += 1
        
        time.sleep(0.01)
    
    if rate_limited:
        print(f"   ✅ Rate limiting triggered after {success_count} requests")
        return True
    else:
        print("   ❌ Rate limiting not triggered")
        return False

def test_auth_bypass():
    """SEC-04: Authentication bypass test"""
    print("\n[SEC-04] Testing authentication bypass...")
    
    protected_routes = [
        '/dashboard',
        '/detect-threat',
        '/upload-logs',
        '/real-time-dashboard',
        '/profile'
    ]
    
    for route in protected_routes:
        response = requests.get(f"{BASE_URL}{route}")
        
        if response.status_code == 200 and "login" not in response.url:
            print(f"   ❌ Auth bypass possible on {route}")
            return False
        elif response.status_code != 302 and response.status_code != 401:
            print(f"   ⚠️  Unexpected status {response.status_code} on {route}")
    
    print("   ✅ Authentication properly enforced")
    return True

def run_security_tests():
    """Run all security tests"""
    print("="*60)
    print("SECURITY TESTS")
    print("="*60)
    
    tests = [
        ("SQL Injection", test_sql_injection),
        ("CSRF Protection", test_csrf_protection),
        ("Rate Limiting", test_rate_limiting),
        ("Auth Bypass", test_auth_bypass)
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"   ❌ Test {name} error: {e}")
            results.append((name, False))
    
    # Print summary
    print("\n" + "="*60)
    print("SECURITY TEST SUMMARY")
    print("="*60)
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {name}")
    
    return all(result for _, result in results)

if __name__ == "__main__":
    success = run_security_tests()
    exit(0 if success else 1)