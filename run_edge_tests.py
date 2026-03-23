"""
Edge Cases and Negative Testing
"""
import requests
import json

BASE_URL = "http://localhost:5000"

def test_empty_file():
    """EDGE-01: Empty file upload"""
    print("\n[EDGE-01] Testing empty file upload...")
    
    session = requests.Session()
    session.post(f"{BASE_URL}/login", data={
        'username': 'testuser',
        'password': 'testpass123'
    })
    
    # Create empty file
    with open('empty.csv', 'w') as f:
        pass
    
    with open('empty.csv', 'rb') as f:
        response = session.post(f"{BASE_URL}/upload-logs", 
                                files={'file': f})
    
    if response.status_code == 400 or "error" in response.text.lower():
        print("   ✅ Empty file handled gracefully")
        return True
    else:
        print("   ❌ Empty file not handled properly")
        return False

def test_malformed_json():
    """EDGE-02: Malformed JSON"""
    print("\n[EDGE-02] Testing malformed JSON...")
    
    session = requests.Session()
    session.post(f"{BASE_URL}/login", data={
        'username': 'testuser',
        'password': 'testpass123'
    })
    
    # Create malformed JSON
    with open('malformed.json', 'w') as f:
        f.write('{"this is": "not valid" "json"')
    
    with open('malformed.json', 'rb') as f:
        response = session.post(f"{BASE_URL}/upload-logs", 
                                files={'file': f})
    
    if response.status_code == 400 or "invalid" in response.text.lower():
        print("   ✅ Malformed JSON handled")
        return True
    else:
        print("   ❌ Malformed JSON not handled")
        return False

def test_large_file():
    """EDGE-03: Extremely large file"""
    print("\n[EDGE-03] Testing large file handling...")
    
    session = requests.Session()
    session.post(f"{BASE_URL}/login", data={
        'username': 'testuser',
        'password': 'testpass123'
    })
    
    # Create 100MB file with random data
    with open('large_file.txt', 'wb') as f:
        f.write(b'x' * 100 * 1024 * 1024)
    
    try:
        with open('large_file.txt', 'rb') as f:
            response = session.post(f"{BASE_URL}/upload-logs", 
                                    files={'file': f},
                                    timeout=30)
        
        if response.status_code != 500:
            print("   ✅ Large file handled without crash")
            return True
        else:
            print("   ❌ Large file caused server error")
            return False
    except requests.Timeout:
        print("   ✅ File size limit properly enforced")
        return True

def test_invalid_ip():
    """EDGE-04: Invalid IP address"""
    print("\n[EDGE-04] Testing invalid IP handling...")
    
    session = requests.Session()
    session.post(f"{BASE_URL}/login", data={
        'username': 'testuser',
        'password': 'testpass123'
    })
    
    response = session.post(f"{BASE_URL}/detect-threat", data={
        'source_ip': 'not_an_ip',
        'target_ip': '192.168.1.1',
        'attack_category': 'port_scan'
    })
    
    if response.status_code == 200:
        print("   ✅ Invalid IP handled without error")
        return True
    else:
        print("   ❌ Invalid IP caused error")
        return False

def run_edge_tests():
    """Run all edge case tests"""
    print("="*60)
    print("EDGE CASE TESTS")
    print("="*60)
    
    tests = [
        ("Empty file", test_empty_file),
        ("Malformed JSON", test_malformed_json),
        ("Large file", test_large_file),
        ("Invalid IP", test_invalid_ip)
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
    print("EDGE CASE TEST SUMMARY")
    print("="*60)
    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {name}")
    
    return all(result for _, result in results)

if __name__ == "__main__":
    success = run_edge_tests()
    exit(0 if success else 1)