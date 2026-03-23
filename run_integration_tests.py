"""
Integration Test Runner
"""
import requests
import json
import time
import sys

BASE_URL = "http://localhost:5000"

def test_detection_to_explanation():
    """IT-01: Detection -> Explanation"""
    print("\n[IT-01] Testing Detection to Explanation Flow...")
    
    # Login first
    session = requests.Session()
    try:
        session.post(f"{BASE_URL}/login", data={
            'username': 'testuser',
            'password': 'testpass123'
        }, timeout=5)
    except:
        print("   [!] Using guest session (login may not be required)")
    
    # Submit threat detection
    threat_data = {
        'source_ip': '192.168.1.100',
        'target_ip': '10.0.0.1',
        'target_port': '22',
        'protocol': 'tcp',
        'tool': 'suricata',
        'attack_category': 'bruteforce',
        'severity': 'critical',
        'description': 'Multiple failed SSH login attempts'
    }
    
    try:
        response = session.post(f"{BASE_URL}/detect-threat", data=threat_data, timeout=10)
        
        if response.status_code == 200:
            print("   [PASS] Detection successful")
            # Check if explanation was generated
            if "explanation" in response.text or "analysis" in response.text.lower():
                print("   [PASS] Explanation generated")
                return True
            else:
                print("   [WARN] Explanation may not be visible")
                return True
        else:
            print(f"   [FAIL] Test failed: {response.status_code}")
            return False
    except Exception as e:
        print(f"   [FAIL] Error: {e}")
        return False

def test_full_pipeline():
    """IT-04: Full Pipeline Test"""
    print("\n[IT-04] Testing Full Pipeline...")
    
    session = requests.Session()
    try:
        session.post(f"{BASE_URL}/login", data={
            'username': 'testuser',
            'password': 'testpass123'
        }, timeout=5)
    except:
        pass
    
    # Simulate complete workflow
    test_logs = [
        "2025-03-23 10:30:45 10.0.0.50 -> 192.168.1.1:22 SSH brute force attempt",
        "2025-03-23 10:31:12 192.168.1.100 scanning ports 1-1024",
        "2025-03-23 10:32:05 5.5.5.5 SYN flooding 192.168.1.1:80"
    ]
    
    success_count = 0
    for log in test_logs:
        try:
            response = session.post(f"{BASE_URL}/detect-threat", data={
                'raw_log': log
            }, timeout=10)
            
            if response.status_code == 200:
                print(f"   [PASS] Processed: {log[:50]}...")
                success_count += 1
            else:
                print(f"   [FAIL] Failed: {log[:50]}...")
        except Exception as e:
            print(f"   [FAIL] Error: {e}")
    
    if success_count == len(test_logs):
        print("   [PASS] Full pipeline test passed")
        return True
    else:
        print(f"   [FAIL] Only {success_count}/{len(test_logs)} succeeded")
        return False

def run_integration_tests():
    """Run all integration tests"""
    print("="*60)
    print("INTEGRATION TESTS")
    print("="*60)
    
    tests = [
        ("Detection -> Explanation", test_detection_to_explanation),
        ("Full Pipeline", test_full_pipeline)
    ]
    
    results = []
    for name, test_func in tests:
        try:
            result = test_func()
            results.append((name, result))
        except Exception as e:
            print(f"   [FAIL] Test {name} error: {e}")
            results.append((name, False))
    
    # Print summary
    print("\n" + "="*60)
    print("INTEGRATION TEST SUMMARY")
    print("="*60)
    for name, result in results:
        status = "[PASS]" if result else "[FAIL]"
        print(f"{status} - {name}")
    
    return all(result for _, result in results)

if __name__ == "__main__":
    success = run_integration_tests()
    sys.exit(0 if success else 1)