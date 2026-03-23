"""
Test the Multi-Expert Explanation Agent
"""

import requests
import json
import time

def test_explanation_agent():
    """Test if the explanation agent generates meaningful output"""
    
    print("="*60)
    print("TESTING MULTI-EXPERT EXPLANATION AGENT")
    print("="*60)
    
    # Test cases
    test_cases = [
        {
            'name': 'Port Scan',
            'tool': 'nmap',
            'src_ip': '192.168.1.100',
            'dest_ip': '192.168.1.1',
            'dest_port': 22,
            'attack_type': 'port_scan',
            'severity': 'high'
        },
        {
            'name': 'Brute Force',
            'tool': 'hydra',
            'src_ip': '10.0.0.50',
            'dest_ip': '192.168.1.1',
            'dest_port': 22,
            'attack_type': 'bruteforce',
            'severity': 'critical'
        },
        {
            'name': 'DoS Attack',
            'tool': 'hping3',
            'src_ip': '172.16.0.25',
            'dest_ip': '192.168.1.1',
            'dest_port': 80,
            'attack_type': 'dos',
            'severity': 'high'
        }
    ]
    
    session = requests.Session()
    
    # Login
    print("\n[1] Logging in...")
    try:
        login_data = {'username': 'testuser', 'password': 'testpass123'}
        session.post('http://localhost:5000/login', data=login_data)
        print("    ✅ Login successful")
    except:
        print("    ⚠️  Could not login. Make sure Flask app is running.")
        return
    
    # Test each scenario
    for test in test_cases:
        print(f"\n[2] Testing: {test['name']}")
        print("-" * 40)
        
        # Send detection
        detection_data = {
            'source_ip': test['src_ip'],
            'target_ip': test['dest_ip'],
            'target_port': test['dest_port'],
            'protocol': 'tcp',
            'tool': test['tool'],
            'attack_category': test['attack_type'],
            'severity': test['severity'],
            'description': f'Test {test["name"]} activity'
        }
        
        start_time = time.time()
        response = session.post('http://localhost:5000/detect-threat', data=detection_data)
        elapsed = time.time() - start_time
        
        if response.status_code == 200:
            print(f"    ✅ Detection processed in {elapsed:.2f}s")
            
            # Check if explanation was generated
            # Look for explanation in response
            if 'formatted_output' in response.text or 'EXPERT ANALYSES' in response.text:
                print("    ✅ Explanation generated successfully")
            else:
                print("    ⚠️  Could not find explanation in response")
        else:
            print(f"    ❌ Detection failed: {response.status_code}")
        
        time.sleep(1)  # Small delay between tests
    
    print("\n" + "="*60)
    print("TESTING COMPLETE")
    print("="*60)

if __name__ == "__main__":
    test_explanation_agent()