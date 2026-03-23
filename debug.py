# debug_api.py
import requests
import json

BASE_URL = "http://localhost:5000"

# First login to get session
session = requests.Session()

# Login
login_data = {
    'username': 'testuser',
    'password': 'testpass123'
}
login_response = session.post(f"{BASE_URL}/login", data=login_data)
print(f"Login status: {login_response.status_code}")

# Test API with different formats
test_cases = [
    {
        'name': 'Format 1 - With src_ip/dest_ip',
        'data': {
            'src_ip': '192.168.1.100',
            'dest_ip': '192.168.1.1',
            'dest_port': 22,
            'proto': 'tcp',
            'tool': 'hydra',
            'attack_type': 'bruteforce',
            'description': 'Brute force attack'
        }
    },
    {
        'name': 'Format 2 - With source_ip/target_ip',
        'data': {
            'source_ip': '192.168.1.100',
            'target_ip': '192.168.1.1',
            'target_port': 22,
            'protocol': 'tcp',
            'tool': 'hydra',
            'attack_category': 'bruteforce',
            'description': 'Brute force attack'
        }
    },
    {
        'name': 'Format 3 - Minimal data',
        'data': {
            'src_ip': '192.168.1.100',
            'dest_ip': '192.168.1.1',
            'tool': 'hydra',
            'attack_type': 'bruteforce'
        }
    }
]

print("\n" + "="*60)
print("Testing API Detection Endpoint")
print("="*60)

for test in test_cases:
    print(f"\n{test['name']}:")
    print(f"Data: {json.dumps(test['data'], indent=2)}")
    
    response = session.post(f"{BASE_URL}/api/detect", json=test['data'])
    print(f"Status: {response.status_code}")
    
    if response.status_code == 200:
        try:
            result = response.json()
            print(f"Response: {json.dumps(result, indent=2)}")
            print("✅ SUCCESS!")
        except:
            print(f"Response text: {response.text}")
    else:
        print(f"Error response: {response.text}")