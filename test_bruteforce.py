"""
Test script for brute force attack detection
Simulates failed login attempts
"""

import time
import random

def simulate_bruteforce_ssh(target_ip="127.0.0.1", attempts=20):
    """
    Simulate SSH brute force attempts
    Uses paramiko if available, otherwise simulates via logs
    """
    print(f"[*] Simulating brute force attack on {target_ip}")
    
    # Common usernames and passwords for simulation
    usernames = ["root", "admin", "user", "test", "ubuntu"]
    passwords = ["password", "123456", "admin", "root", "toor", "password123"]
    
    for i in range(attempts):
        username = random.choice(usernames)
        password = random.choice(passwords)
        
        # This doesn't actually attempt login - just logs the attempt
        print(f"[{i+1}/{attempts}] Attempt: {username} / {password}")
        
        # Create a log entry that would be detected
        log_entry = {
            'timestamp': time.time(),
            'src_ip': '192.168.1.100',
            'dest_ip': target_ip,
            'dest_port': 22,
            'proto': 'tcp',
            'tool': 'hydra',
            'attack_type': 'bruteforce',
            'description': f'Failed login attempt for {username}',
            'severity': 'critical'
        }
        
        # You can POST this to your API
        # Uncomment if you want to test via API
        # import requests
        # requests.post('http://localhost:5000/api/detect', json=log_entry)
        
        time.sleep(0.5)  # Simulate attempt interval
    
    print("[*] Brute force simulation complete")

if __name__ == "__main__":
    simulate_bruteforce_ssh()