"""
Generate test attacks that Suricata will detect
Run this in a separate terminal while Suricata is running
"""

import socket
import time
import random
import threading
import sys

class AttackSimulator:
    def __init__(self, target_ip="127.0.0.1"):
        self.target_ip = target_ip
        self.running = False
        
    def port_scan_attack(self):
        """Simulate port scanning"""
        print("[*] Starting port scan attack simulation...")
        ports = [21, 22, 23, 25, 53, 80, 443, 8080, 3306, 5432, 3389, 5900]
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    print(f"    Port {port}: OPEN")
                sock.close()
                time.sleep(0.1)  # Fast scanning pattern
            except:
                pass
        
        print("[✓] Port scan simulation complete")
    
    def brute_force_simulation(self):
        """Simulate brute force attempts (SSH/FTP)"""
        print("[*] Starting brute force simulation...")
        
        usernames = ["root", "admin", "user", "test", "administrator", "ubuntu"]
        passwords = ["password", "123456", "admin", "root", "toor", "password123", "passw0rd"]
        
        for i in range(20):
            user = random.choice(usernames)
            pwd = random.choice(passwords)
            
            # Create SSH connection attempt
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.target_ip, 22))
                
                # Send SSH banner request
                sock.send(b"SSH-2.0-Test\r\n")
                response = sock.recv(1024)
                sock.close()
                
                print(f"    Attempt {i+1}: {user} / {pwd}")
            except:
                # Even if connection fails, it's still an attempt
                print(f"    Attempt {i+1}: {user} / {pwd} (connection refused)")
            
            time.sleep(0.3)  # Simulate attempt interval
        
        print("[✓] Brute force simulation complete")
    
    def syn_flood_simulation(self):
        """Simulate SYN flood (safe version - doesn't actually flood)"""
        print("[*] Starting SYN flood simulation...")
        
        for i in range(50):
            print(f"    SYN packet #{i+1} sent to {self.target_ip}:80")
            time.sleep(0.05)
        
        print("[✓] SYN flood simulation complete")
    
    def web_attack_simulation(self):
        """Simulate web application attacks"""
        print("[*] Starting web attack simulation...")
        
        # SQL Injection attempts
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --",
            "admin' --"
        ]
        
        # XSS attempts
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')"
        ]
        
        for payload in sql_payloads:
            print(f"    SQL Injection: {payload}")
            time.sleep(0.2)
        
        for payload in xss_payloads:
            print(f"    XSS Attack: {payload}")
            time.sleep(0.2)
        
        print("[✓] Web attack simulation complete")
    
    def run_all_attacks(self):
        """Run all attack simulations"""
        print("\n" + "="*60)
        print("ATTACK SIMULATION SUITE")
        print("="*60)
        
        attacks = [
            ("Port Scan", self.port_scan_attack),
            ("Brute Force", self.brute_force_simulation),
            ("SYN Flood", self.syn_flood_simulation),
            ("Web Attacks", self.web_attack_simulation)
        ]
        
        for name, attack_func in attacks:
            print(f"\n--- {name} Attack ---")
            attack_func()
            time.sleep(2)
        
        print("\n" + "="*60)
        print("ALL ATTACK SIMULATIONS COMPLETE")
        print("="*60)

if __name__ == "__main__":
    simulator = AttackSimulator(target_ip="127.0.0.1")
    simulator.run_all_attacks()