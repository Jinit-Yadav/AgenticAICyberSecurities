"""
Test script for nmap port scanning detection
Run this while your Flask app is running
"""

import socket
import time
import random

def simulate_port_scan(target_ip="127.0.0.1", ports=None):
    """
    Simulate a simple port scan without using actual nmap
    This is safe and won't affect your system
    """
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 443, 8080, 3306, 5432]
    
    print(f"[*] Simulating port scan on {target_ip}")
    print("[*] Opening connections to detect open ports...")
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"    [+] Port {port}: OPEN")
            else:
                print(f"    [-] Port {port}: CLOSED")
            sock.close()
            time.sleep(0.1)  # Small delay to simulate scanning pattern
        except Exception as e:
            print(f"    [!] Port {port}: Error - {e}")
    
    print("[*] Port scan simulation complete")

if __name__ == "__main__":
    # Simulate scanning your own machine
    simulate_port_scan("127.0.0.1")