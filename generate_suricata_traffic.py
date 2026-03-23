"""
Generate test traffic for Suricata detection
Run this while Suricata is running
"""

import socket
import time
import random

def generate_port_scan():
    """Generate port scan traffic that Suricata will detect"""
    print("[*] Generating port scan traffic...")
    target = "127.0.0.1"
    ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080, 8443, 27017]
    
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"    [+] Port {port}: OPEN")
            else:
                print(f"    [-] Port {port}: CLOSED")
            sock.close()
            time.sleep(0.05)  # Fast scan pattern
        except Exception as e:
            print(f"    [!] Port {port}: Error")
    
    print("[*] Port scan complete\n")

def generate_bruteforce():
    """Generate SSH brute force attempts"""
    print("[*] Generating SSH brute force traffic...")
    target = "127.0.0.1"
    port = 22
    
    # Common usernames and passwords for simulation
    attempts = [
        ("root", "password"),
        ("root", "123456"),
        ("admin", "admin"),
        ("admin", "password"),
        ("user", "user"),
        ("test", "test"),
        ("root", "toor"),
        ("admin", "admin123"),
        ("ubuntu", "ubuntu"),
        ("pi", "raspberry")
    ]
    
    for i, (user, pwd) in enumerate(attempts):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.0)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"    [{i+1}/{len(attempts)}] Attempt: {user} / {pwd}")
            sock.close()
            time.sleep(0.3)  # Brute force pattern
        except Exception as e:
            print(f"    [!] Connection error")
    
    print("[*] Brute force simulation complete\n")

def generate_dos_traffic():
    """Generate SYN flood-like traffic (limited for safety)"""
    print("[*] Generating DoS simulation traffic...")
    target = "127.0.0.1"
    port = 80
    
    for i in range(30):  # Limited to 30 packets for safety
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            sock.connect_ex((target, port))
            sock.close()
            print(f"    [{i+1}/30] SYN packet sent")
            time.sleep(0.02)  # Fast packet rate
        except Exception as e:
            pass
    
    print("[*] DoS simulation complete\n")

def generate_web_scan():
    """Generate web scanning traffic"""
    print("[*] Generating web scan traffic...")
    target = "127.0.0.1"
    port = 80
    
    paths = [
        "/admin",
        "/phpmyadmin",
        "/wp-admin",
        "/login",
        "/config.php",
        "/backup",
        "/.git",
        "/api",
        "/v1",
        "/test"
    ]
    
    for path in paths:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect_ex((target, port))
            sock.close()
            print(f"    Scanning: {path}")
            time.sleep(0.1)
        except Exception as e:
            pass
    
    print("[*] Web scan complete\n")

def main():
    """Run all traffic simulations"""
    print("="*60)
    print("GENERATING TEST TRAFFIC FOR SURICATA")
    print("="*60)
    print("Make sure Suricata is running in another terminal!")
    print("Run: suricata -c suricata_test.yaml -i loopback")
    print("="*60)
    
    input("\nPress Enter to start generating traffic...")
    
    # Run all simulations
    generate_port_scan()
    time.sleep(1)
    
    generate_bruteforce()
    time.sleep(1)
    
    generate_dos_traffic()
    time.sleep(1)
    
    generate_web_scan()
    
    print("\n" + "="*60)
    print("TRAFFIC GENERATION COMPLETE!")
    print("="*60)
    print("\nCheck Suricata logs for alerts:")
    print("  fast.log: type C:\\Users\\Lenovo\\Desktop\\AgenticAICybersecurity\\AgenticAICyberSecurities\\suricata_logs\\fast.log")
    print("  eve.json: type C:\\Users\\Lenovo\\Desktop\\AgenticAICybersecurity\\AgenticAICyberSecurities\\suricata_logs\\eve.json")

if __name__ == "__main__":
    main()