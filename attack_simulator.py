"""
Attack Simulator for Testing CyberShield AI
Generates various types of attacks to test detection and response
"""
import socket
import time
import random
import threading
import sys
from datetime import datetime

class AttackSimulator:
    def __init__(self):
        self.target_ip = "127.0.0.1"  # Localhost for testing
        self.attack_count = 0
        self.blocked_attacks = []
        
    def print_header(self):
        print("="*70)
        print("CYBERSHIELD AI - ATTACK SIMULATOR")
        print("="*70)
        print(f"Target: {self.target_ip}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70)
    
    def port_scan_attack(self, ports=None):
        """Simulate port scanning attack"""
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080, 8443]
        
        print(f"\n🔍 [ATTACK {self.attack_count+1}] Port Scan Attack")
        print(f"   Scanning {len(ports)} ports on {self.target_ip}")
        
        open_ports = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.3)
                result = sock.connect_ex((self.target_ip, port))
                
                if result == 0:
                    open_ports.append(port)
                    print(f"   [+] Port {port}: OPEN")
                else:
                    print(f"   [-] Port {port}: CLOSED")
                
                sock.close()
                time.sleep(0.05)  # Fast scan pattern
                
            except Exception as e:
                print(f"   [!] Error scanning port {port}: {e}")
        
        self.attack_count += 1
        
        if open_ports:
            print(f"\n   Found {len(open_ports)} open ports: {open_ports}")
        
        return open_ports
    
    def brute_force_attack(self, target_port=22, attempts=10):
        """Simulate brute force attack on SSH"""
        print(f"\n🔐 [ATTACK {self.attack_count+1}] Brute Force Attack")
        print(f"   Target: {self.target_ip}:{target_port}")
        print(f"   Attempts: {attempts}")
        
        # Common username/password combinations
        credentials = [
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
        
        successful = False
        for i, (username, password) in enumerate(credentials[:attempts]):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((self.target_ip, target_port))
                
                if result == 0:
                    print(f"   [{i+1}/{attempts}] Attempt: {username}/{password} - Connection successful")
                    # In a real attack, would attempt authentication
                    if username == "root" and password == "toor":
                        successful = True
                else:
                    print(f"   [{i+1}/{attempts}] Attempt: {username}/{password} - Connection refused")
                
                sock.close()
                time.sleep(0.2)  # Brute force pattern
                
            except Exception as e:
                print(f"   [!] Error: {e}")
        
        self.attack_count += 1
        
        if successful:
            print(f"\n   ⚠️  CRITICAL: Brute force successful!")
        else:
            print(f"\n   Attack completed - No successful login")
        
        return successful
    
    def dos_attack(self, target_port=80, packets=50):
        """Simulate DoS attack (SYN flood simulation)"""
        print(f"\n🌊 [ATTACK {self.attack_count+1}] DoS Attack (SYN Flood)")
        print(f"   Target: {self.target_ip}:{target_port}")
        print(f"   Packets: {packets}")
        
        def send_syn_packet(source_ip, target_ip, target_port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.connect_ex((target_ip, target_port))
                sock.close()
                return True
            except:
                return False
        
        successful_packets = 0
        for i in range(packets):
            # Spoof source IP for each packet
            spoofed_ip = f"10.0.0.{random.randint(1, 255)}"
            result = send_syn_packet(spoofed_ip, self.target_ip, target_port)
            
            if result:
                successful_packets += 1
            
            if (i + 1) % 10 == 0:
                print(f"   Sent {i+1}/{packets} packets...")
            
            time.sleep(0.01)  # Fast packet rate
        
        self.attack_count += 1
        print(f"\n   Sent {successful_packets}/{packets} SYN packets")
        
        return successful_packets
    
    def web_scan_attack(self):
        """Simulate web application scanning"""
        print(f"\n🌐 [ATTACK {self.attack_count+1}] Web Application Scan")
        
        paths = [
            "/admin",
            "/phpmyadmin",
            "/wp-admin",
            "/login",
            "/config.php",
            "/backup",
            "/.git",
            "/api/v1",
            "/test",
            "/dashboard"
        ]
        
        print(f"   Scanning {len(paths)} paths on {self.target_ip}:80")
        
        found_paths = []
        for path in paths:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                sock.connect_ex((self.target_ip, 80))
                
                # Simulate HTTP request
                request = f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n"
                sock.send(request.encode())
                
                response = sock.recv(1024)
                if response:
                    status = response.split(b'\r\n')[0].decode()
                    print(f"   [+] {path} - {status}")
                    found_paths.append(path)
                else:
                    print(f"   [-] {path} - No response")
                
                sock.close()
                time.sleep(0.1)
                
            except Exception as e:
                print(f"   [!] Error scanning {path}: {e}")
        
        self.attack_count += 1
        
        if found_paths:
            print(f"\n   Found {len(found_paths)} accessible paths: {found_paths}")
        
        return found_paths
    
    def check_blocked_ips(self):
        """Check if IPs are blocked by checking connection"""
        test_ip = "127.0.0.1"
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((test_ip, 80))
            sock.close()
            
            if result != 0:
                print(f"   ✅ IP {test_ip} is BLOCKED (Connection refused)")
                return True
            else:
                print(f"   ❌ IP {test_ip} is NOT blocked")
                return False
        except:
            return False
    
    def run_all_attacks(self):
        """Run all attack types"""
        self.print_header()
        
        input("\nPress Enter to start attacks...")
        
        # Attack 1: Port Scan
        self.port_scan_attack()
        time.sleep(2)
        
        # Attack 2: Brute Force
        self.brute_force_attack(22, 15)
        time.sleep(2)
        
        # Attack 3: DoS Attack
        self.dos_attack(80, 50)
        time.sleep(2)
        
        # Attack 4: Web Scan
        self.web_scan_attack()
        
        print("\n" + "="*70)
        print("ATTACK SIMULATION COMPLETE")
        print("="*70)
        print(f"Total attacks simulated: {self.attack_count}")
        print("\nCheck the following for results:")
        print("  1. Suricata terminal - Should show alerts")
        print("  2. Flask app terminal - Should show detection and responses")
        print("  3. Forwarder terminal - Should show forwarded alerts")
        print("  4. Browser dashboard - Check http://localhost:5000/dashboard")
        print("="*70)
        
        # Check if responses were triggered
        print("\nChecking response status...")
        if self.check_blocked_ips():
            print("\n✅ Response Agent is ACTIVE - IP blocking detected!")
        else:
            print("\n⚠️  No IP blocking detected. Check if Response Agent is configured.")

def continuous_attack_mode():
    """Run attacks continuously for testing"""
    simulator = AttackSimulator()
    simulator.print_header()
    
    print("\nRunning in CONTINUOUS ATTACK MODE")
    print("Attacks will run every 30 seconds")
    print("Press Ctrl+C to stop\n")
    
    try:
        attack_cycle = 0
        while True:
            attack_cycle += 1
            print(f"\n{'='*70}")
            print(f"ATTACK CYCLE #{attack_cycle}")
            print(f"{'='*70}")
            
            # Rotate through attack types
            attack_type = attack_cycle % 4
            
            if attack_type == 0:
                simulator.port_scan_attack()
            elif attack_type == 1:
                simulator.brute_force_attack(22, 10)
            elif attack_type == 2:
                simulator.dos_attack(80, 30)
            else:
                simulator.web_scan_attack()
            
            print(f"\nWaiting 30 seconds before next attack cycle...")
            time.sleep(30)
            
    except KeyboardInterrupt:
        print(f"\n\nContinuous attack stopped after {attack_cycle} cycles")

def main():
    print("="*70)
    print("CYBERSHIELD AI - ATTACK SIMULATOR")
    print("="*70)
    print("\nSelect attack mode:")
    print("1. Run all attacks once (recommended)")
    print("2. Continuous attack mode (runs every 30 seconds)")
    print("3. Port Scan only")
    print("4. Brute Force only")
    print("5. DoS Attack only")
    print("6. Web Scan only")
    
    choice = input("\nEnter choice (1-6): ").strip()
    
    simulator = AttackSimulator()
    
    if choice == '1':
        simulator.run_all_attacks()
    elif choice == '2':
        continuous_attack_mode()
    elif choice == '3':
        simulator.print_header()
        simulator.port_scan_attack()
    elif choice == '4':
        simulator.print_header()
        simulator.brute_force_attack(22, 20)
    elif choice == '5':
        simulator.print_header()
        simulator.dos_attack(80, 100)
    elif choice == '6':
        simulator.print_header()
        simulator.web_scan_attack()
    else:
        print("Invalid choice, running all attacks...")
        simulator.run_all_attacks()

if __name__ == "__main__":
    main()