"""
Test script for DoS attack detection
Simulates SYN flood without actually flooding
"""

import socket
import time
import threading

class SimulatedSynFlood:
    """Safe SYN flood simulation - doesn't actually send packets, just logs"""
    
    def __init__(self, target_ip="127.0.0.1", target_port=80):
        self.target_ip = target_ip
        self.target_port = target_port
        self.running = False
        
    def simulate_packet(self, packet_id):
        """Simulate sending a SYN packet"""
        print(f"[*] Simulated SYN packet #{packet_id} to {self.target_ip}:{self.target_port}")
        
        # Create a log entry that would be detected
        log_entry = {
            'timestamp': time.time(),
            'src_ip': '172.16.0.25',
            'dest_ip': self.target_ip,
            'dest_port': self.target_port,
            'proto': 'tcp',
            'tool': 'hping3',
            'attack_type': 'dos',
            'description': f'SYN flood attack - packet #{packet_id}',
            'severity': 'high'
        }
        return log_entry
    
    def start_flood(self, packet_count=100, rate=10):
        """Start simulated flood"""
        self.running = True
        print(f"[*] Starting simulated SYN flood: {packet_count} packets at {rate}/sec")
        
        for i in range(packet_count):
            if not self.running:
                break
            packet = self.simulate_packet(i + 1)
            time.sleep(1.0 / rate)  # Rate limiting
        
        print("[*] Flood simulation complete")
    
    def stop(self):
        self.running = False

if __name__ == "__main__":
    flood = SimulatedSynFlood()
    flood.start_flood(packet_count=50, rate=20)