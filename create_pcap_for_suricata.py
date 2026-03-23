"""
Create a PCAP file with attacks for Suricata to analyze
"""
from scapy.all import *
import random

print("Creating PCAP file with attacks...")

packets = []
target = "127.0.0.1"

# 1. Port Scan - multiple SYN packets to different ports
print("  Adding port scan packets...")
ports = [21, 22, 23, 25, 53, 80, 443, 3306, 3389, 8080]
for port in ports:
    packet = IP(src="192.168.1.100", dst=target)/TCP(sport=54321, dport=port, flags="S")
    packets.append(packet)

# 2. SSH Brute Force - multiple connections to port 22
print("  Adding brute force packets...")
for i in range(15):
    packet = IP(src="10.0.0.50", dst=target)/TCP(sport=random.randint(10000, 60000), dport=22, flags="S")
    packets.append(packet)

# 3. SYN Flood - many packets from different IPs
print("  Adding SYN flood packets...")
for i in range(50):
    spoofed_ip = f"10.0.0.{i % 255}"
    packet = IP(src=spoofed_ip, dst=target)/TCP(sport=12345, dport=80, flags="S")
    packets.append(packet)

# 4. Web Scan
print("  Adding web scan packets...")
paths = ['/admin', '/phpmyadmin', '/wp-admin', '/login', '/config.php']
for path in paths:
    packet = IP(src="8.8.8.8", dst=target)/TCP(sport=54321, dport=80, flags="A")/Raw(load=f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n")
    packets.append(packet)

# Save PCAP
output_file = "test_attacks.pcap"
wrpcap(output_file, packets)
print(f"\n✅ Created {output_file} with {len(packets)} packets")
print(f"\nNow run Suricata on this PCAP file:")
print(f'suricata -c suricata_test.yaml -r {output_file}')