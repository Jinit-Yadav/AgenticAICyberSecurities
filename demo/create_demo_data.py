import pandas as pd
import json
import os
import random
from pathlib import Path

class DemoDataCreator:
    """Create demo dataset from your existing data"""
    
    def __init__(self):
        self.demo_dir = "demo"
        self.sample_logs_dir = os.path.join(self.demo_dir, "sample_logs")
        os.makedirs(self.sample_logs_dir, exist_ok=True)
    
    def create_attack_samples(self):
        """Create small attack samples from your large files"""
        
        # Your attack log directories
        nmap_dir = 'C:/Users/yadav/Downloads/wetransfer_nmap-sv-json_2025-09-25_1525'
        attacks_dir = 'C:/Users/yadav/Downloads/Attacks log'
        
        attack_samples = []
        
        # Sample from a few key files (take first 5-10 lines)
        sample_files = [
            os.path.join(nmap_dir, 'nmap-sS.json'),
            os.path.join(nmap_dir, 'hydra-ssh.json'), 
            os.path.join(nmap_dir, 'hping3-S.json'),
            os.path.join(nmap_dir, 'gobuster.json'),
            os.path.join(nmap_dir, 'nikto.json'),
            os.path.join(attacks_dir, 'hydra_BruteForce_log.json'),
            os.path.join(attacks_dir, 'nmap_sS_sV_log.json')
        ]
        
        for file_path in sample_files:
            if os.path.exists(file_path):
                print(f"📂 Sampling from: {os.path.basename(file_path)}")
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        lines = []
                        for i, line in enumerate(f):
                            if i >= 10:  # Take only first 10 lines
                                break
                            if line.strip():
                                lines.append(line.strip())
                        
                        if lines:
                            # Save as separate demo file
                            demo_file = os.path.join(self.sample_logs_dir, f"demo_{os.path.basename(file_path)}")
                            with open(demo_file, 'w') as out_f:
                                for line in lines:
                                    out_f.write(line + '\n')
                            print(f"   ✅ Created: demo_{os.path.basename(file_path)}")
                            
                except Exception as e:
                    print(f"   ❌ Error with {file_path}: {e}")
        
        return attack_samples
    
    def create_unsw_normal_samples(self):
        """Create normal traffic samples from UNSW-NB15"""
        
        unsw_path = 'notebook/data/UNSW_NB15_training-set.csv'
        
        if os.path.exists(unsw_path):
            print(f"📂 Loading UNSW-NB15 for normal traffic samples...")
            
            # Load UNSW data
            df = pd.read_csv(unsw_path)
            
            # Get normal traffic (label = 0)
            normal_traffic = df[df['label'] == 0]
            
            if len(normal_traffic) > 0:
                # Take 20 random normal samples
                normal_samples = normal_traffic.sample(n=min(20, len(normal_traffic)), random_state=42)
                
                # Convert to JSON format for demo
                normal_logs = []
                for _, row in normal_samples.iterrows():
                    log_entry = {
                        'timestamp': '2024-01-15T10:00:00.000000',
                        'event_type': 'normal_traffic',
                        'src_ip': f"192.168.{random.randint(1, 100)}.{random.randint(1, 254)}",
                        'src_port': row.get('srcport', random.randint(1024, 65535)),
                        'dest_ip': f"10.0.{random.randint(1, 100)}.{random.randint(1, 254)}", 
                        'dest_port': row.get('dstport', 80),
                        'proto': row.get('proto', 'TCP'),
                        'service': row.get('service', 'http'),
                        'state': row.get('state', 'ESTABLISHED'),
                        'is_threat': 0,
                        'description': 'Normal network traffic'
                    }
                    normal_logs.append(log_entry)
                
                # Save normal traffic samples
                normal_file = os.path.join(self.sample_logs_dir, "demo_normal_traffic.json")
                with open(normal_file, 'w') as f:
                    for log in normal_logs:
                        f.write(json.dumps(log) + '\n')
                
                print(f"✅ Created: demo_normal_traffic.json ({len(normal_logs)} normal samples)")
                return normal_logs
        
        return []
    
    def create_quick_demo_files(self):
        """Create quick demo files without processing all data"""
        
        print("🚀 Creating Quick Demo Dataset...")
        
        # Create some synthetic demo data based on your tool patterns
        demo_attacks = [
            # Nmap Scan
            {
                "timestamp": "2024-01-15T10:30:00.123456",
                "event_type": "alert", 
                "src_ip": "192.168.1.100",
                "src_port": 54321,
                "dest_ip": "192.168.1.1",
                "dest_port": 22,
                "proto": "TCP",
                "tool": "nmap",
                "attack_type": "port_scan",
                "severity": "high",
                "description": "Stealth port scanning detected"
            },
            # Hydra Bruteforce
            {
                "timestamp": "2024-01-15T10:31:15.654321",
                "event_type": "alert",
                "src_ip": "10.0.0.50", 
                "src_port": 45678,
                "dest_ip": "10.0.0.1",
                "dest_port": 22, 
                "proto": "TCP",
                "tool": "hydra",
                "attack_type": "bruteforce",
                "severity": "critical",
                "description": "SSH password brute force attack"
            },
            # Hping3 DoS
            {
                "timestamp": "2024-01-15T10:32:30.987654",
                "event_type": "alert",
                "src_ip": "172.16.0.25",
                "src_port": 34567,
                "dest_ip": "172.16.0.1", 
                "dest_port": 80,
                "proto": "TCP",
                "tool": "hping3",
                "attack_type": "dos",
                "severity": "high", 
                "description": "SYN flood attack attempt"
            },
            # Normal Traffic
            {
                "timestamp": "2024-01-15T10:29:10.111111",
                "event_type": "connection",
                "src_ip": "192.168.1.50",
                "src_port": 54320,
                "dest_ip": "8.8.8.8",
                "dest_port": 53,
                "proto": "UDP",
                "tool": "normal",
                "attack_type": "none",
                "severity": "low",
                "description": "Normal DNS query"
            },
            # Another Normal
            {
                "timestamp": "2024-01-15T10:28:05.222222", 
                "event_type": "connection",
                "src_ip": "192.168.1.75",
                "src_port": 54319,
                "dest_ip": "192.168.1.1",
                "dest_port": 443,
                "proto": "TCP",
                "tool": "normal",
                "attack_type": "none", 
                "severity": "low",
                "description": "Normal HTTPS traffic"
            }
        ]
        
        # Save demo files
        demo_file = os.path.join(self.sample_logs_dir, "demo_attacks.json")
        with open(demo_file, 'w') as f:
            for attack in demo_attacks:
                f.write(json.dumps(attack) + '\n')
        
        print(f"✅ Created: demo_attacks.json ({len(demo_attacks)} samples)")
        print("   - 3 Attack samples (Nmap, Hydra, Hping3)")
        print("   - 2 Normal traffic samples")
        
        return demo_attacks
    
    def run(self):
        """Create all demo data"""
        print("🛠️ Creating Demo Dataset for Cyber Security AI System")
        print("=" * 50)
        
        # Create quick demo files (recommended - fast and reliable)
        demo_data = self.create_quick_demo_files()
        
        # Also try to get some real normal traffic from UNSW
        self.create_unsw_normal_samples()
        
        print("=" * 50)
        print("🎉 Demo dataset created successfully!")
        print("📁 Files saved in: demo/sample_logs/")
        print("🚀 You can now run your Streamlit app!")

if __name__ == "__main__":
    creator = DemoDataCreator()
    creator.run()