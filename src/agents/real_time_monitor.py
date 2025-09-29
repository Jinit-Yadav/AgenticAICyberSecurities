import psutil
import pandas as pd
import time
import threading
from datetime import datetime

class RealTimeMonitor:
    def __init__(self):
        self.network_data = []
        self.process_data = []
        self.is_monitoring = False
        self.monitor_thread = None
        
    def start_monitoring(self):
        """Start real-time monitoring in background thread"""
        self.is_monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        print("🔍 Real-time monitoring started...")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        self.is_monitoring = False
        print("🛑 Real-time monitoring stopped")
    
    def _monitor_loop(self):
        """Main monitoring loop"""
        while self.is_monitoring:
            try:
                # Capture network connections
                self._capture_network_connections()
                
                # Capture process information
                self._capture_processes()
                
                # Keep only last 100 entries to prevent memory issues
                self.network_data = self.network_data[-100:]
                self.process_data = self.process_data[-50:]
                
                time.sleep(2)  # Update every 2 seconds
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(5)
    
    def _capture_network_connections(self):
        """Capture real network connections"""
        try:
            connections = psutil.net_connections(kind='inet')
            
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
                    # Get process name
                    process_name = "unknown"
                    try:
                        if conn.pid:
                            process = psutil.Process(conn.pid)
                            process_name = process.name()
                    except:
                        pass
                    
                    # Create network log entry
                    network_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'tool': process_name,
                        'attack_type': 'unknown',
                        'severity': 'low',
                        'proto': 'tcp' if conn.type == 1 else 'udp',
                        'src_ip': conn.laddr.ip,
                        'dest_ip': conn.raddr.ip,
                        'dest_port': conn.raddr.port,
                        'pid': conn.pid,
                        'status': conn.status
                    }
                    
                    # Add to network data (avoid duplicates)
                    if network_entry not in self.network_data:
                        self.network_data.append(network_entry)
                        
        except Exception as e:
            print(f"Network capture error: {e}")
    
    def _capture_processes(self):
        """Capture running processes"""
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
                try:
                    process_entry = {
                        'timestamp': datetime.now().isoformat(),
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'cpu_percent': proc.info['cpu_percent'],
                        'memory_percent': proc.info['memory_percent'],
                        'status': proc.info['status']
                    }
                    
                    # Add if not already in list
                    if process_entry not in self.process_data:
                        self.process_data.append(process_entry)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except Exception as e:
            print(f"Process capture error: {e}")
    
    def get_network_stats(self):
        """Get statistics about network activity"""
        if not self.network_data:
            return {}
        
        df = pd.DataFrame(self.network_data)
        stats = {
            'total_connections': len(self.network_data),
            'unique_processes': df['tool'].nunique(),
            'unique_ports': df['dest_port'].nunique(),
            'top_processes': df['tool'].value_counts().head(5).to_dict(),
            'top_ports': df['dest_port'].value_counts().head(5).to_dict(),
            'recent_activity': self.network_data[-10:]  # Last 10 connections
        }
        return stats
    
    def get_process_stats(self):
        """Get statistics about processes"""
        if not self.process_data:
            return {}
        
        df = pd.DataFrame(self.process_data)
        stats = {
            'total_processes': len(self.process_data),
            'running_processes': len(df[df['status'] == 'running']),
            'top_cpu_processes': df.nlargest(5, 'cpu_percent')[['name', 'cpu_percent']].to_dict('records'),
            'top_memory_processes': df.nlargest(5, 'memory_percent')[['name', 'memory_percent']].to_dict('records'),
            'recent_processes': self.process_data[-10:]  # Last 10 processes
        }
        return stats