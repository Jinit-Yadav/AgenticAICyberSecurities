"""
Test the Response Agent's process termination capability
Creates a harmless high-CPU process and tests if system detects and kills it
"""

import time
import subprocess
import psutil
import threading

def create_high_cpu_process():
    """Create a harmless process that uses high CPU for testing"""
    
    def cpu_intensive():
        """CPU-intensive loop for testing"""
        x = 0
        while True:
            x = (x + 1) % 1000000
            time.sleep(0.0001)
    
    # Start CPU-intensive thread
    thread = threading.Thread(target=cpu_intensive, daemon=True)
    thread.start()
    
    # Get current process info
    pid = threading.current_thread().ident
    process = psutil.Process()
    
    print(f"[*] Created test process with PID: {process.pid}")
    print(f"[*] CPU usage: {process.cpu_percent(interval=1)}%")
    
    return process

def monitor_and_test():
    """Monitor if the system detects and kills the high-CPU process"""
    
    print("="*60)
    print("TESTING PROCESS TERMINATION")
    print("="*60)
    
    # Start high-CPU process
    print("\n[1] Starting test high-CPU process...")
    test_process = create_high_cpu_process()
    
    # Wait for detection
    print("\n[2] Waiting for system to detect (30 seconds)...")
    time.sleep(30)
    
    # Check if process is still running
    try:
        if test_process.is_running():
            cpu = test_process.cpu_percent(interval=1)
            print(f"    Process still running. CPU: {cpu}%")
            if cpu > 80:
                print("    ⚠️  High-CPU process not terminated!")
        else:
            print("    ✅ Process was terminated by the system")
    except psutil.NoSuchProcess:
        print("    ✅ Process was terminated by the system")
    
    # Check database for record
    print("\n[3] Checking database for kill record...")
    try:
        import sqlite3
        conn = sqlite3.connect('responses.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM blocked_processes ORDER BY created_at DESC LIMIT 5")
        rows = cursor.fetchall()
        if rows:
            print("    ✅ Found process termination records:")
            for row in rows[:3]:
                print(f"       Process: {row[1]}, Action: {row[5]}")
        else:
            print("    ⚠️  No termination records found")
        conn.close()
    except Exception as e:
        print(f"    ⚠️  Could not check database: {e}")

if __name__ == "__main__":
    monitor_and_test()