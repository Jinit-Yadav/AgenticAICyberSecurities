"""
Complete Test Suite for CyberShield AI - With CSRF for API
"""
import requests
import json
import time
import sqlite3
import os
from datetime import datetime
import sys
from bs4 import BeautifulSoup
import re

BASE_URL = "http://localhost:5000"

# Test user credentials
TEST_USER = {
    'username': 'testuser',
    'email': 'test@example.com',
    'password': 'testpass123'
}

class CyberShieldTester:
    def __init__(self):
        self.session = requests.Session()
        self.test_results = []
        self.csrf_token = None
        
    def get_csrf_token(self, url):
        """Extract CSRF token from page"""
        try:
            response = self.session.get(url)
            if response.status_code == 200:
                # Try to find CSRF token in the response
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Check for meta tag
                meta_token = soup.find('meta', {'name': 'csrf-token'})
                if meta_token:
                    self.csrf_token = meta_token.get('content')
                    print(f"  Found CSRF token via meta tag: {self.csrf_token[:20]}...")
                    return self.csrf_token
                
                # Check for input field
                csrf_input = soup.find('input', {'name': 'csrf_token'})
                if csrf_input:
                    self.csrf_token = csrf_input.get('value')
                    print(f"  Found CSRF token via input field: {self.csrf_token[:20]}...")
                    return self.csrf_token
                
                # Check for JavaScript variable
                script_pattern = r'var csrf_token = "([^"]+)"'
                match = re.search(script_pattern, response.text)
                if match:
                    self.csrf_token = match.group(1)
                    print(f"  Found CSRF token via JS variable: {self.csrf_token[:20]}...")
                    return self.csrf_token
                
                # Check for CSRF in headers
                if 'X-CSRFToken' in response.headers:
                    self.csrf_token = response.headers['X-CSRFToken']
                    print(f"  Found CSRF token in headers: {self.csrf_token[:20]}...")
                    return self.csrf_token
                    
            return None
        except Exception as e:
            print(f"  Error getting CSRF token: {e}")
            return None
    
    def log_result(self, test_name, passed, message=""):
        """Log test result"""
        status = "✅ PASS" if passed else "❌ FAIL"
        self.test_results.append({
            'name': test_name,
            'passed': passed,
            'message': message
        })
        print(f"{status} - {test_name}")
        if message:
            print(f"     {message}")
    
    def test_database_connection(self):
        """Test database connectivity"""
        print("\n[TEST 1] Database Connection")
        try:
            db_files = ['threats.db', 'alerts.db']
            found = 0
            for db_file in db_files:
                if os.path.exists(db_file):
                    found += 1
                    print(f"  Found database: {db_file}")
                    conn = sqlite3.connect(db_file)
                    cursor = conn.cursor()
                    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                    tables = cursor.fetchall()
                    print(f"  Tables in {db_file}: {[t[0] for t in tables]}")
                    conn.close()
            
            if found > 0:
                self.log_result("Database Connection", True, f"Found {found} databases")
                return True
            else:
                self.log_result("Database Connection", False, "No databases found")
                return False
        except Exception as e:
            self.log_result("Database Connection", False, str(e))
            return False
    
    def test_user_registration(self):
        """Test user registration"""
        print("\n[TEST 2] User Registration")
        try:
            # Get CSRF token first
            self.get_csrf_token(f"{BASE_URL}/register")
            
            data = {
                'username': TEST_USER['username'],
                'email': TEST_USER['email'],
                'password': TEST_USER['password'],
                'confirm_password': TEST_USER['password']
            }
            
            if self.csrf_token:
                data['csrf_token'] = self.csrf_token
            
            response = self.session.post(f"{BASE_URL}/register", data=data)
            
            if response.status_code == 200 or response.status_code == 302:
                self.log_result("User Registration", True, "Registration successful")
                return True
            elif "already exists" in response.text.lower():
                self.log_result("User Registration", True, "User already exists - skipping")
                return True
            else:
                self.log_result("User Registration", False, f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_result("User Registration", False, str(e))
            return False
    
    def test_user_login(self):
        """Test user login"""
        print("\n[TEST 3] User Login")
        try:
            # Get CSRF token from login page
            self.get_csrf_token(f"{BASE_URL}/login")
            
            data = {
                'username': TEST_USER['username'],
                'password': TEST_USER['password']
            }
            
            if self.csrf_token:
                data['csrf_token'] = self.csrf_token
            
            response = self.session.post(f"{BASE_URL}/login", data=data, allow_redirects=False)
            
            if response.status_code == 302:
                # Login successful, follow redirect
                self.session.get(f"{BASE_URL}/dashboard")
                self.log_result("User Login", True, "Login successful")
                return True
            elif response.status_code == 200:
                if "dashboard" in response.url:
                    self.log_result("User Login", True, "Already logged in")
                    return True
                else:
                    self.log_result("User Login", False, "Login failed")
                    return False
            else:
                self.log_result("User Login", False, f"Status code: {response.status_code}")
                return False
        except Exception as e:
            self.log_result("User Login", False, str(e))
            return False
    
    def test_dashboard_access(self):
        """Test dashboard access"""
        print("\n[TEST 4] Dashboard Access")
        try:
            response = self.session.get(f"{BASE_URL}/dashboard")
            
            if response.status_code == 200:
                self.log_result("Dashboard Access", True, "Dashboard accessible")
                return True
            else:
                self.log_result("Dashboard Access", False, f"Status code: {response.status_code}")
                return False
        except Exception as e:
            self.log_result("Dashboard Access", False, str(e))
            return False
    
    def test_threat_detection_endpoint(self):
        """Test threat detection endpoint with CSRF"""
        print("\n[TEST 5] Threat Detection Endpoint")
        try:
            # Get CSRF token from detection page
            self.get_csrf_token(f"{BASE_URL}/detect-threat")
            
            test_cases = [
                {
                    'source_ip': '192.168.1.100',
                    'target_ip': '10.0.0.1',
                    'target_port': '22',
                    'protocol': 'tcp',
                    'tool': 'hydra',
                    'attack_category': 'bruteforce',
                    'severity': 'critical',
                    'description': 'Multiple failed SSH login attempts'
                },
                {
                    'source_ip': '10.0.0.50',
                    'target_ip': '192.168.1.1',
                    'target_port': '80',
                    'protocol': 'tcp',
                    'tool': 'nmap',
                    'attack_category': 'port_scan',
                    'severity': 'high',
                    'description': 'Port scanning activity detected'
                }
            ]
            
            success_count = 0
            for test_case in test_cases:
                data = test_case.copy()
                if self.csrf_token:
                    data['csrf_token'] = self.csrf_token
                
                response = self.session.post(f"{BASE_URL}/detect-threat", data=data)
                if response.status_code == 200:
                    success_count += 1
                    print(f"  ✅ Detected: {test_case['attack_category']}")
                else:
                    print(f"  ❌ Failed: {test_case['attack_category']} - Status: {response.status_code}")
            
            if success_count == len(test_cases):
                self.log_result("Threat Detection", True, f"{success_count}/{len(test_cases)} tests passed")
                return True
            else:
                self.log_result("Threat Detection", False, f"Only {success_count}/{len(test_cases)} passed")
                return False
                
        except Exception as e:
            self.log_result("Threat Detection", False, str(e))
            return False
    
    def test_real_time_monitoring(self):
        """Test real-time monitoring API"""
        print("\n[TEST 6] Real-Time Monitoring")
        try:
            response = self.session.get(f"{BASE_URL}/api/real-time/network-data")
            if response.status_code == 200:
                try:
                    data = response.json()
                    print(f"  Network connections: {len(data.get('data', []))}")
                    print(f"  Stats: {data.get('stats', {})}")
                    self.log_result("Real-Time Monitoring", True, "Network data API working")
                    return True
                except json.JSONDecodeError:
                    self.log_result("Real-Time Monitoring", False, "Invalid JSON response")
                    return False
            else:
                self.log_result("Real-Time Monitoring", False, f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_result("Real-Time Monitoring", False, str(e))
            return False
    
    def test_api_detection(self):
        """Test API detection endpoint with CSRF token"""
        print("\n[TEST 7] API Detection Endpoint")
        try:
            # First, get a fresh CSRF token
            self.get_csrf_token(f"{BASE_URL}/detect-threat")
            
            if not self.csrf_token:
                self.log_result("API Detection", False, "Could not get CSRF token")
                return False
            
            print(f"  Using CSRF token: {self.csrf_token[:20]}...")
            
            # Test with JSON data including CSRF token
            test_data = {
                'src_ip': '192.168.1.100',
                'dest_ip': '192.168.1.1',
                'dest_port': 22,
                'proto': 'tcp',
                'tool': 'hydra',
                'attack_type': 'bruteforce',
                'description': 'Brute force attack',
                'csrf_token': self.csrf_token  # Add CSRF token to JSON
            }
            
            # Set CSRF token in headers as well (some APIs expect it there)
            self.session.headers.update({
                'X-CSRFToken': self.csrf_token,
                'Content-Type': 'application/json'
            })
            
            response = self.session.post(f"{BASE_URL}/api/detect", json=test_data)
            
            if response.status_code == 200:
                try:
                    result = response.json()
                    print(f"  ✅ Detection result: {result.get('attack_type', 'Unknown')}")
                    print(f"  Confidence: {result.get('confidence', 0)}%")
                    print(f"  Severity: {result.get('severity', 'unknown')}")
                    self.log_result("API Detection", True, "API endpoint working")
                    return True
                except json.JSONDecodeError:
                    print(f"  Response: {response.text[:200]}")
                    self.log_result("API Detection", False, "Invalid JSON response")
                    return False
            else:
                print(f"  Status: {response.status_code}")
                print(f"  Response: {response.text[:200]}")
                
                # Try form data instead of JSON
                print("  Trying form data format...")
                form_data = {
                    'source_ip': '192.168.1.100',
                    'target_ip': '192.168.1.1',
                    'target_port': '22',
                    'protocol': 'tcp',
                    'tool': 'hydra',
                    'attack_category': 'bruteforce',
                    'csrf_token': self.csrf_token
                }
                response = self.session.post(f"{BASE_URL}/api/detect", data=form_data)
                
                if response.status_code == 200:
                    self.log_result("API Detection", True, "API endpoint working with form data")
                    return True
                else:
                    self.log_result("API Detection", False, f"Both formats failed, status: {response.status_code}")
                    return False
                
        except Exception as e:
            self.log_result("API Detection", False, str(e))
            return False
    
    def test_system_info(self):
        """Test system info endpoint"""
        print("\n[TEST 8] System Information")
        try:
            response = self.session.get(f"{BASE_URL}/api/system-info")
            
            if response.status_code == 200:
                try:
                    info = response.json()
                    if info.get('success'):
                        sys_info = info.get('system_info', {})
                        print(f"  CPU Usage: {sys_info.get('cpu', {}).get('usage_percent', 'N/A')}%")
                        print(f"  Memory Usage: {sys_info.get('memory', {}).get('used_percent', 'N/A')}%")
                        self.log_result("System Info", True, "System information retrieved")
                        return True
                    else:
                        self.log_result("System Info", False, info.get('error', 'Unknown error'))
                        return False
                except json.JSONDecodeError:
                    self.log_result("System Info", False, "Invalid JSON response")
                    return False
            else:
                self.log_result("System Info", False, f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_result("System Info", False, str(e))
            return False
    
    def test_detection_history(self):
        """Test detection history endpoint"""
        print("\n[TEST 9] Detection History")
        try:
            response = self.session.get(f"{BASE_URL}/api/detection-history")
            
            if response.status_code == 200:
                try:
                    data = response.json()
                    history_count = len(data.get('history', []))
                    print(f"  Detection history entries: {history_count}")
                    self.log_result("Detection History", True, f"Found {history_count} entries")
                    return True
                except json.JSONDecodeError:
                    self.log_result("Detection History", False, "Invalid JSON response")
                    return False
            else:
                self.log_result("Detection History", False, f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_result("Detection History", False, str(e))
            return False
    
    def test_logout(self):
        """Test logout functionality"""
        print("\n[TEST 10] Logout")
        try:
            response = self.session.get(f"{BASE_URL}/logout")
            
            if response.status_code == 200 or response.status_code == 302:
                self.log_result("Logout", True, "Logout successful")
                return True
            else:
                self.log_result("Logout", False, f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_result("Logout", False, str(e))
            return False
    
    def run_all_tests(self):
        """Run all tests"""
        print("=" * 70)
        print("CYBERSHIELD AI COMPREHENSIVE TEST SUITE (WITH CSRF)")
        print("=" * 70)
        print(f"Testing against: {BASE_URL}")
        print(f"Test Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 70)
        
        # Check if Flask app is running
        try:
            response = requests.get(f"{BASE_URL}/", timeout=5)
            print(f"✅ Flask app detected at {BASE_URL}")
        except:
            print(f"❌ Flask app not running at {BASE_URL}!")
            print("Please start your Flask app first:")
            print("  python application.py")
            return False
        
        # Run all tests
        tests = [
            self.test_database_connection,
            self.test_user_registration,
            self.test_user_login,
            self.test_dashboard_access,
            self.test_threat_detection_endpoint,
            self.test_real_time_monitoring,
            self.test_api_detection,
            self.test_system_info,
            self.test_detection_history,
            self.test_logout
        ]
        
        for test in tests:
            try:
                test()
                time.sleep(0.5)
            except Exception as e:
                print(f"  Test error: {e}")
                import traceback
                traceback.print_exc()
        
        # Print summary
        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        
        passed = sum(1 for r in self.test_results if r['passed'])
        total = len(self.test_results)
        
        print(f"Total Tests: {total}")
        print(f"Passed: {passed}")
        print(f"Failed: {total - passed}")
        print(f"Success Rate: {(passed/total*100):.1f}%")
        
        print("\nDetailed Results:")
        for result in self.test_results:
            status = "✅" if result['passed'] else "❌"
            print(f"  {status} {result['name']}")
            if result['message']:
                print(f"      {result['message']}")
        
        print("=" * 70)
        
        if passed == total:
            print("🎉 ALL TESTS PASSED! Your CyberShield AI system is working perfectly!")
        else:
            print("⚠️  SOME TESTS FAILED. Please review the failures above.")
        
        return passed == total

def main():
    """Main test runner"""
    # Check if BeautifulSoup is installed
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        print("Installing required dependency: beautifulsoup4")
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "beautifulsoup4"])
        from bs4 import BeautifulSoup
    
    tester = CyberShieldTester()
    success = tester.run_all_tests()
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()