"""
Master Test Runner for CyberShield AI System - Fixed for Windows
"""
import subprocess
import sys
import os
import time

def run_test_script(script_name):
    """Run a test script and return success status"""
    print(f"\n{'='*60}")
    print(f"RUNNING: {script_name}")
    print('='*60)
    
    # Set UTF-8 encoding for the subprocess
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    
    result = subprocess.run([sys.executable, script_name], 
                           capture_output=True, 
                           text=True,
                           env=env)
    
    # Print output without Unicode errors
    try:
        print(result.stdout.encode('ascii', errors='ignore').decode('ascii'))
    except:
        print(result.stdout)
    
    if result.stderr:
        print("ERRORS:")
        try:
            print(result.stderr.encode('ascii', errors='ignore').decode('ascii'))
        except:
            print(result.stderr)
    
    return result.returncode == 0

def main():
    """Run all test suites"""
    print("="*60)
    print("CYBERSHIELD AI TEST SUITE (FIXED VERSION)")
    print("="*60)
    print("Starting comprehensive testing...")
    
    # Check if Flask app is running
    import requests
    try:
        requests.get('http://localhost:5000', timeout=2)
        print("[OK] Flask app detected")
    except:
        print("[ERROR] Flask app not running!")
        print("Please start the Flask app first:")
        print("python application.py")
        sys.exit(1)
    
    # Test order
    tests = [
        'run_unit_tests_fixed.py',
        'run_integration_tests_fixed.py',
        'run_performance_tests_fixed.py',
        'run_security_tests_fixed.py',
        'run_edge_tests_fixed.py'
    ]
    
    results = {}
    
    for test in tests:
        if os.path.exists(test):
            success = run_test_script(test)
            results[test] = success
        else:
            print(f"[WARNING] Test file not found: {test}")
            results[test] = False
    
    # Print final summary
    print("\n" + "="*60)
    print("FINAL TEST SUMMARY")
    print("="*60)
    
    all_passed = True
    for test, passed in results.items():
        status = "[PASS]" if passed else "[FAIL]"
        print(f"{status} - {test}")
        if not passed:
            all_passed = False
    
    print("\n" + "="*60)
    if all_passed:
        print("[SUCCESS] ALL TESTS PASSED!")
        print("System is ready for deployment!")
    else:
        print("[WARNING] SOME TESTS FAILED")
        print("Please review the failures above")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)