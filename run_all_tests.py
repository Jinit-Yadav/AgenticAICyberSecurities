"""
Master Test Runner for CyberShield AI System
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
    
    result = subprocess.run([sys.executable, script_name], 
                           capture_output=True, 
                           text=True)
    
    print(result.stdout)
    if result.stderr:
        print("ERRORS:")
        print(result.stderr)
    
    return result.returncode == 0

def main():
    """Run all test suites"""
    print("="*60)
    print("CYBERSHIELD AI TEST SUITE")
    print("="*60)
    print("Starting comprehensive testing...")
    
    # Check if Flask app is running
    import requests
    try:
        requests.get('http://localhost:5000', timeout=2)
        print("✅ Flask app detected")
    except:
        print("❌ Flask app not running!")
        print("Please start the Flask app first:")
        print("python application.py")
        sys.exit(1)
    
    # Test order
    tests = [
        'run_unit_tests.py',
        'run_integration_tests.py',
        'run_performance_tests.py',
        'run_security_tests.py',
        'run_edge_tests.py'
    ]
    
    results = {}
    
    for test in tests:
        if os.path.exists(test):
            success = run_test_script(test)
            results[test] = success
        else:
            print(f"⚠️  Test file not found: {test}")
            results[test] = False
    
    # Print final summary
    print("\n" + "="*60)
    print("FINAL TEST SUMMARY")
    print("="*60)
    
    all_passed = True
    for test, passed in results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} - {test}")
        if not passed:
            all_passed = False
    
    print("\n" + "="*60)
    if all_passed:
        print("🎉 ALL TESTS PASSED!")
        print("System is ready for deployment!")
    else:
        print("⚠️  SOME TESTS FAILED")
        print("Please review the failures above")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)