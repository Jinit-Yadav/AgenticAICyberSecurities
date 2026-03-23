"""
Unit Test Runner for CyberShield AI System - Fixed Version
"""
import unittest
import sys
import os

# Add project root and src to path
project_root = r'C:\Users\Lenovo\Desktop\AgenticAICybersecurity\AgenticAICyberSecurities'
sys.path.insert(0, project_root)
sys.path.insert(0, os.path.join(project_root, 'src'))

# Import test modules - using simplified tests
from tests.test_detection_simple import TestDetectionAgent

def run_tests():
    """Run all unit tests"""
    
    # Create test suites
    detection_suite = unittest.TestLoader().loadTestsFromTestCase(TestDetectionAgent)
    
    # Combine suites
    all_tests = unittest.TestSuite([detection_suite])
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(all_tests)
    
    # Print summary
    print("\n" + "="*60)
    print("UNIT TEST SUMMARY")
    print("="*60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    if result.testsRun > 0:
        success_rate = ((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100)
        print(f"Success Rate: {success_rate:.1f}%")
    
    return result.wasSuccessful()

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)