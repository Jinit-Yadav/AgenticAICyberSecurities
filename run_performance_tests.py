"""
Performance Testing Script
"""
import requests
import time
import statistics
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

BASE_URL = "http://localhost:5000"

def test_response_time():
    """Measure response times for various operations"""
    print("\n" + "="*60)
    print("PERFORMANCE TESTS - RESPONSE TIME")
    print("="*60)
    
    session = requests.Session()
    session.post(f"{BASE_URL}/login", data={
        'username': 'testuser',
        'password': 'testpass123'
    })
    
    test_cases = [
        ("Single threat detection", 
         lambda: session.post(f"{BASE_URL}/detect-threat", data={
             'source_ip': '192.168.1.100',
             'target_ip': '10.0.0.1',
             'attack_category': 'port_scan'
         })),
        
        ("Real-time dashboard", 
         lambda: session.get(f"{BASE_URL}/api/real-time/stats")),
        
        ("Database query", 
         lambda: session.get(f"{BASE_URL}/api/threats/history"))
    ]
    
    results = []
    for test_name, test_func in test_cases:
        times = []
        for i in range(10):  # Run 10 iterations
            start = time.time()
            response = test_func()
            elapsed = time.time() - start
            times.append(elapsed)
        
        avg_time = statistics.mean(times) * 1000  # Convert to ms
        min_time = min(times) * 1000
        max_time = max(times) * 1000
        
        results.append({
            'test': test_name,
            'avg_ms': avg_time,
            'min_ms': min_time,
            'max_ms': max_time
        })
        
        print(f"\n{test_name}:")
        print(f"  Average: {avg_time:.2f} ms")
        print(f"  Min: {min_time:.2f} ms")
        print(f"  Max: {max_time:.2f} ms")
    
    return results

def test_batch_processing():
    """Test batch log processing"""
    print("\n" + "="*60)
    print("PERFORMANCE TESTS - BATCH PROCESSING")
    print("="*60)
    
    # Create test logs
    test_logs = []
    for i in range(1000):
        test_logs.append({
            'source_ip': f'10.0.0.{i % 255}',
            'target_ip': '192.168.1.1',
            'timestamp': time.time(),
            'event': 'SYN packet' if i % 10 == 0 else 'normal traffic'
        })
    
    # Save to file
    with open('test_logs_1000.json', 'w') as f:
        json.dump(test_logs, f)
    
    # Test upload
    session = requests.Session()
    session.post(f"{BASE_URL}/login", data={
        'username': 'testuser',
        'password': 'testpass123'
    })
    
    with open('test_logs_1000.json', 'rb') as f:
        start = time.time()
        response = session.post(f"{BASE_URL}/upload-logs", 
                                files={'file': f})
        elapsed = time.time() - start
    
    print(f"Batch processing 1000 logs:")
    print(f"  Time: {elapsed:.2f} seconds")
    print(f"  Throughput: {1000/elapsed:.2f} logs/second")
    
    return elapsed

def test_load():
    """Load testing with concurrent users"""
    print("\n" + "="*60)
    print("PERFORMANCE TESTS - LOAD TESTING")
    print("="*60)
    
    def make_request(user_id):
        session = requests.Session()
        session.post(f"{BASE_URL}/login", data={
            'username': f'testuser{user_id}',
            'password': 'testpass123'
        })
        
        start = time.time()
        response = session.get(f"{BASE_URL}/dashboard")
        elapsed = time.time() - start
        
        return elapsed, response.status_code
    
    load_levels = [10, 50, 100]
    results = []
    
    for users in load_levels:
        print(f"\nTesting with {users} concurrent users...")
        
        with ThreadPoolExecutor(max_workers=users) as executor:
            futures = [executor.submit(make_request, i) for i in range(users)]
            
            response_times = []
            errors = 0
            
            for future in as_completed(futures):
                elapsed, status = future.result()
                response_times.append(elapsed)
                if status != 200:
                    errors += 1
            
            avg_time = statistics.mean(response_times) * 1000
            error_rate = (errors / users) * 100
            
            results.append({
                'users': users,
                'avg_response_ms': avg_time,
                'error_rate': error_rate
            })
            
            print(f"  Avg Response: {avg_time:.2f} ms")
            print(f"  Error Rate: {error_rate:.1f}%")
    
    return results

if __name__ == "__main__":
    print("Starting Performance Tests...")
    
    # Run tests
    response_times = test_response_time()
    batch_time = test_batch_processing()
    load_results = test_load()
    
    # Print summary
    print("\n" + "="*60)
    print("PERFORMANCE TEST SUMMARY")
    print("="*60)
    
    all_passed = True
    
    # Check response time thresholds
    for test in response_times:
        threshold = 2000 if "threat" in test['test'] else 500
        if test['avg_ms'] > threshold:
            print(f"❌ FAIL: {test['test']} - {test['avg_ms']:.2f}ms > {threshold}ms")
            all_passed = False
        else:
            print(f"✅ PASS: {test['test']} - {test['avg_ms']:.2f}ms")
    
    # Check batch processing
    if batch_time > 20:
        print(f"❌ FAIL: Batch processing - {batch_time:.2f}s > 20s")
        all_passed = False
    else:
        print(f"✅ PASS: Batch processing - {batch_time:.2f}s")
    
    # Check load test
    for load in load_results:
        if load['error_rate'] > 1:
            print(f"❌ FAIL: Load test with {load['users']} users - error rate {load['error_rate']}%")
            all_passed = False
        else:
            print(f"✅ PASS: Load test with {load['users']} users")
    
    if all_passed:
        print("\n✅ ALL PERFORMANCE TESTS PASSED")
    else:
        print("\n❌ SOME PERFORMANCE TESTS FAILED")