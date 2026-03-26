"""
Calculate response time from detection to containment
"""

import sqlite3
from datetime import datetime
import json

def parse_timestamp(ts):
    """Parse various timestamp formats"""
    try:
        # Try ISO format with T
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except:
        try:
            # Try space-separated format
            return datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')
        except:
            return None

def calculate_response_times():
    """Calculate time between alert and response"""
    
    # Get alerts from alerts.db
    alert_conn = sqlite3.connect('alerts.db')
    alert_cursor = alert_conn.cursor()
    alert_cursor.execute("""
        SELECT alert_id, timestamp, attack_type, severity 
        FROM alerts 
        ORDER BY created_at DESC 
        LIMIT 20
    """)
    alerts = alert_cursor.fetchall()
    
    # Get responses from responses.db
    resp_conn = sqlite3.connect('responses.db')
    resp_cursor = resp_conn.cursor()
    resp_cursor.execute("""
        SELECT alert_id, timestamp, action 
        FROM responses 
        ORDER BY created_at DESC 
        LIMIT 20
    """)
    responses = resp_cursor.fetchall()
    
    # Create lookup for responses
    response_times = {}
    for resp in responses:
        response_times[resp[0]] = {
            'timestamp': resp[1],
            'action': resp[2]
        }
    
    print("="*70)
    print("THREAT CONTAINMENT TIME ANALYSIS")
    print("="*70)
    
    response_times_list = []
    
    for alert in alerts:
        alert_id = alert[0]
        alert_time = alert[1]
        attack_type = alert[2]
        severity = alert[3]
        
        if alert_id in response_times:
            resp_time = response_times[alert_id]['timestamp']
            action = response_times[alert_id]['action']
            
            # Parse timestamps
            t1 = parse_timestamp(alert_time)
            t2 = parse_timestamp(resp_time)
            
            if t1 and t2:
                time_diff = (t2 - t1).total_seconds()
                response_times_list.append(time_diff)
                
                print(f"\nAlert: {alert_id}")
                print(f"  Attack: {attack_type} ({severity})")
                print(f"  Detection: {alert_time}")
                print(f"  Response: {resp_time}")
                print(f"  Action: {action}")
                print(f"  ⏱️  Time to contain: {time_diff:.3f} seconds")
    
    if response_times_list:
        avg_time = sum(response_times_list) / len(response_times_list)
        min_time = min(response_times_list)
        max_time = max(response_times_list)
        
        print("\n" + "="*70)
        print("SUMMARY STATISTICS")
        print("="*70)
        print(f"📊 Total responses analyzed: {len(response_times_list)}")
        print(f"⚡ Fastest containment: {min_time:.3f} seconds")
        print(f"🐢 Slowest containment: {max_time:.3f} seconds")
        print(f"📈 Average containment: {avg_time:.3f} seconds")
        
        if avg_time < 0.23:
            print(f"\n✅ PROOF: Average containment time {avg_time:.3f}s is LESS than 0.23 seconds!")
        else:
            print(f"\n⚠️  Average containment: {avg_time:.3f}s")
    
    alert_conn.close()
    resp_conn.close()
    
    return response_times_list

if __name__ == "__main__":
    calculate_response_times()
    