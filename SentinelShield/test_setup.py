#!/usr/bin/env python3
"""
Test script to verify SentinelShield setup
"""

import requests
import time
import json

def test_target_website():
    """Test if target website is accessible"""
    try:
        response = requests.get('http://localhost/', timeout=5)
        print(f"✅ Target website accessible: Status {response.status_code}")
        return True
    except Exception as e:
        print(f"❌ Target website not accessible: {e}")
        return False

def test_dashboard():
    """Test if dashboard is accessible"""
    try:
        response = requests.get('http://localhost:8080/', timeout=5)
        print(f"✅ Dashboard accessible: Status {response.status_code}")
        return True
    except Exception as e:
        print(f"❌ Dashboard not accessible: {e}")
        return False

def test_api_endpoints():
    """Test API endpoints"""
    try:
        # Test health endpoint
        response = requests.get('http://localhost:8080/health', timeout=5)
        print(f"✅ Health endpoint: Status {response.status_code}")
        
        # Test data endpoint
        response = requests.get('http://localhost:8080/data', timeout=5)
        print(f"✅ Data endpoint: Status {response.status_code}")
        
        return True
    except Exception as e:
        print(f"❌ API endpoints not accessible: {e}")
        return False

def simulate_suspicious_activity():
    """Simulate suspicious activity"""
    print("\n🔍 Simulating suspicious activity...")
    
    # Test 1: Rate limiting
    print("Testing rate limiting (60 requests)...")
    for i in range(60):
        try:
            requests.get('http://localhost/', timeout=1)
            if i % 10 == 0:
                print(f"  Sent {i+1} requests...")
        except:
            pass
    
    # Test 2: Suspicious user agent
    print("Testing suspicious user agent...")
    try:
        requests.get('http://localhost/', headers={'User-Agent': 'sqlmap'}, timeout=5)
        print("  Sent request with sqlmap user agent")
    except:
        pass
    
    # Test 3: Suspicious path
    print("Testing suspicious path...")
    try:
        requests.get('http://localhost/../../etc/passwd', timeout=5)
        print("  Sent request to suspicious path")
    except:
        pass

def check_events_file():
    """Check if events.json has been updated"""
    try:
        with open('backend/events.json', 'r') as f:
            events = json.load(f)
            print(f"\n📊 Events file contains {len(events)} events")
            if events:
                print("Recent events:")
                for event in events[-3:]:  # Show last 3 events
                    print(f"  - {event.get('type', 'Unknown')}: {event.get('ip', 'Unknown IP')} at {event.get('timestamp', 'Unknown time')}")
            return len(events) > 0
    except Exception as e:
        print(f"❌ Could not read events.json: {e}")
        return False

def main():
    print("🚀 SentinelShield Setup Test")
    print("=" * 40)
    
    # Test basic connectivity
    target_ok = test_target_website()
    dashboard_ok = test_dashboard()
    api_ok = test_api_endpoints()
    
    if not target_ok:
        print("\n❌ Target website is not accessible. Please check:")
        print("  1. Docker containers are running")
        print("  2. Port 80 is not blocked")
        print("  3. Target website container is healthy")
        return
    
    # Simulate suspicious activity
    simulate_suspicious_activity()
    
    # Wait a bit for processing
    print("\n⏳ Waiting 5 seconds for event processing...")
    time.sleep(5)
    
    # Check results
    events_found = check_events_file()
    
    print("\n" + "=" * 40)
    if events_found:
        print("✅ SUCCESS: Suspicious activity detected and logged!")
    else:
        print("❌ ISSUE: No events detected. Possible problems:")
        print("  1. Log processing threads not running")
        print("  2. NGINX not writing to access.log")
        print("  3. File permissions issues")
        print("  4. Log format mismatch")

if __name__ == "__main__":
    main() 