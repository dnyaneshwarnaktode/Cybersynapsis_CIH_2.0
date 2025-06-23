#!/usr/bin/env python3
"""
Simple debug script for SentinelShield setup
"""

import os
import json
import time

def check_files():
    """Check if required files exist"""
    print("🔍 Checking required files...")
    
    files_to_check = [
        'backend/events.json',
        'backend/logs.json',
        'backend/data.json'
    ]
    
    for file_path in files_to_check:
        if os.path.exists(file_path):
            print(f"✅ {file_path} exists")
            try:
                with open(file_path, 'r') as f:
                    content = f.read().strip()
                    if content:
                        data = json.loads(content)
                        if isinstance(data, list):
                            print(f"   Contains {len(data)} items")
                        else:
                            print(f"   Contains data: {type(data)}")
                    else:
                        print("   Empty file")
            except Exception as e:
                print(f"   Error reading: {e}")
        else:
            print(f"❌ {file_path} does not exist")

def check_containers():
    """Check if containers are running"""
    print("\n🐳 Checking containers...")
    
    # This is a simple check - in a real scenario you'd use docker API
    print("Please run: docker ps")
    print("Look for these containers:")
    print("  - sentinelshield-nginx-waf")
    print("  - sentinelshield-app") 
    print("  - target-website")

def check_ports():
    """Check if ports are accessible"""
    print("\n🔌 Checking ports...")
    print("Please check if these ports are accessible:")
    print("  - Port 80: Target website (http://localhost/)")
    print("  - Port 8080: Dashboard (http://localhost:8080/)")

def simulate_manual_test():
    """Manual test instructions"""
    print("\n🧪 Manual Testing Instructions:")
    print("1. Open a web browser")
    print("2. Go to http://localhost/ (should show target website)")
    print("3. Go to http://localhost:8080/ (should show login page)")
    print("4. Login with admin/password123")
    print("5. Check the dashboard for events")

def check_events_after_test():
    """Check events after manual test"""
    print("\n📊 After manual testing, check events.json:")
    try:
        with open('backend/events.json', 'r') as f:
            events = json.load(f)
            print(f"Events found: {len(events)}")
            if events:
                print("Recent events:")
                for event in events[-3:]:
                    print(f"  - {event.get('type', 'Unknown')}: {event.get('ip', 'Unknown')}")
    except Exception as e:
        print(f"Error reading events: {e}")

def main():
    print("🚀 SentinelShield Debug Setup")
    print("=" * 40)
    
    check_files()
    check_containers()
    check_ports()
    simulate_manual_test()
    
    print("\n" + "=" * 40)
    print("After running manual tests, run this script again to check events.")
    
    # Check events if they exist
    check_events_after_test()

if __name__ == "__main__":
    main() 