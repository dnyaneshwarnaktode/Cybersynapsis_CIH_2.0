#!/usr/bin/env python3
"""
Test script to verify integration between target website and SentinelShield
"""

import json
import os
import time
from datetime import datetime, timezone

# Test the shared events file
EVENTS_FILE = '/shared/events.json'

def test_shared_events():
    """Test that both containers can write to the same events.json file"""
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(EVENTS_FILE), exist_ok=True)
    
    # Test event from SentinelShield
    sentinel_event = {
        'type': 'Test Event from SentinelShield',
        'ip': '192.168.1.100',
        'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
        'details': 'This is a test event from SentinelShield backend',
        'severity': 'MEDIUM',
        'source': 'sentinelshield'
    }
    
    # Test event from target website
    target_event = {
        'type': 'Test Event from Target Website',
        'ip': '192.168.1.101',
        'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'),
        'details': 'This is a test event from target website',
        'severity': 'LOW',
        'source': 'target_website'
    }
    
    # Load existing events
    try:
        with open(EVENTS_FILE, 'r') as f:
            content = f.read().strip()
            events = json.loads(content) if content else []
    except (FileNotFoundError, json.JSONDecodeError):
        events = []
    
    # Add test events
    events.append(sentinel_event)
    events.append(target_event)
    
    # Save events
    with open(EVENTS_FILE, 'w') as f:
        json.dump(events, f, indent=4)
    
    print("✅ Test events written to shared events.json file")
    print(f"📁 File location: {EVENTS_FILE}")
    print(f"📊 Total events: {len(events)}")
    
    # Display recent events
    print("\n📋 Recent events:")
    for event in events[-5:]:  # Show last 5 events
        print(f"  - {event['timestamp']}: {event['type']} (Source: {event['source']})")

if __name__ == "__main__":
    test_shared_events() 