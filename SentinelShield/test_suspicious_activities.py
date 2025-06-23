#!/usr/bin/env python3
"""
Test script to demonstrate suspicious activities and show what gets logged
"""

import requests
import time
import json
import os
from datetime import datetime

# Test URLs
BASE_URL = "http://localhost"
DASHBOARD_URL = "http://localhost:8080"

def test_suspicious_activities():
    """Test various suspicious activities and show what gets logged"""
    
    print("🚨 TESTING SUSPICIOUS ACTIVITIES ON TARGET WEBSITE")
    print("=" * 60)
    
    # 1. Test SQL Injection Attempts
    print("\n1️⃣ TESTING SQL INJECTION ATTEMPTS:")
    sql_injection_urls = [
        f"{BASE_URL}/?id=1'OR'1'='1",
        f"{BASE_URL}/?user=admin'--",
        f"{BASE_URL}/?search=1=1",
        f"{BASE_URL}/?query=UNION SELECT * FROM users",
        f"{BASE_URL}/?param=DROP TABLE users"
    ]
    
    for url in sql_injection_urls:
        try:
            response = requests.get(url, timeout=5)
            print(f"   ✅ SQL Injection: {url}")
            print(f"      Status: {response.status_code}")
        except Exception as e:
            print(f"   ❌ SQL Injection: {url} - Error: {e}")
    
    time.sleep(2)
    
    # 2. Test XSS Attempts
    print("\n2️⃣ TESTING XSS ATTEMPTS:")
    xss_urls = [
        f"{BASE_URL}/?input=<script>alert('xss')</script>",
        f"{BASE_URL}/?param=javascript:alert('xss')",
        f"{BASE_URL}/?data=onerror=alert('xss')",
        f"{BASE_URL}/?x=<img src=x onerror=alert('xss')>"
    ]
    
    for url in xss_urls:
        try:
            response = requests.get(url, timeout=5)
            print(f"   ✅ XSS Attempt: {url}")
            print(f"      Status: {response.status_code}")
        except Exception as e:
            print(f"   ❌ XSS Attempt: {url} - Error: {e}")
    
    time.sleep(2)
    
    # 3. Test Suspicious Paths
    print("\n3️⃣ TESTING SUSPICIOUS PATHS:")
    suspicious_paths = [
        f"{BASE_URL}/admin",
        f"{BASE_URL}/wp-admin",
        f"{BASE_URL}/phpmyadmin",
        f"{BASE_URL}/config",
        f"{BASE_URL}/.env",
        f"{BASE_URL}/backup",
        f"{BASE_URL}/shell",
        f"{BASE_URL}/cmd"
    ]
    
    for path in suspicious_paths:
        try:
            response = requests.get(path, timeout=5)
            print(f"   ✅ Suspicious Path: {path}")
            print(f"      Status: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Suspicious Path: {path} - Error: {e}")
    
    time.sleep(2)
    
    # 4. Test Suspicious User Agents
    print("\n4️⃣ TESTING SUSPICIOUS USER AGENTS:")
    suspicious_agents = [
        "sqlmap/1.0",
        "nmap/7.80",
        "nikto/2.1.6",
        "curl/7.68.0",
        "python-requests/2.25.1",
        "Burp Suite Professional",
        "OWASP ZAP"
    ]
    
    for agent in suspicious_agents:
        try:
            headers = {'User-Agent': agent}
            response = requests.get(f"{BASE_URL}/", headers=headers, timeout=5)
            print(f"   ✅ Suspicious User-Agent: {agent}")
            print(f"      Status: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Suspicious User-Agent: {agent} - Error: {e}")
    
    time.sleep(2)
    
    # 5. Test Rate Limiting (Multiple rapid requests)
    print("\n5️⃣ TESTING RATE LIMITING:")
    print("   Making 60 rapid requests to trigger rate limiting...")
    
    for i in range(60):
        try:
            response = requests.get(f"{BASE_URL}/", timeout=5)
            if i % 10 == 0:
                print(f"      Request {i+1}/60 - Status: {response.status_code}")
        except Exception as e:
            print(f"      Request {i+1}/60 - Error: {e}")
    
    time.sleep(2)
    
    # 6. Test Unauthorized Access
    print("\n6️⃣ TESTING UNAUTHORIZED ACCESS:")
    protected_pages = [
        f"{BASE_URL}/",
        f"{BASE_URL}/how-it-works",
        f"{BASE_URL}/team"
    ]
    
    for page in protected_pages:
        try:
            response = requests.get(page, timeout=5)
            print(f"   ✅ Unauthorized Access: {page}")
            print(f"      Status: {response.status_code}")
        except Exception as e:
            print(f"   ❌ Unauthorized Access: {page} - Error: {e}")
    
    time.sleep(2)
    
    # 7. Test Login Attempts
    print("\n7️⃣ TESTING LOGIN ATTEMPTS:")
    try:
        response = requests.post(f"{BASE_URL}/login", data={'username': 'test', 'password': 'test'}, timeout=5)
        print(f"   ✅ Login Attempt: POST to /login")
        print(f"      Status: {response.status_code}")
    except Exception as e:
        print(f"   ❌ Login Attempt: Error: {e}")
    
    print("\n" + "=" * 60)
    print("🎯 ALL SUSPICIOUS ACTIVITIES COMPLETED!")
    print("📊 Check the events.json file and SentinelShield dashboard for logged events")

def check_events_file():
    """Check what events were logged"""
    print("\n📋 CHECKING LOGGED EVENTS:")
    print("=" * 60)
    
    events_file = "/shared/events.json"
    
    try:
        if os.path.exists(events_file):
            with open(events_file, 'r') as f:
                content = f.read().strip()
                events = json.loads(content) if content else []
            
            print(f"📁 Events file: {events_file}")
            print(f"📊 Total events logged: {len(events)}")
            
            if events:
                print("\n🔍 RECENT SUSPICIOUS EVENTS:")
                for i, event in enumerate(events[-10:], 1):  # Show last 10 events
                    print(f"\n{i}. {event.get('type', 'Unknown')}")
                    print(f"   📅 Time: {event.get('timestamp', 'Unknown')}")
                    print(f"   🌐 IP: {event.get('ip', 'Unknown')}")
                    print(f"   ⚠️  Severity: {event.get('severity', 'Unknown')}")
                    print(f"   📝 Details: {event.get('details', 'No details')}")
                    print(f"   🔧 Source: {event.get('source', 'Unknown')}")
            else:
                print("📭 No events found in the file")
        else:
            print(f"❌ Events file not found: {events_file}")
            
    except Exception as e:
        print(f"❌ Error reading events file: {e}")

if __name__ == "__main__":
    test_suspicious_activities()
    time.sleep(5)  # Wait for events to be processed
    check_events_file() 