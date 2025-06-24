#!/usr/bin/env python3
"""
Test script to verify the history data endpoint is working correctly.
This script will test the /history-data endpoint and display the results.
"""

import requests
import json
import time

def test_history_data():
    """Test the history data endpoint"""
    base_url = "http://localhost:8080"
    
    # First, we need to login to get a session
    session = requests.Session()
    
    try:
        # Login
        login_data = {
            'username': 'admin',
            'password': 'password123'
        }
        
        print("🔐 Attempting to login...")
        login_response = session.post(f"{base_url}/", data=login_data)
        
        if login_response.status_code == 200:
            print("✅ Login successful")
        else:
            print(f"❌ Login failed with status code: {login_response.status_code}")
            return
        
        # Test the history data endpoint
        print("\n📊 Testing /history-data endpoint...")
        history_response = session.get(f"{base_url}/history-data")
        
        if history_response.status_code == 200:
            print("✅ History data endpoint responded successfully")
            
            data = history_response.json()
            print(f"\n📈 Data received:")
            print(f"  - Requests per minute history: {len(data.get('requests_per_minute_history', []))} entries")
            print(f"  - HTTP status counts: {len(data.get('http_status_counts', {}))} status codes")
            print(f"  - Unique visitors: {data.get('unique_visitor_count', 0)}")
            
            # Show sample data
            if data.get('requests_per_minute_history'):
                print(f"\n📊 Sample requests history:")
                for entry in data['requests_per_minute_history'][:3]:
                    print(f"  - {entry.get('timestamp')}: {entry.get('requests')} requests")
            
            if data.get('http_status_counts'):
                print(f"\n🌐 HTTP Status Codes:")
                for status, count in data['http_status_counts'].items():
                    print(f"  - {status}: {count} requests")
            
            # Test if the data structure is valid for charts
            print(f"\n🔍 Data validation:")
            has_requests_data = bool(data.get('requests_per_minute_history'))
            has_status_data = bool(data.get('http_status_counts'))
            
            print(f"  - Has requests data: {'✅' if has_requests_data else '❌'}")
            print(f"  - Has status data: {'✅' if has_status_data else '❌'}")
            
            if has_requests_data and has_status_data:
                print("🎉 Data structure is valid for charts!")
            else:
                print("⚠️  Some data is missing, but the endpoint is working")
                
        else:
            print(f"❌ History data endpoint failed with status code: {history_response.status_code}")
            print(f"Response: {history_response.text}")
            
    except requests.exceptions.ConnectionError:
        print("❌ Could not connect to the server. Make sure the containers are running.")
        print("   Run: docker-compose up -d")
    except Exception as e:
        print(f"❌ An error occurred: {e}")

if __name__ == "__main__":
    print("🚀 Testing SentinelShield History Data Endpoint")
    print("=" * 50)
    test_history_data()
    print("\n" + "=" * 50)
    print("Test completed!") 