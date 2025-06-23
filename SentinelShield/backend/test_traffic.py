import requests
import time

url = "http://localhost:8000/"
headers = {
    "User-Agent": "python-requests/2.31.0"
}

for i in range(100):
    try:
        r = requests.get(url, headers=headers)
        print(f"{i+1}: Status {r.status_code}")
    except Exception as e:
        print("Error:", e)
    time.sleep(0.2)  # Reduced from 1 sec to 0.2 sec (5x faster)
