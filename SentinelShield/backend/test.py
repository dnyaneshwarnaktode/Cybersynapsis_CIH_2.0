import requests
import time

for i in range(30):
    headers = {'User-Agent': 'python-requests/2.31.0'}
    r = requests.get('http://localhost:8080/', headers=headers)  # Point to any URL you're monitoring
    time.sleep(1)  # Fast traffic
