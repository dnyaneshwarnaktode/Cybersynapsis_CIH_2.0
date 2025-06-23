import time
import random

log_file = "mock_access.log"

user_agents = [
    "Mozilla/5.0", "curl/7.68.0", "sqlmap/1.5.2", 
    "nmap", "python-requests/2.25", "Hydra"
]

def generate_log():
    ip = f"192.168.1.{random.randint(2, 255)}"
    status = random.choice(["200", "403", "404", "500"])
    size = random.randint(200, 1500)
    user_agent = random.choice(user_agents)
    timestamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000")

    log_line = (
        f'{ip} - - [{timestamp}] "GET /login HTTP/1.1" {status} {size} '
        f'"-" "{user_agent}" "-"'
    )

    with open(log_file, "a") as f:
        f.write(log_line + "\n")

print("⏳ Generating mock logs every 2 seconds...")
while True:
    generate_log()
    time.sleep(2)
