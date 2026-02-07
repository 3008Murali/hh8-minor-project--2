import time
import random
from collections import defaultdict, deque

TIME_WINDOW = 10          
REQUEST_THRESHOLD = 5     
RUN_DURATION = 5          

ip_requests = defaultdict(deque)
blacklist = set()
blocked_logged = set()  

SIMULATED_IPS = [
    "192.168.1.10",
    "192.168.1.20",
    "192.168.1.30",
    "10.0.0.5"
]

def get_fake_packet():
    """
    Simulates incoming network traffic.
    One IP appears more frequently to mimic an attack.
    """
    return random.choice(SIMULATED_IPS + ["192.168.1.10"] * 5)

def detect_ddos(ip):
    current_time = time.time()
    requests = ip_requests[ip]

    while requests and current_time - requests[0] > TIME_WINDOW:
        requests.popleft()

    requests.append(current_time)

    if len(requests) > REQUEST_THRESHOLD and ip not in blacklist:
        blacklist.add(ip)
        print(f"[ALERT] Potential DDoS detected from {ip}")
        print(f"[ACTION] {ip} added to blacklist\n")

def main():
    print("Starting DDoS Detection Tool (Educational Mode)")
    print("Monitoring simulated traffic...\n")

    start_time = time.time()

    while time.time() - start_time < RUN_DURATION:
        src_ip = get_fake_packet()

        if src_ip in blacklist:
            if src_ip not in blocked_logged:
                print(f"[BLOCKED] Traffic from blacklisted IP: {src_ip}")
                blocked_logged.add(src_ip)
        else:
            detect_ddos(src_ip)

        time.sleep(0.1)

    print("\nExecution stopped after 5 seconds.")
    print("Blacklisted IPs:", blacklist)

if __name__ == "__main__":
    main()







