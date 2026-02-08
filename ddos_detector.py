from scapy.all import sniff, IP
from collections import defaultdict
import time
import sys

ip_counter = defaultdict(int)
blocked_ips = set()

PACKET_THRESHOLD = 20
RUN_DURATION = 10   
BLACKLIST_FILE = "blacklistt.txt"

start_time = time.time()

def block_ip(ip):
    blocked_ips.add(ip)
    with open(BLACKLIST_FILE, "a") as f:
        f.write(ip + "\n")
    print(f"[BLOCKED] {ip} added to blacklistt")

def packet_handler(packet):
    if IP in packet:
        src_ip = packet[IP].src

        if src_ip in blocked_ips:
            return

        ip_counter[src_ip] += 1

def stop_filter(packet):
    return time.time() - start_time >= RUN_DURATION

print("🛡️ DDoS Detection Tool Started...")
print("Monitoring network traffic for 10 seconds...\n")

sniff(prn=packet_handler, stop_filter=stop_filter, store=False)

print("\n--- Traffic Analysis ---")
for ip, count in ip_counter.items():
    print(f"IP: {ip} | Packets: {count}")

    if count >= PACKET_THRESHOLD:
        print(f"[ALERT] DDoS suspected from {ip}")
        block_ip(ip)

print("\n✅ Monitoring stopped after 10 seconds.")
