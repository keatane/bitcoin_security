import csv
import signal
import sys
from scapy.all import sniff, IP, TCP
from datetime import datetime
from threading import Lock

BITCOIN_MAGIC = b"\xf9\xbe\xb4\xd9"
lock = Lock()

# Track messages by connection hash
connections = {}

def get_connection_hash(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return None
    ip_src, port_src = pkt[IP].src, pkt[TCP].sport
    ip_dst, port_dst = pkt[IP].dst, pkt[TCP].dport
    ep1 = (ip_src, port_src)
    ep2 = (ip_dst, port_dst)
    if ep1 <= ep2:
        return f"{ep1[0]}:{ep1[1]}-{ep2[0]}:{ep2[1]}", ep1, ep2
    else:
        return f"{ep2[0]}:{ep2[1]}-{ep1[0]}:{ep1[1]}", ep2, ep1

def extract_bitcoin_message_name(payload):
    if payload.startswith(BITCOIN_MAGIC) and len(payload) > 24:
        cmd_bytes = payload[4:16]
        cmd = cmd_bytes.replace(b"\x00", b"").decode("ascii", errors="ignore")
        return cmd
    return None

def packet_handler(pkt):
    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        payload = bytes(pkt[TCP].payload)
        msg = extract_bitcoin_message_name(payload)
        if not msg:
            return

        hash_key, ep1, ep2 = get_connection_hash(pkt)
        ip_src, port_src = pkt[IP].src, pkt[TCP].sport

        direction = ">" if (ip_src, port_src) == ep1 else "<"
        full_msg = f"{direction}{msg}"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with lock:
            if hash_key not in connections:
                connections[hash_key] = {
                    "timestamp": timestamp,
                    "messages": []
                }
            connections[hash_key]["messages"].append(full_msg)
            print(f"[{timestamp}] {hash_key} {full_msg}")

def shutdown_handler(sig, frame):
    print("\nSaving captured Bitcoin messages to bitcoin_messages.csv...")
    with open("bitcoin_messages.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp_first_seen", "connection_hash", "messages"])
        with lock:
            for hash_key, data in connections.items():
                writer.writerow([
                    data["timestamp"],
                    hash_key,
                    ";".join(data["messages"])
                ])
    print("Done. Exiting.")
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown_handler)

print("Starting live capture on interface 'ens3'... Press Ctrl+C to stop and save.")
sniff(iface="ens3", prn=packet_handler, store=False)
