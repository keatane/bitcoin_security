import csv
import statistics
import threading
from scapy.all import *
from scapy.layers.inet import IP, TCP
from collections import defaultdict
from datetime import datetime
import matplotlib.pyplot as plt

# Bitcoin protocol magic bytes (mainnet)
BITCOIN_MAGIC = b"\xf9\xbe\xb4\xd9"


# returns a consistent hash identifier for a TCP/IP connection (bidirectional)
def gethash(p):
    if not p.haslayer(IP) or not p.haslayer(TCP):
        # fallback for non-IP/TCP
        try:
            return f"OTHER {p.src}_{p.dst}"
        except Exception:
            return None
    ip_src, port_src = p[IP].src, p[TCP].sport
    ip_dst, port_dst = p[IP].dst, p[TCP].dport
    # create a canonical key sorted by (ip,port)
    endpoint1 = (ip_src, port_src)
    endpoint2 = (ip_dst, port_dst)
    if endpoint1 <= endpoint2:
        return f"{endpoint1[0]}:{endpoint1[1]}-{endpoint2[0]}:{endpoint2[1]}"
    else:
        return f"{endpoint2[0]}:{endpoint2[1]}-{endpoint1[0]}:{endpoint1[1]}"


# Extract Bitcoin command name from TCP payload
def extract_bitcoin_message_name(payload):
    if payload.startswith(BITCOIN_MAGIC) and len(payload) > 24:
        cmd_bytes = payload[4:16]
        cmd = cmd_bytes.replace(b"\x00", b"").decode("ascii", errors="ignore")
        return cmd
    return None


# Thread-safe connection storage
lock = threading.Lock()
connections = defaultdict(
    lambda: {
        "start_timestamp": None,
        "end_timestamp": None,
        "sent_size": 0,
        "received_size": 0,
        "messages": [],  # list of (direction_symbol, message)
        "client": None,  # tuple (ip, port) of initiator
        "server": None,  # tuple (ip, port) of responder
    }
)


# Worker function for processing packet chunks
def process_packets(packets_chunk):
    for pkt in packets_chunk:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue
        key = gethash(pkt)
        ip_src, port_src = pkt[IP].src, pkt[TCP].sport
        ip_dst, port_dst = pkt[IP].dst, pkt[TCP].dport
        flags = pkt[TCP].flags
        payload = bytes(pkt[TCP].payload)

        with lock:
            conn = connections[key]
            # On first SYN (without ACK), record endpoints
            if flags == "S":
                conn["start_timestamp"] = conn["start_timestamp"] or pkt.time
                conn["client"] = (ip_src, port_src)
                conn["server"] = (ip_dst, port_dst)
            # On FIN or RST, set end timestamp
            if flags in ("F", "R", "FA", "RA"):
                conn["end_timestamp"] = pkt.time
            # Determine direction: '>' if from client, '<' if from server
            direction = None
            if conn["client"] == (ip_src, port_src):
                conn["sent_size"] += len(payload)
                direction = ">"
            else:
                conn["received_size"] += len(payload)
                direction = "<"
            # Extract and record Bitcoin messages with direction prefix
            msg = extract_bitcoin_message_name(payload)
            if msg:
                conn["messages"].append(f"{direction}{msg}")


# Utility to chunk packets
def chunk_packets(reader, chunk_size=1000):
    chunk = []
    for pkt in reader:
        chunk.append(pkt)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk


# --- Main execution ---
packets = PcapReader("obstacled_traffic.pcap")
threads = []
num_threads = 8
for packet_chunk in chunk_packets(packets, 1000):
    for sub in [packet_chunk[i::num_threads] for i in range(num_threads)]:
        t = threading.Thread(target=process_packets, args=(sub,))
        t.start()
        threads.append(t)
for t in threads:
    t.join()
packets.close()

# --- CSV and Analysis ---
csv_filename = "connection_times.csv"
header = [
    "id",
    "hash",
    "start_time",
    "start_epoch",
    "end_time",
    "end_epoch",
    "duration_s",
    "sent_size",
    "received_size",
    "messages",
]
connection_durations = []
rows = []
for idx, (key, info) in enumerate(connections.items(), start=1):
    start = info["start_timestamp"]
    end = info["end_timestamp"]
    duration = end - start if start and end else None
    if duration is not None:
        connection_durations.append(duration)
    rows.append(
        [
            idx,
            key,
            (
                datetime.fromtimestamp(float(start)).strftime("%Y-%m-%d %H:%M:%S")
                if start
                else None
            ),
            float(start) if start else None,
            (
                datetime.fromtimestamp(float(end)).strftime("%Y-%m-%d %H:%M:%S")
                if end
                else None
            ),
            float(end) if end else None,
            round(duration, 5) if duration else None,
            info["sent_size"],
            info["received_size"],
            ";".join(info["messages"]),
        ]
    )

# Write CSV
table = [header] + rows
with open(csv_filename, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerows(table)
print(f"Saved CSV to {csv_filename}")

# Stats
avg = statistics.mean(connection_durations) if connection_durations else 0
var = statistics.variance(connection_durations) if len(connection_durations) > 1 else 0
print(f"Average Duration: {avg:.5f}s, Variance: {var:.5f}s^2")


# Plot histogram
def generate_histogram(durations):
    if durations:
        plt.figure(figsize=(10, 6))
        plt.hist(durations, bins=100, edgecolor="black")
        plt.title("Connection Duration Histogram")
        plt.xlabel("Seconds")
        plt.ylabel("Frequency")
        plt.grid(True)
        plt.savefig("plot.png")
        plt.show()
    else:
        print("No durations to plot.")


generate_histogram(connection_durations)
