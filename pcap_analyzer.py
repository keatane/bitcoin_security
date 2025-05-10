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

# Fixed-size slot tracking
NUM_SLOTS = 30
slots = [None] * NUM_SLOTS  # Holds active connection hashes
hash_to_slot = {}           # Maps hash to slot index
slot_counter = 0            # Global counter to track next available ID

# Returns a consistent hash identifier for a TCP/IP connection (bidirectional)
def gethash(p):
    if not p.haslayer(IP) or not p.haslayer(TCP):
        try:
            return f"OTHER {p.src}_{p.dst}"
        except Exception:
            return None
    ip_src, port_src = p[IP].src, p[TCP].sport
    ip_dst, port_dst = p[IP].dst, p[TCP].dport
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
        "messages": [],
        "client": None,
        "server": None,
    }
)

# Allocates a slot for a new connection and returns the index
def allocate_slot(hash_key):
    global slot_counter
    for i in range(NUM_SLOTS):
        if slots[i] is None:
            slots[i] = hash_key
            hash_to_slot[hash_key] = i
            slot_counter = max(slot_counter, i + 1)  # Track the highest slot index
            return i
    return None  # No available slot

# Releases a slot for a connection
def release_slot(hash_key):
    idx = hash_to_slot.get(hash_key)
    if idx is not None:
        slots[idx] = None
        del hash_to_slot[hash_key]

# Worker function for processing packet chunks
def process_packets(packets_chunk):
    for pkt in packets_chunk:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue
        key = gethash(pkt)
        if key is None:
            continue
        ip_src, port_src = pkt[IP].src, pkt[TCP].sport
        ip_dst, port_dst = pkt[IP].dst, pkt[TCP].dport
        flags = pkt[TCP].flags
        payload = bytes(pkt[TCP].payload)

        with lock:
            conn = connections[key]

            # Handle SYN
            if flags == "S":
                if conn["client"] is None:
                    conn["client"] = (ip_src, port_src)
                    conn["server"] = (ip_dst, port_dst)
                if conn["start_timestamp"] is None:
                    conn["start_timestamp"] = pkt.time
                if key not in hash_to_slot:
                    allocate_slot(key)

            # Handle FIN/RST
            if flags in ("F", "R", "FA", "RA"):
                conn["end_timestamp"] = pkt.time
                release_slot(key)

            # Determine direction ('>' for sent, '<' for received)
            direction = None
            if conn["client"] == (ip_src, port_src):
                conn["sent_size"] += len(payload)
                direction = ">"
            else:
                conn["received_size"] += len(payload)
                direction = "<"

            # Extract Bitcoin messages and record them
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
if len(sys.argv) < 2:
    print("Usage: python pcap_analyzer.py <pcap_file>")
    sys.exit(1)

pcap_file = sys.argv[1]
packets = PcapReader(pcap_file)
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
for key, info in connections.items():
    # if key not in hash_to_slot:
    #     continue  # Skip connections that never got an ID (i.e., no SYN or no valid slot)
    idx = hash_to_slot.get(key,None)
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
