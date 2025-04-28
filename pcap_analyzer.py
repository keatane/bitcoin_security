import csv
import statistics
import threading
from scapy.all import *
from scapy.layers.inet import IP, TCP
from collections import defaultdict
from datetime import datetime
import matplotlib.pyplot as plt

# Use a lock for safe dictionary access
lock = threading.Lock()

connections = defaultdict(lambda: {
    'start_timestamp': None,
    'end_timestamp': None,
    'sent_size': 0,
    'received_size': 0,
    'messages': set()
})

# Bitcoin protocol magic bytes (mainnet)
BITCOIN_MAGIC = b'\xf9\xbe\xb4\xd9'

def extract_bitcoin_message_name(payload):
    """Extract the Bitcoin protocol command name from TCP payload."""
    if payload.startswith(BITCOIN_MAGIC) and len(payload) > 24:
        command_bytes = payload[4:16]
        command = command_bytes.replace(b'\x00', b'').decode('ascii', errors='ignore')
        return command
    return None

# Worker function for each thread
def process_packets(packets_chunk):
    for pkt in packets_chunk:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            port_src = pkt[TCP].sport
            port_dst = pkt[TCP].dport
            payload = bytes(pkt[TCP].payload)

            connection_id = (ip_src, port_src, ip_dst, port_dst)

            # For reverse (incoming) traffic
            reverse_connection_id = (ip_dst, port_dst, ip_src, port_src)

            with lock:
                if pkt[TCP].flags == "S":  # SYN packet
                    connections[connection_id]['start_timestamp'] = pkt.time
                if pkt[TCP].flags in ("R", "F", "RA", "FA"):  # RST or FIN
                    connections[connection_id]['end_timestamp'] = pkt.time

                # Update sent and received sizes
                if (ip_src, port_src, ip_dst, port_dst) in connections:
                    connections[(ip_src, port_src, ip_dst, port_dst)]['sent_size'] += len(payload)
                elif (ip_dst, port_dst, ip_src, port_src) in connections:
                    connections[(ip_dst, port_dst, ip_src, port_src)]['received_size'] += len(payload)

                # Try to extract Bitcoin message names
                message_name = extract_bitcoin_message_name(payload)
                if message_name:
                    if connection_id in connections:
                        connections[connection_id]['messages'].add(message_name)
                    elif reverse_connection_id in connections:
                        connections[reverse_connection_id]['messages'].add(message_name)

def chunk_packets(reader, chunk_size=1000):
    """Yield chunks of packets from PcapReader."""
    chunk = []
    for pkt in reader:
        chunk.append(pkt)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk

# --- Main execution ---
packets = PcapReader("legit_traffic.pcap")

threads = []
num_threads = 8  # Adjust depending on your CPU

for packet_chunk in chunk_packets(packets, chunk_size=1000):
    split_chunks = [packet_chunk[i::num_threads] for i in range(num_threads)]

    for sub_chunk in split_chunks:
        t = threading.Thread(target=process_packets, args=(sub_chunk,))
        t.start()
        threads.append(t)

for t in threads:
    t.join()

packets.close()

# --- CSV and analysis ---
csv_filename = "connection_times.csv"
header = ["id", "ipsrc", "portsrc", "ipdst", "portdst", "timesyn", "timerst_or_fst", "connection_duration", "sent_size", "received_size", "messages"]

connection_durations = []
connection_data = []

for index, (conn_id, conn_info) in enumerate(connections.items(), start=1):
    ipsrc, portsrc, ipdst, portdst = conn_id
    conn_id = index
    start_timestamp = conn_info['start_timestamp']
    end_timestamp = conn_info['end_timestamp']
    sent_size = conn_info['sent_size']
    received_size = conn_info['received_size']
    messages = sorted(conn_info['messages'])  # Sort for easier reading

    start_time = None
    end_time = None
    duration = None
    if start_timestamp:
        start_time = datetime.fromtimestamp(float(start_timestamp)).strftime('%Y-%m-%d %H:%M:%S')
    if end_timestamp:
        end_time = datetime.fromtimestamp(float(end_timestamp)).strftime('%Y-%m-%d %H:%M:%S')
    if start_timestamp and end_timestamp:
        duration = end_timestamp - start_timestamp
        connection_durations.append(float(duration))

    connection_data.append([
        conn_id, ipsrc, portsrc, ipdst, portdst,
        start_time, end_time,
        duration if duration else None,
        sent_size,
        received_size,
        ",".join(messages) if messages else ""
    ])

avg_duration = statistics.mean(connection_durations) if connection_durations else 0
var_duration = statistics.variance(connection_durations) if len(connection_durations) > 1 else 0

print(f"Average Connection Duration: {avg_duration:.5f} seconds")
print(f"Variance in Duration: {var_duration:.5f} seconds^2")

# Write to CSV
with open(csv_filename, mode="w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(header)
    for row in connection_data:
        writer.writerow([
            row[0], row[1], row[2], row[3], row[4],
            row[5], row[6],
            round(float(row[7]), 5) if row[7] is not None else None,
            row[8], row[9],
            row[10]
        ])

print(f"CSV file '{csv_filename}' has been saved.")

# --- Plotting ---
def generate_histogram(durations):
    if durations:
        plt.figure(figsize=(10, 6))
        plt.hist(durations, bins=1000, edgecolor='black')
        plt.title('Histogram of Connection Durations')
        plt.xlabel('Connection Duration (seconds)')
        plt.ylabel('Frequency')
        plt.xlim(0, 100)
        plt.grid(True)
        plt.savefig("plot.png")
        plt.show()
    else:
        print("No connection duration values available to plot.")

generate_histogram(connection_durations)
