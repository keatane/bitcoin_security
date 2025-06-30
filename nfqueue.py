import argparse
from netfilterqueue import NetfilterQueue
from scapy.all import IP
import os

# Configuration
FAKE_IP = "10.0.0.123"  # The IP to mask with

def process_packet_sender(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(IP):
        print(f"[Sender] Original Source IP: {scapy_packet.src}")
        scapy_packet.src = FAKE_IP
        print(f"[Sender] Masked Source IP: {scapy_packet.src}")
        del scapy_packet[IP].chksum
        packet.set_payload(bytes(scapy_packet))
    packet.accept()

def process_packet_listener(packet):
    scapy_packet = IP(packet.get_payload())
    if scapy_packet.haslayer(IP) and scapy_packet.src == FAKE_IP:
        print(f"[Listener] Masked Source IP: {scapy_packet.src}")
        # Restore original IP if you know how to map it
        # Example below assumes all masked IPs should become 192.168.1.10
        real_ip = "192.168.1.10"
        print(f"[Listener] Restored Source IP: {real_ip}")
        scapy_packet.src = real_ip
        del scapy_packet[IP].chksum
        packet.set_payload(bytes(scapy_packet))
    packet.accept()

def setup_iptables(mode):
    if mode == "sender":
        os.system("iptables -A OUTPUT -p ip -j NFQUEUE --queue-num 1")
    elif mode == "listener":
        os.system("iptables -A INPUT -p ip -j NFQUEUE --queue-num 1")

def flush_iptables():
    os.system("iptables -F")

def main():
    parser = argparse.ArgumentParser(description="IP Masking using nfqueue")
    parser.add_argument("mode", choices=["sender", "listener"], help="Node mode (sender or listener)")
    args = parser.parse_args()

    print(f"[*] Running in {args.mode} mode...")
    setup_iptables(args.mode)

    nfqueue = NetfilterQueue()
    if args.mode == "sender":
        nfqueue.bind(1, process_packet_sender)
    else:
        nfqueue.bind(1, process_packet_listener)

    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print("\n[!] Exiting and flushing iptables...")
        # flush_iptables()

if __name__ == "__main__":
    main()
