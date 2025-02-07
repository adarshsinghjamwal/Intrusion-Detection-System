from scapy.all import sniff, IP
import csv
import time
import os

# Function to log packets
def log_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_size = len(packet)
        timestamp = time.time()  # Current time in Unix format

        # Ensure the data directory exists
        os.makedirs("data", exist_ok=True)

        # Append packet data to the CSV
        with open('data/traffic_data.csv', 'a') as f:
            writer = csv.writer(f)
            writer.writerow([timestamp, src_ip, dst_ip, protocol, packet_size])
        print(f"Logged packet: {src_ip} -> {dst_ip}, Protocol: {protocol}, Size: {packet_size}")

# Function to start the packet sniffer
def start_sniffer(interface="en0"):
    print("Starting packet sniffer...")
    sniff(iface=interface, prn=log_packet, store=False)