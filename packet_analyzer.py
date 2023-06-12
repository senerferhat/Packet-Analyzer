from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP
from collections import Counter

ip_counter = Counter()
THRESHOLD = 50  # adjust this value

def packet_handler(packet):
    # Check for IP layer and print details
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        ip_counter[ip_src] += 1
        print(f'IP Packet: Source IP: {ip_src} ---- Destination IP: {ip_dst}')

    # Check for TCP layer
    if packet.haslayer(TCP):
        print("TCP Packet detected.")

    # Check for UDP layer
    if packet.haslayer(UDP):
        print("UDP Packet detected.")

    # Check for ICMP layer
    if packet.haslayer(ICMP):
        print("ICMP Packet detected.")

def capture_live():
    # Capture live packets
    sniff(prn=packet_handler, count=10)

def read_pcap(file_path):
    # Read packets from a pcap file
    packets = rdpcap(file_path)
    for packet in packets:
        packet_handler(packet)

def print_stats():
    # Print the statistics
    print("Most common source IPs:")
    for ip, count in ip_counter.most_common(5):
        print(f"{ip}: {count} packets")

def check_anomalies():
    # Detect anomalies or potential security threats
    for ip, count in ip_counter.items():
        if count > THRESHOLD:
            print(f"Potential anomaly: {ip} has sent {count} packets")

if __name__ == "__main__":
    # Use capture_live() or read_pcap(file_path) based on your need
    capture_live()

    print_stats()
    check_anomalies()