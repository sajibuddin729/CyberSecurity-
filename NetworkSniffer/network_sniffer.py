# Author: Md Sajib Uddin

import os
import sys
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, hexdump

def banner():
    """Displays an elite banner"""
    print("\n" + "="*50)
    print(" ** NETWORK SNIFFER **  ")
    print("="*50 + "\n")

def packet_callback(packet):
    """detailed analysis."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print(f"\n[{timestamp}] Packet: {src_ip} -> {dst_ip} | Protocol: {proto}")

        if TCP in packet:
            print(f" | TCP | Src Port: {packet[TCP].sport} | Dst Port: {packet[TCP].dport}")

        elif UDP in packet:
            print(f" | UDP | Src Port: {packet[UDP].sport} | Dst Port: {packet[UDP].dport}")

            
            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                print(" | Possible DNS Query Detected!")

        elif ICMP in packet:
            print(" | ICMP (Ping) Packet Detected")

        if Raw in packet:
            print(" | Payload Detected:")
            hexdump(packet[Raw].load) 

def start_sniffing(interface="eth0", packet_count=10, filter_expr=""):
    """ sniffing packets ."""
    print(f"[*] Sniffing on {interface}, capturing {packet_count} packets...")

    if filter_expr:
        print(f"[*] Applying Filter: {filter_expr}")

    sniff(iface=interface, prn=packet_callback, count=packet_count, store=False, filter=filter_expr)

if __name__ == "__main__":
    banner()
    
    if os.geteuid() != 0:
        sys.exit("[ERROR] Run this script as root")

    interface = input("Enter network interface (e.g., eth0, wlan0): ").strip()
    packet_count = int(input("Enter number of packets to capture: "))
    filter_choice = input("Filter packets? (tcp, udp, icmp, none): ").strip().lower()

    filters = {
        "tcp": "tcp",
        "udp": "udp",
        "icmp": "icmp",
        "none": ""
    }

    selected_filter = filters.get(filter_choice, "")

    start_sniffing(interface, packet_count, selected_filter)
