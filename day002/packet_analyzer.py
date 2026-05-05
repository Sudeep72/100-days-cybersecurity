"""
Day 002 - Packet Analyzer
100 Days of Cybersecurity by Sudeep Ravichandran

Shows TCP/IP layers live by capturing and parsing network packets.
Run with: sudo python3 packet_analyzer.py
Requires: pip install scapy
"""

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from datetime import datetime
import sys


def analyze_packet(packet):
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # TCP - catch the 3-way handshake
        if TCP in packet:
            flags = packet[TCP].flags
            flag_list = []
            if flags & 0x02: flag_list.append("SYN")
            if flags & 0x10: flag_list.append("ACK")
            if flags & 0x01: flag_list.append("FIN")
            if flags & 0x04: flag_list.append("RST")

            flag_str = ",".join(flag_list) if flag_list else "DATA"
            print(f"[{timestamp}] TCP {src_ip}:{packet[TCP].sport} "
                  f"→ {dst_ip}:{packet[TCP].dport} [{flag_str}]")

            # Highlight handshake steps
            if flag_list == ["SYN"]:
                print(f"  ↳ 🤝 Step 1 — SYN: Client initiating connection")
            elif "SYN" in flag_list and "ACK" in flag_list:
                print(f"  ↳ 🤝 Step 2 — SYN-ACK: Server responding")
            elif flag_list == ["ACK"]:
                print(f"  ↳ 🤝 Step 3 — ACK: Handshake complete, data can flow")

        # UDP - catch DNS queries
        elif UDP in packet:
            if DNS in packet and packet[DNS].qr == 0:  # qr=0 means query
                if DNSQR in packet:
                    domain = packet[DNSQR].qname.decode().rstrip(".")
                    print(f"[{timestamp}] DNS Query: {domain}")
                    print(f"  ↳ 🌐 Resolving IP for: {domain}")
                    print(f"  ↳ ⚠  Attack surface: DNS spoofing could "
                          f"return a malicious IP here")


def main():
    print("=" * 55)
    print("100 Days of Cybersecurity — Day 002")
    print("TCP/IP Packet Analyzer")
    print("=" * 55)
    print("\nCapturing 30 packets... (Ctrl+C to stop early)\n")

    try:
        sniff(prn=analyze_packet, count=30, store=0)
    except KeyboardInterrupt:
        print("\nCapture stopped.")
    except PermissionError:
        print("Need root: sudo python3 packet_analyzer.py")
        sys.exit(1)


if __name__ == "__main__":
    main()