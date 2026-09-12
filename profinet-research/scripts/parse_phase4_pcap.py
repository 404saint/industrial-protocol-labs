#!/usr/bin/env python3
from scapy.all import rdpcap, Ether, Raw
import struct

PCAP_PATH = "pcaps/phase4_profinet_audit.pcap"

def analyze_pcap():
    try:
        packets = rdpcap(PCAP_PATH)
    except FileNotFoundError:
        print(f"[!] PCAP file not found at {PCAP_PATH}. Ensure the path is correct.")
        return

    print(f"[*] Total Packets Captured: {len(packets)}")
    
    netload_count = 0
    dcp_count = 0
    malformed_count = 0
    other_count = 0

    for pkt in packets:
        if Ether in pkt:
            eth = pkt[Ether]
            payload = bytes(pkt[Raw].load) if Raw in pkt else b""
            
            # Check for Netload Class III burst packets (60-byte zero padding)
            if len(payload) == 60 and payload == b"\x00" * 60:
                netload_count += 1
            # Check for DCP-Like Station-Name simulation (Service ID 0x03, Service Type 0x01)
            elif len(payload) >= 2 and payload[0] == 0x03 and payload[1] == 0x01:
                dcp_count += 1
            # Check for Malformed Frame ID injection (0x00FF)
            elif len(payload) >= 2:
                fid = struct.unpack("!H", payload[:2])[0]
                if fid == 0x00FF:
                    malformed_count += 1
                else:
                    other_count += 1
            else:
                other_count += 1

    print("\n--- PCAP Analysis Breakdown ---")
    print(f"[+] PI Netload Class III Burst Packets : {netload_count}")
    print(f"[+] DCP-Like Station-Name Packets     : {dcp_count}")
    print(f"[+] Malformed Frame ID (0x00FF) Packets : {malformed_count}")
    print(f"[+] Other / Background RT Frames      : {other_count}")
    print("--------------------------------")

if __name__ == "__main__":
    analyze_pcap()