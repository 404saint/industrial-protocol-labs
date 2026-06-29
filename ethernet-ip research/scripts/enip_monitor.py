#!/usr/bin/env python3
import struct
from scapy.all import sniff, TCP, IP

# CIP Service Mappings for High-Signal Context
CIP_SERVICES = {
    0x4C: "Read Tag (Single)",
    0x4D: "Write Tag (Single)",
    0x52: "Unconnected Send (Router)",
    0x0E: "Get Attribute Single"
}

def parse_enip_packet(packet):
    # Ensure the packet has a TCP payload and data exists
    if not packet.haslayer(TCP) or not packet[TCP].payload:
        return

    raw_payload = bytes(packet[TCP].payload)
    if len(raw_payload) < 24:
        return  # Not enough bytes for a valid ENIP Encapsulation Header

    try:
        # 1. Parse the standard 24-byte EtherNet/IP Encapsulation Header
        # Command (2B), Length (2B), Session Handle (4B), Status (4B), Context (8B), Options (4B)
        command, length, session_handle, status, context, options = struct.unpack(
            "<HHII8sI", raw_payload[:24]
        )

        # Filter for SendRRData (0x006F) or RegisterSession (0x0065)
        if command == 0x0065:
            print(f"[!] SESSION REGISTRATION DETECTED | Handle: {hex(session_handle)} | Status: {status}")
            return

        if command == 0x006F:  # SendRRData handles explicit messaging
            cpf_data = raw_payload[24:]
            
            # 2. Look for the Symbolic Tag Data pattern on the wire
            # Rather than calculating shifting offsets of unstable nested layers, 
            # we use a safe, high-signal signature search for the ANSI Symbolic Type Segment (0x91)
            if b'\x91' in cpf_data:
                idx = cpf_data.index(b'\x91')
                tag_len = cpf_data[idx + 1]
                
                # Extract the tag string safely based on its specified length boundary
                tag_name_bytes = cpf_data[idx + 2 : idx + 2 + tag_len]
                
                # Basic validation to ensure it's printable ASCII text
                if all(32 <= b <= 126 for b in tag_name_bytes):
                    tag_name = tag_name_bytes.decode('ascii', errors='ignore')
                    
                    # 3. Identify the CIP Service executing against the tag
                    # The service code typically sits right before the path segment
                    service_code = cpf_data[idx - 2] if idx >= 2 else 0x00
                    service_desc = CIP_SERVICES.get(service_code, f"Unknown Service ({hex(service_code)})")
                    
                    print(f"[+] INDUSTRIAL MONITORING ALERT")
                    print(f"    Source IP    : {packet[IP].src}")
                    print(f"    Session      : {hex(session_handle)}")
                    print(f"    CIP Service  : {service_desc}")
                    print(f"    Target Asset : {tag_name}")
                    print("-" * 50)

    except Exception as e:
        # Fail silently on malformed background network noise to maintain parsing uptime
        pass

def main():
    print("[*] Launching Passive Industrial Protocol Analysis Engine...")
    print("[*] Monitoring interface 'lo' for explicit EtherNet/IP traffic (Port 44818)...")
    
    # Sniff loopback traffic on port 44818 continuously
    sniff(iface="lo", filter="tcp port 44818", prn=parse_enip_packet, store=0)

if __name__ == "__main__":
    main()