#!/usr/bin/env python3
import socket
import struct
import sys

def fingerprint_encapsulation(target_ip="127.0.0.1", target_port=44818):
    print(f"[*] Phase 7: Sending raw ListServices (0x0004) to fingerprint target stack...")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((target_ip, target_port))
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        sys.exit(1)

    # Build a standard 24-byte encapsulation header with NO trailing payload data
    # Command: 0x0004 (ListServices), Length: 0, Session: 0, Status: 0, Context: FINGERPT, Options: 0
    list_services_header = struct.pack(
        '<HHII8sI',
        0x0004,            # Command: ListServices
        0,                 # Length of payload (0 for basic inquiry)
        0x00000000,        # Session Handle (0)
        0x00000000,        # Status (0)
        b'FINGERPT',       # Sender Context
        0x00000000         # Options Flags (0)
    )

    s.send(list_services_header)
    
    try:
        response = s.recv(1024)
    except socket.timeout:
        print("[-] Target timed out waiting for ListServices response.")
        s.close()
        sys.exit(1)
        
    s.close()

    print(f"[+] Received {len(response)} bytes back from target.")
    print("-" * 60)
    print(f"Raw Response Hex: {response.hex()}")
    print("-" * 60)
    
    if len(response) >= 24:
        # Extract response header parameters
        command, length, session, status, context, options = struct.unpack('<HHII8sI', response[:24])
        print(f"Decoded Response Command : {hex(command)} (Expected: 0x4)")
        print(f"Payload Data Length      : {length} bytes")
        print(f"CIP Stack Status Code    : {hex(status)}")
        
        # Output trailing payload hex if it exists for stack matching
        if length > 0:
            print(f"Stack Capability Block   : {response[24:24+length].hex()}")
    print("-" * 60)

if __name__ == "__main__":
    fingerprint_encapsulation()