#!/usr/bin/env python3
"""
IEC 60870-5-104 - Phase 2: ASDU & IOA Enumeration Dissector (Buffer-Sliced)
Target: cs104_server_no_threads / lib60870-C
"""

import socket
import time
import sys

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 2404

# Track client-side send sequence number
tx_ns = 0
rx_nr = 0

def build_i_frame(type_id, vsq, cot, ca, ioa, payload=bytes()):
    """Builds a valid IEC 104 I-Format frame with dynamic N(S) and N(R)."""
    global tx_ns, rx_nr
    
    # ASDU Construction
    asdu = bytes([
        type_id,
        vsq,
        cot, 0x00,              # COT (2 bytes: Cause + Originator Address)
        ca & 0xFF, (ca >> 8) & 0xFF,  # Common Address (2 bytes)
        ioa & 0xFF, (ioa >> 8) & 0xFF, (ioa >> 16) & 0xFF # IOA (3 bytes)
    ]) + payload

    apci_payload_len = 4 + len(asdu) # 4 Control Bytes + ASDU
    
    # APCI Control Fields with sequence numbers
    ctrl0 = (tx_ns << 1) & 0xFE
    ctrl1 = (tx_ns >> 7) & 0xFF
    ctrl2 = (rx_nr << 1) & 0xFE
    ctrl3 = (rx_nr >> 7) & 0xFF
    
    tx_ns += 1
    return bytes([0x68, apci_payload_len, ctrl0, ctrl1, ctrl2, ctrl3]) + asdu

# U-Format APCI Frames
STARTDT_ACT = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])

def dissect_single_apci_frame(frame_bytes):
    """Dissects a single validated 0x68 APCI frame."""
    global rx_nr
    if len(frame_bytes) < 6 or frame_bytes[0] != 0x68:
        return

    ctrl1 = frame_bytes[2]

    # Process I-Format Frames (Bit 0 of Ctrl1 is 0)
    if (ctrl1 & 0x01) == 0x00:
        ns = ((frame_bytes[2] | (frame_bytes[3] << 8)) >> 1)
        nr = ((frame_bytes[4] | (frame_bytes[5] << 8)) >> 1)
        rx_nr = ns + 1  # Track server's send counter to ACK correctly

        if len(frame_bytes) < 12:
            print(f"  \033[1;34m◄── RX\033[0m | Short I-Frame | N(S):{ns:<2} N(R):{nr:<2}")
            return

        type_id = frame_bytes[6]
        vsq = frame_bytes[7]
        sq = (vsq & 0x80) >> 7
        num_obj = vsq & 0x7F
        cot = frame_bytes[8]
        ca = frame_bytes[10] | (frame_bytes[11] << 8)

        # Single Object Structure (SQ=0)
        if sq == 0:
            if len(frame_bytes) >= 15:
                ioa = frame_bytes[12] | (frame_bytes[13] << 8) | (frame_bytes[14] << 16)
                value_bytes = frame_bytes[15:].hex()
                print(
                    f"  \033[1;34m◄── RX\033[0m | \033[1mI-FRAME\033[0m | N(S):{ns:<2} N(R):{nr:<2} | "
                    f"\033[1;32mType:{type_id:<3}\033[0m | COT:{cot:<2} | CA:{ca:<3} | "
                    f"\033[1;33mIOA:{ioa:<5}\033[0m | Data: 0x{value_bytes}"
                )
            else:
                print(f"  \033[1;34m◄── RX\033[0m | \033[1mI-FRAME (No IOA Payload)\033[0m | N(S):{ns:<2} N(R):{nr:<2} | Type:{type_id:<3} | COT:{cot:<2}")
        
        # Contiguous Sequence Structure (SQ=1)
        else:
            base_ioa = frame_bytes[12] | (frame_bytes[13] << 8) | (frame_bytes[14] << 16)
            print(
                f"  \033[1;34m◄── RX\033[0m | \033[1mI-FRAME (SQ Sequence)\033[0m | N(S):{ns:<2} N(R):{nr:<2} | "
                f"\033[1;32mType:{type_id:<3}\033[0m | Objects:{num_obj:<2} | Base IOA:{base_ioa:<5}"
            )

    # Process S-Format Supervisory ACKs
    elif (ctrl1 & 0x03) == 0x01:
        nr = ((frame_bytes[4] | (frame_bytes[5] << 8)) >> 1)
        print(f"  \033[1;35m◄── RX\033[0m | \033[1mS-FRAME ACK\033[0m | N(R)={nr}")

    # Process U-Format Control Confirmation
    elif (ctrl1 & 0x03) == 0x03:
        print(f"  \033[1;32m◄── RX\033[0m | \033[1mU-FRAME CON\033[0m | Ctrl: 0x{ctrl1:02X}")

def process_tcp_stream_buffer(raw_buffer):
    """Slices concatenated 0x68 APCI frames from raw socket buffer."""
    offset = 0
    buffer_len = len(raw_buffer)

    while offset < buffer_len:
        # Scan for start byte 0x68
        if raw_buffer[offset] != 0x68:
            offset += 1
            continue

        if offset + 2 > buffer_len:
            break

        apci_length = raw_buffer[offset + 1]
        frame_total_length = apci_length + 2

        if offset + frame_total_length > buffer_len:
            break

        single_frame = raw_buffer[offset : offset + frame_total_length]
        dissect_single_apci_frame(single_frame)
        offset += frame_total_length

def run_phase2_enumeration():
    global tx_ns, rx_nr
    tx_ns = 0
    rx_nr = 0

    print("\n\033[1;36m=== IEC 104 PHASE 2: ASDU & IOA ENUMERATION (SLICED DISSECTION) ===\033[0m")
    print(f"Target: {TARGET_HOST}:{TARGET_PORT}\n")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.5)

    try:
        s.connect((TARGET_HOST, TARGET_PORT))
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        sys.exit(1)

    # Step 1: Link Activation
    print("[\033[1;33mSTEP 1\033[0m] Link Activation (STARTDT ACT)")
    s.sendall(STARTDT_ACT)
    resp = s.recv(1024)
    process_tcp_stream_buffer(resp)

    # Step 2: General Interrogation
    print("\n[\033[1;33mSTEP 2\033[0m] Transmitting General Interrogation Command (Type ID 100)")
    # Type 100, SQ=0/Num=1 (0x01), COT=6 (Activation), CA=1, IOA=0, QOI=0x20
    gi_frame = build_i_frame(100, 0x01, 6, 1, 0, bytes([0x20]))
    print(f"  \033[1;32m──► TX\033[0m | \033[1mI-FRAME\033[0m | Type: 100 (GI) | CA: 1 | Global IOA: 0 | N(S): {tx_ns-1}")
    s.sendall(gi_frame)

    # Collect and slice returned stream
    start_time = time.time()
    while time.time() - start_time < 2.5:
        try:
            stream_chunk = s.recv(2048)
            if not stream_chunk:
                break
            process_tcp_stream_buffer(stream_chunk)
        except socket.timeout:
            break

    # Step 3: Out-of-Bounds Interrogation Probe
    print("\n[\033[1;33mSTEP 3\033[0m] Out-of-Bounds Probe (Common Address: 9999)")
    invalid_ca_frame = build_i_frame(100, 0x01, 6, 9999, 0, bytes([0x20]))
    print(f"  \033[1;32m──► TX\033[0m | \033[1mI-FRAME\033[0m | Type: 100 (GI) | Target CA: 9999 (Invalid) | N(S): {tx_ns-1}")
    s.sendall(invalid_ca_frame)

    try:
        resp = s.recv(1024)
        if resp:
            process_tcp_stream_buffer(resp)
        else:
            print("  [*] Server closed socket.")
    except socket.timeout:
        print("  [*] Silent Drop: Server ignored request without returning error ASDU.")

    # Step 4: Unauthenticated Single Command Execution
    print("\n[\033[1;33mSTEP 4\033[0m] Unauthenticated Single Command Direct Execution (Type ID 45)")
    # Type 45, SQ=0/Num=1 (0x01), COT=6 (Activation), CA=1, IOA=5000, SCO=0x01 (State ON, Direct Execute)
    single_cmd_frame = build_i_frame(45, 0x01, 6, 1, 5000, bytes([0x01]))
    print(f"  \033[1;32m──► TX\033[0m | \033[1mI-FRAME\033[0m | Type: 45 (Single Command) | Target IOA: 5000 | State: ON | N(S): {tx_ns-1}")
    s.sendall(single_cmd_frame)

    try:
        resp = s.recv(1024)
        if resp:
            process_tcp_stream_buffer(resp)
    except socket.timeout:
        print("  [*] Command transmitted. Listening completed.")

    s.close()
    print("\n\033[1;36m=== PHASE 2 ENUMERATION COMPLETE ===\033[0m")

if __name__ == "__main__":
    run_phase2_enumeration()