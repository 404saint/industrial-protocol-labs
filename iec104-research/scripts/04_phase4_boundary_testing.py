import socket
import time
import sys

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 2404

# U-Format Base Payload Constants
STARTDT_ACT = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])
STARTDT_CON = bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00]) # Client shouldn't send CON

def process_tcp_stream_buffer(raw_buffer):
    """Dissects returning frames or logs anomaly indicators."""
    if not raw_buffer:
        print("  [*] Connection closed by server (Clean Termination/Drop).")
        return

    offset = 0
    buffer_len = len(raw_buffer)

    while offset < buffer_len:
        if raw_buffer[offset] != 0x68:
            print(f"  \033[1;31m[!] Non-0x68 Header Received:\033[0m 0x{raw_buffer[offset:]:hex()}")
            break

        if offset + 2 > buffer_len:
            break

        apci_length = raw_buffer[offset + 1]
        frame_total_length = apci_length + 2

        if offset + frame_total_length > buffer_len:
            print(f"  [*] Truncated frame in stream buffer ({buffer_len - offset} of {frame_total_length} bytes)")
            break

        frame_bytes = raw_buffer[offset : offset + frame_total_length]
        ctrl1 = frame_bytes[2]
        
        # I-Format
        if (ctrl1 & 0x01) == 0x00:
            ns = ((frame_bytes[2] | (frame_bytes[3] << 8)) >> 1)
            nr = ((frame_bytes[4] | (frame_bytes[5] << 8)) >> 1)
            type_id = frame_bytes[6] if len(frame_bytes) >= 7 else 0
            cot = frame_bytes[8] if len(frame_bytes) >= 9 else 0
            print(f"  \033[1;34m◄── RX\033[0m | \033[1mI-FRAME\033[0m | N(S):{ns:<2} N(R):{nr:<2} | \033[1;32mType:{type_id:<3}\033[0m | \033[1;33mCOT:{cot:<2}\033[0m")
        # S-Format
        elif (ctrl1 & 0x03) == 0x01:
            nr = ((frame_bytes[4] | (frame_bytes[5] << 8)) >> 1)
            print(f"  \033[1;35m◄── RX\033[0m | \033[1mS-FRAME ACK\033[0m | N(R)={nr}")
        # U-Format
        elif (ctrl1 & 0x03) == 0x03:
            print(f"  \033[1;32m◄── RX\033[0m | \033[1mU-FRAME\033[0m | Ctrl: 0x{ctrl1:02X}")

        offset += frame_total_length

def execute_boundary_test(test_name, test_func):
    print(f"\n\033[1;36m=== {test_name} ===\033[0m")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect((TARGET_HOST, TARGET_PORT))
        # Activate link first for non-APCI framing tests
        test_func(s)
    except ConnectionRefusedError:
        print("  \033[1;31m[-] CRITICAL: Server process died/crashed!\033[0m")
    except Exception as e:
        print(f"  [-] Communication error: {e}")
    finally:
        s.close()
        time.sleep(0.4)

# --- TEST 1: Start Byte Corruption & APCI Length Mismatch ---
def test1_framing_corruption(s):
    print("1. Sending frame with corrupted Start Byte (0x99 instead of 0x68)...")
    bad_start = bytes([0x99, 0x04, 0x07, 0x00, 0x00, 0x00])
    s.sendall(bad_start)
    try:
        resp = s.recv(1024)
        process_tcp_stream_buffer(resp)
    except socket.timeout:
        print("  [*] Silent Drop: Server ignored invalid start byte.")

    print("2. Re-connecting to test APCI Exaggerated Length Indicator...")
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.settimeout(2.0)
    s2.connect((TARGET_HOST, TARGET_PORT))
    # APCI claims 255 bytes length (0xFF), but only sends 6 bytes
    oversized_len_frame = bytes([0x68, 0xFF, 0x07, 0x00, 0x00, 0x00])
    s2.sendall(oversized_len_frame)
    try:
        resp = s2.recv(1024)
        process_tcp_stream_buffer(resp)
    except socket.timeout:
        print("  [*] Server timed out / waiting for missing bytes.")
    s2.close()

# --- TEST 2: Unsupported / Reserved ASDU Type IDs ---
def test2_unsupported_asdu_type(s):
    print("1. Activating Link (STARTDT ACT)...")
    s.sendall(STARTDT_ACT)
    s.recv(1024)

    print("2. Injecting I-FRAME with undefined ASDU Type ID 255 (0xFF)...")
    # Type 255, VSQ 1, COT 6 (Activation), CA 1, IOA 0
    type_255_frame = bytes([
        0x68, 0x0E,              # APCI Header (14 bytes payload)
        0x00, 0x00, 0x00, 0x00,  # N(S)=0, N(R)=0
        0xFF,                    # Type ID: 255 (Undefined)
        0x01,                    # VSQ: 1
        0x06, 0x00,              # COT: 6
        0x01, 0x00,              # CA: 1
        0x00, 0x00, 0x00         # IOA: 0
    ])
    s.sendall(type_255_frame)
    try:
        resp = s.recv(1024)
        process_tcp_stream_buffer(resp)
    except socket.timeout:
        print("  [*] Silent Drop on Type ID 255.")

# --- TEST 3: Out-of-Sequence U-Format Control Handshakes ---
def test3_out_of_sequence_u_format(s):
    print("1. Injecting STARTDT CON (Confirm) from Client (Illegal Direction)...")
    s.sendall(STARTDT_CON)
    try:
        resp = s.recv(1024)
        process_tcp_stream_buffer(resp)
    except socket.timeout:
        print("  [*] Silent Drop: Server ignored illegal confirmation frame.")

# --- TEST 4: ASDU Payload Truncation ---
def test4_asdu_truncation(s):
    print("1. Activating Link (STARTDT ACT)...")
    s.sendall(STARTDT_ACT)
    s.recv(1024)

    print("2. Injecting I-FRAME with truncated ASDU header (APCI length claims 10 bytes, only 2 sent)...")
    # APCI header claims 10 payload bytes, but payload ends abruptly after Type ID
    truncated_frame = bytes([0x68, 0x0A, 0x02, 0x00, 0x00, 0x00, 0x2D]) 
    s.sendall(truncated_frame)
    try:
        resp = s.recv(1024)
        process_tcp_stream_buffer(resp)
    except socket.timeout:
        print("  [*] Silent Drop: Sever ignored truncated ASDU.")

def run_phase4():
    print("\033[1;35m=== IEC 104 PHASE 4: BOUNDARIES & EDGE CASES ===\033[0m")
    print(f"Target: {TARGET_HOST}:{TARGET_PORT}")

    execute_boundary_test("TEST 1: APCI Framing & Length Mismatches", test1_framing_corruption)
    execute_boundary_test("TEST 2: Unsupported ASDU Type ID Injection (Type 255)", test2_unsupported_asdu_type)
    execute_boundary_test("TEST 3: Out-of-Sequence U-Format Control", test3_out_of_sequence_u_format)
    execute_boundary_test("TEST 4: ASDU Payload Truncation", test4_asdu_truncation)

    print("\n\033[1;35m=== PHASE 4 BOUNDARY TESTING COMPLETE ===\033[0m")

if __name__ == "__main__":
    run_phase4()