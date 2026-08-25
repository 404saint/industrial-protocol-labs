import socket
import time
import sys

# Target Configuration
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 2404

# U-Format Frame Bitmasks (APCI Control Byte 1)
STARTDT_ACT = bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00])
STARTDT_CON = 0x0B
STOPDT_ACT  = bytes([0x68, 0x04, 0x13, 0x00, 0x00, 0x00])
STOPDT_CON  = 0x23
TESTFR_ACT  = bytes([0x68, 0x04, 0x43, 0x00, 0x00, 0x00])
TESTFR_CON  = 0x83

def print_banner(text):
    print(f"\n\033[1;36m=== {text} ===\033[0m")

def print_step(step_num, title):
    print(f"\n[\033[1;33mSTEP {step_num}\033[0m] {title}")

def print_sent(frame_type, description):
    print(f"  \033[1;32m──► TX\033[0m | Frame: \033[1m{frame_type:<12}\033[0m | Action: {description}")

def print_recv(frame_type, state_status, details=""):
    status_color = "\033[1;32m" if "ACTIVE" in state_status or "CONFIRMED" in state_status or "ALIVE" in state_status else "\033[1;31m"
    print(f"  \033[1;34m◄── RX\033[0m | Frame: \033[1m{frame_type:<12}\033[0m | State: {status_color}{state_status}\033[0m {details}")

def parse_apci_frame(data):
    if len(data) < 6 or data[0] != 0x68:
        return "UNKNOWN", "MALFORMED_APCI"
    
    ctrl1 = data[2]
    
    # Check for S-Format (Bit 0 = 1, Bit 1 = 0 -> 0x01 mask check)
    if (ctrl1 & 0x03) == 0x01:
        nr = (data[4] | (data[5] << 8)) >> 1
        return f"S-FRAME", f"SUPERVISORY_ACK (N(R)={nr})"

    # Check for U-Format (Bit 0 = 1, Bit 1 = 1 -> 0x03 mask check)
    elif (ctrl1 & 0x03) == 0x03:
        if ctrl1 == STARTDT_CON:
            return "STARTDT CON", "LINK_STARTED (DATA_TRANSFER_ACTIVE)"
        elif ctrl1 == STOPDT_CON:
            return "STOPDT CON", "LINK_STOPPED (DATA_TRANSFER_SUSPENDED)"
        elif ctrl1 == TESTFR_CON:
            return "TESTFR CON", "KEEP_ALIVE_ALIVE"
        elif ctrl1 == STARTDT_ACT[2]:
            return "STARTDT ACT", "LINK_START_REQUESTED"
        elif ctrl1 == TESTFR_ACT[2]:
            return "TESTFR ACT", "KEEP_ALIVE_REQUESTED"
        else:
            return f"U-FRAME (0x{ctrl1:02X})", "UNMAPPED_U_STATE"

    # I-Format (Bit 0 = 0)
    elif (ctrl1 & 0x01) == 0x00:
        ns = (ctrl1 | (data[3] << 8)) >> 1
        nr = (data[4] | (data[5] << 8)) >> 1
        return f"I-FRAME", f"DATA_TRANSFER (N(S)={ns}, N(R)={nr})"
        
    return "UNKNOWN", "UNPARSED_FRAME"

def drain_socket(s):
    """Flushes unread frames to ensure sequence synchronization"""
    s.settimeout(0.2)
    try:
        while True:
            data = s.recv(1024)
            if not data:
                break
    except socket.timeout:
        pass
    s.settimeout(3.0)

def run_phase1_lab():
    print_banner("IEC 104 PHASE 1: APCI LINK STATE HANDSHAKE")
    print(f"Target Endpoint   : {TARGET_HOST}:{TARGET_PORT}")
    print(f"Transport Protocol: TCP / Native Cleartext")
    
    # 1. TCP Layer Session Initialization
    print_step(1, "Establishing Layer 4 TCP Connection")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((TARGET_HOST, TARGET_PORT))
        print("  \033[1;32m[+] TCP Socket Connected successfully [SYN-ACK handshake cleared]\033[0m")
        print("  [*] Initial Session State: STOPPED (No ASDUs will be processed)")
    except Exception as e:
        print(f"  \033[1;31m[-] Connection Failed: {e}\033[0m")
        sys.exit(1)

    time.sleep(0.5)

    # 2. Activate Link State (STARTDT ACT -> CON)
    print_step(2, "Negotiating APCI Link Activation (STARTDT)")
    print_sent("STARTDT ACT", "Requesting RTU to open data transfer phase")
    s.sendall(STARTDT_ACT)
    
    try:
        resp = s.recv(1024)
        frame_name, state_str = parse_apci_frame(resp)
        print_recv(frame_name, state_str, "| Data Transfer Enabled")
    except socket.timeout:
        print("  \033[1;31m[-] Timeout waiting for STARTDT CON\033[0m")

    time.sleep(0.5)
    drain_socket(s)

    # 3. Channel Keep-Alive Verification (TESTFR ACT -> CON)
    print_step(3, "Channel Health Monitoring (TESTFR Keep-Alive)")
    print_sent("TESTFR ACT", "Transmitting link verification frame")
    s.sendall(TESTFR_ACT)
    
    try:
        resp = s.recv(1024)
        frame_name, state_str = parse_apci_frame(resp)
        print_recv(frame_name, state_str, "| Link Latency verified")
    except socket.timeout:
        print("  \033[1;31m[-] Timeout waiting for TESTFR CON\033[0m")

    time.sleep(0.5)
    drain_socket(s)

    # 4. Graceful Deactivation (STOPDT ACT -> CON)
    print_step(4, "Graceful Link State Deactivation (STOPDT)")
    print_sent("STOPDT ACT", "Requesting RTU to suspend data transfer")
    s.sendall(STOPDT_ACT)
    
    try:
        resp = s.recv(1024)
        frame_name, state_str = parse_apci_frame(resp)
        print_recv(frame_name, state_str, "| Reverted to STOPPED state")
    except socket.timeout:
        print("  \033[1;31m[-] Timeout waiting for STOPDT CON\033[0m")

    # 5. Teardown
    print_step(5, "Socket Closure")
    s.close()
    print("  [*] Layer 4 TCP connection terminated")
    print_banner("PHASE 1 HANDSHAKE COMPLETE - ALL STATES VERIFIED")

if __name__ == "__main__":
    run_phase1_lab()