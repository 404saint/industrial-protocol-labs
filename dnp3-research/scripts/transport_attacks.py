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
        
        console.print(f"[magenta][<-] Response ({len(response)} bytes):[/magenta] {response.hex(' ')}")
        decode_response(response)
    except Exception as e:
        console.print(f"[bold red][!] Connection/Send Error: {e}[/bold red]")

def decode_response(data):
    if len(data) < 14:
        console.print("[red][!] Response too short to parse.[/red]")
        return

    iin2 = data[13]
    param_error = bool(iin2 & 0x04)

    if param_error:
        console.print("[bold red]    └── Result: PROTOCOL ANOMALY DETECTED / REJECTED (IIN2.2 Set)[/bold red]")
    else:
        console.print("[bold green]    └── Result: FRAME ACCEPTED BY TARGET ENGINE (0x00)[/bold green]")

def build_unsolicited_response_frame():
    """
    Constructs a DNP3 Unsolicited Response frame (FC 0x82) containing Group 30 Var 1 (Analog Input) telemetry.
    """
    # Transport Byte: FIR=1, FIN=1, SEQ=0 -> 0xC0
    # App Header: FIR=1, FIN=1, CON=0, UNS=1 (0xC0), FC 0x82
    # Obj: Group 30 Var 1 (30 01), Qual 0x00, Count 1, Point #0, Value 0x7FFF (Max Analog Overrange)
    payload = bytearray.fromhex("c0 c0 82 00 00 1e 01 00 01 00 00 ff 7f 01")
    
    # DNP3 Header: Sync (05 64), Length (18), Ctrl (44), Addrs (00 00 / 01 00), CRC (3b e3)
    frame = bytearray.fromhex("05 64 12 44 00 00 01 00 3b e3") + payload
    return bytes(frame)

def run_phase4_tests():
    console.print("[bold green]=== DNP3 Phase 4: Transport Layer & Protocol Abuse ===[/bold green]")

    # Test 1: Fragment Anomaly - Missing FIR Flag (FIR=0, FIN=1, SEQ=0 -> Transport Byte 0x80)
    orphaned_fragment = bytes.fromhex("05 64 0c 44 00 00 01 00 3b e3 80 c1 01")
    send_frame(orphaned_fragment, "Transport Fragment Anomaly - Orphaned Fragment (FIR=0, FIN=1)")

    # Test 2: Sequence Desynchronization Stream (FIR=1, FIN=0, SEQ=5 -> Transport Byte 0x45)
    first_fragment = bytes.fromhex("05 64 0c 44 00 00 01 00 3b e3 45 c1 01")
    send_frame(first_fragment, "Transport Fragment - Start Stream (FIR=1, FIN=0, SEQ=5)")

    # Test 3: Unsolicited Response Forgery (FC 0x82)
    unsolicited_frame = build_unsolicited_response_frame()
    send_frame(unsolicited_frame, "Unsolicited Response Forgery (FC 0x82) - Fake Telemetry Injection")

if __name__ == "__main__":
    run_phase4_tests()