import socket
import sys
import struct
import time
from rich.console import Console

console = Console()

HOST = "127.0.0.1"
PORT = 20000

# Buffer state for tracking multi-fragment reassembly
reassembly_buffer = {
    "active": False,
    "expected_seq": 0,
    "payload": bytearray()
}

def build_dnp3_response(fc=0x81, iin1=0x00, iin2=0x00, payload=b""):
    """
    Constructs a DNP3 Response frame (FC 0x81) with active IIN flags and payload.
    """
    response_frame = bytearray.fromhex("05 64 0e 44 00 00 01 00 3b e3 c1 81")
    response_frame.append(iin1)
    response_frame.append(iin2)
    response_frame.extend(payload)
    
    # Update length byte in header (index 2)
    response_frame[2] = len(response_frame) - 5
    return bytes(response_frame)

def parse_transport_header(transport_byte):
    """
    Parses DNP3 Transport Control Byte flags: FIN (bit 7), FIR (bit 6), Sequence (bits 0-5)
    """
    fin = bool(transport_byte & 0x80)
    fir = bool(transport_byte & 0x40)
    seq = transport_byte & 0x3F
    return fir, fin, seq

def process_fragment_and_apdu(data):
    """
    Parses Transport Layer flags and Application Layer Function Codes.
    """
    if len(data) < 13:
        return build_dnp3_response(iin2=0x04)

    transport_byte = data[10]
    fir, fin, seq = parse_transport_header(transport_byte)
    
    app_ctrl = data[11]
    func_code = data[12]

    console.print(f"[bold cyan][*] Transport Header: FIR={fir}, FIN={fin}, SEQ={seq}[/bold cyan]")

    # Detect Fragment Reassembly Anomalies
    if not fir and not reassembly_buffer["active"]:
        console.print("[bold red][!] REASSEMBLY ANOMALY: Received middle/final fragment without FIR flag![/bold red]")
        return build_dnp3_response(iin2=0x04) # Parameter/Buffer Error

    if fir:
        reassembly_buffer["active"] = True
        reassembly_buffer["expected_seq"] = (seq + 1) % 64
        reassembly_buffer["payload"] = bytearray(data[11:])
        console.print(f"[green][+] Started new fragment stream. Next expected SEQ: {reassembly_buffer['expected_seq']}[/green]")
    else:
        if seq != reassembly_buffer["expected_seq"]:
            console.print(f"[bold red][!] SEQUENCE DESYNC: Expected SEQ {reassembly_buffer['expected_seq']}, got {seq}![/bold red]")
            reassembly_buffer["active"] = False
            return build_dnp3_response(iin2=0x04)
        
        reassembly_buffer["payload"].extend(data[11:])
        reassembly_buffer["expected_seq"] = (seq + 1) % 64

    if fin:
        console.print("[bold green][✓] APDU Stream Reassembly Complete.[/bold green]")
        reassembly_buffer["active"] = False

    # FC 0x82: UNSOLICITED RESPONSE (Master Processing Mode)
    if func_code == 0x82:
        console.print("[bold magenta][⚡] UNSOLICITED RESPONSE (FC 0x82) RECEIVED ON MASTER INTERFACE[/bold magenta]")
        if len(data) >= 18:
            group = data[13]
            var = data[14]
            point_id = data[17] if len(data) > 17 else 0
            console.print(f"[bold yellow][!] Injection Alert: Spoofed Telemetry Data (Group {group} Var {var} on Point #{point_id})[/bold yellow]")
            console.print("[bold red][🔒] Master Database State Forged: Analog Input Overrange Condition Set.[/bold red]")
            return build_dnp3_response(fc=0x80) # Master Confirm frame (FC 0x00 / 0x80)
        else:
            return build_dnp3_response(fc=0x80)

    # Standard Echo Response for baseline validation
    return build_dnp3_response()

def run_outstation():
    console.print(f"[bold green][*] Starting DNP3 Target (Phase 4 Transport/Protocol Engine) on {HOST}:{PORT}...[/bold green]")
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server.bind((HOST, PORT))
        server.listen(1)
        console.print("[bold blue][+] Target listening. Ready for Phase 4 testing.[/bold blue]")
    except Exception as e:
        console.print(f"[bold red][!] Bind failed: {e}[/bold red]")
        sys.exit(1)

    while True:
        conn, addr = server.accept()
        try:
            data = conn.recv(1024)
            if data:
                console.print(f"\n[cyan][->] Received {len(data)} bytes from {addr[0]}:{addr[1]}:[/cyan] {data.hex(' ')}")
                if len(data) >= 2 and data[0] == 0x05 and data[1] == 0x64:
                    resp = process_fragment_and_apdu(data)
                    conn.send(resp)
                    console.print(f"[magenta][<-] Sent {len(resp)} bytes response.[/magenta]")
        except Exception as e:
            console.print(f"[red][!] Error handling connection: {e}[/red]")
        finally:
            conn.close()

if __name__ == "__main__":
    run_outstation()