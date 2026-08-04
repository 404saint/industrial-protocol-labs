import socket
import struct
import sys
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# --- Configuration Targets ---
TARGET_IP = "192.168.1.196" # Replace with the target BBMD or BACnet/IP device IP address
TARGET_PORT = 47808  # Default BACnet/IP UDP Port (0xBAC0)
LOCAL_TTL = 300      # Foreign Device Registration Time-To-Live (seconds)


def create_bvlc_header(bvlc_function: int, length: int) -> bytes:
    """Constructs a 4-byte BVLC (BACnet Virtual Link Control) header."""
    return struct.pack("!BBH", 0x81, bvlc_function, length)


def build_foreign_device_registration(ttl: int) -> bytes:
    """
    Vector A: Register-Foreign-Device (BVLL Type 0x05)
    Structure:
      - BVLC Type: 0x81
      - BVLC Function: 0x05 (Register-Foreign-Device)
      - Length: 6 bytes (4-byte header + 2-byte TTL)
      - Time-to-Live: 16-bit unsigned integer
    """
    header = create_bvlc_header(0x05, 6)
    payload = struct.pack("!H", ttl)
    return header + payload


def build_who_is_router_to_network(net_number: int = None) -> bytes:
    """
    Vector B: Who-Is-Router-To-Network (NPDU Message Type 0x00)
    Structure:
      - BVLC Header: Type 0x81, Function 0x0A (Original-Unicast-NPDU), Length 8 or 10
      - NPDU Header: Version 0x01, Control 0x80 (Network Layer Message)
      - Message Type: 0x00 (Who-Is-Router-To-Network)
      - Payload: Optional 2-byte Target Network Number
    """
    if net_number is not None:
        npdu = struct.pack("!BBB H", 0x01, 0x80, 0x00, net_number)
    else:
        npdu = struct.pack("!BBB", 0x01, 0x80, 0x00)
    
    bvlc = create_bvlc_header(0x0A, 4 + len(npdu))
    return bvlc + npdu


def build_who_is_global_broadcast(low_limit: int = 0, high_limit: int = 4194303) -> bytes:
    """
    Vector C: Global Who-Is Discovery over BVLL Broadcast (BVLL Type 0x0B)
    Structure:
      - BVLC Header: Type 0x81, Function 0x0B (Original-Broadcast-NPDU)
      - NPDU Header: Version 0x01, Control 0x20 (Destination Specifier Present)
        * DNET: 0xFFFF (Global Broadcast)
        * DLEN: 0 (Broadcast)
        * Hop Count: 0xFF
      - APDU: Unconfirmed-Request (0x10), Service Choice 0x08 (Who-Is)
        * Context Tag 0: Device Instance Low Limit
        * Context Tag 1: Device Instance High Limit
    """
    # NPDU with DNET=0xFFFF (Global Broadcast) and Hop Count=255
    npdu = struct.pack("!BB H B B", 0x01, 0x20, 0xFFFF, 0x00, 0xFF)
    
    # APDU: Who-Is Request (Unconfirmed-Request, Type 1, Service Choice 8)
    # Tag 0 (Low Limit), Tag 1 (High Limit)
    apdu = bytes([0x10, 0x08])
    if low_limit is not None and high_limit is not None:
        apdu += bytes([0x09, low_limit & 0xFF, 0x19, high_limit & 0xFF])
        
    bvlc = create_bvlc_header(0x0B, 4 + len(npdu) + len(apdu))
    return bvlc + npdu + apdu


def main():
    console.print(Panel.fit(
        "[bold cyan]Pillar 3: Network Topology, BBMD & Boundary Traversal Research Harness[/bold cyan]\n"
        "[dim]Vectors: BBMD Foreign Device Abuse, Router Discovery & Global Broadcast Traversal[/dim]",
        border_style="cyan"
    ))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)

    # --- Vector A: Foreign Device Registration ---
    console.print(f"\n[bold yellow][Vector A][/bold yellow] Registering as Foreign Device with TTL={LOCAL_TTL}s (BVLL 0x05)...")
    fdr_pkt = build_foreign_device_registration(LOCAL_TTL)
    sock.sendto(fdr_pkt, (TARGET_IP, TARGET_PORT))
    
    try:
        data, addr = sock.recvfrom(1024)
        bvlc_type, bvlc_func, bvlc_len = struct.unpack("!BBH", data[:4])
        result_code = struct.unpack("!H", data[4:6])[0] if len(data) >= 6 else -1
        
        if bvlc_func == 0x00 and result_code == 0x00:
            console.print(f"[bold green][+][/bold green] Foreign Device Registration Successful! ACK received from {addr[0]}:{addr[1]}")
        else:
            console.print(f"[bold red][!][/bold red] FDR Registration NAK/Error Code: {hex(result_code)}")
    except socket.timeout:
        console.print("[bold yellow][!][/bold yellow] FDR Request timed out (No response from BBMD target)")

    # --- Vector B: Router Mapping & Network Discovery ---
    console.print(f"\n[bold yellow][Vector B][/bold yellow] Mapping Router Topology (Who-Is-Router-To-Network)...")
    wir_pkt = build_who_is_router_to_network()
    sock.sendto(wir_pkt, (TARGET_IP, TARGET_PORT))
    
    router_networks = []
    try:
        data, addr = sock.recvfrom(1024)
        if len(data) >= 7 and data[1] == 0x0A:  # Original-Unicast
            npdu_ctrl = data[5]
            msg_type = data[6]
            if msg_type == 0x01:  # I-Am-Router-To-Network
                num_nets = (len(data) - 7) // 2
                router_networks = list(struct.unpack(f"!{num_nets}H", data[7:7+(num_nets*2)]))
                console.print(f"[bold green][+][/bold green] I-Am-Router Response Received! Routed Networks: {router_networks}")
    except socket.timeout:
        console.print("[bold yellow][!][/bold yellow] No router responses returned for network discovery query.")

    # --- Vector C: Global Broadcast Traversal ---
    console.print(f"\n[bold yellow][Vector C][/bold yellow] Executing Global Who-Is Broadcast Traversal (DNET 0xFFFF)...")
    whois_pkt = build_who_is_global_broadcast(0, 4194303)
    sock.sendto(whois_pkt, (TARGET_IP, TARGET_PORT))
    
    discovered_devices = []
    start_time = time.time()
    while time.time() - start_time < 2.0:
        try:
            data, addr = sock.recvfrom(1024)
            # Check for I-Am APDU (Type 1, Service Choice 0x10)
            if b"\x10\x10" in data or b"\x20\x10" in data:
                discovered_devices.append((addr[0], addr[1]))
                console.print(f"[bold green][+][/bold green] Received I-Am Response from Device at [cyan]{addr[0]}:{addr[1]}[/cyan]")
        except socket.timeout:
            break

    # --- Results Summary Table ---
    console.print(f"\n[bold white]              Network Topology & BBMD Audit Summary              [/bold white]")
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Vector Target", style="dim", width=25)
    table.add_column("BVLL / NPDU Function", width=30)
    table.add_column("Status / Observation", width=25)

    table.add_row("Foreign Device Reg.", "Register-Foreign-Device (0x05)", "Registration ACK Received" if 'result_code' in locals() and result_code == 0 else "No BBMD ACK")
    table.add_row("Router Discovery", "Who-Is-Router-To-Net (0x00)", f"Mapped {len(router_networks)} DNETs" if router_networks else "Direct IP Only")
    table.add_row("Global Who-Is Probe", "Original-Broadcast-NPDU (0x0B)", f" {len(discovered_devices)} I-Am Responses Observed")

    console.print(table)
    sock.close()
    console.print("\n[*]" + " Socket closed. Pillar 3 research harness execution completed.")


if __name__ == "__main__":
    main()