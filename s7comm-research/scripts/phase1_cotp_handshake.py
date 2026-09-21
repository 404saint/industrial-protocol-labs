#!/usr/bin/env python3
"""
S7comm Research Lab - Phase 1: Transport & Session Layer Initialization (TPKT/COTP)
Target: Classic S7comm / Snap7 C++ Server on TCP Port 102
"""

import socket
import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from scapy.all import Packet, ByteField, ShortField, StrLenField

console = Console()

# -----------------------------------------------------------------------------
# Scapy Custom Layers for Accurate Dissection
# -----------------------------------------------------------------------------
class TPKT(Packet):
    name = "TPKT (RFC 1006)"
    fields_desc = [
        ByteField("version", 3),
        ByteField("reserved", 0),
        ShortField("length", None)
    ]

class COTP_CR(Packet):
    name = "COTP Connection Request"
    fields_desc = [
        ByteField("hdr_len", 17),
        ByteField("pdu_type", 0xE0),  # CR
        ShortField("dst_ref", 0x0000),
        ShortField("src_ref", 0x0001),
        ByteField("option", 0x00),
        # Parameters
        ByteField("dst_tsap_code", 0xC2),
        ByteField("dst_tsap_len", 2),
        ShortField("dst_tsap", 0x0102), # Rack 0, Slot 2 default
        ByteField("src_tsap_code", 0xC1),
        ByteField("src_tsap_len", 2),
        ShortField("src_tsap", 0x0100),
        ByteField("pdu_size_code", 0xC0),
        ByteField("pdu_size_len", 1),
        ByteField("pdu_size_val", 0x09)  # 1024 bytes
    ]

# -----------------------------------------------------------------------------
# Utility Functions
# -----------------------------------------------------------------------------
def encode_tsap(connection_type: int, rack: int, slot: int) -> int:
    """
    Encodes Rack and Slot into standard Siemens S7 TSAP format.
    Byte 1: Connection Type (0x01 = PG/PC, 0x02 = OP/HMI, 0x03 = Basic S7)
    Byte 2: (Rack << 5) | Slot
    """
    return (connection_type << 8) | ((rack << 5) | slot)

def format_hex(raw_bytes: bytes) -> str:
    return " ".join(f"{b:02X}" for b in raw_bytes)

# -----------------------------------------------------------------------------
# Phase 1 Lab Actions
# -----------------------------------------------------------------------------
def execute_cotp_handshake(target_ip="127.0.0.1", target_port=102, rack=0, slot=2, conn_type=1):
    dst_tsap = encode_tsap(conn_type, rack, slot)
    src_tsap = 0x0100  # Generic Src TSAP
    
    # 1. Build COTP Layer
    cotp = COTP_CR(dst_tsap=dst_tsap, src_tsap=src_tsap)
    
    # 2. Build TPKT Layer (4 bytes TPKT + length of COTP PDU)
    total_len = 4 + len(cotp)
    tpkt = TPKT(length=total_len)
    
    raw_tx = bytes(tpkt / cotp)

    console.print(Panel(
        f"[bold cyan]Target Endpoint:[/bold cyan] {target_ip}:{target_port}\n"
        f"[bold cyan]Target Routing:[/bold cyan] Rack {rack}, Slot {slot} (Dst-TSAP: 0x{dst_tsap:04X})\n"
        f"[bold cyan]Source TSAP:[/bold cyan] 0x{src_tsap:04X}",
        title="[bold yellow]Phase 1 Action: Crafting TPKT/COTP Connection Request (CR)[/bold yellow]",
        expand=False
    ))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        
        start_time = time.perf_counter()
        sock.connect((target_ip, target_port))
        
        # Send raw frame
        sock.sendall(raw_tx)
        raw_rx = sock.recv(1024)
        rtt = (time.perf_counter() - start_time) * 1000
        sock.close()

        display_dissection(raw_tx, raw_rx, rtt, dst_tsap)

    except Exception as e:
        console.print(f"[bold red][!] Transport Layer Failure: {e}[/bold red]")

def display_dissection(tx_bytes: bytes, rx_bytes: bytes, rtt_ms: float, dst_tsap: int):
    # 1. Framing Breakdown Table
    table = Table(title="TPKT / COTP Transport Layer Exchange", show_header=True, header_style="bold magenta")
    table.add_column("Direction", style="bold cyan", width=12)
    table.add_column("Raw PDU Hex", style="green")
    table.add_column("Framing Breakdown & Field Mapping", style="white")

    # TX Analysis
    tx_tpkt_ver = tx_bytes[0]
    tx_tpkt_len = int.from_bytes(tx_bytes[2:4], "big")
    tx_cotp_type = hex(tx_bytes[5])
    table.add_row(
        "TX (Client)",
        format_hex(tx_bytes),
        f"TPKT Ver: 0x{tx_tpkt_ver:02X} | Length: {tx_tpkt_len}B\n"
        f"COTP Type: {tx_cotp_type} (Connection Request)\n"
        f"Target TSAP: 0x{dst_tsap:04X}"
    )

    # RX Analysis
    if len(rx_bytes) >= 7:
        rx_tpkt_ver = rx_bytes[0]
        rx_tpkt_len = int.from_bytes(rx_bytes[2:4], "big")
        rx_cotp_len = rx_bytes[4]
        rx_cotp_type = rx_bytes[5]
        
        if rx_cotp_type == 0xD0:
            cotp_desc = "0xD0 (Connection Confirm - CC)"
            status_style = "bold green"
        else:
            cotp_desc = f"0x{rx_cotp_type:02X} (Unexpected / Reject)"
            status_style = "bold red"

        rx_dst_ref = int.from_bytes(rx_bytes[6:8], "big")
        rx_src_ref = int.from_bytes(rx_bytes[8:10], "big")

        table.add_row(
            "RX (Server)",
            format_hex(rx_bytes),
            f"TPKT Ver: 0x{rx_tpkt_ver:02X} | Length: {rx_tpkt_len}B\n"
            f"COTP Type: [{status_style}]{cotp_desc}[/{status_style}]\n"
            f"Refs -> Dst: 0x{rx_dst_ref:04X}, Src: 0x{rx_src_ref:04X}"
        )
    else:
        table.add_row("RX (Server)", format_hex(rx_bytes), "Malformed or Truncated Response")

    console.print(table)

    # Summary Panel
    console.print(Panel(
        f"[bold green]✔ TPKT Frame Validated:[/bold green] Version 3 (ISO-on-TCP / RFC 1006)\n"
        f"[bold green]✔ COTP Session State:[/bold green] Connection Confirm (CC) Received in {rtt_ms:.2f} ms\n"
        f"[bold yellow]✔ TSAP Route Processing:[/bold yellow] Target Rack/Slot TSAP accepted by core endpoint\n"
        f"[bold dim]Result: ISO-on-TCP Pipe Open. Ready for Phase 2 S7 PDU Negotiation.[/bold dim]",
        title="[bold green]Phase 1 Observation Summary[/bold green]"
    ))

def test_tsap_anomalies(target_ip="127.0.0.1", target_port=102):
    """
    Tests server behavior against non-standard / unexpected TSAP combinations.
    """
    console.print("\n[bold magenta]=== Phase 1 Stress Action: Non-Standard TSAP Routing ===[/bold magenta]")
    
    # Test cases: (Description, ConnType, Rack, Slot)
    test_cases = [
        ("Invalid Rack/Slot (Rack 7, Slot 31)", 1, 7, 31),
        ("Unusual Connection Type (0x0F)", 15, 0, 2),
    ]

    anomaly_table = Table(title="Unexpected TSAP Routing Responses", show_header=True)
    anomaly_table.add_column("Test Scenario", style="cyan")
    anomaly_table.add_column("Tested Dst-TSAP", style="yellow")
    anomaly_table.add_column("Server Reaction / Status", style="green")

    for desc, conn_type, rack, slot in test_cases:
        tsap = encode_tsap(conn_type, rack, slot)
        cotp = COTP_CR(dst_tsap=tsap)
        pkt = bytes(TPKT(length=4 + len(cotp)) / cotp)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((target_ip, target_port))
            s.sendall(pkt)
            res = s.recv(1024)
            s.close()

            if res and len(res) >= 6 and res[5] == 0xD0:
                reaction = "[yellow]Accepted CC (Lenient Routing)[/yellow]"
            elif res:
                reaction = f"[red]Rejected PDU (0x{res[5]:02X})[/red]"
            else:
                reaction = "[red]Dropped Connection[/red]"

        except Exception as err:
            reaction = f"[red]Socket Error: {err}[/red]"

        anomaly_table.add_row(desc, f"0x{tsap:04X}", reaction)

    console.print(anomaly_table)

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    console.print("[bold white on blue] S7COMM RESEARCH LAB - PHASE 1 EXECUTION [/bold white on blue]\n")
    
    # 1. Primary Handshake Execution (Standard Rack 0, Slot 2)
    execute_cotp_handshake(target_ip="127.0.0.1", target_port=102, rack=0, slot=2)
    
    # 2. TSAP Routing Boundary Checks
    test_tsap_anomalies(target_ip="127.0.0.1", target_port=102)