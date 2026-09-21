#!/usr/bin/env python3
"""
S7comm Protocol Test - Phase 4: System Status List (SZL) & CPU Diagnostics Enumeration
-----------------------------------------------------------------------------------
Objective: Extract hardware metadata, inventory metrics, and operational diagnostics 
using S7 UserData PDU requests without authentication.
"""

import socket
import struct

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 102
SRC_TSAP    = 0x0100
DST_TSAP    = 0x0102  # Rack 0, Slot 2

# --- S7comm protocol lookup tables -----------------------------------------

ROSCTR_TYPES = {
    0x01: "Job (request)",
    0x02: "Ack (no data)",
    0x03: "Ack-Data (response with data)",
    0x07: "Userdata",
}

SZL_IDS = {
    0x0011: "Module Identification (MLFB / Order Number)",
    0x0111: "CPU Hardware / Firmware Version",
    0x0012: "Component Identification",
    0x001C: "Diagnostic Buffer",
}

S7_RETURN_CODES = {
    0xFF: ("Success", "green"),
    0x01: ("Hardware Error", "red"),
    0x03: ("Access Denied", "red"),
    0x04: ("Address Out of Range / Invalid Area", "bold yellow"),
    0x05: ("Address Out of Range (Data Type)", "yellow"),
    0x0A: ("Object Does Not Exist", "bold red"),
}

# --- Protocol builders (matching Phase 2/3 architecture) ----------------------

def build_cotp_cr(src_tsap: int, dst_tsap: int) -> bytes:
    tpkt = bytes([0x03, 0x00, 0x00, 0x16])
    cotp = bytes([
        0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00,
        0xC1, 0x02, (src_tsap >> 8) & 0xFF, src_tsap & 0xFF,
        0xC2, 0x02, (dst_tsap >> 8) & 0xFF, dst_tsap & 0xFF,
        0xC0, 0x01, 0x0A,
    ])
    return tpkt + cotp


def build_s7_setup_comm(pdu_ref: int = 1) -> bytes:
    s7_pdu = bytes([
        0x32, 0x01, 0x00, 0x00,
        (pdu_ref >> 8) & 0xFF, pdu_ref & 0xFF,
        0x00, 0x08, 0x00, 0x00,
        0xF0, 0x00, 0x00, 0x01, 0x00, 0x01, 0x01, 0xE0,
    ])
    tpkt_len = 4 + 3 + len(s7_pdu)
    tpkt = bytes([0x03, 0x00, (tpkt_len >> 8) & 0xFF, tpkt_len & 0xFF])
    cotp_dt = bytes([0x02, 0xF0, 0x80])
    return tpkt + cotp_dt + s7_pdu


def build_szl_request_packet(szl_id: int, szl_index: int, pdu_ref: int = 2) -> bytes:
    """
    Constructs an S7 UserData (ROSCTR 0x07) Read SZL Request PDU.
    Function Group: 0x04 (CPU Services)
    Subfunction:    0x01 (Read SZL)
    """
    # UserData Parameter Block (8 bytes)
    # [0-2] Parameter head (constant, identifies CPU-service UserData)
    # [3]   Length of parameter bytes that follow (0x04)
    # [4]   Method: 0x11 = Request
    # [5]   Type(Request=4) | Function Group(CPU=4), nibble-packed -> 0x44
    # [6]   Subfunction: 0x01 = Read SZL
    # [7]   Sequence number
    param = bytes([
        0x00, 0x01, 0x12,
        0x04,
        0x11,
        0x44,
        0x01,
        0x00,
    ])

    # UserData Data Block — SZL item specification (8 bytes)
    # [0]   Return code placeholder (0xFF for requests)
    # [1]   Transport size (0x09 = Octet String)
    # [2-3] Length of following data (0x0004)
    # [4-5] SZL-ID
    # [6-7] SZL-Index
    data = struct.pack(">BBHHH", 0xFF, 0x09, 0x0004, szl_id, szl_index)

    # S7 Header (ROSCTR 0x07 = UserData)
    s7_header = struct.pack(
        ">BBHHHH",
        0x32, 0x07,   # Protocol ID, ROSCTR: UserData
        0x0000,       # Redundancy ID
        pdu_ref,      # PDU Reference
        len(param),   # Parameter Length
        len(data),    # Data Length
    )

    pdu = s7_header + param + data
    tpkt_len = 4 + 3 + len(pdu)
    return bytes([
        0x03, 0x00, (tpkt_len >> 8) & 0xFF, tpkt_len & 0xFF,
        0x02, 0xF0, 0x80,
    ]) + pdu


def open_session() -> socket.socket:
    """Opens a fresh TCP connection and completes COTP & S7 Setup handshakes."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3.0)
    sock.connect((TARGET_HOST, TARGET_PORT))

    # COTP Connection Request
    sock.sendall(build_cotp_cr(SRC_TSAP, DST_TSAP))
    resp = sock.recv(1024)
    if not resp or len(resp) < 6 or resp[5] != 0xD0:
        raise RuntimeError("COTP handshake failed (expected CC 0xD0)")

    # S7 Setup Communication
    sock.sendall(build_s7_setup_comm(pdu_ref=1))
    resp = sock.recv(1024)
    if not resp or len(resp) < 12 or resp[8] != 0x03:
        raise RuntimeError("S7 PDU negotiation failed (expected Ack-Data 0x03)")

    return sock


def format_hex_dump(data: bytes) -> str:
    """Formats bytes into an aligned hex + ASCII display."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk).ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"  [cyan]{i:04X}[/cyan]  {hex_part}  |[bold white]{ascii_part}[/bold white]|")
    return "\n".join(lines)


def run_szl_query(szl_id: int, szl_index: int = 0x0000):
    desc_szl = SZL_IDS.get(szl_id, "Custom / Extended SZL ID")
    console.print(Panel(
        f"[bold yellow]Querying SZL ID: 0x{szl_id:04X} -- {desc_szl}[/bold yellow]\n"
        f"[dim]Index: 0x{szl_index:04X} | Target: {TARGET_HOST}:{TARGET_PORT}[/dim]",
        expand=False,
    ))

    sock = None
    try:
        sock = open_session()
        packet = build_szl_request_packet(szl_id, szl_index, pdu_ref=2)
        sock.sendall(packet)
        resp = sock.recv(2048)

        if not resp or len(resp) < 12:
            console.print("[bold red][!] Response too short or empty.[/bold red]")
            return

        s7_payload = resp[7:]
        rosctr = s7_payload[1]

        # Ack-Data (0x03) header is 12 bytes; Job/Userdata responses use 10
        param_len = struct.unpack(">H", s7_payload[6:8])[0]
        header_len = 12 if rosctr == 0x03 else 10
        data_start = header_len + param_len

        if len(s7_payload) <= data_start:
            console.print("[bold red][!] Data payload section missing from response.[/bold red]")
            return

        # Extract return code from UserData response item
        return_code = s7_payload[data_start]
        code_desc, code_style = S7_RETURN_CODES.get(return_code, ("Unknown", "bold red"))

        table = Table(box=None)
        table.add_column("Field", style="dim cyan")
        table.add_column("Value", style="white")
        table.add_row("PDU Type (ROSCTR)", f"0x{rosctr:02X} -- {ROSCTR_TYPES.get(rosctr, 'Unknown')}")
        table.add_row("Return Code", f"[{code_style}]0x{return_code:02X} -- {code_desc}[/{code_style}]")
        console.print(table)
        console.print()

        if return_code == 0xFF:
            # Extract raw SZL payload records
            szl_data = s7_payload[data_start:]
            console.print(Panel(
                format_hex_dump(szl_data),
                title=f"[bold white]SZL 0x{szl_id:04X} Response Payload ({len(szl_data)} bytes)[/bold white]",
                expand=False,
            ))

            # Printable strings extraction for MLFB / firmware versions
            printable = "".join([chr(b) if 32 <= b <= 126 else "." for b in szl_data])
            chunks = [c.strip() for c in printable.split('.') if len(c.strip()) >= 3]
            if chunks:
                console.print("\n[bold green]Extracted Device Metadata / Strings:[/bold green]")
                for chunk in chunks:
                    console.print(f"  > [cyan]{chunk}[/cyan]")
        else:
            console.print(f"[yellow][!] SZL query returned non-success code: 0x{return_code:02X}[/yellow]")

    except Exception as e:
        console.print(f"[bold red][!] Execution Error: {e}[/bold red]")
    finally:
        if sock is not None:
            sock.close()


def main():
    console.print(Panel(
        "[bold cyan]S7comm Protocol Test -- Phase 4: SZL & CPU Diagnostics Enumeration[/bold cyan]\n"
        "[dim]Extracting hardware inventory and firmware metadata via unauthenticated UserData PDUs.[/dim]",
        box=box.DOUBLE,
        style="bold white on blue",
    ))

    # Test 1: Module Identification (MLFB / Order Number)
    run_szl_query(szl_id=0x0011, szl_index=0x0000)
    console.print()

    # Test 2: CPU Hardware / Firmware Identification
    run_szl_query(szl_id=0x0111, szl_index=0x0000)


if __name__ == "__main__":
    main()