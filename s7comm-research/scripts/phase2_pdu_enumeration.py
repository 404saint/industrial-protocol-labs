#!/usr/bin/env python3
"""
Phase 2: S7comm PDU Negotiation & Memory Read Enumeration
---------------------------------------------------------
Objective: Establish the main S7 communication state and passively map
memory space layout without altering process data.
"""

import socket
import struct
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 102

# Read target for this run -- change these to enumerate a different DB/offset
DB_NUMBER = 3
START_BYTE = 0
BYTE_COUNT = 16

# --- S7comm protocol lookup tables (for human-readable decoding) -----------

ROSCTR_TYPES = {
    0x01: "Job (request)",
    0x02: "Ack (no data)",
    0x03: "Ack-Data (response with data)",
    0x07: "Userdata",
}

AREA_IDS = {
    0x81: "Process Inputs (I)",
    0x82: "Process Outputs (Q)",
    0x83: "Merkers (M)",
    0x84: "Data Block (DB)",
    0x1C: "Counters (C)",
    0x1D: "Timers (T)",
}

TRANSPORT_SIZES = {
    0x01: "BIT",
    0x02: "BYTE/WORD/DWORD (as bytes)",
    0x03: "INTEGER (bit-counted)",
    0x04: "DINTEGER (bit-counted)",
    0x05: "REAL (bit-counted)",
    0x06: "OCTET STRING",
}

S7_RETURN_CODES = {
    0xFF: ("Success", "green"),
    0x01: ("Hardware Error", "red"),
    0x03: ("Access Denied", "red"),
    0x04: ("Address Out of Range / Invalid Area", "bold yellow"),
    0x05: ("Address Out of Range (Data Type)", "yellow"),
    0x06: ("Data Type Not Supported", "yellow"),
    0x0A: ("Object Does Not Exist", "bold red"),
}


def create_cotp_cr() -> bytes:
    tpkt = struct.pack(">BBH", 3, 0, 22)
    cotp = bytes([
        0x11,                     # COTP Length
        0xE0,                     # Connection Request (CR)
        0x00, 0x00,               # Dst Ref
        0x00, 0x01,               # Src Ref
        0x00,                     # Class 0
        0xC2, 0x02, 0x01, 0x02,   # Dst TSAP (Rack 0, Slot 2)
        0xC1, 0x02, 0x01, 0x00,   # Src TSAP
        0xC0, 0x01, 0x09          # Max PDU Size (1024)
    ])
    return tpkt + cotp


def create_s7_setup_comm(pdu_length: int = 480) -> bytes:
    s7_pdu = bytes([
        0x32,        # Protocol ID
        0x01,        # ROSCTR: Job
        0x00, 0x00,  # Redundancy ID
        0x00, 0x01,  # PDU Reference
        0x00, 0x08,  # Parameter Length (8 bytes)
        0x00, 0x00,  # Data Length (0 bytes)
        0xF0,        # Function: Setup Comm
        0x00,        # Reserved
        0x00, 0x01,  # Max Calling Parallel Jobs (1)
        0x00, 0x01,  # Max Called Parallel Jobs (1)
        (pdu_length >> 8) & 0xFF, pdu_length & 0xFF  # PDU Length
    ])
    cotp_dt = bytes([0x02, 0xF0, 0x80])
    total_len = 4 + len(cotp_dt) + len(s7_pdu)
    tpkt = struct.pack(">BBH", 3, 0, total_len)
    return tpkt + cotp_dt + s7_pdu


def create_s7_read_var(db_number: int, start_byte: int, byte_count: int) -> bytes:
    bit_offset = start_byte * 8

    # 12-Byte S7 Any-Pointer Item:
    # [0] Variable Spec  : 0x12
    # [1] Addr Spec Len  : 0x0A (10 bytes follow)
    # [2] Syntax ID      : 0x10 (S7-Any)
    # [3] Transport Size : 0x02 (BYTE)
    # [4-5] Length       : byte_count
    # [6-7] DB Number    : db_number
    # [8] Area ID        : 0x84 (DB)
    # [9-11] Address     : 24-bit bit-offset pointer
    item_header = struct.pack(
        ">BBBBHHB",
        0x12, 0x0A, 0x10, 0x02,
        byte_count, db_number, 0x84
    )
    address_pointer = bytes([
        (bit_offset >> 16) & 0xFF,
        (bit_offset >> 8) & 0xFF,
        bit_offset & 0xFF
    ])
    s7_item = item_header + address_pointer  # Exactly 12 Bytes

    # S7 PDU Header (10 bytes). Parameter Length = 0x000E (2-byte param
    # header + 12-byte item).
    s7_header = struct.pack(">BBHHHH", 0x32, 0x01, 0x0000, 0x0002, 0x000E, 0x0000)
    param_header = bytes([0x04, 0x01])  # Function 0x04 (ReadVar), Item Count 1
    s7_pdu = s7_header + param_header + s7_item

    cotp_dt = bytes([0x02, 0xF0, 0x80])
    total_len = 4 + len(cotp_dt) + len(s7_pdu)
    tpkt = struct.pack(">BBH", 3, 0, total_len)
    return tpkt + cotp_dt + s7_pdu


def print_read_request_structure(db_number: int, start_byte: int, byte_count: int):
    """Renders the outbound ReadVar item fields as a decoded table, so the
    request is as legible as the response."""
    bit_offset = start_byte * 8
    table = Table(title="[bold cyan]ReadVar Request Item Structure[/bold cyan]", box=None)
    table.add_column("Field", style="dim cyan")
    table.add_column("Raw", style="white")
    table.add_column("Meaning", style="bold green")
    table.add_row("Variable Specification", "0x12", "Item follows (S7 addressing item)")
    table.add_row("Addr. Spec. Length", "0x0A", "10 bytes of addressing data follow")
    table.add_row("Syntax ID", "0x10", "S7-Any pointer")
    table.add_row("Transport Size", "0x02", TRANSPORT_SIZES.get(0x02, "Unknown"))
    table.add_row("Requested Count", str(byte_count), f"{byte_count} bytes requested")
    table.add_row("DB Number", str(db_number), f"Target: DB{db_number}")
    table.add_row("Area ID", "0x84", AREA_IDS.get(0x84, "Unknown"))
    table.add_row("Byte/Bit Address", f"Byte {start_byte}", f"Bit offset {bit_offset} (0x{bit_offset:06X})")
    console.print(table)
    console.print()


def format_hex_dump(data: bytes) -> str:
    """Formats bytes into an aligned hex + ASCII display."""
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02X}" for b in chunk).ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"  [cyan]{i:04X}[/cyan]  {hex_part}  |[bold white]{ascii_part}[/bold white]|")
    return "\n".join(lines)


def main():
    console.print(Panel(
        "[bold green]Phase 2: S7comm PDU Negotiation & Memory Read Enumeration[/bold green]\n"
        "[dim]Objective: establish main communication state and passively map memory "
        "layout without altering process data.[/dim]",
        expand=False
    ))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3.0)

    try:
        # --- Step 1: TCP Connect ---
        sock.connect((TARGET_HOST, TARGET_PORT))
        console.print(f"[dim][+][/dim] Connected to [bold cyan]{TARGET_HOST}:{TARGET_PORT}[/bold cyan]")

        # --- Step 2: COTP Handshake ---
        sock.sendall(create_cotp_cr())
        cotp_resp = sock.recv(1024)
        if len(cotp_resp) >= 6 and cotp_resp[5] == 0xD0:
            console.print("[dim][+][/dim] COTP Connection Confirmed ([bold green]CC 0xD0[/bold green])\n")
        else:
            console.print("[bold red][!] COTP Handshake Failed[/bold red]")
            return

        # --- Step 3: S7 Setup Comm Negotiation ---
        setup_req = create_s7_setup_comm(pdu_length=480)
        sock.sendall(setup_req)
        setup_resp = sock.recv(1024)

        if len(setup_resp) > 10:
            s7_payload = setup_resp[7:]
            rosctr = s7_payload[1]
            rosctr_desc = ROSCTR_TYPES.get(rosctr, "Unknown")

            # Ack-Data header is 12 bytes (proto, rosctr, redID x2, pduRef x2,
            # paramLen x2, dataLen x2, errClass, errCode) before the parameter
            # block (Setup Comm ack param = 8 bytes: function, reserved,
            # max-calling x2, max-called x2, pdu-length x2).
            param_start = 12
            max_calling = struct.unpack(">H", s7_payload[param_start + 2: param_start + 4])[0]
            max_called = struct.unpack(">H", s7_payload[param_start + 4: param_start + 6])[0]
            neg_pdu = struct.unpack(">H", s7_payload[param_start + 6: param_start + 8])[0]

            table = Table(title="[bold yellow]Setup Communication -- PDU Negotiation[/bold yellow]", box=None)
            table.add_column("Parameter", style="dim cyan")
            table.add_column("Value", style="bold green")
            table.add_row("PDU Type (ROSCTR)", f"0x{rosctr:02X} -- {rosctr_desc}")
            table.add_row("Max Calling Parallel Jobs", str(max_calling))
            table.add_row("Max Called Parallel Jobs", str(max_called))
            table.add_row("Negotiated PDU Size", f"{neg_pdu} Bytes")
            console.print(table)
            console.print()

        # --- Step 4: S7 ReadVar Execution ---
        console.print(f"[bold yellow]Executing ReadVar (Function 0x04) -- DB{DB_NUMBER}, "
                       f"byte {START_BYTE}..{START_BYTE + BYTE_COUNT - 1}[/bold yellow]\n")
        print_read_request_structure(DB_NUMBER, START_BYTE, BYTE_COUNT)

        read_req = create_s7_read_var(DB_NUMBER, START_BYTE, BYTE_COUNT)
        sock.sendall(read_req)

        read_resp = sock.recv(1024)
        s7_read_payload = read_resp[7:]

        param_len = struct.unpack(">H", s7_read_payload[6:8])[0]
        rosctr = s7_read_payload[1]
        header_len = 12 if rosctr == 0x03 else 10  # Ack-Data carries 2 extra error-class/code bytes
        data_start = header_len + param_len

        return_code = s7_read_payload[data_start]
        code_desc, code_style = S7_RETURN_CODES.get(return_code, ("Unknown Error Code", "bold red"))

        resp_table = Table(title="[bold yellow]ReadVar Response[/bold yellow]", box=None)
        resp_table.add_column("Field", style="dim cyan")
        resp_table.add_column("Value", style="bold white")
        resp_table.add_row("PDU Type (ROSCTR)", f"0x{rosctr:02X} -- {ROSCTR_TYPES.get(rosctr, 'Unknown')}")
        resp_table.add_row("Return Code", f"[{code_style}]0x{return_code:02X} -- {code_desc}[/{code_style}]")

        if return_code == 0xFF:
            transport_size = s7_read_payload[data_start + 1]
            transport_desc = TRANSPORT_SIZES.get(transport_size, "Unknown")
            data_len_bits = struct.unpack(">H", s7_read_payload[data_start + 2: data_start + 4])[0]
            data_len_bytes = data_len_bits // 8 if transport_size in (0x03, 0x04, 0x05) else data_len_bits

            raw_data = s7_read_payload[data_start + 4: data_start + 4 + data_len_bytes]

            resp_table.add_row("Transport Size", f"0x{transport_size:02X} -- {transport_desc}")
            resp_table.add_row("Data Length", f"{data_len_bytes} Bytes ({data_len_bits} bits on the wire)")
            resp_table.add_row("Source", f"DB{DB_NUMBER}, offset {START_BYTE}")
            console.print(resp_table)
            console.print()
            console.print(Panel(
                format_hex_dump(raw_data),
                title=f"[bold white]DB{DB_NUMBER} Process Data -- byte {START_BYTE} to {START_BYTE + len(raw_data) - 1}[/bold white]",
                expand=False
            ))
        else:
            console.print(resp_table)
            console.print(f"\n[bold yellow][!] ReadVar failed.[/bold yellow] "
                           f"Target server rejected the request against DB{DB_NUMBER}: "
                           f"[bold]0x{return_code:02X} ({code_desc})[/bold].")
            console.print(f"[dim]Hint: confirm DB{DB_NUMBER} is registered via RegisterArea() "
                           f"in the server's source.[/dim]")

    except socket.timeout:
        console.print("[bold red][!] Socket timed out waiting for server response.[/bold red]")
    except Exception as e:
        console.print(f"[bold red][!] Execution Error: {e}[/bold red]")
    finally:
        sock.close()


if __name__ == "__main__":
    main()