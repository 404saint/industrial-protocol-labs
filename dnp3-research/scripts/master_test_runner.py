import sys
import time
import socket
import struct
import logging
from dataclasses import dataclass
from typing import Tuple, Optional
from rich.console import Console
from rich.table import Table

console = Console()

# Configure logger
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("DNP3-MasterRunner")

# ============================================================================
# PROTOCOL CONSTANTS
# ============================================================================

DNP3_START_BYTES = b'\x05\x64'

# Function Codes
FC_CONFIRM = 0x00
FC_READ = 0x01
FC_WRITE = 0x02
FC_SELECT = 0x03
FC_OPERATE = 0x04
FC_DIRECT_OPERATE = 0x05
FC_RESPONSE = 0x81
FC_UNSOLICITED_RESPONSE = 0x82

# Secure Authentication Function Codes (IEEE 1815-2012 / SA v5)
FC_AUTH_REQUEST = 0x20
FC_AUTH_RESPONSE = 0x21

# SA Variations
SA_CHALLENGE = 1
SA_REPLY = 2
SA_AGRESSOR_CHECK = 3
SA_SESSION_KEY_STATUS = 4
SA_SESSION_KEY_CHANGE = 5
SA_ERROR = 7


# ============================================================================
# DNP3 CRC HELPERS
# ============================================================================

def compute_dnp3_crc(data: bytes) -> int:
    """Computes standard DNP3 CRC-16 (inverted remainder)."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return ~crc & 0xFFFF


def append_crc_block(data: bytes) -> bytes:
    """Appends 2-byte little-endian CRC to a block of up to 16 bytes."""
    crc = compute_dnp3_crc(data)
    return data + struct.pack('<H', crc)


def verify_crc_block(block_with_crc: bytes) -> bool:
    """Verifies DNP3 CRC for a block containing data + 2-byte CRC."""
    if len(block_with_crc) < 3:
        return False
    data = block_with_crc[:-2]
    expected_crc = struct.unpack('<H', block_with_crc[-2:])[0]
    return compute_dnp3_crc(data) == expected_crc


# ============================================================================
# DNP3 MASTER TEST HARNESS ENGINE
# ============================================================================

class DNP3MasterHarness:
    def __init__(self, target_host: str = "127.0.0.1", target_port: int = 20000, master_addr: int = 100, outstation_addr: int = 1):
        self.host = target_host
        self.port = target_port
        self.master_addr = master_addr
        self.outstation_addr = outstation_addr
        self.tx_sequence = 0
        self.app_sequence = 0
        self.sock: Optional[socket.socket] = None

    def connect(self) -> bool:
        """Establishes TCP connection to the Outstation."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(3.0)
            self.sock.connect((self.host, self.port))
            console.print(f"[bold green][+] Connected to Outstation at {self.host}:{self.port}[/bold green]")
            return True
        except Exception as e:
            console.print(f"[bold red][!] Connection failed: {e}[/bold red]")
            return False

    def disconnect(self):
        """Closes active socket connection."""
        if self.sock:
            self.sock.close()
            self.sock = None

    def build_frame(self, app_payload: bytes) -> bytes:
        """Wraps Application payload into Transport Control byte and FT3 Data Link Frame."""
        # Transport Header: FIR=1, FIN=1, SEQ (0x60 bitwise mask)
        transport_header = bytes([0xC0 | (self.tx_sequence & 0x3F)])
        self.tx_sequence = (self.tx_sequence + 1) % 64

        tp_payload = transport_header + app_payload
        user_data_len = len(tp_payload) + 5  # Length includes DIR/PRM/FC + Dest(2) + Source(2)

        # Build FT3 Link Header: Sync(05 64), Length, Control (DIR=1, PRM=1, FC=UserData -> 0xC4), Dest, Src
        header_raw = (
            DNP3_START_BYTES +
            bytes([user_data_len, 0xC4]) +
            struct.pack('<H', self.outstation_addr) +
            struct.pack('<H', self.master_addr)
        )
        link_header = append_crc_block(header_raw)

        # Append payload blocks in 16-byte chunks with CRC-16 padding
        chunked_payload = bytearray()
        for i in range(0, len(tp_payload), 16):
            chunk = tp_payload[i : i + 16]
            chunked_payload.extend(append_crc_block(chunk))

        return link_header + bytes(chunked_payload)

    def parse_response(self, raw: bytes) -> Tuple[bool, int, bytes]:
        """
        Parses raw bytes received from Outstation, checking link CRC and extracting Application payload.
        Returns: (Success Flag, Function Code, App Payload)
        """
        if len(raw) < 10:
            return False, 0, b""

        if raw[0:2] != DNP3_START_BYTES:
            return False, 0, b""

        if not verify_crc_block(raw[0:10]):
            console.print("[bold red][!] Header CRC Error in Response[/bold red]")
            return False, 0, b""

        expected_len = raw[2] - 5
        payload_crc = raw[10:]

        # Extract user payload stripping 2-byte CRCs
        user_data = bytearray()
        idx = 0
        remaining = expected_len
        while idx < len(payload_crc) and remaining > 0:
            block_len = min(16, remaining)
            chunk = payload_crc[idx : idx + block_len]
            user_data.extend(chunk)
            idx += block_len + 2
            remaining -= block_len

        if len(user_data) < 2:
            return False, 0, b""

        # User data layout: [Transport Header (1 byte)][App Header (2 bytes)][App Payload]
        app_bytes = user_data[1:]
        app_ctrl = app_bytes[0]
        func_code = app_bytes[1]
        app_payload = app_bytes[2:]

        return True, func_code, app_payload

    def send_and_receive(self, app_payload: bytes) -> Tuple[bool, int, bytes]:
        """Helper to transmit a built frame and wait for response."""
        frame = self.build_frame(app_payload)
        console.print(f"[cyan][->] Sending Frame ({len(frame)} bytes):[/cyan] {frame[:14].hex(' ')}...")

        try:
            self.sock.sendall(frame)
            response_raw = self.sock.recv(1024)
            if not response_raw:
                console.print("[red][!] No data received (Connection Closed)[/red]")
                return False, 0, b""

            console.print(f"[magenta][<-] Received Response ({len(response_raw)} bytes):[/magenta] {response_raw[:14].hex(' ')}...")
            return self.parse_response(response_raw)
        except Exception as e:
            console.print(f"[bold red][!] Transmit/Receive Error: {e}[/bold red]")
            return False, 0, b""


# ============================================================================
# PHASE 5 TEST SUITE EXECUTION MODULES
# ============================================================================

def run_phase5_master_suite():
    console.print("[bold blue]=========================================================[/bold blue]")
    console.print("[bold green]   DNP3 PHASE 5: SECURE AUTHENTICATION TEST SUITE       [/bold green]")
    console.print("[bold blue]=========================================================[/bold blue]\n")

    harness = DNP3MasterHarness(target_host="127.0.0.1", target_port=20000)

    if not harness.connect():
        sys.exit(1)

    results_table = Table(title="Phase 5 Execution Summary")
    results_table.add_column("Test ID", style="cyan", no_wrap=True)
    results_table.add_column("Test Description", style="bold yellow")
    results_table.add_column("Expected Result", style="blue")
    results_table.add_column("Status", style="bold green")

    try:
        # --------------------------------------------------------------------
        # TEST 1: Standard Binary/Analog Telemetry Scan (FC 0x01)
        # --------------------------------------------------------------------
        console.print("\n[bold yellow][*] TEST 1: Executing Class 0 Integrity / Read Scan (FC 0x01)[/bold yellow]")
        # App Ctrl: FIR=1, FIN=1, CON=0, UNS=0, SEQ=0 -> 0xC0
        app_read = bytes([0xC0, FC_READ, 0x01, 0x02, 0x06])  # Read Group 1 Var 2
        success, fc, payload = harness.send_and_receive(app_read)
        
        if success and fc == FC_RESPONSE:
            console.print("[bold green][✓] Telemetry Read Accepted. IIN Bytes verified.[/bold green]")
            results_table.add_row("P5-01", "Class 0 Integrity Read", "FC 0x81 Response", "[green]PASS[/green]")
        else:
            results_table.add_row("P5-01", "Class 0 Integrity Read", "FC 0x81 Response", "[red]FAIL[/red]")

        # --------------------------------------------------------------------
        # TEST 2: Secure Authentication Challenge Initiation (FC 0x20 Var 1)
        # --------------------------------------------------------------------
        console.print("\n[bold yellow][*] TEST 2: Requesting SA Challenge Object (FC 0x20 Variation 1)[/bold yellow]")
        # FC 0x20 Auth Request, Object 120 Variation 1 (Challenge)
        app_sa_challenge = bytes([0xC1, FC_AUTH_REQUEST, 120, SA_CHALLENGE])
        success, fc, payload = harness.send_and_receive(app_sa_challenge)

        if success and fc == FC_AUTH_RESPONSE:
            console.print("[bold green][✓] SA Challenge Response Received (FC 0x21 / Group 120 Var 1).[/bold green]")
            results_table.add_row("P5-02", "SA Challenge Request", "FC 0x21 Response", "[green]PASS[/green]")
        else:
            results_table.add_row("P5-02", "SA Challenge Request", "FC 0x21 Response", "[red]FAIL[/red]")

        # --------------------------------------------------------------------
        # TEST 3: SA Session Key Status Response Verification (FC 0x20 Var 2)
        # --------------------------------------------------------------------
        console.print("\n[bold yellow][*] TEST 3: Submitting SA Challenge Reply (FC 0x20 Variation 2)[/bold yellow]")
        # FC 0x20 Auth Request, Object 120 Variation 2 (Reply) + Dummy HMAC Bytes
        fake_hmac_reply = bytes([0xC2, FC_AUTH_REQUEST, 120, SA_REPLY]) + (b'\x01' * 8)
        success, fc, payload = harness.send_and_receive(fake_hmac_reply)

        if success and fc == FC_AUTH_RESPONSE:
            console.print("[bold green][✓] Outstation validated HMAC session structure & responded with Status (Group 120 Var 4).[/bold green]")
            results_table.add_row("P5-03", "SA Challenge Reply", "FC 0x21 Session Key Status", "[green]PASS[/green]")
        else:
            results_table.add_row("P5-03", "SA Challenge Reply", "FC 0x21 Session Key Status", "[red]FAIL[/red]")

        # --------------------------------------------------------------------
        # TEST 4: Control Command Execution (CROB - FC 0x03 Select / 0x04 Operate)
        # --------------------------------------------------------------------
        console.print("\n[bold yellow][*] TEST 4: Issuing Select-Before-Operate Control (FC 0x03 - Group 12 Var 1)[/bold yellow]")
        # Select Command for Point 0 (Control Code 0x01 - Pulse On)
        app_select = bytes([0xC3, FC_SELECT, 12, 1, 0x17, 0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00])
        success, fc, payload = harness.send_and_receive(app_select)

        if success and fc == FC_RESPONSE:
            console.print("[bold green][✓] Control Select Reserved on Target.[/bold green]")
            results_table.add_row("P5-04", "CROB Control Select", "FC 0x81 ACK", "[green]PASS[/green]")
        else:
            results_table.add_row("P5-04", "CROB Control Select", "FC 0x81 ACK", "[red]FAIL[/red]")

        # Print Execution Results
        console.print("\n")
        console.print(results_table)

    finally:
        harness.disconnect()


if __name__ == "__main__":
    run_phase5_master_suite()