#!/usr/bin/env python3
import socket
import struct
import time
import sys

INTERFACE = sys.argv[1] if len(sys.argv) > 1 else "veth-device"

FRAME_ID = 0x8000
CYCLE_TIME_MS = 32.0

SRC_MAC = b"\x00\x11\x22\x33\x44\x55"
DST_MAC = b"\x01\x0e\xcf\x00\x00\x00"

# Actual PROFINET RT trailer observed in the Phase 3 PCAP
PN_RT_CYCLE_COUNTER = 0x0000
DATA_STATUS = 0x35
TRANSFER_STATUS = 0x00


def create_raw_socket(interface):
    try:
        sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(0x0003)
        )
        sock.bind((interface, 0))
        return sock
    except PermissionError:
        print("[!] Root privileges required to open AF_PACKET raw sockets.")
        sys.exit(1)


def build_io_data(application_sequence):
    """
    Build the 40-byte application/process-data region.

    PCAP layout:
        bytes 16-17 : application sequence
        bytes 18-21 : 01 02 03 04
        bytes 22-55 : padding
    """

    return (
        struct.pack("!H", application_sequence) +
        b"\x01\x02\x03\x04" +
        b"\x00" * 34
    )


def build_pn_rt_frame(application_sequence):
    eth_hdr = struct.pack(
        "!6s6sH",
        DST_MAC,
        SRC_MAC,
        0x8892
    )

    frame_id = struct.pack("!H", FRAME_ID)

    io_data = build_io_data(application_sequence)

    cycle_counter = struct.pack(
        "!H",
        PN_RT_CYCLE_COUNTER
    )

    footer = struct.pack(
        "!BB",
        DATA_STATUS,
        TRANSFER_STATUS
    )

    return eth_hdr + frame_id + io_data + cycle_counter + footer


def generate_pn_rt_stream(interface):
    sock = create_raw_socket(interface)

    print(
        f"[*] Generating PROFINET RT traffic on interface '{interface}'..."
    )
    print(
        f"[*] FrameID: {hex(FRAME_ID)} | "
        f"Interval: {CYCLE_TIME_MS}ms | "
        f"Cycle Counter: 0x{PN_RT_CYCLE_COUNTER:04x}"
    )
    print(
        "[*] Application sequence occupies IO data bytes 0-1."
    )
    print("[*] Press Ctrl+C to stop.")

    application_sequence = 0

    try:
        while True:
            application_sequence = (
                application_sequence + 1
            ) & 0xFFFF

            frame = build_pn_rt_frame(application_sequence)

            sock.send(frame)

            time.sleep(CYCLE_TIME_MS / 1000.0)

    except KeyboardInterrupt:
        print("\n[*] Traffic generation stopped.")

    finally:
        sock.close()


if __name__ == "__main__":
    generate_pn_rt_stream(INTERFACE)