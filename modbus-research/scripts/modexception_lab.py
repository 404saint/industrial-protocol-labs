#!/usr/bin/env python3

import socket
import time

HOST = "localhost"
PORT = 502
UNIT_ID = 1


# -----------------------------
# Low-level Modbus utilities
# -----------------------------

def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


def recv_modbus(sock):
    header = recv_exact(sock, 7)
    length = int.from_bytes(header[4:6], "big")
    body = recv_exact(sock, length - 1)
    return header + body


def send_raw(sock, tid, pdu):
    request = (
        tid.to_bytes(2, "big") +
        b"\x00\x00" +
        (len(pdu) + 1).to_bytes(2, "big") +
        UNIT_ID.to_bytes(1, "big") +
        pdu
    )

    sock.sendall(request)
    return recv_modbus(sock)


def parse_response(resp):
    fc = resp[7]

    if fc & 0x80:
        return {
            "exception": True,
            "code": resp[8]
        }

    return {
        "exception": False,
        "fc": fc
    }


# -----------------------------
# Test 1: Illegal Quantity
# -----------------------------

def test_illegal_quantity(sock, tid):
    print("\n=== Illegal Quantity Test ===")

    test_cases = [
        (3, 0),        # invalid (0 registers)
        (3, 126),      # above FC03 limit
        (3, 1000),     # absurdly large
    ]

    for fc, qty in test_cases:
        pdu = bytes([
            fc,
            0x00, 0x00,      # address
            (qty >> 8) & 0xFF,
            qty & 0xFF
        ])

        resp = send_raw(sock, tid, pdu)
        parsed = parse_response(resp)

        print(f"FC{fc} qty={qty} -> {parsed}")
        tid += 1

    return tid


# -----------------------------
# Test 2: Illegal Address range
# -----------------------------

def test_address_bounds(sock, tid):
    print("\n=== Address Boundary Test ===")

    addresses = [0, 10, 100, 1000, 60000]

    for addr in addresses:
        pdu = bytes([
            3,
            (addr >> 8) & 0xFF,
            addr & 0xFF,
            0x00, 0x01
        ])

        resp = send_raw(sock, tid, pdu)
        parsed = parse_response(resp)

        print(f"addr={addr} -> {parsed}")
        tid += 1

    return tid


# -----------------------------
# Test 3: Malformed Length
# -----------------------------

def test_malformed_length(sock, tid):
    print("\n=== Malformed Length Test ===")

    # We lie in MBAP header length field
    # but still send valid payload

    pdu = bytes([3, 0x00, 0x00, 0x00, 0x01])

    request = (
        tid.to_bytes(2, "big") +
        b"\x00\x00" +
        b"\x00\xFF" +   # WRONG LENGTH (huge)
        UNIT_ID.to_bytes(1, "big") +
        pdu
    )

    print("[>] Sending malformed length packet")

    try:
        sock.sendall(request)
        resp = recv_modbus(sock)
        print("[<] Response:", resp.hex(" "))
        print(parse_response(resp))

    except Exception as e:
        print("[!] Exception:", str(e))

    return tid + 1


# -----------------------------
# Test 4: Truncated Packet
# -----------------------------

def test_truncated(sock, tid):
    print("\n=== Truncated Packet Test ===")

    # Send incomplete frame manually
    packet = (
        tid.to_bytes(2, "big") +
        b"\x00\x00" +
        b"\x00\x06" +
        UNIT_ID.to_bytes(1, "big") +
        b"\x03\x00"
    )

    print("[>] Sending truncated packet")

    try:
        sock.sendall(packet)
        resp = recv_modbus(sock)
        print("[<] Response:", resp.hex(" "))
        print(parse_response(resp))

    except Exception as e:
        print("[!] Exception:", str(e))

    return tid + 1


# -----------------------------
# Test 5: Recovery Test
# -----------------------------

def test_recovery(sock, tid):
    print("\n=== Recovery Test ===")

    sequence = [
        bytes([0x2B, 0x0E, 0x01, 0x00]),  # FC43 invalid
        bytes([0x2B, 0x0E, 0x01, 0x00]),  # repeat invalid
        bytes([0x03, 0x00, 0x00, 0x00, 0x01])  # valid FC03
    ]

    for i, pdu in enumerate(sequence):
        resp = send_raw(sock, tid, pdu)
        parsed = parse_response(resp)

        print(f"step {i} -> {parsed}")
        tid += 1

    return tid


# -----------------------------
# Main
# -----------------------------

def main():
    print(f"[*] Connecting to {HOST}:{PORT}")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))

        tid = 1

        tid = test_illegal_quantity(sock, tid)
        tid = test_address_bounds(sock, tid)
        tid = test_malformed_length(sock, tid)
        tid = test_truncated(sock, tid)
        tid = test_recovery(sock, tid)

        print("\n[*] Exception research complete.")


if __name__ == "__main__":
    main()