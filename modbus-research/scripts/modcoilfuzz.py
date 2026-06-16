#!/usr/bin/env python3

import socket

HOST = "localhost"
PORT = 502
UNIT_ID = 1


def recv_exact(sock, size):
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError()
        data += chunk
    return data


def recv_modbus(sock):
    header = recv_exact(sock, 7)
    length = int.from_bytes(header[4:6], "big")
    body = recv_exact(sock, length - 1)
    return header + body


def write_raw(sock, tid, value):
    request = (
        tid.to_bytes(2, "big")
        + b"\x00\x00"
        + b"\x00\x06"
        + UNIT_ID.to_bytes(1, "big")
        + b"\x05"
        + b"\x00\x00"
        + value.to_bytes(2, "big")
    )

    print(
        f"\n[>] Value: 0x{value:04x}"
    )
    print(
        f"[>] Request: {request.hex(' ')}"
    )

    sock.sendall(request)

    response = recv_modbus(sock)

    print(
        f"[<] Response: {response.hex(' ')}"
    )

    fc = response[7]

    if fc & 0x80:
        print(
            f"[!] Exception: {response[8]}"
        )
        return

    print("[+] Accepted")


values = [
    0x0000,
    0x0001,
    0x0002,
    0x1234,
    0xFFFF,
    0xFF00
]

with socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
) as sock:

    print(
        f"[*] Connecting to "
        f"{HOST}:{PORT}"
    )

    sock.connect(
        (HOST, PORT)
    )

    tid = 1

    for value in values:
        write_raw(sock, tid, value)
        tid += 1