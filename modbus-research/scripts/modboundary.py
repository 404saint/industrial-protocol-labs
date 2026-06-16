#!/usr/bin/env python3

import socket

HOST = "localhost"
PORT = 502
UNIT = 1


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError()
        data += chunk
    return data


def recv_modbus(sock):
    hdr = recv_exact(sock, 7)
    length = int.from_bytes(hdr[4:6], "big")
    body = recv_exact(sock, length - 1)
    return hdr + body


def read_register(sock, tid, addr):
    pdu = bytes([
        0x03,
        (addr >> 8) & 0xff,
        addr & 0xff,
        0x00,
        0x01
    ])

    req = (
        tid.to_bytes(2, "big")
        + b"\x00\x00"
        + (len(pdu)+1).to_bytes(2, "big")
        + bytes([UNIT])
        + pdu
    )

    sock.sendall(req)

    resp = recv_modbus(sock)

    fc = resp[7]

    if fc & 0x80:
        return False

    return True


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

    s.connect((HOST, PORT))

    low = 0
    high = 65535
    tid = 1

    while low < high:

        mid = (low + high + 1) // 2

        ok = read_register(s, tid, mid)
        tid += 1

        print(f"testing {mid} -> {ok}")

        if ok:
            low = mid
        else:
            high = mid - 1

    print("\n[+] Highest readable register:", low)