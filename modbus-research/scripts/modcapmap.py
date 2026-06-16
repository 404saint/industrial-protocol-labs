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


def send(sock, tid, pdu):
    request = (
        tid.to_bytes(2, "big")
        + b"\x00\x00"
        + (len(pdu) + 1).to_bytes(2, "big")
        + UNIT_ID.to_bytes(1, "big")
        + pdu
    )

    sock.sendall(request)

    response = recv_modbus(sock)

    fc = response[7]

    if fc & 0x80:
        return False, response[8]

    return True, None


probes = {
    1: b"\x01\x00\x00\x00\x01",
    2: b"\x02\x00\x00\x00\x01",
    3: b"\x03\x00\x00\x00\x01",
    4: b"\x04\x00\x00\x00\x01",
    5: b"\x05\x00\x00\x00\x00",
    6: b"\x06\x00\x00\x00\x00",
    15: b"\x0f\x00\x00\x00\x01\x01\x00",
    16: b"\x10\x00\x00\x00\x01\x02\x00\x00",
}


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

    print("\nCapability Map\n")

    tid = 1

    for fc in sorted(probes):

        ok, exc = send(
            sock,
            tid,
            probes[fc]
        )

        if ok:
            print(
                f"FC{fc:02d} : SUPPORTED"
            )
        else:
            print(
                f"FC{fc:02d} : "
                f"Exception {exc}"
            )

        tid += 1