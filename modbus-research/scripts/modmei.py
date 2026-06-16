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

    length = int.from_bytes(
        header[4:6],
        "big"
    )

    body = recv_exact(
        sock,
        length - 1
    )

    return header + body


def read_device_id(
    sock,
    tid=1,
    read_code=1,
    object_id=0
):
    pdu = bytes([
        0x2B,
        0x0E,
        read_code,
        object_id
    ])

    request = (
        tid.to_bytes(2, "big")
        + b"\x00\x00"
        + (len(pdu) + 1).to_bytes(2, "big")
        + bytes([UNIT_ID])
        + pdu
    )

    print(
        "\n[>] Request :",
        request.hex(" ")
    )

    sock.sendall(request)

    response = recv_modbus(sock)

    print(
        "[<] Response:",
        response.hex(" ")
    )

    return response


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

    read_device_id(sock)