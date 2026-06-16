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


def write_single_coil(
    sock,
    tid,
    address,
    state
):
    value = (
        b"\xff\x00"
        if state
        else b"\x00\x00"
    )

    request = (
        tid.to_bytes(2, "big")
        + b"\x00\x00"
        + b"\x00\x06"
        + UNIT_ID.to_bytes(1, "big")
        + b"\x05"
        + address.to_bytes(2, "big")
        + value
    )

    print(
        f"\n[>] FC05 Request : "
        f"{request.hex(' ')}"
    )

    sock.sendall(request)

    response = recv_modbus(sock)

    print(
        f"[<] FC05 Response: "
        f"{response.hex(' ')}"
    )

    fc = response[7]

    if fc & 0x80:
        return {
            "exception": True,
            "code": response[8]
        }

    return {
        "exception": False,
        "address": int.from_bytes(
            response[8:10],
            "big"
        ),
        "value": response[10:12].hex()
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

    print("\n[*] Turning coil ON")
    result = write_single_coil(
        sock,
        tid=1,
        address=0,
        state=True
    )
    print(result)

    input(
        "\nPress ENTER to turn it OFF..."
    )

    print("\n[*] Turning coil OFF")
    result = write_single_coil(
        sock,
        tid=2,
        address=0,
        state=False
    )
    print(result)