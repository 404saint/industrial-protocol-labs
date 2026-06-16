#!/usr/bin/env python3

import socket
import time

HOST = "localhost"
PORT = 502
UNIT_ID = 1


def recv_exact(sock, size):
    data = b""

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError(
                "Connection closed"
            )

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


def read_coils(
    sock,
    tid,
    address,
    quantity
):
    request = (
        tid.to_bytes(2, "big")
        + b"\x00\x00"
        + b"\x00\x06"
        + UNIT_ID.to_bytes(1, "big")
        + b"\x01"
        + address.to_bytes(2, "big")
        + quantity.to_bytes(2, "big")
    )

    print(
        f"\n[>] FC01 Request : "
        f"{request.hex(' ')}"
    )

    sock.sendall(request)

    response = recv_modbus(sock)

    print(
        f"[<] FC01 Response: "
        f"{response.hex(' ')}"
    )

    fc = response[7]

    if fc & 0x80:
        return {
            "exception": True,
            "code": response[8]
        }

    byte_count = response[8]
    payload = response[9:9 + byte_count]

    coils = []

    for byte in payload:
        for bit in range(8):
            coils.append(
                (byte >> bit) & 1
            )

    return {
        "exception": False,
        "coils": coils[:quantity]
    }


def main():
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

        print(
            "\n[*] Watching coils..."
        )

        while True:
            result = read_coils(
                sock,
                tid=tid,
                address=0,
                quantity=8
            )

            if result["exception"]:
                print(result)
                break

            print(
                f"Coils: "
                f"{result['coils']}"
            )

            tid += 1
            time.sleep(0.5)


if __name__ == "__main__":
    main()