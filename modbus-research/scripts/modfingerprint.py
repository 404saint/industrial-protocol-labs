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


def send_probe(sock, tid, fc):
    request = (
        tid.to_bytes(2, "big")
        + b"\x00\x00"
        + b"\x00\x06"
        + UNIT_ID.to_bytes(1, "big")
        + fc.to_bytes(1, "big")
        + b"\x00\x00"
        + b"\x00\x01"
    )

    try:
        sock.sendall(request)
        response = recv_modbus(sock)

        rfc = response[7]

        if rfc & 0x80:
            return {
                "fc": fc,
                "supported": False,
                "exception": response[8],
                "raw": response.hex(" ")
            }

        return {
            "fc": fc,
            "supported": True,
            "raw": response.hex(" ")
        }

    except Exception as e:
        return {
            "fc": fc,
            "supported": False,
            "error": str(e)
        }


def main():
    print(
        f"[*] Connecting to "
        f"{HOST}:{PORT}"
    )

    with socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    ) as sock:

        sock.connect(
            (HOST, PORT)
        )

        print(
            "\n[*] Enumerating function codes...\n"
        )

        for fc in range(1, 128):
            result = send_probe(
                sock,
                tid=fc,
                fc=fc
            )

            print(
                f"FC{fc:02d}: {result}"
            )


if __name__ == "__main__":
    main()