#!/usr/bin/env python3

import socket
import time

HOST = "localhost"
PORT = 502
UNIT_ID = 1


# ==========================================================
# Socket Helpers
# ==========================================================

def recv_exact(sock, size):
    data = b""

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            raise ConnectionError(
                "Server closed connection"
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


# ==========================================================
# FC03
# ==========================================================

def read_holding(
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
        + b"\x03"
        + address.to_bytes(2, "big")
        + quantity.to_bytes(2, "big")
    )

    sock.sendall(request)

    response = recv_modbus(sock)

    fc = response[7]

    if fc & 0x80:
        return {
            "exception": True,
            "code": response[8]
        }

    byte_count = response[8]

    values = []

    for i in range(
        0,
        byte_count,
        2
    ):
        start = 9 + i

        value = int.from_bytes(
            response[start:start + 2],
            "big"
        )

        values.append(value)

    return {
        "exception": False,
        "values": values
    }


# ==========================================================
# FC16
# ==========================================================

def write_multiple_registers(
    sock,
    tid,
    start_address,
    values
):
    quantity = len(values)
    byte_count = quantity * 2

    payload = b""

    for v in values:
        payload += v.to_bytes(
            2,
            "big"
        )

    pdu = (
        UNIT_ID.to_bytes(1, "big")
        + b"\x10"
        + start_address.to_bytes(2, "big")
        + quantity.to_bytes(2, "big")
        + byte_count.to_bytes(1, "big")
        + payload
    )

    length = len(pdu).to_bytes(
        2,
        "big"
    )

    request = (
        tid.to_bytes(2, "big")
        + b"\x00\x00"
        + length
        + pdu
    )

    sock.sendall(request)

    response = recv_modbus(sock)

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
        "quantity": int.from_bytes(
            response[10:12],
            "big"
        )
    }


# ==========================================================
# Experiment 1
# ==========================================================

def test_max_register_count(sock):
    print("\n=== Maximum Register Count ===")

    for count in [
        120,
        121,
        122,
        123,
        124,
        125
    ]:
        try:
            values = list(
                range(count)
            )

            result = write_multiple_registers(
                sock,
                tid=count,
                start_address=0,
                values=values
            )

            print(
                f"{count} registers -> "
                f"{result}"
            )

        except Exception as e:
            print(
                f"{count} registers -> "
                f"CRASH ({e})"
            )


# ==========================================================
# Experiment 2
# ==========================================================

def test_address_boundaries(sock):
    print("\n=== Address Boundaries ===")

    addresses = [
        0,
        100,
        1000,
        10000,
        65535
    ]

    for addr in addresses:
        try:
            result = write_multiple_registers(
                sock,
                tid=100 + addr,
                start_address=addr,
                values=[111, 222, 333]
            )

            print(
                f"addr={addr} -> "
                f"{result}"
            )

        except Exception as e:
            print(
                f"addr={addr} -> "
                f"CRASH ({e})"
            )


# ==========================================================
# Experiment 3
# ==========================================================

def test_atomicity(sock):
    print("\n=== Atomicity Test ===")

    boundary = 65534

    try:
        result = write_multiple_registers(
            sock,
            tid=999,
            start_address=boundary,
            values=[
                111,
                222,
                333
            ]
        )

        print(result)

    except Exception as e:
        print(
            f"Atomicity test crashed: "
            f"{e}"
        )


# ==========================================================
# Experiment 4
# ==========================================================

def test_performance(sock):
    print("\n=== Performance Test ===")

    payload = list(
        range(100)
    )

    start = time.time()

    success = 0

    for i in range(100):
        try:
            result = write_multiple_registers(
                sock,
                tid=2000 + i,
                start_address=0,
                values=payload
            )

            if not result["exception"]:
                success += 1

        except Exception:
            pass

    end = time.time()

    print(
        f"Successful writes: "
        f"{success}/100"
    )

    print(
        f"Elapsed time: "
        f"{end - start:.2f}s"
    )


# ==========================================================
# Validation
# ==========================================================

def dump_first_20(sock):
    print("\n=== Register Dump ===")

    result = read_holding(
        sock,
        tid=5000,
        address=0,
        quantity=20
    )

    print(result)


# ==========================================================
# Main
# ==========================================================

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

        test_max_register_count(sock)
        test_address_boundaries(sock)
        test_atomicity(sock)
        test_performance(sock)
        dump_first_20(sock)

    print("\n[*] Research complete.")


if __name__ == "__main__":
    main()