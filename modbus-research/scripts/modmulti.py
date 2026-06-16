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
            raise ConnectionError(
                "Connection closed by server"
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


#
# FC03
#
def build_fc03_request(
    tid,
    address,
    quantity=1
):
    pid = b"\x00\x00"
    uid = UNIT_ID.to_bytes(1, "big")
    fc = b"\x03"

    pdu = (
        uid
        + fc
        + address.to_bytes(2, "big")
        + quantity.to_bytes(2, "big")
    )

    length = len(pdu).to_bytes(
        2,
        "big"
    )

    return (
        tid.to_bytes(2, "big")
        + pid
        + length
        + pdu
    )


def read_holding(
    sock,
    tid,
    address,
    quantity=1
):
    request = build_fc03_request(
        tid,
        address,
        quantity
    )

    print(
        f"\n[>] FC03 Request : "
        f"{request.hex(' ')}"
    )

    sock.sendall(request)

    response = recv_modbus(
        sock
    )

    print(
        f"[<] FC03 Response: "
        f"{response.hex(' ')}"
    )

    fc = response[7]

    #
    # Exception
    #
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
        end = start + 2

        value = int.from_bytes(
            response[start:end],
            "big"
        )

        values.append(value)

    return {
        "exception": False,
        "values": values
    }


#
# FC16
#
def build_fc16_request(
    tid,
    start_address,
    values
):
    pid = b"\x00\x00"
    uid = UNIT_ID.to_bytes(1, "big")
    fc = b"\x10"

    quantity = len(values)
    byte_count = quantity * 2

    registers = b""

    for value in values:
        registers += value.to_bytes(
            2,
            "big"
        )

    pdu = (
        uid
        + fc
        + start_address.to_bytes(2, "big")
        + quantity.to_bytes(2, "big")
        + byte_count.to_bytes(1, "big")
        + registers
    )

    length = len(pdu).to_bytes(
        2,
        "big"
    )

    return (
        tid.to_bytes(2, "big")
        + pid
        + length
        + pdu
    )


def write_multiple_registers(
    sock,
    tid,
    start_address,
    values
):
    request = build_fc16_request(
        tid,
        start_address,
        values
    )

    print(
        f"\n[>] FC16 Request : "
        f"{request.hex(' ')}"
    )

    sock.sendall(request)

    response = recv_modbus(
        sock
    )

    print(
        f"[<] FC16 Response: "
        f"{response.hex(' ')}"
    )

    fc = response[7]

    #
    # Exception
    #
    if fc & 0x80:
        return {
            "exception": True,
            "code": response[8]
        }

    address = int.from_bytes(
        response[8:10],
        "big"
    )

    quantity = int.from_bytes(
        response[10:12],
        "big"
    )

    return {
        "exception": False,
        "address": address,
        "quantity": quantity
    }


def main():
    values = [
        100,
        200,
        300,
        400,
        500
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

        #
        # FC16
        #
        result = write_multiple_registers(
            sock,
            tid=1,
            start_address=0,
            values=values
        )

        print(
            "\n[*] FC16 Result"
        )
        print(result)

        #
        # FC03 Validation
        #
        result = read_holding(
            sock,
            tid=2,
            address=0,
            quantity=5
        )

        print(
            "\n[*] Readback Result"
        )
        print(result)

        if not result["exception"]:
            print("\n[+] Register Dump")

            for i, value in enumerate(
                result["values"]
            ):
                print(
                    f"[{i}] = {value}"
                )


if __name__ == "__main__":
    main()