#!/usr/bin/env python3

import socket

HOST = "localhost"
PORT = 502
UNIT_ID = 1


EXCEPTIONS = {
    0x01: "Illegal Function",
    0x02: "Illegal Data Address",
    0x03: "Illegal Data Value",
    0x04: "Server Device Failure",
    0x05: "Acknowledge",
    0x06: "Server Device Busy",
    0x08: "Memory Parity Error",
    0x0A: "Gateway Path Unavailable",
    0x0B: "Gateway Target Device Failed to Respond",
}


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

    length = int.from_bytes(
        header[4:6],
        "big"
    )

    body = recv_exact(
        sock,
        length - 1
    )

    return header + body


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


def build_fc06_request(
    tid,
    address,
    value
):
    pid = b"\x00\x00"
    uid = UNIT_ID.to_bytes(1, "big")
    fc = b"\x06"

    pdu = (
        uid
        + fc
        + address.to_bytes(2, "big")
        + value.to_bytes(2, "big")
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


def parse_response(data):
    tid = int.from_bytes(
        data[0:2],
        "big"
    )

    fc = data[7]

    result = {
        "tid": tid,
        "function_code": fc,
        "raw": data.hex(" ")
    }

    #
    # Exception response
    #
    if fc & 0x80:
        code = data[8]

        result["exception"] = True
        result["exception_code"] = code
        result["exception_name"] = EXCEPTIONS.get(
            code,
            "Unknown Exception"
        )

        return result

    #
    # FC03
    #
    if fc == 0x03:
        byte_count = data[8]

        values = []

        for i in range(
            0,
            byte_count,
            2
        ):
            start = 9 + i
            end = start + 2

            value = int.from_bytes(
                data[start:end],
                "big"
            )

            values.append(value)

        result["exception"] = False
        result["values"] = values

        return result

    #
    # FC06
    #
    if fc == 0x06:
        address = int.from_bytes(
            data[8:10],
            "big"
        )

        value = int.from_bytes(
            data[10:12],
            "big"
        )

        result["exception"] = False
        result["address"] = address
        result["value"] = value

        return result

    result["exception"] = False
    return result


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

    sock.sendall(request)

    response = recv_modbus(
        sock
    )

    return parse_response(
        response
    )


def write_register(
    sock,
    tid,
    address,
    value
):
    request = build_fc06_request(
        tid,
        address,
        value
    )

    print(
        f"\n[>] FC06 Request : "
        f"{request.hex(' ')}"
    )

    sock.sendall(request)

    response = recv_modbus(
        sock
    )

    print(
        f"[<] FC06 Response: "
        f"{response.hex(' ')}"
    )

    return parse_response(
        response
    )


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

        #
        # Write
        #
        result = write_register(
            sock,
            tid=1,
            address=0,
            value=1337
        )

        print(
            "\n[*] Write Result"
        )
        print(result)

        #
        # Read it back
        #
        result = read_holding(
            sock,
            tid=2,
            address=0
        )

        print(
            "\n[*] Read Result"
        )
        print(result)

        if (
            not result["exception"]
            and result["values"]
        ):
            value = result["values"][0]

            print(
                f"\n[+] Register 0 = "
                f"{value}"
            )


if __name__ == "__main__":
    main()