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


def build_request(tid, address, quantity=1):
    """
    Build an FC03 (Read Holding Registers) request.
    """

    protocol_id = b"\x00\x00"
    unit_id = UNIT_ID.to_bytes(1, "big")
    function_code = b"\x03"

    pdu = (
        unit_id
        + function_code
        + address.to_bytes(2, "big")
        + quantity.to_bytes(2, "big")
    )

    length = len(pdu).to_bytes(2, "big")

    adu = (
        tid.to_bytes(2, "big")
        + protocol_id
        + length
        + pdu
    )

    return adu


def send_request(sock, request):
    sock.sendall(request)
    return sock.recv(1024)


def parse_response(data):
    """
    Parse a Modbus TCP response.
    """

    tid = int.from_bytes(data[0:2], "big")
    protocol_id = int.from_bytes(data[2:4], "big")
    length = int.from_bytes(data[4:6], "big")
    unit_id = data[6]
    function_code = data[7]

    result = {
        "tid": tid,
        "protocol_id": protocol_id,
        "length": length,
        "unit_id": unit_id,
        "function_code": function_code,
    }

    # Exception response
    if function_code & 0x80:
        exception_code = data[8]

        result["exception"] = True
        result["exception_code"] = exception_code
        result["exception_name"] = EXCEPTIONS.get(
            exception_code,
            "Unknown Exception"
        )

        return result

    # Normal response
    byte_count = data[8]

    values = []

    for i in range(0, byte_count, 2):
        start = 9 + i
        end = start + 2

        value = int.from_bytes(
            data[start:end],
            "big"
        )

        values.append(value)

    result["exception"] = False
    result["byte_count"] = byte_count
    result["values"] = values

    return result


def read_holding(sock, tid, address, quantity=1):
    request = build_request(
        tid,
        address,
        quantity
    )

    response = send_request(
        sock,
        request
    )

    return parse_response(response)


def scan_range(sock, start, end):
    tid = 1

    for address in range(start, end):

        try:
            result = read_holding(
                sock,
                tid,
                address
            )

            if result["exception"]:
                print(
                    f"[{address:05d}] "
                    f"EXCEPTION "
                    f"{result['exception_code']:02x} "
                    f"({result['exception_name']})"
                )
            else:
                value = result["values"][0]

                print(
                    f"[{address:05d}] = {value}"
                )

        except Exception as e:
            print(
                f"[{address:05d}] ERROR: {e}"
            )

        tid += 1


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
            "[*] Enumerating holding "
            "registers..."
        )

        scan_range(
            sock,
            start=0,
            end=100
        )


if __name__ == "__main__":
    main()