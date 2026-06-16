import socket

HOST = "localhost"
PORT = 502

# Transaction ID
tid = b"\x00\x01"

# Protocol ID (always 0 for Modbus TCP)
pid = b"\x00\x00"

# Unit ID
uid = b"\x01"

# Function Code 03
fc = b"\x03"

# Starting Address = 0
addr = b"\x00\x00"

# Quantity = 1 register
qty = b"\x00\x01"

# PDU
pdu = uid + fc + addr + qty

# Length field
length = len(pdu).to_bytes(2, "big")

# ADU
request = tid + pid + length + pdu

print("Request:", request.hex(" "))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(request)

    response = s.recv(1024)

print("Response:", response.hex(" "))