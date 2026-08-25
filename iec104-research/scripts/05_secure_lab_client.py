import socket
import ssl

HOST = "127.0.0.1"
PORT = 19999

def send_secure_command(ioa_target, desc):
    print(f"\n--- Test: Dispatching Control to {desc} (IOA: {ioa_target}) over TLS ---")
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.load_verify_locations(cafile="ca-cert.pem")
    context.load_cert_chain(certfile="client-cert.pem", keyfile="client-key.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    with socket.create_connection((HOST, PORT)) as raw_sock:
        with context.wrap_socket(raw_sock, server_hostname="localhost") as secure_sock:
            # Build Type 45 Single Command frame
            frame = bytes([
                0x68, 0x0B,              # APCI Length (11 bytes payload)
                0x00, 0x00, 0x00, 0x00,  # N(S)=0, N(R)=0
                0x2D,                    # Type ID 45 (Single Command)
                0x01,                    # VSQ: 1
                0x06, 0x00,              # COT: 6 (Activation)
                0x01, 0x00,              # CA: 1
                ioa_target & 0xFF, (ioa_target >> 8) & 0xFF, (ioa_target >> 16) & 0xFF,
                0x01                     # State: ON
            ])
            
            secure_sock.sendall(frame)
            resp = secure_sock.recv(1024)
            print(f"  [rx] Raw Response Bytes: {resp.hex()}")
            
            # Parse response confirmation type
            if len(resp) >= 4:
                control_byte = resp[2]
                if control_byte == 0x47:
                    print(f"  \033[1;31m[✔] RBAC Enforcement Verified:\033[0m Server rejected command (Negative Confirmation / Access Denied).")
                elif control_byte == 0x0B:
                    print(f"  \033[1;32m[✔] Authorized Execution:\033[0m Command accepted.")
                else:
                    print(f"  [i] Received control status byte: 0x{control_byte:02X}")

if __name__ == "__main__":
    send_secure_command(5001, "Critical Breaker Actuator")
