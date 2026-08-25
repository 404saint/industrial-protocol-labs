#!/usr/bin/env python3
import socket
import ssl

HOST = "127.0.0.1"
PORT = 19999

def run_rbac_server():
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server-cert.pem", keyfile="server-key.pem")
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations(cafile="ca-cert.pem")
    context.minimum_version = ssl.TLSVersion.TLSv1_3

    bind_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bind_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    bind_socket.bind((HOST, PORT))
    bind_socket.listen(1)

    print(f"\033[1;32m[+] Secure RBAC IEC 104 Server listening on {HOST}:{PORT}\033[0m")

    try:
        while True:
            client_sock, client_addr = bind_socket.accept()
            try:
                secure_conn = context.wrap_socket(client_sock, server_side=True)
                peer_cert = secure_conn.getpeercert()
                cn = dict(x[0] for x in peer_cert.get('subject', [])).get('commonName', 'Unknown')
                print(f"\n[+] Authenticated Session Established with CN: {cn}")

                while True:
                    data = secure_conn.recv(1024)
                    if not data:
                        break
                    
                    print(f"  [rx] Secure Tunnel Bytes ({len(data)}): {data.hex()}")
                    
                    # Basic ASDU Inspection inside TLS
                    if len(data) >= 7:
                        type_id = data[6]
                        # Check for control action (Type 45 / Single Command)
                        if type_id == 45 and len(data) >= 15:
                            ioa = data[12] | (data[13] << 8) | (data[14] << 16)
                            print(f"  [i] Control Request Detected -> IOA: {ioa}")
                            
                            # Enforce Role-Based Access Control (RBAC Simulation)
                            if cn != "scada-engineer" and ioa >= 5000:
                                print(f"  \033[1;31m[!] RBAC Violation:\033[0m User '{cn}' unauthorized for actuator IOA {ioa}.")
                                # Send negative confirmation or application error response
                                err_resp = bytes([0x68, 0x04, 0x47, 0x00, 0x00, 0x00]) # Example error/reject
                                secure_conn.sendall(err_resp)
                                continue

                        print(f"  [✔] Request Authorized & Processed for CN: {cn}")
                        secure_conn.sendall(bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00]))
                    else:
                        print("  \033[1;33m[!] Malformed / Truncated frame inside TLS tunnel dropped.\033[0m")

            except ssl.SSLError as e:
                print(f"  \033[1;31m[-] TLS/Handshake Error:\033[0m {e}")
            except Exception as e:
                print(f"  \033[1;31m[-] Error:\033[0m {e}")
            finally:
                client_sock.close()
    except KeyboardInterrupt:
        print("\n[!] Shutting down.")
    finally:
        bind_socket.close()

if __name__ == "__main__":
    run_rbac_server()