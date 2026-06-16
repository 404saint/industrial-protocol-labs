"""
Note: This is a minimal protocol mock for testing socket connectivity.
To reproduce the specific research findings regarding memory boundaries (8191) 
and coil fuzzing, please use an actual OpenPLC Runtime instance as described in the notes.
"""
import socket

HOST = '127.0.0.1'
PORT = 502  # Standard Modbus port. Note: May require sudo/root.

# Our raw data store for Holding Registers (Addresses 0, 1, 2)
# Register 0: 0xDEAD (57005)
# Register 1: 0xBEEF (48879)
# Register 2: 0x1337 (4919)
REGISTERS = b'\xDE\xAD\xBE\xEF\x13\x37'

def run_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"[*] High-Signal Pure Socket Modbus Server listening on {HOST}:{PORT}...")
        
        while True:
            conn, addr = s.accept()
            with conn:
                print(f"\n[+] Client connected from {addr}")
                request = conn.recv(1024)
                if not request:
                    continue
                
                print(f"[RAW IN] Received Hex: {request.hex().upper()}")
                
                # Minimum Modbus TCP request length is 12 bytes
                if len(request) >= 12:
                    # Extract fields from the incoming MBAP header and PDU
                    tx_id = request[0:2]      # Transaction ID (Echo back to client)
                    proto_id = request[2:4]   # Protocol ID (Should be 00 00)
                    unit_id = request[6]      # Unit ID / Slave ID
                    func_code = request[7]    # Function Code (e.g., 03)
                    
                    # If it's a Read Holding Registers request (Function Code 03)
                    if func_code == 3:
                        print(f"[PARSE] Intercepted Read Holding Registers (FC03) for Unit ID: {unit_id}")
                        
                        # Build the response dynamically
                        # PDU Data payload: Byte Count (6 bytes) + our 3 registers (6 bytes of data)
                        pdu_payload = b'\x06' + REGISTERS
                        
                        # Calculate length: Unit ID (1 byte) + Function Code (1 byte) + PDU Payload
                        length = (2 + len(pdu_payload)).to_bytes(2, byteorder='big')
                        
                        # Assemble full Modbus TCP Application Data Unit (ADU)
                        response = tx_id + proto_id + length + bytes([unit_id]) + bytes([func_code]) + pdu_payload
                        
                        conn.sendall(response)
                        print(f"[RAW OUT] Sent Hex: {response.hex().upper()}")
                    else:
                        print(f"[!] Received unsupported Function Code: {func_code}")

if __name__ == "__main__":
    run_server()