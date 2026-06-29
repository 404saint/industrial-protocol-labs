#!/usr/bin/env python3
from cpppo.server.enip import client

def prove_write_single():
    print("[*] Phase 3: Executing native Write Tag Single (0x4D) transaction...")
    
    host = "127.0.0.1"
    port = 44818
    tag = "SAINT_DATA[0]"
    value = 1337

    print(f"[*] Writing value {value} to tag '{tag}' via native connector...")
    
    try:
        with client.connector(host=host, port=port) as conn:
            # Pass the tag name list and specify the data payload separately
            for val in conn.write([tag], data=[value]):
                print(f"[+] Server Processing Response Block: {val}")
    except Exception as e:
        print(f"[-] Execution error during write: {e}")

if __name__ == "__main__":
    prove_write_single()