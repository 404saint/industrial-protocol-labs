#!/usr/bin/env python3
from cpppo.server.enip import client

def prove_fragmented_operations():
    print("[*] Phase 4: Triggering Fragmented Array Bounds tracking...")
    
    host = "127.0.0.1"
    port = 44818
    
    # Requesting the entire 10-element range forces the engine to calculate 
    # array boundaries and track index limits.
    tag_slice = "SAINT_DATA[0-9]"

    print(f"[*] Querying array slice via native connector: {tag_slice}")
    
    try:
        with client.connector(host=host, port=port) as conn:
            # Execute the read across the array span
            for val in conn.read([tag_slice]):
                print(f"[+] Elements Recovered from State Generator: {val}")
    except Exception as e:
        print(f"[-] Execution error during fragmented read: {e}")

if __name__ == "__main__":
    prove_fragmented_operations()