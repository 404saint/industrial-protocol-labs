#!/usr/bin/env python3
from cpppo.server.enip import client

def prove_exceptions():
    print("[*] Phase 9: Intentionally triggering CIP Routing Exception...")
    
    host = "127.0.0.1"
    port = 44818
    invalid_tag = "NON_EXISTENT_TAG"

    print(f"[*] Querying invalid tag via native connector: {invalid_tag}")
    
    try:
        with client.connector(host=host, port=port) as conn:
            for val in conn.read([invalid_tag]):
                print(f"[+] Response (Unexpected): {val}")
    except Exception as e:
        print(f"\n[+] Caught Expected Exception at Application Layer:")
        print(f"    -> {e}")

if __name__ == "__main__":
    prove_exceptions()