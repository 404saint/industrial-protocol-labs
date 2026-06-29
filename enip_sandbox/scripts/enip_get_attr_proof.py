#!/usr/bin/env python3
from cpppo.server.enip import client

def prove_attribute_query():
    print("[*] Phase 5: Executing explicit Get_Attribute_Single (0x0E) transaction...")
    
    host = "127.0.0.1"
    port = 44818
    
    # In cpppo client syntax, direct object paths can be explicitly addressed
    # Using the standard identity object route: Class 1, Instance 1, Attribute 1
    identity_path = "@1/1/1"

    print(f"[*] Querying Identity Object Attribute via native connector: {identity_path}")
    
    try:
        with client.connector(host=host, port=port) as conn:
            # Query the core object attribute
            for val in conn.read([identity_path]):
                print(f"[+] Attribute Data Resolved from State Engine: {val}")
    except Exception as e:
        print(f"[-] Execution error during attribute query: {e}")

if __name__ == "__main__":
    prove_attribute_query()