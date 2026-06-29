#!/usr/bin/env python3
from cpppo.server.enip import client

def prove_attribute_write():
    print("[*] Phase 6: Executing explicit Set_Attribute_Single (0x10) transaction...")
    
    host = "127.0.0.1"
    port = 44818
    
    # Targeting a configuration attribute route: Class 1, Instance 1, Attribute 2
    # In standard CIP, this modifies or forces specific behavioral states.
    target_attribute_path = "@1/1/2"
    new_state_value = 1

    print(f"[*] Sending Set_Attribute state change to path: {target_attribute_path}")
    
    try:
        with client.connector(host=host, port=port) as conn:
            # Execute the write operation targeting the direct object attribute path
            for val in conn.write([target_attribute_path], data=[new_state_value]):
                print(f"[+] Attribute Write Resolved from State Engine: {val}")
    except Exception as e:
        print(f"[-] Execution error during attribute configuration: {e}")

if __name__ == "__main__":
    prove_attribute_write()