#!/usr/bin/env python3
from cpppo.server.enip import client

def discover_identity_attributes():
    print("[*] Phase 8: Extracting clean Identity Object attributes (Class 0x01, Instance 0x01)...")
    
    host = "127.0.0.1"
    port = 44818
    
    # Standard ODVA Identity Object Attributes:
    # Attribute 1: Vendor ID
    # Attribute 2: Device Type
    # Attribute 3: Product Code
    # Attribute 4: Revision (Major/Minor)
    # Attribute 7: Product Name
    attributes = {
        "Vendor ID": "@1/1/1",
        "Device Type": "@1/1/2",
        "Product Code": "@1/1/3",
        "Revision": "@1/1/4",
        "Product Name": "@1/1/7"
    }
    
    try:
        with client.connector(host=host, port=port) as conn:
            for label, path in attributes.items():
                for val in conn.read([path]):
                    print(f"[+] {label:<15} ({path}) -> State Engine Field: {val}")
    except Exception as e:
        print(f"[-] Execution error during identification discovery: {e}")

if __name__ == "__main__":
    discover_identity_attributes();