#!/usr/bin/env python3
from cpppo.server.enip import client

def discover_boundaries():
    print("[*] Phase 10: Initiating CIP Boundary Scan and Attribute Discovery...")
    
    host = "127.0.0.1"
    port = 44818
    
    # We will crawl attributes 1 through 10 on the Identity Object to map the structural limit
    scan_paths = [f"@1/1/{i}" for i in range(1, 11)]
    
    print(f"[*] Sweeping attributes on Class 1, Instance 1 across range 1-10...")
    
    try:
        with client.connector(host=host, port=port) as conn:
            for path in scan_paths:
                print(f"[-] Scanning path boundary: {path}")
                for val in conn.read([path]):
                    pass # Let the state engine handle routing evaluation
    except Exception as e:
        print(f"[-] Scan boundary event: {e}")

if __name__ == "__main__":
    discover_boundaries()