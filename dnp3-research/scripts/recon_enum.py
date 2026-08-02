import socket
import sys
from rich.console import Console
from rich.table import Table

console = Console()

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 20000

# Standard DNP3 IIN Bit Mask Reference (IIN1 and IIN2 bytes)
IIN_FLAGS = {
    "IIN1": {
        0x01: "IIN1.0 - All Stations / Broadcast Received",
        0x02: "IIN1.1 - Class 1 Data Available",
        0x04: "IIN1.2 - Class 2 Data Available",
        0x08: "IIN1.3 - Class 3 Data Available",
        0x10: "IIN1.4 - Time Sync Required",
        0x20: "IIN1.5 - Local Control Active",
        0x40: "IIN1.6 - Device Troubleshooting / Abnormal State",
        0x80: "IIN1.7 - Device Restart Detected"
    },
    "IIN2": {
        0x01: "IIN2.0 - Function Code Not Supported",
        0x02: "IIN2.1 - Object Group / Variation Unknown",
        0x04: "IIN2.2 - Parameter Out of Range",
        0x08: "IIN2.3 - Event Buffer Overflow",
        0x10: "IIN2.4 - Operation Already Executing",
        0x20: "IIN2.5 - Configuration Corrupt",
        0x40: "IIN2.6 - Reserved",
        0x80: "IIN2.7 - Reserved"
    }
}

def build_group80_read_request():
    """
    Constructs a raw DNP3 Read Request frame targeting Group 80 (Device Attributes).
    Header breakdown:
      - 05 64       : Sync Bytes
      - 0A          : Length
      - C4          : Link Control (DIR=1, PRM=1, FC=User Data)
      - 01 00       : Destination Address (1 - Little Endian)
      - 00 00       : Source Address (0 - Master)
      - CRC         : Header CRC-16
      - Transport / App Header + Object Header (Group 80)
    """
    # Standard DNP3 Read Request for Group 80 Var 0 (All Variations)
    # 0x05 0x64 (Sync) + Payload
    raw_payload = bytes.fromhex("05 64 0a c4 01 00 00 00 60 ad c1 c1 01 50 00 06 3b 1c")
    return raw_payload

def parse_iin_bytes(iin1_byte, iin2_byte):
    """Decodes IIN1 and IIN2 bitfields into human-readable flags."""
    active_flags = []
    
    for mask, description in IIN_FLAGS["IIN1"].items():
        if iin1_byte & mask:
            active_flags.append(description)
            
    for mask, description in IIN_FLAGS["IIN2"].items():
        if iin2_byte & mask:
            active_flags.append(description)
            
    return active_flags

def run_recon():
    console.print(f"[bold green][*] Initiating DNP3 Recon Probe against {TARGET_HOST}:{TARGET_PORT}...[/bold green]")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect((TARGET_HOST, TARGET_PORT))
        
        request = build_group80_read_request()
        console.print(f"[cyan][->] Sending Group 80 Read Request ({len(request)} bytes)[/cyan]")
        s.send(request)
        
        response = s.recv(1024)
        if response:
            console.print(f"[bold green][✓] Response received ({len(response)} bytes):[/bold green] {response.hex(' ')}")
            
            # Simple heuristic check for FT3 framing and Application Layer IIN location
            if len(response) >= 14 and response[0] == 0x05 and response[1] == 0x64:
                # In DNP3 responses, IIN bytes sit in the Application Header (bytes 12 & 13 of un-segmented payloads)
                iin1 = response[12]
                iin2 = response[13]
                
                flags = parse_iin_bytes(iin1, iin2)
                
                table = Table(title="DNP3 Internal Indications (IIN) Status")
                table.add_column("Byte", style="cyan", no_wrap=True)
                table.add_column("Hex Value", style="magenta")
                table.add_column("Active Indicators", style="green")
                
                table.add_row("IIN1", f"0x{iin1:02X}", "\n".join([f for f in flags if "IIN1" in f]) or "None")
                table.add_row("IIN2", f"0x{iin2:02X}", "\n".join([f for f in flags if "IIN2" in f]) or "None")
                
                console.print(table)
            else:
                console.print("[yellow][!] Non-standard response payload structure.[/yellow]")
        else:
            console.print("[bold red][!] No data returned from Outstation.[/bold red]")
            
        s.close()
    except Exception as e:
        console.print(f"[bold red][!] Connection error during probe: {e}[/bold red]")

if __name__ == "__main__":
    run_recon()