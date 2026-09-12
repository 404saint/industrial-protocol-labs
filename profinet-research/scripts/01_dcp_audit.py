#!/usr/bin/env python3
import sys
import time
from scapy.all import Ether, Raw, sendp, AsyncSniffer, get_if_hwaddr
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

INTERFACE = "veth-controller"
ETH_P_PROFINET = 0x8892
DCP_MULTICAST_MAC = "01:0e:cf:00:00:00"

def build_dcp_identify_req(src_mac: str) -> Ether:
    """
    Builds a strictly compliant PROFINET L2 DCP Identify Request Frame.
    Frame ID: 0xFEFE (Identify Request)
    Service ID: 0x05 (Identify), Service Type: 0x00 (Request)
    XID: 0x12345678
    Response Delay: 0x0001 (1 sec)
    DCP Data Length: 0x0004
    Option: 0xFF (All), Suboption: 0xFF (All), Length: 0x0000
    """
    dcp_payload = (
        b"\xfe\xfe"          # Frame ID: DCP Identify Request
        b"\x05\x00"          # Service ID (5=Identify), Service Type (0=Request)
        b"\x12\x34\x56\x78"  # Transaction ID (XID)
        b"\x00\x01"          # Response Delay (1s)
        b"\x00\x04"          # DCP Data Length (4 bytes for Option block)
        b"\xff\xff"          # Option: All (0xFF), Suboption: All (0xFF)
        b"\x00\x00"          # Block Length: 0
    )
    return Ether(dst=DCP_MULTICAST_MAC, src=src_mac, type=ETH_P_PROFINET) / Raw(load=dcp_payload)

def build_dcp_set_station_name(src_mac: str, dst_mac: str, new_name: str) -> Ether:
    """Builds DCP Set Request (0xFEEF) to modify Name of Station."""
    name_bytes = new_name.encode("ascii")
    block_len = 2 + len(name_bytes)
    padding = b"\x00" if (block_len % 2 != 0) else b""
    
    dcp_payload = (
        b"\xfe\xef"          # Frame ID: Set Request
        b"\x03\x00"          # Service ID: Set, Service Type: Request
        b"\x87\x65\x43\x21"  # XID
        b"\x00\x00"          # Response Delay
        + (4 + block_len + len(padding)).to_bytes(2, "big")
        + b"\x02\x02"        # Option 2 (Device Prop), Suboption 2 (Name of Station)
        + block_len.to_bytes(2, "big")
        + b"\x00\x00"        # BlockInfo: Permanent change
        + name_bytes
        + padding
    )
    return Ether(dst=dst_mac, src=src_mac, type=ETH_P_PROFINET) / Raw(load=dcp_payload)

def parse_dcp_blocks(raw_payload: bytes) -> dict:
    parsed = {}
    if len(raw_payload) < 10:
        return parsed
    
    # Strip Frame ID (2), Service ID/Type (2), XID (4), Delay (2)
    dcp_data = raw_payload[10:]
    if len(dcp_data) < 2:
        return parsed
        
    data_len = int.from_bytes(dcp_data[0:2], "big")
    blocks = dcp_data[2:2+data_len]
    offset = 0
    
    while offset + 4 <= len(blocks):
        opt = blocks[offset]
        subopt = blocks[offset+1]
        length = int.from_bytes(blocks[offset+2:offset+4], "big")
        block_body = blocks[offset+4 : offset+4+length]
        
        if opt == 0x01 and subopt == 0x02:  # IP Parameter
            if len(block_body) >= 14:
                parsed["ip"] = ".".join(str(b) for b in block_body[2:6])
                parsed["mask"] = ".".join(str(b) for b in block_body[6:10])
                parsed["gw"] = ".".join(str(b) for b in block_body[10:14])
        elif opt == 0x02 and subopt == 0x02:  # Name of Station
            parsed["station_name"] = block_body[2:].decode("ascii", errors="ignore").rstrip("\x00")
        elif opt == 0x02 and subopt == 0x03:  # Device ID / Vendor ID
            if len(block_body) >= 6:
                parsed["vendor_id"] = f"0x{int.from_bytes(block_body[2:4], 'big'):04X}"
                parsed["device_id"] = f"0x{int.from_bytes(block_body[4:6], 'big'):04X}"

        offset += 4 + length
        if length % 2 != 0:
            offset += 1
            
    return parsed

def render_audit_table(src_mac: str, data: dict):
    table = Table(title="[bold green]L2 DCP Enumeration Report[/bold green]", show_lines=True)
    table.add_column("PROFINET Attribute", style="cyan")
    table.add_column("Value / Parameter", style="bold white")
    
    table.add_row("Device MAC Address", src_mac)
    table.add_row("Name of Station", data.get("station_name", "N/A"))
    table.add_row("Vendor ID", data.get("vendor_id", "N/A"))
    table.add_row("Device ID", data.get("device_id", "N/A"))
    table.add_row("IP Address", data.get("ip", "0.0.0.0"))
    table.add_row("Subnet Mask", data.get("mask", "0.0.0.0"))
    table.add_row("Default Gateway", data.get("gw", "0.0.0.0"))
    
    console.print(Panel(table, expand=False, border_style="bright_blue"))

target_device = {}

def process_response(pkt):
    global target_device
    if pkt.haslayer(Ether) and pkt[Ether].type == ETH_P_PROFINET:
        payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        if payload.startswith(b"\xfe\xff"):  # Identify Response Frame ID (0xFEFF)
            src_mac = pkt[Ether].src
            console.print(f"[bold yellow][+] Captured DCP Identify Response from {src_mac}[/bold yellow]")
            parsed = parse_dcp_blocks(payload)
            target_device["mac"] = src_mac
            target_device["data"] = parsed
            render_audit_table(src_mac, parsed)

def main():
    my_mac = get_if_hwaddr(INTERFACE)
    console.print(Panel.fit("[bold white]PROFINET Phase 1: Active DCP Audit & State Modification[/bold white]", style="blue"))
    
    # 1. Start Async Sniffer BEFORE transmitting
    sniffer = AsyncSniffer(iface=INTERFACE, filter="ether proto 0x8892", prn=process_response)
    sniffer.start()
    time.sleep(0.2)  # Give sniffer socket time to initialize

    # 2. Transmit frame
    console.print(f"[*] Transmitting [bold green]DCP Identify Request[/bold green] on [bold cyan]{INTERFACE}[/bold cyan] ({my_mac})...")
    req_pkt = build_dcp_identify_req(my_mac)
    sendp(req_pkt, iface=INTERFACE, verbose=False)

    # 3. Wait for response
    time.sleep(2.0)
    sniffer.stop()

    if not target_device:
        console.print("[bold red][!] No PROFINET DCP targets responded.[/bold red]")
        sys.exit(1)

    dev_mac = target_device["mac"]

    if "--set-name" in sys.argv:
        new_name = sys.argv[sys.argv.index("--set-name") + 1]
        console.print(f"[*] Executing DCP Set Request: Renaming station to [bold yellow]{new_name}[/bold yellow]...")
        sendp(build_dcp_set_station_name(my_mac, dev_mac, new_name), iface=INTERFACE, verbose=False)

if __name__ == "__main__":
    main()