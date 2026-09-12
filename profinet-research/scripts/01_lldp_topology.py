#!/usr/bin/env python3
import sys
from scapy.all import Ether, Raw, sniff
from rich.console import Console
from rich.panel import Panel
from rich.tree import Tree

console = Console()
INTERFACE = "veth-controller"
ETH_P_LLDP = 0x88cc

def clean_string(b: bytes) -> str:
    """Filters null bytes and control characters from binary TLV strings."""
    return "".join(chr(c) if 32 <= c <= 126 else " " for c in b).strip()

def parse_lldp_tlvs(raw_payload: bytes) -> dict:
    tlvs = {}
    offset = 0
    
    while offset + 2 <= len(raw_payload):
        header = int.from_bytes(raw_payload[offset:offset+2], "big")
        tlv_type = header >> 9
        tlv_len = header & 0x01FF
        value = raw_payload[offset+2 : offset+2+tlv_len]
        
        if tlv_type == 0:  # End of LLDPDU
            break
        elif tlv_type == 1:  # Chassis ID
            tlvs["chassis_id"] = clean_string(value[1:])
        elif tlv_type == 2:  # Port ID
            tlvs["port_id"] = clean_string(value[1:])
        elif tlv_type == 3:  # Time to Live
            tlvs["ttl"] = int.from_bytes(value, "big")
        elif tlv_type == 4:  # Port Description
            tlvs["port_desc"] = clean_string(value)
        elif tlv_type == 5:  # System Name
            tlvs["sys_name"] = clean_string(value)
        elif tlv_type == 6:  # System Description
            tlvs["sys_desc"] = clean_string(value)
            
        offset += 2 + tlv_len
        
    return tlvs

def render_topology_tree(src_mac: str, lldp_data: dict):
    tree = Tree(f"[bold green]L2 Topology Neighbor Identified: {src_mac}[/bold green]")
    
    chassis_node = tree.add(f"[bold cyan]Chassis Information[/bold cyan]")
    chassis_node.add(f"Chassis ID: {lldp_data.get('chassis_id', 'N/A')}")
    chassis_node.add(f"System Name: {lldp_data.get('sys_name', 'p-net IO-Device')}")
    
    port_node = tree.add(f"[bold yellow]Port & Topology Link[/bold yellow]")
    port_node.add(f"Port ID: {lldp_data.get('port_id', 'N/A')}")
    port_node.add(f"Keep-Alive TTL: {lldp_data.get('ttl', 0)} seconds")
    
    console.print(Panel(tree, title="[bold white]LLDP L2 Network Map[/bold white]", border_style="magenta"))

def process_packet(pkt):
    if pkt.haslayer(Ether) and pkt[Ether].type == ETH_P_LLDP:
        raw_bytes = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
        lldp_info = parse_lldp_tlvs(raw_bytes)
        render_topology_tree(pkt[Ether].src, lldp_info)

def main():
    console.print(Panel.fit("[bold white]PROFINET Phase 1: Passive LLDP Topology Mapper[/bold white]", style="magenta"))
    console.print(f"[*] Sniffing [bold cyan]{INTERFACE}[/bold cyan] for LLDP frames (0x88CC)...")
    sniff(iface=INTERFACE, filter="ether proto 0x88cc", prn=process_packet, timeout=6.0)

if __name__ == "__main__":
    main()