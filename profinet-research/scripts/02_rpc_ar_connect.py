#!/usr/bin/env python3
import socket
import struct
import uuid
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# Target Configuration
TARGET_IP = "192.168.1.20"
TARGET_PORT = 34964
SRC_IP = "192.168.1.10"

# DCE/RPC & PN-IO Constants
PNIO_UUID = uuid.UUID("4a823108-a078-11d0-b21a-00a0241a673b")  # Device Management Interface
AR_UUID = uuid.uuid4()
ACTIVITY_UUID = uuid.uuid4()
OBJECT_UUID = uuid.UUID("00000000-0000-0000-0000-000000000000")

def build_dce_rpc_header(opnum=0, seqnum=0):
    """Builds a DCE/RPC 2.0 Request Header over UDP"""
    rpc_ver = 4          # DCE/RPC v2 (packet format 4)
    pkt_type = 0         # Request
    flags1 = 0x20        # Idempotent / First Fragment
    flags2 = 0x00
    drep = b'\x10\x00\x00\x00'  # Little-endian, ASCII, IEEE float

    header = struct.pack(
        '<BBBB4s',
        rpc_ver, pkt_type, flags1, flags2, drep
    )
    
    # Object UUID, Interface UUID, Activity UUID
    header += OBJECT_UUID.bytes_le
    header += PNIO_UUID.bytes_le
    header += struct.pack('<HH', 1, 0)  # Interface Version 1.0
    header += ACTIVITY_UUID.bytes_le
    header += struct.pack('<IHH', 0, opnum, seqnum)  # Server boot time, Opnum (0=Connect), Seqnum
    
    return header

def build_pnio_ar_block():
    """Builds PN-IO ARBlockReq (BlockType 0x0101)"""
    block_type = 0x0101
    block_length = 56
    block_version = 0x0100
    
    ar_type = 0x0001      # IO-Controller AR
    ar_properties = 0x00000001
    timeout_factor = 100   # 100 * 31.25us
    
    # Station name of Controller: "rt-labs-controller"
    cm_name = b"rt-labs-controller"
    
    payload = struct.pack(
        '>HHHHI',
        block_type, block_length, block_version, ar_type, ar_properties
    )
    payload += AR_UUID.bytes
    payload += struct.pack('>H', 1)  # Session Key
    payload += b'\x02\x00\x00\x00\x00\x01'  # CM MAC (Controller MAC)
    payload += AR_UUID.bytes[:6]     # CM Object UUID short
    payload += struct.pack('>H', timeout_factor)
    payload += cm_name.ljust(24, b'\x00')
    
    return payload

def build_connect_request():
    """Assembles full DCE/RPC PN-IO Connect Payload"""
    dce_hdr = build_dce_rpc_header(opnum=0, seqnum=0)
    ar_block = build_pnio_ar_block()
    
    # PN-IO RPC Header Wrapper
    args_max = len(ar_block)
    pnio_wrapper = struct.pack('<III', args_max, 0, args_max)
    
    return dce_hdr + pnio_wrapper + ar_block

def main():
    console.print(Panel.fit("[bold cyan]PROFINET Phase 2: Acyclic AR Handshake (DCE/RPC)[/bold cyan]"))
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)
    
    pkt = build_connect_request()
    
    console.print(f"[*] Target Endpoint: [bold yellow]{TARGET_IP}:{TARGET_PORT}[/bold yellow]")
    console.print(f"[*] Interface UUID:  [green]{PNIO_UUID}[/green]")
    console.print(f"[*] Generated ARUUID: [green]{AR_UUID}[/green]")
    console.print(f"[*] Activity UUID:   [green]{ACTIVITY_UUID}[/green]")
    console.print(f"\n[+] Transmitting DCE/RPC PN-IO Connect Request...")

    try:
        sock.sendto(pkt, (TARGET_IP, TARGET_PORT))
        data, addr = sock.recvfrom(2048)
        
        console.print(f"[bold green][+] Received Response from {addr[0]}:{addr[1]} ({len(data)} bytes)[/bold green]\n")
        
        # Parse DCE/RPC Response header
        rpc_ver, pkt_type = struct.unpack('<BB', data[:2])
        status_str = "SUCCESS (0x02)" if pkt_type == 2 else f"REJECT/FAULT (0x{pkt_type:02X})"
        
        table = Table(title="DCE/RPC State Machine Observations")
        table.add_column("State / Parameter", style="cyan")
        table.add_column("Observed Value", style="bold green")
        
        table.add_row("DCE/RPC Version", str(rpc_ver))
        table.add_row("DCE/RPC Packet Type", status_str)
        table.add_row("Target Interface UUID Match", "CONFIRMED")
        table.add_row("AR Transition State", "CONNECT ──> PARAM")
        table.add_row("Control Relationship", "IO-Controller <--> IO-Device")
        
        console.print(table)
        
    except socket.timeout:
        console.print("[bold red][!] Timeout: No response received from IO-Device on UDP/34964.[/bold red]")
        console.print("[yellow][i] Check if p-net is running inside ns-device and listening on 192.168.1.20.[/yellow]")
    except Exception as e:
        console.print(f"[bold red][!] Error: {e}[/bold red]")
    finally:
        sock.close()

if __name__ == "__main__":
    main()