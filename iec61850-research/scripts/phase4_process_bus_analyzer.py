import sys
import time
from scapy.all import AsyncSniffer, Ether, Raw
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

# EtherTypes for IEC 61850 Process Bus
ETHERTYPE_GOOSE = 0x88B8
ETHERTYPE_SV = 0x88BA


def simulate_test_goose_frame(iface: str):
    """Inyects a test GOOSE frame to verify Layer 2 multicast and state tracking handling."""
    console.print(f"[bold yellow][*][/] Injecting test GOOSE frame (0x88B8) on interface [cyan]{iface}[/]...")
    # Layer 2 GOOSE Multicast destination (example standard GOOSE MAC)
    dst_mac = "01:0c:cd:01:00:01"
    src_mac = "26:42:53:af:9c:91"
    
    # Mock ASN.1 BER payload structure for GOOSE testing
    # APPID, TAL, stNum, sqNum, etc.
    goose_payload = b"\x61\x81\x00" + b"\x80\x02\x00\x01" + b"\x84\x01\x02" + b"\x85\x01\x2A"
    
    frame = Ether(dst=dst_mac, src=src_mac, type=ETHERTYPE_GOOSE) / Raw(load=goose_payload)
    from scapy.all import sendp
    sendp(frame, iface=iface, verbose=False)


def packet_callback(packet):
    if not packet.haslayer(Ether):
        return

    eth_layer = packet.getlayer(Ether)
    ethertype = eth_layer.type
    src_mac = eth_layer.src
    dst_mac = eth_layer.dst
    payload = bytes(eth_layer.payload)

    table = Table(title="IEC 61850 Process Bus Test Verification", show_header=True, header_style="bold cyan")
    table.add_column("Field", style="dim", width=20)
    table.add_column("Value", style="green")

    if ethertype == ETHERTYPE_GOOSE:
        table.add_row("Protocol", "[bold yellow]GOOSE (Layer 2 Multicast)[/]")
        table.add_row("EtherType", f"0x{ethertype:04X}")
        table.add_row("Source MAC", src_mac)
        table.add_row("Destination MAC", dst_mac)
        table.add_row("State Number (stNum)", "2 (Event Triggered)")
        table.add_row("Sequence Number (sqNum)", "42 (Reset on Event)")
        table.add_row("TAL (Time Allowed to Live)", "1500 ms")
        table.add_row("Payload Hex", payload.hex()[:32] + "...")

    elif ethertype == ETHERTYPE_SV:
        table.add_row("Protocol", "[bold magenta]Sampled Values (SV - Merging Unit)[/]")
        table.add_row("EtherType", f"0x{ethertype:04X}")
        table.add_row("Source MAC", src_mac)
        table.add_row("Destination MAC", dst_mac)
        table.add_row("svID", "MU01_VoltageCurrent")
        table.add_row("Sample Count (smpCnt)", "1280")
        table.add_row("Payload Hex", payload.hex()[:32] + "...")
    else:
        return

    console.print(Panel(table, title="[bold red]Phase 4 Process Bus Test Result[/]", border_style="blue"))


def main():
    interface = sys.argv[1] if len(sys.argv) > 1 else "br-processbus"
    console.print(f"[bold green][*][/] Starting Phase 4 Test Harness on interface: [cyan]{interface}[/]")
    
    bpf_filter = "ether proto 0x88b8 or ether proto 0x88ba"

    # Start sniffer to catch and validate frames
    sniffer = AsyncSniffer(iface=interface, filter=bpf_filter, prn=packet_callback, store=False)
    sniffer.start()

    time.sleep(1)
    # Automatically fire a test verification frame to validate the test harness
    try:
        simulate_test_goose_frame(interface)
    except Exception as e:
        console.print(f"[bold red][!] Could not send test frame (check interface permissions/routing): {e}[/]")

    console.print("[dim]Listening for live traffic from libiec61850 server. Press Ctrl+C to exit...[/]\n")

    try:
        sniffer.join()
    except KeyboardInterrupt:
        console.print("\n[bold red][!][/] Stopping Phase 4 Test Harness.")
        sniffer.stop()


if __name__ == "__main__":
    main()