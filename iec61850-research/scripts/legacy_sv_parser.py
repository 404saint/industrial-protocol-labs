#!/usr/bin/env python3
"""
IEC 61850-9-2LE Sampled Values (SV) Dissector for Legacy PCAP Telemetry Streams.
"""

import struct
import sys
from pathlib import Path
import matplotlib.pyplot as plt
from scapy.all import rdpcap, Ether, Raw
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()

SV_ETHERTYPE = 0x88BA
VLAN_ETHERTYPE = 0x8100


class SampledValuesParser:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path
        self.frames_parsed = 0
        self.sv_count = 0
        self.parsed_records = []

    def parse_asdu_payload(self, raw_bytes: bytes) -> dict:
        """
        Parses raw BER-encoded savPDU/ASDU payload for 9-2LE 64-byte measurement datasets.
        """
        # Locate tag 0x87 (Data payload tag in 9-2LE)
        tag_idx = raw_bytes.find(b"\x87")
        if tag_idx == -1 or len(raw_bytes) < tag_idx + 2:
            return None

        len_byte = raw_bytes[tag_idx + 1]
        if len_byte != 0x40:  # 9-2LE fixed dataset is exactly 64 bytes (8 channels * 8 bytes)
            return None

        data_start = tag_idx + 2
        data_bytes = raw_bytes[data_start : data_start + 64]

        if len(data_bytes) < 64:
            return None

        # Extract smpCnt if present (Tag 0x82)
        smp_cnt = None
        smp_idx = raw_bytes.find(b"\x82\x02")
        if smp_idx != -1 and len(raw_bytes) >= smp_idx + 4:
            smp_cnt = struct.unpack(">H", raw_bytes[smp_idx + 2 : smp_idx + 4])[0]

        # Unpack 8 channels: Each channel is Int32 Value + UInt32 Quality Bitmask
        # Payload Order: Ia, q, Ib, q, Ic, q, In, q, Va, q, Vb, q, Vc, q, Vn, q
        unpacked = struct.unpack(">iIiIiIiIiIiIiIiI", data_bytes)

        return {
            "smpCnt": smp_cnt,
            "Ia": (unpacked[0], unpacked[1]),
            "Ib": (unpacked[2], unpacked[3]),
            "Ic": (unpacked[4], unpacked[5]),
            "In": (unpacked[6], unpacked[7]),
            "Va": (unpacked[8], unpacked[9]),
            "Vb": (unpacked[10], unpacked[11]),
            "Vc": (unpacked[12], unpacked[13]),
            "Vn": (unpacked[14], unpacked[15]),
        }

    def plot_waveforms(self, output_file: str = "sv_waveforms.png"):
        """
        Plots 3-phase Current (I) and Voltage (V) sine waves from accumulated SV telemetry.
        """
        if not self.parsed_records:
            console.print("[yellow]No SV records captured for plotting.[/yellow]")
            return

        samples = range(len(self.parsed_records))

        # Extract 3-Phase Currents
        ia = [d["Ia"][0] for d in self.parsed_records]
        ib = [d["Ib"][0] for d in self.parsed_records]
        ic = [d["Ic"][0] for d in self.parsed_records]

        # Extract 3-Phase Voltages
        va = [d["Va"][0] for d in self.parsed_records]
        vb = [d["Vb"][0] for d in self.parsed_records]
        vc = [d["Vc"][0] for d in self.parsed_records]

        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8), sharex=True)
        fig.suptitle(f"IEC 61850-9-2LE Process Bus Telemetry ({Path(self.pcap_path).name})", fontsize=14, fontweight="bold")

        # 3-Phase Current Subplot
        ax1.plot(samples, ia, label="Ia (Phase A)", color="red", alpha=0.85)
        ax1.plot(samples, ib, label="Ib (Phase B)", color="green", alpha=0.85)
        ax1.plot(samples, ic, label="Ic (Phase C)", color="blue", alpha=0.85)
        ax1.set_ylabel("Current (mA/A)")
        ax1.set_title("3-Phase Current Waveforms")
        ax1.grid(True, linestyle="--", alpha=0.5)
        ax1.legend(loc="upper right")

        # 3-Phase Voltage Subplot
        ax2.plot(samples, va, label="Va (Phase A)", color="crimson", linestyle="--", alpha=0.85)
        ax2.plot(samples, vb, label="Vb (Phase B)", color="forestgreen", linestyle="--", alpha=0.85)
        ax2.plot(samples, vc, label="Vc (Phase C)", color="royalblue", linestyle="--", alpha=0.85)
        ax2.set_xlabel("Sample Frame Index")
        ax2.set_ylabel("Voltage (10mV)")
        ax2.set_title("3-Phase Voltage Waveforms")
        ax2.grid(True, linestyle="--", alpha=0.5)
        ax2.legend(loc="upper right")

        plt.tight_layout()
        plt.savefig(output_file, dpi=300)
        console.print(f"[bold green][+][/bold green] Waveform plot successfully saved to '[bold cyan]{output_file}[/bold cyan]'\n")

    def execute(self, max_rows: int = 20, generate_plot: bool = True, output_plot_file: str = "sv_waveforms.png"):
        if not Path(self.pcap_path).is_file():
            console.print(f"[bold red]Error:[/bold red] File '{self.pcap_path}' not found.")
            sys.exit(1)

        table = Table(
            title="[bold cyan]IEC 61850-9-2LE Sampled Values (SV) Frame Stream[/bold cyan]",
            caption="Process Bus Telemetry - Raw Hex & Decoded Primary Values",
            header_style="bold magenta",
            border_style="dim white",
            expand=True,
        )

        table.add_column("Frame", justify="right", style="cyan", no_wrap=True)
        table.add_column("VLAN", justify="center", style="yellow")
        table.add_column("smpCnt", justify="right", style="green")
        table.add_column("Ia (mA/A)", justify="right")
        table.add_column("Ib (mA/A)", justify="right")
        table.add_column("Ic (mA/A)", justify="right")
        table.add_column("In (mA/A)", justify="right")
        table.add_column("Va (10mV)", justify="right")
        table.add_column("Vb (10mV)", justify="right")
        table.add_column("Vc (10mV)", justify="right")
        table.add_column("Quality Flags", justify="left", style="red")

        packets = rdpcap(self.pcap_path)

        for pkt in packets:
            self.frames_parsed += 1
            if not pkt.haslayer(Ether):
                continue

            eth = pkt[Ether]
            vlan_id = "None"
            eth_type = eth.type

            # VLAN Tag Handling (802.1Q)
            if eth_type == VLAN_ETHERTYPE:
                vlan_id = str(pkt.vlan) if hasattr(pkt, "vlan") else "Tag"
            elif eth_type != SV_ETHERTYPE:
                continue

            parsed = self.parse_asdu_payload(bytes(eth.payload))
            if not parsed:
                continue

            self.sv_count += 1
            self.parsed_records.append(parsed)

            # Limit table output to max_rows while accumulating all records for plotting
            if self.sv_count <= max_rows:
                qualities = [parsed[ch][1] for ch in ["Ia", "Ib", "Ic", "In", "Va", "Vb", "Vc", "Vn"]]
                has_anomaly = any(q != 0 for q in qualities)
                q_str = f"[bold red]0x{max(qualities):08X}[/bold red]" if has_anomaly else "[dim green]OK (0x0)[/dim green]"

                table.add_row(
                    str(self.frames_parsed),
                    vlan_id,
                    str(parsed["smpCnt"]) if parsed["smpCnt"] is not None else "N/A",
                    f"{parsed['Ia'][0]:,}",
                    f"{parsed['Ib'][0]:,}",
                    f"{parsed['Ic'][0]:,}",
                    f"{parsed['In'][0]:,}",
                    f"{parsed['Va'][0]:,}",
                    f"{parsed['Vb'][0]:,}",
                    f"{parsed['Vc'][0]:,}",
                    q_str,
                )

        summary_text = Text()
        summary_text.append(f"Parsed File: {self.pcap_path}\n", style="bold white")
        summary_text.append(f"Total L2 Frames Analyzed: {self.frames_parsed}\n", style="dim white")
        summary_text.append(f"Valid 9-2LE SV Frames Processed: {self.sv_count}", style="bold green")

        console.print(Panel(summary_text, title="[bold blue]Capture Summary[/bold blue]", border_style="blue"))
        console.print(table)

        if generate_plot:
            self.plot_waveforms(output_file=output_plot_file)


if __name__ == "__main__":
    pcap = sys.argv[1] if len(sys.argv) > 1 else "Sample240.pcap"
    parser = SampledValuesParser(pcap)
    parser.execute(max_rows=20, generate_plot=True)