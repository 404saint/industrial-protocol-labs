import os
import sys
import tempfile
from lxml import etree as ET
import socket
import subprocess

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.syntax import Syntax
from rich.text import Text

console = Console()

TARGET_IP = "192.168.1.10"
TARGET_PORT = 102
TARGET_NETNS = "ns-ied1"

# ----------------------------------------------------------------------
# Test 1.1: XML Parsing Resiliency (XXE / Entity Expansion Probe)
# ----------------------------------------------------------------------

def run_test_xml_parsing():
    console.print(Panel("[bold cyan]Test 1.1: XML Parsing Resiliency (XXE / Entity Expansion)[/bold cyan]"))
    
    # Malformed / XXE-infused SCL payload
    xxe_scl_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE SCL [
  <!ENTITY xxeTest SYSTEM "file:///etc/passwd">
  <!ENTITY lol "lol">
  <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<SCL xmlns="http://www.iec.ch/61850/2003/SCL" revision="B">
  <Header id="EXP_TEST_01" version="1.0.0"/>
  <Substation name="Substation_Alpha">
    <VoltageLevel name="110kV">
      <Bay name="Bay_Bay1">
        <ConductingEquipment name="CB1" type="CBR">
          <SubEquipment name="Payload">&xxeTest;</SubEquipment>
        </ConductingEquipment>
      </Bay>
    </VoltageLevel>
  </Substation>
</SCL>"""

    console.print("[bold yellow][*] Generated SCL Test Payload (XXE & Entity Expansion Probe)[/bold yellow]")
    console.print(Syntax(xxe_scl_payload[:360] + "\n...", "xml", theme="monokai", line_numbers=True))

    with tempfile.NamedTemporaryFile(suffix=".xml", mode="w+", delete=False) as tmp_scl:
        tmp_scl.write(xxe_scl_payload)
        tmp_scl_path = tmp_scl.name

    parsing_failed = False
    observation_detail = ""

    try:
        # Explicit lxml parser configuration targeting entity expansion behavior
        parser = ET.XMLParser(resolve_entities=True, dtd_validation=False, load_dtd=True)
        tree = ET.parse(tmp_scl_path, parser=parser)
        root = tree.getroot()
        
        # Check if entity was expanded in sub-equipment payload text
        sub_eq = root.find(".//{http://www.iec.ch/61850/2003/SCL}SubEquipment")
        expanded_val = sub_eq.text if sub_eq is not None else ""
        
        observation_detail = (
            f"Parser expanded entity reference.\n"
            f"Parsed content snippet: {expanded_val[:40]}...\n"
            f"Impact: Unrestricted entity expansion enabled (XXE / File Ingestion risk)."
        )
    except ET.XMLSyntaxError as xse:
        parsing_failed = True
        observation_detail = f"lxml rejected malicious DTD/entity expansion safely:\n{xse}"
    except Exception as e:
        parsing_failed = True
        observation_detail = f"Parser raised exception:\n{type(e).__name__}: {e}"
    finally:
        if os.path.exists(tmp_scl_path):
            os.remove(tmp_scl_path)

    # Output Summary Table
    table = Table(title="Test 1.1 Summary: SCL Schema Resiliency")
    table.add_column("Target Plane", style="bold green")
    table.add_column("Vulnerability Class", style="bold yellow")
    table.add_column("Observed Parser Reaction", style="white")
    table.add_column("Verdict", style="bold cyan")
    
    verdict = "[bold red]VULNERABLE[/bold red]" if not parsing_failed else "[bold green]RESILIENT[/bold green]"
    table.add_row(
        "Engineering / SCL",
        "XXE / DTD Expansion",
        observation_detail,
        verdict
    )
    
    console.print(table)
    console.print()

# ----------------------------------------------------------------------
# Test 1.2: Dataset Schema & Logical Node Mapping Mutation
# ----------------------------------------------------------------------

def run_test_dataset_manipulation():
    console.print(Panel("[bold cyan]Test 1.2: Dataset Schema & Logical Node Mapping Mutation[/bold cyan]"))

    base_scl_snippet = """<DataSet name="datasetAnalogValues">
  <FCDA ldInst="LD0" lnClass="GGIO" lnInst="1" doName="AnIn1" daName="mag.f" fc="MX"/>
</DataSet>"""

    mutated_scl_snippet = """<DataSet name="datasetAnalogValues">
  <FCDA ldInst="LD0" lnClass="XCBR" lnInst="1" doName="AnIn1" daName="mag.f" fc="ST"/>
</DataSet>"""

    console.print("[bold green][+] Original SCL FCDA Mapping:[/bold green]")
    console.print(Syntax(base_scl_snippet, "xml", theme="monokai"))
    
    console.print("\n[bold red][!] Mutated SCL FCDA Mapping (Functional Constraint MX -> ST, LN Class GGIO -> XCBR):[/bold red]")
    console.print(Syntax(mutated_scl_snippet, "xml", theme="monokai"))

    console.print("\n[bold yellow][*] Probing target IED ISO-on-TCP stack inside namespace...[/bold yellow]")

    # Execute a connection probe inside the namespace to generate wire telemetry for external capture
    soc_script = f"""
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
try:
    s.connect(('{TARGET_IP}', {TARGET_PORT}))
    # TPKT/COTP CR
    s.send(bytes.fromhex('0300001611e00000000100c1020001c2020002c0010a'))
    s.recv(1024)
except Exception:
    pass
finally:
    s.close()
"""
    cmd = ["sudo", "ip", "netns", "exec", TARGET_NETNS, "python3", "-c", soc_script]
    res = subprocess.run(cmd, capture_output=True, text=True)

    wire_explanation = (
        "Generated ISO-on-TCP (TPKT/COTP) handshake against IED endpoint.\n"
        "Wire-level drift occurs when subscriber SCL schema definitions\n"
        "diverge from live MMS/GOOSE object models (e.g., FC=MX vs FC=ST)."
    )

    table = Table(title="Test 1.2 Summary: Dataset Schema Mutation")
    table.add_column("Target Attribute", style="bold green")
    table.add_column("Mutation Applied", style="bold yellow")
    table.add_column("Protocol Impact & Trust Boundary", style="white")

    table.add_row(
        "FCDA Definition",
        "FC: MX (Measured) -> ST (Status)\nLN: GGIO -> XCBR",
        wire_explanation
    )
    
    console.print(table)
    console.print()

# ----------------------------------------------------------------------
# Main Execution Entry Point
# ----------------------------------------------------------------------

if __name__ == "__main__":
    console.print(Panel.fit(
        "[bold white on blue] IEC 61850 LAB - PHASE 1 TEST HARNESS [/bold white on blue]\n"
        "[italic]SCL Configuration & Schema Attack Surface Execution[/italic]\n\n"
        "[bold yellow]Ensure tcpdump/Wireshark is recording on 'br-process' in another terminal.[/bold yellow]"
    ))
    console.print()
    
    run_test_xml_parsing()
    run_test_dataset_manipulation()
    
    console.print("[bold green]✔ Phase 1 execution completed.[/bold green]")