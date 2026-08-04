import sys
import time
import socket
import struct
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax

console = Console()

# --- Protocol Dictionaries ---
APDU_TYPES = {
    0: "ConfirmedRequest",
    1: "UnconfirmedRequest",
    2: "SimpleACK",
    3: "ComplexACK",
    4: "SegmentACK",
    5: "Error",
    6: "Reject",
    7: "Abort",
}

BVLC_FUNCTIONS = {
    0x0A: "Original-Unicast-NPDU",
    0x0B: "Original-Broadcast-NPDU",
    0x04: "Forwarded-NPDU",
    0x09: "Register-Foreign-Device",
}


def decode_apdu_details(apdu: bytes, apdu_type: int) -> str:
    """Extracts high-level fields from APDU payloads for fast human analysis."""
    if not apdu:
        return ""

    # UnconfirmedRequest (Type 1) - e.g., UnconfirmedCOVNotification (Service 0x02)
    if apdu_type == 1 and len(apdu) >= 2:
        service_choice = apdu[1]
        if service_choice == 0x02:
            return "Service: UnconfirmedCOVNotification (0x02)"

    # ComplexACK (Type 3) - ReadPropertyACK
    if apdu_type == 3 and len(apdu) >= 3:
        invoke_id = apdu[1]
        service_choice = apdu[2]
        payload = apdu[3:]

        # Search for BitString tag pattern: Tag 8 (0x82) -> [Tag, UnusedBits, MaskBytes]
        bitstring_idx = payload.find(b"\x82")
        if bitstring_idx != -1 and len(payload) >= bitstring_idx + 3:
            unused_bits = payload[bitstring_idx + 1]
            bitmask_val = payload[bitstring_idx + 2]
            return (
                f"ReadPropertyACK (InvokeID {invoke_id}) -> "
                f"BitString Value: 0x{bitmask_val:02X} (Unused bits: {unused_bits})"
            )
        return f"ComplexACK (InvokeID {invoke_id}, Service 0x{service_choice:02X})"

    # SimpleACK (Type 2)
    if apdu_type == 2 and len(apdu) >= 3:
        invoke_id = apdu[1]
        service_choice = apdu[2]
        return f"SimpleACK (InvokeID {invoke_id}, Service 0x{service_choice:02X})"

    return ""


def parse_bacnet_packet(data: bytes) -> dict | None:
    """
    Parses BVLC and variable-length NPDU headers dynamically.
    Returns parsed structural metadata and unparsed APDU payload.
    """
    if len(data) < 6:
        return None

    # 1. Parse BVLC
    bvlc_type = data[0]
    bvlc_function = data[1]
    bvlc_length = struct.unpack("!H", data[2:4])[0]

    if bvlc_type != 0x81 or len(data) < bvlc_length:
        return None

    offset = 4

    # 2. Parse NPDU
    npdu_version = data[offset]
    offset += 1
    if npdu_version != 0x01:
        return None

    control = data[offset]
    offset += 1

    # Skip NPDU Destination Address if present (Control Bit 5 / 0x20)
    if control & 0x20:
        if offset + 2 > len(data):
            return None
        dlen = data[offset + 2]
        offset += 3 + dlen + 1  # DNET (2B) + DLEN (1B) + DADR (dlen B) + HopCount (1B)

    # Skip NPDU Source Address if present (Control Bit 3 / 0x08)
    if control & 0x08:
        if offset + 2 > len(data):
            return None
        slen = data[offset + 2]
        offset += 3 + slen  # SNET (2B) + SLEN (1B) + SADR (slen B)

    # Skip Message Type if Network Layer Message (Control Bit 7 / 0x80)
    if control & 0x80:
        offset += 1

    if offset >= len(data):
        return None

    apdu = data[offset:]
    apdu_type = (apdu[0] >> 4) & 0x0F
    decoded_info = decode_apdu_details(apdu, apdu_type)

    return {
        "bvlc_function": bvlc_function,
        "control": control,
        "apdu_type": apdu_type,
        "apdu_name": APDU_TYPES.get(apdu_type, f"Unknown (0x{apdu_type:X})"),
        "apdu_bytes": apdu,
        "decoded_info": decoded_info,
    }


def send_and_collect(
    sock: socket.socket, target: tuple[str, int], payload: bytes, timeout: float = 2.5
) -> list[tuple[bytes, dict | None]]:
    """
    Transmits a payload and collects ALL returning packets until deadline expiration.
    Captures asynchronous COVNotifications alongside immediate ACKs.
    """
    sock.sendto(payload, target)
    responses = []
    deadline = time.time() + timeout

    while time.time() < deadline:
        try:
            sock.settimeout(max(0.1, deadline - time.time()))
            data, addr = sock.recvfrom(2048)
            pkt = parse_bacnet_packet(data)
            responses.append((data, pkt))
        except socket.timeout:
            break
        except Exception as e:
            console.print(f"[bold red][!] Socket Error:[/bold red] {e}")
            break

    return responses


def log_packet_stream(title: str, responses: list[tuple[bytes, dict | None]]):
    """Prints ingested raw bytes and parsed APDU telemetry."""
    console.print(f"\n[bold yellow]=== {title} ===[/bold yellow]")
    if not responses:
        console.print("[dim]No packets ingested within deadline window.[/dim]")
        return

    for idx, (raw_data, pkt) in enumerate(responses, 1):
        hex_str = raw_data.hex(" ")
        console.print(f"[bold cyan]Frame #{idx}:[/bold cyan] Ingested {len(raw_data)} bytes")
        console.print(Syntax(hex_str, "text", word_wrap=True))

        if pkt:
            bvlc_name = BVLC_FUNCTIONS.get(pkt["bvlc_function"], hex(pkt["bvlc_function"]))
            detail_str = f" | [green]{pkt['decoded_info']}[/green]" if pkt["decoded_info"] else ""
            console.print(
                f" └─ Parse Result: BVLC Function=[bold green]{bvlc_name}[/bold green] | "
                f"APDU Type=[bold magenta]{pkt['apdu_name']}[/bold magenta] (0x{pkt['apdu_type']:X}){detail_str}\n"
            )
        else:
            console.print(" └─ Parse Result: [red]Malformed or Non-BACnet Frame[/red]\n")


def build_bvlc_npdu(apdu: bytes) -> bytes:
    """Wraps an APDU in standard Original-Unicast-NPDU (BVLC 0x0A, NPDU 0x01 0x04)."""
    npdu = bytes([0x01, 0x04]) + apdu
    bvlc_len = 4 + len(npdu)
    bvlc = bytes([0x81, 0x0A, (bvlc_len >> 8) & 0xFF, bvlc_len & 0xFF])
    return bvlc + npdu


# --- Payload Builders ---

def build_subscribe_cov(invoke_id: int, subscriber_id: int, obj_type: int, obj_inst: int) -> bytes:
    """Builds Confirmed SubscribeCOV (Service 0x05) Request."""
    obj_id_bytes = struct.pack(">I", (obj_type << 22) | (obj_inst & 0x3FFFFF))
    apdu = bytes([
        0x00, 0x02, invoke_id, 0x05,  # Confirmed-Request, Seg=0, InvokeID, Service=SubscribeCOV
        0x09, subscriber_id,          # Context Tag 0: Subscriber Process ID
        0x1C                          # Context Tag 1 Opening
    ]) + obj_id_bytes + bytes([
        0x29, 0x00,                    # Context Tag 2: Issue Confirmed Notifications = False
        0x39, 0x01, 0x2C               # Context Tag 3: Lifetime = 300 seconds
    ])
    return build_bvlc_npdu(apdu)


def build_read_property(invoke_id: int, obj_type: int, obj_inst: int, prop_id: int) -> bytes:
    """Builds ReadProperty (Service 0x0C) Request."""
    obj_id_bytes = struct.pack(">I", (obj_type << 22) | (obj_inst & 0x3FFFFF))
    apdu = bytes([
        0x00, 0x02, invoke_id, 0x0C,  # Confirmed-Request, ReadProperty
        0x0C
    ]) + obj_id_bytes + bytes([
        0x19, prop_id                 # Context Tag 1: Property Identifier
    ])
    return build_bvlc_npdu(apdu)


def build_write_event_enable(invoke_id: int, obj_type: int, obj_inst: int, bitmask: int) -> bytes:
    """Builds WriteProperty (Service 0x0F) for Event_Enable (Prop 35) as a BitString."""
    obj_id_bytes = struct.pack(">I", (obj_type << 22) | (obj_inst & 0x3FFFFF))
    apdu = bytes([
        0x00, 0x02, invoke_id, 0x0F,  # Confirmed-Request, WriteProperty
        0x0C
    ]) + obj_id_bytes + bytes([
        0x19, 0x23,                   # Context Tag 1: Property 35 (Event_Enable)
        0x3E,                         # Opening Tag 3 (Value)
        0x82, 0x05, bitmask,          # Application Tag 8 (BitString): 5 unused bits, byte bitmask
        0x3F                          # Closing Tag 3
    ])
    return build_bvlc_npdu(apdu)


def main():
    target_ip = "192.168.1.196"  # Replace with the target BACnet/IP device IP address
    target_port = 47808
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 0))

    console.print("[bold blue]Starting Updated Pillar 4 Inspection Harness...[/bold blue]")
    summary_observations = []

    # =========================================================================
    # VECTOR A: SubscribeCOV Inspection
    # =========================================================================
    cov_payload = build_subscribe_cov(invoke_id=1, subscriber_id=101, obj_type=0, obj_inst=1)
    resps_a = send_and_collect(sock, (target_ip, target_port), cov_payload)
    log_packet_stream("Vector A: SubscribeCOV (Analog Input 1)", resps_a)

    types_a = [r[1]["apdu_name"] for r in resps_a if r[1]]
    obs_a = f"Ingested {len(resps_a)} frame(s): {', '.join(types_a) if types_a else 'No response'}"
    summary_observations.append(("SubscribeCOV (0x05)", "Analog Input 1", obs_a))

    # =========================================================================
    # VECTOR B: Property 35 (Event_Enable) Read-Write-Read Verification
    # =========================================================================
    console.print("\n[bold yellow]=== Vector B: Event_Enable Dual-Read State Audit ===[/bold yellow]")

    # Step 1: Baseline Read
    rp_pre = build_read_property(invoke_id=2, obj_type=0, obj_inst=1, prop_id=35)
    resps_b1 = send_and_collect(sock, (target_ip, target_port), rp_pre)
    log_packet_stream("Vector B (Step 1): Baseline ReadProperty (Prop 35)", resps_b1)

    # Step 2: Write Property 35 -> 0xE0 (Enable all event transitions)
    wp_payload = build_write_event_enable(invoke_id=3, obj_type=0, obj_inst=1, bitmask=0xE0)
    resps_b2 = send_and_collect(sock, (target_ip, target_port), wp_payload)
    log_packet_stream("Vector B (Step 2): WriteProperty (Prop 35 = 0xE0)", resps_b2)

    # Step 3: Post-Write Read Verification
    rp_post = build_read_property(invoke_id=4, obj_type=0, obj_inst=1, prop_id=35)
    resps_b3 = send_and_collect(sock, (target_ip, target_port), rp_post)
    log_packet_stream("Vector B (Step 3): Post-Write ReadProperty (Prop 35)", resps_b3)

    # Extract state change observation
    pre_val = resps_b1[0][1]["decoded_info"] if resps_b1 and resps_b1[0][1] else "Unknown"
    post_val = resps_b3[0][1]["decoded_info"] if resps_b3 and resps_b3[0][1] else "Unknown"
    obs_b = f"Pre: [{pre_val}] -> Post: [{post_val}]"
    summary_observations.append(("WriteProperty Prop 35 (0xE0)", "Analog Input 1", obs_b))

    # =========================================================================
    # VECTOR C: BACnet/SC Listener Audit (TCP 47809)
    # =========================================================================
    console.print("\n[bold yellow]=== Vector C: BACnet/SC Transport Probe ===[/bold yellow]")
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_sock.settimeout(2.0)
    try:
        tcp_sock.connect((target_ip, 47809))
        obs_c = "TCP Connection Accepted on 47809 (Listener Active)"
    except (socket.timeout, ConnectionRefusedError) as e:
        obs_c = f"Connection Refused / Closed ({type(e).__name__})"
    finally:
        tcp_sock.close()

    console.print(f"Port 47809 Status: [bold magenta]{obs_c}[/bold magenta]")
    summary_observations.append(("WebSocket Handshake (47809)", "BACnet/SC Audit", obs_c))

    # =========================================================================
    # FACTUAL SUMMARY TABLE
    # =========================================================================
    table = Table(title="\nPillar 4 Empirical Observation Summary", title_style="bold green")
    table.add_column("Protocol Probe / Service", style="cyan")
    table.add_column("Target Parameter", style="yellow")
    table.add_column("Empirical Telemetry Observation", style="white")

    for probe, target, obs in summary_observations:
        table.add_row(probe, target, obs)

    console.print(table)
    sock.close()


if __name__ == "__main__":
    main()