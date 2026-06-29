# 11 - Network Detection Heuristics and Signature Logic

## Overview

EtherNet/IP detection is not based solely on function codes or register patterns, but on layered behavioral signals across three protocol levels:

* EtherNet/IP Encapsulation Header
* Common Packet Format (CPF)
* CIP Application Services and Status Codes

These layers together provide a reliable basis for identifying enumeration activity, unauthorized configuration attempts, and malformed session behavior in industrial environments.

---

## Behavioral Detection Signatures

### 1. Unauthenticated Capability Discovery (ListServices)

* **Behavior**: A client issues a `ListServices` request (`0x0004`) to an EtherNet/IP device, often without following up with a session establishment (`RegisterSession`, `0x0065`).
* **Interpretation**: This pattern is commonly associated with passive discovery or pre-engagement fingerprinting of the EtherNet/IP stack.
* **Protocol Indicator**: Encapsulation command field equals `0x0004`.

This request is frequently used to identify supported communication services before application-layer interaction begins.

---

### 2. Tag Enumeration and Attribute Brute-Force Patterns

* **Behavior**: Repeated explicit messaging requests return CIP General Status codes such as:

  * `0x05` (Path Destination Unknown)
  * `0x14` (Attribute Not Supported)
* **Interpretation**: Indicates systematic probing of object classes, instances, or symbolic tag namespaces.
* **Protocol Indicator**: High frequency of non-zero CIP status responses within a short time interval.

This pattern reflects structured traversal of the CIP object model rather than isolated request failures.

---

### 3. Invalid Session or Out-of-Sequence Transport Attempts

* **Behavior**: Explicit messaging commands such as `SendRRData` (`0x006F`) or `SendUnitData` (`0x0070`) are transmitted with an invalid or zeroed Session Handle (`0x00000000`).
* **Interpretation**: Indicates malformed session state, unauthenticated injection attempts, or broken protocol sequencing.
* **Protocol Indicator**: Valid encapsulation command but invalid session context.

---

## Intrusion Detection Rule Examples

The following examples illustrate how EtherNet/IP behavior can be detected using packet inspection logic.

---

### Rule 1: Detect ListServices Enumeration

```text
alert tcp any any -> any 44818 (
    msg:"ICS-ENIP-SCAN: ListServices Capability Discovery";
    dsize:24;
    content:"|04 00|"; offset:0; depth:2;
    classtype:protocol-command-decode;
    sid:2001001;
    rev:1;
)
```

**Logic**:
Detects a `ListServices` encapsulation command (`0x0004`) by matching the first two bytes of the EtherNet/IP frame. The fixed-size payload reflects a minimal capability query.

---

### Rule 2: Detect Unauthorized Attribute Modification Attempts

```text
alert tcp any any -> any 44818 (
    msg:"ICS-CIP-WRITE: Set_Attribute_Single Configuration Change Attempt";
    content:"|6F 00|"; offset:0; depth:2;
    content:"|10|"; distance:24; within:1;
    classtype:industrial-control;
    sid:2001002;
    rev:1;
)
```

**Logic**:
Identifies a `SendRRData` encapsulation header (`0x006F`) and inspects the CIP service layer following the encapsulation header for a `Set Attribute Single` operation (`0x10`), indicating a configuration write attempt.

---

## Security Characteristics

* EtherNet/IP detection relies on multi-layer inspection across encapsulation, CPF, and CIP service fields.
* Enumeration behavior is often visible through repeated CIP error status patterns rather than successful responses.
* Session integrity is critical; invalid session handles are strong indicators of malformed or injected traffic.
* Detection logic must account for both successful and failed CIP transactions, as reconnaissance often relies on error-based inference.

---

## Key Takeaways

* EtherNet/IP detection is multi-layered, spanning encapsulation, transport, and CIP application services.
* `ListServices` (`0x0004`) is commonly used for unauthenticated stack discovery.
* Repeated CIP status codes such as `0x05` and `0x14` indicate structured enumeration behavior.
* Invalid or missing session handles (`0x00000000`) are strong indicators of malformed or injected traffic.
* Effective IDS rules must correlate encapsulation commands with CIP service behavior, not just individual bytes.
