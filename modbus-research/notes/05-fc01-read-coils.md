# FC01 – Read Coils

## Objective

Understand and manually implement Modbus Function Code 01 (Read Coils), observe coil state changes in real-time, and analyze how Modbus encodes discrete outputs inside protocol responses.

---

## Protocol Overview

* **Function Code:** `0x01`
* **Purpose:** Read the status of one or more sequential coils.

A coil is a **single-bit value** representing binary states:

* `0` = OFF
* `1` = ON

### Typical representations:

* Relays, physical switches, and actuators
* Digital outputs
* Internal PLC logic flags

### Compared to Holding Registers:

* **Registers:** 16-bit values (analog, integer, multi-bit data).
* **Coils:** 1-bit values (strictly binary ON/OFF).

---

## Request Structure

| Field | Size (Bytes) | Description |
| --- | --- | --- |
| **Transaction ID** | 2 | Identifies the request/response pair |
| **Protocol ID** | 2 | `00 00` = Modbus protocol |
| **Length** | 2 | Number of remaining bytes |
| **Unit ID** | 1 | Target device address |
| **Function Code** | 1 | FC01 (`0x01`) |
| **Start Address** | 2 | The first coil address to read |
| **Quantity** | 2 | Number of coils to read |

---

## Lab Setup

* **Target:** OpenPLC Runtime (Modbus TCP)
* **Port:** `502`
* **Client:** Custom Python implementation utilizing raw socket communication
* **Test Range:** Coils 0 through 7 (Quantity: 8 coils)

---

## Manual Packet Construction

### FC01 Request:

`00 01 00 00 00 06 01 01 00 00 00 08`

### Field Breakdown:

* `00 01` $\rightarrow$ Transaction ID
* `00 00` $\rightarrow$ Protocol ID
* `00 06` $\rightarrow$ Remaining bytes (6 bytes follow)
* `01`    $\rightarrow$ Unit ID
* `01`    $\rightarrow$ Function Code (`0x01`)
* `00 00` $\rightarrow$ Starting Coil Address (0)
* `00 08` $\rightarrow$ Quantity of coils to read (8)

---

## Observed Response

* **Response:** `00 01 00 00 00 04 01 01 01 00`

### Decoded Response PDU:

* **Byte Count** = `01` (1 data byte follows to represent 8 coils)
* **Data Byte** = `0x00`

**Result:** Coil array matches `[0, 0, 0, 0, 0, 0, 0, 0]`. All target coils were actively **OFF**.

---

## Real-Time Coil Observation

During execution, the PLC program logic actively toggled Coil 0. Continuous polling captured the following real-time state changes:

### State 1

* **Response:** `00 02 00 00 00 04 01 01 01 01`
* **Data Byte:** `0x01` $\rightarrow$ Binary: `00000001`
* **Decoded Status:** `[1, 0, 0, 0, 0, 0, 0, 0]` (Coil 0 turned **ON**)

### State 2

* **Response:** `00 03 00 00 00 04 01 01 01 00`
* **Data Byte:** `0x00` $\rightarrow$ Binary: `00000000`
* **Decoded Status:** `[0, 0, 0, 0, 0, 0, 0, 0]` (Coil 0 turned **OFF**)

### State 3

* **Response:** `00 06 00 00 00 04 01 01 01 01`
* **Data Byte:** `0x01` $\rightarrow$ Binary: `00000001`
* **Decoded Status:** `[1, 0, 0, 0, 0, 0, 0, 0]` (Coil 0 toggled back **ON**)

---

## Coil Encoding (The Bit-Ordering Gotcha)

Modbus packs multiple coil states into a single data byte, but it employs a **Least Significant Bit (LSB) first** mapping structure.

Suppose we read 8 coils with the following active states:

```text
Coil Map: [1, 0, 1, 1, 0, 0, 0, 1]  (Where index 0 is Coil 0)

```

When mapped to an 8-bit response byte, **Coil 0 goes into the lowest-order bit (Bit 0)**, while **Coil 7 goes into the highest-order bit (Bit 7)**:

| Bit 7 | Bit 6 | Bit 5 | Bit 4 | Bit 3 | Bit 2 | Bit 1 | Bit 0 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| Coil 7 | Coil 6 | Coil 5 | Coil 4 | Coil 3 | Coil 2 | Coil 1 | Coil 0 |
| `1` | `0` | `0` | `0` | `1` | `1` | `0` | `1` |

* **Binary Representation:** `10001101`
* **Resulting Hex Response Byte:** `0x8D`

> ⚠️ **Research Note:** This LSB-first packing order is one of the most common sources of parsing logic inversion bugs when writing custom Modbus clients.

---

## Research Findings

### FC01 Implemented Successfully

The bare-metal Python client correctly built the raw requests, handled network sockets, and systematically decoded bit-packed responses without depending on commercial Modbus libraries.

### Real-Time State Monitoring

Repeated high-frequency polling cleanly reflected physical state transitions instantaneously. This reinforces that FC01 can be leveraged as a live monitoring tap for process states.

### Efficient Data Encoding

Reading 8 individual process points required just 1 single response data byte. Modbus coil transfers are highly compact and bandwidth-efficient.

### PLC Logic Visibility

By purely monitoring the shifting bits of FC01 network responses, an external entity can fully map asset timelines, state cycles, and underlying control loop logic without having native access to the PLC program code.

---

## Security Implications

While FC01 is strictly a read-only command, it represents a core element of **passive and active industrial reconnaissance**.

An attacker can use coil scanning to:

* Enumerate active digital output relays.
* Map physical operational routines (e.g., timing how long a pump stays open).
* Match shifting bits against known industrial safety routines to identify the optimal window for a disruptive write attack.

---

## Detection Opportunities

Network IDS layers can signature FC01 activity cleanly by monitoring for **Function Code 0x01**.

### Example Signature Pattern:

```text
?? ?? 00 00 ?? ?? ?? 01

```

### Threat Indicators:

* High-frequency polling loops targeting broad address gaps.
* Complete sequential coil enumeration (sweeping address ranges from 0 upward).
* Read operations originating from unusual, unmapped host nodes on the OT subnet.

---

## Hardening Guidance

* **Access Control Lists:** Lock down `TCP/502` so that only designated HMI or SCADA monitoring nodes can poll coil states.
* **Scan Thresholding:** Define a network security baseline to flag or drop hosts executing continuous sequential address reads across wide coil ranges.
* **Traffic Isolation:** Treat unauthorized broad-spectrum FC01 polling explicitly as adversarial reconnaissance.

---

## Key Takeaways

* FC01 provides a streamlined, compact method for evaluating discrete process states through bit-packed network buffers.
* Manual implementation highlighted the critical need to handle LSB-first bit-ordering accurately to prevent inverted data parses.
* Observing raw response bit-shifting is entirely sufficient to reverse-engineer ongoing PLC logic routines externally.
* Unchecked coil scanning exposes an asset to deep operational intelligence gathering, stripping away the privacy of the underlying industrial process.

