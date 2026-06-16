# FC43 / MEI (Modbus Encapsulated Interface)

## Objective

Evaluate support for Function Code 43 (`0x2B`), specifically the Modbus Encapsulated Interface (MEI) used for device identification. The goal was to determine whether the target exposed critical asset markers through standard Modbus mechanisms:

* Vendor Name
* Product Code
* Firmware Version
* Device Metadata

---

## Background

Function Code 43 is defined as `0x2B` and is commonly paired with **MEI Type `0x0E**`, which corresponds to **Read Device Identification**.

Many industrial devices implement FC43 to provide system identification natively without requiring proprietary or vendor-specific engineering protocols. When fully supported, it allows an entity to extract:

* Vendor Name
* Product Name
* Model / Type Descriptors
* Revision / Firmware Levels
* Device Serial Numbers

---

## Protocol Structure

### Request Fields

| Field | Size (Bytes) | Description |
| --- | --- | --- |
| **MBAP Header** | 7 | Standard Modbus TCP framing header |
| **Function Code** | 1 | FC43 (`0x2B`) |
| **MEI Type** | 1 | Encapsulated Interface Type (`0x0E` for Device ID) |
| **Read Code** | 1 | `0x01` = Request Basic Device Identification |
| **Object ID** | 1 | `0x00` = Start at object 0 (Vendor Name) |

### Packet Sent

* **Hex Stream:** `00 01 00 00 00 05 01 2B 0E 01 00`

### Field Breakdown:

* `00 01` $\rightarrow$ Transaction ID (1)
* `00 00` $\rightarrow$ Protocol ID (0)
* `00 05` $\rightarrow$ Remaining Bytes (5 bytes follow)
* `01`    $\rightarrow$ Unit ID (1)
* `2B`    $\rightarrow$ Function Code (43)
* `0E`    $\rightarrow$ MEI Type (14 / Read Device ID)
* `01`    $\rightarrow$ Read Code (Basic Device Identification)
* `00`    $\rightarrow$ Object ID (Vendor Name object category)

---

## Observed Response

* **Response Hex Stream:** `00 01 00 00 00 03 01 AB 01`

### Decoding

#### MBAP Header:

* **Transaction ID** = `00 01`
* **Protocol ID** = `00 00`
* **Length** = `00 03` (3 bytes follow)
* **Unit ID** = `01`

#### PDU Payload:

* **Byte 1:** `AB`
* **Byte 2:** `01`

### Function Code Analysis

The server returned an execution value of **`0xAB`**.
According to the Modbus exception rule, when a server encounters an error, it echoes the requested function code with its highest bit (Bit 7) set to `1` (adding `0x80` in hex):

$$\text{Requested Function Code } (0x2B) + 0x80 = 0xAB$$

This indicates a standard **Protocol Exception Response**.

### Exception Code Analysis

The second byte of the PDU payload returned **`0x01`**, which maps directly to the standard Modbus exception table:

* **Exception Code `01`:** Illegal Function.

> **Conclusion:** The device runtime environment does not implement the FC43 handler logic. **FC43 is UNSUPPORTED**.

---

## Research Findings

### No Device Identification Available

The OpenPLC target context refused to disclose its vendor name, product code, software firmware layer, device model, or hardware revision pointers over the active Modbus data bus.

### Standards-Compliant Rejection

The payload signature `AB 01` explicitly conforms to the official Modbus specification rules for rejecting unhandled or unmapped internal functions.

### Reduced Fingerprinting Surface

Because an operator cannot explicitly query an identification banner string from the port, asset profiling must pivot away from banner grabbing. Instead, mapping tools must analyze behavioral anomalies and protocol nuances, such as:

* Supported function code bounds
* Address table layout quirks
* Transaction timing behaviors
* Error-response variations under pressure

---

## Security Implications

### 🟢 Defensive Advantages

The absence of FC43 actively reduces trivial metadata leakage. An unauthenticated attacker scanning the environment cannot immediately harvest the precise device vendor, model number, or firmware version to match against public exploit databases (such as CVE lists) using standard Modbus sweeps.

### 🔴 Defensive Disadvantages

The total lack of programmatic identification vectors complicates benign security operations. Network defenders will face increased friction when attempting to perform automated asset inventories, passive device tracking, or automated configuration audits natively over the Modbus protocol stack.

---

## Detection Opportunities

In a typical production environment, requests containing **FC43 / MEI Type `0x0E**` are highly uncommon during normal baseline industrial run loops.

### Threat Indicators:

* Network frames seeking Function Code `0x2B` combined with MEI Type `0x0E`.
* Repeated exception loops or anomalous bursts of `Illegal Function` errors matching transaction IDs from the same source node.
* Widespread active asset discovery scans sweeping across internal OT subnets.

---

## Hardening Guidance

* **Filter Management Frames:** Even though FC43 failed in this specific lab environment, production-grade PLCs often implement it natively. Industrial firewalls should explicitly block or alarm on outbound `0x2B` frames passing across boundary zones.
* **Log Exception Footprints:** Configure internal security tools to capture and centralize instances of unsupported function code queries (`Exception 01`).
* **Restrict Access:** Ensure strict host validation limits access to the target PLC exclusively to authorized engineering and asset-management nodes.

---

## Key Takeaways

* Active testing confirmed that OpenPLC does not support Modbus Device Identification, returning a standard `Illegal Function (01)` exception.
* No system-level identity metrics or software version footprints are leaked through this interface.
* Because direct banner grabbing is neutralized, fingerprinting must rely entirely on deep protocol behavior mapping.
* This evaluation successfully completes our operational analysis of the primary Modbus function codes exposed by this target runtime.
