# Function Code Fingerprinting

## Objective

Identify which Modbus function codes are supported by the target PLC and build a capability map entirely through active protocol interaction, without relying on vendor documentation.

### Common Use Cases:

* **Asset Discovery:** Identifying unknown industrial controllers on a network segment.
* **Protocol Reconnaissance:** Mapping out exposed attack surfaces.
* **Device Fingerprinting:** Profiling specific PLC vendors or firmware traits based on supported features.
* **Security Assessments:** Verifying implemented vs. unauthorized capability sets.
* **Protocol Reverse Engineering:** Analyzing proprietary or non-standard protocol extensions.

---

## Background

Every Modbus operation is defined by a unique 1-byte Function Code (FC). Devices rarely implement the entire protocol specification; a standard PLC may support basic read/write capabilities while rejecting diagnostics or custom sub-functions.

Because implementations vary, the specific array of accepted vs. rejected function codes forms a highly unique capability fingerprint of the device runtime.

---

## Methodology

A custom Modbus TCP client script was developed to enumerate function codes sequentially from **FC01 to FC127**.

```text
[Custom Fingerprinter]  ---( Sequential FC Request )--->  [ Target PLC ]
                        <---( Response / Exception )---- 

```

### The Enumeration Loop:

1. Send a baseline request for a single function code index ($N$).
2. Observe and capture the server's response framework.
3. Record the support status (Success Data vs. Protocol Exception).
4. Increment $N$ and loop until FC127 is reached.

---

## Response Interpretation

### Case A: Supported Function

The server processes the request and responds normally with data, or returns a data-specific error (such as an illegal data address), confirming the logic handler exists.

* **Example:** FC03 Request
* **Observed Response:** `00 03 00 00 00 05 01 03 02 00 00`
* **Result:** **SUPPORTED**

### Case B: Unsupported Function

The server immediately rejects the execution engine. Per the Modbus standard, it flips the highest bit (Bit 7) of the requested function code (effectively adding `0x80` to the hex value) and appends **Exception Code 01** (*Illegal Function*).

* **Example:** FC07 Request
* **Observed Response:** `00 07 00 00 00 03 01 87 01`
* **Mathematical Decode:** `0x87` $\rightarrow$ `0x07` (Requested FC) + `0x80` (Exception Flag)
* **PDU Payload:** `01` (Exception Code: Illegal Function)
* **Result:** **UNSUPPORTED**

---

## Capability Map Results

After scanning the complete protocol index boundary (`0x01` – `0x7F`), OpenPLC's active feature set was explicitly mapped.

### OpenPLC Capability Profile

| Function Code (FC) | Operation Name | Capability Type | Status |
| --- | --- | --- | --- |
| **01** | Read Coils | Discrete Output Read | **Supported** |
| **02** | Read Discrete Inputs | Discrete Input Read | **Supported** |
| **03** | Read Holding Registers | 16-bit Register Read | **Supported** |
| **04** | Read Input Registers | 16-bit Input Read | **Supported** |
| **05** | Write Single Coil | Discrete Output Write | **Supported** |
| **06** | Write Single Register | 16-bit Register Write | **Supported** |
| **15** | Write Multiple Coils | Bulk Discrete Write | **Supported** |
| **16** | Write Multiple Registers | Bulk Register Write | **Supported** |

> All other functions in the scanned `01` - `127` spectrum returned predictable Exception Code `01` arrays.

---

## FC43 / MEI Investigation

Function Code 43 (`0x2B`) handles Modbus Encapsulated Interface (MEI) transport, specifically Type `0x0E` to read the **Device Identification** string (Vendor Name, Product Code, Version Number).

* **Constructed Request:** `00 01 00 00 00 05 01 2B 0E 01 00`
* **Observed Response:** `00 01 00 00 00 03 01 AB 01`
* **Mathematical Decode:** `0xAB` = `0x2B` + `0x80`
* **Result:** **UNSUPPORTED** (OpenPLC does not expose identity metadata through Modbus).

---

## Research Findings

### Core Data Model Coverage

OpenPLC exposes the complete standard Modbus data universe: Coils, Discrete Inputs, Input Registers, and Holding Registers. Both single and bulk read/write operations are actively supported.

### Absolute Metadata Privacy

Because FC43 is completely unsupported, an assessor or adversary cannot gather hardware platform, operating software versions, or project asset descriptors over the Modbus network stream.

### Compliance Uniformity

The exception handling engine inside OpenPLC matches standard specifications perfectly. Every unsupported code tested (e.g., `FC07` $\rightarrow$ `87 01`, `FC08` $\rightarrow$ `88 01`, `FC43` $\rightarrow$ `AB 01`) generated a completely uniform and predictable response signature.

---

## Security Implications

Function code fingerprinting is highly advantageous for an analyst because it strips away black-box uncertainty.

From this single test script, we successfully mapped out precisely what vectors are available to tap process data (`FC01`-`FC04`) and what vectors exist to inject physical or logical disruption (`FC05`, `FC06`, `FC15`, `FC16`).

---

## Detection Opportunities

While fingerprint scans are entirely non-disruptive, they create an aggressive, easily profiled network anomaly signature.

### Threat Indicators:

* High-frequency sequential function code enumeration (sweeping sequentially from `0x01` out to `0x7F`).
* An anomalous surge of *Illegal Function* Exception Code `01` frames originating from a single source host.
* Repeated requests containing atypical diagnostic or proprietary function codes.

### Example Network Sweep Pattern:

```text
Host 10.0.0.5 -> PLC: FC01 (OK)
Host 10.0.0.5 -> PLC: FC02 (OK)
Host 10.0.0.5 -> PLC: FC03 (OK)
Host 10.0.0.5 -> PLC: ...
Host 10.0.0.5 -> PLC: FC07 (Exception 01)
Host 10.0.0.5 -> PLC: FC08 (Exception 01)

```

---

## Hardening Guidance

* **Establish Behavioral Triggers:** Configure intrusion detection systems (IDS) to alert immediately if any single IP generates multiple consecutive *Illegal Function* (`Exception 01`) responses.
* **Network Access Segmentation:** Isolate the target PLC behind industrial firewalls that explicitly filter out unapproved function codes at the network boundary, ensuring even supported functions like `FC16` can only be sent by trusted IP profiles.
* **Reconnaissance Baselines:** Treat any widespread function code mapping behavior as active adversarial reconnaissance.

---

## Key Takeaways

* Active fingerprinting completely documents a PLC's capability profile without requiring access to vendor schematic manuals.
* OpenPLC implements the standard, classic core Modbus read/write features but completely lacks identification features (`FC43`).
* System exceptions are mathematically compliant with historical protocol design rules.
* Generating a complete functional map establishes the essential baseline required to build out subsequent advanced protocol scanning and vulnerability validations.
