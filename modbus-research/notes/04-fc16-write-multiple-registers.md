# FC16 – Write Multiple Registers

## Objective

Understand and manually implement Modbus Function Code 16 (Write Multiple Registers), verify bulk register updates, and evaluate how OpenPLC handles multi-register write operations.

---

## Protocol Overview

* **Function Code:** `0x10` (Decimal 16)
* **Purpose:** Write multiple holding registers in a single request.

### Common Use Cases:

* Updating process variables in bulk
* Writing arrays or sequence lists
* Sending recipes or operational configurations
* Synchronizing multiple interlinked system values simultaneously

### Compared to FC06:

* **FC06:** Writes exactly one register per transaction.
* **FC16:** Writes many registers across sequential addresses in a single transaction.

---

## Request Structure

| Field | Size (Bytes) | Description |
| --- | --- | --- |
| **Transaction ID** | 2 | Identifies the request/response pair |
| **Protocol ID** | 2 | `00 00` = Modbus protocol |
| **Length** | 2 | Number of remaining bytes |
| **Unit ID** | 1 | Target device address |
| **Function Code** | 1 | FC16 (`0x10`) |
| **Start Address** | 2 | The first register address to write to |
| **Quantity** | 2 | Number of registers to write |
| **Byte Count** | 1 | Number of data bytes to follow ($2 \times \text{Quantity}$) |
| **Register Data** | $N$ | The raw 16-bit values to be written |

---

## Lab Setup

* **Target:** OpenPLC Runtime (Modbus TCP)
* **Port:** `502`
* **Client:** Custom Python implementation utilizing raw socket communication
* **Values Written:** `[100, 200, 300, 400, 500]`
* **Target Registers:** Addresses 0 through 4

---

## Manual Packet Construction

### FC16 Request:

`00 01 00 00 00 11 01 10 00 00 00 05 0a 00 64 00 c8 01 2c 01 90 01 f4`

### Field Breakdown:

* `00 01` $\rightarrow$ Transaction ID
* `00 00` $\rightarrow$ Protocol ID
* `00 11` $\rightarrow$ Remaining bytes (17 bytes follow)
* `01`    $\rightarrow$ Unit ID
* `10`    $\rightarrow$ Function Code (`0x10`)
* `00 00` $\rightarrow$ Starting Register Address (0)
* `00 05` $\rightarrow$ Quantity of registers to write (5)
* `0a`    $\rightarrow$ Byte Count (10 data bytes follow)
* `00 64` $\rightarrow$ Register Value 1 (**100**)
* `00 c8` $\rightarrow$ Register Value 2 (**200**)
* `01 2c` $\rightarrow$ Register Value 3 (**300**)
* `01 90` $\rightarrow$ Register Value 4 (**400**)
* `01 f4` $\rightarrow$ Register Value 5 (**500**)

---

## Observed Response

* **Response:** `00 01 00 00 00 06 01 10 00 00 00 05`

### Decoded Response PDU:

* **Start Address** = `0`
* **Quantity** = `5`

**Observation:** OpenPLC acknowledged the write operation successfully. Note that unlike FC06, **FC16 does not echo all values back**. The server only returns the validated starting address and the quantity written.

---

## Verification Using FC03

To verify the bulk memory operation, a Function Code 03 read request was issued for 5 registers starting at address 0.

* **Read Response:** `00 02 00 00 00 0d 01 03 0a 00 64 00 c8 01 2c 01 90 01 f4`

```text
[0] = 100
[1] = 200
[2] = 300
[3] = 400
[4] = 500

```

**Result:** Verified that all values matched perfectly.

---

## Research Findings

### Multi-Register Writes Work Correctly

OpenPLC cleanly accepted 5 consecutive register writes and correctly stored all values sequentially in memory.

### Read-After-Write Validation

FC03 confirmed that every written value was readable immediately, demonstrating that FC16 and FC03 operate directly on the exact same underlying memory space.

### Maximum Register Count

Probing the boundaries of bulk writes showed robust capabilities:

```text
120 registers -> Success
121 registers -> Success
122 registers -> Success
123 registers -> Success
124 registers -> Success
125 registers -> Success

```

**Observation:** OpenPLC fully supports up to the Modbus standard maximum of **125 registers** per single payload.

### Address Boundaries

Testing revealed that OpenPLC effectively enforces limits on boundaries:

* Address `0` $\rightarrow$ Valid
* Address `100` $\rightarrow$ Valid
* Address `1000` $\rightarrow$ Valid
* Address `10000` $\rightarrow$ Exception Code `02` (Illegal Data Address)

### Performance

During a stress test comprising 100 continuous bulk writes, the total elapsed time was `~0.01s`. No system instability or data corruption was observed during rapid write operations.

---

## Security Implications

FC16 introduces significantly higher operational and systemic risks than single-register writes (`FC06`).

> ⚡ **High Risk Vector:** A malicious actor can completely alter entire process states in a **single packet transaction**, dramatically minimizing the window for detection systems to intervene.

### Potential Impact:

* Rewriting vast blocks of device memory simultaneously
* Altering multiple interdependent process values at once to bypass safety thresholds
* Pushing completely spoofed system configurations or malicious "recipes"

---

## Detection Opportunities

FC16 traffic is highly distinct and easily profileable due to its unique structure.

### Example Signature Pattern:

```text
?? ?? 00 00 ?? ?? ?? 10

```

### Threat Indicators:

* Abnormally large bulk write operations
* Write volumes pushing close to the 125-register limit
* High-frequency or repeated FC16 write activity across varying modules
* Unscheduled configuration updates outside of known maintenance windows

---

## Hardening Guidance

* **Segregated Monitoring:** Monitor and baseline `FC16` operations separately from `FC06`, tracking typical payload sizes.
* **Volume Baselining:** Create an alert profile for any transaction requesting anomalous register quantities.
* **Access Control:** Isolate PLC management layers and restrict `TCP/502` access to authorized engineering stations using strict firewall ACLs.
* **Configuration Audits:** Explicitly log all mass configuration shifts and configuration writes for administrative sign-off.

---

## Key Takeaways

* FC16 was successfully implemented natively using manually crafted Modbus TCP packets without third-party libraries.
* The experiment demonstrated seamless bulk register modification through a single targeted request payload.
* OpenPLC handles standard maximum limits (125 registers) and enforces correct address boundaries reliably.
* Due to its capability to change an entire operational loop in a single network frame, FC16 presents a drastically expanded attack surface compared to single-register writes.

