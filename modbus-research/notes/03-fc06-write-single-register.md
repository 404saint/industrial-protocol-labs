# FC06 – Write Single Register

## Objective

Understand and manually implement Modbus Function Code 06 (Write Single Register), validate server behavior, and verify that written values persist in memory during runtime.

---

## Protocol Overview

* **Function Code:** `0x06`
* **Purpose:** Write a single holding register.
* **Response:** The server echoes the request exactly if successful.

### Request Structure

| Field | Size (Bytes) | Description |
| --- | --- | --- |
| **Transaction ID** | 2 | Identifies the request/response pair |
| **Protocol ID** | 2 | `00 00` = Modbus protocol |
| **Length** | 2 | Number of remaining bytes |
| **Unit ID** | 1 | Target device address |
| **Function Code** | 1 | FC06 (`0x06`) |
| **Register Addr** | 2 | Target register address |
| **Value** | 2 | 16-bit data to write |

---

## Lab Setup

* **Target:** OpenPLC Runtime (Modbus TCP)
* **Port:** `502`
* **Client:** Custom Python implementation utilizing raw socket communication

---

## Manual Packet Construction

To test the operation, we will write the value **1337 (`0x0539`)** to **Register 0**.

**Request Packet:** `00 01 00 00 00 06 01 06 00 00 05 39`

### Field Breakdown:

* `00 01` $\rightarrow$ Transaction ID
* `00 00` $\rightarrow$ Protocol ID
* `00 06` $\rightarrow$ Remaining bytes (Length)
* `01`    $\rightarrow$ Unit ID
* `06`    $\rightarrow$ Function Code (Write Single Register)
* `00 00` $\rightarrow$ Register Address (0)
* `05 39` $\rightarrow$ Value to Write (1337)

---

## Observed Response

* **Response:** `00 01 00 00 00 06 01 06 00 00 05 39`

**Observation:** OpenPLC echoed the request exactly as required by the Modbus specification, confirming a successful write.

---

## Verification Using FC03

After writing the register, Function Code 03 (Read Holding Registers) was used to verify the state of memory.

* **Read Response:** `00 02 00 00 00 05 01 03 02 05 39`
* **Decoded Data:** `0x0539` $\rightarrow$ `1337`

```text
[+] Register 0 = 1337

```

---

## Research Findings

### Successful Write

The server correctly accepted the request (`Register 0 = 1337`) and returned the expected echo response.

### Read-After-Write Validation

A subsequent FC03 read confirmed the written value immediately became visible. This demonstrates that the write path and read path reference the exact same memory area.

### Runtime Persistence

Repeated reads showed that the register value remained available during runtime.

* Example: Executing `modwrite.py` to write `1337` followed by `modscan.py` consistently returned `register 0 = 1337`.

### Restart Behavior

Later testing showed that register values are **not** guaranteed to survive service restarts. OpenPLC startup logs contained the following:

```text
Warning: Persistent Storage file not found

```

This indicates that no persistent backing storage was configured on the server.

* **Result:** Persistence exists in RAM only.

---

## Security Implications

FC06 enables direct, unauthorized modification of process variables.

### Potential Impact:

* Changing critical system setpoints
* Overriding operator safety values
* Manipulating active process states
* Altering PLC logic inputs to trigger unintended physical behavior

> ⚠️ **Critical Vulnerability:** No authentication was observed at the protocol layer. Any client capable of reaching `TCP/502` could successfully issue write requests.

---

## Detection Opportunities

FC06 traffic can be identified natively via network monitoring tools by filtering for **Function Code = 0x06**.

### Example Signature Pattern:

```text
?? ?? 00 00 00 06 ?? 06

```

### Threat Indicators:

* High-frequency or repeated register writes
* Unexpected or out-of-bounds value changes
* Writes originating from IP addresses outside authorized engineering workstations or outside defined maintenance windows

---

## Hardening Guidance

* **Network Segmentation:** Restrict access to `TCP/502` and cleanly isolate PLC networks from IT networks.
* **Activity Monitoring:** Heavily monitor and log all write-heavy function codes (`FC05`, `FC06`, `FC15`, `FC16`).
* **Anomalous Alerting:** Alert immediately on unauthorized or unrecognized register modifications.
* **Storage Configuration:** Enable persistent storage only when explicitly required by operational guidelines.
* **Audit Trails:** Implement centralized logging for all successful and failed write operations.

---

## Key Takeaways

* FC06 was successfully implemented entirely by hand using raw sockets.
* The experiment cleanly demonstrated manual Modbus packet construction and correct FC06 request/response echoing.
* Read-after-write validation using FC03 proved effective for immediate validation.
* Registers maintain runtime memory persistence but reset on service reboot due to volatile RAM architecture.
* A lack of protocol-level authentication exposes a severe security attack surface via unrestricted register writes.
