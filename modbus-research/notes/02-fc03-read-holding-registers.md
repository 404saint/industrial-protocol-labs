# FC03 — Read Holding Registers

## Objective

Understand how Modbus Function Code 03 (Read Holding Registers) works by manually constructing packets, interacting with OpenPLC, and validating protocol behavior without external libraries.

---

## Why FC03 Matters

FC03 is one of the most commonly used Modbus operations. It allows a client to read values from Holding Registers.

### Typical uses include:

* Reading sensor values
* Reading counters
* Reading process variables
* Monitoring PLC state

Because most industrial monitoring relies on reading data, FC03 is usually one of the first functions exposed by a Modbus device.

---

## Protocol Definition

* **Function Code:** `0x03`
* **Operation:** Read Holding Registers
* **Access Type:** Read Only
* **Data Type:** 16-bit Registers

### Request Structure

**Example Packet:** `00 01 00 00 00 06 01 03 00 00 00 01`

| Layer | Bytes | Value | Description |
| --- | --- | --- | --- |
| **MBAP Header** | `00 01` | Transaction ID | Identifies the request/response pair |
|  | `00 00` | Protocol ID | `00 00` = Modbus protocol |
|  | `00 06` | Length | 6 bytes follow |
|  | `01` | Unit ID | Target device address |
| **PDU** | `03` | Function Code | FC03 (Read Holding Registers) |
|  | `00 00` | Start Address | Starting register address (0) |
|  | `00 01` | Quantity | Number of registers to read (1) |

> **Meaning:** Read 1 holding register starting at address 0.

### Response Structure

**Observed Response:** `00 01 00 00 00 05 01 03 02 00 00`

| Layer | Bytes | Value | Description |
| --- | --- | --- | --- |
| **MBAP Header** | `00 01` | Transaction ID | Matches request Transaction ID |
|  | `00 00` | Protocol ID | `00 00` = Modbus protocol |
|  | `00 05` | Length | 5 bytes follow |
|  | `01` | Unit ID | Target device address |
| **PDU** | `03` | Function Code | FC03 (Read Holding Registers) |
|  | `02` | Byte Count | 2 bytes of data follow |
|  | `00 00` | Register Value | Data from Register 0 |

> **Result:** Register 0 = `0`

---

## Hand-Crafted Client

Below is the bare-metal Python implementation used to perform the initial validation:

```python
import socket

# Initialize TCP socket and connect to OpenPLC
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("localhost", 502))

# Construct raw hex request (FC03, Read 1 Register at Address 0)
request = bytes.fromhex("000100000006010300000001")
sock.sendall(request)

# Receive and print response
response = sock.recv(1024)
print(response.hex(" "))

sock.close()

```

---

## Lab Observations

### Initial Validation

* **Request:** `00 01 00 00 00 06 01 03 00 00 00 01`
* **Response:** `00 01 00 00 00 05 01 03 02 00 00`

**Finding:** FC03 worked immediately against OpenPLC. This successfully validated our TCP connectivity, MBAP construction, function code handling, and basic register access.

### Register Enumeration

A custom scanner was created to repeatedly issue FC03 requests across multiple addresses to discover accessible register space, identify non-zero values, and map PLC memory.

```text
[00000] = 0
[00001] = 0
[00002] = 0
...

```

### Reading Written Values

After testing FC06 (Write Single Register) to set **Register 0 = 1337**, an FC03 readback was executed:

* **Response:** `00 02 00 00 00 05 01 03 02 05 39`
* **Decoded Data:** `0x0539` $\rightarrow$ `1337`

**Finding:** FC03 accurately reflected values previously written using FC06.

### Address Boundary Discovery

Using binary-search style testing, the limits of OpenPLC's register map were probed:

* `4096` $\rightarrow$ Valid
* `6144` $\rightarrow$ Valid
* `8191` $\rightarrow$ Valid
* `8192` $\rightarrow$ Invalid

**Finding:** OpenPLC exposed readable holding registers up to address **8191**.

### Exception Behavior

Invalid addresses generated standards-compliant Modbus exceptions:

* **Test Address:** 60000
* **Result:** Exception Code `02` (**Illegal Data Address**)

**Finding:** OpenPLC correctly rejected requests pointing outside its defined register map.

### Quantity Testing

* `qty=0` $\rightarrow$ Accepted
* `qty=126` $\rightarrow$ Accepted
* `qty=1000` $\rightarrow$ Exception (Code `02`)

**Finding:** OpenPLC enforced practical protocol limits on the number of registers requested in a single FC03 loop.

### State Persistence Observation

Testing revealed distinct behaviors before and after runtime states:

1. **During Runtime:** Write (FC06) $\rightarrow$ Read (FC03) returned `1337`. Data remained persistently accessible in memory.
2. **After Runtime Restart:** Read (FC03) returned `0`.

**Finding:** Holding register contents were volatile and did not persist across OpenPLC runtime restarts.

---

## Packet Signature

FC03 traffic has a highly recognizable structure that network security tools can log.

* **Request:** `[TID][0000][0006][UID][03][ADDR][COUNT]`
* **Response:** `[TID][0000][LEN][UID][03][BYTECOUNT][DATA]`

Detection systems can reliably identify FC03 operations using a combination of:

* Target port `TCP/502`
* Function Code `03`
* Standard MBAP header layouts

---

## Security Implications

While FC03 appears harmless because it only reads data, in practice, it is heavily leveraged for malicious utility:

* **Process Reconnaissance:** Mapping out internal operations.
* **Register Mapping:** Determining which registers control critical processes.
* **Operational Intelligence Gathering:** Monitoring logic shifts or production cycles.
* **Asset Fingerprinting:** Discovering PLC memory limits to identify vendor/firmware profiles.

An attacker will almost always use FC03 to completely map system behavior before attempting disruptive write operations.

---

## Defensive Considerations

### Indicators of Reconnaissance:

* Sequential address reads (sweeping)
* Large quantity requests close to protocol limits
* Full register-space scans
* Unusually high frequency of repeated FC03 requests

### Recommended Controls:

* Strict network segmentation (separating IT from OT layers)
* Access control lists (ACLs) to restrict `TCP/502` traffic exclusively to authorized engineering/HMI stations
* Implementation of OT-aware firewalls to monitor and alert on abnormal read volumes or sequential register sweeps

---

## Key Takeaways

* FC03 successfully retrieved holding register values from OpenPLC.
* Manual packet construction was entirely sufficient to interact with the PLC without third-party dependencies.
* Register values written via FC06 were immediately readable through FC03.
* OpenPLC exposed holding registers up to a strict boundary address of 8191; anything higher generated an Exception Code `02`.
* Register contents were volatile and reset across runtime restarts.
* FC03 provides a straightforward, powerful method for process reconnaissance.
