# FC05 – Write Single Coil

## Objective

Understand and manually implement Modbus Function Code 05 (Write Single Coil), verify coil state changes, and analyze how Modbus controls discrete outputs at the protocol level.

---

## Protocol Overview

* **Function Code:** `0x05`
* **Purpose:** Write the status of a single discrete coil.

### Coils represent binary system elements:

* Digital outputs
* Physical relays and actuators
* Status switches
* Internal PLC software flags

### Compared to Holding Registers:

* **FC06:** Writes an entire 16-bit analog or multi-bit data block.
* **FC05:** Modifies a single bit (binary state).

### Valid Coil Values

The official Modbus specification defines only two valid data constants to manipulate a state:

| Desired State | Protocol Hex Value | Meaning |
| --- | --- | --- |
| **ON** | `FF 00` | Coil = `TRUE` |
| **OFF** | `00 00` | Coil = `FALSE` |

---

## Request Structure

| Field | Size (Bytes) | Description |
| --- | --- | --- |
| **Transaction ID** | 2 | Identifies the request/response pair |
| **Protocol ID** | 2 | `00 00` = Modbus protocol |
| **Length** | 2 | Number of remaining bytes (always `00 06` for FC05) |
| **Unit ID** | 1 | Target device address |
| **Function Code** | 1 | FC05 (`0x05`) |
| **Coil Address** | 2 | Target coil index to modify |
| **Coil Value** | 2 | `FF 00` (ON) or `00 00` (OFF) |

---

## Lab Setup

* **Target:** OpenPLC Runtime (Modbus TCP)
* **Port:** `502`
* **Client:** Custom Python implementation utilizing raw socket communication
* **Target Coil:** Coil 0

---

## Manual Packet Construction

### Writing Coil ON

* **Request:** `00 01 00 00 00 06 01 05 00 00 FF 00`
* **Observed Response:** `00 01 00 00 00 06 01 05 00 00 FF 00`

> **Result:** Function Code `05`, Address `0`, Value `FF00`. **Coil 0 turned ON**.

### Writing Coil OFF

* **Request:** `00 02 00 00 00 06 01 05 00 00 00 00`
* **Observed Response:** `00 02 00 00 00 06 01 05 00 00 00 00`

> **Result:** Function Code `05`, Address `0`, Value `0000`. **Coil 0 turned OFF**.

### Response Behavior

FC05 mirrors the confirmation pattern found in FC06: the server echoes back the exact request structure (Function Code, Address, and Value) upon a successful write. This provides an immediate network confirmation that the command was processed.

---

## Verification Using FC01

After issuing each write command, Function Code 01 (Read Coils) was used to verify the actual state changes in memory:

* **Post-ON Read Response:** `[1, 0, 0, 0, 0, 0, 0, 0]`
* **Post-OFF Read Response:** `[0, 0, 0, 0, 0, 0, 0, 0]`

**Observation:** FC05 state adjustments were reflected instantly in subsequent FC01 loops.

---

## Coil Value Fuzzing (Specification Deviation)

Additional fuzz testing was conducted to evaluate how OpenPLC handles non-standard data constants in the **Coil Value** field.

| Tested Value (Hex) | OpenPLC Response Status | Result |
| --- | --- | --- |
| `0x0000` | Accepted (Echoed Back) | Treated as **OFF** |
| `0x0001` | Accepted (Echoed Back) | Treated as **ON** |
| `0x0002` | Accepted (Echoed Back) | Treated as **ON** |
| `0x1234` | Accepted (Echoed Back) | Treated as **ON** |
| `0xFFFF` | Accepted (Echoed Back) | Treated as **ON** |
| `0xFF00` | Accepted (Echoed Back) | Treated as **ON** |

```text
Example Anomalous Payload:
Request:  ?? ?? 00 00 00 06 01 05 00 00 12 34
Response: ?? ?? 00 00 00 06 01 05 00 00 12 34

```

### 🔍 Research Finding: Implementation Flaw

* **The Specification:** The official Modbus protocol guidelines explicitly state that *only* `0xFF00` and `0x0000` are valid inputs. Any other values must generate a Modbus Exception response.
* **OpenPLC Behavior:** OpenPLC accepted arbitrary hex values (like `0x1234` and `0xFFFF`) and cleanly echoed them back without generating any exception errors.
* **Implication:** OpenPLC treats any non-zero value as a logical `TRUE` (ON). This lack of strict validation represents a significant implementation flaw from a protocol compliance standpoint.

---

## Research Findings

* **FC05 Successfully Implemented:** The custom client successfully built packets, parsed write acknowledgments, and flipped coil states entirely over raw TCP sockets.
* **Immediate State Control:** Changes are applied natively to the execution loop instantly, proving FC05 can immediately affect active hardware logic.
* **Weak Input Validation:** Fuzzing proved that OpenPLC fails to validate strict boundaries on the coil data field, echoing arbitrary garbage values instead of dropping them.

---

## Security Implications

FC05 is a high-impact function code because it directly modifies physical or logical binary states.

### Potential Impact:

* Force-starting or force-stopping machinery out of sequence.
* Manually overriding interlocking safety relays.
* Triggering or silencing critical industrial alarms.
* Tripping physical circuit breakers or valves.

> ⚠️ **Critical Risk:** Because Modbus lacks protocol-level authentication, any host with network visibility to `TCP/502` can send an FC05 payload to violently manipulate active hardware modules.

---

## Detection Opportunities

Network Intrusion Detection Systems (NIDS) can reliably track FC05 transactions using deep packet inspection (DPI) for **Function Code 0x05**.

### Example Signature Pattern:

```text
?? ?? 00 00 ?? ?? ?? 05

```

### Threat Indicators:

* FC05 commands originating from unauthorized subnets (e.g., corporate/IT networks).
* **Rapid State Toggling / Denial of Service:** A rapid sequence of ON/OFF writes targeting the same coil to wear out mechanical relays or destabilize electrical processes.
* Unexpected writes to unmapped coil addresses.

---

## Hardening Guidance

* **Workstation Filtering:** Establish firewall rules allowing *only* the authorized HMI/SCADA runtime or engineering console IPs to use `FC05` against the PLC.
* **Pattern Alerting:** Monitor for rapid ON/OFF or high-frequency toggling profiles targeting digital output pins.
* **Log Retention:** Log all instances of successful bit manipulations to a centralized, write-once SIEM platform for post-incident analysis.

---

## Key Takeaways

* FC05 enables direct manipulation of binary process loops using a clean write-and-echo framework.
* Hand-crafted payloads are completely effective at bypassing native automation applications to switch coils.
* Fuzzing uncovered a protocol non-compliance issue where OpenPLC accepts non-standard parameters instead of throwing standard exception flags.
* Due to its immediate physical downstream consequences, FC05 must be treated as a high-risk security vector in any industrial control assessment.
