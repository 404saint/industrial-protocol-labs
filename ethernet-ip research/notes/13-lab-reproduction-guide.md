# 13 - Industrial Control Systems Sandbox Laboratory Guide

## Overview

This document defines the experimental laboratory environment used to validate EtherNet/IP and Common Industrial Protocol (CIP) behavior in a controlled software-defined setting. It describes the simulation stack, monitoring tools, and execution workflow used throughout this research series.

---

## Sandbox Environment Architecture

The test environment is implemented as a local loopback-based simulation stack running on a Linux host. It reproduces EtherNet/IP control-plane behavior without interacting with physical industrial hardware.

### 1. Simulation Stack

* **Controller Simulator**: The environment uses the open-source `cpppo` EtherNet/IP implementation to emulate a PLC-style message router.
* **Network Interface**: The simulator listens on the standard EtherNet/IP explicit messaging port `44818` (TCP).
* **Data Model**: A preconfigured dataset named `SAINT_DATA` is loaded into the simulated controller memory space to support tag-based and fragmented operations.

---

### 2. Monitoring Infrastructure

* **Active Test Suite**: A set of Python-based client scripts used to execute structured CIP service requests and validate protocol responses.
* **Passive Monitor**: `enip_monitor.py` runs on the local loopback interface (`lo`) and captures EtherNet/IP encapsulation traffic in real time. It decodes:

  * Encapsulation headers (24 bytes)
  * Session establishment flows
  * CIP service responses and status codes

---

## Laboratory Execution Matrix

The following matrix maps each experimental phase to its corresponding script and observed protocol behavior.

| Phase | Script                                | Reference Note                | Observed Behavior                                                  |
| :---- | :------------------------------------ | :---------------------------- | :----------------------------------------------------------------- |
| 1–2   | `scripts/enip_read_proof.py`          | 02 - Read Tag Single          | Session creation and `0x4C` read operations targeting `SAINT_DATA` |
| 3     | `scripts/enip_write_proof.py`         | 03 - Write Tag Single         | `0x4D` write operations modifying tag values                       |
| 4     | `scripts/enip_frag_proof.py`          | 04 - Fragmented Transfers     | `0x52` / `0x53` fragmented read/write behavior                     |
| 5     | `scripts/enip_get_attr_proof.py`      | 05 - Get Attribute Single     | `0x0E` object attribute reads via logical paths                    |
| 6     | `scripts/enip_set_attr_proof.py`      | 06 - Set Attribute Single     | `0x10` object attribute modifications                              |
| 7     | `scripts/enip_command_fingerprint.py` | 07 - ListServices             | Unauthenticated `0x0004` capability discovery                      |
| 8     | `scripts/enip_identity_clean.py`      | 08 - Identity Object          | Class `0x01` device metadata extraction                            |
| 9     | `scripts/enip_exception_proof.py`     | 09 - Error Routing            | CIP General Status `0x05` routing failures                         |
| 10    | `scripts/enip_boundary_scan.py`       | 10 - Boundary Discovery       | Attribute and instance space enumeration                           |
| 11–13 | `scripts/enip_monitor.py`             | 11–13 - Detection & Hardening | Continuous traffic inspection and rule validation                  |

---

## Execution Flow Model

```text
[Phase 1–3: Tag Operations]
        ↓
[Phase 4: Fragmented Data Handling]
        ↓
[Phase 5–6: Object Attribute Operations]
        ↓
[Phase 7–10: Discovery & Enumeration]
        ↓
[Phase 11–13: Monitoring & Defensive Analysis]
```

This structure reflects a progression from basic tag manipulation to full protocol discovery, followed by detection and defensive analysis.

---

## Operational Procedure

### 1. Base Communication Validation

Start the monitoring process:

* Launch `enip_monitor.py`
* Execute `enip_read_proof.py` followed by `enip_write_proof.py`

The monitor will log session establishment events and decode `SAINT_DATA` access patterns.

---

### 2. Fragmented Transfer Testing

Execute `enip_frag_proof.py` to observe segmented data transfers.

This phase validates how CIP manages multi-packet data movement and updates offset tracking within the encapsulation layer.

---

### 3. Object-Level Interaction

Run:

* `enip_get_attr_proof.py`
* `enip_set_attr_proof.py`

This transitions the analysis from symbolic tag operations to structured CIP object attributes.

---

### 4. Stack Discovery and Fault Induction

Execute:

* `enip_command_fingerprint.py`
* `enip_identity_clean.py`
* `enip_exception_proof.py`

These scripts expose:

* Device capability enumeration
* Identity object metadata extraction
* CIP routing failure behavior and General Status responses

---

## Key Takeaways

* The sandbox is fully software-defined and replicates EtherNet/IP behavior using a loopback simulation stack.
* `cpppo` is used as the CIP message router emulation layer.
* `enip_monitor.py` provides passive inspection of encapsulation, session, and CIP traffic.
* The lab is structured in progressive phases: tag operations → object operations → discovery → detection.
* Each script maps directly to a specific CIP service or protocol behavior observed in earlier notes.
