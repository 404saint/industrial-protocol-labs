# Modbus TCP Research Lab

A hands-on Modbus TCP research project focused on understanding industrial communication protocols through manual packet crafting, protocol analysis, capability mapping, detection engineering, and defensive assessment.

Rather than relying on existing high-level libraries, this research implements core Modbus functionality directly in Python at the raw socket layer to demystify how industrial devices communicate at the packet level.

---

## Project Goals

This project was designed to answer a fundamental question: **What actually happens when a PLC receives a Modbus TCP packet?** To answer that question, every major protocol feature was explored manually through custom tooling, packet fuzzing, and deep packet inspection. Research focus areas include:

* Protocol Anatomy & Header Dissection
* Function Code Analysis
* Volatile Register & Coil Manipulation
* Specification Exception Handling
* Boundary and Memory Discovery
* Automated Capability Mapping
* Blue-Team Detection Engineering
* Industrial Network Hardening

---

## Lab Environment

* **Target System:** OpenPLC Runtime with Modbus TCP Engine enabled (`TCP/502`).
* **Research Host:** Linux Workstation equipped with Python 3.x, `tcpdump`, and Wireshark.
* **Protocol Context:** Standard Modbus TCP (Unauthenticated).

---

## Research Progression Blueprint

The project follows a rigorous, structured progression moving from raw packet baseline parsing to advanced threat hunting and defensive design.

| Phase | Topic | Core Lab Focus |
| --- | --- | --- |
| **01** | Protocol Anatomy | Structural validation of MBAP Headers and PDU payloads. |
| **02** | FC03 Read Holding Registers | Polling and decoding 16-bit word analog values. |
| **03** | FC06 Write Single Register | Intervening in process state with single-point injections. |
| **04** | FC16 Write Multiple Registers | Overriding continuous parameter data arrays in bulk blocks. |
| **05** | FC01 Read Coils | Extracting bit-packed discrete output statuses. |
| **06** | FC05 Write Single Coil | Forcing binary bit flips (`TRUE`/`FALSE`) to alter execution logic. |
| **07** | Function Code Fingerprinting | Probing `FC01`–`FC127` to map exposed server capabilities. |
| **08** | FC43 / MEI Investigation | Profiling device identification and vendor exposure boundaries. |
| **09** | Exception Handling Research | Stressing input filters to evaluate server resilience under error states. |
| **10** | Register Boundary Discovery | Using binary-search optimization to trace volatile RAM constraints. |
| **11** | Detection Heuristics | Defining high-fidelity network intrusion signatures for blue teams. |
| **12** | Hardening Guidance | Constructing architectural containment frameworks for industrial zones. |
| **13** | Lab Reproduction Guide | Packaging a complete playbook for independent research replication. |

---

## Major Findings

### 📊 Supported Function Codes

Active scanning mapped direct runtime access to the core Modbus data model universe: `FC01` (Read Coils), `FC02` (Read Discrete Inputs), `FC03` (Read Holding Registers), `FC04` (Read Input Registers), `FC05` (Write Single Coil), `FC06` (Write Single Register), `FC15` (Write Multiple Coils), and `FC16` (Write Multiple Registers).

### 🛡️ Device Identification Boundaries

Queries targeting **Function Code 43 (MEI Type `0x0E`)** were dropped with a standard `Illegal Function (01)` exception response. The target does not expose its vendor name, firmware level, or hardware platform over Modbus, reducing the surface area for passive exploit profiling.

### 📐 Register Space Constraints

The binary-search discovery tool successfully pinned the maximum readable holding register address right at offset **`8191`**. This configures an explicit, open holding-register workspace of **8,192 address points** (exactly **16 KB** of volatile RAM allocation). Access attempts beyond this boundary seamlessly throw an `Illegal Data Address (02)` exception.

### ⚠️ Parser Deviations (Coil Fuzzing)

While the official Modbus specification mandates that `FC05` must reject any state inputs other than `0xFF00` or `0x0000`, fuzz testing revealed that OpenPLC accepts non-compliant hex arguments (e.g., `0x1234`), processing any non-zero value as a logical `TRUE`.

### 🔄 Memory Volatility Profiles

Persistence verification proved that while state overrides survive continuous multi-client connections, they do not persist across complete runtime service restarts. Data maps operate purely out of dynamic, volatile memory blocks.

---

## Repository Tree Structure

```text
.
├── scripts/                      # Bare-metal Python socket implementation scripts
│   ├── modbus_client.py          # FC03 - Read Holding Registers
│   ├── modwrite.py               # FC06 - Write Single Register
│   ├── modmulti.py               # FC16 - Write Multiple Registers
│   ├── modcoils.py               # FC01 - Read Coils
│   ├── modcoilwrite.py           # FC05 - Write Single Coil
│   ├── modfingerprint.py         # FC01-FC127 - Function Code Sweeper
│   ├── modmei.py                 # FC43 - MEI Identity Query
│   ├── modexception_lab.py       # Controlled Exception Testing
│   ├── modboundary.py            # Binary-Search Boundary Discovery
│   └── modscan.py                # Complete Register Enumeration
│
├── notes/                        # Deep-dive engineering reports & technical analyses
│   ├── 01-protocol-anatomy.md
│   ├── 02-fc03-read-holding-registers.md
│   ├── 03-fc06-write-single-register.md
│   ├── 04-fc16-write-multiple-registers.md
│   ├── 05-fc01-read-coils.md
│   ├── 06-fc05-write-single-coil.md
│   ├── 07-function-code-fingerprinting.md
│   ├── 08-fc43-mei.md
│   ├── 09-exception-research.md
│   ├── 10-boundary-discovery.md
│   ├── 11-detection-heuristics.md
│   ├── 12-hardening-guidance.md
│   └── 13-lab-reproduction-guide.md
│
└── findings/ executive-summary.md          # High-level overview of findings and security impact

```

---

## Packet Capture Baseline Validation

To monitor raw transaction hex behavior or save an audit trace for rule engineering, initialize background capture tools before executing scripts:

```bash
sudo tcpdump -i any port 502 -w modbus-lab.pcap

```

Analyze the captured packet traces using Wireshark or open them via command-line tools using the standard protocol dissectional layers.

---

## Replicating the Research

To configure your local environment, install Structured Text automation modules, execute scripts, and independently confirm these results, reference the step-by-step documentation located in [notes/13-lab-reproduction-guide.md](https://github.com/404saint/industrial-protocol-labs/blob/main/modbus-research/notes/13-lab-reproduction-guide.md).

---

## Key Takeaway

Understanding an industrial protocol at the raw byte level exposes critical operational traits that abstract engineering tools hide. By manually driving raw sockets, analyzing error structures, and tracing boundaries, this research establishes that **Modbus was engineered for raw performance and operational interoperability, completely trading off security validation.** Because native protection does not exist within the protocol, securing an automated environment depends entirely on strict network architecture, behavioral anomaly logging, firewall segmentation, and endpoint defense.

---

## Disclaimer

This research was developed inside an isolated, authorized laboratory environment using OpenPLC for educational, defensive security engineering, and protocol research purposes. Never run active scans or testing toolsets against production industrial assets without explicit authorization and formal safety oversight.
