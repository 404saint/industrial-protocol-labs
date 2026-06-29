# EtherNet/IP & CIP Research Lab

A hands-on research framework for EtherNet/IP and the Common Industrial Protocol (CIP), focused on understanding industrial communication systems through low-level packet construction, protocol analysis, behavioral mapping, and defensive assessment.

Rather than relying on high-level abstractions or black-box tooling, this project reconstructs EtherNet/IP behavior directly through Python-based implementations, raw socket interactions, and structured packet inspection.

The objective is to make industrial protocol behavior observable, reproducible, and explainable at the wire level.

---

## Project Goals

This work explores a core question:

> What actually happens inside a PLC when it receives an EtherNet/IP encapsulation command or a CIP service request?

To answer this, each protocol layer was implemented and analyzed through controlled experiments, covering:

* EtherNet/IP encapsulation structure and session handling
* CIP service execution and routing behavior
* Object model interaction (class / instance / attribute hierarchy)
* Tag-based symbolic memory access
* Fragmentation and multi-packet transfer behavior
* Error generation and General Status semantics
* Enumeration and capability discovery patterns
* Passive detection and behavioral fingerprinting
* Defensive design and industrial hardening strategies
* CIP Security and encrypted transport models

---

## Lab Environment

* **Target System**: `cpppo` EtherNet/IP simulator (TCP/44818)
* **Host System**: Linux-based research workstation (Python 3.x)
* **Interface Context**: Local loopback (`lo`) network simulation
* **Protocol Scope**: EtherNet/IP “This repository treats EtherNet/IP not as documentation, but as a runtime system that can be observed, reconstructed, and reasoned about at the packet level.”explicit messaging (CIP over TCP/IP), unauthenticated baseline configuration

---

## Research Progression Blueprint

The project is structured as a progressive exploration of EtherNet/IP, moving from foundational packet structure to defensive architecture design.

| Phase | Topic                   | Core Focus                                        |
| :---- | :---------------------- | :------------------------------------------------ |
| 01    | Protocol Anatomy        | 24-byte encapsulation header and CPF structure    |
| 02    | Read Tag Operations     | CIP `0x4C` Read Tag Single behavior               |
| 03    | Write Tag Operations    | CIP `0x4D` Write Tag Single state modification    |
| 04    | Fragmented Transfers    | CIP `0x52` / `0x53` multi-packet tracking         |
| 05    | Object Attribute Reads  | CIP `0x0E` Get_Attribute_Single                   |
| 06    | Object Attribute Writes | CIP `0x10` Set_Attribute_Single                   |
| 07    | Stack Fingerprinting    | Unauthenticated `ListServices (0x0004)` discovery |
| 08    | Identity Profiling      | Class `0x01` device metadata extraction           |
| 09    | Error Routing Behavior  | CIP General Status analysis                       |
| 10    | Boundary Discovery      | Attribute and object space enumeration            |
| 11    | Detection Engineering   | Behavioral signatures and monitoring logic        |
| 12    | Hardening Guidance      | Segmentation, mode control, and CIP Security      |
| 13    | Reproduction Guide      | Full laboratory replication workflow              |

---

## Key Findings

### 1. EtherNet/IP Exposes Structured Execution at the Wire Level

EtherNet/IP is not opaque. It exposes internal execution through:

* Encapsulation commands
* CIP service codes
* Object addressing paths
* Explicit response status fields

This makes protocol behavior directly observable in packet captures.

---

### 2. CIP Is an Object-Oriented Industrial Model

Unlike register-based protocols, CIP operates through a structured hierarchy:

* Class → Instance → Attribute

This enables dynamic discovery and extensibility but also introduces a large, observable attack surface for enumeration.

---

### 3. Error States Are Informational Signals

CIP General Status codes provide meaningful structural insight:

* `0x05` → Invalid object or path
* `0x14` → Unsupported attribute
* `0x04` → Path parsing failure
* `0x10` → Device state conflict

Errors are therefore not only failure states but also **structured feedback about internal object validation logic**.

---

### 4. Enumeration Is Native to the Protocol

Discovery mechanisms are built into the protocol itself:

* `ListServices (0x0004)` reveals stack capabilities
* Identity Object (`Class 0x01`) exposes device metadata
* Attribute iteration reveals object structure boundaries
* Symbolic tag access exposes runtime variable spaces (where implemented)

---

### 5. Security Is Deployment-Dependent, Not Protocol-Inherent

EtherNet/IP security posture depends heavily on configuration:

* Legacy deployments expose unauthenticated explicit messaging
* Control is often enforced through network segmentation and device state (RUN/PROG modes)
* CIP Security introduces TLS/DTLS-based protection with certificate authentication

---

## Repository Structure

```text
.
├── scripts/                 # Python-based protocol implementations
│   ├── enip_read_proof.py
│   ├── enip_write_proof.py
│   ├── enip_frag_proof.py
│   ├── enip_get_attr_proof.py
│   ├── enip_set_attr_proof.py
│   ├── enip_command_fingerprint.py
│   ├── enip_identity_clean.py
│   ├── enip_exception_proof.py
│   ├── enip_boundary_scan.py
│   └── enip_monitor.py
│
├── notes/                   # Protocol deep-dives (01–13 series)
│   └── ...
│
└── findings/
    └── executive-summary.md
```

---

## Packet Capture & Monitoring

Capture EtherNet/IP traffic on the loopback interface:

```bash
sudo tcpdump -i lo port 44818 -w enip_lab_capture.pcap
```

Run passive protocol monitoring:

```bash
sudo python3 scripts/enip_monitor.py
```

Analyze traffic in Wireshark or through the integrated parsing logic.

---

## Reproducing the Research

Follow the execution sequence defined in:

```
notes/13-lab-reproduction-guide.md
```

This provides a full step-by-step replication path for all observed behaviors, from basic tag operations to enumeration and defensive monitoring.

---

## Key Takeaway

EtherNet/IP is best understood not as a simple industrial transport protocol, but as a structured execution system where every interaction produces observable behavioral signals across transport, application, and object layers.

By operating at the packet level, this research demonstrates that:

* Industrial protocols are inherently inspectable
* Execution semantics are exposed through CIP service design
* Enumeration and error handling reveal internal structure
* Security is primarily a function of deployment architecture, not protocol design

> “This repository treats EtherNet/IP not as documentation, but as a runtime system that can be observed, reconstructed, and reasoned about at the packet level.”

---

## Disclaimer

This project is intended strictly for educational and defensive security research purposes within an isolated laboratory environment.

Do not apply any of these techniques against operational or production industrial systems without explicit authorization and appropriate safety controls.
