# Industrial Protocol Labs

![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square)
![Research](https://img.shields.io/badge/Focus-Industrial%20Protocols-red.svg?style=flat-square)
![Language](https://img.shields.io/badge/Language-Python%203-yellow.svg?style=flat-square)
![Category](https://img.shields.io/badge/Domain-ICS%20%2F%20OT%20Security-orange.svg?style=flat-square)

A collection of implementation-driven research projects exploring industrial communication protocols used throughout Operational Technology (OT) and Industrial Control Systems (ICS).

Rather than treating protocols as opaque APIs, this series studies how they operate internally by implementing parsers, state machines, packet construction, and protocol workflows from first principles. Each repository combines protocol engineering with practical security analysis to better understand how industrial devices process, validate, and exchange data.

---

# Research Philosophy

Every protocol in this series follows the same guiding principle:

> **Understand the protocol before attempting to secure or attack it.**

Instead of beginning with exploits or fuzzing, each project starts with protocol architecture and progressively builds toward implementation, experimentation, and defensive analysis.

The typical workflow is:

```text
Study Specification
        │
        ▼
Implement Protocol
        │
        ▼
Validate Behavior
        │
        ▼
Analyze State Machines
        │
        ▼
Evaluate Security Properties
        │
        ▼
Document Defensive Guidance
```

This methodology produces repositories that are both educational and reproducible while remaining grounded in the protocol specifications.

---

# Research Series

| Repository                                                                                                      | Protocol              | Layer                   | Default Transport  | Primary Research Focus                                       | Status         |
| --------------------------------------------------------------------------------------------------------------- | --------------------- | ----------------------- | ------------------ | ------------------------------------------------------------ | -------------- |
| [`modbus-research`](https://github.com/404saint/industrial-protocol-labs/tree/main/modbus-research)             | **Modbus TCP**        | Application             | TCP/502            | Register model, function codes, protocol behavior            | 🟢 Complete    |
| [`ethernet-ip research`](https://github.com/404saint/industrial-protocol-labs/tree/main/ethernet-ip%20research) | **EtherNet/IP (CIP)** | Application             | TCP/44818          | Encapsulation protocol, CIP object model, session management | 🟢 Complete    |
| [`dnp3-research`](https://github.com/404saint/industrial-protocol-labs/tree/main/dnp3-research)                 | **DNP3 (IEEE 1815)**  | Application / Data Link | TCP/20000*         | Layered architecture, state machines, Secure Authentication  | 🟢 Complete    |
| `bacnet-research`                                                                                               | **BACnet/IP**         | Application             | UDP/47808          | Object discovery, services, property access                  | 🟡 In Progress |
| `opcua-research`                                                                                                | **OPC UA**            | Application             | TCP/4840           | Secure channels, sessions, information models                | ⚪ Planned      |
| `iec60870-5-104-research`                                                                                       | **IEC 60870-5-104**   | Application             | TCP/2404           | Telecontrol architecture and ASDUs                           | ⚪ Planned      |
| `iec61850-research`                                                                                             | **IEC 61850**         | Application             | TCP/102 / Ethernet | MMS, GOOSE, Sampled Values                                   | ⚪ Planned      |
| `profinet-research`                                                                                             | **PROFINET**          | Application             | Ethernet           | Industrial Ethernet and device discovery                     | ⚪ Planned      |
| `s7comm-research`                                                                                               | **Siemens S7comm**    | Application             | TCP/102            | PLC communication and engineering workflows                  | ⚪ Planned      |

> **Note:** Some protocols support multiple transport media. Where applicable, the transport shown above reflects the laboratory implementation used for the accompanying research.

---

# Repository Structure

Each protocol repository follows a consistent layout.

```text
protocol-research/
├── notes/          # Technical documentation and research papers
├── scripts/        # Python implementations
├── pcaps/          # Packet captures
├── screenshots/    # Experimental output
└── README.md
```

This structure allows every project to be reproduced independently while maintaining a consistent organization across the research series.

---

# Research Methodology

Although each protocol differs architecturally, every repository generally progresses through the following stages:

* Protocol architecture and frame analysis
* Enumeration and capability discovery
* State machine exploration
* Control and administrative operations
* Boundary and transport validation
* Security mechanism evaluation
* Defensive recommendations

Some protocols include additional protocol-specific phases. For example, Secure Authentication in DNP3 or object model analysis in EtherNet/IP.

---

# Laboratory Environment

All experiments are performed inside isolated laboratory environments using simulated devices, software implementations, or containerized services.

Typical tooling includes:

* Python 3
* Raw TCP/UDP sockets
* Wireshark
* tcpdump
* Scapy
* OpenPLC
* Protocol-specific simulators

No production industrial infrastructure is used during the research.

---

# Research Objectives

The purpose of this series is to develop a deeper understanding of industrial communication protocols through implementation and experimentation.

Topics explored throughout the repositories include:

* Protocol implementation
* Binary protocol parsing
* Object and register models
* Session management
* State machine behavior
* Transport mechanisms
* Secure authentication
* Detection engineering
* Defensive protocol analysis

---

# Intended Audience

These repositories are intended for:

* ICS/OT security researchers
* Detection engineers
* Protocol reverse engineers
* Malware analysts
* Network defenders
* Students studying industrial communication protocols

A working knowledge of networking and Python is helpful but not required to follow the research.

---

# License

This project is licensed under the Apache License 2.0.

See the accompanying `LICENSE` file for the complete license text.

---

# Disclaimer

All research published in this repository was conducted in isolated laboratory environments using simulated devices or systems under the author's control.

The code and documentation are provided exclusively for educational, research, and defensive security purposes. They should not be used against production industrial systems or any infrastructure without explicit authorization.

Industrial Control Systems frequently interact with physical processes. Always perform protocol research responsibly and within appropriately isolated laboratory environments.
