# Industrial Protocol Labs

![License: Apche 2.0](https://img.shields.io/badge/License-Apache-blue.svg?style=flat-square)
![Category: ICS/OT Security](https://img.shields.io/badge/Category-ICS%2FOT%20Security-red.svg?style=flat-square)
![Language: Python 3](https://img.shields.io/badge/Language-Python%203-yellow.svg?style=flat-square)
![Environment: OpenPLC](https://img.shields.io/badge/Environment-OpenPLC-orange.svg?style=flat-square)

A specialized, low-level security research portfolio dedicated to the dissection, reverse-engineering, and defensive analysis of Operational Technology (OT) and Industrial Control System (ICS) communication protocols.

Rather than relying on high-level third-party libraries or abstract scanners, this repository focuses on building custom, bare-metal toolsets from the raw socket layer up. The goal is to evaluate exactly how industrial control daemons interpret binary data packets, enforce memory boundaries, validate inputs, and respond to protocol manipulation.

## Core Research Methodology

Every protocol added to this series is systematically subjected to a 5-phase evaluation lifecycle to maintain research consistency and deep analytical rigor:

```text
  [01: DISSECTION]      --> Reverse-engineer the specification, map headers, and craft raw binary frames.
         │
  [02: CAPABILITY]      --> Enumerate function codes, commands, or objects to map exposed footprints.
         │
  [03: MANIPULATION]    --> Test variable read/write boundaries, state overrides, and memory persistence.
         │
  [04: RESILIENCE]      --> Inject structural anomalies, clip payload lengths, and analyze exception behavior.
         │
  [05: DEFENSIVE]       --> Export malicious/normal PCAPs, engineer IDS rules, and document hardening steps.

```

---

## Master Protocol Matrix

This matrix tracks active research progress, transport layer specs, and completed engineering deliverables across the industrial protocol spectrum.

| Directory | Protocol Name | OSI Layer | Transport | Research Focus | Status |
| --- | --- | --- | --- | --- | --- |
| [`/01-modbus-tcp`](https://github.com/404saint/industrial-protocol-labs/tree/main/modbus-research) | **Modbus TCP** | Application | TCP/502 | Register Polling & Volatile Bit-Flipping | 🟢 **Complete** |
| [`/02-ethernet-ip`](https://github.com/404saint/industrial-protocol-labs/tree/main/ethernet-ip%20research) | **EtherNet/IP (CIP)** | Application | TCP/44818 | Object Attributes & Session Handshakes | 🟢 **Complete** |
| `/03-dnp3` | **DNP3** | App/Link | TCP/20000 | Distributed Class Polling & COS Events |🟡 *In Progress* |
| `/04-bacnet-ip` | **BACnet/IP** | Application | UDP/47808 | Building Automation Property Discovery | 🔴 *Backlog* |

---

## Unified Test Environment Blueprint

All experiments are executed within a sandboxed, hardware-in-the-loop or containerized simulation lab. This guarantees safe exploration of catastrophic process state manipulation without risking real-world physical damage or hardware exhaustion.

* **Target Runtimes:** OpenPLC Engine, specialized protocol daemons, and synthetic industrial simulators.
* **Analysis Toolkit:** Python 3.x (Standard `socket` and `struct` libraries), `tcpdump`, and Wireshark.

---

## Skills & Capabilities Demonstrated

* **OT/ICS Security Engineering:** Practical understanding of industrial automation data models, register spacing, and PLC runtime execution patterns.
* **Protocol Reverse Engineering:** Hand-crafting binary request payloads, tracking transaction boundaries, and raw socket programming.
* **Vulnerability Assessment:** Target profiling, fuzzing fixed parameters, and testing input validation limits.
* **Detection Engineering:** Developing high-fidelity network-level signatures and tracking exception ratios to stop malicious reconnaissance.

---

## License

This repository is open-sourced under the Apache License 2.0. You are free to use, modify, and distribute the custom scripts and methodologies. These permissions apply to educational, defensive, and authorized security assessment purposes. See the local LICENSE file for full liability disclaimer text.

---

## Disclaimer

All research, scripts, and packet captures published in this repository are developed strictly within an isolated, authorized laboratory environment for educational and defensive security engineering purposes. Do not target production industrial controls, utility networks, or live automated environments without formal authorization and explicit safety constraints.
