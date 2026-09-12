# PROFINET Protocol Security Research Laboratory

> A practical research series examining PROFINET architecture, DCP and LLDP discovery, DCE/RPC application-relation establishment, cyclic Real-Time communication, Layer 2 traffic injection, netload resilience, malformed-frame handling, and the security extensions defined by PROFIBUS & PROFINET International.

---

## Overview

This repository documents a hands-on security and protocol study of **PROFINET** using the `p-net` device stack, isolated Linux network namespaces, custom Python research harnesses, raw Layer 2 traffic generation, and packet-level analysis.

The research examines PROFINET from discovery through application-relation establishment and cyclic communication, with a focus on:

* DCP-based device discovery and station identity
* LLDP chassis and port topology information
* DCE/RPC communication over UDP/34964
* Application Relationship and IOCR-related structures
* PROFINET RT cyclic frame layout
* Cycle counters, DataStatus, and TransferStatus
* Layer 2 payload injection
* Netload-oriented traffic generation
* DCP-like station-name spoofing
* Malformed Frame ID and truncated-payload handling
* Historical Security Class 1, 2, and 3 mechanisms
* Current secure-extension architecture, including SXP, SecureAccess, and SecureRealtime

Testing combines the `p-net` sample application, custom Python scripts, Scapy, raw Layer 2 sockets, Wireshark, `tcpdump`, and controlled virtual network infrastructure. The repository focuses on observable protocol behavior and clearly separates packet-level evidence, application output, calculated values, and unverified endpoint behavior.

---

## Research Scope

The research is divided into five phases:

1. **DCP & Topology Discovery:** Examining PROFINET DCP identity and configuration traffic, station-name information, vendor and device identifiers, IP configuration blocks, and LLDP topology metadata.
2. **DCE/RPC & Application-Relation Context Management:** Analyzing acyclic communication over UDP/34964, DCE/RPC request and response structures, AR-related identifiers, and AR, IOCR, and AlarmCR block construction.
3. **Cyclic RT I/O Analysis:** Dissecting PROFINET Real-Time Layer 2 frames, process-data payloads, cycle-counter placement, DataStatus, TransferStatus, and controlled RT-like traffic generation.
4. **Netload & Resiliency Audit:** Generating controlled Layer 2 bursts, DCP-like station identity traffic, malformed Frame IDs, and truncated payloads to examine the observable traffic surface and capture-level behavior.
5. **Secure Extension Contrast:** Comparing the attack surfaces observed in the earlier phases against the security mechanisms defined by PROFINET specifications and PROFIBUS & PROFINET International security material.

An architecture primer establishes the protocol vocabulary used throughout the research. A separate reproduction guide documents the laboratory construction and execution workflow.

---

## Repository Structure

```text
.
├── notes/
│   ├── 00.architecture-primer.md
│   ├── 01.phase1-dcp-topology-discovery.md
│   ├── 02.phase2-dcerpc-ar-context-management.md
│   ├── 03.phase3-cyclic-rt-io-analysis.md
│   ├── 04.phase4-netload-resiliency-audit.md
│   ├── 05.phase5-secure-extension-contrast.md
│   └── lab-reproduction-guide.md
│
├── pcaps/
│   ├── phase1-dcp-lldp.pcap
│   ├── phase2_rpc_ar_connect.pcap
│   ├── phase3_rt_cyclic.pcap
│   └── phase4_profinet_audit.pcap
│
├── screenshots/
│   ├── 01_dcp_audit.png
│   ├── 01_lldp_topology.png
│   ├── 02_rpc_ar_connect.png
│   ├── 02_rpc_full_handshake.png
│   ├── phase3_profinet_rt_analysis.png
│   └── phase4_profinet_audit.png
│
└── scripts/
    ├── 01_dcp_audit.py
    ├── 01_lldp_topology.py
    ├── 02_rpc_ar_connect.py
    ├── 02_rpc_full_handshake.py
    ├── lab-setup.sh
    ├── parse_phase4_pcap.py
    ├── phase3_profinet_rt_analysis.py
    ├── phase4_profinet_audit.py
    └── pn_rt_traffic_generator.py
```

---

## Research Notes

| Phase | Focus                                                       |
| ----- | ----------------------------------------------------------- |
| `00`  | PROFINET architecture and security model                    |
| `01`  | DCP discovery, station identity, and LLDP topology          |
| `02`  | DCE/RPC and Application-Relation context management         |
| `03`  | Cyclic PROFINET RT I/O and status-field analysis            |
| `04`  | Netload, Layer 2 injection, spoofing, and malformed traffic |
| `05`  | PROFINET secure-extension contrast                          |

The `00` architecture primer establishes the protocol baseline used throughout the research. The `lab-reproduction-guide.md` document is a **reproduction guide**, not an additional research phase.

---

## Research Harnesses

Each experimental phase uses one or more independent research scripts:

| Script                           | Purpose                                                    |
| -------------------------------- | ---------------------------------------------------------- |
| `01_dcp_audit.py`                | DCP discovery and station-identity analysis                |
| `01_lldp_topology.py`            | LLDP chassis, port, and topology analysis                  |
| `02_rpc_ar_connect.py`           | Initial DCE/RPC and AR-related request generation          |
| `02_rpc_full_handshake.py`       | Extended AR, IOCR, and AlarmCR request analysis            |
| `pn_rt_traffic_generator.py`     | Controlled Layer 2 RT-like traffic generation              |
| `phase3_profinet_rt_analysis.py` | Cyclic RT frame parsing and timing analysis                |
| `phase4_profinet_audit.py`       | Netload, DCP-like spoofing, and malformed-frame generation |
| `parse_phase4_pcap.py`           | Capture-level classification of Phase 4 traffic            |

The scripts are designed for the accompanying isolated laboratory environment and should not be used against systems without explicit authorization. The Phase 3 traffic generator is a Layer 2 packet-generation harness. It does not implement a complete PROFINET controller or IO-Device and does not establish an Application Relationship or demonstrate receiver-side acceptance.

---

## Laboratory Environment

The laboratory uses:

* `p-net`
* Linux network namespaces
* Virtual Ethernet interfaces
* Python 3
* Scapy
* Raw Layer 2 sockets
* Wireshark
* `tcpdump`
* Custom protocol-analysis scripts

## Network Layout

The primary laboratory separates the controller-side audit environment from the device-side target environment using two Linux network namespaces connected by a virtual Ethernet pair.

```text
                 Host Linux System
                        │
          ┌─────────────┴─────────────┐
          │                           │
   ┌──────┴───────┐             ┌─────┴───────┐
   │ ns-controller│             │  ns-device  │
   │              │             │             │
   │ veth-        │             │ veth-       │
   │ controller   │             │ device      │
   │              │             │             │
   │ 192.168.1.10 │             │ 192.168.1.20│
   └──────┬───────┘             └─────┬───────┘
          │                           │
          └──────── Virtual Ethernet ─┘
```

The controller-side namespace is used for:

* Audit script execution
* Packet capture
* RT analysis
* PCAP parsing

The device-side namespace is used for:

* `pn_dev`
* The Phase 3 RT traffic generator

DCP and LLDP are observed at Layer 2 using EtherType `0x8892` and `0x88CC`, respectively. DCE/RPC application-relation traffic is analyzed over UDP port `34964`.

---

## Key Findings

The laboratory produced several notable observations:

* DCP discovery exposed the tested device's station name, vendor identifier, device identifier, and active IP configuration.
* An attempted DCP station-name update did not change the target's observed station name, consistent with runtime write protection in the tested configuration.
* LLDP exposed chassis, port, system-name, and TTL information that can contribute to local topology mapping.
* The tested DCE/RPC exchange used UDP/34964 and exposed request/response structures, an interface UUID, operation number, and application-level AR-related data.
* The tested application-relation request included ARBlockReq, IOCRBlockReq, and AlarmCRBlockReq structures.
* The Phase 3 capture contained cyclic RT-like frames using EtherType `0x8892` and Frame ID `0x8000`.
* The actual PROFINET cycle counter was located in the cyclic trailer and remained `0x0000` in the captured generator traffic.
* The sequential values previously interpreted as cycle counters were located inside the IO/application payload and represented an application-level sequence.
* DataStatus `0x35` and TransferStatus `0x00` remained constant throughout the Phase 3 capture.
* Controlled payload bytes such as `FF 00 AA 55` were transmitted inside the IO/application data region.
* The Phase 3 capture did not independently demonstrate controller-side acceptance of injected frames or process-image modification.
* The Phase 4 capture contained a 500-frame high-rate EtherType `0x8892` burst, three DCP-like station-name frames, and five crafted frames using Frame ID `0x00FF` with truncated payloads.
* The Phase 4 PCAP provided evidence of transmitted traffic and timing, but did not independently prove target-side acceptance, rejection, logging, or state changes.
* The tested traffic was plaintext at the observed Layer 2 and DCE/RPC boundaries, providing a useful baseline for comparing historical and current PROFINET security mechanisms.
* The secure-extension review shows that the historical Security Class 1/2/3 model has evolved toward newer secure application mechanisms, including secure-capable protocol successors, device identity provisioning, and application classes such as `SecureAccess` and `SecureRealtime`.

These observations apply to the specific `p-net` laboratory configuration, traffic-generation harnesses, and packet captures used in this research. They should not be interpreted as universal characteristics of all PROFINET implementations or deployments.

---

## Packet Capture Evidence

The repository contains packet captures corresponding to the major experimental phases:

| Capture                      | Evidence                                       |
| ---------------------------- | ---------------------------------------------- |
| `phase1-dcp-lldp.pcap`       | DCP discovery and LLDP topology traffic        |
| `phase2_rpc_ar_connect.pcap` | DCE/RPC and AR-related communication           |
| `phase3_rt_cyclic.pcap`      | Cyclic RT-like frames and process-data layout  |
| `phase4_profinet_audit.pcap` | Netload, DCP-like, and malformed-frame traffic |

The captures provide wire-level evidence for the observations documented in the corresponding research notes. Packet captures should be interpreted together with the scripts and their execution output. A transmitted packet does not, by itself, prove that the target accepted, parsed, acted upon, or rejected it.

---

## Research Methodology

The research follows a layered experimental workflow:

```text
Architecture
     │
     ▼
Protocol Interaction
     │
     ▼
Packet Capture
     │
     ▼
Field-Level Analysis
     │
     ▼
Implementation Observation
     │
     ▼
Security Assessment
     │
     ▼
Security Extension Review
```

Protocol behavior is evaluated through:

* Protocol specification analysis
* Controlled DCP and LLDP interaction
* Custom DCE/RPC request generation
* Raw Layer 2 frame construction
* `p-net` sample-stack execution
* Scapy-based traffic generation
* Packet captures
* Wireshark and TShark inspection
* Manual hexadecimal analysis
* Timing measurements
* Controlled malformed and anomalous inputs
* Comparison with published PROFINET security material

The objective is to document **observable implementation behavior** and connect it back to the underlying PROFINET architecture and security model.

The research also maintains explicit evidence boundaries:

* Packet captures establish what was transmitted and observed.
* Application output establishes what the application reported.
* Calculations establish derived values such as timing and watchdog models.
* Endpoint acceptance or rejection requires independent evidence.
* Security implications are evaluated against the tested architecture and the relevant specification material.

---

## Reproduction

The complete laboratory setup and execution workflow is documented in:

```text
notes/lab-reproduction-guide.md
```

The guide covers:

* Linux namespace provisioning
* Virtual Ethernet configuration
* `p-net` execution
* Phase 3 traffic-generator execution
* DCP and LLDP capture
* DCE/RPC and AR analysis
* Cyclic RT-like traffic generation
* Netload and malformed-frame testing
* PCAP validation
* Laboratory teardown

The laboratory depends on specific namespace, interface, stack, and script configuration. Environment-specific adjustments may be required when reproducing the experiments on another system.

---

## Disclaimer

This repository is intended for educational, protocol research, and defensive security analysis. All active testing was performed against locally controlled laboratory infrastructure. No experiments were conducted against production industrial networks, operational PROFINET devices, or unauthorized infrastructure. Use these techniques only against systems for which you have explicit authorization to conduct security research.
