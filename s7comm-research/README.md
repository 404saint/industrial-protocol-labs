# S7comm Protocol Security Research Laboratory

> A practical research series examining classic S7comm communication, COTP/TPKT session establishment, PDU negotiation, PLC memory access, SZL diagnostics, state-machine behavior, and the security evolution toward S7CommPlus.

---

## Overview

This repository documents a hands-on security and protocol study of **S7comm** using the Snap7 1.4.2 native C++ server, custom Python research clients, packet captures, and protocol-level analysis.

The research examines S7comm from transport/session establishment through memory access, diagnostic services, state handling, and the security mechanisms introduced in modern Siemens communication architectures.

Testing combines the Snap7 server, custom protocol-construction scripts, Wireshark, `tshark`, `tcpdump`, and controlled local experiments. The repository focuses on observable protocol behavior and clearly separates transmitted traffic, target responses, and implementation-specific behavior.

---

## Research Scope

The research is divided into six phases:

1. **COTP / TPKT Transport & Session:** Examining TCP/102, TPKT framing, COTP Connection Request/Confirm exchanges, TSAP parameters, reference handling, and session behavior.
2. **S7comm PDU Enumeration:** Analyzing Setup Communication, negotiated PDU size, ReadVar requests, S7-Any addressing, and PLC memory access.
3. **Memory Write & Control Abuse:** Examining WriteVar operations, memory-boundary validation, and S7 UserData control requests.
4. **SZL & CPU Diagnostics:** Analyzing UserData diagnostic services and SZL-based module identification.
5. **State Manipulation & Anomalies:** Testing service processing before Setup Communication, controlled malformed traffic, and held-open session behavior.
6. **S7CommPlus Secure Contrast:** Comparing the classic S7comm security model and observed Snap7 behavior against modern Siemens access protection, session security, and secure communication mechanisms.

An architecture primer establishes the protocol vocabulary used throughout the research. A separate reproduction guide documents the laboratory construction and execution workflow.

---

## Repository Structure

```text
.
├── notes/
│   ├── 00.architecture-primer.md
│   ├── 01.phase1-cotp-tpkt-transport-session.md
│   ├── 02.phase2-s7comm-pdu-enumeration.md
│   ├── 03.phase3-memory-write-control-abuse.md
│   ├── 04.phase4-szl-cpu-diagnostics.md
│   ├── 05.phase5-state-manipulation-anomalies.md
│   ├── 06.phase6-s7comm-plus-secure-contrast.md
│   └── lab-reproduction-guide.md
│
├── pcaps/
│   ├── phase1_cotp_handshake.pcap
│   ├── phase2_s7comm_pdu_read.pcap
│   ├── phase3_write_control_abuse.pcap
│   ├── phase4_szl_enumerator.pcap
│   └── phase5_state_anomalies.pcap
│
├── screenshots/
└── scripts/
    ├── phase1_cotp_handshake.py
    ├── phase2_pdu_enumeration.py
    ├── phase3_write_control_abuse.py
    ├── phase4_szl_enumerator.py
    ├── phase5_state_anomalies.py
    └── run_plc_server.sh
```

---

## Research Notes

| Phase | Focus                                         |
| ----- | --------------------------------------------- |
| `00`  | S7comm architecture and security model        |
| `01`  | TPKT/COTP transport and session establishment |
| `02`  | S7comm PDU negotiation and memory enumeration |
| `03`  | Memory writes and control-plane requests      |
| `04`  | SZL and CPU diagnostic services               |
| `05`  | State manipulation and protocol anomalies     |
| `06`  | S7CommPlus and modern security contrast       |

The `00` architecture primer establishes the protocol baseline used throughout the research. The `lab-reproduction-guide.md` document is a **reproduction guide**, not an additional research phase.

---

## Research Harnesses

Each experimental phase uses an independent Python research client:

| Script                          | Purpose                                          |
| ------------------------------- | ------------------------------------------------ |
| `phase1_cotp_handshake.py`      | COTP connection establishment and TSAP testing   |
| `phase2_pdu_enumeration.py`     | Setup Communication and ReadVar enumeration      |
| `phase3_write_control_abuse.py` | WriteVar, boundary testing, and control requests |
| `phase4_szl_enumerator.py`      | SZL diagnostic enumeration                       |
| `phase5_state_anomalies.py`     | State-machine and resource-handling experiments  |
| `run_plc_server.sh`             | Snap7 native C++ target launcher                 |

The clients construct and transmit S7comm traffic against the local Snap7 laboratory target. Packet captures are used to verify the resulting wire-level behavior.

---

## Laboratory Environment

The laboratory uses:

* Snap7 1.4.2
* Native C++ server
* Python 3
* Wireshark
* Rich 
* Scapy
* `tshark`
* `tcpdump`
* Custom S7comm research clients
* Linux loopback networking

The target listens on: `TCP/102` and the research clients connect locally through: `127.0.0.1:102`.

The protocol path examined throughout the research is:

```text
Ethernet
   │
   ▼
  IP
   │
   ▼
TCP/102
   │
   ▼
TPKT
   │
   ▼
COTP
   │
   ▼
S7comm
```

The primary test memory area is **DB3**, provided by the Snap7 demonstration server.

---

## Key Findings

The laboratory produced several implementation-specific observations:

* The Snap7 target accepted COTP Connection Requests using the tested TSAP values and returned COTP Connection Confirms.
* Setup Communication negotiated a maximum S7 PDU size of 480 bytes.
* ReadVar successfully retrieved data from DB3 using S7-Any addressing.
* The tested Snap7 configuration accepted an unauthenticated WriteVar operation against DB3.
* Out-of-range memory access was rejected by the target with the observed invalid-address response.
* A constructed CPU control UserData request was transmitted, but the Snap7 demonstration server did not implement the tested control function.
* SZL `0x0011` returned module-identification data from the simulated target, while the tested `0x0111` request was unavailable.
* The Snap7 implementation processed a ReadVar request before Setup Communication had occurred, demonstrating incomplete state enforcement for the tested read path.
* A pre-Setup WriteVar request was processed but did not successfully modify the tested memory location.
* Fifty held-open sessions containing malformed TPKT traffic did not cause the tested server to become unavailable during the observation window.
* The S7CommPlus review documents the security evolution from classic S7comm toward stronger access protection, session security, cryptographic mechanisms, and secure communication features in modern Siemens architectures.

These observations apply to the specific Snap7 1.4.2 laboratory configuration and should not be treated as universal characteristics of Siemens PLC hardware.

---

## Packet Capture Evidence

The repository contains packet captures corresponding to the experimental phases:

| Capture                           | Evidence                                         |
| --------------------------------- | ------------------------------------------------ |
| `phase1_cotp_handshake.pcap`      | TPKT/COTP session establishment and TSAP testing |
| `phase2_s7comm_pdu_read.pcap`     | Setup Communication and ReadVar                  |
| `phase3_write_control_abuse.pcap` | WriteVar, bounds checking, and control request   |
| `phase4_szl_enumerator.pcap`      | SZL diagnostic requests and responses            |
| `phase5_state_anomalies.pcap`     | State-machine and malformed-session experiments  |

The captures provide wire-level evidence for the observations documented in the corresponding research notes. A transmitted packet does not, by itself, establish that a target accepted, acted upon, or rejected the requested operation. The research therefore correlates client output, server behavior, and packet-level evidence wherever possible.

---

## Research Methodology

The research follows a layered workflow:

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
Security Contrast
```

The methodology combines protocol documentation, hand-crafted S7comm requests, controlled memory operations, diagnostic enumeration, malformed input testing, packet capture, and manual field-level analysis. The objective is to document **observable protocol behavior** while keeping implementation-specific results separate from claims about physical Siemens PLCs.

---

## Reproduction

The complete laboratory setup and execution workflow is documented in:

```text
notes/lab-reproduction-guide.md
```

The guide covers:

* Snap7 1.4.2 acquisition and compilation
* Native C++ server construction
* TCP/102 target setup
* Research client execution
* PCAP capture with `tcpdump`
* Wireshark and `tshark` validation
* Phase-by-phase reproduction
* Laboratory reset and teardown

---

## Disclaimer

This repository is intended for educational, protocol research, and defensive security analysis. All active testing was performed against locally controlled laboratory infrastructure. No experiments were conducted against production industrial networks, operational PLCs, or unauthorized systems. Use these techniques only against systems for which you have explicit authorization to conduct security research.
