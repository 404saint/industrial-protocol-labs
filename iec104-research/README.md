
# IEC 60870-5-104 Protocol Security Research Laboratory

> A practical research series examining IEC 60870-5-104 architecture, APCI state management, ASDU addressing, unauthenticated control execution, parser boundaries, and IEC 62351 security extensions through controlled laboratory experimentation.

---

## Overview

This repository documents a hands-on security study of **IEC 60870-5-104 (IEC 104)** using a locally controlled `lib60870-C` server and a Python-based security-extension laboratory.

The research examines the protocol from the wire level upward, focusing on:

* APCI link-state activation and control framing
* ASDU structure and Information Object Address (IOA) enumeration
* Common Address and sequence-counter handling
* Unauthenticated control execution and Select-Before-Operate (SBO)
* Malformed APCI and ASDU boundary handling
* IEC 62351-3 TLS / mutual TLS protection
* IEC 62351-8 role-based authorization
* Cleartext versus cryptographically protected communication

Testing combines custom Python protocol harnesses with Wireshark packet capture and direct observation of the target server behavior.

---

## Research Scope

The research is divided into five protocol-security phases:

1. **Link State Dynamics:** Examining TCP initialization, APCI control framing, `STARTDT`, `STOPDT`, `TESTFR`, and unauthenticated link activation.
2. **ASDU & IOA Enumeration:** Mapping telemetry points, Common Addresses, sequence numbers, and application-layer command structures.
3. **Unauthenticated Attack Surface:** Testing APCI state enforcement, sequence-counter validation, direct control execution, and SBO requirements.
4. **Security Boundaries:** Evaluating malformed framing, invalid lengths, unsupported Type IDs, truncated ASDUs, and illegal U-Format directives.
5. **Secure Extension Contrast:** Comparing the cleartext attack surface against TLS/mTLS and authorization controls implemented in the secured laboratory.

A separate reproduction guide documents the complete laboratory build and execution workflow.

---

## Repository Structure

```text
.
├── certificates/
├── notes/
│   ├── 00.architecture-primer.md
│   ├── 01.phase1-link-state-handshake.md
│   ├── 02.phase2-asdu-ioa-enumeration.md
│   ├── 03.phase3-unauthenticated-attack-surface.md
│   ├── 04.phase4-security-boundaries.md
│   ├── 05.phase5-secure-extension-contrast.md
│   └── 06.lab-reproduction-guide.md
│
├── pcaps/
├── screenshots/
└── scripts/
    ├── 01_phase1_handshake.py
    ├── 02_phase2_enumeration.py
    ├── 03_phase3_attack_surface.py
    ├── 04_phase4_boundary_testing.py
    ├── 05_secure_lab_client.py
    └── 05_secure_lab_server.py
````

---

# Research Notes

| Phase | Focus                                             |
| ----- | ------------------------------------------------- |
| `00`  | IEC 60870-5-104 architecture and security model   |
| `01`  | Link-state dynamics and APCI control framing      |
| `02`  | ASDU structure and IOA enumeration                |
| `03`  | Unauthenticated attack surface and state abuse    |
| `04`  | Security boundaries and implementation edge cases |
| `05`  | Secure extensions and cryptographic mitigation    |
| `06`  | Laboratory reproduction and automation            |

The `00` architecture primer establishes the protocol baseline used throughout the research.

The `06` document is a **reproduction guide**, not an additional research phase.

---

## Research Harnesses

Each research phase is implemented as an independent Python harness:

| Script                          | Purpose                                                            |
| ------------------------------- | ------------------------------------------------------------------ |
| `01_phase1_handshake.py`        | APCI link-state activation, control framing, and state transitions |
| `02_phase2_enumeration.py`      | ASDU interrogation, telemetry analysis, and IOA mapping            |
| `03_phase3_attack_surface.py`   | State-machine, sequence-counter, and control-execution testing     |
| `04_phase4_boundary_testing.py` | Malformed APCI/ASDU and parser-boundary testing                    |
| `05_secure_lab_client.py`       | TLS/mTLS security-control validation                               |
| `05_secure_lab_server.py`       | Secure IEC 104 laboratory endpoint                                 |

The scripts are designed to operate against the corresponding local laboratory components rather than production IEC 104 infrastructure.

---

## Laboratory Environment

### Cleartext IEC 104 Target

The baseline target uses:

* `lib60870-C`
* `cs104_server_no_threads`
* TCP port `2404`
* Local loopback address `127.0.0.1`

The cleartext environment provides the implementation baseline used during Phases 1–4.

### Secure Laboratory

The security-extension environment uses:

* Python
* OpenSSL
* TLS 1.3
* X.509 certificates
* Mutual TLS authentication
* Role-based authorization
* TCP port `19999`

The secured environment provides the comparative baseline used during Phase 5.

### Analysis Tooling

* Linux
* Python 3.x
* CMake / GNU Make
* OpenSSL
* Wireshark
* TShark
* Git

---

## Key Findings

The laboratory produced several notable observations:

* `STARTDT ACT` was accepted without native identity authentication on the cleartext IEC 104 endpoint.
* The target transitioned into `DATA_TRANSFER_ACTIVE` without cryptographic verification.
* General Interrogation exposed configured telemetry information and IOA structures.
* Direct Single Command execution was accepted without an enforced Select-Before-Operate sequence.
* High-impact control points could be manipulated through unauthenticated application-layer commands in the tested configuration.
* Large forward APCI sequence-number jumps were accepted without an observed transport reset.
* Invalid APCI framing and malformed ASDU structures were handled without observed process crashes.
* Unsupported ASDU Type IDs were silently discarded rather than generating explicit negative acknowledgments in the tested implementation.
* TLS 1.3 with mutual X.509 authentication prevented unauthenticated clients from establishing the secured session.
* Role-based authorization rejected an authenticated client attempting an unauthorized control operation.

These observations apply to the specific laboratory configuration and implementation under test. They should not be interpreted as universal characteristics of all IEC 60870-5-104 deployments.

---

## Packet Capture Evidence

Each research phase has an associated packet capture:

| Capture                                        | Evidence                                                |
| ---------------------------------------------- | ------------------------------------------------------- |
| `phase1-link-state-handshake.pcapng`           | TCP establishment and APCI link-state transitions       |
| `phase2-asdu-ioa-enumeration.pcapng`           | ASDU exchanges, telemetry, and IOA behavior             |
| `phase3-unauthenticated-attack-surface.pcapng` | Sequence manipulation and control execution             |
| `phase4-security-boundaries.pcapng`            | Malformed and boundary-condition handling               |
| `phase5-secure-extension-contrast.pcapng`      | TLS-protected communication and authentication behavior |

The packet captures provide wire-level evidence supporting the observations documented in the corresponding research notes.

---

## Research Methodology

The research follows a consistent experimental workflow:

```text
Architecture Baseline
        │
        ▼
Protocol Interaction
        │
        ▼
Wire Capture
        │
        ▼
Implementation Observation
        │
        ▼
Security Assessment
        │
        ▼
Mitigation Validation
```

Protocol behavior is validated through a combination of:

* Raw protocol construction
* Server responses
* Application-layer output
* Packet captures
* Controlled malformed inputs
* Comparative security testing

The objective is to establish observable protocol behavior rather than rely solely on theoretical specification analysis.

---

## Reproduction

The complete laboratory setup is documented in:

```text
notes/06.lab-reproduction-guide.md
```

The guide covers:

* `lib60870-C` compilation
* IEC 104 server deployment
* Research script execution
* Laboratory certificate generation
* TLS/mTLS configuration
* Wireshark capture methodology
* Cleartext versus secure-environment comparison

---

## Disclaimer

This repository is intended for educational, protocol research, and defensive security analysis. All testing was performed against locally controlled laboratory infrastructure. The IEC 104 control operations, malformed-frame tests, and security-boundary experiments were not performed against production systems or unauthorized infrastructure. Use these techniques only against systems for which you have explicit authorization to conduct security research.

