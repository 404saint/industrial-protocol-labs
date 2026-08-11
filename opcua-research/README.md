# OPC UA Protocol Security Research Laboratory

> A practical research series exploring OPC UA protocol architecture, security boundaries, session handling, address-space access control, and X.509 validation through controlled laboratory experimentation.

---

## Overview

This repository documents a hands-on study of **OPC UA** using an isolated `open62541` laboratory server.

The research focuses on understanding how OPC UA exposes and enforces:

* Endpoint security policies
* SecureChannels and sessions
* Identity authentication
* Address-space access control
* Variable write permissions
* X.509 certificate validation

Testing combines custom Python research harnesses with Wireshark/tshark packet analysis.

---

## Research Scope

The research is divided into four phases:

1. **Endpoint Discovery :** Enumerating server metadata, endpoints, security modes, policies, and identity tokens.
2. **Session Handshake :** Examining SecureChannel establishment, session activation, and authentication behavior.
3. **Address-Space Traversal :** Mapping nodes, resolving NodeIds, inspecting access levels, and testing write authorization.
4. **Security Boundaries :** Evaluating insecure endpoint exposure, X.509 validation, and invalid identity handling.

A dedicated reproduction guide documents the complete laboratory setup.

---

## Repository Structure

```text
.
├── captures/
│   ├── opcua_phase1.pcap
│   ├── opcua_phase2.pcap
│   ├── opcua_phase3.pcap
│   ├── opcua_phase4.pcap
│   └── opcua_phase4_2.pcap
│
├── logs/
│   └── phase3_output.txt
│
├── notes/
│   ├── 00-architecture-primer.md
│   ├── 01-phase1-endpoint-discovery.md
│   ├── 02-phase2-session-handshake.md
│   ├── 03-phase3-node-traversal.md
│   ├── 04-phase4-security-boundaries.md
│   └── 05-lab-reproduction-guide.md
│
├── screenshots/
│
└── scripts/
    ├── phase1_get_endpoints.py
    ├── phase2_session_handshake.py
    ├── phase3_node_traversal.py
    ├── phase4_security_audit.py
    └── phase4_security_audit_2.py
```

---

# Research Notes

| Phase | Focus                                              |
| ----- | -------------------------------------------------- |
| `00`  | OPC UA architecture and security model             |
| `01`  | Endpoint discovery and security-policy enumeration |
| `02`  | SecureChannel and session handshake analysis       |
| `03`  | Address-space traversal and access-level auditing  |
| `04`  | Security boundaries and misconfiguration analysis  |
| `05`  | Laboratory reproduction and automation             |

Detailed findings, packet analysis, and observations are documented in the individual research notes.

---

## Research Harnesses

Each phase has a standalone Python harness:

| Script                        | Purpose                                 |
| ----------------------------- | --------------------------------------- |
| `phase1_get_endpoints.py`     | Endpoint and security-policy discovery  |
| `phase2_session_handshake.py` | Session and authentication testing      |
| `phase3_node_traversal.py`    | Address-space and write-access auditing |
| `phase4_security_audit.py`    | Security-boundary testing               |
| `phase4_security_audit_2.py`  | Independent X.509 trust-boundary retest |

---

## Laboratory Environment

* Linux
* Python 3.x
* Docker
* `open62541`
* `asyncua`
* `cryptography`
* Wireshark / tshark
* tcpdump
* Rich

The target server communicates over OPC UA TCP on **port 4840**.

---

## Key Findings

The laboratory produced several notable observations:

* `SecurityPolicy#None` was advertised alongside protected endpoints.
* Anonymous session activation was permitted on the tested insecure endpoint.
* Invalid username credentials were rejected with `BadUserAccessDenied`.
* Recursive address-space traversal exposed accessible server nodes.
* Multiple laboratory variables accepted anonymous write operations.
* An independently generated self-signed certificate was rejected with `BadCertificateUriInvalid`.
* OPC UA service exchanges were verified through packet captures.

These observations apply to the specific laboratory configuration and are not representative of OPC UA implementations generally.

---

## Research Philosophy

The goal is to understand OPC UA through direct experimentation rather than treating the protocol stack as a black box.

Each phase follows:

```text
Discover → Interact → Capture → Validate → Document
```

Protocol observations are supported where possible by both application-layer results and wire-level evidence.

---

## Reproduction

See:

```text
notes/05-lab-reproduction-guide.md
```

for the complete laboratory setup, execution sequence, packet-capture workflow, and teardown instructions.

---

## Disclaimer

This repository is intended for educational and defensive security research.

All testing was performed against an isolated laboratory environment under the author's control. No testing was conducted against production systems or unauthorized infrastructure.

Use these techniques only in environments where you have explicit permission to perform security research.
