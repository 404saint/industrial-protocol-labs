# DNP3 (IEEE 1815) Protocol Research Laboratory

> A protocol-first, implementation-driven study of DNP3 architecture, state machines, transport behavior, control execution, and Secure Authentication.

---

## Overview

This repository documents a complete hands-on study of the **Distributed Network Protocol 3 (DNP3 / IEEE 1815)** from both a protocol engineering and defensive security perspective.

Rather than treating DNP3 as a collection of function codes to fuzz, the research begins with the protocol's architecture and progressively builds toward increasingly complex behavior, including:

* Protocol architecture and encapsulation
* Asset reconnaissance and enumeration
* Control execution workflows
* Administrative state transitions
* Transport-layer behavior and fragmentation
* Secure Authentication (SA v5)

Every phase is accompanied by:

* Technical documentation
* Reproducible Python implementations
* Packet captures
* Laboratory screenshots
* Experimental observations

The objective is not simply to demonstrate offensive techniques, but to understand **how a DNP3 implementation behaves internally**, how protocol state changes over time, and what those behaviors mean for both attackers and defenders.

---

# Research Methodology

This repository represents a significant shift from my earlier industrial protocol research.

My previous Modbus TCP and EtherNet/IP projects primarily focused on manually implementing protocol functionality and demonstrating offensive workflows.

This research adopts a different methodology.

Instead of beginning with attacks, every experiment starts by understanding the protocol itself:

1. Study the protocol specification.
2. Build a minimal implementation.
3. Observe protocol behavior.
4. Validate implementation state.
5. Analyze the resulting security implications.

The result is a repository that emphasizes protocol mechanics just as much as offensive security.

The goal is to understand **why** a particular behavior exists before exploring **how** it can be abused or defended.

---

# Repository Structure

```text
dnp3-research/
├── notes/           # Research papers and protocol analysis
├── scripts/         # Python laboratory implementations
├── pcaps/           # Packet captures for each experiment
└── screenshots/     # Laboratory execution screenshots
```

---

# Research Papers

| Phase  | Topic                            |
| ------ | -------------------------------- |
| **00** | Architecture Primer              |
| **01** | Reconnaissance & Enumeration     |
| **02** | Control Execution                |
| **03** | Administrative State Transitions |
| **04** | Transport Protocol Behavior      |
| **05** | Secure Authentication Mechanisms |
| **06** | Laboratory Reproduction Guide    |

Each document builds upon the previous one, progressing from protocol fundamentals to more advanced implementation and security concepts.

---

# Laboratory Components

## Documentation

The `notes/` directory contains the complete technical write-up for every research phase.

These documents explain:

* protocol internals
* implementation details
* packet structures
* experimental observations
* defensive considerations

---

## Scripts

The `scripts/` directory contains the Python implementations used throughout the research.

The code intentionally avoids large abstraction frameworks wherever practical so that individual protocol fields, headers, and state transitions remain visible and easy to follow.

---

## Packet Captures

The `pcaps/` directory contains Wireshark captures recorded during the experiments.

These captures allow readers to compare the documented packet structures with actual network traffic generated during the laboratory exercises.

---

## Screenshots

The `screenshots/` directory contains terminal output captured during each research phase.

These images document the experiments as they were originally performed.

> **Note**
>
> The screenshots may not exactly match the current source code.
>
> As the project evolved, the simulated outstation was substantially refactored to improve readability, simplify the internal state machine, and remove experimental code that was no longer required.
>
> The underlying protocol behavior and research findings remain unchanged, but the implementation has become significantly cleaner and easier to maintain.

---

# Laboratory Environment

The experiments were developed using:

* Python 3.10+
* Linux
* Raw TCP sockets
* Wireshark
* `rich` terminal output

All testing was performed inside an isolated laboratory environment using simulated DNP3 endpoints.

No production infrastructure or operational industrial systems were involved.

---

# Goals

This repository is intended to serve as a practical reference for:

* ICS/OT security researchers
* protocol reverse engineers
* detection engineers
* malware analysts
* network defenders
* students learning industrial communication protocols

Rather than relying exclusively on existing protocol libraries, the research focuses on understanding how DNP3 behaves on the wire and how protocol state evolves during communication.

---

# Related Research

This repository is part of a broader series of industrial communication protocol research.

Previous protocol studies include:

* Modbus TCP
* EtherNet/IP (CIP)

Together, these repositories document an ongoing effort to study industrial communication protocols from first principles through implementation, experimentation, and protocol analysis.

---

# Disclaimer

This repository was developed exclusively for educational, research, and defensive security purposes.

All experiments were conducted inside an isolated laboratory environment using simulated devices under the author's control.

Nothing in this repository should be interpreted as authorization to interact with production industrial infrastructure or systems without explicit permission.

Industrial Control Systems frequently interact with physical processes. Always perform protocol research in isolated laboratory environments and follow responsible security practices.
