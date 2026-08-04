# BACnet/IP Protocol Research Laboratory

> A practical research series exploring BACnet/IP protocol internals through manual packet construction, protocol analysis, and controlled laboratory experimentation.

---

## Overview

BACnet (Building Automation and Control Network) is one of the most widely deployed protocols in modern Building Automation Systems (BAS). Unlike traditional industrial protocols that expose register-based memory maps, BACnet implements an object-oriented application model consisting of standardized objects, properties, services, and event mechanisms.

This repository documents a structured study of BACnet/IP by manually constructing protocol messages, observing device behavior, and analyzing protocol responses inside an isolated laboratory environment.

The objective is to understand how BACnet devices process application services, command arbitration, routing infrastructure, and event mechanisms without relying on high-level protocol libraries.

---

## Research Scope

This research covers four major protocol areas:

- Object Model & Property Engine
- Priority Array Arbitration
- BBMD Routing & Network Traversal
- Change-of-Value (COV), Alarm Handling & BACnet/SC

All testing was performed against a laboratory BACnet/IP implementation and focuses on protocol behavior rather than vulnerability exploitation.

---

## Repository Structure

```
.
├── notes/
│   ├── 00-architecture-primer.md
│   ├── 01-object-property-database.md
│   ├── 02-priority-array-arbitration.md
│   ├── 03-routing-bbmd-subnets.md
│   ├── 04-cov-alarms-and-modern-sc.md
│   ├── 05-final-assessment.md
│   └── 06-lab-reproduction-guide.md
│
├── scripts/
│   ├── object-model-and-properties.py
│   ├── priority-array-arbitration.py
│   ├── bbmd-boundary-traversal.py
│   └── cov-alarms-sc-transition.py
│
└── screenshots/
```

---

# Research Notes

## 00 — BACnet Protocol Architecture & Object Database Model

Introduces the BACnet object-oriented architecture including:

- Object hierarchy
- Property model
- UDP/BVLL/NPDU/APDU encapsulation
- Priority Array architecture
- BBMD infrastructure
- Foreign Device Registration
- BACnet routing concepts

---

## 01 — Object Model & Property Engine

Focuses on core application services including:

- ReadProperty
- ReadPropertyMultiple
- Object enumeration
- CreateObject
- DeleteObject
- Property error handling

Research observations include object discovery, property inspection, runtime object creation behavior, and protocol-compliant error responses.

---

## 02 — Priority Array Arbitration

Examines BACnet's command arbitration mechanism by observing:

- Priority slot writes
- Slot precedence
- NULL relinquish behavior
- Present_Value arbitration
- Priority_Array inspection

The accompanying harness demonstrates how commandable objects evaluate competing control requests.

---

## 03 — Routing, BBMD & Subnet Traversal

Explores BACnet/IP networking infrastructure including:

- BVLL messaging
- Foreign Device Registration
- BBMD behavior
- Router discovery
- Global Who-Is broadcasts

The research focuses on how BACnet extends communication beyond a single broadcast domain.

---

## 04 — COV, Alarm Processing & BACnet/SC

Investigates BACnet event mechanisms through:

- SubscribeCOV
- COV Notifications
- Event_Enable property modification
- Alarm state inspection
- BACnet/SC transport probing

This phase also compares traditional BACnet/IP transport with modern BACnet Secure Connect (BACnet/SC).

---

## Research Harnesses

Each protocol area is accompanied by a standalone Python research harness.

| Script | Purpose |
|---------|---------|
| `object-model-and-properties.py` | Object database inspection and property analysis |
| `priority-array-arbitration.py` | Priority slot arbitration experiments |
| `bbmd-boundary-traversal.py` | BVLL, BBMD and routing analysis |
| `cov-alarms-sc-transition.py` | COV subscriptions, alarm behavior and BACnet/SC inspection |

Every harness constructs BACnet packets manually using Python's standard library and communicates directly over UDP without external BACnet protocol libraries.

---

## Laboratory Environment

Research was conducted inside an isolated laboratory using:

- Linux
- Python 3.10+
- BACnet Stack (`bacserv`)
- Wireshark
- tcpdump
- Rich (terminal formatting)

Complete reproduction instructions are available in:

```
notes/06-lab-reproduction-guide.md
```

---

## Screenshots

The `screenshots/` directory contains terminal captures and protocol diagrams corresponding to each research phase.

---

## Research Philosophy

The purpose of this repository is educational.

Rather than relying on existing BACnet frameworks, every experiment was built by manually constructing protocol frames and analyzing device responses. This approach provides visibility into the protocol itself and helps develop a deeper understanding of BACnet's application services, routing mechanisms, and event model.

The observations documented throughout this repository reflect the behavior of the laboratory environment used during testing. They should not be interpreted as representative of every BACnet implementation.

---

## Disclaimer

This repository is intended solely for educational and defensive security research.

All experiments were performed in an isolated laboratory environment under the author's control. No testing was conducted against production building automation systems or third-party infrastructure.

The material presented here should be used only to improve understanding of BACnet and to support the secure design, assessment, and operation of building automation networks.
