# 12 - Industrial Infrastructure Hardening Guidance

## Overview

EtherNet/IP systems are often deployed in environments where legacy devices and modern secure controllers coexist. As a result, defensive strategy must operate across two distinct layers:

* Network-level isolation and segmentation
* Protocol-level security using CIP Security (where supported)

This layered model is necessary because traditional EtherNet/IP explicit messaging was originally designed without built-in authentication or confidentiality.

---

## Defensive Layer 1: Network-Level Isolation

### 1. Industrial Demilitarized Zone (IDMZ)

EtherNet/IP traffic should never traverse directly between enterprise and control networks without segmentation.

* EtherNet/IP explicit messaging typically operates over TCP/UDP port `44818`
* Implicit I/O traffic commonly uses UDP port `2222`

These ports should be restricted to segmented industrial zones with controlled routing paths and monitoring points.

Engineering access should be mediated through hardened jump hosts or engineering workstations placed inside the IDMZ.

---

### 2. I/O Traffic Containment

Where supported, converting multicast implicit I/O traffic to unicast communication can reduce network-wide visibility of process data and limit unnecessary exposure across Layer 2 infrastructure.

This reduces passive observability of controller state across switched environments.

---

### 3. Controller Mode Enforcement

Many PLCs provide a physical or software-based mode selector (e.g., RUN / PROGRAM / REMOTE).

When a controller is in **RUN mode**, many implementations restrict or reject configuration-level operations such as:

* Write operations (`Set Attribute Single`, `0x10`)
* Firmware or program modification services

In such cases, rejected operations may produce CIP General Status responses such as `0x10` (Device State Conflict), depending on vendor implementation.

---

## Defensive Layer 2: CIP Security

CIP Security extends EtherNet/IP by introducing cryptographic protection mechanisms at the transport and application boundary.

Instead of raw TCP/UDP communication, secure sessions are established using authenticated and encrypted channels.

---

### 1. Secure Transport Mapping

| Traffic Type       | Standard EtherNet/IP | CIP Security Equivalent |
| :----------------- | :------------------- | :---------------------- |
| Explicit Messaging | TCP `44818`          | TLS-secured channel     |
| Implicit I/O       | UDP `2222`           | DTLS-secured channel    |

This transformation moves EtherNet/IP from plaintext communication to authenticated and encrypted session-based exchange.

---

### 2. Security Mechanisms

### Device Authentication

CIP Security relies on **X.509 certificates** to establish device identity. Each participating node must present a valid certificate issued by a trusted authority or provisioning system before secure communication is allowed.

This reduces the feasibility of unauthorized session establishment attempts such as `RegisterSession` (`0x0065`) in environments where CIP Security is enforced.

---

### Data Integrity and Anti-Replay Protection

Secure sessions typically incorporate cryptographic integrity checks (e.g., HMAC-based verification) to ensure that messages cannot be modified or replayed without detection.

This protects explicit messaging flows and object attribute modifications from in-transit tampering.

---

### Confidentiality of Control Traffic

When encryption is enabled, payload contents—including:

* Symbolic tag names
* Object attributes
* CIP service parameters

are no longer visible in plaintext on the network. This prevents passive observation techniques such as tag enumeration or object scanning through packet capture alone.

---

## Security Characteristics

* EtherNet/IP requires strict network segmentation due to its default lack of authentication in legacy deployments.
* Explicit and implicit communication ports (`44818`, `2222`) must be controlled at the network boundary.
* Controller operating modes can restrict or reject configuration-level operations depending on implementation.
* CIP Security introduces authentication, integrity, and encryption at the protocol level using TLS/DTLS and certificate-based identity.
* Visibility into CIP traffic is significantly reduced when secure transport is enabled.

---

## Key Takeaways

* Industrial EtherNet/IP security relies on layered defense: network isolation + CIP Security.
* Legacy EtherNet/IP traffic is inherently unauthenticated and must be segmented.
* CIP Security introduces TLS/DTLS-based protection for explicit and implicit messaging.
* Device identity is enforced using X.509 certificates in secure deployments.
* Encryption removes visibility into symbolic tags and object-level traffic during passive monitoring.
