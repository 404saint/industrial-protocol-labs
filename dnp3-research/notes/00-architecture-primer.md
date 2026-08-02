---
title: 00-architecture-primer
tags: [Research Notes]

---

# 00: DNP3 Architectural Foundation

## 1. Introduction

DNP3 (Distributed Network Protocol 3), standardized as IEEE 1815, is one of the most widely deployed communication protocols in electric power systems, water treatment facilities, transportation infrastructure, and other industrial control environments. It was designed to provide reliable communication between SCADA masters, Remote Terminal Units (RTUs), Intelligent Electronic Devices (IEDs), and other field equipment operating across both serial and IP-based networks.

Unlike protocols such as Modbus, which primarily expose contiguous memory through register-based operations, DNP3 organizes communication around structured objects, event reporting, and layered message processing. The protocol incorporates mechanisms for fragmentation, integrity verification, unsolicited event reporting, and standardized data modeling, making it significantly more sophisticated than many legacy industrial communication protocols.

Understanding these architectural concepts is essential before examining DNP3 traffic, crafting packets, or analyzing protocol behavior. This document introduces the protocol layers, message structure, and object model that form the foundation for the remainder of this research repository.

---

# 2. Protocol Architecture

Rather than implementing the complete seven-layer OSI model, DNP3 follows a simplified communication architecture commonly referred to as the **Enhanced Performance Architecture (EPA)**. The protocol defines three primary communication layers while introducing an additional **Pseudo-Transport Layer** responsible for fragmenting and reassembling larger application messages.

```
+-------------------------------------------------------+
|                Application Layer                      |
| (Function Codes, Object Groups, Variations, IIN Bits) |
+-------------------------------------------------------+
|               Pseudo-Transport Layer                  |
|        (Segmentation, FIR/FIN Bits, Sequence #)       |
+-------------------------------------------------------+
|                   Data Link Layer                     |
|      (FT3 Framing, CRC-16 Block Checks, Addressing)   |
+-------------------------------------------------------+
|                    Physical Layer                     |
|    (RS-232/RS-485 Serial OR TCP/UDP Port 20000)       |
+-------------------------------------------------------+
```

Each layer has a distinct responsibility. The Application Layer defines protocol operations and data representation, the Pseudo-Transport Layer manages fragmentation, the Data Link Layer provides reliable frame delivery, and the Physical Layer carries the encoded frames across serial or Ethernet-based communication media.

> **Diagram Placeholder**
>
> **Type:** Layering & Encapsulation Block Diagram
>
> **Content:** Illustrate an Application Layer fragment being segmented by the Pseudo-Transport Layer, encapsulated inside FT3 Data Link frames, and transmitted over either serial or TCP/IP media.

---

# 3. Data Link Layer & FT3 Framing

The Data Link Layer is responsible for framing, addressing, and integrity verification. DNP3 uses the **Frame Transmission Format 3 (FT3)**, a frame structure designed to provide reliable communication over noisy and bandwidth-constrained links.

Every FT3 frame begins with a fixed 10-byte header followed by one or more payload blocks. To improve transmission reliability, DNP3 protects both the frame header and every 16-byte payload block with an independent **CRC-16-DNP** checksum. This allows communication errors to be detected throughout the frame rather than only after the entire payload has been received.

### Data Link Header

1. **Sync Bytes (2 Bytes)** — Always `0x05 0x64`, identifying the start of an FT3 frame.
2. **Length (1 Byte)** — Specifies the frame length excluding CRC fields.
3. **Link Control (1 Byte)** — Contains direction, primary/secondary status, frame sequencing information, and the Data Link function code.
4. **Destination Address (2 Bytes)** — Identifies the receiving device.
5. **Source Address (2 Bytes)** — Identifies the transmitting device.
6. **Header CRC (2 Bytes)** — CRC-16-DNP calculated across the first eight bytes of the frame.

The Link Control field contains several important control bits:

* **DIR** — Indicates communication direction.
* **PRM** — Distinguishes primary stations from secondary stations.
* **FCB** — Frame Count Bit used during confirmed communication.
* **FCV** — Indicates whether the Frame Count Bit is valid.
* **Function Code** — Defines Data Link operations such as Reset Link, Test Link, Acknowledge, and User Data transmission.

Although most modern deployments operate over TCP/IP, the FT3 frame structure remains unchanged. Ethernet replaces only the underlying transport medium; the Data Link format itself remains identical.

---

# 4. Pseudo-Transport Layer

The Data Link Layer cannot transport an entire application fragment within a single frame. To accommodate larger messages, DNP3 introduces a lightweight **Pseudo-Transport Layer** responsible for fragmentation and reassembly.

Each Data Link payload begins with a one-byte Transport Header that indicates whether the current frame begins or ends an application fragment while maintaining a sequence number used during reassembly.

### Transport Header

```
 Bit 7    Bit 6      Bits 5-0
+-------+--------+------------------+
|  FIR  |  FIN   | Sequence Number  |
+-------+--------+------------------+
```

* **FIR (First Fragment)** — Indicates that the frame contains the beginning of an application fragment.
* **FIN (Final Fragment)** — Indicates that the frame contains the final portion of the application fragment.
* **Sequence Number** — Six-bit counter used to maintain fragment ordering during transmission.

This layer exists solely to transport large application messages across multiple FT3 frames while presenting a complete application fragment to the layer above.

---

# 5. Application Layer

The Application Layer defines the operations performed between SCADA masters and outstations. It carries requests, responses, object headers, and protocol metadata required to read measurements, issue control commands, synchronize time, retrieve device information, and exchange diagnostic data.

Application communication consists of **Requests** transmitted by the master and **Responses** returned by the outstation.

### Application Header

```
+------------------+-------------------+-----------------+
| Application Ctrl |   Function Code   | Internal Ind.   |
|     (1 Byte)     |     (1 Byte)      | (2 Bytes - Rsp) |
+------------------+-------------------+-----------------+
```

The Application Control field contains fragment indicators, confirmation flags, unsolicited message indicators, and a four-bit application sequence number used to correlate requests and responses.

The Function Code identifies the requested operation. Common examples include:

| Function | Description  |
| -------- | ------------ |
| `0x01`   | Read         |
| `0x02`   | Write        |
| `0x03`   | Select       |
| `0x04`   | Operate      |
| `0x0D`   | Cold Restart |
| `0x18`   | Write Time   |

Responses also include a two-byte **Internal Indications (IIN)** field that communicates the operational status of the outstation.

Some commonly encountered IIN flags include:

| Flag   | Description                   |
| ------ | ----------------------------- |
| IIN1.0 | All Stations                  |
| IIN1.4 | Time Synchronization Required |
| IIN1.7 | Device Trouble                |
| IIN2.1 | Object Unknown                |
| IIN2.3 | Buffer Overflow               |

The IIN field provides immediate insight into device state and protocol processing results, making it an important source of operational and diagnostic information during protocol analysis.

---

# 6. Object Groups & Variations

One of the defining characteristics of DNP3 is its object-oriented data model. Rather than exposing raw memory locations, every piece of information is represented as a standardized object with one or more associated variations.

An **Object Group** defines the logical type of data being exchanged, while a **Variation** specifies how that data is encoded on the wire. Multiple variations may exist for the same logical object, allowing vendors to represent identical information using different serialization formats.

### Example Object Groups

| Data Type         | Object Group | Variation   | Description                          |
| ----------------- | ------------ | ----------- | ------------------------------------ |
| Binary Input      | Group 1      | Variation 1 | Packed binary input                  |
| Binary Input      | Group 1      | Variation 2 | Binary input with status flags       |
| Binary Output     | Group 10     | Variation 2 | Binary output status                 |
| Control Relay     | Group 12     | Variation 1 | Control Relay Output Block (CROB)    |
| Analog Input      | Group 30     | Variation 1 | 32-bit integer analog value          |
| Analog Input      | Group 30     | Variation 5 | IEEE 754 floating-point analog value |
| Device Attributes | Group 80     | Variation 2 | Device identification attributes     |

This object model enables devices from different vendors to exchange semantically equivalent information while supporting multiple encoding formats for the same logical data.

> **Diagram Placeholder**
>
> **Type:** Byte Breakdown / Payload Parsing Diagram
>
> **Content:** Display an Application Header followed by an Object Header, Group/Variation identifiers, Qualifier, Range fields, and the resulting payload bytes.

---

# 7. Event Classes & Unsolicited Responses

DNP3 distinguishes between **static data** and **event data** to reduce communication overhead while preserving important state changes.

Static data represents the current state of monitored points, whereas event data records changes that have occurred since the previous collection cycle.

The protocol defines four event classes:

* **Class 0** — Static data snapshot.
* **Class 1** — High-priority events.
* **Class 2** — Medium-priority events.
* **Class 3** — Low-priority events.

Rather than requiring continuous polling, DNP3 also supports **Unsolicited Responses**. When enabled, an outstation may transmit event data immediately after significant changes occur, allowing important operational events to reach the master without waiting for the next polling cycle.

This event-driven communication model reduces bandwidth consumption while improving the responsiveness of supervisory control systems.

---

# 8. Why This Architecture Matters

Every packet transmitted over DNP3 is shaped by the architectural components described in this document. Data Link framing, transport fragmentation, application processing, object representation, and event handling collectively determine how information is exchanged between masters and outstations.

The remaining documents in this repository build upon these concepts by examining packet structure, object interactions, protocol behavior, and offensive security research conducted within isolated laboratory environments. A solid understanding of the protocol architecture provides the context necessary to interpret captured traffic, construct valid messages, and analyze implementation behavior with confidence.
