# BACnet Protocol Architecture & Object Database Model

## Executive Summary

Building Automation and Control Networks (BACnet) differ fundamentally from traditional Industrial Control System (ICS) protocols such as Modbus and DNP3. Instead of exposing memory addresses or register maps, BACnet presents devices as distributed, object-oriented databases. Every controller maintains a collection of standardized objects that describe physical equipment, logical control points, configuration data, and device metadata.

This architectural model changes how clients interact with a controller. Rather than reading or writing fixed memory locations, applications request properties from named objects through standardized services. As a result, understanding BACnet requires thinking in terms of objects, properties, and application services rather than registers and function codes.

This document establishes the architectural foundation for the remainder of this research series. It introduces the BACnet object model, explains how BACnet/IP packets are encapsulated on the wire, examines the command arbitration mechanism implemented through Priority Arrays, and concludes with the routing infrastructure that enables communication across multiple IP subnets.

---

## 1. Object-Oriented Abstraction Model

Every BACnet-compliant controller operates as an application server exposing a standardized collection of **Objects**. Each object represents either a physical device, a software variable, or an administrative component within the controller. Rather than exposing raw memory, the controller publishes information through these structured objects, allowing clients to interact with equipment using standardized application services.

Each object contains a predefined set of **Properties** describing its current state, configuration, capabilities, and operational limits. These properties form the primary interface between BACnet clients and field devices, making the object database the central component of the protocol's design.

## 1.1 Object Structure and Identifiers

Every object is uniquely identified by its **Object Identifier**, a 32-bit value divided into two fields:

* **10-bit Object Type** identifying the class of object.
* **22-bit Instance Number**, allowing up to **4,194,303** unique instances for each object type.

Individual properties are referenced using standardized numeric identifiers. For example:

* `Present_Value` → Property Identifier **85**
* `Object_Name` → Property Identifier **77**

This standardized property model allows BACnet clients from different vendors to query and manipulate compatible devices without relying on vendor-specific memory layouts.



*`[DIAGRAM PLACEHOLDER: BACnet Object Hierarchy Tree]`*

> Figure 1. Simplified representation of a BACnet Device object exposing multiple standardized object instances. In practice, a single device may contain hundreds or thousands of objects, each uniquely identified by an (Object Type, Instance Number) pair and accessed through standardized BACnet application services.

### 1.2 Core Object Types

Although ANSI/ASHRAE Standard 135 defines dozens of standardized object types, only a relatively small subset appears consistently during typical building automation operations. These objects form the primary focus of this research series because they represent the majority of operational telemetry and control traffic observed during normal network activity.

| Object Type                  | Type Enumerator | Functional Role                                   | Critical Properties                                                          |
| ---------------------------- | --------------- | ------------------------------------------------- | ---------------------------------------------------------------------------- |
| **Device**                   | `8`             | Root container describing the controller itself.  | `Object_List`, `Vendor_Identifier`, `Firmware_Revision`, `Database_Revision` |
| **Analog Input (AI)**        | `0`             | Physical sensor measurements.                     | `Present_Value`, `Status_Flags`, `Event_State`, `Units`                      |
| **Analog Output (AO)**       | `1`             | Analog actuator outputs such as VFDs.             | `Present_Value`, `Priority_Array`, `Relinquish_Default`                      |
| **Analog Value (AV)**        | `2`             | Internal software variables and setpoints.        | `Present_Value`, `Priority_Array`, `Relinquish_Default`                      |
| **Binary Input (BI)**        | `3`             | Discrete status inputs.                           | `Present_Value`, `Status_Flags`, `Polarity`                                  |
| **Binary Output (BO)**       | `4`             | Relay or contactor control points.                | `Present_Value`, `Priority_Array`, `Relinquish_Default`                      |
| **Multi-State Output (MSO)** | `14`            | Multi-position devices such as dampers or valves. | `Present_Value`, `Priority_Array`, `Number_Of_States`                        |

---

## 2. Wire-Level Encapsulation

BACnet/IP transports application traffic over **UDP port 47808 (`0xBAC0`)** using a layered encapsulation model. Each transmitted packet consists of four nested protocol layers:

> **UDP → BVLC → NPDU → APDU**

Unlike Modbus TCP or EtherNet/IP, BACnet introduces additional network-layer processing through the **BACnet Virtual Link Control (BVLC)** and **Network Protocol Data Unit (NPDU)** headers. These layers provide routing capabilities, broadcast management, and media-independent communication while preserving a consistent application interface.



*`[DIAGRAM PLACEHOLDER: BACnet/IP Packet Frame Breakdown]`*

> Figure 2. BACnet/IP encapsulation hierarchy. Application services are transported within an APDU, encapsulated by the BACnet Network Protocol Data Unit (NPDU) and BACnet Virtual Link Control (BVLC) headers before transmission over UDP port 47808 (0xBAC0). Optional NPDU routing fields are present only when packets traverse BACnet internetworks.

### 2.1 BACnet Virtual Link Control (BVLC)

The BVLC header provides IP-specific transport functions while allowing the higher BACnet layers to remain independent of the underlying network technology.

The first octet (`0x81`) identifies the packet as BACnet/IP, while the Function field determines how the frame should be processed.

Common function values include:

* `0x0A` : **Original-Unicast-NPDU**
* `0x0B` : **Original-Broadcast-NPDU**
* `0x04` : **Forwarded-NPDU**
* `0x05` : **Register-Foreign-Device**

These functions become particularly important when examining broadcast forwarding and Foreign Device Registration later in this document.

---

### 2.2 Network Protocol Data Unit (NPDU)

The NPDU provides logical network routing between different BACnet media, including BACnet/IP, BACnet MS/TP, BACnet Ethernet, and other supported transport technologies.

Its Control octet determines whether routing information accompanies the application payload.

Key control bits include:

* **Bit 5** : Destination specification (`DNET`, `DLEN`, `DADR`)
* **Bit 3** : Source specification (`SNET`, `SLEN`, `SADR`)
* **Bit 2** : Expecting Reply

When routing information is present, BACnet routers use these fields to forward traffic across heterogeneous BACnet networks without modifying the application payload itself.

---

### 2.3 Application Protocol Data Unit (APDU)

The APDU carries the actual BACnet application services used to discover devices, retrieve properties, modify object state, and exchange operational data.

The upper nibble of the first byte specifies the APDU type, defining how the receiving device should interpret the remainder of the payload.

Common APDU types include:

* `0x0` : Confirmed Request
* `0x1` : Unconfirmed Request
* `0x2` : Simple ACK
* `0x3` : Complex ACK
* `0x5` : Error

Most services examined throughout this research, including `Who-Is`, `I-Am`, `ReadProperty`, `ReadPropertyMultiple`, and `WriteProperty`, are transported within these APDUs.

---

## 3. Command Arbitration: Priority Arrays

Unlike many industrial protocols where a write operation immediately replaces the existing value, BACnet introduces a command arbitration mechanism through the **Priority Array**.

Every commandable object maintains sixteen independent priority slots. Instead of overwriting the current output directly, write operations populate one of these slots. The controller continuously evaluates the array and selects the highest-priority non-NULL value as the effective output state.

This design allows multiple independent systems, including schedules, operator workstations, supervisory controllers, and life-safety applications to issue commands without permanently overwriting one another.

 `[DIAGRAM PLACEHOLDER: BACnet Priority Array Evaluation Process]`

> Figure 3. Flow diagram illustrating BACnet's 16-slot Priority Array evaluation process. Multiple write requests populate independent priority slots within a commandable object. During evaluation, the controller scans the array sequentially from Priority 1 (highest precedence) to Priority 16 (lowest precedence), selecting the first non-NULL value as the object's effective Present_Value. If every priority slot contains NULL, the controller assigns the value stored in the Relinquish_Default property.

### 3.1 Priority Evaluation Rules

Priority resolution follows three straightforward rules:

1. The highest-priority non-NULL slot determines the active `Present_Value`.
2. Releasing control requires writing the BACnet `NULL` data type back to the same priority slot.
3. If every slot contains `NULL`, the controller restores the value stored in `Relinquish_Default`.

This mechanism is one of BACnet's defining characteristics and frequently appears during operational analysis, incident response, and security assessments because understanding *which* priority currently owns an output often explains seemingly inconsistent actuator behavior.

### 3.2 Standard Priority Assignments


| Priority Level | Standard Application | Operational Context |
| --- | --- | --- |
| **1** | Manual-Life Safety | High-priority manual emergency overrides (e.g., smoke purge). |
| **2** | Automatic-Life Safety | Automated safety trips and interlocks. |
| **3–5** | Available / Reserved | High-priority application and critical equipment control. |
| **6** | Minimum On/Off Time | Hardware safety loops enforcing equipment run-time protections. |
| **7** | Available | General application logic. |
| **8** | Manual Operator | Standard entry slot for HMI manual overrides and operator commands. |
| **9–15** | Available / Calculations | Automated control loop algorithms and secondary routines. |
| **16** | Scheduled | Default entry slot for daily operational schedules. |

---

## 4. Subnet Traversal and Broadcast Infrastructure

BACnet relies heavily on broadcast messaging for device discovery and network initialization. Services such as `Who-Is` and `I-Am` assume that devices sharing a broadcast domain can communicate without prior knowledge of one another.

Since conventional IP routers do not forward broadcast traffic, BACnet introduces two complementary mechanisms that preserve this discovery model across multiple routed networks: **BACnet Broadcast Management Devices (BBMDs)** and **Foreign Device Registration (FDR).**

### 4.1 BACnet Broadcast Management Device (BBMD)

A BBMD extends BACnet broadcasts beyond a single IP subnet.

When a local device transmits an `Original-Broadcast-NPDU`, the BBMD receives the frame, encapsulates it as a `Forwarded-NPDU`, and unicasts it to peer BBMDs listed in its Broadcast Distribution Table (BDT). Each receiving BBMD then recreates the broadcast on its local subnet, allowing discovery traffic to propagate throughout the BACnet internetwork while traversing conventional IP routers.

### 4.2 Foreign Device Registration (FDR)

Foreign Device Registration provides an alternative mechanism for endpoints located outside a BACnet broadcast domain.

Rather than deploying a local BBMD, the remote device registers directly with an existing BBMD using a `Register-Foreign-Device` request that includes a lease duration (TTL). Upon successful registration, the BBMD records the client in its Foreign Device Table (FDT) and forwards broadcast traffic to that endpoint via unicast for the lifetime of the registration.

This approach is commonly used by engineering workstations, supervisory servers, and remote management systems that require participation in BACnet discovery traffic without residing on the local subnet.

---

## Security Characteristics

From a protocol analysis perspective, BACnet's object-oriented architecture introduces a substantially different attack surface than register-based industrial protocols. Enumerating objects, reading properties, and understanding Priority Array ownership often reveals significantly more operational context than simply identifying open network services. Likewise, the protocol's reliance on broadcast discovery and cross-subnet forwarding mechanisms means that network architecture plays a central role in both system visibility and security.

Establishing a solid understanding of the object database, packet encapsulation layers, and routing infrastructure provides the foundation required for the protocol analysis performed throughout the remainder of this research series.


