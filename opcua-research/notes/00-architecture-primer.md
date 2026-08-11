# OPC UA Architecture & Protocol Specification Primer

## Executive Summary

Open Platform Communications Unified Architecture (OPC UA), standardized as **IEC 62541**, represents a major architectural shift from the register- and object-oriented protocols examined earlier in this research series. Rather than exposing process data through fixed memory addresses or predefined object properties, OPC UA represents industrial systems as a **typed object graph** composed of Nodes and References.

This information model allows an OPC UA server to represent not only process values, but also the relationships, metadata, types, and functionality associated with those values. A client can therefore interact with an industrial system through a standardized model rather than relying exclusively on vendor-specific memory maps.

OPC UA also separates communication into distinct architectural layers. The `opc.tcp` mapping provides binary communication over TCP, while the SecureChannel and Session abstractions establish the security and application context in which OPC UA services operate.

This document establishes the architectural baseline for the research that follows. It introduces the OPC UA information model, the `opc.tcp` protocol stack and message structure, and the relationship between SecureChannels, Sessions, SecurityPolicies, and Message Security Modes.

---

## 1. Information Model & Object-Oriented Architecture

The architectural progression examined throughout this research series can be summarized as:

```text
Modbus
  │
  │  Flat registers and coils
  ▼
DNP3
  │
  │  Typed Groups / Variations / Objects
  ▼
BACnet
  │
  │  Objects / Properties
  ▼
OPC UA
  │
  │  Nodes / References / Types
  ▼
Typed Information Graph
```

The key difference is that OPC UA does not treat the device primarily as a collection of addresses or isolated objects. It exposes an **Address Space** representing the system as a connected information model.

A simplified example might look like:

```text
                         Pump_01
                            │
             ┌──────────────┼──────────────┐
             │              │              │
       HasComponent    HasComponent   HasTypeDefinition
             │              │              │
          FlowRate      Temperature      PumpType
             │
        HasProperty
             │
      EngineeringUnits
```

The graph describes both the entities within the system and the relationships between them.

This distinction becomes important when analyzing OPC UA because discovering a server can reveal considerably more than individual process values. The information model itself may describe equipment, variables, types, metadata, and available functionality.

---

### 1.1 Address Space, Nodes & References

The **Address Space** is the collection of Nodes exposed by an OPC UA Server.

A Node represents an entity within the information model. Depending on its NodeClass, it can represent physical equipment, process data, methods, types, organizational structures, or other elements of the model.

Common NodeClasses include:

* `Object`
* `Variable`
* `Method`
* `ObjectType`
* `VariableType`
* `DataType`
* `ReferenceType`
* `View`

Nodes contain defined attributes describing them, while **References** establish relationships between Nodes.

For example:

```text
Pump_01
   │
   ├── HasComponent ──> Temperature
   │
   ├── HasComponent ──> Pressure
   │
   └── HasTypeDefinition ──> PumpType
```

References therefore provide semantic context that would not exist in a simple address/value model.

A `Variable` may represent a process value such as temperature or pressure. A `Method` may represent executable functionality. An `Object` can provide structure around related components.

The combination of Nodes and References forms the core of the OPC UA information model.

---

### 1.2 NodeIds & Namespaces

Every Node is identified by a **NodeId**.

A NodeId combines a namespace identifier with an identifier value.

For example:

```text
ns=0;i=85
```

or:

```text
ns=2;s=Line1.Pump01.Temperature
```

The namespace identifies the namespace in which the Node is defined, while the identifier uniquely identifies the Node within that namespace.

OPC UA supports several identifier forms:

| Identifier Type | Example                     |
| --------------- | --------------------------- |
| **Numeric**     | `ns=0;i=85`                 |
| **String**      | `ns=2;s=Pump01.Temperature` |
| **GUID**        | `ns=2;g=<GUID>`             |
| **Opaque**      | `ns=2;b=<ByteString>`       |

Namespace `0` contains standardized OPC UA definitions, while application-specific information models commonly use additional namespaces.

The NodeId therefore provides the addressing mechanism for the information model, while the Node's attributes and References provide its meaning.

---

## 2. OPC UA Protocol Stack & Wire Architecture

OPC UA separates its abstract services from the underlying network transport. Several mappings exist, including HTTPS and WebSockets, but the primary transport examined in this research is the binary `opc.tcp` mapping over TCP.

A simplified protocol stack is:

```text
+-----------------------------------------------+
|              OPC UA Services                  |
|        Read / Write / Browse / Call           |
+-----------------------------------------------+
|                Session                       |
|       Authentication / Session State          |
+-----------------------------------------------+
|             SecureChannel                    |
|     Security / Message Protection             |
+-----------------------------------------------+
|            OPC UA Connection                  |
|                 HEL / ACK                     |
+-----------------------------------------------+
|                    TCP                        |
+-----------------------------------------------+
```

Each layer has a distinct responsibility.

The connection layer establishes the OPC UA transport parameters. The SecureChannel establishes the cryptographic communication context. The Session establishes the logical interaction between client and server. OPC UA services then operate within that established context.

---

### 2.1 `opc.tcp`

The `opc.tcp` mapping transports OPC UA binary messages directly over TCP.

The conventional endpoint format is:

```text
opc.tcp://<hostname>:<port>
```

Port `4840` is commonly used for OPC UA TCP services, although deployments may configure alternative ports.

The transport is message-oriented even though TCP provides the underlying byte stream. OPC UA therefore defines its own framing structure so that individual messages and message chunks can be identified within the TCP connection.

---

### 2.2 Message Framing

Each `opc.tcp` message begins with an 8-byte header:

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Message Type  | Chunk Type |          Message Size           |
|    3 Bytes    |  1 Byte    |             4 Bytes             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|                       Message Body                            |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

The first three bytes identify the message type.

The fourth byte identifies the chunk type:

```text
F = Final
C = Continuation
A = Abort
```

The following four bytes specify the total message size, including the header.

This framing allows larger OPC UA messages to be divided into multiple chunks while preserving message boundaries within the TCP stream.

---

### 2.3 OPC UA Message Types

Several message types form the basic `opc.tcp` communication lifecycle:

| Message | Purpose                                           |
| ------- | ------------------------------------------------- |
| `HEL`   | Initiates the OPC UA TCP connection               |
| `ACK`   | Acknowledges and negotiates connection parameters |
| `OPN`   | Opens a SecureChannel                             |
| `MSG`   | Carries secured OPC UA service messages           |
| `CLO`   | Closes the SecureChannel                          |
| `ERR`   | Reports connection-level errors                   |

At a high level, communication progresses from transport establishment into SecureChannel establishment and then into normal service communication.

```text
Client                                      Server
  │                                           │
  │--------------- HEL ---------------------> │
  │<-------------- ACK ---------------------- │
  │                                           │
  │--------------- OPN ---------------------> │
  │<-------------- OPN ---------------------- │
  │                                           │
  │--------------- MSG ---------------------> │
  │<-------------- MSG ---------------------- │
  │                                           │
```

The contents of these messages and their cryptographic properties become relevant during the subsequent protocol analysis phases.

---

### 2.4 Binary Encoding

OPC UA defines **UA Binary** as a compact binary encoding for its structured data.

The encoding uses predefined representations for primitive and structured values rather than transmitting human-readable field names.

At a conceptual level:

```text
OPC UA Message
      │
      ▼
Structured Service Data
      │
      ▼
UA Binary Encoding
      │
      ▼
opc.tcp Message
```

Primitive values use defined binary representations, while more complex OPC UA structures are serialized according to their type definitions.

This encoding is important when interpreting raw packet captures because OPC UA application data is not directly represented as readable text or JSON. The byte stream must be interpreted according to the relevant OPC UA structure.

Detailed binary structures are examined where necessary during the later packet-level research rather than being reproduced here as a complete encoding reference.

---

## 3. SecureChannel & Session Architecture

OPC UA separates application communication security from logical application interaction.

The relationship can be summarized as:

```text
+------------------------------------------+
|                  Session                 |
|                                          |
|       User Identity / Session State      |
+------------------------------------------+
                     │
                     ▼
+------------------------------------------+
|              SecureChannel               |
|                                          |
| Application Identity / Message Security  |
+------------------------------------------+
                     │
                     ▼
+------------------------------------------+
|                    TCP                   |
+------------------------------------------+
```

This separation is one of the most important concepts required for understanding OPC UA security.

---

### 3.1 SecureChannel

The **SecureChannel** establishes a security context between OPC UA application instances.

It is responsible for mechanisms associated with:

* Application authentication
* Message integrity
* Message confidentiality
* Security tokens
* Cryptographic key establishment

Application identity is associated with X.509 application instance certificates.

The exact cryptographic mechanisms depend on the selected SecurityPolicy.

The SecureChannel is established through the `OPN` message exchange and subsequently protects normal OPC UA message traffic according to the negotiated security configuration.

---

### 3.2 Session

The **Session** represents the logical interaction between an OPC UA Client and Server.

A simplified lifecycle is:

```text
CreateSession
      │
      ▼
ActivateSession
      │
      ▼
Service Requests
```

The Session carries application-level state and user identity information.

Depending on server configuration, user authentication can involve mechanisms such as:

* Anonymous
* Username / Password
* X.509 user certificates

The important distinction is:

```text
Application Identity
        ≠
User Identity
```

The SecureChannel establishes the protected communication relationship between application instances, while the Session establishes the logical context under which services are invoked.

---

### 3.3 Security Policies & Message Modes

OPC UA endpoints advertise the security configurations available to clients.

Two concepts are particularly important:

**SecurityPolicy** defines the cryptographic algorithms and mechanisms used by the communication security configuration.

**Message Security Mode** determines how messages are protected.

The principal modes are:

| Mode               | Protection                                             |
| ------------------ | ------------------------------------------------------ |
| **None**           | No message-level signing or encryption                 |
| **Sign**           | Message integrity and authentication                   |
| **SignAndEncrypt** | Message integrity, authentication, and confidentiality |

SecurityPolicies have evolved over multiple generations. Legacy policies such as `Basic128Rsa15` and `Basic256` are deprecated, while newer policies provide stronger cryptographic constructions.

The important architectural point is that **SecurityPolicy and MessageSecurityMode work together** to determine how the SecureChannel protects OPC UA messages.

An endpoint therefore exposes more than an address. Its configuration can indicate:

```text
Endpoint URL
SecurityPolicy
MessageSecurityMode
Server Certificate
User Token Policies
```

These parameters establish the security context in which a client can communicate with the server.

---

## Security Characteristics

OPC UA's security architecture is closely integrated with its information model and communication stack.

The protocol provides distinct mechanisms for:

* Application identity
* Message integrity
* Message confidentiality
* User authentication
* Session management
* Access control

At the same time, the protocol's rich information model creates a larger semantic surface than simpler register-oriented protocols.

A BACnet client may discover objects and properties. An OPC UA client can encounter an interconnected model containing:

```text
Objects
  ↓
Variables
  ↓
Types
  ↓
References
  ↓
Methods
  ↓
Metadata
```

This makes the security posture of an OPC UA deployment dependent not only on cryptographic configuration, but also on what information and functionality the server exposes and which identities are permitted to interact with it.

For the research that follows, this architecture establishes four foundational areas:

```text
Endpoint Configuration
        ↓
SecureChannel / Session
        ↓
Address Space
        ↓
Security Boundaries
```

These correspond directly to the subsequent investigation of endpoint exposure, channel and session behavior, information-model traversal, and security-boundary enforcement.
