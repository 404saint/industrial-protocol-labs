# 03 - CIP Service 0x4D: Write Tag Single

## Overview

The **Write Tag Single** service (`0x4D`) allows a client to modify the value of a symbolic tag through explicit CIP messaging. Rather than writing to a fixed memory offset, the request identifies the target variable by its symbolic name and supplies both the data type and the new value.

A successful write request contains three primary components:

* The CIP service header
* The symbolic path identifying the target tag
* The data type and value to be written

---

## CIP Request Structure

Write requests are transported inside an EtherNet/IP `SendRRData` packet and typically encapsulated within an **Unconnected Data Item** (`0x00B2`). The CIP payload specifies both the target tag and the value to be written.

### Service Header

| Field             | Value    | Description                                                   |
| :---------------- | :------- | :------------------------------------------------------------ |
| Service Code      | `0x4D`   | Write Tag Single                                              |
| Request Path Size | Variable | Length of the symbolic request path, measured in 16-bit words |

---

## Symbolic Tag Path

CIP identifies controller variables using an ANSI Extended Symbolic Segment rather than numerical register addresses.

| Field           | Value                           | Description                                     |
| :-------------- | :------------------------------ | :---------------------------------------------- |
| Segment Type    | `0x91`                          | ANSI Extended Symbolic Segment                  |
| Length          | `0x0A`                          | Length of the tag name (`SAINT_DATA`)           |
| Symbolic Name   | `53 41 49 4E 54 5F 44 41 54 41` | ASCII representation of `SAINT_DATA`            |
| Element Segment | `28 00`                         | References element `0` within the target object |

This symbolic addressing mechanism allows controllers to expose variables by name instead of fixed memory locations.

---

## Data Type and Value Encoding

Before transmitting the new value, the client specifies the CIP data type to ensure the controller interprets the payload correctly.

| CIP Type | Data Type | Size   | Example Encoding (Value = 1337) |
| :------- | :-------- | :----- | :------------------------------ |
| `0xC2`   | SINT      | 8-bit  | `39`                            |
| `0xC3`   | INT       | 16-bit | `39 05`                         |
| `0xC4`   | DINT      | 32-bit | `39 05 00 00`                   |

The data type identifier immediately precedes the encoded value within the CIP payload.

---

## Successful Response

A successful write operation returns a **Write Tag Reply** with the service response bit set.

```text id="tzr81m"
+-----------------------------------------------------------+
| EtherNet/IP Encapsulation Header                          |
|   Command        : 0x006F (SendRRData)                    |
|   Session Handle : Active Session                         |
+-----------------------------------------------------------+
| Common Packet Format (CPF)                                |
|   Item Type      : 0x00B2 (Unconnected Data Item)         |
+-----------------------------------------------------------+
| CIP Application Payload                                   |
|   Service Reply : 0xCD                                   |
|   General Status: 0x00 (Success)                          |
+-----------------------------------------------------------+
```

A service reply of `0xCD` indicates that the controller successfully processed the `0x4D` write request and committed the requested modification.

---

## Security Characteristics

* CIP write operations modify controller variables by symbolic tag name rather than fixed memory addresses.
* Every write request explicitly declares the expected data type, reducing ambiguity when interpreting application data.
* A successful response confirms that the controller accepted and processed the requested modification.
* Any client capable of issuing valid `Write Tag Single` requests can modify writable controller variables unless additional authentication or network-level protections are in place.

---

## Key Takeaways

* Service `0x4D` performs explicit writes to a single symbolic tag.
* A write request consists of a service header, symbolic tag path, data type identifier, and encoded value.
* CIP uses ANSI symbolic segments to identify controller variables by name.
* The data type identifier is required so the controller correctly interprets the incoming value.
* A successful operation returns a `0xCD` service reply with a general status of `0x00`.
