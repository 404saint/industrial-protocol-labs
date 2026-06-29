# 06 - CIP Service 0x10: Set Attribute Single

## Overview

The **Set Attribute Single** service (`0x10`) modifies the value of a single attribute within a CIP object instance. Like `Get Attribute Single`, this service operates on the CIP object model by navigating a logical path composed of **Class**, **Instance**, and **Attribute** identifiers.

Rather than addressing symbolic tags, `Set Attribute Single` targets object attributes that represent device configuration, operating parameters, or other implementation-defined properties.

---

## Request Structure

A `Set Attribute Single` request consists of the service code, the encoded logical path, and the new value to be written.

The following request targets the logical path:

```text id="0m7p2a"
@1/1/2
```

which corresponds to:

* Class `0x01` (Identity Object)
* Instance `0x01`
* Attribute `0x02`

The CIP application payload is structured as follows.

| Field             | Value               | Description                               |
| :---------------- | :------------------ | :---------------------------------------- |
| Service           | `0x10`              | Set Attribute Single                      |
| Request Path Size | `0x03`              | Three 16-bit words (6 bytes) of path data |
| Logical Path      | `20 01 24 01 30 02` | Class → Instance → Attribute              |
| Attribute Data    | `01 00`             | New value written to the target attribute |

The request identifies the destination attribute through the logical path before appending the binary data to be written.

---

## Attribute Data Encoding

Unlike symbolic tag writes (`0x4D`), which include an explicit CIP data type identifier as part of the request, object attribute writes frequently rely on the data format defined by the target object's specification.

In the verified transaction, the payload contains only the raw attribute value following the logical path. The controller interprets these bytes according to the expected data type for the targeted attribute.

---

## Response Structure

A successful operation returns a **Set Attribute Single Reply** (`0x90`), which is the request service (`0x10`) with the response bit (`0x80`) applied.

```text id="vq3n8h"
+-----------------------------------------------------------+
| EtherNet/IP Encapsulation Header                          |
|   Command        : 0x006F (SendRRData)                    |
+-----------------------------------------------------------+
| Common Packet Format (CPF)                                |
|   Item Type      : 0x00B2 (Unconnected Data Item)         |
+-----------------------------------------------------------+
| CIP Application Payload                                   |
|   Service Reply : 0x90                                   |
|   General Status: 0x00 (Success)                          |
+-----------------------------------------------------------+
```

A successful response confirms that the target object accepted and processed the requested attribute modification.

---

## Security Characteristics

* Object attributes are modified through logical Class, Instance, and Attribute identifiers rather than symbolic tag names.
* The interpretation of the supplied data depends on the definition of the targeted object attribute.
* Incorrect attribute values or malformed requests may result in CIP error responses or rejected write operations.
* Because object attributes often expose configuration parameters, unauthorized use of `Set Attribute Single` can alter device behavior if write access is not restricted.

---

## Key Takeaways

* Service `0x10` writes a single attribute within a CIP object.
* Requests consist of a service code, logical object path, and attribute data.
* The path `@1/1/2` resolves to Class 1, Instance 1, Attribute 2.
* Successful operations return a `0x90` service reply with a General Status of `0x00`.
* Understanding logical object addressing is essential for interacting with standard CIP objects beyond symbolic tag operations.
