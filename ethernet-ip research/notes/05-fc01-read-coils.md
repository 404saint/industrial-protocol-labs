# 05 - CIP Service 0x0E: Get Attribute Single

## Overview

The **Get Attribute Single** service (`0x0E`) retrieves the value of a single attribute from a CIP object instance. Unlike symbolic tag services, which identify variables by name, this service navigates the CIP object model using a logical path composed of **Class**, **Instance**, and **Attribute** identifiers.

Many standard EtherNet/IP functions—including device identification, status reporting, and configuration queries—rely on this object-oriented addressing model.

---

## Logical Path Encoding

A `Get Attribute Single` request specifies the target object by encoding a logical path rather than a symbolic tag.

For example, the path:

```text
@1/1/1
```

identifies:

* **Class 1** (Identity Object)
* **Instance 1**
* **Attribute 1** (Vendor ID)

This path is encoded using CIP Logical Segments.

| Bytes   | Segment           | Description                    |
| :------ | :---------------- | :----------------------------- |
| `20 01` | Class Segment     | Class `0x01` (Identity Object) |
| `24 01` | Instance Segment  | Instance `0x01`                |
| `30 01` | Attribute Segment | Attribute `0x01` (Vendor ID)   |

Each logical segment identifies one level of the CIP object hierarchy.

---

## Request Structure

A standard `Get Attribute Single` request consists of the service code followed by the encoded logical path.

| Field             | Value               | Description                               |
| :---------------- | :------------------ | :---------------------------------------- |
| Service           | `0x0E`              | Get Attribute Single                      |
| Request Path Size | `0x03`              | Three 16-bit words (6 bytes) of path data |
| Path              | `20 01 24 01 30 01` | Class → Instance → Attribute              |

Unlike symbolic tag requests, no ANSI Symbolic Segment (`0x91`) is used because the target is identified entirely through object identifiers.

---

## Response Structure

A successful request returns a **Get Attribute Single Reply** (`0x8E`), which is the original service code with the response bit (`0x80`) applied.

The response contains:

| Field             | Description                                             |
| :---------------- | :------------------------------------------------------ |
| Service Reply     | `0x8E`                                                  |
| General Status    | `0x00` (Success)                                        |
| Additional Status | Present only when required                              |
| Attribute Data    | Native binary representation of the requested attribute |

Unlike symbolic tag services, object attribute responses frequently return only the attribute value itself. The client is expected to understand the data type and layout defined by the CIP object specification for the requested attribute.

---

## Security Characteristics

* Object attributes are addressed through logical object identifiers rather than symbolic tag names.
* Standard CIP objects expose device identity, status, and configuration information through well-defined Class, Instance, and Attribute paths.
* Successful responses often contain raw attribute data without accompanying type metadata, requiring the client to interpret the value according to the object specification.
* Because many object attributes are readable without modifying controller state, `Get Attribute Single` is frequently used during device discovery, fingerprinting, and passive reconnaissance.

---

## Key Takeaways

* Service `0x0E` retrieves a single attribute from a CIP object.
* Requests use logical path segments (`Class → Instance → Attribute`) instead of symbolic tag names.
* The path `@1/1/1` resolves to Class 1, Instance 1, Attribute 1.
* Successful responses return a service code of `0x8E` with the requested attribute encoded in its native binary format.
* Understanding logical path encoding is fundamental to interacting with standard CIP objects and performing protocol analysis.
