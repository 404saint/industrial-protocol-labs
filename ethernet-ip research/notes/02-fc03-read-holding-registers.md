# 02 - CIP Service 0x4C: Read Tag Single

## Overview

The **Read Tag Single** service (`0x4C`) is one of the most commonly used explicit messaging services in the Common Industrial Protocol (CIP). It allows a client to read the value of a single symbolic tag by name rather than accessing memory through fixed register offsets.

Unlike protocols such as Modbus, where data is addressed numerically, CIP uses symbolic identifiers that reference controller variables directly. A successful read returns the requested tag's data type and current value within the CIP application payload.

---

## Response Structure

The following packet was captured during a successful read request for the symbolic tag `SAINT_DATA`. The response consists of three distinct protocol layers:

1. EtherNet/IP Encapsulation Header
2. Common Packet Format (CPF)
3. CIP Application Data

---

## EtherNet/IP Encapsulation Header (24 Bytes)

| Bytes | Field          | Value                | Description                           |
| :---- | :------------- | :------------------- | :------------------------------------ |
| 00–01 | Command        | `0x006F`             | `SendRRData` response                 |
| 02–03 | Length         | `0x0018`             | Payload length (24 bytes)             |
| 04–07 | Session Handle | `0x6ddc0969`         | Active EtherNet/IP session identifier |
| 08–11 | Status         | `0x00000000`         | Request completed successfully        |
| 12–19 | Sender Context | `0x0000000000000000` | Client tracking context               |
| 20–23 | Options Flags  | `0x00000000`         | Reserved                              |

---

## Common Packet Format (CPF)

The EtherNet/IP payload encapsulates CIP data using the Common Packet Format (CPF).

| Field             | Value                          | Description                                      |
| :---------------- | :----------------------------- | :----------------------------------------------- |
| Interface Handle  | `0x00000000`                   | CIP interface identifier                         |
| Item Count        | `2`                            | Two CPF items follow                             |
| Null Address Item | Type `0x0000`, Length `0x0000` | Indicates an unconnected explicit message        |
| Data Item         | Type `0x00B2`                  | Unconnected Data Item containing the CIP payload |
| Data Length       | `0x0008`                       | Eight bytes of application-layer data            |

---

## CIP Application Payload

The captured CIP payload contains the service response, execution status, returned data type, and tag value.

| Field                  | Value        | Description                                   |
| :--------------------- | :----------- | :-------------------------------------------- |
| Service Reply          | `0xD2`       | Response service code observed during testing |
| General Status         | `0x00`       | Success                                       |
| Additional Status Size | `0x00`       | No additional status words                    |
| Data Type              | `0x00C3`     | CIP `DINT` (32-bit signed integer)            |
| Tag Value              | `0x00000000` | Current value of `SAINT_DATA`                 |

During testing, the first byte of the CIP payload was observed as `0xD2`. While a standard response to Service `0x4C` typically sets the response bit (`0x80`) to produce `0xCC`, the simulator (`cpppo`) returned `0xD2` for this transaction. This suggests that the response is wrapped or encoded differently by the simulator's implementation and warrants additional protocol investigation.

---

## Empirical Verification

The following hexadecimal sequence was captured directly from the successful response.

```text
6f 00 18 00 69 09 dc 6d 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 08 00 02 00 00 00 00 00
b2 00 08 00 d2 00 00 00 c3 00 00 00
```

The packet decodes cleanly into the EtherNet/IP encapsulation header, the Common Packet Format wrapper, and an 8-byte CIP application payload containing the service response, status, data type, and returned tag value.

---

## Security Characteristics

* CIP explicit messaging addresses controller variables by symbolic tag name rather than fixed memory offsets.
* Successful read operations disclose both the tag's current value and its underlying CIP data type.
* EtherNet/IP encapsulates CIP messages inside the Common Packet Format, providing a consistent transport structure for explicit messaging.
* Differences between simulator behavior and protocol expectations, such as the observed `0xD2` service reply, should be validated against physical devices before drawing protocol-level conclusions.

---

## Key Takeaways

* Service `0x4C` is used to read the value of a single symbolic tag.
* A successful response is composed of three protocol layers: the EtherNet/IP encapsulation header, the Common Packet Format wrapper, and the CIP application payload.
* The returned application payload includes the service response, execution status, data type, and tag value.
* The observed response contained a `DINT` (`0x00C3`) with a value of `0x00000000`.
* Simulator-specific protocol behavior should be distinguished from EtherNet/IP specification behavior during protocol analysis.
