# 04 - CIP Services 0x52 / 0x53: Fragmented Tag Transfers

## Overview

CIP provides dedicated services for reading and writing data that cannot be transferred efficiently within a single explicit message. The **Read Tag Fragmented** (`0x52`) and **Write Tag Fragmented** (`0x53`) services allow clients to access large arrays or multi-element datasets by dividing the transfer into multiple fragments.

Rather than treating an array as a continuous byte stream, fragmented services maintain explicit position information so both the client and controller know which portion of the data is being transferred.

---

## Fragmented Request Structure

After the standard symbolic tag path, fragmented requests append two additional fields that describe how much data should be transferred and where the transfer should begin.

| Field         | Data Type | Description                                   |
| :------------ | :-------- | :-------------------------------------------- |
| Element Count | `uint16`  | Number of array elements requested            |
| Byte Offset   | `uint32`  | Starting byte position within the target data |

These fields extend the normal `Read Tag` and `Write Tag` request format, allowing clients to retrieve or modify data incrementally.

---

## Calculating the Byte Offset

The byte offset is determined by multiplying the desired array index by the size of each element.

[
\text{Byte Offset} = \text{Array Index} \times \text{Element Size (bytes)}
]

For example, consider a `DINT` array named `SAINT_DATA`, where each element occupies four bytes.

| Array Index | Element Size | Byte Offset  |
| :---------- | :----------- | :----------- |
| `0`         | 4 bytes      | `0x00000000` |
| `5`         | 4 bytes      | `0x00000014` |
| `10`        | 4 bytes      | `0x00000028` |

As additional fragments are requested, the client updates the byte offset to indicate where the next transfer should begin.

---

## Fragmented Response Behavior

Successful fragmented operations return dedicated response service codes.

| Request Service               | Response Service |
| :---------------------------- | :--------------- |
| `0x52` (Read Tag Fragmented)  | `0xD2`           |
| `0x53` (Write Tag Fragmented) | `0xD3`           |

The CIP General Status field indicates whether additional fragments remain.

| General Status | Meaning                                                             |
| :------------- | :------------------------------------------------------------------ |
| `0x06`         | Partial transfer completed. Additional fragments must be requested. |
| `0x00`         | Transfer completed successfully. No further fragments remain.       |

The client continues issuing requests with updated byte offsets until the controller returns a completion status.

---

## Security Characteristics

* Fragmented services enable clients to access datasets larger than those returned in a single explicit message.
* The byte offset is entirely client-controlled, making it a critical parameter during protocol analysis and fuzz testing.
* Controllers must correctly validate element counts and byte offsets to prevent invalid memory access or malformed requests from producing unexpected behavior.
* Large data transfers expose predictable request patterns that can be identified through passive network monitoring.

---

## Key Takeaways

* Services `0x52` and `0x53` support fragmented reads and writes for large CIP datasets.
* Fragmented requests extend the standard symbolic tag path with an element count and byte offset.
* The byte offset identifies the exact starting position within the target data.
* A General Status of `0x06` indicates that additional fragments remain, while `0x00` marks the completion of the transfer.
* Understanding fragmented transfers is essential when analyzing large array operations and protocol implementations.
