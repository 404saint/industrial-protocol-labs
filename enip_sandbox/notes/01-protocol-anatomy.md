# 01 - EtherNet/IP Encapsulation Header Anatomy

## Overview

EtherNet/IP (ENIP) transports Common Industrial Protocol (CIP) messages over standard TCP/IP networks using an encapsulation layer defined by the ODVA specification. Before a client can exchange CIP messages, it must establish an EtherNet/IP session by issuing a `RegisterSession` request.

Every encapsulation packet begins with a fixed **24-byte header** encoded in **little-endian** format. Understanding this structure is fundamental for constructing raw EtherNet/IP packets, parsing responses, and analyzing protocol behavior at the byte level.

---

## Encapsulation Header Layout

The following header layout was verified by transmitting a handcrafted `RegisterSession` request and decoding the response received from the target.

| Byte Offset | Field                 | Data Type | Verified Value     | Description                                                                       |
| :---------- | :-------------------- | :-------- | :----------------- | :-------------------------------------------------------------------------------- |
| **00–01**   | Encapsulation Command | `uint16`  | `0x0065`           | Identifies the requested encapsulation command (`RegisterSession`).               |
| **02–03**   | Length                | `uint16`  | `0x0004`           | Length of the payload immediately following the 24-byte header.                   |
| **04–07**   | Session Handle        | `uint32`  | `0xc5e86a69`       | Session identifier allocated by the target PLC or simulator.                      |
| **08–11**   | Status                | `uint32`  | `0x00000000`       | Indicates the result of the request (`0x00000000` = Success).                     |
| **12–19**   | Sender Context        | `char[8]` | `5341494e54343034` | User-defined context echoed back by the target (`SAINT404`).                      |
| **20–23**   | Options Flags         | `uint32`  | `0x00000000`       | Reserved protocol options. Standard implementations leave this field set to zero. |

---

## RegisterSession Payload

Immediately following the encapsulation header is a 4-byte payload specific to the `RegisterSession` command.

| Field            | Data Type | Value    |
| :--------------- | :-------- | :------- |
| Protocol Version | `uint16`  | `0x0001` |
| Options Flags    | `uint16`  | `0x0000` |

The protocol version must be set to `1`, while the options field is reserved and normally remains zero.

---

## Empirical Verification

The header layout was validated by sending a raw TCP `RegisterSession` request and decoding the returned packet directly from the captured byte stream.

```text
Bytes 00-01 (Command)        : 0x65 (Expected: 0x65)
Bytes 02-03 (Length)         : 4 bytes (Expected: 4)
Bytes 04-07 (Session Handle) : 0xc5e86a69 (Allocated by PLC)
Bytes 08-11 (Status)         : 0x0 (Success)
Bytes 12-19 (Sender Context) : SAINT404 (Echoed back)
Bytes 20-23 (Options Flags)  : 0x0
------------------------------------------------------------
Trailing Data Payload Hex    : 01000000
  -> Protocol Version        : 1
  -> Options Flags           : 0
```

The observed response matched the documented encapsulation format exactly. All field offsets aligned with the expected layout, the session handle was allocated by the target, and the supplied sender context was returned unchanged.

---

## Security Characteristics

* EtherNet/IP session establishment occurs before any CIP messaging is exchanged.
* The target generates the session handle, which becomes the identifier for subsequent communication within the session.
* The sender context is reflected unchanged in the response, allowing clients to correlate requests and responses without affecting protocol behavior.
* The encapsulation header itself contains no authentication, integrity, or confidentiality mechanisms. It is purely a transport wrapper for CIP messages.

---

## Key Takeaways

* Every EtherNet/IP packet begins with a fixed 24-byte encapsulation header encoded in little-endian format.
* A `RegisterSession` request is required before exchanging CIP messages.
* The session handle is allocated by the target, while the sender context is supplied by the client and echoed in the response.
* The `RegisterSession` payload consists of only a protocol version and reserved option flags.
* Understanding the encapsulation header is essential for constructing raw EtherNet/IP traffic and interpreting protocol exchanges during security research.
