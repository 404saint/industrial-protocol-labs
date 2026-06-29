# 07 - EtherNet/IP Encapsulation Command Fingerprinting

## Overview

EtherNet/IP defines several encapsulation commands that operate before any CIP messaging or session-dependent communication occurs. One of these commands, **ListServices** (`0x0004`), allows a client to discover the communication services supported by a target.

Because `ListServices` can be issued without first establishing a session, it is commonly used during protocol discovery, asset identification, and network reconnaissance.

---

## ListServices Response Structure

The following response was captured from the `cpppo` EtherNet/IP simulator after issuing a `ListServices` request.

Following the standard 24-byte encapsulation header, the remaining payload describes the communication services supported by the target.

| Byte Offset | Field            | Data Type  | Verified Value   | Description                          |
| :---------- | :--------------- | :--------- | :--------------- | :----------------------------------- |
| **24–25**   | Item Count       | `uint16`   | `0x0001`         | One service capability entry follows |
| **26–27**   | Item Type        | `uint16`   | `0x0001`         | Communications Service Item          |
| **28–29**   | Item Length      | `uint16`   | `0x0013`         | Nineteen bytes of capability data    |
| **30–31**   | Protocol Version | `uint16`   | `0x0001`         | Service format version               |
| **32–33**   | Capability Flags | `uint16`   | `0x0020`         | Explicit messaging supported         |
| **34–48**   | Service Name     | `char[15]` | `Communications` | Null-terminated service description  |

---

## Capability Enumeration

The `ListServices` response advertises the communication capabilities implemented by the target's EtherNet/IP stack.

In the captured response:

* One Communications Service Item was returned.
* The capability flags indicated support for explicit messaging.
* The advertised service name was `Communications`.

Although the overall response format is standardized, individual implementations may differ in the number of advertised services, supported capability flags, string formatting, or other implementation-specific details.

---

## Empirical Verification

The following packet was captured directly from the simulator during execution of `enip_command_fingerprint.py`.

```text id="9fg2wn"
04 00 19 00 00 00 00 00 00 00 00 00 46 49 4e 47
45 52 50 54 00 00 00 00 01 00 00 01 13 00 01 00
20 00 43 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e 73 00
```

The payload decodes into a single Communications Service Item containing the protocol version, capability flags, and service description.

---

## Security Characteristics

* `ListServices` can be queried without establishing an EtherNet/IP session.
* The response advertises protocol capabilities before any application-layer communication occurs.
* Variations in capability flags, supported service items, and implementation details may provide useful fingerprinting characteristics across different EtherNet/IP stacks.
* Because the command is read-only and unauthenticated, it is frequently observed during passive asset discovery and active network reconnaissance.

---

## Key Takeaways

* `ListServices` (`0x0004`) enumerates the communication services supported by an EtherNet/IP device.
* The response follows the standard encapsulation header and returns one or more Communications Service Items.
* Each capability entry includes a protocol version, capability flags, and a service description.
* The captured simulator response advertised explicit messaging support through a single Communications Service Item.
* Differences between implementations can provide useful protocol fingerprinting information during device identification.
