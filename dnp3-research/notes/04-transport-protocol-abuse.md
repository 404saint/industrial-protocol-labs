# 04: Transport Reassembly & Unsolicited Messaging

## Executive Summary

The DNP3 Transport Pseudo-Layer provides a lightweight fragmentation and reassembly mechanism for Application Protocol Data Units (APDUs). Unlike transport protocols such as TCP, it does not provide reliability or routing. Instead, it maintains fragment sequencing information that allows large application messages to be reconstructed across multiple Data Link frames.

This document examines two aspects of DNP3 communication that rely on this mechanism: transport-layer reassembly and unsolicited messaging. Laboratory experiments were conducted against a simulated DNP3 implementation to observe how abnormal fragment sequences are processed and how unsolicited response messages are handled once successfully reassembled.

The objective of these experiments is to better understand implementation behavior, protocol state management, and the security considerations associated with transport reassembly and unsolicited communications.

---

# 1. The DNP3 Transport Pseudo-Layer

Large DNP3 Application Protocol Data Units (APDUs) may exceed the maximum payload that can be carried within a single Data Link frame. To accommodate larger messages, DNP3 introduces a lightweight Transport Pseudo-Layer positioned between the Data Link and Application layers.

Each transport fragment begins with a single-byte transport header.

```text
 7   6   5   4   3   2   1   0
+---+---+-----------------------+
|FIN|FIR|   Sequence (0 - 63)   |
+---+---+-----------------------+
```

The transport header contains three fields:

* **FIR (First Fragment):** Indicates the first fragment of a transport sequence.
* **FIN (Final Fragment):** Indicates the final fragment of a transport sequence.
* **Sequence Number:** A six-bit counter used to maintain fragment ordering during reassembly.

Unlike TCP, the DNP3 Transport Pseudo-Layer does not implement retransmission or reliability. Its responsibility is limited to maintaining sufficient state to reconstruct fragmented application messages.

---

# 2. Unsolicited Responses

Most DNP3 communication follows a request-response model in which a master polls an outstation for information. DNP3 also defines **Unsolicited Responses (`Function Code 0x82`)**, allowing an outstation to transmit event data without waiting for a polling request.

These messages are commonly used to report Class 1, Class 2, or Class 3 events, enabling important operational changes to be communicated with lower latency than periodic polling.

Because unsolicited responses directly deliver application-layer objects to the receiving master, implementations must correctly validate message origin, protocol state, and application context before incorporating received information into operational workflows.

---

# 3. Laboratory Methodology

A lightweight Python research utility (`transport_attacks.py`) was developed to manually construct DNP3 transport frames and unsolicited responses. Experiments were performed against a simulated DNP3 implementation operating on TCP port **20000**.

The objective was not to evaluate a particular vendor implementation, but rather to observe protocol behavior when presented with valid and intentionally abnormal transport sequences.

---

# 4. Experiment 1 — Orphaned Fragment

## Objective

Determine how the implementation responds when a fragment marked as the final segment of an APDU is received without an active reassembly context.

## Method

A transport frame was constructed with:

* `FIR = 0`
* `FIN = 1`
* `Sequence = 0`

No preceding fragment was transmitted.

### Request

```text id="n7j24d"
05 64 0c 44 00 00 01 00 3b e3 80 c1 01
```

### Response

```text id="a0txv9"
05 64 09 44 00 00 01 00 3b e3 c1 81 00 04
```

## Observation

The simulated implementation rejected the fragment because no active transport reassembly context existed. The returned response indicated a protocol error consistent with the implementation's validation logic.

## Interpretation

This experiment demonstrates that the evaluated implementation maintains transport-layer state and validates fragment ordering before attempting APDU reassembly.

---

# 5. Experiment 2 — Incomplete Fragment Stream

## Objective

Observe transport state initialization when the first fragment of a multi-fragment sequence is received.

## Method

A transport frame was transmitted with:

* `FIR = 1`
* `FIN = 0`
* `Sequence = 5`

No subsequent fragments were transmitted.

### Request

```text id="mtcrg6"
05 64 0c 44 00 00 01 00 3b e3 45 c1 01
```

### Response

```text id="3zkmwb"
05 64 09 44 00 00 01 00 3b e3 c1 81 00 00
```

## Observation

The implementation accepted the initial fragment and established a transport reassembly context, advancing its expected sequence number in preparation for the remaining fragments.

## Interpretation

The experiment illustrates how transport-layer state is allocated before a complete APDU has been received. Production implementations typically pair this behavior with timeout mechanisms that eventually discard incomplete reassembly contexts.

---

# 6. Experiment 3 — Unsolicited Response Processing

## Objective

Observe how the simulated implementation processes a single-fragment unsolicited response containing application-layer event data.

## Method

A single-fragment **Unsolicited Response (`Function Code 0x82`)** was constructed containing a **Group 30 Variation 1** Analog Input object with a test value representing an over-range condition.

### Request

```text id="mcnwht"
05 64 12 44 00 00 01 00 3b e3 c0 c0 82 00 00 1e 01 00 01 00 00 ff 7f 01
```

### Response

```text id="6b8w4n"
05 64 09 44 00 00 01 00 3b e3 c1 81 00 00
```

## Observation

The simulated implementation successfully reassembled the single-fragment APDU, parsed the unsolicited response, and processed the contained Group 30 Variation 1 object according to its application logic.

Within the laboratory environment, the injected analog value was subsequently reflected in the simulated master's internal state.

## Interpretation

The experiment demonstrates that unsolicited responses are processed through the same transport and application parsing pipeline as solicited responses. The resulting behavior depends on the implementation's validation logic, configured trust relationships, and support for authentication or message verification.

---

# 7. Experimental Results

| Experiment                 | Mechanism Evaluated    | Observed Behavior                                                |
| -------------------------- | ---------------------- | ---------------------------------------------------------------- |
| Orphaned Fragment          | Transport Reassembly   | Fragment rejected without active reassembly state                |
| Incomplete Fragment Stream | Transport State        | Reassembly context initialized and sequence tracking established |
| Unsolicited Response       | Application Processing | Single-fragment unsolicited message parsed successfully          |

The experiments demonstrate that transport-layer processing depends on internal reassembly state, while unsolicited messaging relies on successful progression through both the transport and application layers.

---

# 8. Discussion

Unlike connection-oriented transport protocols, the DNP3 Transport Pseudo-Layer maintains only the state necessary to reconstruct fragmented application messages. Although comparatively lightweight, this state influences how implementations interpret incoming fragments and determines whether application-layer processing can proceed.

The laboratory observations also illustrate that unsolicited responses are not treated as fundamentally different protocol objects. Once transport reassembly has completed successfully, unsolicited messages follow the normal application parsing pipeline defined by the implementation.

Understanding these interactions provides valuable insight into protocol behavior, implementation validation, and defensive monitoring of DNP3 traffic.

---

# 9. Security Considerations

The protocol behaviors examined in this document suggest several considerations for production DNP3 deployments.

### Validate Transport Reassembly

Implementations should enforce fragment ordering, maintain bounded reassembly state, and discard incomplete transport contexts after reasonable timeout intervals to prevent unnecessary resource consumption.

### Verify Unsolicited Message Origin

Master stations should accept unsolicited responses only from expected outstations and should validate addressing, sequence state, and protocol context before processing received application objects.

### Deploy DNP3 Secure Authentication

Where supported, DNP3 Secure Authentication provides cryptographic protection for critical protocol operations and helps ensure that accepted messages originate from authenticated devices.

### Monitor Reassembly Anomalies

Repeated fragment ordering failures, incomplete transport sequences, or unexpected unsolicited responses may indicate implementation faults, configuration issues, or abnormal network activity. These events should therefore be considered useful indicators during protocol monitoring and incident investigation.

---

# 10. Conclusion

The experiments presented in this document demonstrate that the DNP3 Transport Pseudo-Layer maintains protocol state beyond the Data Link layer despite its minimal design. Fragment ordering, sequence tracking, and reassembly all influence whether application-layer processing can proceed successfully.

The study also illustrates how unsolicited responses traverse the same parsing pipeline as other application messages once transport validation has completed. Together, these observations provide a deeper understanding of DNP3 transport behavior and establish a foundation for evaluating implementation robustness, protocol conformance, and defensive monitoring strategies.
