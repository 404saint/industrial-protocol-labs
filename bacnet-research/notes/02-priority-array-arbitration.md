# Priority Array Arbitration & Command Precedence Analysis

## Executive Summary

This phase investigated BACnet's priority-based command arbitration mechanism for commandable objects. Unlike many industrial protocols where the most recent write immediately determines device state, BACnet resolves competing commands through a sixteen-slot `Priority_Array`, allowing multiple control sources to coexist while enforcing deterministic precedence rules.

The research focused on three areas: priority-qualified `WriteProperty` requests, relinquish behavior using `NULL` values, and the server's handling of priority metadata during application processing. Testing confirmed that the server correctly parsed priority-qualified requests and acknowledged each operation with a `SimpleACK`. Subsequent inspection of the `Priority_Array` revealed an unexpected discrepancy between the requested priority and the displayed slot assignment for one value. The observation is documented as encountered during testing; investigation of the implementation-specific behavior was outside the scope of this research.

---

# 1. Research Environment

| Component            | Description                                                                                        |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| **Target**           | BACnet/IP `SimpleServer`                                                                           |
| **Protocol**         | BACnet/IP (ANSI/ASHRAE Standard 135)                                                               |
| **Research Harness** | `priority-array-arbitration.py`                                                                    |
| **Assessment Scope** | Priority-qualified writes, command arbitration, relinquish behavior, and Priority Array inspection |

---

# 2. Research Objectives

This phase examined three characteristics of BACnet command arbitration:

* Evaluate how priority-qualified `WriteProperty` requests are processed.
* Observe how `NULL` writes influence arbitration and command relinquishment.
* Inspect the resulting `Priority_Array` following multiple write operations.

---

# 3. Experimental Analysis

## 3.1 Priority-Based Command Arbitration

The first experiment examined how the server processed writes directed at different priority levels.

### Protocol Background

Commandable BACnet objects expose Property **85 (`Present_Value`)**, which may be modified using the `WriteProperty` service. An optional Priority parameter allows the client to specify one of sixteen priority levels.

When multiple priority slots contain values, BACnet determines the effective output by selecting the highest-priority non-`NULL` entry within the `Priority_Array`.

### Test Sequence

Three priority-qualified writes were issued sequentially:

| Vector | Operation    | Requested Priority | Result      |
| ------ | ------------ | ------------------ | ----------- |
| A      | Write `22.5` | Priority 16        | `SimpleACK` |
| B      | Write `99.0` | Priority 1         | `SimpleACK` |
| C      | Write `50.0` | Priority 8         | `SimpleACK` |

### Server Observations

Server diagnostic output confirmed that each request was decoded using the intended priority value.

```
WP: type=1 instance=1 property=85 priority=16 index=4294967295
WP: type=1 instance=1 property=85 priority=1 index=4294967295
WP: type=1 instance=1 property=85 priority=8 index=4294967295
```

Each request completed successfully with a `SimpleACK`.

### Discussion

The experiment demonstrates that the server correctly parsed the priority parameter supplied within each `WriteProperty` request. No application-layer errors were generated, indicating successful processing of all three operations.

From the client perspective, subsequent `ReadProperty` requests continued to report a `NULL` `Present_Value`, suggesting that the observable output state did not immediately reflect the written values during this experiment.

---

## 3.2 Relinquish Processing Using `NULL`

The second experiment evaluated how the implementation handled relinquishing an active priority slot.

### Protocol Background

BACnet releases control of a priority slot by writing the application data type `NULL` to the corresponding priority entry. After relinquishment, the controller recalculates the effective output using the remaining populated slots. If every slot contains `NULL`, the object falls back to its configured `Relinquish_Default`.

### Test Parameters

| Operation | Target                 |
| --------- | ---------------------- |
| Service   | `WriteProperty (0x0F)` |
| Value     | `NULL`                 |
| Priority  | `1`                    |

### Observations

The relinquish request completed successfully.

Server diagnostics recorded:

```
WP: type=1 instance=1 property=85 priority=1 index=4294967295
WP: Sending Simple Ack!
```

The client subsequently reported a successful response and continued with inspection of the `Priority_Array`.

### Discussion

The experiment confirms that the implementation accepted a `NULL` write directed at Priority 1 and processed the request without error. The behavior is consistent with BACnet's command relinquishment mechanism, although this phase focused on protocol behavior rather than validating the resulting control logic through external process variables.

---

## 3.3 Priority Array Inspection

The final experiment inspected Property **87 (`Priority_Array`)** after the preceding write operations.

### Observations

The returned array contained predominantly `NULL` entries.

The only populated slot reported by the client was:

| Slot | Value  |
| ---- | ------ |
| 12   | `50.0` |

All remaining slots, including Slots **1**, **8**, and **16**, were reported as `NULL`.

### Discussion

This observation differed from the priorities supplied during the write operations. While server diagnostics confirmed receipt of writes targeting Priorities **16**, **1**, and **8**, the subsequent `Priority_Array` inspection displayed the remaining value in Slot **12**.

The source of this discrepancy was not investigated further during this phase. Consequently, this paper records the observation without attributing it to a specific implementation or protocol behavior.

---

# 4. Security Characteristics

The experiments illustrate how BACnet separates command issuance from command arbitration through the `Priority_Array` mechanism.

Several observations emerged during testing:

* The server accepted priority-qualified `WriteProperty` requests without generating protocol errors.
* Server diagnostics confirmed that the intended priority values were correctly decoded during request processing.
* Priority slot inspection produced results that differed from the requested priorities, highlighting the importance of validating implementation behavior in addition to protocol semantics.

These findings reinforce that protocol compliance and implementation behavior should be evaluated independently when assessing BACnet deployments.

---

# 5. Hardening Recommendations

Based on the observed behavior, the following practices are recommended:

1. Restrict write access to commandable objects using appropriate network segmentation and implementation-specific access controls.
2. Monitor priority-qualified `WriteProperty` requests, particularly those targeting high-precedence priority levels.
3. Validate controller behavior against expected `Priority_Array` semantics during commissioning and security assessments.
4. Review implementation-specific documentation when observed priority behavior differs from expected protocol operation.


