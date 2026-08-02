---
title: 02-control-execution
tags: [Research Notes]

---

# 02: Control Execution

## Executive Summary

DNP3 (IEEE 1815) provides multiple mechanisms for issuing control commands to field devices. This document examines how an outstation processes output control requests, with particular emphasis on the **Select-Before-Operate (SBO)** workflow, **Direct Operate** requests, and the **Control Relay Output Block (CROB)** used to describe control actions.

Laboratory experiments were conducted against a simulated DNP3 outstation to observe command sequencing, state transitions, and protocol responses under both valid and invalid execution paths. The results demonstrate how the protocol maintains execution context and validates control requests before permitting output operations.

---

# 1. Control Execution in DNP3

Unlike simple request-response protocols, DNP3 incorporates state-aware control workflows designed to reduce the likelihood of unintended operations. Before an output is actuated, an outstation may require that the requesting master establish a valid execution context through a **Select-Before-Operate (SBO)** sequence.

The protocol defines two primary methods for issuing discrete output commands:

## Select-Before-Operate (SBO)

Select-Before-Operate is a two-step control workflow intended to verify both the command parameters and the target point before execution.

### Phase 1 — Select (`Function Code 0x03`)

The master transmits a **Select** request identifying the target point together with its associated Control Relay Output Block (CROB). The outstation validates the request and, if accepted, establishes a temporary control state associated with that operation.

### Phase 2 — Operate (`Function Code 0x04`)

The master follows the Select request with an **Operate** command containing matching control parameters. If the previously established control state remains valid and the configured timeout has not expired, the requested output operation is executed.

## Direct Operate (`Function Code 0x05`)

Direct Operate combines validation and execution into a single request. Unlike SBO, it does not require a preceding Select operation.

Whether Direct Operate requests are accepted depends on the implementation and the control policy configured by the outstation. Some deployments permit Direct Operate for selected outputs, while others restrict critical operations to the SBO workflow.

```text
Select-Before-Operate Workflow

Master                                  Outstation
  |                                          |
  |---- Select (FC 0x03) ------------------->|
  |                                          |
  |<--- Confirmation ------------------------|
  |                                          |
  |---- Operate (FC 0x04) ------------------>|
  |                                          |
  |<--- Status Response ---------------------|


Direct Operate Workflow

Master                                  Outstation
  |                                          |
  |---- Direct Operate (FC 0x05) ----------->|
  |                                          |
  |<--- Status Response ---------------------|
```

---

# 2. Control Relay Output Block (CROB)

Output control requests are carried using **Object Group 12 Variation 1**, commonly referred to as the **Control Relay Output Block (CROB)**.

The CROB defines both the requested control action and the timing parameters associated with its execution.

| Offset | Field        | Description                            | Example                       |
| ------ | ------------ | -------------------------------------- | ----------------------------- |
| `0`    | Control Code | Requested output operation             | `0x81` (Trip), `0x41` (Close) |
| `1`    | Count        | Number of requested operations         | `0x01`                        |
| `2-5`  | On Time      | Pulse duration (milliseconds)          | `500 ms`                      |
| `6-9`  | Off Time     | Delay between operations               | `0 ms`                        |
| `10`   | Status       | Operation status returned in responses | `0x00`, `0x04`, etc.          |

Although the CROB format is standardized, individual control codes, timing constraints, and validation rules remain implementation dependent.

---

# 3. Laboratory Methodology

A lightweight Python research utility (`control_attacks.py`) was developed to construct DNP3 control requests manually and transmit them to a simulated outstation operating on TCP port **20000**.

The experiments were designed to evaluate how the implementation responded to both valid and invalid command sequences while observing the resulting protocol responses and returned status codes.

---

# 4. Experiment 1 — Direct Operate

## Objective

Determine whether the evaluated implementation accepts Direct Operate requests without first establishing an SBO control state.

## Method

A **Direct Operate (`FC 0x05`)** request was constructed containing a CROB configured with the **Trip (`0x81`)** control code targeting output point zero.

### Request

```text
05 64 18 c4 01 00 00 00 00 00 c1 c1 05 0c 01 17 01 00 81 01 ...
```

### Response

```text
05 64 0e 44 00 00 01 00 3b e3 c1 81 10 00 0c 01 17 01 00 00
```

## Observation

Within the laboratory environment, the simulated outstation accepted the Direct Operate request and returned a successful command status (`0x00`) without requiring a preceding Select request.

## Interpretation

The evaluated implementation permitted Direct Operate for the tested control point. This behavior is implementation specific and should not be assumed across all DNP3 deployments, as many devices restrict critical outputs to the Select-Before-Operate workflow.

---

# 5. Experiment 2 — Operate Without Select

## Objective

Evaluate how the outstation responds when an Operate request is received without an active Select state.

## Method

An **Operate (`FC 0x04`)** request containing a **Close (`0x41`)** CROB was transmitted without first issuing a matching Select request.

### Request

```text
05 64 18 c4 01 00 00 00 00 00 c1 c1 04 0c 01 17 01 00 41 01 ...
```

### Response

```text
05 64 0e 44 00 00 01 00 3b e3 c1 81 10 04 0c 01 17 01 00 04
```

## Observation

The outstation rejected the request and returned status code **`0x04 (NOT_SELECTED)`**, indicating that no valid Select operation had established the required execution context.

## Interpretation

The evaluated implementation correctly enforced the Select-Before-Operate state machine by refusing an Operate request that was not preceded by a valid Select operation.

---

# 6. Experimental Results

| Experiment             | Function Code | Initial State   | Returned Status       | Outcome  |
| ---------------------- | ------------- | --------------- | --------------------- | -------- |
| Direct Operate         | `0x05`        | No Select state | `0x00`                | Accepted |
| Operate Without Select | `0x04`        | No Select state | `0x04 (NOT_SELECTED)` | Rejected |

The contrasting results demonstrate that command acceptance depends not only on packet structure but also on the execution state maintained by the outstation.

---

# 7. Discussion

The experiments illustrate that DNP3 command processing is fundamentally state dependent. Rather than evaluating each request in isolation, the outstation maintains internal execution context that influences whether subsequent commands are accepted or rejected.

This behavior is particularly evident during Select-Before-Operate workflows, where successful execution depends on a previously established control state, matching command parameters, and implementation-defined timing constraints.

Understanding these state transitions is important when developing protocol analyzers, intrusion detection signatures, implementation conformance tests, or protocol fuzzing methodologies.

---

# 8. Security Considerations

The observations presented in this document suggest several defensive considerations for DNP3 deployments.

### Restrict Direct Operate

Where supported by the implementation, configure critical outputs to require the Select-Before-Operate workflow rather than accepting Direct Operate requests.

### Deploy Secure Authentication

Implement **DNP3 Secure Authentication** to protect control operations from unauthorized command injection and to verify the authenticity of requesting devices.

### Monitor Control Sequences

Network monitoring solutions capable of interpreting DNP3 traffic should detect unexpected Direct Operate requests, repeated sequence validation failures, and unusually frequent `NOT_SELECTED` responses, as these behaviors may indicate configuration issues, application faults, or command-sequence probing.

### Validate State Transitions

Intrusion detection systems that understand DNP3 state transitions can distinguish between legitimate control workflows and malformed or out-of-sequence command sequences, providing greater context than simple function code inspection.

---

# 9. Conclusion

The laboratory experiments demonstrate that DNP3 control operations extend beyond individual function codes. Successful command execution depends on the interaction between application-layer requests and the execution state maintained by the outstation.

While Direct Operate and Select-Before-Operate ultimately perform similar control functions, they follow different validation paths and may be handled differently depending on device implementation and configured control policy. Understanding these behaviors provides an important foundation for analyzing control traffic, evaluating implementation conformance, and conducting protocol security research in subsequent documents.
