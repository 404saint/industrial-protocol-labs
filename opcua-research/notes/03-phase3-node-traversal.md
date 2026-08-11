# Phase 3: Address Space Traversal & Access Control Audit

## Executive Summary

Phase 3 examined the OPC UA address space exposed to the anonymous session established during Phase 2. The objective was to determine what information and operational variables could be discovered through the server's object graph and whether the anonymous session could perform state-changing operations.

A recursive traversal of the server's `Objects` hierarchy identified application-defined Variable nodes and inspected their `AccessLevel`, `UserAccessLevel`, and current values where permitted. The traversal demonstrated that anonymous access was **not universally unrestricted**: several nodes rejected reads with authorization-related errors.

However, the audit identified a more significant security boundary failure. Five application variables accepted write operations from the anonymous session, and each test resulted in an observable value change:

* `Boolean`: `False → True`
* `integer`: `0 → 1`
* `Double`: `0.0 → 1.0`
* `Int64`: `0 → 1`
* `example bytestring`: `b'test123' → b'test123_probe'`

Each successful mutation was immediately reverted to its original value.

The resulting security boundary is therefore selective rather than completely open: **the anonymous session encounters protected nodes but retains unauthenticated write access to specific application variables.**

---

## 1. Address Space Traversal

OPC UA exposes server information through a hierarchical object graph rather than a flat register space. Phase 3 used the anonymous session established in Phase 2 to traverse the server's `Objects` hierarchy and identify Variable nodes available to that session.

The audit recursively inspected the object hierarchy and collected Variable nodes for subsequent access testing.

The traversal recorded:

* Browse Name
* NodeId
* NodeId type and namespace
* NodeClass
* `AccessLevel`
* `UserAccessLevel`
* Current value or returned access error

The purpose was not to reproduce the complete OPC UA information model, but to establish the **effective address-space visibility available to the anonymous session**.

### Traversal Model

```text
Root
└── Objects
    ├── Server
    │   └── ServerStatus
    │       └── CurrentTime
    │
    └── Application Namespace
        ├── Application Objects
        ├── Variables
        └── Methods
```

The traversal demonstrated that the anonymous session could enumerate portions of the application-defined address space while encountering different access-control responses depending on the node.

---

## 2. NodeId Resolution & Browse Path Translation

OPC UA clients can resolve semantic browse paths into concrete NodeIds through the address-space services.

As a controlled test, the following relative path was resolved:

```text
0:Objects
    → 0:Server
        → 0:ServerStatus
            → 0:CurrentTime
```

The server resolved the path to:

```text
ns=0;i=2258
```

This corresponds to the standardized `ServerStatus.CurrentTime` node.

The test confirms that the anonymous session was capable of performing normal address-space path resolution rather than requiring preconfigured NodeIds for every discovered object.

---

## 3. Address Space Access Boundaries

Recursive enumeration revealed that access was not uniform across the discovered address space.

Several application nodes were deliberately configured with restricted access characteristics. Attempts to interact with these nodes produced authorization or readability errors rather than unrestricted access.

Representative observations included:

| Node                            | NodeId                      | NodeClass | Observed Behavior                        |
| :------------------------------ | :-------------------------- | :-------- | :--------------------------------------- |
| `the.answer`                    | `ns=1;s=the.answer`         | Variable  | Read/Write accessible                    |
| `the.answer - not readable`     | `ns=1;s=the.answer.no.read` | Variable  | Read rejected with `BadNotReadable`      |
| `the.answer - not current user` | `ns=1;i=1337`               | Variable  | Read rejected with `BadUserAccessDenied` |
| `Demo → Scalar`                 | `ns=1;i=50001`              | Object    | Container for application variables      |
| `hello_world`                   | `ns=1;i=62541`              | Method    | Executable method exposed                |

These results are important because they demonstrate that the anonymous session did **not** possess unrestricted access to every node encountered during traversal.

Instead, the server enforced different access outcomes across the address space.

### Observed Access Model

```text
Anonymous Session
       │
       ▼
   Objects
       │
       ├── Protected Nodes
       │      ├── BadNotReadable
       │      └── BadUserAccessDenied
       │
       └── Accessible Application Nodes
              │
              └── Writable Variables
```

This distinction becomes significant when evaluating the write tests below.

---

## 4. Controlled Write Authorization Testing

After identifying readable Variable nodes, the audit attempted controlled write operations using values appropriate to each variable's native data type.

The test procedure was:

1. Read the original value.
2. Generate a minimally modified probe value.
3. Submit a `Write` operation using the anonymous session.
4. Verify whether the server accepted the mutation.
5. Restore the original value immediately after a successful write.

The probe values were intentionally simple to minimize the impact on the simulated process state.

### Write Test Results

| Variable             | Original Value | Probe Value        | Result             |
| :------------------- | :------------- | :----------------- | :----------------- |
| `Boolean`            | `False`        | `True`             | **Write Accepted** |
| `integer`            | `0`            | `1`                | **Write Accepted** |
| `Double`             | `0.0`          | `1.0`              | **Write Accepted** |
| `Int64`              | `0`            | `1`                | **Write Accepted** |
| `example bytestring` | `b'test123'`   | `b'test123_probe'` | **Write Accepted** |

All five writes produced an observable value transition.

For example:

```text
Boolean
False → True
      → False (reverted)

integer
0 → 1
  → 0 (reverted)

Double
0.0 → 1.0
    → 0.0 (reverted)

Int64
0 → 1
  → 0 (reverted)

example bytestring
b'test123' → b'test123_probe'
           → b'test123' (reverted)
```

The successful mutations demonstrate that the server accepted state-changing `Write` requests from the anonymous session.

---

## 5. Security Boundary Finding

The Phase 3 results establish a more precise security condition than simply describing the server as having "anonymous access."

The anonymous session encountered protected nodes, including nodes returning:

```text
BadNotReadable
BadUserAccessDenied
```

At the same time, specific application-defined variables accepted authenticated OPC UA `Write` service requests without requiring a stronger user identity.

The resulting boundary can be summarized as:

```text
                  Anonymous Session
                         │
                         ▼
                Address Space Access
                         │
             ┌───────────┴───────────┐
             │                       │
        Protected Nodes         Writable Nodes
             │                       │
      Access Denied /          Anonymous Write
      Not Readable             Accepted
                                     │
                              State Mutation
```

This represents a **selective authorization failure** rather than unrestricted access to the entire address space.

The security impact depends on the role of the affected variables. If equivalent permissions were applied to operational setpoints, actuator commands, or control parameters in a production deployment, an unauthenticated network client could potentially modify process state without possessing a user credential.

---

## Security Characteristics

Phase 3 demonstrated that an anonymous OPC UA session can expose substantially more than passive metadata when application variables are incorrectly permissioned.

The most significant observation was not that every node was accessible, but that **authorization boundaries were inconsistently enforced across the address space**. Protected variables correctly rejected unauthorized operations, while five application variables accepted state-changing writes from the anonymous session.

The findings therefore establish three important characteristics of the target:

* **Address-space traversal:** Application-defined nodes can be discovered through standard OPC UA browsing mechanisms.
* **Selective authorization:** Access controls exist for some nodes and produce explicit `BadNotReadable` or `BadUserAccessDenied` responses.
* **Unauthenticated state mutation:** Five tested application variables accepted writes from the anonymous session and changed state successfully.

The successful writes provide the primary security finding for this phase: **anonymous access is capable of crossing the read/write authorization boundary for specific application variables.**

Phase 4 will examine the security boundaries surrounding this access, including endpoint security-policy behavior, certificate trust, and invalid session or identity handling.
