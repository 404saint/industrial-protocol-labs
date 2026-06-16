# Hardening Guidance

## Objective

Translate all lab research findings into practical, architectural defensive recommendations for securing Modbus TCP deployments. This document focuses on reducing systemic risks associated with:

* Unauthorized Access
* Active/Passive Reconnaissance
* Protocol Abuse & Fuzzing
* Downstream Process Manipulation
* Operational Disruption

---

## Research Summary

Our laboratory assessment systematically confirmed active support for the core Modbus data suite (`FC01`, `FC02`, `FC03`, `FC04`, `FC05`, `FC06`, `FC15`, `FC16`). It further demonstrated that function code enumeration, memory boundary discovery, register mapping, state manipulation, and exception profiling could all be executed seamlessly **without authentication**.

Because Modbus TCP inherently provides **no authentication, no authorization, and no encryption**, security cannot be managed at the protocol layer. Security must be aggressively enforced through external architectural boundaries and monitoring hooks.

---

## Priority 1: Network Segmentation & Perimeter Isolation

### Why It Matters

The single most effective defense is preventing unauthorized hosts from reaching `TCP/502` entirely. During lab testing, every read, write, and profiling script succeeded based purely on basic IP connectivity to the port. Once a network path was achieved, the protocol offered no secondary line of defense.

### Recommendation

Isolate PLCs within dedicated, tightly firewalled industrial network segments. Completely sever direct connectivity between enterprise networks and the industrial floor.

```text
[ Corporate Network ]
         |
    ( Firewall )
         |
[ Industrial DMZ (Historians / Jump Hosts) ]
         |
    ( Firewall )
         |
[ Control Subnet / SCADA Runtime ]
         |
[ PLCs / Automation Layer (TCP/502 Lockdown) ]

```

---

## Priority 2: Restrict and Whitelist Write Access

### Why It Matters

The lab assessment proved that commands manipulating system state (`FC05`, `FC06`, `FC15`, `FC16`) are executed instantly by the runtime without validation. Unchecked write access allows any rogue node to alter physical logic fields or safety limits.

### Recommendation

Deploy firewall access control lists (ACLs) to ensure only highly explicit, trusted assets can transmit write commands.

* **Authorized Sources:** Designated SCADA Servers, primary HMI Runtimes, and Engineering Workstations during active maintenance windows.
* **Explicitly Blocked Sources:** Corporate user VLANs, IT jump hosts, unauthorized laptops, and unmapped network nodes.

---

## Priority 3: Granular Monitoring of Write Operations

### Why It Matters

While read traffic (`FC01`, `FC03`) is continuous and normal for data logging, write operations modify active variables. Tracking these modification commands provides an immediate indicator of potential process manipulation.

### Recommendation

Configure operational monitoring solutions or Network Intrusion Detection Systems (NIDS) to flag and parse write payloads (`FC05`, `FC06`, `FC15`, `FC16`). Treat any write payload coming from an unexpected source, occurring outside an official maintenance window, or executing in an anomalous volume as a high-severity security event.

---

## Priority 4: Monitor Exception Response Rates

### Why It Matters

An influx of exception frames was generated consistently across our testing whenever function fingerprinting, binary-search memory mapping, or payload fuzzing scripts were executed.

### Recommendation

Establish a strict baseline for protocol errors. Generate an alert if a target asset experiences a sharp spike in exception responses—specifically **Exception 01 (Illegal Function)**, **Exception 02 (Illegal Data Address)**, or **Exception 03 (Illegal Data Value)** within a short period (e.g., more than 10 exceptions per minute).

---

## Priority 5: Detect Function Code Enumeration

### Why It Matters

Executing `modfingerprint.py` cleanly mapped the device’s capabilities by scanning through the sequential `0x01` to `0x7F` function code spectrum, providing a clear roadmap of accessible commands.

### Recommendation

Deploy a behavioral detection logic rule that triggers an alert when a single client IP queries multiple distinct or unsupported function codes within a tight time window.

---

## Priority 6: Detect Memory Address Discovery

### Why It Matters

Our `modboundary.py` script pinpointed the exact maximum readable register limit of the device (`8191`) in under 20 packets by using alternating, binary-search jumps.

### Recommendation

Monitor and alert on unusual, non-sequential register access profiles. Look specifically for massive mathematical address jumps or probing sequences that abruptly halt or adjust upon receiving a cluster of `Illegal Data Address (02)` responses.

---

## Priority 7: Limit Raw Exposure of TCP/502

### Why It Matters

Every single successful exploit, sweep, and profile built during this research depended completely on `TCP/502` being left open and exposed to the testing machine.

### Recommendation

Never expose Modbus TCP directly to corporate user VLANs, guest networks, or external internet connections. If remote connectivity is operationally mandatory, enforce strict client-to-site industrial VPNs, multi-factor authenticated jump hosts, and protocol-aware industrial firewalls.

---

## Priority 8: Active Asset Inventory Validation

### Why It Matters

Our testing proved that a threat actor can easily reverse-engineer device profiles, register limits, and supported operations over the wire. Defenders must understand their own memory footprint before an outsider maps it.

### Recommendation

Maintain continuous, documented visibility over your automation footprint. Keep accurate records detailing device counts, active IP addresses, expected register map ranges, and the precise function code profiles each asset is expected to handle under normal runtime states.

---

## Priority 9: Baseline Normal Operational Traffic

### Why It Matters

Industrial control loops are highly cyclical and static, typically repeating basic read commands (`FC03`, `FC04`) indefinitely. Our research activities (such as `FC43` queries, malformed payloads, and wide address sweeps) stood out clearly against this flat baseline.

### Recommendation

Record and establish standard operating baselines for normal function codes, expected register address spaces, typical poll frequencies, and acceptable write profiles. Treat any structural or quantitative deviation from this baseline as a primary anomaly indicator.

---

## Priority 10: Hardening Engineering Workstations

### Why It Matters

If an adversary compromises an authorized engineering workstation, they inherit a legitimate path to issue `FC05`, `FC06`, `FC15`, and `FC16` write commands. Network firewalls will view this malicious activity as authorized operator behavior.

### Recommendation

Apply strict defensive baselines to all engineering endpoints. Enforce hardware-based Multi-Factor Authentication (MFA), application whitelisting/control policies, aggressive patch schedules, endpoint detection and response (EDR) agent monitoring, and total isolation from direct internet browsing.

---

## Defensive Prioritization Matrix

The following table visualizes the relative security impact and implementation difficulty of each core security control investigated during our research:

| Security Control | Protective Impact | Implementation Difficulty |
| --- | --- | --- |
| **Network Segmentation** | Very High | Medium |
| **Restrict TCP/502 Access via Firewalls** | Very High | Low |
| **Monitor Write Operations** | High | Low |
| **Exception Response Monitoring** | High | Low |
| **Function Enumeration Detection** | High | Medium |
| **Boundary Discovery Detection** | Medium | Medium |
| **Asset Inventory Validation** | Medium | Low |
| **Traffic Baselining & Anomaly Detection** | High | Medium |
| **Engineering Workstation Security** | Very High | Medium |

---

## Hardening Validation Checklist

* [ ] **Network Segmentation:** PLCs are completely isolated into a dedicated industrial security zone.
* [ ] **Access Restriction:** Firewall rules block all unauthorized endpoints from communicating with `TCP/502`.
* [ ] **Write Mitigation:** `FC05` and `FC06` execution sources are restricted via whitelists to authorized SCADA/HMIs.
* [ ] **Bulk Write Mitigation:** `FC15` and `FC16` execution paths are strictly locked down to engineering endpoints.
* [ ] **Exception Alerting:** Monitoring rules trigger alerts immediately upon tracking spikes in Exception Codes `01`, `02`, or `03`.
* [ ] **Reconnaissance Detection:** Active signatures are deployed to flag sequential function code fingerprinting loops.
* [ ] **Boundary Probing Detection:** Automated logic tracks and flags binary-search style address jump patterns.
* [ ] **Traffic Baselining:** Normal function frequencies and register limits have been profiled and mapped.
* [ ] **Asset Tracking:** Comprehensive inventory documentation details the exact roles and maps of all live controllers.
* [ ] **Endpoint Protection:** Engineering workstations are locked down with MFA, EDR tools, and application whitelisting.
* [ ] **Zero Internet Footprint:** Validated that no local automation endpoints are directly reachable from external networks.

---

## Key Takeaways

The most important finding of this research project is not a complex, hidden software flaw—it is the complete, structural absence of built-in security controls inside the legacy Modbus TCP protocol.

As practically demonstrated in our lab environment, any machine that can establish a direct network connection to `TCP/502` can seamlessly map functions, discover memory perimeters, harvest raw state data, and rewrite coils or holding registers at will. Because the protocol cannot defend itself, **security must be aggressively enforced from the outside through careful architecture, deep monitoring, strict network segmentation, and endpoint hardening**.

For the vast majority of industrial setups, locking down access to `TCP/502` via firewall parameters and continuously logging write actions will deliver the highest immediate return on security investment with minimal operational complexity.
