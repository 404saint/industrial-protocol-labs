# Detection Heuristics

## Objective

Translate the protocol behaviors observed during laboratory testing into practical, actionable detection opportunities for network defenders. The ultimate goal is to define exactly what this adversarial activity looks like on the wire and provide a framework to distinguish normal Modbus traffic from reconnaissance or active abuse.

---

## Background & Threat Model

Throughout this research, multiple categories of Modbus activity were systematically generated over the wire:

* **Routine Operations:** Normal reads (`FC01`, `FC03`), normal writes (`FC05`, `FC06`), and bulk modifications (`FC15`, `FC16`).
* **Anomalous Testing:** Function code fingerprinting, binary-search boundary discovery, error state exploration, and protocol fuzzing.

While baseline industrial control loops are notoriously static, repetitive, and predictable, the protocol research and exploitation techniques observed during this assessment generate highly distinct, erratic network artifacts.

---

## Core Detection Heuristics

### Heuristic 1: Function Code Enumeration

* **Description:** Continuous sequential testing of consecutive function codes (e.g., looping `FC01` through `FC127`).
* **Observed During:** Execution of `modfingerprint.py`.
* **Operational Context:** Production industrial control systems typically communicate using a highly restricted, immutable subset of function codes tailored to the HMI/SCADA design (most commonly just `FC01`, `FC02`, `FC03`, and `FC04`).
* **Detection Logic:** Trigger an alert when a single client host requests more than a predefined threshold of distinct, unmapped function codes within a tight time window.

---

### Heuristic 2: Exception Rate Spikes

* **Description:** An uncharacteristic, rapid generation of Modbus exception responses from the target controller.
* **Observed During:** Boundary discovery validation, malformed payload handling, and custom function code fingerprinting.
* **Captured Signatures:** Exception Code `01` (Illegal Function), `02` (Illegal Data Address), and `03` (Illegal Data Value).
* **Operational Context:** Healthy industrial subnets experience near-zero protocol exceptions. A sudden surge in error frames indicates an active external probe attempting to discover software boundaries or validate crash vectors.
* **Detection Logic:** Trigger an alert when the total exception response volume from a specific PLC asset exceeds a statistical baseline (e.g., $>10$ exception responses per minute) or when the exception-to-data frame ratio exceeds $5\%$.

---

### Heuristic 3: Address Boundary Discovery

* **Description:** Probing target registers using mathematically aggressive, alternating address offsets to isolate memory space maximums.
* **Observed During:** Execution of `modboundary.py` (Binary-search mapping pattern: `32768` $\rightarrow$ `16384` $\rightarrow$ `8192` $\rightarrow$ `4096` $\rightarrow \dots \rightarrow$ `8191`).
* **Operational Context:** Valid operational assets are pre-programmed with explicit awareness of their internal memory maps; they do not need to query arbitrary register boundaries. This math pattern points exclusively to active discovery tools or vulnerability researchers.
* **Detection Logic:** Identify and alert on large, alternating mathematical jumps across register address boundaries, or automated sweeps that terminate immediately upon encountering a cluster of `Exception Code 02` responses.

---

### Heuristic 4: Register Enumeration (Address Sweeping)

* **Description:** Sequential, incremental read operations tracking across wide blocks of memory to harvest process data values.
* **Observed During:** Execution of `modscan.py` (Addresses: $0, 1, 2, 3, 4, \dots$).
* **Operational Context:** SCADA pollers generally pack multiple desired registers into discrete, optimized bulk requests rather than querying single registers sequentially across vast address gaps.
* **Detection Logic:** Trigger a security flag when a client reads an unusually high volume of consecutive, unlinked registers within an operational window.

---

### Heuristic 5: High-Rate Polling (Denial of Service/Flooding)

* **Description:** An unrelenting, high-velocity loop of standard read requests (`FC01` or `FC03`) designed to map fast changes or stress connection pools.
* **Observed During:** Continuous bash looping tests.
* **Operational Context:** Normal HMIs operate on rigid, pre-configured polling cycle intervals (e.g., exactly once every 500ms or 1000ms). Continuous, sub-millisecond polling floods can exhaust PLC network stack buffers.
* **Detection Logic:** Trigger an alert when the transaction volume from a specific workstation IP exceeds a hard baseline ceiling (e.g., $100+$ requests per minute from a single node).

---

### Heuristic 6: Unauthorized Write Activity

* **Description:** Detection of system manipulation function codes (`FC05`, `FC06`, `FC15`, `FC16`) traversing unapproved network sectors.
* **Observed During:** Coil flipping and single/bulk holding register override operations.
* **Operational Context:** Modbus TCP completely lacks native authentication mechanisms. Any host that can route traffic to `TCP/502` can alter the physical behavior of the plant.
* **Detection Logic:** Restrict and alert on any write-heavy function codes (`0x05`, `0x06`, `0x0F`, `0x10`) that originate from IP addresses outside a strict whitelist of engineering workstations and runtime HMI engines.

---

### Heuristic 7: Bulk Register Modification Abuse

* **Description:** Large-scale data manipulation payloads leveraging multi-register write frames.
* **Observed During:** Advanced `FC16` block data validation.
* **Operational Context:** Because `FC16` can rewrite an entire control loop or runtime state array in a single network transaction, its potential for rapid process destabilization is significantly higher than single-register overrides (`FC06`).
* **Detection Logic:** Establish a baseline for normal bulk register modification quantities, and flag anomalous transactions pushing large write data counts (e.g., payloads manipulating $25+$, $50+$, or $100+$ registers simultaneously).

---

### Heuristic 8: Unsupported Function Queries

* **Description:** Inbound requests explicitly utilizing unmapped, obscure, or proprietary function code values.
* **Observed During:** Probes across diagnostic commands (`FC07`, `FC08`) and identification metadata sweeps (`FC43`).
* **Captured Signatures:** Uniform server-side generation of `Illegal Function` exception frames (`87 01`, `88 01`, `AB 01`).
* **Operational Context:** Legitimate control equipment never requests functions it was not engineered to support. These frames serve as high-fidelity indicators of automated exploit scanners or misconfigured external assets.
* **Detection Logic:** Flag any instance of an `Exception Code 01` response generated by the PLC, treating it as immediate proof of a non-compliant or malicious query.

---

### Heuristic 9: Protocol Fuzzing

* **Description:** Injecting arbitrary, non-standard data inputs into fixed structural fields (such as fuzzing the coil state word with `0x1234` or `0xFFFF`).
* **Observed During:** OpenPLC single-coil value fuzzing.
* **Operational Context:** Standard client software strictly adheres to standard values (`0xFF00` or `0x0000` for coils). Out-of-bounds parameters point directly to fuzzing frameworks probing for implementation flaws or input validation vulnerabilities.
* **Detection Logic:** Implement deep packet inspection (DPI) to monitor and alert on non-compliant payload syntax, or instances where a server accepts non-standard arguments without raising protocol errors.

---

## Defensive Monitoring Matrix

The following matrix categorizes network events based on their signal strength and operational rarity to help defenders prioritize alert tuning:

| Tested Activity | Network Signal Strength | Operational Rarity | Risk Priority |
| --- | --- | --- | --- |
| **`FC03` / `FC04` Reads** | Low | Extremely Common | Routine Baseline |
| **`FC01` / `FC02` Reads** | Low | Extremely Common | Routine Baseline |
| **`FC06` Single Writes** | High | Less Common | Medium Monitoring Target |
| **`FC05` Coil Writes** | High | Less Common | Medium Monitoring Target |
| **`FC16` Bulk Writes** | Very High | Rare | High Monitoring Target |
| **Function Enumeration** | Very High | Exceptionally Rare | Critical Alert Trigger |
| **Boundary Discovery** | Very High | Exceptionally Rare | Critical Alert Trigger |
| **Protocol Fuzzing** | Very High | Exceptionally Rare | Critical Alert Trigger |
| **Exception Storms** | High | Exceptionally Rare | Critical Alert Trigger |

---

## Key Takeaway

This research demonstrates that Modbus reconnaissance and state manipulation cannot occur silently; they naturally generate highly visible, uniquely structured traffic anomalies.

Crucially, a network defender does not need complex, heavy deep-packet inspection of specific analog process variables to detect the majority of these scanning techniques. Basic, lightweight monitoring tracking **function code distribution, exception code ratios, address jump geometry, and unauthorized write source zones** is entirely sufficient to catch protocol exploitation, active scanning, and targeted industrial abuse early in the attack lifecycle.
