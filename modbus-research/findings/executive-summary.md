# Executive Summary

## Project Overview
Manual protocol analysis and vulnerability assessment of Modbus TCP using OpenPLC. Core focus: raw socket interaction, memory boundary discovery, and implementation-specific fuzzing.

---

## Major Findings

### 1. Zero Native Protocol Security Controls
Assessment confirmed the absence of authentication, authorization, or encryption. Network-level access to `TCP/502` grants full read/write control.

### 2. Memory Map Constraints
Discovered a 16 KB volatile RAM allocation via binary-search discovery.
* **Upper Boundary:** Offset 8191.
* **Total Space:** 8,192 registers.
* **Enforcement:** Accessing index 8192+ triggers `Exception 02`.

### 3. Core Specification Deviation (Coil Fuzzing)
OpenPLC fails to validate `FC05` (Write Single Coil) arguments.
* **Specification:** Only `0xFF00` (ON) and `0x0000` (OFF) are valid.
* **Observed Flaw:** OpenPLC accepts arbitrary hex (e.g., `0x1234`), treating any non-zero value as `TRUE`.

### 4. Metadata Privacy (FC43)
Function Code 43 (MEI Type `0x0E`) is unsupported, returning `Exception 01`. Vendor and firmware metadata are not exposed via the Modbus port.

### 5. Volatility and Persistence
Data maps exist purely in volatile memory. State overrides survive concurrent client connections but reset upon runtime service restart.

---

## Defensive Insights
Malicious activity produces distinct wire artifacts:
* **Fingerprinting:** Sequential sweeps (`FC01` $\rightarrow$ `FC127`) + surge of `Exception 01`.
* **Mapping:** Alternating address jumps + `Exception 02` clusters.
* **Fuzzing:** Non-standard hex values in `FC05` payloads.

## Strategic Priorities
1. **Perimeter Isolation:** Strict industrial firewall segmentation to block unauthorized `TCP/502` traffic.
2. **Write Whitelisting:** Restrict `FC05`, `FC06`, and `FC16` to specific, hardened HMI/Engineering nodes.
3. **Exception Monitoring:** Baseline protocol errors and alert on spikes in `Exception 01` or `02`.

---

## Conclusion
Modbus is a protocol built for interoperability, not security. As confirmed through manual probing and binary analysis, the reliability of an OT asset depends entirely on external architectural boundaries and anomaly-based detection.
