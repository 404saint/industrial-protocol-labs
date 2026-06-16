# Register Boundary Discovery

## Objective
Identified the logical memory ceiling of the OpenPLC target to map the exposed attack surface and validate memory enforcement quality.

---

## Methodology
A binary-search discovery engine was utilized to converge on the memory limit, reducing the scan footprint from a theoretical 65,535 packets to **under 20 packets**.

---

## Probing Convergence Path
* `32768` $\rightarrow$ ❌ Exception 02
* `16384` $\rightarrow$ ❌ Exception 02
* `8192`  $\rightarrow$ ❌ Exception 02
* `4096`  $\rightarrow$ ✅ Success
* `6144`  $\rightarrow$ ✅ Success
* `7168`  $\rightarrow$ ✅ Success
* `7680`  $\rightarrow$ ✅ Success
* `7936`  $\rightarrow$ ✅ Success
* `8064`  $\rightarrow$ ✅ Success
* `8128`  $\rightarrow$ ✅ Success
* `8160`  $\rightarrow$ ✅ Success
* `8176`  $\rightarrow$ ✅ Success
* `8184`  $\rightarrow$ ✅ Success
* `8188`  $\rightarrow$ ✅ Success
* `8190`  $\rightarrow$ ✅ Success
* `8191`  $\rightarrow$ ✅ Success

**Conclusion:** The maximum readable holding register offset is **8191**.

### Critical Metric:
* **Total Registers:** 8,192
* **Memory Surface:** 16 KB (8,192 * 2 bytes)
* **Enforcement:** Strict. Address 8192 triggers `Exception 02` immediately.

---

## Memory Map Architecture

```text
       0 --------------------------- 8191   |   8192+
       |                            |   |   |
       |    Accessible Data Space   |   |   |   Invalid Memory Space
       |       (Returns Data)       |   |   |  (Exception Code 02)
       ------------------------------   |   v

```

---

## Security Implications
Knowing exact memory bounds allows attackers to optimize scans and avoid "Illegal Address" exceptions that typically trigger IDS alerts. 

---

## Detection Opportunities
The binary-search signature is highly anomalous:
* **Arithmetic Jumps:** Non-sequential jumps across the address space.
* **Convergence Pattern:** Repeated halving of address ranges within milliseconds.
* **Error Clustering:** A burst of `Exception 02` codes at the boundary point.

---

## Hardening Guidance
* **Address Whitelisting:** Alarm on any request outside the HMI/SCADA range (0–4 for this lab).
* **Rate-Limit Exceptions:** Flag source IPs that generate multiple `Exception 02` responses.
* **Perimeter Lockdown:** Block `TCP/502` to unauthorized engineering hosts.
