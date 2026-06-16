# Lab Reproduction Guide

## Purpose

This guide explains how to reproduce every experiment documented throughout this research project. By maintaining the same environment configurations, execution paths, and testing sequence, an independent researcher will be able to obtain results that closely match the empirical data reported across this portfolio.

---

## Lab Architecture & Topology

The entire replication environment is lightweight and can be contained within a single local test segment or hosted across virtualized containers.

```text
+----------------------------+
|        Attacker Host       |
| (Custom Python Toolkit /   |
|   Tshark / Packet Capture) |
+--------------+-------------+
               |
               | TCP Port 502
               | (Modbus TCP Stream)
               |
+--------------v-------------+
|       OpenPLC Target       |
|    (Runtime Environment)   |
+----------------------------+

```

### Protocol Environment Bounds:

* **Protocol Layer:** Modbus TCP
* **Target Port:** `502` (Standard ICS Default)
* **Access Control:** Fully unauthenticated network path

---

## Environment Setup & Requirements

### Target Controller:

* **Software:** OpenPLC Runtime Environment.
* **Configuration:** Ensure the Modbus TCP server thread is actively enabled and mapped to port 502.

### Analysis Workstation:

* **Operating System:** Linux environment (e.g., Arch Linux, Ubuntu, or Kali).
* **Software Prerequisites:** Python 3.x interpreter, `tcpdump` engine, and Wireshark/Tshark for packet dissection.

### Base Target Verification:

Prior to executing test scripts, verify that the target daemon is actively listening on the control interface:

```bash
ss -tlnp | grep 502

```

#### Expected Terminal Output:

```text
LISTEN 0 128 0.0.0.0:502

```

---

## PLC Program Labs (Structured Text Configuration)

Several steps require deploying specific logic models to the OpenPLC core to provide a baseline data pool for the network scripts.

### Program 1 — Holding Register Lab

* **Purpose:** Provides variables for validation of `FC03` (Read), `FC06` (Write), `FC16` (Bulk Write), and Memory Boundary Discovery.

```iecst
PROGRAM Main
VAR
    Reg0 AT %MW0 : INT;
    Reg1 AT %MW1 : INT;
    Reg2 AT %MW2 : INT;
    Reg3 AT %MW3 : INT;
    Reg4 AT %MW4 : INT;
END_VAR
END_PROGRAM

```

* **Action:** Compile, upload, and launch the runtime state via the OpenPLC dashboard.

### Program 2 — Coil Lab

* **Purpose:** Maps standard discrete memory addresses for binary bit manipulation (`FC01` / `FC05`).

```iecst
PROGRAM Main
VAR
    Coil0 AT %QX0.0 : BOOL;
END_VAR
END_PROGRAM

```

### Program 3 — Coil Toggle (Dynamic State Loop)

* **Purpose:** Simulates an active, running manufacturing loop to test real-time monitoring capabilities.

```iecst
PROGRAM Main
VAR
    Coil0 AT %QX0.0 : BOOL;
END_VAR

Coil0 := NOT Coil0;
END_PROGRAM

```

> *Note:* Real-time data captures will reflect shifting binary states on each polling request based on your configured PLC task scan rate.

---

## Network Packet Capture Baselines

Always initialize network tapping infrastructure *prior* to executing any evaluation scripts to build an audit trail of raw protocol frames.

### Capture Live to Terminal Hex Display:

```bash
sudo tcpdump -i any port 502 -nn -X

```

### Log Directly to PCAP File for Wireshark Analysis:

```bash
sudo tcpdump -i any port 502 -w modbus-lab.pcap

```

---

## Tooling Blueprint Inventory

The following script assets make up the custom bare-metal Python exploitation and testing engine used throughout this lab:

| Script Filename | Target Field | Primary Research Purpose |
| --- | --- | --- |
| `modbus_client.py` | `FC03` | Read 16-bit word data from holding registers |
| `modwrite.py` | `FC06` | Inject single 16-bit register value adjustments |
| `modmulti.py` | `FC16` | Modify extensive arrays of registers in bulk blocks |
| `modcoils.py` | `FC01` | Polling discrete output binary bit flags |
| `modcoilwrite.py` | `FC05` | Force discrete single coil modifications (`TRUE`/`FALSE`) |
| `modfingerprint.py` | `FC01` - `FC127` | Automated sequence mapping of all supported function paths |
| `modmei.py` | `FC43` | Investigating Device Identification metadata exposure |
| `modexception_lab.py` | Fuzzing | Testing runtime stability against structural protocol errors |
| `modboundary.py` | Algorithm | Executing binary search to find memory space ceilings |
| `modscan.py` | Profiling | Executing complete sequential address mapping sweeps |

---

## Sequential Step-by-Step Research Replication Process

To replicate the project accurately, execute the following instructions in exact chronological order:

### Step 1 — Protocol Anatomy Initialization

1. Spin up the network capture background thread (`tcpdump`).
2. Analyze the structural boundaries of the 7-byte Modbus Application Protocol (MBAP) Header (Transaction ID, Protocol ID, Length, and Unit ID) against the downstream Protocol Data Unit (PDU).

### Step 2 — FC03 Holding Register Evaluation

* **Execution:** `python modbus_client.py`
* **Expected Request Frame Data:** `00 01 00 00 00 06 01 03 00 00 00 01`
* **Expected Response Frame Data:** `00 01 00 00 00 05 01 03 02 00 00`
* **Objective:** Verify raw socket reception of 16-bit register configurations.

### Step 3 — FC06 Single Register Modification

* **Execution:** `python modwrite.py`
* **Expected Result:** Target Register 0 explicitly switches to integer state `1337`. Response echoes the modified frame cleanly.
* **Objective:** Verify manual process variable intervention over raw sockets.

### Step 4 — FC16 Bulk Array Modification

* **Execution:** `python modmulti.py`
* **Expected Result:** Direct concurrent overwrite of five sequential register blocks to state elements `[100, 200, 300, 400, 500]`.
* **Objective:** Validate complex multi-point command injections.

### Step 5 — FC01 Discrete Coil Evaluation

* **Execution:** `python modcoils.py`
* **Expected Result:** Captures boolean bit arrays (`[0,0,0,0,0,0,0,0]` or `[1,0,0,0,0,0,0,0]`) mapping to active PLC logic states.
* **Objective:** Evaluate bit-packed LSB-first network structures.

### Step 6 — FC05 Single Bit Manipulation

* **Execution:** `python modcoilwrite.py`
* **Expected Result:** Targeted manipulation of Coil 0 using explicit values `FF00` (ON) or `0000` (OFF).
* **Objective:** Prove single-point logic override reliability.

### Step 7 — Active Device Capability Mapping

* **Execution:** `python modfingerprint.py`
* **Expected Result:** Verification that `FC01`, `FC02`, `FC03`, `FC04`, `FC05`, `FC06`, `FC15`, and `FC16` are fully open, while out-of-range functions trigger immediate exception frames.
* **Objective:** Document total exposed capabilities without manufacturer documentation.

### Step 8 — Device Identity Extraction Profiling

* **Execution:** `python modmei.py`
* **Expected Result:** Server rejects frame with signature `AB 01` (Exception `01` - Illegal Function).
* **Objective:** Validate metadata privacy boundaries over the protocol layer.

### Step 9 — Controlled Exception Injections

* **Execution:** `python modexception_lab.py`
* **Expected Result:** Orderly generation and tracking of Exception Codes `01` (Illegal Function), `02` (Illegal Data Address), and `03` (Illegal Data Value).
* **Objective:** Validate internal error containment bounds.

### Step 10 — Binary Search Memory Ceiling Convergence

* **Execution:** `python modboundary.py`
* **Expected Result:** Core tool converges cleanly onto register **`8191`** as the absolute maximum boundary limit, flagging index `8192` as a terminal `Exception 02` error.
* **Objective:** Map total accessible memory map limits via automated scripts.

### Step 11 — Memory State Durability Testing

1. Issue a write payload to a specific register: `python modwrite.py`
2. Run `python modscan.py` to confirm the value was successfully written to memory.
3. Restart the core OpenPLC container or runtime service daemon thread.
4. Run `python modscan.py` again to check the current memory state.

* **Expected Result:** Written values are lost post-restart, demonstrating volatile RAM-only register operations.

### Step 12 — Concurrent Multi-Client Transaction Stress

* **Execution (Terminal 1 Loop):** `while true; do python modwrite.py; done`
* **Execution (Terminal 2 Loop):** `while true; do python modbus_client.py; done`
* **Expected Result:** Concurrent multi-socket workflows process smoothly with zero thread lockups, system crashes, or connection failures.
* **Objective:** Confirm structural thread stability under competing processing loads.

### Step 13 — Intrusion Detection Signature Engineering

1. Terminate active collection tools and open your stored trace file: `wireshark modbus-lab.pcap`
2. Analyze the unique wire traits left by fingerprint loops, binary address jumps, and out-of-bounds parameter values.
3. Translate these indicators into behavioral detection rules.

---

## Expected Findings Verification Matrix

A successful laboratory reproduction is confirmed when the local workspace metrics line up completely with the following project baselines:

```text
[✓] Core Functions Validated : FC01, FC02, FC03, FC04, FC05, FC06, FC15, FC16 Supported
[✓] Identity Privacy Bounds  : FC43 Safely Rejected (Returns Exception 01)
[✓] Memory Ceiling Offset     : High Register Upper Boundary Fixed at 8191
[✓] Protocol Error Handling  : Clean Exception Signatures (01, 02, 03 Generated)
[✓] Core Vulnerability Note  : Complete Absence of Protocol Authentication Validated
[✓] Implementation Flaw      : Fuzzing Confirms Non-Standard Coil Values Accepted

```

---

## Laboratory Replication Checklist

* [ ] OpenPLC daemon is actively initialized and serving frames.
* [ ] Network accessibility to `TCP/502` has been verified from the analysis workstation.
* [ ] Background packet captures are actively recording data streams.
* [ ] `FC03` holding register extraction executes successfully.
* [ ] `FC06` single write parameter manipulation is verified.
* [ ] `FC16` block array state modification behaves as expected.
* [ ] `FC01` bit-packed coil status queries execute successfully.
* [ ] `FC05` binary point override mechanics are verified.
* [ ] Widespread capability fingerprinting maps out the active function profile.
* [ ] `FC43` identity query rejection behavior is documented.
* [ ] Automated exception generation matches the standard protocol error matrices.
* [ ] Binary-search loops successfully converge on upper memory boundaries.
* [ ] Memory volatility is confirmed via controlled runtime service restarts.
* [ ] Concurrent connection pipelines function without service drops or thread lockups.
* [ ] Raw packet traces are extracted for detection rule engineering.

---

## Key Takeaway

This reproduction guide provides a reliable, end-to-end framework to independently verify every phase of this research initiative—moving from raw packet construction up through capability profiling, vulnerability testing, and defensive analysis. Any researcher executing these instructions in order can thoroughly assess the security posture of the Modbus environment, validate the findings independently, and leverage the custom script framework to analyze additional industrial components.
