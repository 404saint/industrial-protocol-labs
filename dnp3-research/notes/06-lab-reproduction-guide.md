# 06: Laboratory Reproduction Guide

## Overview

This guide explains how to reproduce every experiment presented throughout the DNP3 (IEEE 1815) research series. It covers environment preparation, dependency installation, execution of each laboratory phase, and basic troubleshooting.

The laboratory is intentionally self-contained and is designed to run entirely on a single host using a simulated DNP3 outstation. Every experiment described in the accompanying research documents can therefore be reproduced without requiring physical industrial hardware.

---

# 1. Laboratory Requirements

The recommended environment is a modern Linux distribution with Python 3.10 or later.

| Component                | Recommended Version                                               |
| ------------------------ | ----------------------------------------------------------------- |
| Operating System         | Arch Linux, EndeavourOS, Ubuntu, or equivalent Linux distribution |
| Python                   | 3.10 or newer                                                     |
| Packet Capture           | Wireshark or TShark                                               |
| Optional Terminal Output | `rich` Python library                                             |

Clone this repository before continuing with the setup process.

---

# 2. Environment Setup

Create a Python virtual environment and install the required dependencies.

```bash
cd dnp3-lab

python3 -m venv venv

source venv/bin/activate

pip install dnp3-python rich scapy
```

Once installation completes, all laboratory scripts can be executed from within the activated virtual environment.

---

# 3. Laboratory Workflow

The research series is organized into five independent experimental phases. Unless otherwise noted, each phase uses the standard simulated outstation (`scripts/outstation.py`).

---

# Phase 1 — Reconnaissance & Enumeration

## Objective

Observe basic DNP3 communication, validate FT3 framing, and retrieve initial protocol information from the simulated outstation.

### Step 1 — Start the Outstation

```bash
python scripts/outstation.py
```

### Step 2 — Execute the Enumeration Script

Open a second terminal with the virtual environment activated.

```bash
python scripts/recon_enum.py
```

### Expected Outcome

Successful execution should demonstrate:

* Connection to `127.0.0.1:20000`
* Successful exchange of DNP3 application messages
* Retrieval of Internal Indications (IIN)
* Basic protocol parsing

---

# Phase 2 — Control Execution

## Objective

Evaluate DNP3 control operations, including Select-Before-Operate and Direct Operate workflows.

### Step 1 — Ensure the Outstation is Running

```bash
python scripts/outstation.py
```

### Step 2 — Execute the Control Test Suite

```bash
python scripts/control_attacks.py
```

### Expected Outcome

The script exercises several control workflows and reports the resulting application responses. Depending on the scenario being tested, operations may succeed or be rejected according to the simulated implementation's control state.

---

# Phase 3 — Administrative State Transitions

## Objective

Evaluate administrative function codes including Warm Restart, Cold Restart, Stop Application, and Write Time.

### Step 1 — Start the Outstation

```bash
python scripts/outstation.py
```

### Step 2 — Execute the Administrative Test Suite

```bash
python scripts/system_attacks.py
```

### Expected Outcome

Successful execution should demonstrate:

* Warm Restart processing
* Cold Restart processing
* Time synchronization requests
* Administrative state transitions
* Corresponding protocol responses

---

# Phase 4 — Transport Reassembly & Unsolicited Messaging

## Objective

Evaluate transport-layer fragment handling and unsolicited response processing.

### Step 1 — Start the Outstation

```bash
python scripts/outstation.py
```

### Step 2 — Execute the Transport Test Suite

```bash
python scripts/transport_attacks.py
```

### Expected Outcome

The script performs several transport-layer experiments, including:

* Invalid fragment ordering
* Fragment stream initialization
* Unsolicited response processing

The exact responses will depend upon the transport state maintained by the simulated implementation.

---

# Phase 5 — Secure Authentication

## Objective

Evaluate the Secure Authentication workflow implemented within the laboratory environment.

### Step 1 — Start the Secure Authentication Outstation

```bash
python scripts/outstation-sa.py
```

### Step 2 — (Optional) Start Packet Capture

```bash
wireshark -k -i lo &
```

Recommended display filter:

```text
dnp3 || tcp.port == 20000
```

### Step 3 — Execute the Master Test Harness

```bash
python scripts/master_test_runner.py
```

### Expected Outcome

Successful execution demonstrates the Secure Authentication workflow implemented within the laboratory environment, including:

* Challenge generation
* Challenge response
* Session establishment
* Authenticated control operations

---

# 4. Script Reference

| Script                          | Purpose                                               |
| ------------------------------- | ----------------------------------------------------- |
| `scripts/outstation.py`         | Simulated DNP3 outstation used throughout Phases 1–4  |
| `scripts/outstation-sa.py`      | Secure Authentication-enabled outstation              |
| `scripts/recon_enum.py`         | Reconnaissance and protocol enumeration               |
| `scripts/control_attacks.py`    | Control execution experiments                         |
| `scripts/system_attacks.py`     | Administrative function experiments                   |
| `scripts/transport_attacks.py`  | Transport-layer and unsolicited messaging experiments |
| `scripts/master_test_runner.py` | Secure Authentication test harness                    |

---

# 5. Troubleshooting

## Port Already in Use

If the simulated outstation cannot bind to TCP port **20000**, terminate any existing process using the port.

```bash
fuser -k 20000/tcp
```

---

## CRC Verification Errors

If manually modifying packet contents, ensure that every FT3 header and payload block contains a valid CRC-16-DNP checksum.

The helper functions used by the laboratory implementation can be found in:

* `scripts/outstation.py`
* `scripts/master_test_runner.py`

---

## Script Execution

If a script is not directly executable, invoke it explicitly with Python.

```bash
python scripts/<script_name>.py
```

Alternatively, executable permissions may be added to every script.

```bash
chmod +x scripts/*.py
```

---

# 6. Next Steps

After successfully reproducing the experiments, readers are encouraged to inspect the packet captures alongside the accompanying research documents.

Each phase of the series corresponds directly to one of the laboratory scripts, allowing protocol behavior observed in Wireshark to be compared with the implementation logic and the analysis presented throughout this repository.

Because the laboratory is implemented entirely in Python, it also provides a foundation for extending the experiments, implementing additional DNP3 features, or evaluating alternative protocol behaviors within a controlled environment.
