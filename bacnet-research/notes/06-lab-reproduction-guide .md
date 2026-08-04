# Laboratory Reproduction Guide

This guide describes the laboratory environment used throughout the BACnet research series and provides the steps required to reproduce each experiment locally. The research was conducted against the open-source **BACnet Stack** demonstration server (`bacserv`), allowing all protocol interactions to be performed in an isolated environment without requiring production Building Automation Systems.

---

# Technical Environment Requirements

## Operating System

* **Host OS:** Linux (EndeavourOS, Ubuntu 22.04+, or equivalent)
* **Kernel:** Linux 5.x or newer

## Software Dependencies

Install the required development tools and utilities.

```bash
sudo pacman -S git gcc make socat tcpdump tshark python python-pip
```

Ubuntu/Debian users may install equivalent packages using `apt`.

## Python Requirements

Python **3.10** or newer is recommended.

Install the required Python package:

```bash
pip install rich
```

---

# Step 1 — Build the BACnet Protocol Stack

The laboratory targets the open-source **BACnet Stack** project.

Clone the repository:

```bash
git clone https://github.com/bacnet-stack/bacnet-stack.git
cd bacnet-stack
```

Compile the BACnet/IP demonstration binaries:

```bash
make clean
make BACNET_PORT=47808 BACDL_DEFINE=-DBACDL_BIP=1
```

Successful compilation produces the demonstration binaries under the `bin/` directory, including the `bacserv` server used throughout this research.

---

# Step 2 — Start the Laboratory Device

Open a new terminal and configure the BACnet/IP interface.

Replace `<network-interface>` with the interface connected to your laboratory network (for example `eth0`, `enp0s31f6`, or `wlan0`).

```bash
export BACNET_IP_PORT=47808
export BACNET_IFACE=<network-interface>
```

Launch the demonstration server:

```bash
./bin/bacserv 1234
```

The server exposes a BACnet/IP device with **Device Instance 1234**, matching the configuration used throughout this repository.

Leave this terminal running for the remainder of the experiments.

---

# Step 3 — Clone This Repository

Clone the research repository into a separate working directory.

The repository is organized as follows: **`see README.md`**



---

# Step 4 — Configure the Research Harnesses

Each research harness targets the BACnet/IP demonstration server.

Open each Python script and update the target address if necessary.

```python
TARGET_IP = "127.0.0.1"
TARGET_PORT = 47808
```

If your BACnet server is running on another machine, replace the loopback address with the server's IP address.

---

# Step 5 — Execute the Research Phases

Each script corresponds directly to one research document within the repository.

| Research Phase                             | Python Harness                   | Research Notes                      |
| ------------------------------------------ | -------------------------------- | ----------------------------------- |
| Phase 1 — Object Model & Property Engine   | `object-model-and-properties.py` | `01-object-model-and-properties.md` |
| Phase 2 — Priority Array Arbitration       | `priority-array-arbitration.py`  | `02-priority-array-arbitration.md`  |
| Phase 3 — Routing, BBMD & Subnet Traversal | `bbmd-boundary-traversal.py`     | `03-routing-bbmd-subnets.md`        |
| Phase 4 — COV, Alarms & BACnet/SC          | `cov-alarms-sc-transition.py`    | `04-cov-alarms-and-modern-sc.md`    |

Run each harness individually.

### Phase 1

```bash
python object-model-and-properties.py
```

### Phase 2

```bash
python priority-array-arbitration.py
```

### Phase 3

```bash
python bbmd-boundary-traversal.py
```

### Phase 4

```bash
python cov-alarms-sc-transition.py
```

Each harness produces terminal output that corresponds directly to the observations documented in the associated research paper.

---

# Optional Packet Capture

Packet captures may be collected alongside the experiments using `tcpdump`.

```bash
sudo tcpdump -i <network-interface> -nn udp port 47808 -w bacnet_capture.pcap
```

Alternatively, Wireshark or `tshark` may be used to inspect BVLL, NPDU, and APDU traffic during execution.

---

# Expected Laboratory Behavior

The demonstration server used during this research is intentionally lightweight and does not implement every feature defined by the BACnet standard. Consequently, reproduced observations may include:

* Successful `ReadProperty` and `WriteProperty` exchanges.
* Object enumeration through `Object_List`.
* Priority Array manipulation.
* Foreign Device Registration acknowledgements.
* Change-of-Value (COV) subscription notifications.
* Limited router discovery functionality.
* No BACnet Secure Connect (BACnet/SC) listener by default.

These behaviors are consistent with the laboratory environment used throughout this research series and provide a controlled platform for studying BACnet protocol mechanics.

---

# Disclaimer

This laboratory was developed exclusively for educational and defensive security research. All experiments were conducted against an intentionally deployed BACnet/IP demonstration server in an isolated environment. No testing was performed against production Building Automation Systems or third-party infrastructure.
