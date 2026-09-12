# PROFINET Security & Protocol Analysis Lab Reproduction Guide

This guide reproduces the isolated Linux lab used for the PROFINET protocol and security research series.

The environment consists of two network namespaces connected by a virtual Ethernet pair:

* `ns-controller`: controller-side audit and packet-capture environment
* `ns-device`: device-side target or traffic-generation environment

The laboratory uses two execution models:

1. The `p-net` `pn_dev` sample application is used as the device-side endpoint for Phases 1, 2, and 4.
2. A separate Layer 2 traffic generator is used for Phase 3 to produce controlled PROFINET RT-like frames for wire-level analysis.

The Phase 3 generator is a packet-generation harness. It is not a complete PROFINET IO-Device implementation and does not establish an Application Relationship, negotiate IOCRs, maintain a process image, or demonstrate receiver-side acceptance.

## 1. Prerequisites and Dependencies

## Operating System

A Linux system with support for:

* Network namespaces
* Virtual Ethernet interfaces
* Raw Layer 2 sockets
* Promiscuous interfaces
* Packet capture

The following packages are required:

* `iproute2`
* `iputils` or equivalent basic networking utilities
* `tcpdump`
* `net-tools`, if legacy interface inspection commands are required
* Python 3.x
* Python Scapy
* A working C build environment for compiling `p-net`

On Debian-based systems, the basic dependencies can be installed with:

```bash
sudo apt update
sudo apt install -y \
    iproute2 \
    iputils-ping \
    net-tools \
    tcpdump \
    python3 \
    python3-pip \
    build-essential
```

Install Scapy with:

```bash
python3 -m pip install scapy
```

Depending on the local Python installation, the distribution package may be preferable:

```bash
sudo apt install -y python3-scapy
```

## Target Stack

The laboratory requires a compiled `p-net` sample application capable of producing the `pn_dev` executable.

The expected executable location used in this guide is:

```text
bin/pn_dev
```

The target stack must be configured to use the device-side interface:

```text
veth-device
```

The exact command-line arguments and configuration files may vary depending on the `p-net` version and local build configuration.

### Repository Layout

The commands in this guide assume the following project structure:

```text
profinet-lab/
├── bin/
│   └── pn_dev
├── scripts/
│   ├── 01_dcp_audit.py
│   ├── 01_lldp_topology.py
│   ├── 02_rpc_ar_connect.py
│   ├── 02_rpc_full_handshake.py
│   ├── phase3_profinet_rt_analysis.py
│   ├── pn_rt_traffic_generator.py
│   ├── phase4_profinet_audit.py
│   └── parse_phase4_pcap.py
├── pcaps/
├── notes/
└── lab-setup.sh
```

Create the capture directory before running any phase:

```bash
mkdir -p pcaps
```

All commands below should be executed from the repository root unless stated otherwise.

## 2. Lab Network Design

The laboratory uses a direct veth connection:

```text
┌──────────────────────────────┐
│ ns-controller                │
│                              │
│ veth-controller              │
│ 192.168.1.10/24              │
│ MAC 02:00:00:00:00:01        │
└──────────────┬───────────────┘
               │
               │ Virtual Ethernet Pair
               │
┌──────────────┴───────────────┐
│ ns-device                    │
│                              │
│ veth-device                  │
│ 192.168.1.20/24              │
│ MAC 02:00:00:00:00:02        │
└──────────────────────────────┘
```

The IP addresses are provided for protocols and tools that require IPv4. The primary communication paths investigated in the research remain Layer 2 or directly bound to Layer 2 and UDP transport. The namespaces are isolated from the host network. No default gateway is required for the experiments.

## 3. Step 1: Lab Environment Provisioning

Create the following setup script:

```bash
cat << 'EOF' > lab-setup.sh
#!/usr/bin/env bash
set -euo pipefail

CONTROLLER_NS="ns-controller"
DEVICE_NS="ns-device"

CONTROLLER_IF="veth-controller"
DEVICE_IF="veth-device"

CONTROLLER_MAC="02:00:00:00:00:01"
DEVICE_MAC="02:00:00:00:00:02"

CONTROLLER_IP="192.168.1.10/24"
DEVICE_IP="192.168.1.20/24"

# Remove an incomplete previous setup if either namespace exists.
if ip netns list | awk '{print $1}' | grep -qx "${CONTROLLER_NS}"; then
    ip netns del "${CONTROLLER_NS}"
fi

if ip netns list | awk '{print $1}' | grep -qx "${DEVICE_NS}"; then
    ip netns del "${DEVICE_NS}"
fi

# Create isolated namespaces.
ip netns add "${CONTROLLER_NS}"
ip netns add "${DEVICE_NS}"

# Create the virtual Ethernet pair.
ip link add "${CONTROLLER_IF}" type veth peer name "${DEVICE_IF}"

# Move each endpoint into its namespace.
ip link set "${CONTROLLER_IF}" netns "${CONTROLLER_NS}"
ip link set "${DEVICE_IF}" netns "${DEVICE_NS}"

# Configure the controller namespace.
ip netns exec "${CONTROLLER_NS}" ip link set lo up
ip netns exec "${CONTROLLER_NS}" ip link set \
    "${CONTROLLER_IF}" address "${CONTROLLER_MAC}"
ip netns exec "${CONTROLLER_NS}" ip addr add \
    "${CONTROLLER_IP}" dev "${CONTROLLER_IF}"
ip netns exec "${CONTROLLER_NS}" ip link set \
    "${CONTROLLER_IF}" up

# Configure the device namespace.
ip netns exec "${DEVICE_NS}" ip link set lo up
ip netns exec "${DEVICE_NS}" ip link set \
    "${DEVICE_IF}" address "${DEVICE_MAC}"
ip netns exec "${DEVICE_NS}" ip addr add \
    "${DEVICE_IP}" dev "${DEVICE_IF}"
ip netns exec "${DEVICE_NS}" ip link set \
    "${DEVICE_IF}" up

# Enable promiscuous mode for packet inspection and raw L2 testing.
ip netns exec "${CONTROLLER_NS}" ip link set \
    "${CONTROLLER_IF}" promisc on
ip netns exec "${DEVICE_NS}" ip link set \
    "${DEVICE_IF}" promisc on

echo "[+] Namespaces created:"
echo "    ${CONTROLLER_NS}: ${CONTROLLER_IF} ${CONTROLLER_IP}"
echo "    ${DEVICE_NS}:     ${DEVICE_IF} ${DEVICE_IP}"

echo
echo "[+] Controller interface:"
ip netns exec "${CONTROLLER_NS}" ip -br link show "${CONTROLLER_IF}"
ip netns exec "${CONTROLLER_NS}" ip -br addr show "${CONTROLLER_IF}"

echo
echo "[+] Device interface:"
ip netns exec "${DEVICE_NS}" ip -br link show "${DEVICE_IF}"
ip netns exec "${DEVICE_NS}" ip -br addr show "${DEVICE_IF}"

echo
echo "[+] PROFINET isolated Layer 2 lab environment successfully provisioned."
EOF

chmod +x lab-setup.sh
sudo ./lab-setup.sh
```

## Verify Namespace Connectivity

Confirm that both namespaces exist:

```bash
sudo ip netns list
```

Expected output should include:

```text
ns-controller
ns-device
```

Inspect both interfaces:

```bash
sudo ip netns exec ns-controller ip -br addr
sudo ip netns exec ns-device ip -br addr
```

Test the IP path:

```bash
sudo ip netns exec ns-controller ping -c 3 192.168.1.20
```

The IP connectivity test is only a basic namespace verification step. It does not validate PROFINET functionality.

Confirm the Layer 2 EtherType can be observed:

```bash
sudo ip netns exec ns-controller \
    tcpdump -i veth-controller -nn -e -c 1 'ether proto 0x8892'
```

This command may wait until a PROFINET-related frame is transmitted.

## 4. Step 2: Target Execution Strategy

The target process depends on the research phase.

### Phases 1, 2, and 4

Run the `p-net` sample application inside `ns-device`:

```bash
sudo ip netns exec ns-device \
    ./bin/pn_dev veth-device
```

If the application requires a configuration file or additional arguments, provide them according to the local `p-net` build. Keep this process running while the corresponding controller-side audit scripts execute.

### Phase 3

Phase 3 uses a separate traffic-generation harness:

```bash
sudo ip netns exec ns-device \
    python3 scripts/pn_rt_traffic_generator.py veth-device
```

This generator constructs and transmits controlled Layer 2 frames. It does not represent a complete controller/device cyclic I/O exchange.

The generator should be treated as an independent traffic source for:

* Frame ID analysis
* Process-data payload layout
* Cycle-counter and status-field inspection
* Controlled payload injection
* Timing and watchdog-model experiments

## 5. Packet Capture Workflow

Packet capture should be started before the audit script or target action that generates the traffic. Use a separate terminal for each capture. The capture process should be stopped explicitly after the experiment completes.

A general capture command is:

```bash
sudo ip netns exec ns-controller \
    tcpdump -i veth-controller -nn -e -s 0 \
    -w pcaps/<capture-name>.pcap \
    '<capture-filter>'
```

The options mean:

* `-i`: capture interface
* `-nn`: disable name and service resolution
* `-e`: include Ethernet headers
* `-s 0`: capture the complete packet
* `-w`: write packets to a PCAP file

To stop a capture running in the foreground, press:

```text
Ctrl+C
```

The capture summary should be recorded in the research notes, including:

* Number of packets captured
* Number of packets received by the filter
* Number of packets dropped by the kernel
* Capture start and end times
* Interface used
* BPF filter used

## 6. Phase 1: Discovery and Topology Audit

## Objective

Inspect Layer 2 discovery and configuration traffic, including:

* DCP Identify behavior
* DCP station-name information
* Vendor and device identifiers
* IP configuration blocks
* LLDP chassis and port information
* Discovery traffic before ordinary IP-based communication

## Target

Run: `p-net pn_dev` inside: `ns-device`.
## Start the Target

In Terminal A:

```bash
sudo ip netns exec ns-device \
    ./bin/pn_dev veth-device
```

## Start the Capture

In Terminal B:

```bash
sudo ip netns exec ns-controller \
    tcpdump -i veth-controller -nn -e -s 0 \
    -w pcaps/phase1_dcp_lldp.pcap \
    'ether proto 0x8892 or ether proto 0x88cc'
```

### Execute the DCP Audit

In Terminal C:

```bash
sudo ip netns exec ns-controller \
    python3 scripts/01_dcp_audit.py
```

The audit should generate DCP discovery or configuration-related traffic.

## Execute the LLDP Audit

After the DCP test completes, run:

```bash
sudo ip netns exec ns-controller \
    python3 scripts/01_lldp_topology.py
```

## Stop the Capture

Return to Terminal B and press: `Ctrl+C`

## Expected Evidence

The resulting PCAP should be inspected for:

* EtherType `0x8892` for PROFINET-related DCP traffic
* EtherType `0x88CC` for LLDP
* DCP service and service-type fields
* Name of Station option and suboption
* Vendor and device identifiers
* IP configuration blocks
* LLDP chassis ID
* LLDP port ID
* LLDP TTL
* System Name

The capture should be treated as the authoritative source for the observed wire format. Application output may be used as supporting evidence, but it should not replace packet-level validation.

## 7. Phase 2: Parameterization and Application-Relation Analysis

## Objective

Analyze the acyclic communication path used for application-relation establishment, including:

* UDP port `34964`
* DCE/RPC request and response structures
* Interface UUID
* Operation number
* Application Relationship identifiers
* AR, IOCR, and AlarmCR block construction
* Device-side state progression where observable

## Target

Run: `p-net pn_dev` inside: `ns-device` . 

## Start the Target

In Terminal A:

```bash
sudo ip netns exec ns-device \
    ./bin/pn_dev veth-device
```

## Start the Capture

In Terminal B:

```bash
sudo ip netns exec ns-controller \
    tcpdump -i veth-controller -nn -e -s 0 \
    -w pcaps/phase2_rpc_ar.pcap \
    'udp port 34964'
```

## Execute the Initial AR Test

In Terminal C:

```bash
sudo ip netns exec ns-controller \
    python3 scripts/02_rpc_ar_connect.py
```

## Execute the Full Handshake Test

After the initial test completes:

```bash
sudo ip netns exec ns-controller \
    python3 scripts/02_rpc_full_handshake.py
```

## Stop the Capture

Press: `Ctrl+C` in Terminal B.

### Expected Evidence

The PCAP should be inspected for:

* UDP source and destination ports
* DCE/RPC version fields
* DCE/RPC packet type
* Interface UUID
* Operation number
* Request and response association
* Object UUID
* Application-level block contents where the dissector exposes them
* ARUUID values
* IOCRBlockReq structures
* AlarmCRBlockReq structures

The capture may independently prove the DCE/RPC exchange while application output provides additional evidence about block construction and target-side handling. Do not infer that every application-level block was accepted solely because a request and response were observed. Acceptance should be supported by target logs, a valid response structure, or another independently observable result.

## 8. Phase 3: Real-Time Cyclic I/O and Traffic Generation

## Objective

Inspect the wire-level structure of PROFINET RT-like traffic and evaluate:

* EtherType `0x8892`
* Frame ID placement
* Cyclic process-data payload
* Actual PROFINET cycle-counter location
* DataStatus
* TransferStatus
* Application-level sequence fields
* Controlled payload injection
* Timing behavior
* Watchdog-model calculations

## Experimental Boundary

Phase 3 uses: `pn_rt_traffic_generator.py` rather than the `pn_dev` sample application.

The generator creates controlled Layer 2 frames with:

* Ethernet header
* PROFINET RT EtherType
* Frame ID
* 40-byte process-data region
* Cycle Counter
* DataStatus
* TransferStatus

The generator does not:

* Establish an Application Relationship
* Negotiate an IOCR
* Implement a complete PROFINET controller
* Implement a complete PROFINET IO-Device
* Maintain a negotiated process image
* Demonstrate receiver-side acceptance
* Prove that a controller updates its process image
* Prove that a controller changes state in response to generated frames

## Start the Capture

In Terminal A:

```bash
sudo ip netns exec ns-controller \
    tcpdump -i veth-controller -nn -e -s 0 \
    -w pcaps/phase3_profinet_rt.pcap \
    'ether proto 0x8892'
```

## Start the RT Generator

In Terminal B:

```bash
sudo ip netns exec ns-device \
    python3 scripts/pn_rt_traffic_generator.py veth-device
```

## Run the RT Analyzer

In Terminal C:

```bash
sudo ip netns exec ns-controller \
    python3 scripts/phase3_profinet_rt_analysis.py veth-controller
```

If the analyzer is designed to inspect an existing PCAP rather than capture live traffic, run it after the generator completes using the appropriate PCAP path.

## Stop the Capture

Press: `Ctrl+C` in Terminal A.

## Expected Evidence

The PCAP should be inspected for:

* EtherType `0x8892`
* Frame ID values
* Process-data payload contents
* Actual cycle-counter bytes
* DataStatus values
* TransferStatus values
* Inter-frame timing
* Application-level sequence fields
* Presence or absence of additional diagnostic traffic

The actual PROFINET cycle counter must be located from the protocol trailer, not inferred from a sequential value inside the process-data payload.

For the current generator layout, the RT payload begins immediately after the Ethernet header:

```text
Offset relative to RT payload start  | Field
-------------------------------------|----------------------------
0–1                                  | Frame ID
2–41                                 | 40-byte IO/application data
42–43                                | Cycle Counter
44                                   | DataStatus
45                                   | TransferStatus
``` 

The application sequence field used by the generator is part of the IO/application data. It is not the PROFINET cycle counter.

## Watchdog Model

The watchdog calculation used in this phase is a laboratory model:

```text
Watchdog Model = Cycle Time × Retention Factor
```

For example:

```text
Cycle Time:       32 ms
Retention Factor: 3
Watchdog Model:   96 ms
```

This value is not a universal PROFINET watchdog threshold. Any claim about actual controller behavior requires independent controller-side evidence.

## 9. Phase 4: Netload, Spoofing, and Resiliency Audit

## Objective

Generate controlled Layer 2 inputs against the `p-net` environment, including:

* High-rate EtherType `0x8892` traffic
* DCP-like station-name frames
* Crafted malformed Frame ID values
* Truncated payloads
* Capture-level evidence of traffic timing and endpoint responses

### Experimental Boundary

Phase 4 uses: `p-net pn_dev` as the device-side implementation. The Scapy-based audit harness is an independent traffic source. The PCAP proves what was transmitted and captured. It does not, by itself, prove that `pn_dev` accepted, rejected, parsed, logged, or acted upon the frames.

Endpoint behavior should only be reported when supported by:

* Target logs
* A visible state transition
* A response packet
* A diagnostic or alarm packet
* A subsequent protocol exchange
* Another independently observable result

## Start the Target

In Terminal A:

```bash
sudo ip netns exec ns-device \
    ./bin/pn_dev veth-device
```

## Start the Capture

In Terminal B:

```bash
sudo ip netns exec ns-controller \
    tcpdump -i veth-controller -nn -e -s 0 \
    -w pcaps/phase4_profinet_audit.pcap \
    'ether proto 0x8892'
```

## Execute the Resiliency Suite

In Terminal C:

```bash
sudo ip netns exec ns-controller \
    python3 scripts/phase4_profinet_audit.py veth-controller
```

The suite performs three controlled stages:

1. Netload-oriented Layer 2 burst generation
2. DCP-like station-name traffic from a forged source MAC
3. Crafted malformed frames using Frame ID `0x00FF` and truncated payloads

## Stop the Capture

Press: `Ctrl+C`  in Terminal B.

## Parse the PCAP

Run the parser from the repository root:

```bash
python3 scripts/parse_phase4_pcap.py
```

Expected parser output should identify the broad traffic categories:

```text
[*] Total Packets Captured: 508

--- PCAP Analysis Breakdown ---
[+] PI Netload Class III Burst Packets  : 500
[+] DCP Identify Response Packets       : 3
[+] Malformed Frame ID (0x00FF) Packets : 5
[+] Other / Background RT Frames        : 0
```

The parser's categories are traffic classifications based on byte patterns. They should not automatically be interpreted as proof of endpoint-side handling.

For example:

* EtherType `0x8892` alone does not prove that a packet is a valid PROFINET RT frame.
* A payload beginning with `0x03 0x01` is classified by the parser as DCP-like traffic, but the parser must also verify the expected DCP Frame ID and complete PDU structure before calling it a valid DCP packet.
* A Frame ID of `0x00FF` is treated as malformed for this test. The capture alone does not prove that the target rejected it or generated a protocol warning.

## 10. PCAP Validation Procedure

Each phase should include a post-capture validation pass.

### Confirm the Capture Exists

```bash
ls -lh pcaps/
```

### Inspect Link-Layer Headers

```bash
tcpdump -nn -e -r pcaps/phase1_dcp_lldp.pcap
```

Replace the filename for the phase being analyzed.

### Inspect Raw Hexadecimal Data

```bash
tcpdump -nn -e -XX -r pcaps/phase3_profinet_rt.pcap
```

### Inspect Packet Counts

```bash
capinfos pcaps/phase3_profinet_rt.pcap
```

If `capinfos` is unavailable, use:

```bash
tcpdump -nn -r pcaps/phase3_profinet_rt.pcap | wc -l
```

### Inspect with TShark

Where supported:

```bash
tshark -r pcaps/phase3_profinet_rt.pcap
```

For selected fields:

```bash
tshark -r pcaps/phase3_profinet_rt.pcap \
    -T fields \
    -e frame.number \
    -e frame.time_epoch \
    -e eth.src \
    -e eth.dst \
    -e eth.type
```

The available PROFINET fields depend on the installed Wireshark and TShark version. If a field is not exposed by the dissector, inspect the raw bytes directly and document the manual offset calculation.

## 11. Evidence Recording Requirements

For every phase, record the following:

## Environment

* Host operating system
* Kernel version
* Python version
* Scapy version
* Wireshark or TShark version
* `p-net` version or commit
* Interface names
* Namespace names
* MAC addresses
* IP addresses

## Execution

* Exact command used
* Script version or commit
* Target configuration
* Capture filter
* Start and stop time
* Number of packets generated
* Number of packets captured
* Kernel or interface drop count

## Packet Evidence

* EtherType
* Source and destination MAC
* VLAN presence or absence
* Frame ID
* Transport protocol and port
* DCE/RPC fields
* DCP service fields
* RT trailer fields
* Payload offsets
* Timing measurements
* Response or diagnostic traffic

## Interpretation

Every conclusion should be categorized as one of the following:

* Directly observed on the wire
* Reported by the application
* Calculated from captured values
* Inferred from protocol behavior
* Not demonstrated

This prevents generated script labels from being mistaken for target-side observations.

## 12. Lab Teardown

Create a teardown script:

```bash
cat << 'EOF' > lab-teardown.sh
#!/usr/bin/env bash
set -euo pipefail

if ip netns list | awk '{print $1}' | grep -qx "ns-controller"; then
    sudo ip netns del ns-controller
fi

if ip netns list | awk '{print $1}' | grep -qx "ns-device"; then
    sudo ip netns del ns-device
fi

echo "[+] PROFINET laboratory namespaces removed."
EOF

chmod +x lab-teardown.sh
```

Run it with:

```bash
./lab-teardown.sh
```

The namespace deletion also removes the veth interfaces contained within them.

If a target process is still running, stop it before teardown: `Ctrl+C` or terminate it from another terminal:

```bash
sudo pkill -f pn_dev
```

Use the broad `pkill` command carefully if other `pn_dev` processes are running outside this laboratory.

## 13. Reproduction Notes

The laboratory is intentionally divided into two complementary models.

Phases 1, 2, and 4 use the `p-net` sample stack to investigate discovery, acyclic communication, and externally generated Layer 2 inputs against an actual PROFINET-oriented implementation.

Phase 3 uses an independent traffic generator because the available `pn_dev` configuration did not provide a suitable cyclic RT stream for the intended wire-level analysis. Its results therefore describe the structure and timing of generated RT-like traffic rather than complete controller/device interoperability.

The PCAP is the primary evidence source for packet structure, field locations, timing, and traffic presence. Application output is supplementary and should only be treated as endpoint evidence when it is clearly produced by the target implementation rather than by the audit harness itself.

## 14. Reproduction Checklist

At each phase:

* [ ] Namespaces exist
* [ ] Interfaces are up
* [ ] MAC addresses are correct
* [ ] IP connectivity has been verified where required
* [ ] Target process is running in the correct namespace
* [ ] Capture directory exists
* [ ] Packet capture has started
* [ ] Audit script is using the intended interface
* [ ] Capture filter matches the phase objective
