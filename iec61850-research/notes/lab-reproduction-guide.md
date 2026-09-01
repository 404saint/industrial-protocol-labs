# IEC 61850 Process Bus & MMS Virtual Lab: Reproduction Guide

This guide documents the Linux environment used to reproduce the IEC 61850 research phases covering SCL configuration, MMS, GOOSE, and Sampled Values (SV).

The lab uses `libiec61850`, Linux network namespaces, virtual Ethernet pairs, and Linux bridges to create an isolated environment containing simulated IEDs, subscribers, and process-bus participants.

The goal is not to reproduce a vendor-specific substation. The goal is to provide a small, inspectable environment in which the protocol behavior discussed throughout the research can be observed directly.

> **Lab note:** The MMS and process-bus portions of this environment required slightly different network arrangements. In particular, GOOSE and SV operate directly over Ethernet and therefore depend on the correct Layer 2 interface being passed to the `libiec61850` examples. If the Layer 2 interfaces are recreated, renamed, or attached to a different bridge, the examples may stop receiving traffic even though the IP configuration appears correct.

---

## 1. Lab Architecture

The core environment consists of isolated Linux network namespaces connected through virtual Ethernet pairs.

A simplified version of the topology is:

```text
                         HOST
                           |
                    br-processbus
           ______________|_____________
           |             |            |
           |             |            |
        ns-ied1        ns-sub1      ns-mu1
       192.168.1.10   192.168.1.20   SV Publisher
           |              |             |
        veth-ied1      veth-sub1     veth-mu1
           |              |             |
           +--------------+-------------+
                     Layer 2 segment
```

The simulated participants serve different purposes:

| Namespace       | Role                         | Primary traffic        |
| --------------- | ---------------------------- | ---------------------- |
| `ns-ied1`       | Soft IED / server            | MMS, GOOSE             |
| `ns-sub1`       | Subscriber / research client | MMS, GOOSE/SV analysis |
| `ns-mu1`        | Merging Unit simulation      | Sampled Values         |
| `br-processbus` | Layer 2 process-bus segment  | GOOSE / SV             |

The IP addresses used for the MMS experiments were:

```text
IED       192.168.1.10/24
Subscriber 192.168.1.20/24
```

The process-bus traffic itself does not depend on these IP addresses. GOOSE and SV are Ethernet Layer 2 protocols.

---

# 2. Software Requirements

The lab was built around:

* Linux network namespaces
* `iproute2`
* `tcpdump`
* Wireshark / TShark
* Python 3
* scapy
* rich
* CMake
* GCC / standard build tooling
* `libiec61850` 1.6.2

The research used the `libiec61850` example applications rather than a commercial IED simulator.

Clone and build the library:

```bash
cd ~/Desktop/iec61850-lab

git clone https://github.com/mz-automation/libiec61850.git

cd libiec61850

mkdir build
cd build

cmake ..
make
```

The resulting example binaries are located below:

```text
libiec61850/build/examples/
```

The exact path may differ if the repository is cloned somewhere else.

---

# 3. Creating the Network Namespaces

Create the namespaces used by the lab:

```bash
sudo ip netns add ns-ied1
sudo ip netns add ns-sub1
sudo ip netns add ns-mu1
```

Create the process-bus bridge:

```bash
sudo ip link add name br-processbus type bridge
sudo ip link set dev br-processbus up
```

Create virtual Ethernet pairs:

```bash
sudo ip link add veth-ied1 type veth peer name veth-ied1-br
sudo ip link add veth-sub1 type veth peer name veth-sub1-br
sudo ip link add veth-mu1 type veth peer name veth-mu1-br
```

Attach the bridge-side interfaces:

```bash
sudo ip link set veth-ied1-br master br-processbus
sudo ip link set veth-sub1-br master br-processbus
sudo ip link set veth-mu1-br master br-processbus
```

Move the other ends into their respective namespaces:

```bash
sudo ip link set veth-ied1 netns ns-ied1
sudo ip link set veth-sub1 netns ns-sub1
sudo ip link set veth-mu1 netns ns-mu1
```

Bring the bridge-side interfaces up:

```bash
sudo ip link set veth-ied1-br up
sudo ip link set veth-sub1-br up
sudo ip link set veth-mu1-br up
```

---

# 4. Configure the Namespace Interfaces

The loopback interface should be brought up explicitly inside each namespace.

For the IED:

```bash
sudo ip netns exec ns-ied1 ip link set dev lo up
sudo ip netns exec ns-ied1 ip link set dev veth-ied1 up
sudo ip netns exec ns-ied1 ip addr add 192.168.1.10/24 dev veth-ied1
```

For the subscriber:

```bash
sudo ip netns exec ns-sub1 ip link set dev lo up
sudo ip netns exec ns-sub1 ip link set dev veth-sub1 up
sudo ip netns exec ns-sub1 ip addr add 192.168.1.20/24 dev veth-sub1
```

For the merging-unit namespace:

```bash
sudo ip netns exec ns-mu1 ip link set dev lo up
sudo ip netns exec ns-mu1 ip link set dev veth-mu1 up
```

At this point, verify the interfaces:

```bash
sudo ip netns exec ns-ied1 ip addr
sudo ip netns exec ns-sub1 ip addr
sudo ip netns exec ns-mu1 ip addr
```

Verify connectivity between the MMS endpoints:

```bash
sudo ip netns exec ns-sub1 ping -c 3 192.168.1.10
```

A successful ping confirms the basic IP path. It does **not** confirm that MMS, GOOSE, or SV is working.

---

# 5. Optional Bridge IP

During the research, an address was also assigned to the process-bus bridge:

```bash
sudo ip addr add 192.168.1.254/24 dev br-processbus
```

This address is not required for GOOSE or SV themselves. It was useful for inspecting and interacting with the bridge from the host.

Verify:

```bash
ip addr show br-processbus
```

---

# 6. Start the Soft IED

The primary MMS target used during the research was the `server_example_basic_io` example.

Start it inside `ns-ied1`:

```bash
cd ~/Desktop/iec61850-lab/libiec61850/build

sudo ip netns exec ns-ied1 \
    ./examples/server_example_basic_io/server_example_basic_io
```

The exact invocation can depend on the example build and version.

In the working environment, the server reported:

```text
Using libIEC61850 version 1.6.2
```

The important point is that the server must be running **inside the namespace containing the IED interface**.

Check whether TCP/102 is listening:

```bash
sudo ip netns exec ns-ied1 ss -lntp | grep ':102'
```

The expected result is a listener on TCP port `102`.

MMS uses ISO-on-TCP and therefore does not behave like an ordinary application protocol directly placed on TCP.

The relevant stack is approximately:

```text
MMS
ISO Presentation
ISO Session
COTP
TPKT
TCP
IP
Ethernet
```

---

# 7. Verify MMS From the Subscriber Namespace

The research client was executed from `ns-sub1`, allowing the subscriber to behave as a separate network participant.

For example:

```bash
sudo ip netns exec ns-sub1 \
    python3 ~/Desktop/iec61850-lab/scripts/phase2_mms_cwrapper.py
```

The successful run produced:

```text
[+] Status: MMS Session & Application Association Established!

IED: 192.168.1.10:102
└── Domain (Logical Device): simpleIOGenericIO
    ├── GGIO1
    ├── GGIO1$CF
    ├── GGIO1$CF$Mod
    ├── GGIO1$CF$Mod$ctlModel
    ├── GGIO1$CF$SPCSO1
    ├── GGIO1$CF$SPCSO1$ctlModel
    ├── GGIO1$CF$SPCSO2
    ├── GGIO1$CF$SPCSO2$ctlModel
    └── ... 296 more MMS variables hidden
```

The complete namespace enumeration contained **304 MMS variables** in the tested model.

If the MMS client refuses to connect, check the following before changing the application code:

```bash
sudo ip netns exec ns-ied1 ip addr
sudo ip netns exec ns-ied1 ss -lntp | grep ':102'
sudo ip netns exec ns-sub1 ping -c 3 192.168.1.10
```

This separates an application problem from a namespace or interface problem.

---

# 8. Capturing MMS Traffic

MMS traffic was captured from the subscriber interface during the enumeration tests.

For example:

```bash
sudo ip netns exec ns-sub1 \
    tcpdump -i veth-sub1 -nn -w \
    ~/Desktop/iec61850-lab/pcaps/phase2_mms_enumeration.pcap \
    port 102
```

Then run the MMS test from another terminal:

```bash
sudo ip netns exec ns-sub1 \
    python3 ~/Desktop/iec61850-lab/scripts/phase2_mms_cwrapper.py
```

The resulting capture can be opened in Wireshark and inspected for:

```text
TCP
TPKT
COTP
ISO Session
ISO Presentation
ACSE
MMS
```

This capture was used to study the association and `GetNameList` enumeration behavior described in Phase 2.

---

# 9. Phase 1: SCL Parser Testing

The SCL experiments operate at the engineering/configuration layer rather than directly on the process bus.

The Phase 1 harness generates and processes mutated SCL XML configurations:

```bash
sudo python3 scripts/phase1_scl.py
```

The tests included:

1. XML DTD/entity expansion testing.
2. Dataset Functional Constraint mutation.
3. Logical Node class mutation.

The XXE test used a local file URI such as:

```xml
<!ENTITY xxeTest SYSTEM "file:///etc/passwd">
```

The research environment demonstrated entity expansion by exposing content from the local filesystem during parsing.

This finding should be interpreted as an **implementation-level parser vulnerability**, not as an inherent vulnerability in the IEC 61850 SCL specification.

The second test modified an FCDA definition:

```xml
<FCDA
    ldInst="LD0"
    lnClass="GGIO"
    lnInst="1"
    doName="AnIn1"
    daName="mag.f"
    fc="MX"/>
```

to:

```xml
<FCDA
    ldInst="LD0"
    lnClass="XCBR"
    lnInst="1"
    doName="AnIn1"
    daName="mag.f"
    fc="ST"/>
```

The resulting schema divergence was then considered against the live MMS/GOOSE object model.

---

# 10. Phase 2: MMS Namespace Enumeration

The Phase 2 harness establishes an MMS association and enumerates the target namespace using `GetNameList`.

Run:

```bash
sudo ip netns exec ns-sub1 \
    python3 ~/Desktop/iec61850-lab/scripts/phase2_mms_cwrapper.py
```

The important result is not simply that TCP/102 is open. The test demonstrates that an unauthenticated client can progress through the MMS association and obtain the server's object namespace.

The research target exposed:

```text
Logical Device:
    simpleIOGenericIO

Logical Node:
    GGIO1

Enumerated MMS variables:
    304
```

This namespace information was subsequently used to identify candidate control objects for Phase 3.

---

# 11. Phase 3: MMS Control Testing

The Phase 3 harness tests several access paths:

```bash
sudo ip netns exec ns-sub1 \
    python3 ~/Desktop/iec61850-lab/scripts/phase3_mms_control_abuse.py
```

The test included direct MMS variable writes and higher-level ACSI control operations.

The observed results were:

| Test                               | Result     |
| ---------------------------------- | ---------- |
| Direct write to control `ctlVal`   | Refused    |
| Write to read-only measured value  | Refused    |
| ACSI `ControlObjectClient_operate` | Accepted   |
| Post-operation state verification  | Successful |
| MMS file directory enumeration     | Refused    |

This is an important part of the research because the results were **not uniformly permissive**.

The raw MMS write path was rejected by the server's object/data-type constraints, while the higher-level ACSI control operation was accepted by the tested configuration. That behavior is more useful than simply labeling the entire MMS stack "vulnerable."

---

# 12. MMS File Service Testing

The file service was tested using the `libiec61850` file-service example:

```bash
sudo ip netns exec ns-sub1 \
    ~/Desktop/iec61850-lab/libiec61850/build/examples/iec61850_client_example_files/file-tool \
    -h 192.168.1.10 -p 102 dir
```

The tested server returned an error when attempting to enumerate the remote root directory.

The result was:

```text
/    REFUSED
MMS error: 99
```

This indicates that the particular server profile used for the experiment did not expose a usable MMS file directory. Therefore, this experiment should **not** be interpreted as proof of successful remote file extraction.

Instead, it demonstrates that MMS file services constitute a separate attack surface whose availability depends on server configuration and file-service initialization.

---

# 13. Process Bus Configuration

GOOSE and SV require a different approach from MMS. MMS is transported through TCP/IP.

GOOSE and SV are Layer 2 Ethernet protocols:

```text
GOOSE -> EtherType 0x88B8
SV    -> EtherType 0x88BA
```

Consequently, the process-bus applications must be given access to the correct Ethernet interface. This is the part of the lab that is most sensitive to interface configuration.

Before starting the examples, inspect the bridge:

```bash
ip link show br-processbus
bridge link
```

Then inspect the namespace interfaces:

```bash
sudo ip netns exec ns-ied1 ip link
sudo ip netns exec ns-sub1 ip link
sudo ip netns exec ns-mu1 ip link
```

The interfaces passed to the `libiec61850` examples must correspond to the interfaces actually connected to the process-bus bridge.

---

# 14. Start the GOOSE Publisher / Server

The working environment used the GOOSE example with the IED's namespace interface:

```bash
sudo ip netns exec ns-ied1 \
    ./examples/server_example_goose/server_example_goose \
    --ifc veth-ied1
```

The application reported:

```text
Using GOOSE interface: veth-ied1
```

This is important. The GOOSE application is being told which interface to use for raw Ethernet traffic. The interface name is therefore part of the lab configuration, not merely documentation.

---

# 15. Start the Sampled Values Publisher

The SV publisher was run from the merging-unit namespace:

```bash
sudo ip netns exec ns-mu1 \
    ./examples/sv_publisher/sv_publisher_example \
    veth-mu1
```

The application reported:

```text
Using interface veth-mu1
```

At this point, the process bus contains participants capable of generating Layer 2 traffic.

---

# 16. Capture GOOSE and SV

Capture directly from the process-bus bridge:

```bash
sudo tcpdump -i br-processbus -nn -s0 \
    -w ~/Desktop/iec61850-lab/pcaps/phase4_process_bus.pcap \
    'ether proto 0x88b8 or ether proto 0x88ba'
```

This capture should contain:

```text
GOOSE  0x88B8
SV     0x88BA
```

A broader capture can also be used:

```bash
sudo tcpdump -i br-processbus -nn -s0 \
    -w ~/Desktop/iec61850-lab/pcaps/iec61850_process_bus.pcap
```

Wireshark can then be used to inspect the Ethernet frames and decode the IEC 61850 payloads.

---

# 17. Phase 4: Process Bus Mechanics

The Phase 4 harness was used to inject and inspect GOOSE frames:

```bash
sudo python3 \
    ~/Desktop/iec61850-lab/scripts/phase4_process_bus_analyzer.py \
    br-processbus
```

The observed test frame contained:

```text
Protocol:       GOOSE
EtherType:      0x88B8
Source MAC:     26:42:53:af:9c:91
Destination:    01:0c:cd:01:00:01
stNum:          2
sqNum:          42
TAL:            1500 ms
```

The Phase 4 analysis focused on:

* Ethernet multicast addressing.
* GOOSE APPID.
* ASN.1 BER encoding.
* `stNum`.
* `sqNum`.
* Time Allowed to Live (TAL).
* Event-triggered versus steady-state transmission behavior.

The corresponding process-bus capture can be inspected in Wireshark:

```text
pcaps/phase4_process_bus.pcap
```

---

# 18. Phase 5: GOOSE/SV Anomaly Injection

The Phase 5 harness operates directly against the process-bus bridge:

```bash
sudo python3 \
    ~/Desktop/iec61850-lab/scripts/phase5_anomaly_injection.py \
    br-processbus
```

The test suite generated several controlled anomalies.

### GOOSE State Number Manipulation

A GOOSE frame was injected using:

```text
Source MAC:
de:ad:be:ef:ff:ff
```

with an intentionally abnormal state number:

```text
stNum = 9999
```

The purpose was to observe subscriber handling of unexpected state progression.

### Quality Flag Manipulation

A second GOOSE payload modified the quality field:

```text
q = 0x03
```

The test was intended to observe how the receiving implementation handles altered quality information.

### Sampled Value Anomaly

An SV frame was also generated using:

```text
EtherType: 0x88BA
Source MAC: de:ad:be:ef:ff:ff
```

The payload targeted the test merging-unit data structure:

```text
MU01_Voltage
```

and introduced abnormal sample/frequency-related values.

---

# 19. Capture Phase 5

Run the capture before starting the anomaly harness:

```bash
sudo tcpdump -i br-processbus -nn -s0 \
    -w ~/Desktop/iec61850-lab/pcaps/phase5_anomaly_injection.pcap \
    'ether proto 0x88b8 or ether proto 0x88ba'
```

Then run:

```bash
sudo python3 \
    ~/Desktop/iec61850-lab/scripts/phase5_anomaly_injection.py \
    br-processbus
```

The capture provides the packet-level evidence used for the Phase 5 analysis.

---

# 20. Troubleshooting the Process Bus

The most common problem encountered while building this environment is an apparently working IP network with no working GOOSE/SV traffic. This is expected to be confusing because GOOSE and SV do not require IP connectivity. If MMS works but GOOSE/SV does not, check the Layer 2 path independently.

### Check the bridge

```bash
ip link show br-processbus
bridge link
```

### Check namespace interfaces

```bash
sudo ip netns exec ns-ied1 ip link
sudo ip netns exec ns-mu1 ip link
sudo ip netns exec ns-sub1 ip link
```

### Confirm the interfaces are UP

For example:

```bash
sudo ip netns exec ns-ied1 \
    ip link show veth-ied1
```

The interface should show `UP`.

### Capture at the bridge

```bash
sudo tcpdump -i br-processbus -nn \
    'ether proto 0x88b8 or ether proto 0x88ba'
```

If frames appear on the bridge but not inside the expected namespace, investigate the bridge/veth attachment. If frames never appear on the bridge, investigate the interface supplied to the publisher.

---

# 21. Why the Lab Uses Separate Verification Steps

The lab deliberately separates network verification from protocol verification.

For MMS:

```text
Namespace
   ↓
IP connectivity
   ↓
TCP/102 listener
   ↓
TPKT/COTP
   ↓
ACSE association
   ↓
MMS service
```

For GOOSE/SV:

```text
Namespace
   ↓
veth interface
   ↓
Linux bridge
   ↓
Ethernet multicast
   ↓
GOOSE / SV
```

This matters when troubleshooting. A successful `ping` does not prove GOOSE works. An open TCP/102 port does not prove MMS association works. A visible GOOSE frame does not prove the subscriber accepted its state. Each layer needs to be verified separately.

---

# 22. Research Scripts

The research scripts used during the study are organized by phase:

```text
scripts/
├── phase1_scl.py
├── phase2_mms_cwrapper.py
├── phase3_mms_control_abuse.py
├── phase4_process_bus_analyzer.py
└── phase5_anomaly_injection.py
```

The scripts are experimental research harnesses rather than production security tools. They were written specifically to generate controlled protocol interactions against the isolated laboratory environment.

---

# 23. Packet Captures

Additional captures may be generated while reproducing individual tests.
When publishing captures, remember that packet traces can contain more information than the protocol payload alone, including:

* MAC addresses.
* IP addresses.
* Timing information.
* Interface-specific metadata.

For this reason, captures should be reviewed before redistribution if the lab is ever connected to anything beyond the isolated test environment.

---

# 24. Reproduction Philosophy

This laboratory is intentionally small. It does not attempt to emulate a complete electrical substation or reproduce every feature of IEC 61850.

Instead, it provides enough protocol surface to study several important boundaries. The research then evaluates what happens when trust assumptions at each boundary are challenged. The most important practical lesson from reproducing this environment is that **protocol testing and network topology cannot be separated for IEC 61850**.

MMS depends on the IP/ISO transport stack. GOOSE and SV depend directly on Layer 2 connectivity.SCL operates before either of those communication paths become relevant. Consequently, a successful reproduction requires treating the laboratory network itself as part of the experiment.

---

## 25. Known Limitations

This guide documents the configuration used for the research and should not be interpreted as a guaranteed one-command deployment.

In particular:

1. Interface names may differ between systems.
2. Linux bridge/veth behavior can vary with the host environment.
3. `libiec61850` example applications may change between releases.
4. The available server examples expose different services and data models.
5. MMS file services are not automatically available on every server profile.
6. GOOSE/SV require correct Layer 2 interface binding and multicast visibility.
7. The exact object namespace depends on the `libiec61850` example and its data model.

If an example fails, the first troubleshooting step should therefore be to verify the network namespace, interface, bridge membership, and listener state before modifying the protocol test itself.

---

# 26. Cleanup

When the research session is complete, the namespaces and bridge can be removed:

```bash
sudo ip netns del ns-ied1
sudo ip netns del ns-sub1
sudo ip netns del ns-mu1

sudo ip link del br-processbus
```

If the bridge or namespaces have already been removed, the corresponding commands may simply report that the object does not exist.

Verify the final host state:

```bash
ip link
ip netns list
```

The research environment should not require any connection to an external substation or production network.

---

## Final Note

The purpose of this laboratory is reproducibility through observation rather than abstraction.

Every major conclusion in the accompanying IEC 61850 research was tied back to one of three things:

* an observed parser or application reaction,
* a protocol exchange captured on the wire,
* or a controlled change in the simulated IED/process-bus environment.

The laboratory therefore serves as the experimental foundation for the accompanying research phases rather than as a production-ready IEC 61850 deployment.
