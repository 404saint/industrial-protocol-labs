# IEC 61850 Protocol Security Research Laboratory

> A practical research series examining IEC 61850 architecture, MMS session behavior, substation namespace exposure, unauthenticated control paths, Layer 2 GOOSE/SV mechanics, process-bus anomaly injection, and IEC 62351 security extensions through controlled laboratory experimentation.

---

## Overview

This repository documents a hands-on security study of **IEC 61850** using `libiec61850`, isolated Linux network namespaces, custom Python research harnesses, and packet-level analysis.

The research examines IEC 61850 from the station bus to the process bus, focusing on:

* SCL-based device and communication configuration
* MMS session establishment and namespace enumeration
* Unauthenticated MMS and ACSI control operations
* MMS file-service exposure
* GOOSE and Sampled Values Layer 2 mechanics
* GOOSE/SV state, sequence, and payload behavior
* Process-bus anomaly injection
* IEC 62351 security extensions

Testing combines custom protocol tooling, `libiec61850` examples, Wireshark, `tcpdump`, and controlled virtual network infrastructure.

---

## Research Scope

The research is divided into six phases:

1. **SCL Attack Surface:** Examining IEC 61850 configuration artifacts and the information exposed through SCL-based device descriptions.
2. **MMS Session & Namespace Enumeration:** Establishing MMS associations and mapping the Logical Device and data-object namespace exposed by the target IED.
3. **MMS Control Abuse:** Testing raw MMS writes, ACSI control operations, state verification, and MMS file-service exposure.
4. **Process Bus Mechanics:** Analyzing GOOSE and Sampled Values at Layer 2, including Ethernet framing, ASN.1 BER structures, state/sequence fields, and multicast behavior.
5. **GOOSE/SV Anomalies:** Injecting controlled state, quality, and Sampled Values anomalies to examine process-bus handling.
6. **Secure Extension Contrast:** Comparing the observed plaintext attack surface against the security mechanisms defined by relevant IEC 62351 profiles.

An additional legacy SV parser is retained as supporting research material. A separate reproduction guide documents the laboratory construction and execution workflow.

---

## Repository Structure

```text
.
├── notes/
│   ├── 00a.legacy-sv-parser.md
│   ├── 00.architecture-primer.md
│   ├── 01.phase1-scl-schema-attack-surface.md
│   ├── 02.phase2-mms-session-enumeration.md
│   ├── 03.phase3-mms-control-abuse.md
│   ├── 04.phase4-process-bus-mechanics.md
│   ├── 05.phase5-goose-sv-injection-anomalies.md
│   ├── 06.phase6-secure-extension-contrast.md
│   └── lab-reproduction-guide.md
│
├── pcaps/
│   ├── phase1_scl_attack_surface.pcap
│   ├── phase2_mms_enumeration.pcap
│   ├── phase3_mms_control_abuse.pcap
│   ├── phase4_process_bus.pcap
│   ├── phase5_anomaly_injection.pcap
│   └── Sample240.pcap
│
├── screenshots/
│   ├── legacy_parser_sv_waveforms.png
│   ├── legacy_sv_parser.png
│   ├── phase1_scl.png
│   ├── phase2_mms_cwrapper.png
│   ├── phase3_mms_control_abuse.png
│   ├── phase4_process_bus_analyzer.png
│   ├── phase5_anomaly_injection_quality_flag_manipulation.png
│   ├── phase5_anomaly_injection_stNum_poisoning.png
│   └── phase5_anomaly_injection_SV_frequency_mismatch.png
│
└── scripts/
    ├── legacy_sv_parser.py
    ├── phase1_scl.py
    ├── phase2_mms_cwrapper.py
    ├── phase3_mms_control_abuse.py
    ├── phase4_process_bus_analyzer.py
    └── phase5_anomaly_injection.py
```

---

## Research Notes

| Phase | Focus                                            |
| ----- | ------------------------------------------------ |
| `00`  | IEC 61850 architecture and security model        |
| `01`  | SCL schema and configuration attack surface      |
| `02`  | MMS session behavior and namespace enumeration   |
| `03`  | MMS control operations and file-service exposure |
| `04`  | GOOSE/SV Layer 2 process-bus mechanics           |
| `05`  | GOOSE/SV anomaly injection and edge cases        |
| `06`  | IEC 62351 security-extension contrast            |

The `00` architecture primer establishes the protocol baseline used throughout the research. The `00a` document contains supporting work from an earlier Sampled Values parser experiment. The `lab-reproduction-guide.md` document is a **reproduction guide**, not an additional research phase.

---

## Research Harnesses

Each experimental phase uses an independent research script:

| Script                           | Purpose                                           |
| -------------------------------- | ------------------------------------------------- |
| `phase1_scl.py`                  | SCL configuration and schema analysis             |
| `phase2_mms_cwrapper.py`         | MMS association and namespace enumeration         |
| `phase3_mms_control_abuse.py`    | MMS write, ACSI control, and file-service testing |
| `phase4_process_bus_analyzer.py` | GOOSE Layer 2 framing and process-bus analysis    |
| `phase5_anomaly_injection.py`    | GOOSE/SV anomaly injection and monitoring         |
| `legacy_sv_parser.py`            | Supporting Sampled Values parsing experiment      |

The scripts are designed for the accompanying isolated laboratory environment and should not be used against systems without explicit authorization.

---

## Laboratory Environment

The laboratory uses:

* `libiec61850`
* Linux network namespaces
* Virtual Ethernet interfaces
* Linux bridging
* Python 3
* Wireshark
* `tcpdump`
* Custom protocol-analysis scripts

### Network Layout

The primary laboratory separates the IED and subscriber environments into isolated namespaces connected through a virtual process-bus bridge.

```text
                Host Linux System
                       │
              ┌────────┴─────────┐
              │  br-processbus   │
              └───────┬──────────┘
                      │
          ┌───────────┴───────────┐
          │                       │
      ns-ied1                  ns-sub1
    192.168.1.10             192.168.1.20
          │                       │
        IED                    Subscriber
```

MMS operates over TCP/102, while GOOSE and Sampled Values are observed directly on the Layer 2 process-bus segment.

---

## Key Findings

The laboratory produced several notable observations:

* MMS application association was established without client authentication in the tested plaintext configuration.
* `GetNameList` requests exposed the Logical Device and a large portion of the target MMS namespace, including control-related objects.
* Raw MMS writes to tested control attributes were rejected by the server's data-access constraints.
* Equivalent control operations issued through the ACSI control interface were accepted without authentication in the tested configuration.
* Process state was queried after control operations to verify the resulting application state.
* MMS file-directory access was refused because the tested server profile did not expose a configured MMS file service.
* GOOSE traffic was observed as Layer 2 multicast using EtherType `0x88B8`.
* Sampled Values traffic was analyzed using EtherType `0x88BA`.
* GOOSE state and sequence fields were observable directly in the ASN.1 BER encoded payload.
* Controlled GOOSE/SV frames using unauthorized source addresses and modified protocol values were successfully injected onto the laboratory process-bus bridge.
* IEC 62351 security mechanisms provide the standards-based security model used to address the plaintext transport, process-bus, and authorization weaknesses examined during the earlier phases.

These observations apply to the specific `libiec61850` laboratory configuration and test harnesses used in this research. They should not be interpreted as universal characteristics of all IEC 61850 implementations or deployments.

---

## Packet Capture Evidence

The repository contains packet captures corresponding to the major experimental phases:

| Capture                          | Evidence                                    |
| -------------------------------- | ------------------------------------------- |
| `phase1_scl_attack_surface.pcap` | Phase 1 laboratory traffic                  |
| `phase2_mms_enumeration.pcap`    | MMS association and namespace enumeration   |
| `phase3_mms_control_abuse.pcap`  | MMS/ACSI control and file-service testing   |
| `phase4_process_bus.pcap`        | GOOSE/SV process-bus traffic                |
| `phase5_anomaly_injection.pcap`  | Controlled GOOSE/SV anomaly injection       |
| `Sample240.pcap`                 | Supporting Sampled Values research material |

The captures provide wire-level evidence for the observations documented in the corresponding research notes.

---

## Research Methodology

The research follows a simple experimental workflow:

```text
Architecture
     │
     ▼
Protocol Interaction
     │
     ▼
Packet Capture
     │
     ▼
Implementation Observation
     │
     ▼
Security Assessment
     │
     ▼
Security Extension Review
```

Protocol behavior is evaluated through:

* Protocol specification analysis
* Controlled protocol interaction
* Custom Python tooling
* `libiec61850` example implementations
* Packet captures
* Wireshark inspection
* Controlled malformed and anomalous inputs
* Application-state verification

The objective is to document **observable implementation behavior** and connect it back to the underlying IEC 61850 security model.

---

## Reproduction

The complete laboratory setup and execution workflow is documented in:

```text
notes/lab-reproduction-guide.md
```

The guide covers:

* `libiec61850` compilation
* Linux namespace and bridge configuration
* Virtual IED deployment
* MMS research execution
* GOOSE/SV process-bus setup
* Packet capture methodology
* Reproduction of the experimental phases

Because the laboratory depends on specific virtual-interface and namespace configuration, some environment-specific adjustments may be required when reproducing the experiments on another system.

---

## Disclaimer

This repository is intended for educational, protocol research, and defensive security analysis. All active testing was performed against locally controlled laboratory infrastructure. No experiments were conducted against production substations, operational IEDs, or unauthorized infrastructure. Use these techniques only against systems for which you have explicit authorization to conduct security research.
