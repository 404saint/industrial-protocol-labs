# Routing, BBMD & Subnet Traversal Analysis

## Executive Summary

BACnet was designed to operate across multiple network media, including Ethernet, IP, and serial fieldbus technologies such as MS/TP. Unlike conventional UDP-based application protocols, BACnet/IP introduces an additional communication layer known as the **BACnet Virtual Link Layer (BVLL)** to facilitate broadcast distribution, network routing, and communication across Layer 3 boundaries.

This phase examined three aspects of BACnet/IP network infrastructure: **Foreign Device Registration (FDR)**, **router discovery**, and **global broadcast traversal**. Testing demonstrated that the target successfully acknowledged a `Register-Foreign-Device` request using a successful BVLL Result message, while router discovery and global broadcast enumeration produced no observable responses during the experiment.

---

# 1. Research Environment

| Component            | Description                                                                                          |
| -------------------- | ---------------------------------------------------------------------------------------------------- |
| **Target**           | BACnet/IP `SimpleServer`                                                                             |
| **Protocol**         | BACnet/IP (ANSI/ASHRAE Standard 135)                                                                 |
| **Research Harness** | `bbmd-boundary-traversal.py`                                                                         |
| **Assessment Scope** | BVLL messaging, Foreign Device Registration, router discovery, and broadcast-based network traversal |

---

# 2. Research Objectives

This phase investigated three components of BACnet/IP network infrastructure:

* Evaluate Foreign Device Registration using BVLL.
* Observe router discovery through `Who-Is-Router-To-Network`.
* Examine broadcast-based device discovery using global `Who-Is` requests.

---

# 3. Experimental Analysis

## 3.1 Foreign Device Registration (FDR)

### Protocol Background

BACnet/IP relies on **BACnet Broadcast Management Devices (BBMDs)** to distribute broadcast traffic between IP subnets. Devices located outside a local BACnet broadcast domain may request participation by transmitting a **Register-Foreign-Device** BVLL message to a BBMD.

The registration request includes a configurable **Time-To-Live (TTL)** value that specifies how long the registration should remain valid before renewal.

### Test Parameters

| Parameter     | Value                            |
| ------------- | -------------------------------- |
| BVLL Function | `Register-Foreign-Device (0x05)` |
| TTL           | `300 seconds`                    |
| Transport     | UDP/47808                        |

### Observations

A `Register-Foreign-Device` request was transmitted with a TTL of **300 seconds**.

The target returned a successful BVLL Result message, which the research harness interpreted as a successful registration acknowledgement.

```
Foreign Device Registration Successful!
ACK received from 192.168.1.196:47808
```

### Discussion

The experiment demonstrates that the implementation accepted and acknowledged the registration request at the BVLL layer. This phase did not examine the server's internal Foreign Device Table (FDT), therefore the long-term registration state was not independently verified.

---

## 3.2 Router Discovery

### Protocol Background

BACnet defines the **Who-Is-Router-To-Network** network layer message to discover routers capable of forwarding traffic between BACnet network numbers.

Implementations supporting routing may respond with an **I-Am-Router-To-Network** message containing the destination networks they advertise.

### Test Parameters

| Parameter    | Value                             |
| ------------ | --------------------------------- |
| NPDU Message | `Who-Is-Router-To-Network (0x00)` |
| Transport    | Original-Unicast-NPDU             |

### Observations

A router discovery request was transmitted to the target.

No `I-Am-Router-To-Network` responses were observed during the collection period.

```
No router responses returned for network discovery query.
```

### Discussion

No evidence of active BACnet routing functionality was observed during testing. Because this experiment targeted a laboratory environment, the absence of responses should not be interpreted as confirmation that routing was unsupported. It simply reflects the behavior observed during the collection window.

---

## 3.3 Global Broadcast Discovery

### Protocol Background

BACnet devices commonly advertise themselves using the unconfirmed **Who-Is** and **I-Am** services. When operating across routed BACnet/IP networks, these broadcasts are distributed through BBMD infrastructure using BVLL broadcast forwarding.

### Test Parameters

| Parameter           | Value                            |
| ------------------- | -------------------------------- |
| BVLL Function       | `Original-Broadcast-NPDU (0x0B)` |
| Destination Network | `0xFFFF` (Global Broadcast)      |
| APDU Service        | `Who-Is`                         |

### Observations

A global `Who-Is` broadcast was transmitted using destination network `0xFFFF`.

No `I-Am` responses were received during the observation period.

The final summary produced by the research harness reported:

| Observation        | Result |
| ------------------ | ------ |
| Devices Discovered | `0`    |

### Discussion

The experiment did not identify additional BACnet devices responding to the broadcast request. The observed result reflects the laboratory environment used during testing and should not be generalized to production BACnet deployments.

---

# 4. Security Characteristics

This phase focused on BACnet/IP network infrastructure rather than application services.

Three observations were recorded during testing:

* The target acknowledged a Foreign Device Registration request using a successful BVLL Result response.
* Router discovery requests produced no observable routing advertisements.
* Global broadcast discovery produced no `I-Am` responses during the observation period.

Collectively, these observations illustrate the separation between BACnet's application services and its underlying network infrastructure. While application-layer communication depends on APDU services such as `ReadProperty` and `WriteProperty`, network reachability across IP subnets relies on BVLL messaging, BBMD functionality, and BACnet routing services.

---

# 5. Hardening Recommendations

Based on the observed behavior, the following practices are recommended:

1. Restrict Foreign Device Registration to trusted engineering systems where BBMD functionality is required.
2. Review BBMD configurations to ensure broadcast forwarding is limited to authorized BACnet networks.
3. Monitor for unexpected BVLL management traffic, including repeated Foreign Device Registration requests and router discovery messages.
4. Isolate BACnet/IP infrastructure from untrusted networks using dedicated OT segmentation and firewall policies controlling UDP port **47808**.

