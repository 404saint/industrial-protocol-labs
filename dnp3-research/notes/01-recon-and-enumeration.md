---
title: 01-recon-and-enumeration
tags: [Research Notes]

---

# 01: Reconnaissance & Asset Enumeration

## 1. Introduction

Reconnaissance is often the first stage of any network assessment, providing the information required to identify devices, understand their operational state, and determine the capabilities exposed by a protocol implementation. Within DNP3, this process can frequently be performed using standard protocol features rather than intrusive scanning techniques.

Several protocol mechanisms expose operational metadata that is intended for supervisory systems. Among the most useful are the **Internal Indications (IIN)** field, which communicates the current status of an outstation, and **Object Group 80 (Device Attributes)**, which provides descriptive information about the device itself.

In deployments where **DNP3 Secure Authentication** is not implemented or not enforced, an endpoint capable of communicating with an outstation may be able to retrieve portions of this information using standard read requests. The resulting metadata can assist with asset inventory, implementation fingerprinting, and behavioral analysis before more intrusive testing begins.

---

# 2. Internal Indications (IIN)

Every DNP3 Application Layer response includes a two-byte **Internal Indications (IIN)** field immediately following the Function Code. These status bits communicate the operational condition of the outstation and provide context for the response being returned.

```text
+------------------+-------------------+-------------------+-------------------+
| Application Ctrl |   Function Code   |    IIN Byte 1     |    IIN Byte 2     |
|     (1 Byte)     |  (Response Code)  |     (1 Byte)      |     (1 Byte)      |
+------------------+-------------------+-------------------+-------------------+
```

The IIN field allows a master to determine whether additional data is available, whether synchronization is required, or whether the outstation has encountered operational conditions that may affect communication.

## Internal Indications Reference

| Byte     | Bit | Flag                          | Protocol Meaning                                 | Reconnaissance Value                                   |
| -------- | --- | ----------------------------- | ------------------------------------------------ | ------------------------------------------------------ |
| **IIN1** | 0   | All Stations                  | Response associated with broadcast communication | Indicates broadcast processing within the environment  |
|          | 1   | Class 1 Data                  | High-priority event data available               | Indicates pending high-priority events                 |
|          | 2   | Class 2 Data                  | Medium-priority event data available             | Indicates queued operational events                    |
|          | 3   | Class 3 Data                  | Low-priority event data available                | Indicates queued low-priority events                   |
|          | 4   | Time Synchronization Required | Outstation clock requires synchronization        | Reveals devices awaiting time synchronization          |
|          | 5   | Local Control                 | Device operating under local control             | Indicates remote control operations may be unavailable |
|          | 6   | Device Trouble                | Device has reported an internal fault            | May indicate degraded operational status               |
|          | 7   | Device Restart                | Device has recently restarted                    | Reveals a recent reboot or power-cycle event           |
| **IIN2** | 0   | Bad Function                  | Unsupported application function received        | Helps identify supported protocol functionality        |
|          | 1   | Object Unknown                | Requested object or variation not supported      | Assists in determining supported object groups         |
|          | 2   | Parameter Error               | Invalid parameter supplied                       | Indicates parameter validation behavior                |
|          | 3   | Buffer Overflow               | Event buffer has overflowed                      | Indicates loss of queued event information             |
|          | 4   | Operation in Progress         | Requested operation is currently executing       | Reveals active device activity                         |
|          | 5   | Configuration Corrupt         | Configuration integrity issue detected           | Indicates configuration or startup problems            |

Although these indicators are primarily intended for operational diagnostics, they also provide valuable context during protocol analysis by exposing aspects of the outstation's current runtime state.

---

# 3. Object Group 80: Device Attribute Enumeration

DNP3 defines **Object Group 80** as a collection of device attributes describing the identity and characteristics of an outstation. Depending on the implementation, these attributes may include vendor information, hardware revisions, firmware versions, and descriptive identifiers configured by the system operator.

Because these values are exchanged using standard protocol objects, they can assist with asset inventory and implementation fingerprinting during a security assessment.

## Common Device Attributes

| Object Group / Variation | Attribute                   | Assessment Value                                               |
| ------------------------ | --------------------------- | -------------------------------------------------------------- |
| **Group 80 Variation 1** | Manufacturer Name           | Identifies the device vendor                                   |
| **Group 80 Variation 2** | Hardware Version            | Identifies hardware revision                                   |
| **Group 80 Variation 3** | Firmware / Software Version | Assists with implementation identification                     |
| **Group 80 Variation 4** | Device Name or Location     | May reveal operational naming conventions or asset identifiers |

The exact attributes supported by an outstation are implementation-dependent and may vary between vendors or firmware versions.

---

# 4. Laboratory Validation

To validate the protocol behavior described above, a lightweight Python utility (`recon_enum.py`) was developed. The tool establishes a TCP connection to an outstation on port **20000**, constructs a DNP3 Read request targeting **Object Group 80**, receives the resulting FT3 frame, removes the Data Link and Pseudo-Transport encapsulation, and parses the returned Application Layer header together with the Internal Indications field.

The objective of the experiment was to determine whether protocol metadata could be retrieved through standard DNP3 communication without performing intrusive network enumeration techniques.

## Example Execution

```text
[*] Initiating DNP3 Recon Probe against 127.0.0.1:20000...
[->] Sending Group 80 Read Request (18 bytes)
[✓] Response received (19 bytes): 05 64 0e 44 00 00 01 00 3b e3 c1 c1 81 10 00 00 00 1a 8f

             DNP3 Internal Indications (IIN) Status
┏━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Byte ┃ Hex Value ┃ Active Indicators                         ┃
┡━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ IIN1 │ 0x81      │ IIN1.0 - All Stations                     │
│      │           │ IIN1.7 - Device Restart                   │
│ IIN2 │ 0x10      │ IIN2.4 - Operation in Progress            │
└──────┴───────────┴───────────────────────────────────────────┘
```

---

# 5. Observations

The laboratory exercise produced the following observations.

### Unauthenticated Metadata Retrieval

Within the laboratory environment, the target outstation processed the Group 80 read request immediately after the TCP connection was established. No Secure Authentication exchange or application-layer credentials were required before protocol metadata became available.

This behavior reflects the configuration of the evaluated environment and should not be interpreted as representative of every DNP3 deployment.

### Operational State Exposure

The returned Internal Indications field provided insight into the runtime condition of the outstation at the time of the request.

In this capture, the device reported both a recent restart (`IIN1.7`) and an operation currently in progress (`IIN2.4`). These indicators provide useful operational context while remaining part of the protocol's standard diagnostic functionality.

---

# 6. Reconnaissance Considerations

Compared with simpler industrial communication protocols, DNP3 exposes a richer set of operational metadata through standardized protocol exchanges. Device identity, implementation characteristics, runtime status, and queued event information may all be observable depending on the capabilities supported by an outstation.

From a security assessment perspective, this information can assist with asset identification, implementation fingerprinting, and protocol understanding before more intrusive testing begins. The availability of this metadata ultimately depends on vendor implementation, enabled object groups, deployment configuration, and the presence of security mechanisms such as DNP3 Secure Authentication.

The following document builds upon these reconnaissance concepts by examining DNP3 packet structure in greater detail, demonstrating how protocol messages are constructed, parsed, and interpreted at the byte level.
