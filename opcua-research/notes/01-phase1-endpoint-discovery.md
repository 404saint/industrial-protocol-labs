# Phase 1: Endpoint Enumeration & Unauthenticated Exposure

* **Target Server:** `opc.tcp://127.0.0.1:4840` (`open62541-based OPC UA Application`)
* **Protocol Layer:** `opc.tcp` / UA Binary
* **Objective:** Audit pre-authentication information exposure, enumerate advertised endpoints, and identify the security policies and user token types offered by the server.

---

## Executive Summary

The first phase examined what an OPC UA client can discover from the target server before establishing an application session.

An unauthenticated `GetEndpointsRequest` was issued over the `opc.tcp` transport. The server responded successfully and exposed **five endpoint configurations**, all associated with the same server URL but offering different combinations of Message Security Mode and SecurityPolicy.

The discovery response also disclosed identifying application metadata, including the server's application name, Application URI, and Product URI. Most notably, the server advertised an endpoint using `SecurityPolicy#None` with `MessageSecurityMode: None`, meaning that the deployment exposes a configuration without message signing or encryption.

All five advertised endpoints also offered `Anonymous` and `UserName` user token policies. This establishes that these authentication mechanisms are available at the endpoint level; whether an authenticated session is subsequently authorized to browse, read, write, or invoke functionality is examined in later phases.

The primary Phase 1 finding is therefore not an authentication bypass, but **pre-authentication disclosure of server identity and security configuration combined with the availability of an unprotected endpoint**.

---

## 1. Unauthenticated Discovery

The discovery script performed the following operation:

```text
[*] Target Server: opc.tcp://127.0.0.1:4840
[*] Sending unauthenticated GetEndpointsRequest over opc.tcp...
[+] Received 5 exposed endpoints.
```

No user identity was supplied during endpoint discovery.

The server nevertheless returned its endpoint metadata, allowing the client to enumerate the security configurations available for subsequent connections.

This establishes an important characteristic of the OPC UA discovery process: **endpoint configuration can be enumerated before a user session is established.**

---

## 2. Leaked Server Metadata

The `GetEndpointsResponse` disclosed the following application metadata:

| Field                | Observed Value                       |
| -------------------- | ------------------------------------ |
| **Application Name** | `open62541-based OPC UA Application` |
| **Application URI**  | `urn:open62541.server.application`   |
| **Product URI**      | `http://open62541.org`               |
| **Application Type** | `Server`                             |

The information identifies the underlying OPC UA implementation as **open62541**.

The Product URI additionally provides a direct association with the open62541 project, giving an observer useful information for technology fingerprinting and subsequent vulnerability research.

This information is not equivalent to a software-version disclosure, the response did not provide a specific open62541 build or version but, it substantially reduces uncertainty about the server implementation.

---

## 3. Exposed Endpoint Configuration

The discovery response contained five endpoint configurations:

| Index | Endpoint URL               |  Security Mode | Security Policy         | Allowed User Tokens |
| :---: | -------------------------- | :------------: | ----------------------- | ------------------- |
| **0** | `opc.tcp://127.0.0.1:4840` |    **None**    | **None**                | Anonymous, UserName |
| **1** | `opc.tcp://127.0.0.1:4840` | SignAndEncrypt | `Aes128_Sha256_RsaOaep` | Anonymous, UserName |
| **2** | `opc.tcp://127.0.0.1:4840` |      Sign      | `Aes128_Sha256_RsaOaep` | Anonymous, UserName |
| **3** | `opc.tcp://127.0.0.1:4840` | SignAndEncrypt | `Basic256Sha256`        | Anonymous, UserName |
| **4** | `opc.tcp://127.0.0.1:4840` |      Sign      | `Basic256Sha256`        | Anonymous, UserName |

The server therefore exposes three distinct security configurations:

```text
                         OPC UA Server
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
          None Mode          Sign       SignAndEncrypt
              │               │               │
          No message       Integrity       Integrity +
          protection       protection      Confidentiality
```

The same server URL can advertise multiple endpoints because the endpoint configuration determines how the subsequent OPC UA communication is protected.

---

## 4. Unprotected Endpoint

Endpoint `0` is configured as:

```text
SecurityMode:   None
SecurityPolicy: None
User Tokens:    Anonymous, UserName
```

This is the most significant configuration identified during discovery.

With `MessageSecurityMode: None`, OPC UA messages exchanged through this endpoint do not receive message-level signing or encryption. Consequently, application traffic transmitted through a channel using this configuration does not receive the confidentiality and integrity protections provided by the secured modes.

From an OT security perspective, exposing such an endpoint creates the possibility of:

* Passive observation of OPC UA application traffic.
* Inspection of otherwise protected application data.
* Active manipulation of unprotected messages.
* Interception of session and service traffic where applicable.

The actual impact depends on what services and operations the server permits after session activation. Those authorization boundaries are investigated during the subsequent research phases.

---

## 5. Sign vs. SignAndEncrypt

Endpoints `2` and `4` use:

```text
MessageSecurityMode: Sign
```

while endpoints `1` and `3` use:

```text
MessageSecurityMode: SignAndEncrypt
```

The distinction is important.

### `Sign`

The `Sign` mode provides message integrity and authentication of the communicating application instances, but does not provide confidentiality.

An observer capable of capturing network traffic may therefore still inspect application payloads even though unauthorized modification should be detectable through message signatures.

### `SignAndEncrypt`

`SignAndEncrypt` provides both integrity protection and confidentiality.

The payload is protected against passive inspection while also receiving message integrity protection.

The server therefore exposes both protected and unencrypted communication configurations simultaneously.

---

## 6. User Token Policies

Every discovered endpoint advertised the same two user token types:

```text
Anonymous
UserName
```

The presence of `Anonymous` indicates that the endpoint configuration supports anonymous user identity tokens.

However, endpoint advertisement alone does **not** establish that anonymous users possess unrestricted access to the server's information model.

The distinction is:

```text
Endpoint accepts Anonymous token
              │
              ▼
        Session activation
              │
              ▼
      Authorization checks
              │
       ┌──────┴──────┐
       ▼             ▼
    Allowed        Denied
```

Determining what an anonymous session can browse, read, write, or execute is therefore outside the scope of this endpoint-enumeration phase and is deferred to the address-space and security-boundary investigations.

The same principle applies to `UserName`: its advertisement establishes that the authentication mechanism is available, not that valid credentials have been obtained or that a particular user has privileged access.

---

## 7. Wire-Level Discovery Sequence

The endpoint enumeration begins with the `opc.tcp` connection handshake before the discovery service request is exchanged.

At a high level:

```text
Client                                      Server
  │                                           │
  │────────────── HEL ──────────────────────> │
  │<───────────── ACK ─────────────────────── │
  │                                           │
  │────────────── OPN ──────────────────────> │
  │<───────────── OPN ─────────────────────── │
  │                                           │
  │──── GetEndpointsRequest (MSG) ──────────> │
  │<── GetEndpointsResponse (MSG) ─────────── │
  │                                           │
```

The `HEL` / `ACK` exchange establishes the OPC UA TCP connection parameters.

The `OPN` exchange establishes the SecureChannel context used for subsequent OPC UA service communication. In this test, the discovery operation was performed using the server's `SecurityPolicy#None` configuration.

The `MSG` exchange then carries the `GetEndpointsRequest` and corresponding `GetEndpointsResponse`.

---

## 8. Transport Evidence

The captured `HEL` frame contained the following parameters:

```text
Message Type:       HEL
Chunk Type:         F
Message Size:       60 bytes
Protocol Version:   0
Receive Buffer:     65535 bytes
Send Buffer:        65535 bytes
Max Message Size:   0
Max Chunk Count:    0
Endpoint URL:       opc.tcp://127.0.0.1:4840
```

The `Max Message Size` and `Max Chunk Count` values of `0` indicate that no explicit limit was advertised by the client for those parameters.

The subsequent `OPN` request was associated with:

```text
SecurityPolicy:
http://opcfoundation.org/UA/SecurityPolicy#None

SecurityMode:
None
```

The request therefore established the test channel without the cryptographic message protection provided by the secured endpoint configurations.

The final discovery request was transported in a `MSG` frame containing the `GetEndpointsRequest`.

---

## 9. Security Assessment

The endpoint enumeration identified three principal security characteristics.

### 9.1 Implementation Fingerprinting

The server discloses:

```text
open62541-based OPC UA Application
urn:open62541.server.application
http://open62541.org
```

This allows an unauthenticated observer to identify the underlying OPC UA implementation.

While no specific software version was disclosed, implementation identification provides useful intelligence for subsequent vulnerability research and technology profiling.

### 9.2 Unprotected Communication Configuration

The server advertises an endpoint using:

```text
SecurityPolicy#None
MessageSecurityMode: None
```

This configuration provides no message-level confidentiality or integrity protection and should therefore be treated as an exposed insecure communication path.

### 9.3 Anonymous Authentication Availability

All five endpoints advertise `Anonymous` user tokens.

This does not by itself demonstrate unrestricted authorization, but it establishes that the server permits anonymous identity tokens at the endpoint configuration level.

The effective privileges associated with those sessions require further testing.

---

## 10. Hardening Recommendations

Based on the Phase 1 observations:

### &check; Disable `SecurityPolicy#None`

Production OPC UA deployments should avoid exposing endpoints that permit unprotected communication unless there is a documented and controlled requirement.

Where secure endpoints are available, `SignAndEncrypt` should be preferred for communications carrying sensitive operational data.

### &check; Minimize Anonymous Access

If anonymous access is not required, remove `Anonymous` from the endpoint's user token policies.

Where anonymous sessions are operationally necessary, their authorization should be explicitly restricted and verified against the server's address-space permissions.

### &check; Prefer Modern Security Policies

Endpoints should use currently supported cryptographic policies appropriate to the deployment rather than legacy or deprecated security configurations.

### &check; Review Discovery Exposure

Application metadata exposed through discovery should be considered part of the server's network-visible attack surface. Unnecessary implementation or deployment information should not be exposed where it can be safely suppressed.

---

## Security Characteristics

Phase 1 demonstrates that OPC UA endpoint discovery can expose meaningful server information before a user session is established.

The target disclosed its underlying implementation identity, five endpoint configurations, supported Message Security Modes, SecurityPolicies, and available user token types through an unauthenticated discovery operation.

The most significant finding was the simultaneous exposure of:

```text
5 Endpoints
     │
     ├── 1 × SecurityMode: None
     │        └── No message protection
     │
     ├── 2 × SecurityMode: Sign
     │        └── Integrity without confidentiality
     │
     └── 2 × SecurityMode: SignAndEncrypt
              └── Integrity + confidentiality
```

Combined with the availability of `Anonymous` authentication across all advertised endpoints, the discovery response provides an unauthenticated client with a detailed map of the server's available security configurations.

The findings establish the starting point for **Phase 2: Secure Channel & Session Handshake Analysis**, where the advertised configurations can be examined through their actual channel and session behavior.
