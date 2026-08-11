# Phase 2: Secure Channel & Session Handshake Analysis

## Executive Summary

Phase 2 examines how an OPC UA client progresses from a raw TCP connection to an active application session. The analysis focuses on the separation between the **SecureChannel** and **Session** layers and uses packet captures from an `open62541`-based server to observe the complete handshake sequence.

The target exposes an `opc.tcp` endpoint using `SecurityPolicy#None`. Against this endpoint, an unauthenticated client successfully completed `OpenSecureChannel`, `CreateSession`, and `ActivateSession` using an Anonymous identity token. A second test using a `UserNameIdentityToken` was rejected with `BadUserAccessDenied`, confirming that invalid user credentials were still enforced.

Packet-level inspection further demonstrated that OPC UA treats UserName credential protection separately from SecureChannel encryption. The username `admin` was visible inside the unencrypted `ActivateSessionRequest`, while the corresponding password was represented as RSA-OAEP ciphertext. This distinction is important: `SecurityPolicy#None` removes SecureChannel message protection, but the UserName identity-token mechanism can apply its own password-encryption mechanism.

The phase therefore establishes the practical relationship between transport negotiation, SecureChannel establishment, session creation, and user identity activation without treating these layers as a single authentication mechanism.

---

## 1. Research Objective

The purpose of this phase is to map the OPC UA connection state machine from transport establishment through application-session activation.

The experiment focuses on three questions:

1. How does an OPC UA client establish a `SecureChannel`?
2. How is an application `Session` created and activated?
3. What changes when different user identity tokens are supplied to the session?

The target environment was:

```text
Server:
    opc.tcp://127.0.0.1:4840

Implementation:
    open62541-based OPC UA Application

Transport:
    TCP/4840

Encoding:
    UA Binary

Tested Security Policy:
    SecurityPolicy#None
```

The phase intentionally builds upon the endpoint configurations discovered during Phase 1 rather than treating endpoint enumeration and session establishment as the same operation.

---

## 2. OPC UA Connection State Machine

An OPC UA client does not immediately begin issuing application services after opening a TCP socket. The connection progresses through distinct protocol layers.

```text
TCP Connection
      │
      ▼
   HEL / ACK
Transport Negotiation
      │
      ▼
 OpenSecureChannel
      │
      ▼
 SecureChannel Established
      │
      ▼
  CreateSession
      │
      ▼
    Session Created
      │
      ▼
 ActivateSession
      │
      ▼
   Session Active
      │
      ▼
 Application Services
 (Read / Write / Browse / Call)
```

This separation is central to OPC UA's architecture.

A **SecureChannel** provides the communication security context between application instances, while a **Session** represents the logical interaction between a client and server. Session activation additionally introduces the user identity context used for application-level access control.

---

## 3. Transport Negotiation

The first protocol exchange observed in the capture consists of the `HEL` and `ACK` messages.

```text
Client                                      Server
  │                                           │
  │──── HEL ────────────────────────────────> │
  │                                           │
  │<─── ACK ───────────────────────────────── │
  │                                           │
```

### HEL — Hello

The client begins the OPC UA connection by sending a `HEL` message containing transport capabilities.

The captured request contained:

| Parameter            |             Observed Value |
| -------------------- | -------------------------: |
| Protocol Version     |                        `0` |
| Receive Buffer Size  |                    `65535` |
| Send Buffer Size     |                    `65535` |
| Maximum Message Size |                        `0` |
| Maximum Chunk Count  |                        `0` |
| Endpoint URL         | `opc.tcp://127.0.0.1:4840` |

The zero values for maximum message size and chunk count indicate that the client did not impose an explicit upper bound through these fields.

### ACK — Acknowledge

The server responds with `ACK`, establishing the transport parameters that will govern the connection.

At this point, TCP and the OPC UA connection layer are established, but no application session exists yet.

---

## 4. OpenSecureChannel

Following transport negotiation, the client issues an `OpenSecureChannel` request.

```text
Client                                      Server
  │                                           │
  │──── OPN: OpenSecureChannel ─────────────> │
  │                                           │
  │<─── OPN: SecureChannel Response ───────── │
  │                                           │
  ▼                                           ▼
       SecureChannel Established
```

For this experiment, the client selected:

```text
Security Policy:
    http://opcfoundation.org/UA/SecurityPolicy#None

Security Mode:
    None
```

The captured `OPN` request contained:

| Field                           | Observed Value        |
| ------------------------------- | --------------------- |
| SecureChannelId                 | `0`                   |
| SecurityPolicy                  | `SecurityPolicy#None` |
| Sender Certificate              | Null                  |
| Receiver Certificate Thumbprint | Null                  |
| Request Type                    | `Issue`               |
| Security Mode                   | `None`                |
| Client Nonce                    | Null                  |
| Requested Lifetime              | `3600000 ms`          |

The server subsequently returned an `OpenSecureChannel` response assigning the SecureChannel context used by subsequent `MSG` traffic.

### Security Observation

Under `SecurityPolicy#None`, the SecureChannel does not provide cryptographic message protection.

This does **not**, however, mean that every field used by an OPC UA service is necessarily transmitted without any independent protection. User identity tokens may implement their own credential-protection mechanisms, as demonstrated later in this phase.

---

## 5. CreateSession

Once the SecureChannel is available, the client creates a logical application session.

Conceptually:

```text
Client                                      Server
  │                                           │
  │──── CreateSessionRequest ───────────────> │
  │                                           │
  │<─── CreateSessionResponse ────────────────│
  │                                           │
  ▼                                           ▼
             Session Created
```

`CreateSession` establishes the logical session context but does not by itself establish the user's identity.

The session therefore proceeds to the activation stage.

---

## 6. ActivateSession

`ActivateSession` associates an identity token with the previously created session.

The general structure observed in the capture was:

```text
MSG
└── ActivateSessionRequest
    ├── RequestHeader
    ├── ClientSignature
    ├── ClientSoftwareCertificates
    ├── LocaleIds
    ├── UserIdentityToken
    └── UserTokenSignature
```

Two identity-token configurations were tested against the `SecurityPolicy#None` endpoint:

1. Anonymous
2. UserName

---

## 7. Test A — Anonymous Session Activation

The first experiment established an Anonymous session without supplying user credentials.

The client output reported:

```text
SecureChannel established
Session activation succeeded
Authentication Type: Anonymous (UserTokenType: 0)
Session Timeout: 3600000 ms
```

The corresponding packet capture identified the identity token as:

```text
ActivateSessionRequest
└── UserIdentityToken
    └── AnonymousIdentityToken
        └── PolicyId:
            open62541-anonymous-policy
```

### Result

```text
Security Policy: SecurityPolicy#None
Identity:        Anonymous
Session:         ACTIVE
Result:          SUCCESS
```

This confirms that the server did not merely advertise Anonymous authentication during endpoint discovery. It **actually permitted an Anonymous application session to become active**.

### Security Significance

This creates a direct relationship between the Phase 1 and Phase 2 findings:

```text
Phase 1
Anonymous advertised
        │
        ▼
Phase 2
Anonymous session activated
```

The endpoint configuration therefore corresponds to an operationally usable unauthenticated session path.

The security impact of that session depends on the permissions assigned to the Anonymous identity, which becomes relevant to the address-space and authorization testing performed in Phase 3.

---

## 8. Test B — UserName Identity Token

The second experiment supplied:

```text
Username:
    admin

Password:
    secret_pass
```

The server rejected the credentials with:

```text
BadUserAccessDenied
0x801F0000
```

The client therefore did not obtain an authenticated UserName session.

However, the packet capture provides additional information about how the identity token was transmitted.

### Captured ActivateSessionRequest

The relevant structure was:

```text
ActivateSessionRequest
└── UserIdentityToken
    └── UserNameIdentityToken
        ├── PolicyId:
        │   open62541-username-policy
        ├── UserName:
        │   admin
        └── Password:
            RSA-OAEP encrypted ciphertext
```

The capture explicitly identified the password encryption algorithm as:

```text
http://www.w3.org/2001/04/xmlenc#rsa-oaep
```

### Result

```text
Security Policy: SecurityPolicy#None
Identity:        UserName
Username:        admin
Authentication:  REJECTED
Server Response: BadUserAccessDenied (0x801F0000)
Password:        RSA-OAEP protected
```

---

## 9. Credential-Protection Observation

The UserName experiment demonstrates an important distinction within the OPC UA security architecture.

Although the SecureChannel itself was operating with:

```text
SecurityPolicy#None
```

the password contained in the `UserNameIdentityToken` was **not transmitted as the plaintext string**:

```text
secret_pass
```

Instead, the packet capture contained RSA-OAEP ciphertext.

The username itself remained visible inside the `ActivateSessionRequest` because the surrounding SecureChannel was not encrypted.

This can be represented as:

```text
SecurityPolicy#None
        │
        ▼
ActivateSessionRequest
        │
        ├── UserName
        │      └── Visible: "admin"
        │
        └── Password
               └── RSA-OAEP protected
```

This finding prevents an important analytical mistake: **absence of SecureChannel encryption does not automatically imply that every credential field is transmitted in plaintext.**

OPC UA can apply protection at different layers of the authentication mechanism.

---

## 10. Session Lifecycle Observed in the Lab

The complete lifecycle demonstrated during the experiment can therefore be summarized as:

```text
┌──────────────────────┐
│ TCP Connection       │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ HEL / ACK            │
│ Transport Negotiation│
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ OpenSecureChannel    │
│ SecurityPolicy#None  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ SecureChannel Active │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ CreateSession        │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ ActivateSession      │
└──────────┬───────────┘
           │
       ┌───┴───────────┐
       │               │
       ▼               ▼
  Anonymous         UserName
       │               │
       ▼               ▼
    ACTIVE          REJECTED
                     │
                     ▼
             BadUserAccessDenied
```

The experiment therefore separates three different states that are easy to conflate:

* **SecureChannel established**
* **Session created**
* **Session activated with an identity**

A successful `OpenSecureChannel` does not imply that a user has authenticated, and a created session does not imply that it has been successfully activated.

---

## Security Characteristics

The Phase 2 experiment established the following security characteristics of the target configuration:

| Observation                                                | Evidence                       | Security Significance                                                             |
| ---------------------------------------------------------- | ------------------------------ | --------------------------------------------------------------------------------- |
| `SecurityPolicy#None` channel accepted                     | Successful `OpenSecureChannel` | SecureChannel provides no cryptographic message protection                        |
| Anonymous session accepted                                 | Successful `ActivateSession`   | Application session can be established without user credentials                   |
| Anonymous token identified as `open62541-anonymous-policy` | PCAP                           | Confirms the identity mechanism used by the server                                |
| Invalid UserName credentials rejected                      | `BadUserAccessDenied`          | UserName authentication is not bypassed by simply supplying arbitrary credentials |
| Username visible in `ActivateSessionRequest`               | PCAP                           | Identity information is exposed when the SecureChannel is unencrypted             |
| Password protected with RSA-OAEP                           | PCAP                           | UserName password has separate credential-level protection                        |
| Session timeout negotiated at `3600000 ms`                 | Client output                  | Session lifetime is explicitly negotiated during session creation                 |

### Key Takeaways

1. **OPC UA separates SecureChannel establishment from Session activation.**
2. **`SecurityPolicy#None` successfully permits the target to establish an unencrypted SecureChannel.**
3. **The target accepts Anonymous session activation on that endpoint.**
4. **Invalid UserName credentials are rejected with `BadUserAccessDenied`.**
5. **The UserName field is visible within the unencrypted `ActivateSessionRequest`.**
6. **The password is not plaintext in the captured request; it is protected using RSA-OAEP.**
7. **Credential protection and SecureChannel protection must therefore be analyzed separately.**
8. **The permissions available after Anonymous activation remain the subject of Phase 3.**

The next phase moves from session establishment into the OPC UA Address Space, where the active session can be used to determine which nodes, attributes, variables, and methods are actually accessible.
