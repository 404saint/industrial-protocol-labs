# Phase 4: Security Boundaries & Misconfiguration Audit

## Executive Summary

Phase 4 evaluated the security boundaries surrounding endpoint selection, certificate validation, and user authentication on the target OPC UA server.

The audit identified an insecure endpoint configuration: the server advertises a `SecurityPolicy#None` endpoint alongside four cryptographically protected endpoints. This establishes a plaintext exposure and downgrade surface, although the testing did **not** demonstrate an active protocol downgrade attack.

The authentication boundary behaved as expected when invalid username credentials were supplied, returning `BadUserAccessDenied`.

Certificate testing produced an important distinction. An initial self-signed certificate was accepted when its Application URI matched the URI advertised by the OPC UA client. A second, independently generated self-signed certificate with a different Application URI was rejected with `BadCertificateUriInvalid`. This demonstrates that the server enforces Application URI binding during the protected handshake. The tests do not, by themselves, establish whether arbitrary self-signed certificates are trusted or whether a particular trust-store configuration permits them.

---

## 1. Security Policy Exposure

### Objective

Determine whether the server exposes insecure security policies alongside cryptographically protected endpoints.

### Test

The server was queried through the OPC UA discovery mechanism and its advertised endpoint configurations were enumerated.

The target exposed five endpoints:

| Index | Security Mode    | Security Policy         | Transport Profile     |
| :---: | :--------------- | :---------------------- | :-------------------- |
| **0** | `None`           | `SecurityPolicy#None`   | `uatcp-uasc-uabinary` |
| **1** | `SignAndEncrypt` | `Aes128_Sha256_RsaOaep` | `uatcp-uasc-uabinary` |
| **2** | `Sign`           | `Aes128_Sha256_RsaOaep` | `uatcp-uasc-uabinary` |
| **3** | `SignAndEncrypt` | `Basic256Sha256`        | `uatcp-uasc-uabinary` |
| **4** | `Sign`           | `Basic256Sha256`        | `uatcp-uasc-uabinary` |

Four endpoints provide cryptographic protection, while endpoint `0` permits an unprotected channel.

### Finding

**[CRITICAL] SecurityPolicy#None endpoint exposed alongside protected endpoints.**

The server permits clients to select:

```text
SecurityMode:   None
SecurityPolicy: None
```

even though stronger `Sign` and `SignAndEncrypt` configurations are simultaneously available.

An unauthenticated client can therefore select the plaintext endpoint during endpoint selection rather than being required to use one of the protected configurations.

### Security Boundary

This test establishes **insecure endpoint exposure**, not an active downgrade attack.

No experiment was performed in which an already-established secure connection was forcibly transitioned from `SignAndEncrypt` to `None`.

The demonstrated condition is therefore more precisely described as:

> **Plaintext endpoint exposure creating a downgrade surface.**

### Security Implications

A client selecting the `SecurityPolicy#None` endpoint does not receive OPC UA message confidentiality or integrity protection from the SecureChannel.

Consequently, application-layer traffic transmitted through such a channel may be observable or modifiable by an attacker with appropriate network positioning.

This is particularly significant because Phase 2 demonstrated that anonymous sessions can successfully operate over the `SecurityPolicy#None` configuration.

---

## 2. X.509 Certificate Validation & Application URI Binding

### Objective

Determine whether the server enforces certificate identity consistency during a protected `SignAndEncrypt` handshake.

Two certificate tests were performed.

### Test A — Self-Signed Certificate With Matching Application URI

A self-signed RSA-2048 client certificate was generated locally.

The certificate contained an OPC UA Application URI matching the URI advertised by the `asyncua` client:

```text
Application URI:
urn:example.org:FreeOpcUa:opcua-asyncio
```

The certificate was then used with:

```text
Security Policy: Basic256Sha256
Security Mode:   SignAndEncrypt
```

### Result

**[OBSERVED] Connection accepted.**

The certificate was not rejected during the observed protected connection attempt.

This establishes that the tested server configuration permits this particular self-signed certificate through the observed handshake path.

However, this result alone does not establish that arbitrary self-signed certificates are trusted.

---

### Test B — Independently Generated Certificate

A second certificate was generated with:

* a completely new RSA keypair
* a new certificate
* a different subject
* a different serial number
* a different Application URI
* an independent self-signature

The Application URI was:

```text
urn:freeopcua:client:independent-test
```

The certificate was again presented using:

```text
Security Policy: Basic256Sha256
Security Mode:   SignAndEncrypt
```

### Result

**[SECURE] Certificate rejected.**

The server returned:

```text
BadCertificateUriInvalid
```

with the diagnostic:

```text
The URI specified in the ApplicationDescription
does not match the URI in the certificate.
```

### Finding

**[SECURE] Application URI binding is enforced.**

The server compares the Application URI presented through the OPC UA `ApplicationDescription` with the URI contained in the client certificate.

When those identities did not match, the protected connection was rejected.

### Important Limitation

The rejection occurred specifically because of the **Application URI mismatch**.

Therefore, this experiment does **not** prove that the server rejects certificates solely because they are self-signed or because they are absent from a configured trust store.

The evidence supports the narrower conclusion:

> The server enforces Application URI consistency between the OPC UA client identity and the presented X.509 certificate.

---

## 3. Invalid Identity Authentication

### Objective

Test whether invalid username credentials can establish an authenticated OPC UA session.

The following credentials were supplied:

```text
Username: admin_probe
Password: invalid_password_123
```

The client attempted normal session establishment against the server.

### Result

**[SECURE] Invalid credentials were rejected.**

The server returned:

```text
BadUserAccessDenied
```

with the associated message:

```text
User does not have permission to perform the requested operation.
```

No authenticated session was established using the supplied invalid credentials.

### Security Boundary

The server therefore demonstrated an effective identity authentication boundary for invalid username/password credentials.

This result should not be interpreted as evidence that the server's overall authorization model is secure.

Phase 3 demonstrated that an anonymous session was able to perform unauthorized writes against several application variables. The present test only establishes that **invalid username/password credentials are rejected**.

---

## 4. Consolidated Findings

| Test                               | Result               | Evidence                      | Assessment            |
| :--------------------------------- | :------------------- | :---------------------------- | :-------------------- |
| `SecurityPolicy#None` exposure     | **Confirmed**        | Five advertised endpoints     | **Critical exposure** |
| Active protocol downgrade          | **Not demonstrated** | No forced transition tested   | Unconfirmed           |
| Matching self-signed certificate   | **Accepted**         | Protected handshake completed | Observation           |
| Independent mismatched certificate | **Rejected**         | `BadCertificateUriInvalid`    | Secure boundary       |
| Invalid username/password          | **Rejected**         | `BadUserAccessDenied`         | Secure boundary       |

---

## 5. Security Recommendations

### 5.1 Remove `SecurityPolicy#None`

Production OPC UA deployments should remove plaintext endpoints when confidentiality and integrity are required.

The server should expose only appropriately protected configurations, preferably using:

```text
SecurityMode: SignAndEncrypt
```

with an approved modern security policy.

### 5.2 Prefer Encrypted Communication

`Sign` protects message integrity but does not provide confidentiality.

Where operational data, telemetry, credentials, or control commands are transmitted, `SignAndEncrypt` should be preferred over `Sign`.

### 5.3 Preserve Application URI Validation

The observed `BadCertificateUriInvalid` behavior demonstrates a useful certificate identity boundary.

Application URI validation should remain enabled and should be combined with appropriate certificate trust management.

### 5.4 Validate Certificate Trust Configuration Separately

The certificate experiments did not conclusively determine whether the server accepts arbitrary self-signed certificates.

A dedicated trust-store experiment would be required to distinguish:

```text
Application URI validation
```

from:

```text
Certificate trust validation
```

These should not be treated as the same security control.

### 5.5 Maintain Authentication Enforcement

The server correctly rejected invalid username/password credentials. Authentication failures should continue to be logged and monitored, particularly in production OT environments.

---

## Security Characteristics

Phase 4 demonstrated a mixed security posture.

The server exposes a plaintext OPC UA endpoint despite advertising cryptographically protected alternatives, creating a significant insecure-communication surface. At the same time, several security boundaries behaved correctly: invalid username credentials were rejected, and mismatched X.509 Application URIs were refused during the protected handshake.

The most important distinction from this phase is that **configuration exposure and security-control failure are not interchangeable findings**. The `SecurityPolicy#None` endpoint is directly demonstrated. The X.509 testing, however, demonstrated Application URI enforcement rather than a generalized certificate trust failure.

### Key Takeaways

* `SecurityPolicy#None` is publicly advertised alongside protected endpoints.
* The test demonstrates plaintext endpoint exposure, not an active downgrade attack.
* Invalid username credentials are rejected with `BadUserAccessDenied`.
* X.509 Application URI mismatches are rejected with `BadCertificateUriInvalid`.
* Acceptance of one matching self-signed certificate does not prove arbitrary self-signed certificates are trusted.
* Certificate trust-store behavior remains a separate research question.
* Phase 3's anonymous write findings remain relevant when evaluating the combined security posture of the server.
