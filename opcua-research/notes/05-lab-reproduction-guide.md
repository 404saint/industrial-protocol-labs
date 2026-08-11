# Phase 5: Lab Reproduction & Automation Guide

## Executive Summary

This document provides the reproducible workflow for deploying the isolated OPC UA research environment, capturing protocol traffic, and executing the audit scripts developed throughout Phases 1–4.

The laboratory uses a containerized `open62541` OPC UA server and a Python-based research client built with `asyncua`. Network traffic is captured from the Docker virtual bridge and retained as PCAP artifacts for protocol-level verification.

The reproduction sequence covers:

1. Endpoint discovery and security-policy enumeration
2. SecureChannel and session establishment
3. Anonymous and username identity testing
4. Address-space traversal and access-level auditing
5. Unauthenticated write testing
6. Security-policy exposure analysis
7. Invalid identity authentication testing
8. Independent X.509 trust-boundary validation

All testing is intended for the isolated laboratory environment.

---

# 1. Prerequisites & Environment Setup

## 1.1 Host Requirements

The research workstation requires:

* Python 3.x
* Docker
* `asyncua`
* `cryptography`
* `rich`
* Wireshark and/or `tcpdump`
* `tshark` for command-line PCAP inspection

The tested environment uses Linux with Docker networking enabled.

---

## 1.2 Python Environment

Create an isolated Python virtual environment:

```bash
python3 -m venv opcua-env
source opcua-env/bin/activate
```

Install the Python dependencies:

```bash
pip install asyncua cryptography rich
```

Verify the installation:

```bash
python -c "import asyncua, cryptography, rich; print('Dependencies OK')"
```

---

# 2. Target Emulation

The laboratory target is an isolated OPC UA server based on `open62541`.

The server listens on the standard OPC UA TCP port:

```text
opc.tcp://127.0.0.1:4840
```

## 2.1 Launch the Target

Start the container:

```bash
docker run -d \
  --name opc-ua-lab-server \
  -p 4840:4840 \
  open62541/open62541:master
```

Verify that the container is running:

```bash
docker ps -f name=opc-ua-lab-server
```

Verify the port is exposed:

```bash
ss -lntp | grep 4840
```

The expected result is a listener on TCP port `4840`.

---

## 2.2 Verify OPC UA Connectivity

Before beginning the audit sequence, confirm that the target responds:

```bash
nmap -p 4840 127.0.0.1
```

Expected result:

```text
4840/tcp open
```

The exact service fingerprint may vary depending on the installed `nmap` probes and server configuration.

---

# 3. Packet Capture Methodology

Protocol-level evidence is collected from the Docker virtual bridge:

```text
docker0
```

The capture filter restricts traffic to OPC UA TCP:

```text
tcp port 4840
```

This allows the resulting PCAPs to be correlated directly with individual research phases.

## 3.1 Wireshark Capture

Start Wireshark:

```bash
sudo -E wireshark -i docker0 -k -f "tcp port 4840"
```

Save each phase under a separate filename.

Alternatively, capture directly with `tcpdump`:

```bash
sudo tcpdump -i docker0 -nn -s 0 -w opcua_phase1.pcap 'tcp port 4840'
```

Stop the capture after the corresponding audit script completes.

---

# 4. Phase 1 — Endpoint Enumeration

### Script

```text
phase1_get_endpoints.py
```

### Objective

Enumerate OPC UA discovery information before authentication, including:

* Application metadata
* Application URI
* Product URI
* Endpoint URLs
* Security modes
* Security policies
* Supported user identity tokens

Start the capture:

```bash
sudo tcpdump -i docker0 -nn -s 0 \
  -w opcua_phase1.pcap \
  'tcp port 4840'
```

In another terminal:

```bash
python phase1_get_endpoints.py
```

The validated laboratory configuration exposed five endpoints:

```text
SecurityMode=None
SecurityMode=SignAndEncrypt
SecurityMode=Sign
SecurityMode=SignAndEncrypt
SecurityMode=Sign
```

The `SecurityPolicy#None` endpoint represents the primary insecure transport finding.

---

# 5. Phase 2 — SecureChannel & Session Handshake

### Script

```text
phase2_session_handshake.py
```

### Objective

Evaluate the transition from transport establishment to OPC UA session activation.

The test covers:

* `HEL`
* `ACK`
* `OPN`
* `CreateSession`
* `ActivateSession`
* Anonymous identity
* Username identity
* Session termination

Start the capture:

```bash
sudo tcpdump -i docker0 -nn -s 0 \
  -w opcua_phase2.pcap \
  'tcp port 4840'
```

Run:

```bash
python phase2_session_handshake.py
```

### Expected Findings

The anonymous test successfully established and activated a session through the `SecurityPolicy#None` endpoint.

The username authentication test using intentionally invalid credentials was rejected with:

```text
BadUserAccessDenied
```

However, the authentication test requires wire-level verification because OPC UA `UserNameIdentityToken` handling depends on the negotiated security configuration.

Inspect the resulting PCAP for the `ActivateSessionRequest`:

```bash
tshark -r opcua_phase2.pcap \
  -Y 'opcua' -V |
  grep -i -A 50 -B 10 'ActivateSessionRequest'
```

The validated capture demonstrated:

```text
UserNameIdentityToken
    PolicyId: open62541-username-policy
    UserName: admin
    Password: <encoded/encrypted value>
    EncryptionAlgorithm: RSA-OAEP
```

This distinction is important: the username was visible in the decoded request, while the password field was represented as an RSA-OAEP encrypted value rather than literal plaintext.

Therefore, the Phase 2 evidence should not describe the password as cleartext merely because the transport endpoint itself uses `SecurityPolicy#None`.

---

# 6. Phase 3 — Address Space Traversal & Write Audit

### Script

```text
phase3_node_traversal.py
```

### Objective

Evaluate the address-space information model and determine whether anonymous access permits unauthorized variable modification.

The script performs:

1. Browse-path resolution
2. Object graph traversal
3. Variable discovery
4. `AccessLevel` inspection
5. `UserAccessLevel` inspection
6. Value reads
7. Controlled write attempts
8. Value restoration after successful writes

Run the capture:

```bash
sudo tcpdump -i docker0 -nn -s 0 \
  -w opcua_phase3.pcap \
  'tcp port 4840'
```

Execute:

```bash
python phase3_node_traversal.py
```

The script writes its terminal output to:

```text
phase3_output.txt
```

## Expected Result

Most of the traversed address space is denied or otherwise inaccessible to the anonymous client.

However, the laboratory exposed several writable variables.

Validated results included:

| Variable             |     Original |        Probe Value | Result             |
| -------------------- | -----------: | -----------------: | ------------------ |
| `Boolean`            |      `False` |             `True` | **Write accepted** |
| `integer`            |          `0` |                `1` | **Write accepted** |
| `Double`             |        `0.0` |              `1.0` | **Write accepted** |
| `Int64`              |          `0` |                `1` | **Write accepted** |
| `example bytestring` | `b'test123'` | `b'test123_probe'` | **Write accepted** |

Each successful mutation was subsequently reverted to its original value by the research script.

The important observation is therefore not that the entire address space was writable. Rather:

> The anonymous session could traverse the exposed address space sufficiently to identify writable variables, and selected application variables accepted unauthenticated write operations.

This establishes an authorization boundary failure for those specific nodes.

---

# 7. Phase 4 — Security Boundaries & Misconfiguration Audit

### Script

```text
phase4_security_audit.py
```

### Objective

Evaluate:

* Security-policy exposure
* Plaintext endpoint availability
* Invalid identity rejection
* X.509 certificate validation behavior

Start the capture:

```bash
sudo tcpdump -i docker0 -nn -s 0 \
  -w opcua_phase4.pcap \
  'tcp port 4840'
```

Execute:

```bash
python phase4_security_audit.py
```

---

## 7.1 Security Policy Exposure

The endpoint discovery process should identify both protected and unprotected configurations.

The validated laboratory configuration exposed:

```text
SecurityPolicy#None
Aes128_Sha256_RsaOaep / Sign
Aes128_Sha256_RsaOaep / SignAndEncrypt
Basic256Sha256 / Sign
Basic256Sha256 / SignAndEncrypt
```

The presence of the `SecurityPolicy#None` endpoint establishes insecure endpoint exposure.

It does **not**, by itself, prove an active downgrade attack.

The appropriate conclusion is:

```text
The server advertises a plaintext security configuration alongside
cryptographically protected endpoints.
```

---

## 7.2 Invalid Identity Authentication

The audit attempts authentication using deliberately invalid credentials:

```text
Username: admin_probe
Password: invalid_password_123
```

Run as part of:

```bash
python phase4_security_audit.py
```

The validated result was:

```text
BadUserAccessDenied
```

This demonstrates that the server's configured identity layer rejected the invalid credentials.

---

# 8. Phase 4.2 — Independent X.509 Trust-Boundary Retest

### Script

```text
phase4_security_audit_2.py
```

This is a separate validation experiment created to eliminate ambiguity from the original certificate test.

### Objective

Determine whether the server accepts a completely independent self-signed client certificate during a protected `Basic256Sha256 / SignAndEncrypt` connection.

The retest deliberately generates:

* A new RSA keypair
* A new self-signed certificate
* A new certificate subject
* A new serial number
* An independent Application URI

The certificate is therefore unrelated to the previous Phase 4 test artifact.

Execute:

```bash
python phase4_security_audit_2.py
```

### Expected Result

The validated server response was:

```text
BadCertificateUriInvalid
```

The server rejected the independent certificate during the tested handshake.

The observed error was:

```text
The URI specified in the ApplicationDescription does not match
the URI in the certificate.
```

This provides evidence that the server enforces Application URI consistency during the tested X.509 handshake.

The experiment should therefore **not** be described as proof of complete PKI trust-store validation. It establishes that the independently generated certificate did not cross the tested certificate-validation boundary.

---

# 9. Artifact Collection

After completing the phases, consolidate the generated evidence:

```bash
mkdir -p captures
mkdir -p logs
```

Move packet captures:

```bash
mv opcua_phase*.pcap ./captures/
```

Move textual audit logs:

```bash
mv phase*_output.txt ./logs/ 2>/dev/null
```

Verify the resulting structure:

```text
opcua-lab/
├── captures/
│   ├── opcua_phase1.pcap
│   ├── opcua_phase2.pcap
│   ├── opcua_phase3.pcap
│   └── opcua_phase4.pcap
│
├── logs/
│   ├── phase3_output.txt
│   ├── phase4_output.txt
│   └── phase4_output_2.txt
│
├── phase1_get_endpoints.py
├── phase2_session_handshake.py
├── phase3_node_traversal.py
├── phase4_security_audit.py
└── phase4_security_audit_2.py
```

Certificate artifacts generated during Phase 4.2 can be retained separately for certificate inspection:

```text
untrusted_cert.pem
untrusted_key.pem
```

Private keys should not be committed to a public repository.

---

# 10. Target Teardown

After evidence collection, stop and remove the laboratory target:

```bash
docker stop opc-ua-lab-server
docker rm opc-ua-lab-server
```

Confirm that the container has been removed:

```bash
docker ps -a -f name=opc-ua-lab-server
```

---

# 11. Reproduction Summary

The complete research workflow is therefore:

```text
Target Deployment
       │
       ▼
Phase 1
Endpoint Enumeration
       │
       ▼
Phase 2
SecureChannel & Session Analysis
       │
       ▼
PCAP Verification
       │
       ▼
Phase 3
Address Space Traversal
       │
       ▼
Access-Level & Write Audit
       │
       ▼
Phase 4
Security Boundary Analysis
       │
       ├───────────────┐
       ▼               ▼
Identity Audit     X.509 Retest
       │               │
       └───────┬───────┘
               ▼
        Artifact Collection
               │
               ▼
             Teardown
```

Each phase is independently reproducible and produces either terminal evidence, packet-level evidence, or both.

---

# 12. Research Safety & Scope

All tests described in this guide were conducted against an isolated laboratory target under controlled conditions.

The scripts are intended for protocol research, defensive validation, and authorized security assessment. They should not be executed against production OPC UA infrastructure without explicit authorization.

The laboratory deliberately exposes insecure configurations and writable test variables so that protocol behavior and authorization boundaries can be observed without interacting with operational industrial equipment.
