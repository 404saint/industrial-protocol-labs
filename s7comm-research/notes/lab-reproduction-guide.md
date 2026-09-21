# S7comm Security Research Laboratory

> A reproducible laboratory environment for examining classic S7comm communication over ISO-on-TCP using the Snap7 native C++ server and custom Python research clients.

# 1. Laboratory Overview

This laboratory reproduces the environment used throughout the S7comm research phases.

The target is a native C++ Snap7 server listening on TCP/102 and exposing a simulated S7 PLC memory model. Custom Python clients construct and transmit S7comm traffic directly, while `tcpdump`, Wireshark, and `tshark` are used to validate the resulting exchanges at the wire level. The laboratory is intentionally local. The target server binds to `0.0.0.0:102`, while the research clients connect to `127.0.0.1:102` through the loopback interface.

The environment is designed to reproduce the protocol observations documented in Phases 1 through 5. Phase 6 is a specification and research contrast with modern S7CommPlus security and does not require an additional laboratory target.

## Components

| Component               | Purpose                         |
| ----------------------- | ------------------------------- |
| Snap7 1.4.2             | Native S7 PLC simulation target |
| C++ server example      | S7comm target endpoint          |
| Python research clients | Hand-crafted protocol requests  |
| TCP/102                 | ISO-on-TCP transport            |
| TPKT / COTP             | Session establishment           |
| Wireshark / tshark      | Packet inspection               |
| tcpdump                 | PCAP capture                    |
| DB3                     | Primary test memory area        |
| Loopback interface      | Isolated local transport        |

## Research Scope

The observations in this laboratory describe the behavior of the tested Snap7 1.4.2 implementation and its configuration.

They should not automatically be interpreted as behavior of Siemens S7-300, S7-400, S7-1200, or S7-1500 hardware. Where a packet is constructed for a service that the emulator does not implement, the research records the transmitted request and the emulator's response or lack of response rather than claiming behavior on a real PLC.

---

# 2. Host Requirements

The laboratory was built on a Linux host with the following general requirements:

* GNU C++ compiler
* `make`
* Python 3
* `rich` and `scapy`
* `wget`
* `p7zip`
* `tcpdump`
* Wireshark or `tshark`
* `sudo` access for TCP/102 and packet capture

TCP/102 is a privileged port on Linux, so the Snap7 server is launched with the required privileges.

Create the laboratory directory:

```bash
mkdir -p ~/Desktop/s7comm-lab
cd ~/Desktop/s7comm-lab
```

---

# 3. Obtain Snap7 1.4.2

Download the Snap7 1.4.2 archive:

```bash
wget https://sourceforge.net/projects/snap7/files/1.4.2/snap7-full-1.4.2.7z
```

Install the extraction utility:

```bash
sudo apt install p7zip
```

Extract the archive into the laboratory directory:

```bash
7z x snap7-full-1.4.2.7z -osnap7-code
```

The resulting source tree should contain:

```text
snap7-code/
└── snap7-full-1.4.2/
```

---

# 4. Build the Snap7 Library

Move into the Unix build directory:

```bash
cd ~/Desktop/s7comm-lab/snap7-code/snap7-full-1.4.2/build/unix
```

Build the x86_64 Linux library:

```bash
make -f x86_64_linux.mk
```

The resulting library is expected under:

```text
snap7-full-1.4.2/build/bin/x86_64-linux/
```

The primary shared library used by the example server is:

```text
libsnap7.so
```

---

# 5. Build the Native C++ Server

Move to the Snap7 C++ example directory:

```bash
cd ~/Desktop/s7comm-lab/snap7-code/snap7-full-1.4.2/examples/cpp/x86_64-linux
```

Compile the server:

```bash
g++ -O3 \
    -o server \
    ../server.cpp \
    ../snap7.cpp \
    -I.. \
    -L../../../build/bin/x86_64-linux \
    -lsnap7
```

The resulting executable is: `server`. The server links against the Snap7 library built in the previous step.

---

# 6. Configure the Runtime Library Path

The server requires the Snap7 shared library to be discoverable at runtime.

From the same directory:

```bash
export LD_LIBRARY_PATH=../../../build/bin/x86_64-linux:$LD_LIBRARY_PATH
```

The example server can now be started directly:

```bash
sudo LD_LIBRARY_PATH=$LD_LIBRARY_PATH ./server
```

A successful launch produces:

```text
2026-09-21 11:15:05 Server started
```

The server can be stopped with:

```text
Ctrl+C
```

---

# 7. Create the Research Server Launcher

For repeatable experiments, the research environment uses a small launcher script instead of manually entering the library path each time.

From:

```text
~/Desktop/s7comm-lab
```

create:

```bash
cat << 'EOF' > run_plc_server.sh
#!/usr/bin/env bash
# S7comm Research Lab - Native C++ Server Launcher

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_PATH="$PROJECT_ROOT/snap7-code/snap7-full-1.4.2/build/bin/x86_64-linux"
SERVER_BIN="$PROJECT_ROOT/snap7-code/snap7-full-1.4.2/examples/cpp/x86_64-linux/server"

if [ ! -f "$SERVER_BIN" ]; then
    echo "[-] Server binary not found at $SERVER_BIN"
    exit 1
fi

export LD_LIBRARY_PATH="$BIN_PATH:$LD_LIBRARY_PATH"

echo "=========================================================="
echo "      S7comm Native C++ PLC Target Server                "
echo "=========================================================="
echo "[*] Library Path : $BIN_PATH"
echo "[*] Listener     : 0.0.0.0:102 (ISO-on-TCP / TPKT / COTP)"
echo "[*] PID          : $$"
echo "=========================================================="

exec "$SERVER_BIN"
EOF
```

Make it executable:

```bash
chmod +x run_plc_server.sh
```

From this point forward, the target can be started from the laboratory root with:

```bash
sudo ./run_plc_server.sh
```

A successful launch should resemble:

```text
==========================================================
      S7comm Native C++ PLC Target Server
==========================================================
[*] Library Path : /home/tesla/Desktop/s7comm-lab/snap7-code/snap7-full-1.4.2/build/bin/x86_64-linux
[*] Listener     : 0.0.0.0:102 (ISO-on-TCP / TPKT / COTP)
[*] PID          : <PID>
==========================================================
2026-09-21 11:15:05 Server started
```

---

# 8. Verify TCP/102

Before beginning the research phases, verify that the server is listening:

```bash
sudo ss -lntp | grep ':102'
```

The endpoint should report TCP/102 in the listening state.

The research clients use:

```text
Target: 127.0.0.1
Port:   102
```

The server itself listens on:

```text
0.0.0.0:102
```

This allows the same target to accept local connections through the loopback interface while retaining the standard S7comm service port.

---

# 9. Research Client Layout

The research clients are stored in the laboratory root alongside the server launcher.

The phase structure is:

```text
s7comm-lab/scripts
├── run_plc_server.sh
├── phase1_cotp_handshake.py
├── phase2_pdu_enumeration.py
├── phase3_write_control_abuse.py
├── phase4_szl_enumerator.py
├── phase5_state_anomalies.py
```

The Python clients generate the S7comm requests used during the research phases.

They intentionally expose the protocol construction rather than relying exclusively on a high-level S7 client library. This makes the TPKT, COTP, S7comm, and service-level fields visible in the research workflow.

---

# 10. Packet Capture

Create the PCAP directory before starting the experiments:

```bash
mkdir -p pcaps
```

The laboratory uses `tcpdump` on the loopback interface because all test traffic is exchanged between the local research client and the local Snap7 target.

The general capture format is:

```bash
sudo tcpdump -i lo port 102 -w pcaps/<phase>.pcap
```

For example:

```bash
sudo tcpdump -i lo port 102 -w pcaps/phase1-cotp-handshake.pcap
```

Leave the capture running while executing the corresponding phase script.

When the experiment finishes, stop `tcpdump` with:

```text
Ctrl+C
```

The resulting PCAP can then be inspected with Wireshark:

```bash
wireshark pcaps/phase1-cotp-handshake.pcap
```

or with `tshark`:

```bash
tshark -r pcaps/phase1-cotp-handshake.pcap
```

A useful general filter is:

```bash
tshark -r pcaps/<phase>.pcap -Y "tcp.port == 102"
```

The PCAPs are laboratory artifacts. The research notes should record decoded protocol observations rather than embedding raw packet dumps.

---

# 11. Phase 1 Reproduction: COTP / TPKT Session Establishment

## Objective

Reproduce the initial ISO-on-TCP connection sequence and examine COTP Connection Request and Connection Confirm behavior.

Start the target:

```bash
sudo ./run_plc_server.sh
```

From another terminal, start the capture:

```bash
sudo tcpdump -i lo port 102 -w pcaps/phase1-cotp-handshake.pcap
```

Run the Phase 1 client:

```bash
python3 phase1_cotp_handshake.py
```

The client establishes a TCP connection to: `127.0.0.1:102` and constructs a COTP Connection Request containing the Siemens-style TSAP values used by the experiment.



The resulting PCAP can be inspected for:

* TPKT version and length
* COTP CR / CC
* Source and destination references
* Calling/called TSAP values
* TPDU size parameter
* TCP connection timing
* Connection acceptance or rejection

Stop the packet capture after the client finishes.

---

# 12. Phase 2 Reproduction: PDU Negotiation and Memory Read

Restart the server if required:

```bash
sudo ./run_plc_server.sh
```

Start a capture:

```bash
sudo tcpdump -i lo port 102 -w pcaps/phase2-pdu-enumeration.pcap
```

Run:

```bash
python3 phase2_pdu_enumeration.py
```

The client performs the normal COTP establishment sequence followed by S7comm Setup Communication. The experiment negotiates a maximum S7 PDU size of: `480 bytes`.



The PCAP should be checked for:

* S7comm ROSCTR values
* Setup Communication parameters
* Negotiated PDU size
* ReadVar function `0x04`
* S7-Any variable specification
* DB number
* Area identifier
* Requested byte range
* Return code
* Returned data length

Stop the capture when the client exits.

---

# 13. Phase 3 Reproduction: Memory Write and Control-Plane Testing

Start the Snap7 target:

```bash
sudo ./run_plc_server.sh
```

Capture the experiment:

```bash
sudo tcpdump -i lo port 102 -w pcaps/phase3-write-control-abuse.pcap
```

Run:

```bash
python3 phase3_write_control_abuse.py
```

The phase performs three separate tests. The corresponding capture contains the three test exchanges and can be examined independently in Wireshark.

---

# 14. Phase 4 Reproduction: SZL Diagnostic Enumeration

Start the target:

```bash
sudo ./run_plc_server.sh
```

Capture:

```bash
sudo tcpdump -i lo port 102 -w pcaps/phase4-szl-diagnostics.pcap
```

Run:

```bash
python3 phase4_szl_enumerator.py
```

The client performs two UserData diagnostic queries.  SZL `0x0011` and SZL `0x0111`. The resulting PCAP allows comparison of: `successful UserData diagnostic request` against: `unsupported / unavailable diagnostic request`

Inspect the capture for:

* ROSCTR `0x07`
* SZL identifiers
* request/response pairing
* response status
* returned diagnostic payload
* session establishment preceding each query

---

# 15. Phase 5 Reproduction: State and Resource Anomaly Testing

Phase 5 contains multiple experiments and should be captured as one research run if the corresponding script executes them sequentially.

Start the target:

```bash
sudo ./run_plc_server.sh
```

Capture:

```bash
sudo tcpdump -i lo port 102 -w pcaps/phase5-state-anomalies.pcap
```

Run:

```bash
python3 phase5_state_anomalies.py
```


The PCAP can be used to inspect:

* repeated TCP connections
* COTP establishment
* Setup Communication
* malformed TPKT length fields
* connection duration
* session teardown

---

# 16. Wireshark Analysis

Open any captured phase with:

```bash
wireshark pcaps/<phase>.pcap
```

For general S7comm traffic:

```text
tcp.port == 102
```



For experiments involving UserData, inspect the S7comm ROSCTR and associated function or diagnostic structures. The packet view should be used to verify the custom client's output rather than treating the Python client output as the sole source of truth.

---

# 17. tshark Validation

`tshark` provides a convenient command-line validation path.

For example:

```bash
tshark -r pcaps/phase1-cotp-handshake.pcap
```

To focus on TCP/102:

```bash
tshark \
    -r pcaps/phase1-cotp-handshake.pcap \
    -Y "tcp.port == 102"
```

For COTP-focused inspection:

```bash
tshark \
    -r pcaps/phase1-cotp-handshake.pcap \
    -Y "cotp"
```

The exact available field names depend on the installed Wireshark version, so field-specific extraction should be verified with:

```bash
tshark -G fields | grep -i s7comm
```

---

# 18. Laboratory Reset Procedure

Some experiments modify DB3. Restarting the Snap7 server is therefore the simplest way to return the target to its initial state between independent experiments.

Stop the running server:

```text
Ctrl+C
```

Start it again:

```bash
sudo ./run_plc_server.sh
```

Before each phase, confirm that:

```text
TCP/102 is listening
Snap7 server is running
DB3 is available
previous PCAP capture is not still active
```

For repeatable results, use a fresh PCAP for every phase rather than appending multiple experiments to the same capture.

---

# 19. Recommended Experiment Workflow

A complete reproduction run follows this sequence:

```text
Build Snap7
    ↓
Build native C++ server
    ↓
Create launcher
    ↓
Start server
    ↓
Start tcpdump
    ↓
Run phase client
    ↓
Stop tcpdump
    ↓
Inspect PCAP
    ↓
Compare client output with wire behavior
    ↓
Record implementation-specific observation
    ↓
Restart server
    ↓
Next phase
```

The important verification principle is that every security observation should have two supporting sources where possible:

```text
Client-side observation
        +
Wire-level observation
        =
Research finding
```

This prevents an application-level script message from being mistaken for proof of what was actually transmitted or accepted by the target.

---

# 20. Phase-to-PCAP Mapping

| Phase   | Client                          | Primary PCAP                      | Main Observation                           |
| ------- | ------------------------------- | --------------------------------- | ------------------------------------------ |
| Phase 1 | `phase1_cotp_handshake.py`      | `phase1-cotp-handshake.pcap`      | TPKT/COTP establishment and TSAP behavior  |
| Phase 2 | `phase2_pdu_enumeration.py`     | `phase2-pdu-enumeration.pcap`     | PDU negotiation and ReadVar                |
| Phase 3 | `phase3_write_control_abuse.py` | `phase3-write-control-abuse.pcap` | WriteVar, bounds checking, control request |
| Phase 4 | `phase4_szl_enumerator.py`      | `phase4-szl-diagnostics.pcap`     | SZL diagnostic enumeration                 |
| Phase 5 | `phase5_state_anomalies.py`     | `phase5-state-anomalies.pcap`     | State handling and resource behavior       |
| Phase 6 | None                            | None                              | Specification/research contrast            |

---

# 21. Expected Laboratory Boundaries

The laboratory intentionally separates three different kinds of evidence.

### ⟶ Protocol Construction

A Python client can construct a valid-looking S7comm request and place it on the wire.

### ⟶ Target Processing

The Snap7 server may accept, reject, ignore, or terminate the connection after receiving that request.

### ⟶Real PLC Behavior

A Siemens PLC may implement additional state checks, authentication, access protection, firmware-specific behavior, or security mechanisms that are absent from the emulator.


---

# 22. Reproducibility Checklist

Before considering the laboratory ready for reproduction, verify:

```text
[✔] Snap7 1.4.2 archive downloaded
[✔] Snap7 source extracted
[✔] x86_64 Linux library built
[✔] Native C++ server compiled
[✔] LD_LIBRARY_PATH resolves libsnap7.so
[✔] run_plc_server.sh is executable
[✔] Server listens on TCP/102
[✔] Python research clients are present
[✔] pcaps/ directory exists
[✔] tcpdump captures on loopback interface
[✔] Phase 1 PCAP reproduced
[✔] Phase 2 PCAP reproduced
[✔] Phase 3 PCAP reproduced
[✔] Phase 4 PCAP reproduced
[✔] Phase 5 PCAP reproduced
[✔] Wireshark/tshark confirms packet observations
[✔] Server restarted between independent experiments
[✔] Snap7-specific findings remain scoped to Snap7
```



After completing the research, the laboratory should contain the Snap7 source/build tree, the native C++ target, the research clients, and the captured PCAP artifacts. This environment provides a controlled target for reproducing the packet-level S7comm observations documented throughout the research series while keeping emulator-specific behavior clearly separated from claims about physical Siemens PLCs.
