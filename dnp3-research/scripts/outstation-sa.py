import sys
import time
import socket
import struct
import logging
from dataclasses import dataclass, field
from typing import Tuple, Optional, Dict

# Configure logging for protocol inspection
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("DNP3-Outstation")

# ============================================================================
# DNP3 CONSTANTS & PROTOCOL ENUMERATIONS
# ============================================================================

DNP3_START_BYTES = b'\x05\x64'

# Function Codes
FC_READ = 0x01
FC_WRITE = 0x02
FC_SELECT = 0x03
FC_OPERATE = 0x04
FC_DIRECT_OPERATE = 0x05
FC_CONFIRM = 0x00
FC_RESPONSE = 0x81
FC_UNSOLICITED_RESPONSE = 0x82

# DNP3 Objects (Group, Variation)
OBJ_BINARY_INPUT_EVENT = (2, 1)
OBJ_ANALOG_INPUT_EVENT = (32, 1)
OBJ_CROB = (12, 1)  # Control Relay Output Block
OBJ_SECURITY_STAT_RESPONSE = (121, 1)

# Secure Authentication Function Codes (DNP3 SAv5 / IEC 62351-5)
FC_AUTH_REQUEST = 0x20
FC_AUTH_RESPONSE = 0x21

# DNP3 SA Variation Types
SA_CHALLENGE = 1
SA_REPLY = 2
SA_AGRESSOR_CHECK = 3
SA_SESSION_KEY_STATUS = 4
SA_SESSION_KEY_CHANGE = 5
SA_ERROR = 7


# ============================================================================
# CRC UTILITIES (DNP3 CRC-16 Kernal)
# ============================================================================

def compute_dnp3_crc(data: bytes) -> int:
    """Computes standard DNP3 CRC-16 (inverted remainder)."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc >>= 1
    return ~crc & 0xFFFF


def append_crc_block(data: bytes) -> bytes:
    """Appends 2-byte little-endian CRC to a block of up to 16 bytes."""
    crc = compute_dnp3_crc(data)
    return data + struct.pack('<H', crc)


def verify_crc_block(block_with_crc: bytes) -> bool:
    """Verifies DNP3 CRC for a block containing data + 2-byte CRC."""
    if len(block_with_crc) < 3:
        return False
    data = block_with_crc[:-2]
    expected_crc = struct.unpack('<H', block_with_crc[-2:])[0]
    return compute_dnp3_crc(data) == expected_crc


# ============================================================================
# STATE TRACKING & DATA MODELS
# ============================================================================

@dataclass
class DNP3Header:
    start: bytes
    length: int
    control: int
    dest: int
    source: int
    header_crc: int


@dataclass
class SecuritySession:
    """Tracks state for DNP3 Secure Authentication Session Keys."""
    session_key_sequence: int = 0
    hmac_key: bytes = field(default_factory=lambda: b'\x00' * 16)
    encryption_key: bytes = field(default_factory=lambda: b'\x00' * 16)
    challenge_count: int = 0
    is_authenticated: bool = False


class OutstationDatabase:
    """In-memory operational database for binary/analog points."""
    def __init__(self):
        self.binary_inputs: Dict[int, bool] = {0: False, 1: True, 2: False}
        self.analog_inputs: Dict[int, float] = {0: 120.5, 1: 13.8, 2: 60.0}
        self.crob_states: Dict[int, str] = {0: "LATCH_OFF", 1: "LATCH_OFF"}

    def read_binary(self, index: int) -> Optional[bool]:
        return self.binary_inputs.get(index)

    def write_crob(self, index: int, code: int) -> bool:
        if index in self.crob_states:
            self.crob_states[index] = f"OPERATED_CODE_{code}"
            return True
        return False


# ============================================================================
# PROTOCOL PARSER & BUILDER ENGINE
# ============================================================================

class DNP3OutstationEngine:
    def __init__(self, outstation_addr: int = 1, master_addr: int = 100):
        self.outstation_addr = outstation_addr
        self.master_addr = master_addr
        self.db = OutstationDatabase()
        self.sa_session = SecuritySession()
        self.tx_sequence = 0
        self.rx_sequence = 0

    def parse_link_layer(self, raw: bytes) -> Optional[Tuple[DNP3Header, bytes]]:
        """Parses DNP3 Link Layer framing and verifies header CRC."""
        if len(raw) < 10:
            logger.debug("Frame too short for DNP3 header")
            return None

        if raw[0:2] != DNP3_START_BYTES:
            logger.error("Invalid DNP3 Start Bytes")
            return None

        length = raw[2]
        control = raw[3]
        dest = struct.unpack('<H', raw[4:6])[0]
        source = struct.unpack('<H', raw[6:8])[0]
        header_crc = struct.unpack('<H', raw[8:10])[0]

        if not verify_crc_block(raw[0:10]):
            logger.error("DNP3 Link Header CRC Mismatch")
            return None

        header = DNP3Header(
            start=DNP3_START_BYTES,
            length=length,
            control=control,
            dest=dest,
            source=source,
            header_crc=header_crc
        )

        payload_with_crc = raw[10:]
        return header, payload_with_crc

    def extract_user_data(self, payload_crc: bytes, expected_length: int) -> bytes:
        """Strips 2-byte CRCs every 16 bytes of transport/app payload."""
        user_data = bytearray()
        idx = 0
        remaining_bytes = expected_length - 5  # Excluding Link Layer control/addr fields

        while idx < len(payload_crc) and remaining_bytes > 0:
            block_len = min(16, remaining_bytes)
            chunk = payload_crc[idx : idx + block_len]
            crc_bytes = payload_crc[idx + block_len : idx + block_len + 2]

            if not verify_crc_block(chunk + crc_bytes):
                logger.error("Payload CRC mismatch in transport chunk")
                return bytes()

            user_data.extend(chunk)
            idx += block_len + 2
            remaining_bytes -= block_len

        return bytes(user_data)

    def process_application_layer(self, app_data: bytes) -> bytes:
        """
        Parses Application Control, Function Code, and Objects.
        Constructs appropriate Application-layer response payload.
        """
        if len(app_data) < 2:
            return b""

        app_ctrl = app_data[0]
        func_code = app_data[1]
        payload = app_data[2:]

        seq = app_ctrl & 0x0F
        logger.info(f"Rx App Frame: Sequence={seq}, FunctionCode=0x{func_code:02X}")

        # Response Header Setup (FIR=1, FIN=1, CON=0, UNS=0 + SEQ)
        resp_ctrl = 0xC0 | (seq & 0x0F)

        # Handle Standard Read (FC 0x01)
        if func_code == FC_READ:
            return self._handle_read_request(resp_ctrl, payload)

        # Handle Control / Operate (FC 0x03 Select, FC 0x04 Operate, FC 0x05 Direct Operate)
        elif func_code in (FC_SELECT, FC_OPERATE, FC_DIRECT_OPERATE):
            return self._handle_control_request(resp_ctrl, func_code, payload)

        # Handle SA Request (FC 0x20)
        elif func_code == FC_AUTH_REQUEST:
            return self._handle_sa_request(resp_ctrl, payload)

        else:
            logger.warning(f"Unhandled Function Code: 0x{func_code:02X}")
            # Internal Indications (IIN2.1 = Function Code Not Supported)
            return bytes([resp_ctrl, FC_RESPONSE, 0x00, 0x02])

    def _handle_read_request(self, resp_ctrl: int, payload: bytes) -> bytes:
        """Builds response for Binary/Analog point polling."""
        # Internal Indications: IIN1=0, IIN2=0
        response = bytearray([resp_ctrl, FC_RESPONSE, 0x00, 0x00])

        if len(payload) >= 3:
            group = payload[0]
            variation = payload[1]
            logger.info(f"Read Request for Group {group}, Variation {variation}")

            # Example: Group 1 Var 2 (Binary Input with Status)
            if group == 1:
                response.extend([0x01, 0x02, 0x00, 0x00, 0x02])  # Header + Range (0..2)
                response.extend([0x81, 0x01, 0x80])  # Status flags for 3 channels

            # Example: Group 30 Var 1 (32-bit Analog Input)
            elif group == 30:
                response.extend([0x1E, 0x01, 0x00, 0x00, 0x00])  # Header + Range (Index 0)
                response.extend([0x01])  # Status Flags: Online
                response.extend(struct.pack('<i', 12050))  # Value 120.50 scaled

        return bytes(response)

    def _handle_control_request(self, resp_ctrl: int, func_code: int, payload: bytes) -> bytes:
        """Handles Select/Operate sequences for CROB objects."""
        response = bytearray([resp_ctrl, FC_RESPONSE, 0x00, 0x00])
        
        # Mirror payload for Select/Operate ACK pattern if Object is CROB (Group 12)
        if len(payload) > 0 and payload[0] == OBJ_CROB[0]:
            logger.info(f"Control Action Executed (FC=0x{func_code:02X})")
            response.extend(payload)
            # Control Status Code 0 = Success (attached at end of CROB structure)
            response.append(0x00) 
        else:
            # IIN2.3 = Parameter Error
            response[3] |= 0x08

        return bytes(response)

    def _handle_sa_request(self, resp_ctrl: int, payload: bytes) -> bytes:
        """Handles DNP3 SA Challenge/Response Handshake Parsing."""
        if len(payload) < 2:
            return bytes([resp_ctrl, FC_RESPONSE, 0x0E, 0x00])  # Auth Error

        sa_variation = payload[1]
        logger.info(f"Processing SA Request (Variation={sa_variation})")

        response = bytearray([resp_ctrl, FC_AUTH_RESPONSE, 0x00, 0x00])

        if sa_variation == SA_CHALLENGE:
            # Construct Challenge Response (Group 120 Var 1)
            response.extend([120, SA_CHALLENGE])
            challenge_seq = struct.pack('<I', self.sa_session.challenge_count)
            user_num = struct.pack('<H', 1)  # Default User 1
            mac_algo = b'\x01'  # HMAC-SHA-256-8
            reason = b'\x01'    # Reason: Critical Function
            nonce = b'\xAA' * 8  # 8-byte Random Challenge Nonce

            response.extend(challenge_seq + user_num + mac_algo + reason + nonce)
            self.sa_session.challenge_count += 1

        elif sa_variation == SA_REPLY:
            # Validate Session Key Response (Group 120 Var 2)
            logger.info("SA Reply payload received. Authenticating session...")
            self.sa_session.is_authenticated = True
            # Respond with Session Key Status (Group 120 Var 4)
            response.extend([120, SA_SESSION_KEY_STATUS])
            response.extend(struct.pack('<I', self.sa_session.session_key_sequence))

        return bytes(response)

    def wrap_link_and_transport(self, app_payload: bytes) -> bytes:
        """Wraps Application payload with Transport Header and Link Layer CRCs."""
        # Single-frame transport wrap (TH = FIR | FIN | Sequence)
        transport_header = bytes([0xC0 | (self.tx_sequence & 0x3F)])
        self.tx_sequence = (self.tx_sequence + 1) % 64

        tp_payload = transport_header + app_payload
        user_data_len = len(tp_payload) + 5  # Control + Dest(2) + Source(2)

        # Build Link Header
        header_raw = (
            DNP3_START_BYTES +
            bytes([user_data_len, 0x44]) +  # Control: DIR=0, PRM=0, FC=UserData
            struct.pack('<H', self.master_addr) +
            struct.pack('<H', self.outstation_addr)
        )
        link_header = append_crc_block(header_raw)

        # Chunk transport payload into 16-byte blocks with CRCs
        chunked_payload = bytearray()
        for i in range(0, len(tp_payload), 16):
            chunk = tp_payload[i : i + 16]
            chunked_payload.extend(append_crc_block(chunk))

        return link_header + bytes(chunked_payload)


# ============================================================================
# NETWORK SERVER EXECUTION (LOOPBACK EMBEDDED ENGINE)
# ============================================================================

def run_outstation_server(host: str = "0.0.0.0", port: int = 20000):
    engine = DNP3OutstationEngine()
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind((host, port))
        server_sock.listen(5)
        logger.info(f"DNP3 Outstation Server listening on {host}:{port}")

        while True:
            conn, addr = server_sock.accept()
            logger.info(f"Incoming connection from Master station: {addr}")

            try:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break

                    logger.debug(f"Raw Bytes Recv [{len(data)}]: {data.hex()}")
                    
                    parsed = engine.parse_link_layer(data)
                    if parsed:
                        header, payload_crc = parsed
                        app_raw = engine.extract_user_data(payload_crc, header.length)
                        
                        if app_raw:
                            # Strip Transport Header (1 byte)
                            app_payload = app_raw[1:]
                            response_app = engine.process_application_layer(app_payload)

                            if response_app:
                                frame_out = engine.wrap_link_and_transport(response_app)
                                conn.sendall(frame_out)
                                logger.info(f"Tx Response Sent ({len(frame_out)} bytes)")
            except ConnectionResetError:
                logger.warning("Master client connection reset.")
            finally:
                conn.close()

    except KeyboardInterrupt:
        logger.info("Stopping DNP3 Outstation emulator.")
    finally:
        server_sock.close()


if __name__ == "__main__":
    run_outstation_server()