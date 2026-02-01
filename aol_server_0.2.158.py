import socket
import struct
import binascii
import time
import sys
import traceback
from datetime import datetime

# --- Configuration ---
HOST = '0.0.0.0'
PORT = 5190
SEED = 0x5443

def get_timestamp():
    return datetime.now().strftime("[%H:%M:%S.%f]")[:-3]

def log(msg):
    print(f"{get_timestamp()} {msg}")
    sys.stdout.flush()

# --- P3 PROTOCOL ENGINE ---
class P3Handler:
    def __init__(self):
        self.tx_seq = 0x80
        self.rx_seq = 0x00
        self.handshake_seed = SEED
        self.session_seed = None
        self.mode = 'control'
        self.seed_locked = False
        self.authenticated = False
        self.screen_name = "NewUser"

    def update_crc(self, byte_val, current_crc):
        for _ in range(8):
            bit = (byte_val ^ current_crc) & 1
            current_crc >>= 1
            if bit: current_crc ^= 0x8408
            byte_val >>= 1
        return current_crc & 0xFFFF

    def get_packet_seed(self, seq):
        if self.session_seed is None: return self.handshake_seed
        return self.update_crc(seq, self.session_seed)

    def find_handshake_seed(self, payload, seq, target_crc):
        for seed_candidate in range(0xFFFF + 1):
            crc = seed_candidate
            byte_val = seq
            for _ in range(8):
                bit = (byte_val ^ crc) & 1
                crc >>= 1
                if bit: crc ^= 0x8408
                byte_val >>= 1
            for byte in payload:
                byte_val = byte
                for _ in range(8):
                    bit = (byte_val ^ crc) & 1
                    crc >>= 1
                    if bit: crc ^= 0x8408
                    byte_val >>= 1
            if (crc & 0xFFFF) == target_crc: return seed_candidate
        return None

    def find_session_seed(self, data):
        if len(data) < 8: return None
        target_crc = struct.unpack("<H", data[1:3])[0]
        len_be = struct.unpack(">H", data[3:5])[0]
        seq_pkt = data[7]
        body = data[5:5+len_be]
        for p_seed in range(0xFFFF + 1):
            crc = p_seed
            crc = self.update_crc((len_be >> 8) & 0xFF, crc)
            crc = self.update_crc(len_be & 0xFF, crc)
            for b in body: crc = self.update_crc(b, crc)
            crc = self.update_crc(0x0D, crc)
            if crc == target_crc:
                for s_seed in range(0xFFFF + 1):
                    if self.update_crc(seq_pkt, s_seed) == p_seed: return s_seed
        return None

    def construct_packet(self, payload, ack_seq=None):
        if ack_seq is not None:
            seq = ack_seq
        else:
            self.tx_seq = (self.tx_seq + 1) % 256
            if self.tx_seq < 0x80: self.tx_seq = 0x81
            seq = self.tx_seq

        if self.mode == 'control':
            length = len(payload) + 1
            crc = self.handshake_seed
            crc = self.update_crc(seq, crc)
            for b in payload: crc = self.update_crc(b, crc)
            return bytes([0x5A, crc & 0xFF, (crc >> 8) & 0xFF, (length >> 8) & 0xFF, length & 0xFF]) + payload + bytes([seq, 0x0D])
        else:
            body = b'\x7f\x7f' + bytes([seq]) + payload
            blen = len(body)
            crc = self.get_packet_seed(seq)
            crc = self.update_crc((blen >> 8) & 0xFF, crc)
            crc = self.update_crc(blen & 0xFF, crc)
            for b in body: crc = self.update_crc(b, crc)
            crc = self.update_crc(0x0D, crc)
            return bytes([0x5A, crc & 0xFF, (crc >> 8) & 0xFF, (blen >> 8) & 0xFF, blen & 0xFF]) + body + b'\x0D'

# --- HELPERS ---

def build_atom(atom_id, payload=b''):
    return struct.pack("<HH", atom_id, len(payload)) + payload

def build_p3_packet(tool_id, opcode, payload):
    return struct.pack(">HH", tool_id, opcode) + payload

def get_aol_timestamp():
    EPOCH_OFFSET = 315532800
    return int(time.time()) - EPOCH_OFFSET

def encode_string(s):
    encoded = s.encode('latin-1')
    return struct.pack('B', len(encoded)) + encoded

def build_motd_payload(text):
    text_bytes = text.encode("latin1", errors="replace")
    text_len = len(text_bytes)
    payload = b''
    payload += struct.pack(">H", 0x0001)            # ObjectType: STRING
    payload += struct.pack(">H", 0x0000)            # Flags
    payload += struct.pack(">I", 6 + 2 + text_len + 2)  # ObjectLength
    payload += struct.pack(">H", 0x0001)            # Charset (ANSI)
    payload += struct.pack(">H", text_len)           # Text length
    payload += text_bytes
    payload += struct.pack(">H", 0x0000)             # Terminator
    return payload

def build_interactive_fdo():
    """
    Builds an INTERACTIVE FDO: Page -> Container -> [Text + Button]
    """
    # 1. Static Text Object (Type 0x0001)
    text_content = b"Setup Wizard: Click Next to continue.\x00"
    text_obj = (
        struct.pack("<H", 0x0001) +  # Type: StaticText
        struct.pack("<H", 0x000A) +  # ID: 10
        struct.pack("<H", len(text_content)) +
        text_content
    )

    # 2. Button Object (Type 0x0003)
    btn_label = b"Next >\x00"
    btn_obj = (
        struct.pack("<H", 0x0003) +  # Type: Button
        struct.pack("<H", 0x000B) +  # ID: 11
        struct.pack("<H", len(btn_label)) +
        btn_label
    )

    # 3. Container Object (Type 0x0002) - Holds Text + Button
    container_content = text_obj + btn_obj
    container = (
        struct.pack("<H", 0x0002) +  # Type: Container
        struct.pack("<H", 0x0005) +  # ID
        struct.pack("<I", len(container_content)) +
        container_content
    )

    # 4. Wizard Page Object (Type 0x0006)
    page = (
        struct.pack("<H", 0x0006) +  # Type: Page
        struct.pack("<H", 0x0001) +  # ID: 1
        struct.pack("<I", len(container)) +
        container
    )

    # 5. FDO Header
    fdo = (
        struct.pack("<I", 1) +       # Version
        struct.pack("<I", 1) +       # Page count
        page
    )

    return fdo

def build_discovery_response():
    atoms_list = []
    atoms_list.append(build_atom(0x0001, b'\x01')) 
    atoms_list.append(build_atom(0x0002, b'\x00\x00\x00\x00'))
    atoms_list.append(build_atom(0x0003, b'\x00\x00\x00\x00'))
    atoms_list.append(build_atom(0x0004, b'\x07\x00\x00\x00')) 
    atom_1000 = (struct.pack("<I", 1) + struct.pack("<I", 0x70000) + struct.pack(">I", 0x1039) + struct.pack("<I", 0xFFFFFFFF))
    atoms_list.append(build_atom(0x1000, atom_1000))
    atom_1010 = struct.pack("<IIH", 1, get_aol_timestamp(), 1)
    atoms_list.append(build_atom(0x1010, atom_1010))
    tools = [(0x1, 1), (0x3, 1), (0x10, 1), (0x17, 1), (0x1B, 1), (0x22, 1), (0x28, 1), (0x39, 3), (0x3A, 3), (0x40, 1), (0x41, 1)]
    for tid, flags in tools: atoms_list.append(build_atom(tid, bytes([flags])))
    atoms_list.append(build_atom(0x1D00, b'\x00\x00\x00\x00'))
    atoms_list.append(build_atom(0x011F, b'\x01'))
    return b''.join(atoms_list)

def build_csl_service_list():
    services = [(0x39, 0x100, 0x80000001), (0x22, 0x100, 1), (0x40, 0x100, 1), (0x41, 0x100, 1), (0x1B, 0x100, 0x80000001)]
    payload = b''
    for svc_id, ver, flags in services: payload += struct.pack('>HHL', svc_id, ver, flags)
    return payload, len(services)

def send_packet(conn, p3_handler, payload, description=""):
    pkt = p3_handler.construct_packet(payload)
    hex_dump = binascii.hexlify(pkt[:16]).decode('utf-8')
    log(f"TX: {hex_dump}... (Len={len(pkt)}) [{description}]")
    conn.send(pkt)

def send_ack(conn, p3_handler, seq_pkt):
    pkt = p3_handler.construct_packet(b'', ack_seq=seq_pkt)
    conn.send(pkt)

# --- POST-AUTH SEQUENCE ---
def send_post_auth_sequence(conn, p3):
    log(">>> 🎯 SENDING WIZARD START SEQUENCE...")
    
    # 1. Screen Name Confirm
    screen_name_data = struct.pack("<I", 0x00000001) + encode_string(p3.screen_name)
    send_packet(conn, p3, build_p3_packet(0x0001, 0x0006, screen_name_data), "Screen Name Confirm")
    time.sleep(0.05)
    
    # 2. MOTD
    motd_text = "Welcome to AOL 7.0 Server (v0.2.158)!\n\nAuthenticating... Success!"
    motd_data = build_motd_payload(motd_text)
    send_packet(conn, p3, build_p3_packet(0x0001, 0x0002, motd_data), "MOTD Object")
    time.sleep(0.05)
    
    # REGISTRATION STATUS
    reg_status_payload = struct.pack("<I", 0xFFFFFFFF) 
    log(">>> 🚦 SENDING REG_STATUS = NOT_REGISTERED...")
    send_packet(conn, p3, build_p3_packet(0x001B, 0x0002, reg_status_payload), "REG_STATUS (Not Registered)")
    time.sleep(0.05)

    # REGISTRATION INIT
    reg_init_payload = b'\x00\x00\x00\x00'
    log(">>> 🚀 SENDING REG_INIT (Force Wizard)...")
    send_packet(conn, p3, build_p3_packet(0x001B, 0x0001, reg_init_payload), "REG_INIT (Start Wizard)")
    time.sleep(0.05)
    
    # REG_BIND_CONTEXT (Op 0x0003)
    ctx_payload = struct.pack("<I", 0x00000001) # Context ID = 1
    log(">>> 🔗 SENDING REG_BIND_CONTEXT (Make Wizard Interactive)...")
    send_packet(conn, p3, build_p3_packet(0x001B, 0x0003, ctx_payload), "REG_BIND_CONTEXT")
    time.sleep(0.05)

    # ---------------------------------------------------------------------
    # FIX: REG_SET_STATE (Op 0x0006) - THE ACTIVATION SIGNAL
    # Tells the Wizard: "Input enabled, Go to Active State"
    # ---------------------------------------------------------------------
    state_payload = struct.pack("<I", 0x00000001) # State = 1 (Active/Running)
    log(">>> ⚡ SENDING REG_SET_STATE (Activate UI)...")
    send_packet(conn, p3, build_p3_packet(0x001B, 0x0006, state_payload), "REG_SET_STATE (Active)")
    time.sleep(0.05)

    # INTERACTIVE FDO
    fdo_payload = build_interactive_fdo()
    log(">>> 🧬 SENDING INTERACTIVE FDO (Text + Button)...")
    send_packet(conn, p3, build_p3_packet(0x001B, 0x0008, fdo_payload), "FDO PUSH (Interactive)")
    time.sleep(0.1)

    # PAGE LOAD COMMAND
    page_load = struct.pack("<HH", 0x0001, 0x0000)
    log(">>> 📟 SENDING PAGE LOAD COMMAND (Page 1)...")
    send_packet(conn, p3, build_p3_packet(0x001B, 0x0004, page_load), "WIZARD LOAD PAGE 1")
    time.sleep(0.05)

    # ... rest of post-auth ...
    config_data = (struct.pack("<I", 1) + struct.pack("<I", get_aol_timestamp()) + encode_string(p3.screen_name) + struct.pack("<H", 0))
    send_packet(conn, p3, build_p3_packet(0x0001, 0x0004, config_data), "User Config")
    time.sleep(0.05)
    
    buddy_data = struct.pack("<HH", 0, 0)
    send_packet(conn, p3, build_p3_packet(0x0003, 0x0002, buddy_data), "Buddy List Initial")
    time.sleep(0.05)
    
    buddy_ready = struct.pack("<I", 1)
    send_packet(conn, p3, build_p3_packet(0x0003, 0x0001, buddy_ready), "Buddy List Ready")
    time.sleep(0.05)
    
    online_data = struct.pack("<I", 2)
    send_packet(conn, p3, build_p3_packet(0x0001, 0x0005, online_data), "Online Status")
    time.sleep(0.05)
    
    session_ready = struct.pack("<I", 1)
    send_packet(conn, p3, build_p3_packet(0x0001, 0x0007, session_ready), "Session Ready")
    
    log(">>> ✅ WIZARD SEQUENCE COMPLETE")


# --- SERVER MAIN ---
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    log(f"AOL 7 Server Alpha 0.2.158 (ACTIVATE UI) listening on Port {PORT}")

    while True:
        try:
            conn, addr = server.accept()
            conn.settimeout(30.0)
            log(f"!!! Incoming connection from {addr} !!!")
            
            p3 = P3Handler()
            p3.mode = 'control'
            p3.tx_seq = 0x80

            while True:
                try:
                    data = conn.recv(4096)
                except socket.timeout:
                    log("Timeout.")
                    break
                except ConnectionResetError:
                    log("Connection RST.")
                    break
                if not data:
                    log("Connection FIN.")
                    break

                if data[0] != 0x5A: continue

                crc_pkt = struct.unpack("<H", data[1:3])[0]
                len_pkt = struct.unpack(">H", data[3:5])[0]
                if len(data) < 5 + len_pkt: continue
                seq_pkt = data[len(data)-2]
                payload = data[5:5+len_pkt]

                if p3.mode == 'control':
                    if not p3.seed_locked:
                        found = p3.find_handshake_seed(payload, seq_pkt, crc_pkt)
                        if found:
                            p3.handshake_seed = found
                            p3.seed_locked = True
                            log(f"Handshake Seed: 0x{found:04X}")
                    if len(payload) >= 2 and struct.unpack(">H", payload[0:2])[0] == 0x7F7F:
                        send_ack(conn, p3, seq_pkt)
                        p3.mode = 'normal'
                        log("Mode: NORMAL. Waiting for client...")
                        continue
                    send_ack(conn, p3, seq_pkt)

                elif p3.mode == 'normal':
                    if p3.session_seed is None and len(data) > 8:
                        seed = p3.find_session_seed(data)
                        if seed: p3.session_seed = seed
                    
                    seq_pkt = data[7]
                    send_ack(conn, p3, seq_pkt)

                    if len(data) > 12:
                        tool_id = struct.unpack(">H", data[8:10])[0]
                        opcode = struct.unpack(">H", data[10:12])[0]
                        
                        log(f"RX Tool=0x{tool_id:04X} Op=0x{opcode:04X} Len={len(payload)}")

                        if tool_id == 0x0001: # CORE
                            if len(payload) > 100:
                                if not p3.authenticated:
                                    log(f">>> 🆔 CLIENT IDENTITY DETECTED!")
                                    payload_start = 12
                                    payload_end = len(data) - 1 
                                    if payload_end > payload_start:
                                        identity_struct = data[payload_start:payload_end]
                                        response_payload = bytearray(identity_struct)
                                        log(">>> Executing: TRUE ECHO MIRROR")
                                        send_packet(conn, p3, build_p3_packet(0x0001, 0x0001, bytes(response_payload)), "Identity Mirror")
                                        
                                        # CORE AUTH FIX
                                        log(">>> 🔑 SENDING LOGIN SUCCESS (CORE 0x0008)...")
                                        login_ok = struct.pack("<I", 0x00000001)
                                        send_packet(conn, p3, build_p3_packet(0x0001, 0x0008, login_ok), "LOGIN SUCCESS (Password OK)")
                                        time.sleep(0.05)

                                        log(">>> Sending: STATE ADVANCE")
                                        state_advance = struct.pack("<II", 0x00000002, 0x00000000)
                                        send_packet(conn, p3, build_p3_packet(0x0001, 0x0003, state_advance), "State Advance")

                                        log(">>> Sending: FINAL P3 CONTROL FRAME")
                                        send_packet(conn, p3, b'', "Final P3 ACK")
                                        
                                        send_post_auth_sequence(conn, p3)
                                        p3.authenticated = True
                                        log(">>> 🎊 CLIENT AUTHENTICATED & WIZARD SHOULD START!")
                                    else: log("!!! ERROR: Unexpected packet length.")
                                else: log(">>> ⚠️ DUPLICATE IDENTITY RECEIVED")

                            elif opcode == 0x0001:
                                log(">>> 🌍 DISCOVERY REQUEST RECEIVED!")
                                resp = build_discovery_response()
                                send_packet(conn, p3, build_p3_packet(0x0001, 0x0001, resp), "Discovery Response")
                        
                        elif tool_id == 0x001B: # REGISTRATION TOOL
                            log(f">>> 📝 REGISTRATION TOOL (Op 0x{opcode:04X})")
                            
                            if opcode == 0x0004:
                                log(">>> 📟 WIZARD PAGE REQUEST DETECTED! IT WORKS!")
                            
                            if opcode == 0x0005:
                                log(">>> 💾 REGISTRATION DATA SUBMITTED!")

                            send_packet(conn, p3, build_p3_packet(0x001B, opcode, b'\x00\x00\x00\x01'), "REG GENERIC ACK")

                        elif tool_id == 0x003A: # CSL
                            if opcode == 0x0009:
                                csl_payload, count = build_csl_service_list()
                                send_packet(conn, p3, build_p3_packet(0x003A, 0x0009, struct.pack('>H', count)), "CSL Length Resp")
                            elif opcode == 0x0008:
                                csl_payload, count = build_csl_service_list()
                                send_packet(conn, p3, build_p3_packet(0x003A, 0x0008, csl_payload), "CSL List Data")
                            elif opcode == 0x0001:
                                send_packet(conn, p3, build_p3_packet(0x003A, 0x0001, b'\x01'), "CSL Supported")
                            else:
                                send_packet(conn, p3, build_p3_packet(0x003A, opcode, b'\x00\x00'), "CSL Generic ACK")
                        else:
                            send_packet(conn, p3, build_p3_packet(tool_id, opcode, b'\x00\x00'), "Generic ACK")

        except Exception as e:
            log(f"ERROR: {e}")
            traceback.print_exc()
        finally:
            if 'conn' in locals(): conn.close()
            log("Closed.")

if __name__ == "__main__":
    start_server()
