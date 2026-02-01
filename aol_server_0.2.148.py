import socket
import struct
import binascii
import time
import sys
import traceback
from datetime import datetime

# --- KONFIGURATION ---
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

def build_discovery_response():
    # DISCOVERY RESPONSE
    atoms_list = []
    atoms_list.append(build_atom(0x0001, b'\x01')) 
    atoms_list.append(build_atom(0x0002, b'\x00\x00\x00\x00'))
    atoms_list.append(build_atom(0x0003, b'\x00\x00\x00\x00'))
    atoms_list.append(build_atom(0x0004, b'\x07\x00\x00\x00')) 

    atom_1000 = (
        struct.pack("<I", 0x00000001) +   
        struct.pack("<I", 0x00070000) +   
        struct.pack(">I", 0x00001039) +   
        struct.pack("<I", 0xFFFFFFFF)     
    )
    atoms_list.append(build_atom(0x1000, atom_1000))

    atom_1010 = struct.pack("<IIH", 0x00000001, get_aol_timestamp(), 0x0001)
    atoms_list.append(build_atom(0x1010, atom_1010))

    tools = [
        (0x0001, 0x01), (0x0003, 0x01), (0x0010, 0x01), (0x0017, 0x01), 
        (0x001B, 0x01), (0x0022, 0x01), (0x0028, 0x01), 
        (0x0039, 0x03), 
        (0x003A, 0x03), 
        (0x0040, 0x01), (0x0041, 0x01)
    ]
    for tid, flags in tools:
        atoms_list.append(build_atom(tid, bytes([flags])))

    atoms_list.append(build_atom(0x1D00, b'\x00\x00\x00\x00'))
    atoms_list.append(build_atom(0x011F, b'\x01'))
    return b''.join(atoms_list)

def build_csl_service_list():
    services = [
        (0x0039, 0x0100, 0x80000001), 
        (0x0022, 0x0100, 0x00000001), 
        (0x0040, 0x0100, 0x00000001), 
        (0x0041, 0x0100, 0x00000001), 
        (0x001B, 0x0100, 0x80000001)
    ]
    payload = b''
    for svc_id, ver, flags in services:
        payload += struct.pack('>HHL', svc_id, ver, flags)
    return payload, len(services)

def send_packet(conn, p3_handler, payload, description=""):
    pkt = p3_handler.construct_packet(payload)
    hex_dump = binascii.hexlify(pkt[:16]).decode('utf-8')
    log(f"TX: {hex_dump}... (Len={len(pkt)}) [{description}]")
    conn.send(pkt)

def send_ack(conn, p3_handler, seq_pkt):
    pkt = p3_handler.construct_packet(b'', ack_seq=seq_pkt)
    conn.send(pkt)

# --- SERVER MAIN ---
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(1)
    log(f"AOL Server v0.44 (TRUE ECHO FIX) bereit auf Port {PORT}")

    while True:
        try:
            conn, addr = server.accept()
            conn.settimeout(30.0)
            log(f"!!! NEUE VERBINDUNG von {addr} !!!")
            
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
                    log("Verbindung RST.")
                    break
                
                if not data:
                    log("Verbindung FIN.")
                    break

                if data[0] != 0x5A: continue

                crc_pkt = struct.unpack("<H", data[1:3])[0]
                len_pkt = struct.unpack(">H", data[3:5])[0]
                
                if len(data) < 5 + len_pkt: continue
                
                seq_pkt = data[len(data)-2]
                payload = data[5:5+len_pkt]

                if p3.mode == 'control':
                    # HANDSHAKE
                    if not p3.seed_locked:
                        found = p3.find_handshake_seed(payload, seq_pkt, crc_pkt)
                        if found:
                            p3.handshake_seed = found
                            p3.seed_locked = True
                            log(f"Handshake Seed: 0x{found:04X}")
                    
                    if len(payload) >= 2 and struct.unpack(">H", payload[0:2])[0] == 0x7F7F:
                        send_ack(conn, p3, seq_pkt)
                        p3.mode = 'normal'
                        log("Mode: NORMAL. Warten auf Client-Anfrage...")
                        continue
                    send_ack(conn, p3, seq_pkt)

                elif p3.mode == 'normal':
                    # SESSION
                    if p3.session_seed is None and len(data) > 8:
                        seed = p3.find_session_seed(data)
                        if seed:
                            p3.session_seed = seed
                            log(f"Session Seed: 0x{seed:04X}")
                    
                    seq_pkt = data[7]
                    send_ack(conn, p3, seq_pkt)

                    if len(data) > 12:
                        tool_id = struct.unpack(">H", data[8:10])[0]
                        opcode = struct.unpack(">H", data[10:12])[0]
                        
                        log(f"RX Tool=0x{tool_id:04X} Op=0x{opcode:04X} Len={len(payload)}")

                        if tool_id == 0x0001: # CORE
                            if len(payload) > 100:
                                log(f">>> 🆔 CLIENT IDENTITY DETECTED!")
                                
                                # FIX v0.43 Logic: Correct Slicing (12 to -1)
                                payload_start = 12
                                payload_end = len(data) - 1 
                                
                                if payload_end > payload_start:
                                    identity_struct = data[payload_start:payload_end]
                                    log(f">>> Extracted Identity Struct: {len(identity_struct)} bytes")
                                    
                                    # FIX v0.44 Logic: TRUE ECHO (Kein Timestamp Modify)
                                    response_payload = bytearray(identity_struct)
                                    
                                    # WIR ENTFERNEN DAS TIMESTAMP UPDATE!
                                    # ts = get_aol_timestamp()
                                    # if len(response_payload) >= 12:
                                    #     response_payload[8:12] = struct.pack(">I", ts)
                                    
                                    log(">>> Executing: TRUE ECHO MIRROR (No changes) + State Advance")
                                    send_packet(conn, p3, build_p3_packet(0x0001, 0x0001, bytes(response_payload)), "Identity Mirror")
                                    
                                    # State Advance (Op 0x0003)
                                    state_advance = struct.pack("<II", 0x00000002, 0x00000000)
                                    send_packet(conn, p3, build_p3_packet(0x0001, 0x0003, state_advance), "State Advance (AUTH->ONLINE)")
                                else:
                                    log("!!! ERROR: Packet strange length.")

                            elif opcode == 0x0001:
                                log(">>> 🌍 DISCOVERY REQUEST RECEIVED!")
                                resp = build_discovery_response()
                                send_packet(conn, p3, build_p3_packet(0x0001, 0x0001, resp), "Discovery Response")
                        
                        elif tool_id == 0x003A: # CSL
                            if opcode == 0x0009:
                                csl_payload, count = build_csl_service_list()
                                log(f">>> 📦 CSL LENGTH REQUEST.")
                                send_packet(conn, p3, build_p3_packet(0x003A, 0x0009, struct.pack('>H', count)), "CSL Length Resp")
                            elif opcode == 0x0008:
                                csl_payload, count = build_csl_service_list()
                                log(f">>> 📜 CSL LIST REQUEST.")
                                send_packet(conn, p3, build_p3_packet(0x003A, 0x0008, csl_payload), "CSL List Data")
                            elif opcode == 0x0001:
                                send_packet(conn, p3, build_p3_packet(0x003A, 0x0001, b'\x01'), "CSL Supported")
                            else:
                                send_packet(conn, p3, build_p3_packet(0x003A, opcode, b'\x00\x00'), "CSL Generic ACK")

                        elif tool_id == 0x001B: # REGISTRATION
                            log(f">>> 📝 REGISTRATION/SIGN-ON TOOL (Op 0x{opcode:04X})")
                            send_packet(conn, p3, build_p3_packet(0x001B, opcode, b'\x00\x00\x00\x01'), "REG GENERIC ACK")

                        elif tool_id == 0x0039: # COMM
                            send_packet(conn, p3, build_p3_packet(0x0039, opcode, b'\x00\x00\x00\x00'), "COMM OK")
                        
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
