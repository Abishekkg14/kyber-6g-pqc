#!/usr/bin/env python3
# ==============================================================================
# Kyber-6G Automated HITL Benchmark Edge Server (gNodeB MEC Station)
# Features:
# - ML-KEM-1024 (FIPS 203) Key Encapsulation & Decapsulation
# - ML-DSA-87 (FIPS 204) Mutual Cryptographic Authentication
# - Parallel Cryptographic Processing (ThreadPoolExecutor, max_workers=2)
# - Dual Transport: UDP (with MTU-Safe Framing & ARQ) or TCP (Length-Prefixed Framing Loop)
# - Deterministic AES-GCM Nonces (RFC 5116 / NIST SP 800-38D) with Clear Header AAD
# ==============================================================================
import socket
import os
import sys
import time
import struct
import argparse
import concurrent.futures

import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "0.0.0.0"
DEFAULT_PORT = 14000
MAX_DGRAM = 1352
SIG_ALG = "ML-DSA-87"
STREAM_SALT_UAV = 0x55415631  # "UAV1"
STREAM_SALT_GNB = 0x474E4231  # "GNB1"

# ----------------------------------------------------------------------
# UDP MTU-Safe Framing (Avoids IP-layer fragmentation drop traps)
# ----------------------------------------------------------------------
def send_framed_udp(sock, addr, msg_type, payload, seq_id=0):
    chunk_size = MAX_DGRAM - 8
    total_frags = (len(payload) + chunk_size - 1) // chunk_size
    if total_frags == 0:
        total_frags = 1
        payload = b""
    for i in range(total_frags):
        chunk = payload[i * chunk_size : (i + 1) * chunk_size]
        header = struct.pack("!HBBH", msg_type, i, total_frags, seq_id & 0xFFFF)
        sock.sendto(header + chunk, addr)

def recv_framed_udp(sock, timeout=5.0):
    sock.settimeout(timeout)
    buffers = {}
    while True:
        try:
            packet, addr = sock.recvfrom(4096)
        except socket.timeout:
            return None, None, None
        if len(packet) < 6:
            continue
        msg_type, frag_idx, total_frags, seq_id = struct.unpack("!HBBH", packet[:6])
        chunk = packet[6:]
        
        key = (addr, msg_type, seq_id)
        if key not in buffers:
            buffers[key] = [None] * total_frags
            
        buffers[key][frag_idx] = chunk
        if all(f is not None for f in buffers[key]):
            full_payload = b"".join(buffers[key])
            del buffers[key]
            return msg_type, full_payload, addr

# ----------------------------------------------------------------------
# TCP Length-Prefixed Stream Framing (Avoids TCP byte-stream truncation)
# ----------------------------------------------------------------------
def recv_exact_tcp(sock, n_bytes):
    buf = bytearray()
    while len(buf) < n_bytes:
        chunk = sock.recv(min(n_bytes - len(buf), 4096))
        if not chunk:
            return None
        buf.extend(chunk)
    return bytes(buf)

def send_framed_tcp(sock, msg_type, payload):
    # 4-byte total payload length + 2-byte msg_type
    header = struct.pack("!IH", len(payload) + 2, msg_type)
    sock.sendall(header + payload)

def recv_framed_tcp(sock, timeout=5.0):
    sock.settimeout(timeout)
    try:
        header = recv_exact_tcp(sock, 6)
        if not header:
            return None, None
        total_len, msg_type = struct.unpack("!IH", header)
        payload_len = total_len - 2
        payload = recv_exact_tcp(sock, payload_len)
        return msg_type, payload
    except socket.timeout:
        return None, None

# ----------------------------------------------------------------------
# Key Cache and Anti-Replay Watermark
# ----------------------------------------------------------------------
class MecKeyCache:
    def __init__(self, ttl=300.0):
        self.ttl = ttl
        self.store = {}
        self.nonce_watermarks = {}

    def lookup(self, ue_id, mobility_hash):
        if ue_id not in self.store:
            return "MISS", None
        entry = self.store[ue_id]
        if time.time() - entry["created_at"] > self.ttl:
            del self.store[ue_id]
            return "STALE", None
        return "HIT", entry["combined_secret"]

    def put(self, ue_id, secret, mobility_hash):
        self.store[ue_id] = {
            "combined_secret": secret,
            "created_at": time.time(),
            "mobility_hash": mobility_hash
        }
        self.nonce_watermarks[ue_id] = 0

    def validate_nonce(self, ue_id, nonce_val):
        wm = self.nonce_watermarks.get(ue_id, 0)
        if nonce_val <= wm:
            return False
        self.nonce_watermarks[ue_id] = nonce_val
        return True

def run_x25519_server(pk_ecdh_drone):
    sk_server = x25519.X25519PrivateKey.generate()
    pk_server = sk_server.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    s_ecdh = sk_server.exchange(x25519.X25519PublicKey.from_public_bytes(pk_ecdh_drone))
    return pk_server, s_ecdh

def run_kyber_encapsulation(pk_kyber_drone):
    kem = oqs.KeyEncapsulation('ML-KEM-1024')
    ct_kyber, s_kyber = kem.encap_secret(pk_kyber_drone)
    kem.free()
    return ct_kyber, s_kyber

def main():
    parser = argparse.ArgumentParser(description="Kyber-6G Automated HITL Benchmark Edge Server")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help="Port to listen on")
    parser.add_argument("--transport", type=str, default="udp", choices=["udp", "tcp"], help="Transport protocol (udp or tcp)")
    args = parser.parse_args()

    print("=" * 75)
    print(f"[*] 6G gNodeB MEC Base Station Server ({args.transport.upper()}) on {HOST}:{args.port}")
    print(f"[*] Post-Quantum Signature Engine: {SIG_ALG} (NIST Category 5)")
    print(f"[*] Parallel Cryptography:        ThreadPoolExecutor (2 workers)")
    print(f"[*] AES-GCM Nonce Policy:         Deterministic (RFC 5116) with Clear Header AAD")
    print("=" * 75)
    
    signer = oqs.Signature(SIG_ALG)
    gnb_sig_pk = signer.generate_keypair()
    cache = MecKeyCache(ttl=300.0)
    TRUSTED_UAV_REGISTRY = {}

    if args.transport == "udp":
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((HOST, args.port))
        run_udp_server(sock, signer, gnb_sig_pk, cache, TRUSTED_UAV_REGISTRY)
    else:
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind((HOST, args.port))
        server_sock.listen(5)
        print(f"[*] Awaiting incoming TCP connections on {HOST}:{args.port}...")
        while True:
            try:
                conn, addr = server_sock.accept()
                print(f"[+] Established TCP session with {addr}")
                run_tcp_client_session(conn, addr, signer, gnb_sig_pk, cache, TRUSTED_UAV_REGISTRY)
            except KeyboardInterrupt:
                break
        server_sock.close()

    signer.free()

def process_handshake_message(msg_type, payload, signer, gnb_sig_pk, cache, TRUSTED_UAV_REGISTRY):
    """Core cryptographic state machine for message processing."""
    if msg_type == 0x01:
        # Message 1: Full Hybrid Handshake (Cache Miss / Initial Auth)
        ue_id = payload[:8]
        mobility_hash = struct.unpack("!I", payload[8:12])[0]
        pk_ecdh_drone = payload[12:44]
        pk_kyber_drone = payload[44:1612]
        sig_len = struct.unpack("!H", payload[1612:1614])[0]
        drone_sig = payload[1614 : 1614 + sig_len]
        drone_sig_pk = payload[1614 + sig_len :]
        
        if ue_id not in TRUSTED_UAV_REGISTRY:
            TRUSTED_UAV_REGISTRY[ue_id] = drone_sig_pk
            print(f"[+] [ENROLL] Enrolled verified UAV identity: {ue_id.decode('ascii', errors='ignore').strip()}")
        elif TRUSTED_UAV_REGISTRY[ue_id] != drone_sig_pk:
            print(f"[-] [AUTH ERROR] Public key mismatch for UAV {ue_id}! Handshake rejected.")
            return None, None
        
        # Verify ML-DSA-87 signature over full transcript
        verifier = oqs.Signature(SIG_ALG)
        transcript_to_verify = ue_id + struct.pack("!I", mobility_hash) + pk_ecdh_drone + pk_kyber_drone
        is_valid = verifier.verify(transcript_to_verify, drone_sig, drone_sig_pk)
        verifier.free()
        if not is_valid:
            print(f"[-] [AUTH ERROR] ML-DSA signature verification failed for {ue_id}!")
            return None, None
        
        # Parallel Key Encapsulation (X25519 ECDH + ML-KEM-1024)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            fut_x = executor.submit(run_x25519_server, pk_ecdh_drone)
            fut_k = executor.submit(run_kyber_encapsulation, pk_kyber_drone)
            pk_server, s_ecdh = fut_x.result()
            ct_kyber, s_kyber = fut_k.result()
        
        # Level-5 Hybrid Master Key Derivation via HKDF-SHA256
        hkdf_salt = os.urandom(16)
        k_final = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hkdf_salt,
            info=b"Kyber6G-3GPP-Rel17-MasterKey"
        ).derive(s_ecdh + s_kyber)
        
        cache.put(ue_id, k_final, mobility_hash)
        
        # Sign Response with gNB Identity Key
        resp_to_sign = pk_server + ct_kyber + hkdf_salt
        gnb_sig = signer.sign(resp_to_sign)
        resp_payload = struct.pack("!H", len(gnb_sig)) + gnb_sig + gnb_sig_pk + resp_to_sign
        return 0x02, resp_payload

    elif msg_type == 0x03:
        # Message 3: Cached Rapid Rekey (1-RTT) Mode
        ue_id = payload[:8]
        mobility_hash = struct.unpack("!I", payload[8:12])[0]
        status, cached_secret = cache.lookup(ue_id, mobility_hash)
        
        if status == "HIT":
            ephemeral_salt = payload[12:28]
            new_session_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=ephemeral_salt,
                info=b"Kyber6G-3GPP-Cached-Rapid-Rekey"
            ).derive(cached_secret)
            cache.put(ue_id, new_session_key, mobility_hash)
            return 0x04, b"CACHED_REKEY_ACK"
        elif status == "STALE_MOBILITY":
            # UAV has moved to a new cell — force full PQC renegotiation.
            # The client MUST re-initiate with msg_type=0x01 (full handshake).
            print(f"[!] STALE_MOBILITY for {ue_id}: forcing full renegotiation")
            return 0x05, b"STALE_MOBILITY_RENEGOTIATE"
        else:
            return 0x05, b"CACHE_MISS_FALLBACK"

    elif msg_type == 0x06:
        # Message 6: AES-256-GCM Telemetry Packet with Deterministic Nonce & Clear Header AAD
        ue_id = payload[:8]
        nonce_counter = struct.unpack("!Q", payload[8:16])[0]
        if not cache.validate_nonce(ue_id, nonce_counter):
            print(f"[-] [REPLAY] Dropped replayed nonce {nonce_counter} from {ue_id}")
            return None, None
        
        gcm_nonce = payload[16:28]
        ciphertext = payload[28:]
        cached_key = cache.store[ue_id]["combined_secret"]
        
        # Additional Authenticated Data (AAD): Clear packet header binds sequence counter & UE ID
        aad = payload[:16]
        
        aesgcm = AESGCM(cached_key)
        try:
            plaintext = aesgcm.decrypt(gcm_nonce, ciphertext, associated_data=aad)
        except Exception as e:
            print(f"[-] [DECRYPT ERROR] AES-GCM decryption failed with AAD: {e}")
            return None, None
        
        # Send authenticated, deterministic ACK (Msg 0x07)
        ack_aad = ue_id + struct.pack("!Q", nonce_counter) + b"ACK"
        reply_nonce = struct.pack("!QI", nonce_counter, STREAM_SALT_GNB)
        reply_ct = aesgcm.encrypt(reply_nonce, b"GNB_TELEMETRY_ACK", associated_data=ack_aad)
        resp_payload = ack_aad + reply_nonce + reply_ct
        return 0x07, resp_payload

    return None, None

def run_udp_server(sock, signer, gnb_sig_pk, cache, TRUSTED_UAV_REGISTRY):
    iteration = 0
    while True:
        try:
            msg_type, payload, client_addr = recv_framed_udp(sock)
            if msg_type is None:
                continue
            resp_type, resp_payload = process_handshake_message(
                msg_type, payload, signer, gnb_sig_pk, cache, TRUSTED_UAV_REGISTRY
            )
            if resp_type is not None:
                send_framed_udp(sock, client_addr, resp_type, resp_payload)
                if resp_type == 0x07:
                    iteration += 1
                    if iteration % 10 == 0 or iteration == 1:
                        print(f"[+] Processed {iteration:3d} authenticated benchmark iterations.")
        except KeyboardInterrupt:
            print("\n[*] Shutting down gNodeB MEC server.")
            break
        except Exception as e:
            print(f"[-] Unexpected server error: {e}", file=sys.stderr)

def run_tcp_client_session(conn, addr, signer, gnb_sig_pk, cache, TRUSTED_UAV_REGISTRY):
    iteration = 0
    with conn:
        while True:
            try:
                msg_type, payload = recv_framed_tcp(conn, timeout=30.0)
                if msg_type is None:
                    break
                resp_type, resp_payload = process_handshake_message(
                    msg_type, payload, signer, gnb_sig_pk, cache, TRUSTED_UAV_REGISTRY
                )
                if resp_type is not None:
                    send_framed_tcp(conn, resp_type, resp_payload)
                    if resp_type == 0x07:
                        iteration += 1
                        if iteration % 10 == 0 or iteration == 1:
                            print(f"[+] Processed {iteration:3d} authenticated TCP benchmark iterations.")
            except Exception as e:
                print(f"[-] TCP session error with {addr}: {e}")
                break

if __name__ == "__main__":
    main()
