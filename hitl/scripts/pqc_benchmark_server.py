import socket
import os
import time
import struct
import concurrent.futures
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HOST = "0.0.0.0"
PORT = 14000
MAX_DGRAM = 1352  # 1400B MTU - 40B IPv6 - 8B UDP header

# Resolve ML-DSA mechanism name
enabled_sigs = oqs.get_enabled_sig_mechanisms()
SIG_ALG = "ML-DSA-87" if "ML-DSA-87" in enabled_sigs else ("Dilithium5" if "Dilithium5" in enabled_sigs else enabled_sigs[0])

def send_framed_udp(sock, addr, msg_type, payload):
    """Chunks large payloads to prevent Wi-Fi router MTU drops."""
    chunk_size = MAX_DGRAM - 6
    total_frags = (len(payload) + chunk_size - 1) // chunk_size
    if total_frags == 0:
        total_frags = 1
        payload = b""
    for i in range(total_frags):
        chunk = payload[i * chunk_size : (i + 1) * chunk_size]
        header = struct.pack("!HBB", msg_type, i, total_frags)
        sock.sendto(header + chunk, addr)

def recv_framed_udp(sock):
    """Reassembles fragmented UDP frames."""
    buffers = {}
    expected_frags = {}
    while True:
        packet, addr = sock.recvfrom(4096)
        if len(packet) < 4:
            continue
        msg_type, frag_idx, total_frags = struct.unpack("!HBB", packet[:4])
        chunk = packet[4:]
        
        key = (addr, msg_type)
        if key not in buffers:
            buffers[key] = [None] * total_frags
            expected_frags[key] = total_frags
            
        buffers[key][frag_idx] = chunk
        
        if all(f is not None for f in buffers[key]):
            full_payload = b"".join(buffers[key])
            del buffers[key]
            del expected_frags[key]
            return msg_type, full_payload, addr

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
        if entry["mobility_hash"] != mobility_hash:
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
    print(f"\n[*] 6G gNodeB MEC Edge Server running (UDP) on {HOST}:{PORT}")
    print(f"[*] Signature Engine: {SIG_ALG} (Level 5)")
    
    signer = oqs.Signature(SIG_ALG)
    gnb_sig_pk = signer.generate_keypair()
    cache = MecKeyCache(ttl=300.0)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    
    iteration = 0
    while True:
        try:
            msg_type, payload, client_addr = recv_framed_udp(sock)
            
            # Message 1: Full Handshake (Cache Miss)
            if msg_type == 0x01:
                ue_id = payload[:8]
                mobility_hash = struct.unpack("!I", payload[8:12])[0]
                pk_ecdh_drone = payload[12:44]
                pk_kyber_drone = payload[44:1612]
                sig_len = struct.unpack("!H", payload[1612:1614])[0]
                drone_sig = payload[1614:1614 + sig_len]
                drone_pk_sig = payload[1614 + sig_len:]
                
                # ML-DSA Mutual Verification
                verifier = oqs.Signature(SIG_ALG)
                is_valid = verifier.verify(pk_ecdh_drone + pk_kyber_drone, drone_sig, drone_pk_sig)
                verifier.free()
                if not is_valid:
                    print("[-] Handshake Rejected: ML-DSA signature failure")
                    continue
                
                # Parallel Encapsulation
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                    fut_x = executor.submit(run_x25519_server, pk_ecdh_drone)
                    fut_k = executor.submit(run_kyber_encapsulation, pk_kyber_drone)
                    pk_server, s_ecdh = fut_x.result()
                    ct_kyber, s_kyber = fut_k.result()
                
                # Key Fusion
                hkdf_salt = os.urandom(16)
                k_final = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=hkdf_salt,
                    info=b"Kyber6G-3GPP-Rel17-MasterKey"
                ).derive(s_ecdh + s_kyber)
                
                cache.put(ue_id, k_final, mobility_hash)
                
                # Sign Response
                resp_to_sign = pk_server + ct_kyber + hkdf_salt
                gnb_sig = signer.sign(resp_to_sign)
                resp_payload = struct.pack("!H", len(gnb_sig)) + gnb_sig + gnb_sig_pk + resp_to_sign
                send_framed_udp(sock, client_addr, 0x02, resp_payload)
            
            # Message 3: 0-RTT RapidRekey (Cache Hit)
            elif msg_type == 0x03:
                ue_id = payload[:8]
                mobility_hash = struct.unpack("!I", payload[8:12])[0]
                status, cached_secret = cache.lookup(ue_id, mobility_hash)
                
                if status == "HIT":
                    # Derive next generation session key instantly
                    ephemeral_salt = payload[12:28]
                    new_session_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=ephemeral_salt,
                        info=b"Kyber6G-3GPP-Rel17-0RTT-Rekey"
                    ).derive(cached_secret)
                    cache.put(ue_id, new_session_key, mobility_hash)
                    send_framed_udp(sock, client_addr, 0x04, b"0RTT_ACK")
                else:
                    send_framed_udp(sock, client_addr, 0x05, b"CACHE_MISS_FALLBACK")
                    
            # Message 6: AES-256-GCM Telemetry Packet
            elif msg_type == 0x06:
                ue_id = payload[:8]
                nonce_counter = struct.unpack("!Q", payload[8:16])[0]
                if not cache.validate_nonce(ue_id, nonce_counter):
                    continue  # Silent drop on replay attack
                
                gcm_nonce = payload[16:28]
                ciphertext = payload[28:]
                cached_key = cache.store[ue_id]["combined_secret"]
                
                aesgcm = AESGCM(cached_key)
                plaintext = aesgcm.decrypt(gcm_nonce, ciphertext, None)
                
                # Send encrypted ACK
                reply_nonce = os.urandom(12)
                reply_ct = aesgcm.encrypt(reply_nonce, b"GNB_TELEMETRY_ACK", None)
                send_framed_udp(sock, client_addr, 0x07, reply_nonce + reply_ct)
                
                iteration += 1
                if iteration % 10 == 0:
                    print(f"[+] Processed {iteration} benchmark iterations.")
                    
        except Exception:
            pass

if __name__ == "__main__":
    main()
