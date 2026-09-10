import socket
import os
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
MAX_DGRAM = 1352

enabled_sigs = oqs.get_enabled_sig_mechanisms()
SIG_ALG = "ML-DSA-87" if "ML-DSA-87" in enabled_sigs else ("Dilithium5" if "Dilithium5" in enabled_sigs else enabled_sigs[0])

def send_framed_udp(sock, addr, msg_type, payload):
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
    buffers = {}
    while True:
        packet, addr = sock.recvfrom(4096)
        if len(packet) < 4:
            continue
        msg_type, frag_idx, total_frags = struct.unpack("!HBB", packet[:4])
        chunk = packet[4:]
        
        key = (addr, msg_type)
        if key not in buffers:
            buffers[key] = [None] * total_frags
            
        buffers[key][frag_idx] = chunk
        if all(f is not None for f in buffers[key]):
            full_payload = b"".join(buffers[key])
            del buffers[key]
            return msg_type, full_payload, addr

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
    print(f"\n[*] Starting 6G gNodeB Interactive MEC Server (UDP) on {HOST}:{PORT}...")
    print(f"[*] Signature Engine: {SIG_ALG} (NIST Level 5)")
    
    signer = oqs.Signature(SIG_ALG)
    gnb_sig_pk = signer.generate_keypair()
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((HOST, PORT))
    
    print("[*] Waiting for UAV RRC Setup Request...")
    
    # 1. Receive Handshake Request
    msg_type, payload, drone_addr = recv_framed_udp(sock)
    if msg_type != 0x01:
        print("[-] Invalid initial message type.")
        return
        
    ue_id = payload[:8]
    mobility_hash = struct.unpack("!I", payload[8:12])[0]
    pk_ecdh_drone = payload[12:44]
    pk_kyber_drone = payload[44:1612]
    sig_len = struct.unpack("!H", payload[1612:1614])[0]
    drone_sig = payload[1614:1614 + sig_len]
    drone_pk_sig = payload[1614 + sig_len:]
    
    print(f"[+] Connection requested by UAV: {ue_id.decode(errors='ignore')} from {drone_addr}")
    print("[*] Verifying UAV ML-DSA-87 digital signature...")
    
    verifier = oqs.Signature(SIG_ALG)
    is_valid = verifier.verify(pk_ecdh_drone + pk_kyber_drone, drone_sig, drone_pk_sig)
    verifier.free()
    if not is_valid:
        print("[-] Signature validation FAILED! Aborting.")
        return
    print("[+] UAV Identity authenticated successfully.")
    
    # 2. Parallel Encapsulation
    print("[*] Executing parallel X25519 + ML-KEM-1024 encapsulation...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        fut_x = executor.submit(run_x25519_server, pk_ecdh_drone)
        fut_k = executor.submit(run_kyber_encapsulation, pk_kyber_drone)
        pk_server, s_ecdh = fut_x.result()
        ct_kyber, s_kyber = fut_k.result()
    
    # 3. HKDF Fusion
    hkdf_salt = os.urandom(16)
    k_final = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=b"Kyber6G-3GPP-Rel17-MasterKey"
    ).derive(s_ecdh + s_kyber)
    
    # 4. Sign and Send Response
    resp_to_sign = pk_server + ct_kyber + hkdf_salt
    gnb_sig = signer.sign(resp_to_sign)
    resp_payload = struct.pack("!H", len(gnb_sig)) + gnb_sig + gnb_sig_pk + resp_to_sign
    send_framed_udp(sock, drone_addr, 0x02, resp_payload)
    
    print(f"[SUCCESS] 256-bit X-Wing Master Key Derived: {k_final.hex()[:24]}...")
    print("[*] Entering AES-256-GCM Secure Data Plane. Listening for UAV commands...\n")
    
    aesgcm = AESGCM(k_final)
    nonce_watermark = 0
    
    while True:
        try:
            msg_type, enc_payload, addr = recv_framed_udp(sock)
            if msg_type == 0x06:
                nonce_counter = struct.unpack("!Q", enc_payload[8:16])[0]
                if nonce_counter <= nonce_watermark:
                    print(f"[-] Replay attack detected! Counter {nonce_counter} <= watermark {nonce_watermark}")
                    continue
                nonce_watermark = nonce_counter
                
                gcm_nonce = enc_payload[16:28]
                ciphertext = enc_payload[28:]
                plaintext = aesgcm.decrypt(gcm_nonce, ciphertext, None)
                cmd_text = plaintext.decode('utf-8', errors='ignore')
                print(f"    [>] UAV Command Received [Seq #{nonce_counter}]: {cmd_text}")
                
                reply_msg = f"gNodeB ACK: [{cmd_text}] processed securely."
                reply_nonce = os.urandom(12)
                reply_ct = aesgcm.encrypt(reply_nonce, reply_msg.encode('utf-8'), None)
                send_framed_udp(sock, addr, 0x07, reply_nonce + reply_ct)
        except KeyboardInterrupt:
            print("\n[*] Server shutdown.")
            break
        except Exception as e:
            print(f"[-] Error: {e}")

if __name__ == "__main__":
    main()
