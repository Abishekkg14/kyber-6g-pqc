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

GNB_SERVER_IP = "172.26.53.139"  # gNodeB IP
GNB_PORT = 14000
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
            return msg_type, full_payload

def run_x25519_keygen():
    sk = x25519.X25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

def run_kyber_keygen():
    kem = oqs.KeyEncapsulation('ML-KEM-1024')
    return kem, kem.generate_keypair()

def main():
    print(f"\n[*] Initializing Drone UAV Tier-1 Interface (UDP)...")
    print(f"[*] Signature Engine: {SIG_ALG} (NIST Level 5)")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (GNB_SERVER_IP, GNB_PORT)
    
    # 1. Asymmetric KeyGen + ML-DSA Signing
    print("[*] Generating ephemeral keypairs and signing RRC Request...")
    signer = oqs.Signature(SIG_ALG)
    drone_sig_pk = signer.generate_keypair()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        fut_x = executor.submit(run_x25519_keygen)
        fut_k = executor.submit(run_kyber_keygen)
        sk_ecdh, pk_ecdh = fut_x.result()
        kem_drone, pk_kyber = fut_k.result()
        
    sig = signer.sign(pk_ecdh + pk_kyber)
    ue_id = b"UAV_GW_1"
    mobility_hash = 0xA1B2C3D4
    
    req_payload = (
        ue_id + struct.pack("!I", mobility_hash) + 
        pk_ecdh + pk_kyber + struct.pack("!H", len(sig)) + 
        sig + drone_sig_pk
    )
    
    print(f"[*] Sending signed RRC Setup Request to {GNB_SERVER_IP}:{GNB_PORT}...")
    send_framed_udp(sock, server_addr, 0x01, req_payload)
    
    # 2. Receive and Verify Response
    _, resp = recv_framed_udp(sock)
    gnb_sig_len = struct.unpack("!H", resp[:2])[0]
    gnb_sig = resp[2:2 + gnb_sig_len]
    gnb_pk = resp[2 + gnb_sig_len : 2 + gnb_sig_len + len(drone_sig_pk)]
    signed_data = resp[2 + gnb_sig_len + len(drone_sig_pk):]
    
    print("[*] Verifying gNodeB ML-DSA-87 digital signature...")
    verifier = oqs.Signature(SIG_ALG)
    is_valid = verifier.verify(signed_data, gnb_sig, gnb_pk)
    verifier.free()
    if not is_valid:
        print("[-] gNodeB verification FAILED! Terminating.")
        return
    print("[+] gNodeB Identity authenticated successfully.")
    
    pk_server = signed_data[:32]
    ct_kyber = signed_data[32:1600]
    hkdf_salt = signed_data[1600:1616]
    
    # 3. Decapsulation and KDF
    s_ecdh = sk_ecdh.exchange(x25519.X25519PublicKey.from_public_bytes(pk_server))
    s_kyber = kem_drone.decap_secret(ct_kyber)
    kem_drone.free()
    
    k_final = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=b"Kyber6G-3GPP-Rel17-MasterKey"
    ).derive(s_ecdh + s_kyber)
    
    print(f"[SUCCESS] 256-bit X-Wing Session Key Derived: {k_final.hex()[:24]}...\n")
    print("[*] AES-256-GCM Secure Shell Ready. Type a command (or 'exit'):\n")
    
    aesgcm = AESGCM(k_final)
    nonce_counter = 0
    
    while True:
        try:
            cmd = input("[UAV Flight Command] -> ")
            if cmd.lower() == 'exit':
                print("[*] Disconnecting.")
                break
            if not cmd.strip():
                continue
                
            nonce_counter += 1
            gcm_nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(gcm_nonce, cmd.encode('utf-8'), None)
            
            packet = ue_id + struct.pack("!Q", nonce_counter) + gcm_nonce + ciphertext
            send_framed_udp(sock, server_addr, 0x06, packet)
            
            # Await reply
            _, reply = recv_framed_udp(sock)
            reply_nonce = reply[:12]
            reply_ct = reply[12:]
            plaintext = aesgcm.decrypt(reply_nonce, reply_ct, None)
            print(f"    [<] Base Station Reply: {plaintext.decode('utf-8')}\n")
        except KeyboardInterrupt:
            print("\n[*] Exiting.")
            break

if __name__ == "__main__":
    main()
