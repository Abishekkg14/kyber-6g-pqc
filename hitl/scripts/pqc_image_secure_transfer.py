#!/usr/bin/env python3
# ==============================================================================
# Kyber-6G High-Resolution Drone Reconnaissance Image Encryptor & Uploader
# - Dual-Cipher: ChaCha20-Poly1305 (ARM NEON) / AES-256-GCM
# - Ingests user's real aerial reconnaissance photographs
# - Measures Shannon Entropy, Encryption Latency, and Throughput (MB/s)
# - Pins to Cortex-A72 Core 1 for SIMD acceleration
# ==============================================================================
import socket
import os
import sys
import time
import struct
import csv
import argparse
import numpy as np
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pqc_media_multicore_engine import QFrameGuardEngine

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

def recv_framed_udp(sock, timeout=5.0):
    sock.settimeout(timeout)
    buffers = {}
    while True:
        try:
            packet, addr = sock.recvfrom(4096)
        except socket.timeout:
            return None, None, None
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

def perform_pqc_handshake(sock, dest, uav_id):
    t_start = time.perf_counter_ns()
    sk_drone_x = x25519.X25519PrivateKey.generate()
    pk_drone_x = sk_drone_x.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    kem = oqs.KeyEncapsulation('ML-KEM-1024')
    pk_drone_k = kem.generate_keypair()

    signer = oqs.Signature(SIG_ALG)
    pk_drone_sig = signer.generate_keypair()

    drone_sig = signer.sign(pk_drone_x + pk_drone_k)
    mobility_hash = 0x6A7B8C9D

    msg1 = uav_id + struct.pack("!I", mobility_hash) + pk_drone_x + pk_drone_k + struct.pack("!H", len(drone_sig)) + drone_sig + pk_drone_sig
    send_framed_udp(sock, dest, 0x01, msg1)

    resp_type, resp_payload, _ = recv_framed_udp(sock, timeout=5.0)
    if resp_type != 0x02 or resp_payload is None:
        print("[-] Handshake timeout or rejected by gNodeB!")
        sys.exit(1)

    sig_len = struct.unpack("!H", resp_payload[:2])[0]
    gnb_sig = resp_payload[2 : 2 + sig_len]
    gnb_sig_pk = resp_payload[2 + sig_len : 2 + sig_len + len(pk_drone_sig)]
    signed_body = resp_payload[2 + sig_len + len(pk_drone_sig) :]
    
    pk_server_x = signed_body[:32]
    ct_server_k = signed_body[32:1600]
    hkdf_salt = signed_body[1600:1616]

    verifier = oqs.Signature(SIG_ALG)
    if not verifier.verify(signed_body, gnb_sig, gnb_sig_pk):
        print("[-] gNodeB Signature Verification FAILED! Aborting.")
        sys.exit(1)
    verifier.free()

    s_drone_k = kem.decap_secret(ct_server_k)
    s_drone_x = sk_drone_x.exchange(x25519.X25519PublicKey.from_public_bytes(pk_server_x))

    k_session = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=b"Kyber6G-3GPP-Rel17-MasterKey"
    ).derive(s_drone_x + s_drone_k)

    t_handshake_ms = (time.perf_counter_ns() - t_start) / 1e6
    kem.free()
    signer.free()
    return k_session, t_handshake_ms

def calculate_entropy(byte_data: bytes) -> float:
    arr = np.frombuffer(byte_data, dtype=np.uint8)
    counts = np.bincount(arr, minlength=256)
    probs = counts / len(arr)
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))

def main():
    parser = argparse.ArgumentParser(description="Kyber-6G Drone Reconnaissance Image Encryptor")
    parser.add_argument("--server", type=str, default="127.0.0.1", help="gNodeB Base Tower IP")
    parser.add_argument("--port", type=int, default=14000, help="UDP port")
    parser.add_argument("--image", type=str, default=None, help="Path to image to encrypt and upload")
    parser.add_argument("--cipher", type=str, default="CHACHA20", choices=["CHACHA20", "AES_GCM"], help="Cipher engine")
    parser.add_argument("--chunk-size", type=int, default=1000, help="MTU-safe chunk payload size")
    parser.add_argument("--pin-core", type=int, default=1, help="ARM Cortex-A72 CPU core affinity")
    args = parser.parse_args()

    # Find default sample image if not specified
    if args.image is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        default_img = os.path.join(base_dir, "assets", "images", "drone_recon_1.jpg")
        if not os.path.exists(default_img):
            default_img = os.path.join(base_dir, "assets", "images", "drone_recon_2.jpg")
        args.image = default_img

    if not os.path.exists(args.image):
        print(f"[-] Error: Image '{args.image}' not found.")
        sys.exit(1)

    uav_id = b"UAV-ALPH"
    dest = (args.server, args.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    print("=" * 75)
    print("KYBER-6G RECONNAISSANCE IMAGE ENCRYPTION PIPELINE")
    print(f"Target Base Tower:     {args.server}:{args.port}")
    print(f"Input Aerial Image:    {args.image} ({os.path.getsize(args.image)} Bytes)")
    print(f"Cryptographic Engine:  {args.cipher} (ARM Cortex-A72 Pin: Core {args.pin_core})")
    print("=" * 75)

    # 1. PQC Handshake
    print("[*] Initiating Level-5 Post-Quantum Key Agreement...")
    k_session, t_hs_ms = perform_pqc_handshake(sock, dest, uav_id)
    print(f"[+] Handshake Authenticated in {t_hs_ms:.2f} ms")
    print(f"[+] 256-bit Session Key Established: {k_session.hex()[:24]}...")

    # 2. Initialize QFrameGuard Engine
    engine = QFrameGuardEngine(master_key=k_session, cipher_mode=args.cipher, chunk_size=args.chunk_size)
    if engine.pin_cpu_core(args.pin_core):
        print(f"[+] Process successfully bound to CPU Core {args.pin_core}")

    with open(args.image, "rb") as f:
        img_bytes = f.read()

    total_size = len(img_bytes)
    total_chunks = (total_size + args.chunk_size - 1) // args.chunk_size
    filename = os.path.basename(args.image)

    h_plain = calculate_entropy(img_bytes)
    print(f"\n[*] Image Analysis:")
    print(f"    Plaintext Size:    {total_size} Bytes")
    print(f"    Plaintext Entropy: {h_plain:.4f} bits/byte")
    print(f"    Chunk Breakdown:   {total_chunks} slices @ {args.chunk_size} B/slice")

    # 3. Transmit Metadata Header (0x10)
    meta = struct.pack("!HII", len(filename.encode('utf-8')), total_size, total_chunks) + filename.encode('utf-8')
    nonce_hdr, ct_hdr, _ = engine.encrypt_slice(meta, frame_id=0, chunk_id=0)
    send_framed_udp(sock, dest, 0x10, uav_id + nonce_hdr + ct_hdr)

    # 4. Encrypt and Stream Chunks (0x11)
    print(f"\n[*] Encrypting and Transmitting Chunks ({args.cipher})...")
    t_stream_start = time.time()
    enc_latencies = []
    encrypted_bytes_pool = []

    for i in range(total_chunks):
        chunk_slice = img_bytes[i * args.chunk_size : (i + 1) * args.chunk_size]
        nonce_c, ct_c, lat_us = engine.encrypt_slice(chunk_slice, frame_id=1, chunk_id=i)
        enc_latencies.append(lat_us)
        encrypted_bytes_pool.append(ct_c)

        payload = uav_id + struct.pack("!I", i) + nonce_c + ct_c
        send_framed_udp(sock, dest, 0x11, payload)

        if (i + 1) % 20 == 0 or (i + 1) == total_chunks:
            pct = ((i + 1) / total_chunks) * 100
            print(f"    [Upload]: Chunk {i+1:03d}/{total_chunks} ({pct:5.1f}%) | Latency: {lat_us:5.1f} µs")
        time.sleep(0.005)

    total_tx_time = time.time() - t_stream_start
    all_ct_bytes = b"".join(encrypted_bytes_pool)
    h_cipher = calculate_entropy(all_ct_bytes)
    avg_enc_us = sum(enc_latencies) / len(enc_latencies)
    throughput_mb = (total_size / (1024 * 1024)) / total_tx_time

    # 5. Await Base Tower Verification ACK (0x12)
    ack_type, ack_payload, _ = recv_framed_udp(sock, timeout=5.0)
    if ack_type == 0x12 and ack_payload is not None:
        ack_nonce = ack_payload[:12]
        ack_ct = ack_payload[12:]
        pt, _, is_ok = engine.decrypt_slice(ack_nonce, ack_ct)
        ack_str = pt.decode('utf-8', errors='ignore') if is_ok else "AUTH_FAILED"
        print(f"\n[+] [IMAGE UPLOAD SUCCESSFUL!]")
        print(f"    Base Station ACK:   {ack_str}")
        print(f"    Ciphertext Entropy: {h_cipher:.4f} bits/byte (Max Theoretical: 8.0000)")
        print(f"    Mean Chunk Encrypt: {avg_enc_us:.2f} µs per chunk")
        print(f"    Network Throughput: {throughput_mb:.2f} MB/s ({total_size/1024/total_tx_time:.1f} KB/s)")
        print(f"    Total Air Time:     {total_tx_time:.2f} s")
    else:
        print("[-] Warning: No confirmation ACK received from Base Tower.")

    # Save metrics to results CSV
    res_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "results")
    os.makedirs(res_dir, exist_ok=True)
    res_csv = os.path.join(res_dir, "image_encryption_benchmarks.csv")
    with open(res_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Filename", "Cipher", "Size_Bytes", "Chunks", "Plaintext_Entropy", "Ciphertext_Entropy", "Avg_Encrypt_us", "Throughput_MBs", "Total_Time_s"])
        w.writerow([filename, args.cipher, total_size, total_chunks, f"{h_plain:.4f}", f"{h_cipher:.4f}", f"{avg_enc_us:.2f}", f"{throughput_mb:.2f}", f"{total_tx_time:.3f}"])
    print(f"[+] Benchmark results saved to: {res_csv}")

if __name__ == "__main__":
    main()
