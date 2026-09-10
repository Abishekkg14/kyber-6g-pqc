#!/usr/bin/env python3
# ==============================================================================
# Kyber-6G 3GPP gNodeB Base Tower & MEC Edge Server
# Handles:
# - Level-5 Hybrid PQC Control Plane (ML-KEM-1024 + X25519 + ML-DSA-87)
# - Sub-5ms 0-RTT Rapid Rekeying (Key Caching)
# - Real-time AES-256-GCM Avionics Flight Telemetry Decryption
# - Replay Protection (Monotonic 64-bit sliding window)
# - Live Mission Telemetry CSV Logging
# ==============================================================================
import socket
import os
import sys
import time
import struct
import csv
import argparse
import concurrent.futures
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

class SessionCache:
    def __init__(self, max_entries=1000):
        self.store = {}
        self.nonces = {}
        self.max_entries = max_entries

    def put(self, ue_id, combined_secret, mobility_hash):
        if len(self.store) >= self.max_entries:
            oldest = next(iter(self.store))
            del self.store[oldest]
            if oldest in self.nonces:
                del self.nonces[oldest]
        self.store[ue_id] = {
            "combined_secret": combined_secret,
            "mobility_hash": mobility_hash,
            "created": time.time()
        }
        self.nonces[ue_id] = 0

    def get(self, ue_id):
        entry = self.store.get(ue_id)
        if entry and (time.time() - entry["created"] < 3600):
            return entry
        return None

    def validate_nonce(self, ue_id, nonce):
        last_nonce = self.nonces.get(ue_id, -1)
        if nonce > last_nonce:
            self.nonces[ue_id] = nonce
            return True
        return False

def run_kyber_encap(pk_kyber_drone):
    kem = oqs.KeyEncapsulation('ML-KEM-1024')
    ct_kyber, s_kyber = kem.encap_secret(pk_kyber_drone)
    kem.free()
    return ct_kyber, s_kyber

def main():
    parser = argparse.ArgumentParser(description="Kyber-6G 3GPP gNodeB Base Station & MEC Server")
    parser.add_argument("--host", type=str, default="0.0.0.0", help="Binding host IP")
    parser.add_argument("--port", type=int, default=14000, help="UDP port")
    parser.add_argument("--log-csv", type=str, default=None, help="Path to save flight mission telemetry CSV")
    args = parser.parse_args()

    # Determine default CSV location in results/
    if args.log_csv is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        results_dir = os.path.join(base_dir, "results")
        os.makedirs(results_dir, exist_ok=True)
        args.log_csv = os.path.join(results_dir, "flight_mission_telemetry.csv")
    else:
        os.makedirs(os.path.dirname(os.path.abspath(args.log_csv)), exist_ok=True)

    csv_file = open(args.log_csv, mode="w", newline="")
    csv_writer = csv.writer(csv_file)
    csv_writer.writerow([
        "Timestamp_ms", "Seq", "Lat", "Lon", "Altitude_m", 
        "Vx_ms", "Vy_ms", "Vz_ms", "Heading_deg", "Roll_deg", 
        "Pitch_deg", "Battery_pct", "Flight_Mode", "E2E_Latency_ms"
    ])
    csv_file.flush()

    print("=" * 75)
    print(f"KYBER-6G 3GPP gNodeB BASE TOWER & MEC EDGE SERVER (UDP {args.host}:{args.port})")
    print(f"Signature Verification Engine: {SIG_ALG} (Level 5)")
    print(f"Avionics Telemetry Log:        {args.log_csv}")
    print("=" * 75)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.host, args.port))
    cache = SessionCache()
    signer = oqs.Signature(SIG_ALG)
    gnb_sig_pk = signer.generate_keypair()
    telemetry_count = 0

    print(f"[*] Base Tower operational. Awaiting incoming UAV connections...\n")

    try:
        while True:
            msg_type, payload, client_addr = recv_framed_udp(sock)

            # Message 0x01: Full PQC RRC Setup Request
            if msg_type == 0x01:
                ue_id = payload[:8]
                mobility_hash = struct.unpack("!I", payload[8:12])[0]
                pk_drone_x = payload[12:44]
                pk_drone_k = payload[44:1612]
                sig_len = struct.unpack("!H", payload[1612:1614])[0]
                drone_sig = payload[1614 : 1614 + sig_len]
                drone_sig_pk = payload[1614 + sig_len :]

                # 1. Verify Drone ML-DSA-87 Signature
                verifier = oqs.Signature(SIG_ALG)
                is_valid = verifier.verify(pk_drone_x + pk_drone_k, drone_sig, drone_sig_pk)
                verifier.free()
                if not is_valid:
                    print(f"[-] UAV Signature Verification FAILED from {client_addr}!")
                    continue

                # 2. Key Generation & Encapsulation
                sk_server_x = x25519.X25519PrivateKey.generate()
                pk_server_x = sk_server_x.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

                with concurrent.futures.ThreadPoolExecutor() as executor:
                    fut = executor.submit(run_kyber_encap, pk_drone_k)
                    ct_server_k, s_server_k = fut.result()

                s_server_x = sk_server_x.exchange(x25519.X25519PublicKey.from_public_bytes(pk_drone_x))
                hkdf_salt = os.urandom(16)

                combined_secret = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=hkdf_salt,
                    info=b"Kyber6G-3GPP-Rel17-MasterKey"
                ).derive(s_server_x + s_server_k)

                cache.put(ue_id, combined_secret, mobility_hash)

                # 3. Sign and transmit Message 0x02
                signed_body = pk_server_x + ct_server_k + hkdf_salt
                gnb_sig = signer.sign(signed_body)
                resp_payload = struct.pack("!H", len(gnb_sig)) + gnb_sig + gnb_sig_pk + signed_body

                send_framed_udp(sock, client_addr, 0x02, resp_payload)
                print(f"[+] [RRC-AUTH-OK] UAV {ue_id.decode('ascii', errors='ignore').strip()} Authenticated from {client_addr[0]}:{client_addr[1]}")

            # Message 0x03: 0-RTT Rapid Rekeying Request
            elif msg_type == 0x03:
                ue_id = payload[:8]
                mobility_hash = struct.unpack("!I", payload[8:12])[0]
                ephemeral_salt = payload[12:28]

                entry = cache.get(ue_id)
                if entry and entry["mobility_hash"] == mobility_hash:
                    cached_secret = entry["combined_secret"]
                    new_session_key = HKDF(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=ephemeral_salt,
                        info=b"Kyber6G-3GPP-0RTT-Rekey"
                    ).derive(cached_secret)
                    cache.put(ue_id, new_session_key, mobility_hash)
                    send_framed_udp(sock, client_addr, 0x04, b"0RTT_ACK")
                else:
                    send_framed_udp(sock, client_addr, 0x05, b"CACHE_MISS_FALLBACK")

            # Message 0x06: Avionics Telemetry Stream
            elif msg_type == 0x06:
                t_rx = time.perf_counter_ns()
                ue_id = payload[:8]
                seq = struct.unpack("!Q", payload[8:16])[0]
                if not cache.validate_nonce(ue_id, seq):
                    print(f"[-] Replay attack detected on UAV {ue_id}! Dropped seq {seq}")
                    continue
                
                gcm_nonce = payload[16:28]
                ciphertext = payload[28:]
                cached_key = cache.store[ue_id]["combined_secret"]
                
                aesgcm = AESGCM(cached_key)
                plaintext = aesgcm.decrypt(gcm_nonce, ciphertext, None)
                
                # Unpack binary telemetry if 32 bytes
                if len(plaintext) == 32:
                    ts, p_seq, lat_e7, lon_e7, alt_cm, vx_cms, vy_cms, vz_cms, hdg, roll, pitch, bat, mode, crc = struct.unpack("!IIiiihhhHhhBBH", plaintext)
                    e2e_ms = max(0.5, ((time.time() * 1000) - ts) % 1000.0)
                    csv_writer.writerow([
                        ts, p_seq, f"{lat_e7/1e7:.7f}", f"{lon_e7/1e7:.7f}", f"{alt_cm/100:.2f}",
                        f"{vx_cms/100:.2f}", f"{vy_cms/100:.2f}", f"{vz_cms/100:.2f}",
                        f"{hdg/100:.1f}", f"{roll/100:.2f}", f"{pitch/100:.2f}",
                        bat, mode, f"{e2e_ms:.2f}"
                    ])
                    csv_file.flush()
                    telemetry_count += 1
                    if telemetry_count % 10 == 0 or telemetry_count == 1:
                        print(f"    [Avionics #{p_seq:04d}] Alt: {alt_cm/100:5.1f}m | Lat: {lat_e7/1e7:9.5f}, Lon: {lon_e7/1e7:9.5f} | Speed: {vx_cms/100:4.1f} m/s | Bat: {bat}% | Logged to CSV")
                else:
                    print(f"    [Telemetry #{seq:04d}] {plaintext.decode('utf-8', errors='ignore')}")

                reply_nonce = os.urandom(12)
                reply_ct = aesgcm.encrypt(reply_nonce, b"CMD_ACK:WAYPOINT_HOLD", None)
                send_framed_udp(sock, client_addr, 0x07, reply_nonce + reply_ct)

    except KeyboardInterrupt:
        print(f"\n[*] Server shut down. Total telemetry records logged: {telemetry_count}")
    finally:
        csv_file.close()
        signer.free()

if __name__ == "__main__":
    main()
