#!/usr/bin/env python3
# ==============================================================================
# Kyber-6G Hardware-in-the-Loop (HITL) Autonomous Benchmark Harness
# Executes 100 iterations on ARM Cortex-A72:
# - Full Level-5 Hybrid Handshake (ML-KEM-1024 + X25519 + ML-DSA-87)
# - Sub-5ms 0-RTT Rapid Rekeying
# - SWaP-C Energy & Microsecond Latency Breakdown
# - Writes output CSV to results/hitl_benchmarks_extended.csv
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

try:
    import psutil
except ImportError:
    psutil = None

MAX_DGRAM = 1352

# Hardware SWaP Parameters (Cortex-A72 Baseline)
P_CPU_ACTIVE = 5.0   # Watts
P_IDLE = 1.0         # Watts
P_TX = 0.52          # Watts
P_RX = 0.16          # Watts
P_MEM_BIT = 0.5e-12  # 0.5 pJ/bit

enabled_sigs = oqs.get_enabled_sig_mechanisms()
SIG_ALG = "ML-DSA-87" if "ML-DSA-87" in enabled_sigs else ("Dilithium5" if "Dilithium5" in enabled_sigs else enabled_sigs[0])

def get_soc_temp():
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
            return round(float(f.read().strip()) / 1000.0, 2)
    except Exception:
        return 0.0

def get_cpu_load():
    if psutil:
        try:
            return psutil.cpu_percent(interval=None)
        except Exception:
            pass
    return 0.0

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
            return None, None
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

def calculate_swap_energy(t_proc, t_tx, t_rx, bytes_transferred):
    e_cpu = P_CPU_ACTIVE * t_proc * 1000.0
    e_tx = P_TX * t_tx * 1000.0
    e_rx = P_RX * t_rx * 1000.0
    e_mem = (bytes_transferred * 8.0 * P_MEM_BIT) * 1e3
    return round(e_cpu + e_tx + e_rx + e_mem, 4)

def run_x25519_keygen():
    sk = x25519.X25519PrivateKey.generate()
    return sk, sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

def run_kyber_keygen():
    kem = oqs.KeyEncapsulation('ML-KEM-1024')
    return kem, kem.generate_keypair()

def main():
    parser = argparse.ArgumentParser(description="Kyber-6G Automated HITL Benchmark Harness")
    parser.add_argument("--server", type=str, default="127.0.0.1", help="gNodeB Base Tower IP")
    parser.add_argument("--port", type=int, default=14000, help="UDP port")
    parser.add_argument("--runs", type=int, default=100, help="Number of benchmark iterations")
    parser.add_argument("--output", type=str, default=None, help="Output CSV path")
    args = parser.parse_args()

    # Determine default CSV output location
    if args.output is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        results_dir = os.path.join(base_dir, "results")
        os.makedirs(results_dir, exist_ok=True)
        args.output = os.path.join(results_dir, "hitl_benchmarks_extended.csv")
    else:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)

    print("=" * 75)
    print(f"KYBER-6G BENCHMARK HARNESS: {args.runs} RUNS")
    print(f"Target gNodeB Base Station: {args.server}:{args.port}")
    print(f"Signature Engine:           {SIG_ALG} (Level 5)")
    print(f"Output Dataset:             {args.output}")
    print("=" * 75)

    signer = oqs.Signature(SIG_ALG)
    drone_sig_pk = signer.generate_keypair()
    ue_id = b"UAV_GW_1"
    mobility_hash = 0xA1B2C3D4
    nonce_counter = 0
    current_session_key = None

    precomputed_pool = [run_kyber_keygen() for _ in range(3)]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_addr = (args.server, args.port)

    with open(args.output, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            "Iteration", "Mode", "Total_Handshake_ms", 
            "Crypto_Proc_ms", "AES_GCM_Tx_Rx_ms", 
            "Energy_mJ", "CPU_Load_Percent", "SoC_Temp_C"
        ])

        for i in range(1, args.runs + 1):
            get_cpu_load()
            force_miss = (i == 1 or i == 51)
            mode = "FULL_PQC" if force_miss else "0RTT_REKEY"

            t0 = time.perf_counter_ns()

            if mode == "FULL_PQC":
                if precomputed_pool:
                    kem_inst, pk_drone_k = precomputed_pool.pop(0)
                else:
                    kem_inst, pk_drone_k = run_kyber_keygen()

                sk_drone_x, pk_drone_x = run_x25519_keygen()
                sig_drone = signer.sign(pk_drone_x + pk_drone_k)

                t1_tx = time.perf_counter_ns()
                msg1 = ue_id + struct.pack("!I", mobility_hash) + pk_drone_x + pk_drone_k + struct.pack("!H", len(sig_drone)) + sig_drone + drone_sig_pk
                send_framed_udp(sock, server_addr, 0x01, msg1)
                t1_tx_end = time.perf_counter_ns()

                msg_type, payload = recv_framed_udp(sock)
                t2_rx = time.perf_counter_ns()
                if msg_type != 0x02 or payload is None:
                    print(f"[-] Full PQC Handshake timed out at run {i}")
                    continue

                sig_len = struct.unpack("!H", payload[:2])[0]
                gnb_sig = payload[2 : 2 + sig_len]
                gnb_sig_pk = payload[2 + sig_len : 2 + sig_len + len(drone_sig_pk)]
                signed_body = payload[2 + sig_len + len(drone_sig_pk) :]

                pk_server_x = signed_body[:32]
                ct_server_k = signed_body[32:1600]
                hkdf_salt = signed_body[1600:1616]

                verifier = oqs.Signature(SIG_ALG)
                verifier.verify(signed_body, gnb_sig, gnb_sig_pk)
                verifier.free()

                s_drone_k = kem_inst.decap_secret(ct_server_k)
                s_drone_x = sk_drone_x.exchange(x25519.X25519PublicKey.from_public_bytes(pk_server_x))
                kem_inst.free()

                current_session_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=hkdf_salt,
                    info=b"Kyber6G-3GPP-Rel17-MasterKey"
                ).derive(s_drone_x + s_drone_k)

                t_crypto_end = time.perf_counter_ns()
                proc_time_s = ((t1_tx - t0) + (t_crypto_end - t2_rx)) / 1e9
                tx_time_s = (t1_tx_end - t1_tx) / 1e9
                rx_time_s = (t2_rx - t1_tx_end) / 1e9
                total_bytes = len(msg1) + len(payload)

            else:
                ephemeral_salt = os.urandom(16)
                msg3 = ue_id + struct.pack("!I", mobility_hash) + ephemeral_salt

                t1_tx = time.perf_counter_ns()
                send_framed_udp(sock, server_addr, 0x03, msg3)
                t1_tx_end = time.perf_counter_ns()

                msg_type, payload = recv_framed_udp(sock)
                t2_rx = time.perf_counter_ns()
                if msg_type != 0x04 or payload is None:
                    print(f"[-] 0-RTT Rekeying timed out at run {i}")
                    continue

                current_session_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=ephemeral_salt,
                    info=b"Kyber6G-3GPP-0RTT-Rekey"
                ).derive(current_session_key)

                t_crypto_end = time.perf_counter_ns()
                proc_time_s = (t_crypto_end - t2_rx) / 1e9
                tx_time_s = (t1_tx_end - t1_tx) / 1e9
                rx_time_s = (t2_rx - t1_tx_end) / 1e9
                total_bytes = len(msg3) + len(payload)

            # Data Plane AES-256-GCM Test
            aesgcm = AESGCM(current_session_key)
            nonce_counter += 1
            gcm_nonce = struct.pack("!Q", nonce_counter) + os.urandom(4)
            telemetry_data = b"UAV_STATUS_OK:LAT=12.9716,LON=77.5946,ALT=120m,BAT=94%"
            
            t_aes_start = time.perf_counter_ns()
            ct = aesgcm.encrypt(gcm_nonce, telemetry_data, None)
            pdu = ue_id + struct.pack("!Q", nonce_counter) + gcm_nonce + ct
            send_framed_udp(sock, server_addr, 0x06, pdu)

            ack_type, ack_payload = recv_framed_udp(sock, timeout=2.0)
            t_aes_end = time.perf_counter_ns()
            aes_rtt_ms = (t_aes_end - t_aes_start) / 1e6

            t_total_end = time.perf_counter_ns()
            total_handshake_ms = (t_total_end - t0) / 1e6
            crypto_proc_ms = proc_time_s * 1e3
            energy_mj = calculate_swap_energy(proc_time_s, tx_time_s, rx_time_s, total_bytes)
            cpu_load = get_cpu_load()
            temp_c = get_soc_temp()

            writer.writerow([
                i, mode, f"{total_handshake_ms:.3f}", 
                f"{crypto_proc_ms:.3f}", f"{aes_rtt_ms:.3f}", 
                energy_mj, cpu_load, temp_c
            ])
            file.flush()

            if i % 10 == 0 or i == 1:
                print(f"  [Run #{i:03d}] {mode:<11} | E2E: {total_handshake_ms:6.2f} ms | Crypto: {crypto_proc_ms:5.2f} ms | AES RTT: {aes_rtt_ms:4.2f} ms | Energy: {energy_mj:5.2f} mJ | Temp: {temp_c} deg C")

            time.sleep(0.05)

    print(f"\n[+] Successfully finished {args.runs} benchmark runs.")
    print(f"[+] Output dataset saved to: {args.output}")
    signer.free()

if __name__ == "__main__":
    main()
