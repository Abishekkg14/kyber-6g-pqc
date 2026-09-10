import socket
import os
import time
import struct
import csv
import psutil
import concurrent.futures
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

GNB_SERVER_IP = "172.26.53.139"  # Adjust if hotspot IP changes
GNB_PORT = 14000
MAX_DGRAM = 1352
CSV_FILENAME = "hitl_benchmarks_extended.csv"
ITERATIONS = 100

# Hardware SWaP Parameters (Jetson Nano / Cortex-A72 Baseline)
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

def calculate_swap_energy(t_proc, t_tx, t_rx, bytes_transferred):
    # E_total = P_cpu * T_proc + P_tx * T_tx + P_rx * T_rx + P_mem * T_mem
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
    print(f"\n[*] Starting 6G HITL Benchmark Harness: {ITERATIONS} Iterations")
    print(f"[*] Signature Engine: {SIG_ALG} (Level 5)")
    print(f"[*] Output CSV: {CSV_FILENAME}\n")
    
    signer = oqs.Signature(SIG_ALG)
    drone_sig_pk = signer.generate_keypair()
    ue_id = b"UAV_GW_1"
    mobility_hash = 0xA1B2C3D4
    nonce_counter = 0
    current_session_key = None
    
    # Pre-computation Pool (N=3)
    precomputed_pool = [run_kyber_keygen() for _ in range(3)]
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5.0)
    server_addr = (GNB_SERVER_IP, GNB_PORT)
    
    with open(CSV_FILENAME, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([
            "Iteration", "Mode", "Total_Handshake_ms", 
            "Crypto_Proc_ms", "AES_GCM_Tx_Rx_ms", 
            "Energy_mJ", "CPU_Load_Percent", "SoC_Temp_C"
        ])
        
        for i in range(1, ITERATIONS + 1):
            psutil.cpu_percent(interval=None)  # Reset CPU calculation window
            
            # Protocol State Logic:
            # Iteration 1: Cold Start (Cache Miss)
            # Iteration 51: Forced Stale Handover (Simulate Route Change / Expiry)
            # Others: 0-RTT RapidRekey (Cache Hit)
            force_miss = (i == 1 or i == 51)
            mode = "FULL_PQC" if force_miss else "0RTT_REKEY"
            
            t_tx = 0.0
            t_rx = 0.0
            bytes_transferred = 0
            
            if force_miss:
                t0 = time.perf_counter()
                
                # Asymmetric Parallel KeyGen + ML-DSA Sign
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                    fut_x = executor.submit(run_x25519_keygen)
                    fut_k = executor.submit(run_kyber_keygen)
                    sk_ecdh, pk_ecdh = fut_x.result()
                    kem_drone, pk_kyber = fut_k.result()
                
                sig = signer.sign(pk_ecdh + pk_kyber)
                t1 = time.perf_counter()
                crypto_proc_ms = (t1 - t0) * 1000.0
                
                # Transmit RRC Setup Request
                tx_start = time.perf_counter()
                req_payload = (
                    ue_id + struct.pack("!I", mobility_hash) + 
                    pk_ecdh + pk_kyber + struct.pack("!H", len(sig)) + 
                    sig + drone_sig_pk
                )
                send_framed_udp(sock, server_addr, 0x01, req_payload)
                t_tx += (time.perf_counter() - tx_start)
                bytes_transferred += len(req_payload)
                
                # Receive RRC Setup Response
                rx_start = time.perf_counter()
                _, resp = recv_framed_udp(sock)
                t_rx += (time.perf_counter() - rx_start)
                bytes_transferred += len(resp)
                
                t2 = time.perf_counter()
                gnb_sig_len = struct.unpack("!H", resp[:2])[0]
                gnb_sig = resp[2:2 + gnb_sig_len]
                gnb_pk = resp[2 + gnb_sig_len : 2 + gnb_sig_len + len(drone_sig_pk)]
                signed_data = resp[2 + gnb_sig_len + len(drone_sig_pk):]
                
                # Verify gNB Signature
                verifier = oqs.Signature(SIG_ALG)
                assert verifier.verify(signed_data, gnb_sig, gnb_pk), "gNodeB auth failed!"
                verifier.free()
                
                pk_server = signed_data[:32]
                ct_kyber = signed_data[32:1600]
                hkdf_salt = signed_data[1600:1616]
                
                s_ecdh = sk_ecdh.exchange(x25519.X25519PublicKey.from_public_bytes(pk_server))
                s_kyber = kem_drone.decap_secret(ct_kyber)
                kem_drone.free()
                
                current_session_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=hkdf_salt,
                    info=b"Kyber6G-3GPP-Rel17-MasterKey"
                ).derive(s_ecdh + s_kyber)
                t3 = time.perf_counter()
                crypto_proc_ms += ((t3 - t2) * 1000.0)
                handshake_ms = (t3 - t0) * 1000.0
                
            else:
                # 0-RTT RapidRekey Handover
                t0 = time.perf_counter()
                ephemeral_salt = os.urandom(16)
                
                tx_start = time.perf_counter()
                rekey_payload = ue_id + struct.pack("!I", mobility_hash) + ephemeral_salt
                send_framed_udp(sock, server_addr, 0x03, rekey_payload)
                t_tx += (time.perf_counter() - tx_start)
                bytes_transferred += len(rekey_payload)
                
                rx_start = time.perf_counter()
                _, ack = recv_framed_udp(sock)
                t_rx += (time.perf_counter() - rx_start)
                bytes_transferred += len(ack)
                
                # Derive next-generation key
                t_rekey_start = time.perf_counter()
                current_session_key = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=ephemeral_salt,
                    info=b"Kyber6G-3GPP-Rel17-0RTT-Rekey"
                ).derive(current_session_key)
                t_rekey_end = time.perf_counter()
                
                crypto_proc_ms = (t_rekey_end - t_rekey_start) * 1000.0
                handshake_ms = (t_rekey_end - t0) * 1000.0
            
            # --- AES-256-GCM Telemetry Exchange ---
            nonce_counter += 1
            t_aes_start = time.perf_counter()
            aesgcm = AESGCM(current_session_key)
            gcm_nonce = os.urandom(12)
            telemetry_data = b"TELEMETRY_SAMPLE_URLLC_PAYLOAD_512B_" + os.urandom(480)
            ct = aesgcm.encrypt(gcm_nonce, telemetry_data, None)
            
            tx_start = time.perf_counter()
            packet_to_send = ue_id + struct.pack("!Q", nonce_counter) + gcm_nonce + ct
            send_framed_udp(sock, server_addr, 0x06, packet_to_send)
            t_tx += (time.perf_counter() - tx_start)
            bytes_transferred += len(packet_to_send)
            
            rx_start = time.perf_counter()
            _, reply = recv_framed_udp(sock)
            t_rx += (time.perf_counter() - rx_start)
            bytes_transferred += len(reply)
            
            reply_nonce = reply[:12]
            reply_ct = reply[12:]
            aesgcm.decrypt(reply_nonce, reply_ct, None)
            t_aes_end = time.perf_counter()
            aes_ms = (t_aes_end - t_aes_start) * 1000.0
            
            # Hardware Telemetry Capture
            time.sleep(0.01)
            cpu_percent = psutil.cpu_percent(interval=None)
            soc_temp = get_soc_temp()
            energy_mj = calculate_swap_energy(crypto_proc_ms / 1000.0, t_tx, t_rx, bytes_transferred)
            
            writer.writerow([
                i, mode, round(handshake_ms, 3), 
                round(crypto_proc_ms, 3), round(aes_ms, 3), 
                energy_mj, cpu_percent, soc_temp
            ])
            
            if i % 10 == 0 or i == 1:
                print(f"[+] Iteration {i:03d}/100 | Mode: {mode:10s} | Handshake: {handshake_ms:6.2f}ms | Energy: {energy_mj:6.2f}mJ | Temp: {soc_temp}°C")

if __name__ == "__main__":
    main()
