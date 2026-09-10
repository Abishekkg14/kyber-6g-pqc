#!/usr/bin/env python3
# ==============================================================================
# Kyber-6G Realistic UAV Companion Computer Flight Client
# - Connects over 3GPP RRC with Level-5 Hybrid PQC
# - Streams 32-byte binary avionics telemetry vector at 20-100 Hz
# - Simulates real 3D circular flight trajectory with realistic GPS & battery
# - Writes output mission log to results/flight_mission_telemetry.csv
# ==============================================================================
import socket
import os
import sys
import time
import struct
import math
import csv
import argparse
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

def build_dynamic_avionics_packet(seq, t_elapsed):
    timestamp_ms = int(time.time() * 1000) & 0xFFFFFFFF
    
    # Orbit parameters: center (12.9716, 77.5946), radius ~150m, 1 revolution per 40s
    theta = (t_elapsed / 40.0) * 2 * math.pi
    lat = 12.971600 + (150.0 / 111320.0) * math.sin(theta)
    lon = 77.594600 + (150.0 / (111320.0 * math.cos(math.radians(12.9716)))) * math.cos(theta)
    alt_m = 100.0 + 15.0 * math.sin(theta * 2.0)
    
    speed_ms = 15.0 + 2.0 * math.cos(theta)
    vx = speed_ms * math.cos(theta)
    vy = speed_ms * math.sin(theta)
    vz = 1.2 * math.cos(theta * 2.0)
    
    heading_deg = (math.degrees(theta) + 90.0) % 360.0
    roll_deg = 5.0 * math.sin(theta)
    pitch_deg = -3.0 * math.cos(theta)
    bat_pct = max(10, int(98 - (t_elapsed / 300.0) * 15))
    flight_mode = 3       # AUTO_MISSION
    crc16 = 0xABCD

    lat_degE7 = int(lat * 1e7)
    lon_degE7 = int(lon * 1e7)
    alt_cm = int(alt_m * 100)
    vx_cms = int(vx * 100)
    vy_cms = int(vy * 100)
    vz_cms = int(vz * 100)
    heading_cdeg = int(heading_deg * 100)
    roll_cdeg = int(roll_deg * 100)
    pitch_cdeg = int(pitch_deg * 100)

    packet = struct.pack("!IIiiihhhHhhBBH", 
                         timestamp_ms, seq, lat_degE7, lon_degE7, 
                         alt_cm, vx_cms, vy_cms, vz_cms, 
                         heading_cdeg, roll_cdeg, pitch_cdeg, 
                         bat_pct, flight_mode, crc16)
    return packet, lat, lon, alt_m, speed_ms, bat_pct

def main():
    parser = argparse.ArgumentParser(description="Kyber-6G UAV Companion Flight Client")
    parser.add_argument("--server", type=str, default="127.0.0.1", help="gNodeB Base Tower IP")
    parser.add_argument("--port", type=int, default=14000, help="UDP port")
    parser.add_argument("--rate", type=float, default=20.0, help="Avionics telemetry rate in Hz (e.g. 20, 50, 100)")
    parser.add_argument("--duration", type=int, default=10, help="Flight streaming duration in seconds")
    parser.add_argument("--uav-id", type=str, default="UAV-ALPH", help="8-character 3GPP UAV ID")
    parser.add_argument("--output", type=str, default=None, help="Output CSV path for flight telemetry")
    args = parser.parse_args()

    # Determine default CSV output location
    if args.output is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        results_dir = os.path.join(base_dir, "results")
        os.makedirs(results_dir, exist_ok=True)
        args.output = os.path.join(results_dir, "flight_mission_telemetry.csv")
    else:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)

    dest = (args.server, args.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    uav_id = args.uav_id.encode('ascii')[:8].ljust(8, b' ')

    print("=" * 70)
    print("KYBER-6G UAV FLIGHT CLIENT (AERIAL USER EQUIPMENT)")
    print(f"Target gNodeB Base Tower: {args.server}:{args.port}")
    print(f"UAV Identifier:           {args.uav_id}")
    print(f"Avionics Telemetry Rate:  {args.rate} Hz | Duration: {args.duration}s")
    print(f"Output Telemetry Log:     {args.output}")
    print("=" * 70)

    # -------------------------------------------------------------
    # PHASE 1: Control Plane 3GPP RRC Setup & Security Mode Handshake
    # -------------------------------------------------------------
    print("\n[*] [PHASE 1] Initiating Level-5 Post-Quantum RRC Handshake...")
    t_start = time.perf_counter_ns()

    sk_drone_x = x25519.X25519PrivateKey.generate()
    pk_drone_x = sk_drone_x.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    kem = oqs.KeyEncapsulation('ML-KEM-1024')
    pk_drone_k = kem.generate_keypair()

    signer = oqs.Signature(SIG_ALG)
    pk_drone_sig = signer.generate_keypair()

    # Sign Ephemeral Public Keys
    drone_sig = signer.sign(pk_drone_x + pk_drone_k)
    mobility_hash = 0x6A7B8C9D

    # Build Message 0x01
    msg1 = uav_id + struct.pack("!I", mobility_hash) + pk_drone_x + pk_drone_k + struct.pack("!H", len(drone_sig)) + drone_sig + pk_drone_sig
    send_framed_udp(sock, dest, 0x01, msg1)
    print(f"[>] Transmitted RRCSetupRequest (0x01) -> Total Payload: {len(msg1)} Bytes")

    # Await Response 0x02
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

    # Verify gNodeB ML-DSA Signature
    verifier = oqs.Signature(SIG_ALG)
    if not verifier.verify(signed_body, gnb_sig, gnb_sig_pk):
        print("[-] gNodeB Signature Verification FAILED! Aborting.")
        sys.exit(1)
    verifier.free()

    # Decapsulate ML-KEM-1024 and X25519
    s_drone_k = kem.decap_secret(ct_server_k)
    s_drone_x = sk_drone_x.exchange(x25519.X25519PublicKey.from_public_bytes(pk_server_x))

    # HKDF Fusion -> Master Session Key
    k_session = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=hkdf_salt,
        info=b"Kyber6G-3GPP-Rel17-MasterKey"
    ).derive(s_drone_x + s_drone_k)

    t_handshake_ms = (time.perf_counter_ns() - t_start) / 1e6
    print(f"[+] [SUCCESS] Handshake Authenticated in {t_handshake_ms:.2f} ms")
    print(f"[+] 256-bit AES-GCM Cipher Key Established: {k_session.hex()[:24]}...")

    # -------------------------------------------------------------
    # PHASE 2: Live Avionics Telemetry Data Plane
    # -------------------------------------------------------------
    print(f"\n[*] [PHASE 2] Streaming Encrypted Avionics Flight Telemetry ({args.rate} Hz)...")
    aesgcm = AESGCM(k_session)
    interval = 1.0 / args.rate
    t_flight_start = time.time()
    t_end = t_flight_start + args.duration
    seq = 1
    rtt_samples = []

    with open(args.output, mode="w", newline="") as log_file:
        log_writer = csv.writer(log_file)
        log_writer.writerow([
            "Timestamp_s", "Seq", "Lat", "Lon", "Altitude_m", 
            "Speed_ms", "Battery_pct", "RTT_ms", "Ack_Status"
        ])

        try:
            while time.time() < t_end:
                t_elapsed = time.time() - t_flight_start
                t_tx = time.perf_counter_ns()
                flight_data, lat, lon, alt_m, speed_ms, bat_pct = build_dynamic_avionics_packet(seq, t_elapsed)
                gcm_nonce = struct.pack("!Q", seq) + os.urandom(4)
                ct = aesgcm.encrypt(gcm_nonce, flight_data, None)
                
                pdu = uav_id + struct.pack("!Q", seq) + gcm_nonce + ct
                send_framed_udp(sock, dest, 0x06, pdu)

                ack_type, ack_payload, _ = recv_framed_udp(sock, timeout=0.2)
                if ack_type == 0x07 and ack_payload is not None:
                    rtt_ms = (time.perf_counter_ns() - t_tx) / 1e6
                    rtt_samples.append(rtt_ms)
                    ack_nonce = ack_payload[:12]
                    ack_ct = ack_payload[12:]
                    ack_text = aesgcm.decrypt(ack_nonce, ack_ct, None).decode('utf-8', errors='ignore')

                    log_writer.writerow([
                        f"{t_elapsed:.3f}", seq, f"{lat:.7f}", f"{lon:.7f}", 
                        f"{alt_m:.2f}", f"{speed_ms:.2f}", bat_pct, 
                        f"{rtt_ms:.3f}", ack_text
                    ])
                    log_file.flush()

                    if seq % int(args.rate) == 0 or seq == 1:
                        print(f"  [Flight #{seq:04d} | t={t_elapsed:4.1f}s] Alt: {alt_m:5.1f}m | Lat: {lat:9.5f}, Lon: {lon:9.5f} | RTT: {rtt_ms:5.2f} ms | Bat: {bat_pct}%")
                else:
                    log_writer.writerow([
                        f"{t_elapsed:.3f}", seq, f"{lat:.7f}", f"{lon:.7f}", 
                        f"{alt_m:.2f}", f"{speed_ms:.2f}", bat_pct, 
                        "TIMEOUT", "NO_ACK"
                    ])
                    log_file.flush()
                
                seq += 1
                time.sleep(interval)

        except KeyboardInterrupt:
            print("\n[*] Stream stopped by user.")

    if rtt_samples:
        avg_rtt = sum(rtt_samples) / len(rtt_samples)
        p99_rtt = sorted(rtt_samples)[int(len(rtt_samples) * 0.99)]
        print("\n" + "=" * 70)
        print("FLIGHT TELEMETRY METRICS SUMMARY:")
        print(f"  Packets Transmitted: {seq-1}")
        print(f"  Packet Delivery PDR: {len(rtt_samples) / (seq-1) * 100:.2f}%")
        print(f"  Average E2E Latency: {avg_rtt:.2f} ms")
        print(f"  99th-Percentile RTT: {p99_rtt:.2f} ms (URLLC < 10ms Compliance: {'YES' if p99_rtt < 10.0 else 'NO'})")
        print(f"  Telemetry CSV Saved: {args.output}")
        print("=" * 70)

    kem.free()
    signer.free()

if __name__ == "__main__":
    main()
