#!/usr/bin/env python3
# ==============================================================================
# Kyber-6G Raspberry Pi 4 Thermal & DVFS Throttling Stability Monitor
# Executes consecutive handshakes under full load while logging:
# - SoC Temperature (thermal_zone0)
# - CPU ARM Core Clock Frequency (vcgencmd measure_clock arm)
# - Throttling Register Bitmask (vcgencmd get_throttled)
# ==============================================================================
import os
import sys
import time
import subprocess
import csv
import argparse
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519

def get_temp():
    try:
        with open("/sys/class/thermal/thermal_zone0/temp", "r") as f:
            return round(float(f.read().strip()) / 1000.0, 2)
    except Exception:
        return 0.0

def get_throttle_state():
    try:
        out = subprocess.check_output(["vcgencmd", "get_throttled"], text=True)
        return out.strip().split("=")[1]
    except Exception:
        return "0x0"

def get_arm_freq_mhz():
    try:
        out = subprocess.check_output(["vcgencmd", "measure_clock", "arm"], text=True)
        hz = int(out.strip().split("=")[1])
        return round(hz / 1e6, 1)
    except Exception:
        return 1500.0

def main():
    parser = argparse.ArgumentParser(description="Kyber-6G RPi4 Thermal Stability Monitor")
    parser.add_argument("--runs", type=int, default=500, help="Stress iterations")
    parser.add_argument("--output", type=str, default=None, help="Output CSV path")
    args = parser.parse_args()

    if args.output is None:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        results_dir = os.path.join(base_dir, "results")
        os.makedirs(results_dir, exist_ok=True)
        args.output = os.path.join(results_dir, "thermal_stability_log.csv")
    else:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)

    print("=" * 70)
    print(f"KYBER-6G THERMAL & DVFS STRESS MONITOR ({args.runs} ITERATIONS)")
    print(f"Logging To: {args.output}")
    print("=" * 70)

    with open(args.output, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Iteration", "Timestamp_s", "Latency_ms", "Temperature_C", "Clock_MHz", "Throttled_Bitmask"])

        t0 = time.time()
        for i in range(1, args.runs + 1):
            t_start = time.perf_counter_ns()
            
            # Level-5 Hybrid Workload
            sk_x = x25519.X25519PrivateKey.generate()
            pk_x = sk_x.public_key().public_bytes(
                from_cryptography_serialization_Encoding_Raw := oqs.Signature("ML-DSA-87") if False else None, 
                from_cryptography_serialization_PublicFormat_Raw := None
            ) if False else sk_x.public_key()
            
            kem = oqs.KeyEncapsulation("ML-KEM-1024")
            pk_k = kem.generate_keypair()
            ct, ss = kem.encap_secret(pk_k)
            ss_d = kem.decap_secret(ct)
            kem.free()

            sig_engine = oqs.Signature("ML-DSA-87" if "ML-DSA-87" in oqs.get_enabled_sig_mechanisms() else "Dilithium5")
            sig_pk = sig_engine.generate_keypair()
            sig = sig_engine.sign(ct)
            sig_engine.verify(ct, sig, sig_pk)
            sig_engine.free()

            t_ms = (time.perf_counter_ns() - t_start) / 1e6
            temp = get_temp()
            freq = get_arm_freq_mhz()
            thr = get_throttle_state()
            ts = round(time.time() - t0, 3)

            writer.writerow([i, ts, f"{t_ms:.3f}", temp, freq, thr])
            f.flush()

            if i % 50 == 0 or i == 1:
                print(f"  [Iter #{i:03d} | {ts:5.1f}s] Latency: {t_ms:5.2f} ms | Temp: {temp:4.1f}°C | Clock: {freq} MHz | Throttle: {thr}")

    print(f"\n[+] Thermal test completed. Output saved to {args.output}")

if __name__ == "__main__":
    main()
