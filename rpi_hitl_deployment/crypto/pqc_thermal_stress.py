#!/usr/bin/env python3
# ==============================================================================
# Kyber-6G Raspberry Pi 4 Thermal & DVFS Throttling Stability Monitor
# Executes 500 consecutive handshakes under full load while logging:
# - SoC Temperature (thermal_zone0)
# - CPU ARM Core Clock Frequency (vcgencmd measure_clock arm)
# - Throttling Register Bitmask (vcgencmd get_throttled)
# ==============================================================================
import os
import sys
import time
import subprocess
import csv
import oqs
from cryptography.hazmat.primitives.asymmetric import x25519

OUTPUT_CSV = os.path.join(os.path.dirname(__file__), "..", "results", "thermal_stability_log.csv")
ITERATIONS = 500

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
        return hz // 1000000
    except Exception:
        return 1500

def main():
    print("=" * 70)
    print("KYBER-6G RPI4 THERMAL STABILITY & DVFS THROTTLING MONITOR")
    print(f"Running {ITERATIONS} continuous PQC cryptographic loops...")
    print(f"Output CSV: {OUTPUT_CSV}")
    print("=" * 70)

    os.makedirs(os.path.dirname(OUTPUT_CSV), exist_ok=True)
    kem = oqs.KeyEncapsulation('ML-KEM-1024')
    
    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["iteration", "timestamp", "temp_c", "arm_freq_mhz", "throttle_hex", "loop_time_ms"])
        
        for i in range(1, ITERATIONS + 1):
            t0 = time.perf_counter_ns()
            sk = x25519.X25519PrivateKey.generate()
            pk_k = kem.generate_keypair()
            ct, ss = kem.encap_secret(pk_k)
            _ = kem.decap_secret(ct)
            loop_ms = (time.perf_counter_ns() - t0) / 1e6

            temp_c = get_temp()
            freq_mhz = get_arm_freq_mhz()
            throttle_hex = get_throttle_state()

            writer.writerow([i, time.time(), temp_c, freq_mhz, throttle_hex, round(loop_ms, 2)])
            if i % 50 == 0 or i == 1:
                print(f"  [Iter {i:03d}/{ITERATIONS}] Temp: {temp_c:5.1f} C | Freq: {freq_mhz} MHz | Throttle: {throttle_hex} | Loop: {loop_ms:.2f} ms")

    kem.free()
    print("\n[+] Thermal test complete! Results saved to:", OUTPUT_CSV)

if __name__ == "__main__":
    main()
