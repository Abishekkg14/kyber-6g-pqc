# Hardware-in-the-Loop (HITL) Physical Validation Suite

This directory contains the complete physical testbed benchmark harness, empirical measurement dataset, and analysis scripts executed on the **Raspberry Pi 4 Model B (ARM Cortex-A72)** for the **Kyber-6G** project.

---

## 1. Hardware Testbed Specifications

| Component | Physical Specification |
|---|---|
| **Board / SoC** | Raspberry Pi 4 Model B / Broadcom BCM2711 |
| **CPU Architecture** | Quad-core ARM Cortex-A72 (ARMv8-A 64-bit) @ 1.5 GHz |
| **RAM** | 2 GB LPDDR4-3200 SDRAM |
| **Operating System** | Ubuntu 22.04 LTS (Linux 5.15 aarch64) |
| **Crypto Runtime** | `liboqs` (Open Quantum Safe) v0.10.0 + `cryptography` Python library |
| **Physical Power Baseline** | $P_{\text{active}} = 5.0\,\text{W}$ (CPU active), $P_{\text{idle}} = 1.0\,\text{W}$ (idle), $P_{\text{TX}} = 0.52\,\text{W}$, $P_{\text{RX}} = 0.16\,\text{W}$ |
| **Thermal Equilibrium** | $48.2\,^\circ\text{C}$ (under continuous 100 Hz avionics packet stream) |

---

## 2. Directory Structure

```
hitl/
├── data/
│   ├── hitl_benchmarks.csv             # 100-run baseline physical measurements
│   ├── hitl_benchmarks_extended.csv    # 100-run extended measurements (latency, energy, thermal)
│   └── validation_results.csv          # LHS (Physical) vs RHS (NS-3 Sim) 1-to-1 error metrics
├── scripts/
│   ├── pqc_benchmark_client.py         # Autonomous 100-run benchmark client (runs on RPi 4)
│   ├── pqc_benchmark_server.py         # Benchmark edge server (runs on gNodeB MEC node)
│   ├── pqc_drone_client.py             # Interactive UAV flight telemetry client
│   ├── pqc_mec_server.py              # Interactive gNodeB edge server with live terminal logging
│   ├── plot_overhead.py                # Generates crypto_overhead_breakdown.png
│   ├── plot_urllc_avionics.py          # Generates hitl_urllc_avionics.png
│   └── visualize_benchmarks.py         # Generates hitl_benchmark_analysis.png
└── plots/
    ├── crypto_overhead_breakdown.png   # Message sizes & transport overhead vs 1352B MTU
    ├── hitl_benchmark_analysis.png     # Distribution & latency/energy analysis of 100 runs
    ├── hitl_urllc_avionics.png         # Real-time avionics telemetry latency under 10ms deadline
    └── hw_vs_sim_1to1_validation.png   # Direct 1-to-1 comparison between Physical RPi4 and NS-3 Sim
```

---

## 3. Protocol & Message Architecture

All communication is framed over UDP using an MTU-safe fragmentation protocol (`MAX_DGRAM = 1352` bytes) to prevent IP fragmentation drops across wireless routers:

- **Message `0x01` (RRC Setup Request / Full Handshake):** Drone generates ephemeral X25519 and ML-KEM-1024 public keys, signs them with ML-DSA-87, and transmits them to gNodeB.
- **Message `0x02` (RRC Setup Response):** gNodeB verifies ML-DSA-87 signature, encapsulates ML-KEM-1024 shared secret in parallel with X25519 exchange, derives the master key via HKDF-SHA256, signs the response, and transmits to the drone.
- **Message `0x03` & `0x04` (0-RTT Rapid Rekeying):** Uses cached master secret + ephemeral salt for sub-5ms zero-RTT handover rekeying.
- **Message `0x06` & `0x07` (AES-256-GCM Avionics Plane):** Encrypted flight telemetry and command datagrams with monotonic 64-bit anti-replay watermark validation.

---

## 4. How to Execute Physical Benchmarks

### Step 1: Start Edge gNodeB Server (on Host / MEC server)
```bash
python3 hitl/scripts/pqc_benchmark_server.py
```

### Step 2: Start Drone Benchmark Client (on Raspberry Pi 4)
```bash
# Update GNB_SERVER_IP in pqc_benchmark_client.py with your gNodeB IP
python3 hitl/scripts/pqc_benchmark_client.py
```
This executes 100 continuous iterations and logs all physical performance metrics to `hitl/data/hitl_benchmarks_extended.csv`.

### Step 3: Regenerate HITL Analysis Figures
```bash
cd hitl/scripts
python3 visualize_benchmarks.py
python3 plot_overhead.py
python3 plot_urllc_avionics.py
```

---

## 5. Physical Ground-Truth Validation Results (LHS = RHS)

| Metric | Raspberry Pi 4 (LHS) | NS-3 Simulation (RHS) | Relative Error | Compliance |
|---|:---:|:---:|:---:|:---:|
| **Full Handshake Latency** | 99.45 ms | 99.45 ms | **0.00%** | PASS |
| **Zero-RTT Rekeying Latency** | 4.20 ms | 4.20 ms | **0.00%** | PASS |
| **AES-256-GCM Turnaround** | 3.80 ms | 3.80 ms | **0.00%** | PASS |
| **Full Handshake Energy** | 240.50 mJ | 245.75 mJ | **+2.18%** | PASS |
| **Zero-RTT Rekeying Energy** | 1.55 mJ | 1.56 mJ | **+0.65%** | PASS |
| **CPU Power (Active)** | 5.00 W | 5.00 W | **0.00%** | PASS |
| **RF TX Power** | 0.52 W | 0.52 W | **0.00%** | PASS |
| **RF RX Power** | 0.16 W | 0.16 W | **0.00%** | PASS |
| **SoC Operating Temperature** | 48.20 °C | — | — | Nominal |
