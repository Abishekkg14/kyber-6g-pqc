# Kyber-6G: Hardware-in-the-Loop Calibrated Post-Quantum Cryptography for 6G Drone Swarms

[![NS-3 v3.42](https://img.shields.io/badge/NS--3-v3.42-blue.svg)](https://www.nsnam.org/)
[![5G-LENA NR](https://img.shields.io/badge/5G--LENA-v3.1-orange.svg)](https://5g-lena.cttc.es/)
[![NIST FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203%20(ML--KEM)-green.svg)](https://csrc.nist.gov/pubs/fips/203/final)
[![NIST FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204%20(ML--DSA)-brightgreen.svg)](https://csrc.nist.gov/pubs/fips/204/final)
[![HITL Calibrated](https://img.shields.io/badge/HITL-RPi4%20Cortex--A72-purple.svg)](#hardware-in-the-loop-hitl-calibration)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An end-to-end research framework and simulation pipeline implementing NIST Level-5 Post-Quantum Cryptography (**ML-KEM-1024 / Kyber-1024**, **X25519**, and **ML-DSA-87 / Dilithium-5**) for ultra-reliable low-latency communications (URLLC) in 6G Unmanned Aerial Vehicle (UAV) swarms.

This repository integrates **physical Hardware-in-the-Loop (HITL) empirical benchmarks** executed on a quad-core **ARM Cortex-A72 (Raspberry Pi 4 Model B)** with an **NS-3 (v3.42) / 5G-LENA NR (v3.1)** discrete-event simulation engine, enforcing **LHS (Physical Hardware) = RHS (Simulation)** alignment within a strict **≤2.18% relative error** margin.

---

## Key Highlights

- **Hardware-in-the-Loop Physical Ground Truth:** 100-iteration empirical benchmark dataset measured directly on a Broadcom BCM2711 ARM Cortex-A72 SoC @ 1.5 GHz with 2 GB LPDDR4 memory.
- **Hybrid PQC Architecture:** FIPS 203 ML-KEM-1024 fused with classical X25519 ECDH via HKDF-SHA256, authenticated with FIPS 204 ML-DSA-87 and secured using AES-256-GCM.
- **C++ NS-3 Model Calibration:** Custom `contrib/pqc-security` module calibrated with RPi4 Cortex-A72 hardware execution profiles, multi-fragment RLC/MAC segmentation (1352-byte MTU), and empirical RF/SoC energy models.
- **Parametric Swarm Evaluation:** Large-scale simulation sweeps evaluating 1 to 80+ UAV swarms under Gauss-Markov mobility (up to 120 m/s) over 3.5 GHz n78 URLLC numerology (SCS = 30 kHz).
- **Interactive 3D Web Visualizer:** Production React/Vite web application featuring a Three.js 3D drone swarm canvas, telemetry dashboards, and KaTeX mathematical proofs.
- **Publication-Ready Figures:** 7 high-resolution (300 DPI) scientific plots validated against physical hardware benchmarks.

---

## Hardware-in-the-Loop (HITL) Physical Calibration

### Physical Benchmark Setup
- **SoC / CPU:** Broadcom BCM2711, quad-core ARM Cortex-A72 (ARMv8-A 64-bit) @ 1.5 GHz
- **Memory:** 2 GB LPDDR4-3200 SDRAM
- **OS / Runtime:** Ubuntu 22.04 LTS (Kernel 5.15 aarch64), Python 3.10, liboqs-c
- **Power & Thermal Baseline:** CPU TDP 5.0 W (active), 1.0 W (idle), RF TX 0.52 W, RF RX 0.16 W, SoC Temp 48.2 °C

### 1-to-1 Ground Truth Verification (LHS = RHS)

| Metric | Physical Hardware (LHS) | Calibrated NS-3 Sim (RHS) | Relative Error | Status |
|---|:---:|:---:|:---:|:---:|
| **Full Handshake Latency** | 99.45 ms | 99.45 ms | **0.00%** | PASS |
| **Zero-RTT Rekeying Latency** | 4.20 ms | 4.20 ms | **0.00%** | PASS |
| **AES-256-GCM Turnaround** | 3.80 ms | 3.80 ms | **0.00%** | PASS |
| **Full Handshake Energy** | 240.50 mJ | 245.75 mJ | **+2.18%** | PASS |
| **Zero-RTT Rekeying Energy** | 1.55 mJ | 1.56 mJ | **+0.65%** | PASS |
| **CPU Active Power** | 5.00 W | 5.00 W | **0.00%** | PASS |
| **RF Transmit Power** | 0.52 W | 0.52 W | **0.00%** | PASS |
| **RF Receive Power** | 0.16 W | 0.16 W | **0.00%** | PASS |

---

## Repository Structure

```
kyber-6g-pqc/
├── hitl/                                   # Hardware-in-the-Loop empirical benchmark suite
│   ├── data/
│   │   ├── hitl_benchmarks.csv             # Baseline 100-run RPi4 physical measurements
│   │   └── hitl_benchmarks_extended.csv    # Extended telemetry (latency, energy, thermal)
│   ├── scripts/
│   │   ├── pqc_benchmark_server.py         # UDP benchmark server executed on RPi4
│   │   └── pqc_mec_server.py              # MEC edge server benchmark harness
│   └── plots/                              # Empirical hardware analysis figures
├── simulation_results/
│   ├── data/
│   │   ├── sim_results_1to1_baseline.csv   # 100-run calibrated NS-3 simulation output
│   │   ├── sim_results_swarm_sweep.csv     # 54-configuration swarm sweep results
│   │   └── validation_results.csv          # LHS vs RHS error verification metrics
│   └── plots/                              # 7 publication-ready 300 DPI figures
│       ├── hw_vs_sim_1to1_validation.png
│       ├── latency_vs_swarm_size.png
│       ├── crypto_latency_breakdown.png
│       ├── energy_vs_swarm_scale.png
│       ├── latency_vs_mobility.png
│       ├── queuing_and_packet_loss.png
│       └── urllc_compliance_heatmap.png
├── scripts/
│   ├── run_hitl_calibrated_pipeline.py     # Master calibrated simulation pipeline
│   ├── generate_calibrated_plots.py        # 300 DPI publication figure generator
│   ├── swarm_pqc_simulation.py             # Analytical Monte Carlo simulator
│   ├── monte_carlo_cvqkd_keyrate.py        # Quantum key distribution modeling
│   ├── monte_carlo_gilbert_elliott.py      # Channel burst loss model
│   └── plot_queueing_model.py              # M/M/1 queueing verification
├── experiments/
│   └── config.yaml                         # HITL-calibrated simulation parameters
├── ns-3-dev/                               # NS-3 (v3.42) discrete-event simulation tree
│   ├── contrib/
│   │   ├── pqc-security/                   # Custom PQC security module
│   │   │   ├── model/
│   │   │   │   ├── crystals-kyber-kem.cc/h # ML-KEM-512/768/1024 implementation
│   │   │   │   ├── hardware-profile.cc/h   # ARM Cortex-A72 hardware profile
│   │   │   │   ├── hybrid-kem-combiner.cc/h# ML-KEM + X25519 HKDF combiner
│   │   │   │   ├── ml-dsa-signer.cc/h      # ML-DSA-87 digital signatures
│   │   │   │   ├── pqc-energy-model.cc/h   # Physical energy & battery model
│   │   │   │   └── pqc-drone-app.cc/h      # Swarm UAV commander/follower app
│   │   └── nr/                             # 5G-LENA NR module (v3.1)
│   └── scratch/
│       ├── drone-swarm-pqc-sim.cc          # Drone swarm simulation driver
│       └── pqc-6g-simulation.cc            # Multi-scenario publication simulation
├── kyber6g-website/                        # Interactive Vite + React + Three.js dashboard
│   ├── src/
│   │   ├── components/DroneSwarmScene.jsx  # Real-time 3D drone swarm renderer
│   │   └── sections/ResultsDashboard.jsx   # Interactive charts & metrics
├── docs/                                   # Architectural and mathematical specifications
│   ├── kyber6g_master_spec.md              # Complete protocol specification
│   └── mathematical_proofs.md              # Security bounds & queuing proofs
├── IEEE_Access_LaTeX_template__1_dup/      # IEEE Access manuscript template
├── elsarticle/                             # Elsevier journal paper template
└── README.md                               # Project documentation
```

---

## Quick Start & Reproduction Guide

### 1. Prerequisites (Ubuntu 22.04 LTS / WSL)

```bash
# Core build dependencies
sudo apt-get update && sudo apt-get install -y \
    cmake g++ python3 python3-pip python3-dev pkg-config \
    ninja-build libgsl-dev libboost-all-dev libssl-dev

# Python data analysis dependencies
pip3 install numpy pandas matplotlib seaborn pyyaml scipy
```

### 2. Building the NS-3 C++ Engine

```bash
cd ns-3-dev
./ns3 configure -d optimized --enable-examples=no --enable-tests=no
./ns3 build -j$(nproc)
```

### 3. Executing the HITL Calibration & Swarm Pipeline

To run both the **1-to-1 baseline verification** (100 runs) and the **multi-drone swarm sweep** (54 configurations):

```bash
python3 scripts/run_hitl_calibrated_pipeline.py
```

### 4. Regenerating Publication Figures

```bash
python3 scripts/generate_calibrated_plots.py
```
All plots are output to `simulation_results/plots/` and the root folder at **300 DPI**.

### 5. Launching the Interactive 3D Visualizer

```bash
cd kyber6g-website
npm install
npm run dev
# Access local dashboard at http://localhost:5173
```

---

## Cryptographic Parameters

| Parameter | Classical Baseline | Hybrid PQC (Proposed) | NIST Level |
|---|:---:|:---:|:---:|
| **KEM Algorithm** | ECDH (X25519) | ML-KEM-1024 + X25519 | Level-5 |
| **Public Key Size** | 32 Bytes | 1,568 + 32 Bytes | — |
| **Ciphertext Size** | 32 Bytes | 1,568 Bytes | — |
| **Digital Signature** | ECDSA (secp256r1) | ML-DSA-87 (Dilithium-5) | Level-5 |
| **Signature Size** | 64 Bytes | 4,627 Bytes | — |
| **Payload Encryption** | AES-128-GCM | AES-256-GCM | — |
| **Forward Secrecy** | Per-Session | Per-Handover / 0-RTT | Post-Quantum |

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
