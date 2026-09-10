# Raspberry Pi 4 HITL Execution & Deployment Guide

This guide details the exact step-by-step commands to transfer, configure, execute, and collect empirical benchmark results from the **Raspberry Pi 4 Model B (ARM Cortex-A72)** for the **Kyber-6G** framework.

---

## 1. Network Prerequisite (Host PC & Raspberry Pi)

Both your Host PC (running the gNodeB base tower server) and your Raspberry Pi 4 must be connected to the same local Wi-Fi, Ethernet switch, or mobile hotspot.

1. **Find Host PC Local IP Address:**
   - **Windows:** Open PowerShell and run `ipconfig` (find `IPv4 Address`, e.g. `192.168.1.50`).
   - **Linux/WSL:** Run `hostname -I` or `ip addr show`.
2. **Find Raspberry Pi IP Address:**
   - On the Pi terminal: `hostname -I` (e.g. `192.168.1.100`).

---

## 2. Transfer Deployment Package to Raspberry Pi

From your Host PC terminal (WSL or Windows PowerShell):

```bash
# Set your Raspberry Pi username and IP
RPI_USER="abishek14"
RPI_IP="192.168.1.100"

# Copy the deployment package to the Raspberry Pi home directory
scp -r "rpi_hitl_deployment" ${RPI_USER}@${RPI_IP}:~/rpi_hitl_deployment
```

---

## 3. Configure Raspberry Pi Environment

SSH into the Raspberry Pi:

```bash
ssh ${RPI_USER}@${RPI_IP}

cd ~/rpi_hitl_deployment/setup

# 1. Install system tools, C liboqs, and python dependencies (One-time setup)
bash install_dependencies.sh

# 2. Apply performance tuning (lock CPU to 1.50 GHz, disable Wi-Fi sleep jitter)
sudo bash rpi_performance_tune.sh
```

---

## 4. Run Standalone Cryptographic Audit (Zero-Network Prerequisite)

Before starting network communications, verify the entire Level-5 post-quantum cryptographic stack locally on the Pi:

```bash
cd ~/rpi_hitl_deployment/crypto

# Execute standalone in-memory verification & negative security tests
taskset -c 2,3 nice -n -10 python3 pqc_standalone_crypto_audit.py
```
*Expected Output:*
- Measures exact timings for ML-KEM-1024, X25519, ML-DSA-87, and AES-256-GCM.
- PASS: FO-Transform implicit rejection on corrupted ciphertext.
- PASS: ML-DSA-87 signature forgery rejection.
- PASS: Ephemeral secret key memory zeroization.

---

## 5. Execute Live Hardware-in-the-Loop (HITL) Benchmark

### Step A: Start gNodeB Base Tower Server on Host PC
On your Host PC terminal:
```bash
cd rpi_hitl_deployment/server
python3 pqc_gnodeb_mec_server.py
```
*(Leave this running; it will listen on UDP port 14000)*

### Step B: Run Autonomous 100-Run Benchmark on Raspberry Pi
On the Raspberry Pi terminal:
```bash
cd ~/rpi_hitl_deployment/crypto

# Run 100 benchmark handshakes with thermal and power logging:
# (Replace 192.168.1.50 with your Host PC's IP)
taskset -c 2,3 nice -n -10 python3 pqc_benchmark_client.py --server 192.168.1.50 --runs 100 --out ../results/hitl_benchmarks_extended.csv
```

### Step C: Stream Live Avionics Flight Telemetry (Optional Demo)
On the Raspberry Pi terminal:
```bash
# Streams 48-byte binary avionics vectors at 20 Hz:
taskset -c 2,3 nice -n -10 python3 pqc_uav_flight_client.py --server 192.168.1.50 --rate 20 --duration 30
```

---

## 6. Retrieve Results Back to Host PC

From your Host PC terminal:

```bash
# Fetch the generated benchmark CSVs back into the main repository:
scp ${RPI_USER}@${RPI_IP}:~/rpi_hitl_deployment/results/*.csv "hitl/data/"
```

---

## 7. Regenerate Calibrated Figures & Update Repository

On your Host PC inside the project directory:

```bash
# 1. Run 1-to-1 baseline validation against the fresh physical benchmarks
python3 scripts/run_hitl_calibrated_pipeline.py

# 2. Regenerate all 300 DPI publication plots
python3 scripts/generate_calibrated_plots.py

# 3. Commit and push fresh physical validation data to GitHub
git add hitl/data/*.csv simulation_results/plots/*.png
git commit -m "data: update HITL physical benchmarks from Raspberry Pi 4 testbed run"
git push origin main
```
