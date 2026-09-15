# Hardware-in-the-Loop (HITL) Physical Validation Suite

This directory contains the complete physical testbed benchmark harness, empirical measurement datasets, cryptographic streaming engines, and analysis scripts executed on the **Raspberry Pi 4 Model B (ARM Cortex-A72)** for the **Kyber-6G** project.

---

## 1. Hardware Testbed Specifications

| Component | Physical Specification |
|---|---|
| **Board / SoC** | Raspberry Pi 4 Model B / Broadcom BCM2711 |
| **CPU Architecture** | Quad-core ARM Cortex-A72 (ARMv8-A 64-bit) @ 1.5 GHz |
| **RAM** | 2.0 GB LPDDR4-3200 SDRAM |
| **Cores for Crypto** | **2 Dedicated Worker Cores** (`ThreadPoolExecutor(max_workers=2)`) |
| **Cores for Avionics / OS** | **2 Dedicated Cores** (Isolated for kernel, UDP stack, MAVLink telemetry) |
| **Operating System** | Ubuntu 22.04 LTS (Linux 5.15 aarch64) |
| **Crypto Runtime** | `liboqs` (Open Quantum Safe) v0.10.0 + `cryptography` Python library |
| **Physical Power Baseline** | $P_{\text{active}} = 4.85\,\text{W}$ (CPU active), $P_{\text{idle}} = 1.20\,\text{W}$ (idle), $P_{\text{TX}} = 0.52\,\text{W}$, $P_{\text{RX}} = 0.16\,\text{W}$ |
| **Thermal Equilibrium** | $48.5\,^\circ\text{C}$ (under continuous 100 Hz avionics packet stream) |

---

## 2. Directory Structure & Script Locations

Executable testbed harnesses are provided both in `hitl/` and `src/hitl/` for immediate execution:

```
hitl/ (and src/hitl/)
├── data/
│   ├── hitl_benchmarks.csv             # Baseline 100-run measurements
│   ├── hitl_benchmarks_extended.csv    # Live 100-iteration ground truth (latency, energy, thermal)
│   ├── image_encryption_benchmarks.csv # High-res reconnaissance image upload benchmarks
│   ├── video_streaming_benchmarks.csv  # Real-time drone video streaming benchmarks
│   └── validation_results.csv          # 1-to-1 Physical vs NS-3 simulation validation (<= 2% error)
├── pqc_benchmark_client.py             # 100-run autonomous client harness (runs on RPi 4)
├── pqc_benchmark_server.py             # Base tower edge server (runs on gNodeB MEC)
├── pqc_video_streamer.py               # Real-time drone video streaming encryptor
├── pqc_image_secure_transfer.py        # Drone aerial image encryptor and uploader
├── pqc_media_multicore_engine.py       # Multi-core hardware-accelerated crypto engine
├── scripts/                            # Detailed evaluation, analysis, and plotting scripts
│   ├── plot_overhead.py                # Generates crypto_overhead_breakdown.png
│   ├── plot_urllc_avionics.py          # Generates hitl_urllc_avionics.png
│   └── visualize_benchmarks.py         # Generates hitl_benchmark_analysis.png
└── plots/
    ├── crypto_overhead_breakdown.png   # Message sizes & transport overhead vs 1352B MTU
    ├── hitl_benchmark_analysis.png     # Latency/energy distribution across 100 runs
    ├── hitl_urllc_avionics.png         # Real-time avionics telemetry latency under 10ms URLLC
    ├── hw_vs_sim_1to1_validation.png   # Direct 1-to-1 comparison between Physical RPi4 and NS-3 Sim
    ├── media_image_encryption_proof.png
    ├── media_throughput_and_core_utilization.png
    └── media_video_frame_proof.png
```

---

## 3. Protocol Engineering & Robustness Solvers

### A. Socket Stream Fragmentation & Buffer Trap Handling (TCP / UDP)
Because **ML-KEM-1024** public keys ($1,568\,\text{bytes}$) and ciphertexts ($1,568\,\text{bytes}$) exceed the standard $1,500\,\text{byte}$ MTU, naive socket calls create fatal buffer traps over physical wireless links:
1. **TCP Byte-Stream Framing**:
   - Calling `sock.recv(2048)` on TCP does not guarantee receiving all $1,568\,\text{bytes}$ in one call.
   - **Solution**: Implemented an explicit 4-byte big-endian length-prefixed framing protocol with an exact byte-accumulation loop (`recv_exact_tcp(sock, n_bytes)`). It loops until every byte is reassembled, completely preventing partial-frame truncation under high wireless jitter.
2. **UDP MTU-Safe Framing & Stop-and-Wait ARQ**:
   - If a large $1,568\,\text{byte}$ datagram is sent directly over UDP, the IP layer fragments it (e.g. $1480\,\text{B} + 88\,\text{B}$). Losing any single fragment causes the entire packet to be dropped silently by the OS.
   - **Solution**: The application layer explicitly chunks payloads into sub-MTU frames (`MAX_DGRAM = 1352` bytes) with framing headers (`struct.pack("!HBBH", msg_type, frag_idx, total_frags, seq_id)`). Handshakes use **Stop-and-Wait ARQ** with exponential backoff (`send_framed_udp_reliable`), automatically retransmitting if packets drop on the wireless channel.
   - Both modes can be selected via `--transport udp` (default) or `--transport tcp`.

### B. AES-256-GCM Nonce Handling & Header AAD Authentication
In AES-GCM, reusing the same 96-bit nonce under the same key completely destroys confidentiality and reveals the GHASH authentication key $H$:
1. **No Random Nonces**: We avoid `os.urandom(12)` in streaming data planes due to birthday-paradox collision probabilities over large packet sequences.
2. **Deterministic Monotonic Counters**:
   - Avionics Telemetry: Constructs a 96-bit nonce via `struct.pack("!QI", nonce_counter, STREAM_SALT)`.
   - Video Frames: Constructs a 96-bit nonce via `struct.pack("!III", epoch_id, frame_id, chunk_id)`.
3. **Additional Authenticated Data (AAD)**:
   - The clear packet header (UAV ID + monotonic sequence counter or frame index) is transmitted in the clear and passed directly as `associated_data` (AAD) to `AESGCM.encrypt(nonce, payload, associated_data=header)` and `AESGCM.decrypt(nonce, ct, associated_data=header)`.
   - **Packet Drop Resilience**: Even if UDP packets drop or arrive out of order, the receiver reads the sequence number from the clear header, reconstructs the identical deterministic nonce, verifies the AAD authentication tag, and decrypts without desynchronizing.

---

## 4. How to Execute Physical Benchmarks

### Step 1: Start Base Tower Edge Server (gNodeB MEC)
```bash
# Default UDP mode
python3 hitl/pqc_benchmark_server.py --port 14000 --transport udp

# Or TCP mode with length-prefixed stream framing
python3 hitl/pqc_benchmark_server.py --port 14000 --transport tcp
```

### Step 2: Start Drone Benchmark Client (Raspberry Pi 4)
```bash
# Run 100 benchmark iterations over UDP (with ARQ retransmission)
python3 hitl/pqc_benchmark_client.py --server <GNB_IP> --port 14000 --transport udp --runs 100

# Or over TCP
python3 hitl/pqc_benchmark_client.py --server <GNB_IP> --port 14000 --transport tcp --runs 100
```
This logs all physical latency, energy, CPU load, and thermal measurements to `hitl/data/hitl_benchmarks_extended.csv`.

### Step 3: Run Drone Video Streaming Pipeline
```bash
# Start gNodeB Media Server
python3 hitl/pqc_gnodeb_mec_server.py --port 14000

# Stream Real-Time Encrypted Video (AES-256-GCM with Deterministic Nonces & AAD)
python3 hitl/pqc_video_streamer.py --server <GNB_IP> --port 14000 --cipher AES_GCM --fps 30
```

### Step 4: Run Reconnaissance Image Encryption & Upload
```bash
python3 hitl/pqc_image_secure_transfer.py --server <GNB_IP> --port 14000 --cipher AES_GCM --image "sample images/drone image-1.jpg"
```

---

## 5. Physical Ground-Truth Validation Results (Physical RPi4 vs. NS-3 Sim)

Evaluated on the 30% held-out test split, confirming physical-to-simulation equivalence within $\le 2.0\%$ variance:

| Evaluation Metric | Physical RPi4 Ground Truth | NS-3 Calibrated Simulation | Empirical Variance | Discrepancy Bound | Status |
|---|:---:|:---:|:---:|:---:|:---:|
| **Full Handshake Latency** | 45.506 ms | 45.513 ms | **0.02%** | $\le 2.00\%$ | **PASS** |
| **Cached Rekey (1-RTT) Latency** | 8.234 ms | 8.150 ms | **1.03%** | $\le 2.00\%$ | **PASS** |
| **Full Handshake Energy** | 66.329 mJ | 66.340 mJ | **0.02%** | $\le 2.00\%$ | **PASS** |
| **Cached Rekey Energy** | 1.277 mJ | 1.261 mJ | **1.29%** | $\le 2.00\%$ | **PASS** |
| **AES-256-GCM Turnaround** | 3.904 ms | 3.978 ms | **1.90%** | $\le 2.00\%$ | **PASS** |
| **CPU Power (Active)** | 4.85 W | 4.85 W | **0.00%** | $\le 2.00\%$ | **PASS** |
| **RF TX / RX Power** | 0.52 W / 0.16 W | 0.52 W / 0.16 W | **0.00%** | $\le 2.00\%$ | **PASS** |
| **Steady-State SoC Temperature** | 48.50 °C | 48.50 °C | **Nominal** | — | **PASS** |

> **Statistical Note:** The HITL dataset contains only N=2 full-handshake
> (FULL_PQC) measurements (iterations 1 and 51 — cold-start and warm-cache).
> Full-handshake statistics in the validation table above are therefore point
> estimates, not distributional. The cached-rekey metrics (N=98) provide
> statistically robust distributional comparisons. For publication, additional
> independent cold-start repetitions (≥30) are recommended to support boxplot
> or CI representation of full-handshake latency/energy.

> **URLLC Tail Latency Note (3GPP Compliance):** The Cached Rekey **mean** latency
> (~8.2 ms) meets the sub-10 ms URLLC bound. However, the **P99 tail latency**
> under wireless channel fading reaches **~11.6 ms** at N=1 and increases with
> swarm density. This exceeds the strict 10 ms P99 URLLC threshold defined in
> 3GPP TR 22.804. Claims of URLLC compliance should specify that **mean**
> latency meets the bound, while P99 tail jitter may require additional
> link-layer optimizations (e.g., HARQ redundancy, prioritized scheduling)
> for unconditional compliance.
>
> **Cryptographic Security Note:** The "Cached Rekey (1-RTT)" mode uses
> `HKDF(cached_master_secret, ephemeral_salt)` for key ratcheting/evolution.
> This provides efficient session key rotation but does **not** constitute
> Perfect Forward Secrecy (PFS), which requires fresh ephemeral asymmetric
> key exchange per session. The full handshake (with fresh ML-KEM-1024 +
> X25519 key generation) provides genuine forward secrecy. Deployment
> policy should trigger periodic full re-handshakes at configurable intervals
> (e.g., every `cacheTtl` seconds or on mobility cell change) to maintain
> forward secrecy guarantees.
