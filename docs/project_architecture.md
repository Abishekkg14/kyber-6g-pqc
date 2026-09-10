# Kyber-6G Project Architecture & Upgrade Documentation

## 1. Project Overview
The **Kyber-6G** project is a highly advanced 6G autonomous UAV swarm simulation framework built on top of the NS-3 simulator (specifically utilizing the CTTC 5G-LENA module). The primary objective is to evaluate and optimize Post-Quantum Cryptography (PQC) integration in extreme mobility and high-frequency environments.

**Core Environmental Constraints:**
*   **Mobility:** High-speed UAV swarms operating at 120 m/s.
*   **Spectrum:** 140 GHz Terahertz (THz) band utilizing narrow pencil-beam MIMO.
*   **Channel Coherence:** Extremely short coherence times ($\approx 17.8 \mu s$), necessitating rapid beam tracking and robust cryptography.
*   **Security:** Migration to NIST Level 5 PQC standards (ML-KEM-1024 and ML-DSA-87), protecting against "harvest-now, decrypt-later" quantum threats.
*   **Latency:** Sub-millisecond Ultra-Reliable Low-Latency Communication (URLLC) requirements.

## 2. Current System Architecture

The architecture spans multiple layers of the OSI model, integrating specialized cryptographic primitives at each layer to balance security with URLLC performance constraints.

### 2.1 Physical & Link Layer (L1/L2)
*   **CV-QKD (Continuous Variable Quantum Key Distribution):** Secures physical drone-to-drone FSO (Free Space Optical) links using photon catalysis to enhance the secure key rate under atmospheric turbulence.
*   **CSIDH-512 MAC CE Bypass:** Isogeny-based KEM with ultra-small keys (64 bytes) embedded directly into MAC Control Elements. This provides an initial, low-latency, fragmentation-free link-layer key exchange, functioning as a latency optimization layer prior to full RRC authentication.

### 2.2 Network & RRC Layer (L3)
*   **X-Wing Hybrid KEM:** The primary authentication and key exchange mechanism (encapsulated within RRC Connection Setup). It combines classical **X25519 (ECDH)** with post-quantum **ML-KEM-1024**, providing Perfect Forward Secrecy (PFS) resilient to both classical and quantum attacks.
*   **ML-DSA-87 Authentication:** Secures the X-Wing handshake by signing the exchanged key material.
*   **EMULSION Framework:** Protects 5G/6G System Information Block (SIB) broadcasts. Uses a TESLA-style HMAC-SHA-256 symmetric chain for per-packet authentication, anchored once per epoch by a post-quantum MAYO signature.

### 2.3 Application & Swarm Layer (L7)
*   **VQFL-DAG Ledger:** Variational Quantum Federated Learning (VQFL) operates over a Directed Acyclic Graph (DAG) ledger for decentralized identity management, swarm intelligence, and trust evaluation (mitigating data poisoning without a centralized PKI).

---

## 3. Recent Architectural Upgrades (Phase 2)

To elevate the project to a mathematically rigorous, publication-ready state (targeting IEEE venues), several critical components were recently developed and integrated.

### 3.1 Formal Mathematical Proofs
A comprehensive set of formal proofs was established (see `docs/mathematical_proofs.md`):
1.  **EMULSION EUF-CMA:** A 4-hop game-hopping proof verifying the unforgeability of the SIB broadcast authentication.
2.  **X-Wing Perfect Forward Secrecy:** An extension of Syverson-Van Oorschot (SVO) Logic, introducing 3 new post-quantum axioms (SVO-PQ1, SVO-PQ2, SVO-PFS) to formally prove the hybrid KEM combiner's security.
3.  **M/G/1 Pollaczek-Khinchine:** Mathematical derivation of gateway buffer waiting times, modeling the bimodal nature of PQC micro-burst service times with TTI-quantized boundaries.

### 3.2 NS-3 C++ Simulation Enhancements
The `contrib/pqc-security/model/` NS-3 tree was significantly refactored:
1.  **Gilbert-Elliott THz Channel Model (`thz-gilbert-elliott-channel.cc`):** Implemented a two-state Markov fading model calibrated to 140 GHz / 120 m/s coherence times. Models exponential Packet Delivery Ratio (PDR) decay across fragmented PQC payloads.
2.  **M/G/1 Queue Tracker (`mg1-queue-tracker.cc`):** Replaced the legacy M/M/1 assumption. Uses Welford's online algorithm to track variance and compute Pollaczek-Khinchine delays in real-time. Capable of detecting TCP RTO cascade events.
3.  **Dynamic TTI Serialization (`pqc-rrc-extension.cc`):** Computes serialization delay based on 3GPP numerologies ($\mu \in \{3,4,5\}$) and Transport Block Sizes (TBS). Tracks exact IP fragmentation counts for large Level 5 PQC payloads.

### 3.3 Physics-Grounded Monte Carlo Analysis
Standalone Python scripts were developed in `scripts/` to generate publication-ready data:
1.  **MAC Serialization (`monte_carlo_mac_serialization.py`):** Models the serialization delay across 6G numerologies with TBS scheduling jitter.
2.  **Gilbert-Elliott PDR (`monte_carlo_gilbert_elliott.py`):** Simulates 100K channel realizations to prove PDR collapse under fragmentation and maps TCP RTO cascade probabilities.
3.  **CV-QKD Holevo Bound (`monte_carlo_cvqkd_keyrate.py`):** Evaluates FSO secure key rates under log-normal atmospheric turbulence fading, demonstrating the boundaries of positive key rates and the impact of photon catalysis.

### 3.4 Literature Analysis
A thorough ablation study (see `docs/literature_analysis.md`) benchmarking Kyber-6G against Q-FE, EMULSION, and QuaRTA-6G. It identifies critical remaining weaknesses (e.g., TCP Head-of-Line blocking, beam tracking overhead) and proposes future mitigation strategies like Stochastic Network Calculus and Rateless Raptor codes.

---

## 4. Simulation & Orchestration Pipeline

The current execution flow for generating project results relies on the following sequence:

1.  **Configuration:** `experiments/config.yaml` defines the matrix of experiment parameters (e.g., KEM type, numerology, swarm size).
2.  **Execution:** The bash script `run_experiments.sh` iterates through configurations and launches the main NS-3 simulation (`ns-3-dev/scratch/pqc-6g-simulation.cc`).
3.  **Data Collection:** The C++ `PqcMetricsCollector` traces simulation events (latency, PDR, queue sizes, KEM overhead) and exports raw data to `.csv` files.
4.  **Aggregation:** `aggregate_results.py` cleans and consolidates the CSV outputs.
5.  **Plotting:** `build_results_and_plots.py` (and the newly added `monte_carlo_*.py` scripts) process the aggregated data and physics models to generate vector graphics (`.pdf`, `.svg`) in the `paper_figures/` directory for LaTeX inclusion.
