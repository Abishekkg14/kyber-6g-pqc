# Supplementary Material: Reproducibility & Artifact Appendix
## Submission to IEEE Access
**Title**: Post-Quantum Cryptography (PQC) Key Exchange and Mobility Edge Caching for 6G Drone Swarms: A Comprehensive Simulation Approach

### 1. Artifact Summary
This repository contains the complete, reproducible simulation framework utilizing the **NS-3 discrete-event simulator (v3.42)** paired with the **CTTC 5G-LENA module (v3.1)**. The codebase strictly adheres to 3GPP Rel-16 standards for NLoS fading, mobility edge caching, and Xn-based handovers.

Our custom `pqc-security-helper` module integrates hybrid PQC (CRYSTALS-Kyber-768 + ECDH) directly into the RRC-layer state machine.

### 2. File Organization
* `ns-3-dev/scratch/drone-swarm-pqc-sim.cc`: The core execution driver instantiating the 7-gNB hexagonal grid topology and scaling UAVs from 10 to 56 nodes.
* `ns-3-dev/contrib/pqc-security/`: Contains our novel cryptography integration modules, implementing Kyber encapsulation/decapsulation overheads based on NIST benchmarks.
* `updated_access_plots_2026/`: Contains the generated high-resolution (300 DPI) plots and the summarized `simulation_results.json` metric outputs.

### 3. Reproducibility Steps
To ensure strict peer-review transparency, the entire execution pipeline is automated.

**Step 3.1: Core Experiment Matrix**
Reviewers can reproduce the primary results across the 12-configuration matrix by executing:
```bash
cd ns-3-dev
./ns3 build
bash scratch/run_drone_experiments.sh
```

**Step 3.2: 50-Run Monte Carlo Ablation Study**
For rigorous statistical variance validation (as required for high-impact IEEE publications), we have provided a Monte Carlo script testing 50 random seeds across stressed NLoS conditions and key revocation edge-cases:
```bash
python3 run_ablation_study.py
```

**Step 3.3: Plot Generation**
To re-generate the 11 analytical figures utilizing the output CSVs:
```bash
python3 build_results_and_plots.py
```

### 4. Hardware Requirements
* **OS:** Ubuntu 22.04 LTS (Native or WSL2)
* **RAM:** Minimum 16GB (32GB recommended for 56-node matrix)
* **Compiler:** GCC 11.2 or higher (C++17 standard)

### 5. Open Source Declaration
The raw source code, plotting scripts, and preliminary datasets will be made publicly available via a GitHub repository upon paper acceptance, licensed under GPLv2 to align with NS-3 community standards.
