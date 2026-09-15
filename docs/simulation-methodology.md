# Simulation Methodology

## Overview

Kyber-6G evaluates post-quantum security for drone swarms using **ns-3** with the `pqc-security` contrib module. Cryptography is **simulated** (correct FIPS 203/204 wire sizes and benchmark-derived delays); no liboqs dependency.

## Primary driver

```bash
cd ns-3-dev
./ns3 run "drone-swarm-pqc-sim --cryptoMode=hybrid --nDrones=28 --numRuns=30 --seed=42"
```

## Scenarios

| Scenario | Description |
|----------|-------------|
| `baseline-ecc` | X25519-only baseline |
| `mlkem512/768/1024` | ML-KEM-only at NIST levels |
| `mlkem1024-cached` | ML-KEM with mobility-aware cache |
| `hybrid-mlkem1024-x25519` | Dual KEM (proposed) |
| `dense-urban-nlos` | Shadowing + urban canyon stress |
| `high-speed-handover` | Elevated mobility + rekey |
| `core-bottleneck` | S1u delay 10 ms |
| `edge-backhaul-latency` | Configurable MEC backhaul |
| `quantum-attack` | HNDL harvest-now-decrypt-later |

## Hardware profiles (ASSUMED — not measured)

| Profile | Crypto scale | CPU W | Idle W | Parallel ops |
|---------|-------------|-------|--------|--------------|
| cortex-a55 | 1.8× | 2.0 | 0.5 | 1 |
| pixhawk-class | 3.5× | 1.5 | 0.3 | 1 |
| jetson-nano | 0.6× | 5.0 | 1.0 | 2 |
| jetson-orin | 0.25× | 15.0 | 2.0 | 4 |
| edge-server | 0.1× | 45.0 | 8.0 | 8 |

## ML-KEM-1024 Selection Rationale

ML-KEM-1024 (FIPS 203) provides NIST Level 5 quantum security (256-bit classical equivalent), with 1568-byte public keys and ciphertexts. Selected for maximum security margin appropriate for long-lived military drone credentials and compliance with the highest NIST post-quantum security category.

## Parallel vs sequential hybrid

`--parallelHandshake=true` uses `max(Kyber, ECDH) × 1.1` when `maxParallelOps ≥ 2`; otherwise latencies sum.

## Monte Carlo protocol

Default `--numRuns=100` (or `--numRuns=3` for smoke testing) with `RngSeedManager::SetSeed(seed + run)`. Aggregate via `aggregate_results.py` for 95% CI.

## Modeled vs measured fields

**Modeled:** energy (mJ), battery life projection, attack-cost estimates, Kyber-level selection bar chart when sweep CSVs absent.

**Measured (simulated workload):** handshake latency, RRC sizes, PDR, queueing delay, cache hit rate.
