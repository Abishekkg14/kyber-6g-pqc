# Advantages and Limitations of the Hybrid CRYSTALS-Kyber/X25519 Scheme

This document summarizes the theoretical and practical implications of the proposed hybrid post-quantum cryptography (PQC) scheme evaluated in the 6G drone swarm simulation, compared against three baselines: `ECC_ONLY`, `KYBER_ONLY`, and `KYBER_CACHED`.

## Evaluation Modes

| Mode | Algorithm(s) | Description |
|------|-------------|-------------|
| `ECC_ONLY` | X25519 ECDH | Classical baseline — broken by Shor's algorithm |
| `KYBER_ONLY` | CRYSTALS-Kyber-768 | Post-quantum baseline — full KEM per handshake |
| `KYBER_CACHED` | Kyber-768 with PSK cache | Optimized PQ — reuses prior encapsulation results |
| `HYBRID_KYBER_ECDH` | X25519 + Kyber-768 + HKDF | Proposed dual-KEM hybrid scheme |

## Advantages of the Hybrid Method

### 1. Quantum Resistance (Shor's Algorithm Resilience)
The primary advantage of introducing CRYSTALS-Kyber-768 into the handshake is its resilience against quantum computing attacks. While the baseline `ECC_ONLY` mode (using X25519) can be broken in polynomial time by a sufficiently large quantum computer running Shor's algorithm, Kyber relies on the hardness of the Module Learning With Errors (MLWE) problem, offering ~203 bits of quantum security.

**Result field mapping:** The `security_strength_score` metric in each CSV captures this:
- `ECC_ONLY`: 128 (equivalent to AES-128)
- `KYBER_ONLY` / `KYBER_CACHED` / `HYBRID_KYBER_ECDH`: 203 (Kyber-768 quantum sieve bound)

### 2. Forward Secrecy and Cryptographic Agility
By combining X25519 and Kyber-768 using a secure Key Derivation Function (HKDF), the hybrid scheme guarantees that the resulting session key remains secure as long as *at least one* of the underlying algorithms remains unbroken. This hedge protects the system against future cryptanalytic breakthroughs in either classical ECC or the relatively new lattice-based Kyber algorithms.

**Result field mapping:** The `security_latency_efficiency` metric (Security Strength / Handshake Latency in ms) quantifies the efficiency of achieving this higher security level. Hybrid mode achieves a 203-bit strength floor at only marginally increased latency compared to `KYBER_ONLY`.

### 3. Backward Compatibility with ECC
The hybrid approach transmits both the classical X25519 public keys and the Kyber public keys/ciphertexts. This maintains structural backward compatibility with legacy drone nodes that may not yet support PQC operations, as the network could potentially fall back to `ECC_ONLY` if post-quantum parameters are stripped or unsupported by a degraded node.

**Result field mapping:** Compare `rrc_request_size_bytes` and `rrc_setup_size_bytes` across modes — the hybrid IE contains both classical and PQ fields, meaning a legacy parser can extract the X25519 portion while ignoring the Kyber extension.

## Limitations

### 1. Larger Handshake Messages (Control Plane Overhead)
The most significant drawback of the hybrid scheme is the increased size of the RRC Control Plane messages.
- An X25519 public key is **32 bytes**.
- A Kyber-768 public key is **1184 bytes**, and the ciphertext is **1088 bytes**.
This inflates the RRC Connection Request and Setup IE payloads significantly, which increases transmission latency over the air interface and introduces a higher probability of packet fragmentation over the radio link.

**Result field mapping:** The `rrc_request_size_bytes` and `rrc_setup_size_bytes` CSV fields directly capture this overhead. The `rlc_segments_per_pdu` metric shows how the NR RLC layer fragments these larger handshake PDUs.

### 2. Higher Computation Overhead
Performing both key generation/encapsulation procedures sequentially increases the overall cryptographic processing delay on the drone's low-power computing hardware. The `HYBRID_KYBER_ECDH` mode requires time to compute both the ECC scalar multiplications and the Kyber matrix operations, leading to slightly increased end-to-end handshake setup times compared to using either scheme independently.

**Result field mapping:** The `crypto_computation_us` field tracks the total cryptographic wall-clock time per handshake. The `handshake_latency_us` captures the full end-to-end handshake duration including air-interface RTT. The ratio of security to latency is captured by `security_latency_efficiency`.

### 3. Impact on Packet Delivery at Scale
As the swarm size grows, the larger handshake messages compete for the shared NR air interface, contributing to higher `queueing_delay_us` and marginally lower `packet_delivery_ratio`. However, once keys are established, the `encrypt_latency_us` and `decrypt_latency_us` of AES-256-GCM data-plane operations are identical across all modes (same symmetric cipher), so the throughput impact is confined to the control plane burst.

**Result field mapping:** Compare `packet_delivery_ratio` and `e2e_app_latency_ms` across modes at each swarm size (10, 28, 56 drones) to observe this scaling effect.

## Summary: Mode Comparison Matrix

| Property | ECC_ONLY | KYBER_ONLY | KYBER_CACHED | HYBRID |
|----------|----------|------------|--------------|--------|
| Quantum Resistance | No | Yes | Yes | Yes |
| Classical Resistance | Yes | Assumed | Assumed | Yes |
| Forward Secrecy | Yes | Yes | Partial | Yes |
| Backward Compatible | Yes | No | No | Yes |
| Handshake Size | ~300 B | ~6,400 B | ~6,400 B | ~6,500 B |
| Handshake Latency | Low | Medium | Low | Medium |
| Security Score | 128 | 203 | 203 | 203 |

## CSV Output Fields Reference

All experiment CSVs in `results/` contain these fields (plus standard statistical columns: count, mean, stddev, min, max, p50, p95, p99):

| Metric Field | Unit | Description |
|-------------|------|-------------|
| `packet_delivery_ratio` | ratio [0,1] | Derived: received / sent packet count |
| `packet_sent_events` | count | Total application packets transmitted |
| `packet_received_events` | count | Total packets successfully received/decrypted |
| `handshake_latency_us` | microseconds | End-to-end PQC handshake time |
| `crypto_computation_us` | microseconds | Total KEM + signature CPU time per handshake |
| `security_strength_score` | log₂(ops) | Bits of security (128 for ECC, 203 for Kyber) |
| `security_latency_efficiency` | score/ms | Security strength / handshake latency |
| `rrc_request_size_bytes` | bytes | PQC RRC Connection Request IE size |
| `rrc_setup_size_bytes` | bytes | PQC RRC Connection Setup IE size |
| `e2e_app_latency_ms` | milliseconds | Application-layer end-to-end latency |
| `queueing_delay_us` | microseconds | MAC-layer queueing delay at gNB gateway |
| `encrypt_latency_us` | microseconds | AES-GCM per-packet encryption time |
| `decrypt_latency_us` | microseconds | AES-GCM per-packet decryption time |
| `throughput_bytes` | bytes | Application payload bytes received |
