# Kyber-6G Empirical Benchmark Versioning & Metadata

**Version:** 2.1.0  
**Timestamp:** 2026-09-15T00:20:00+05:30  
**Testbed Configuration:**
- **UAV Node (Client):** Raspberry Pi 4 Model B (4× ARM Cortex-A72 @ 1.50 GHz, 2 GB LPDDR4, BCM2711)
  - IP: `172.26.53.240`
  - OS: Linux 6.6 (Debian/Raspbian aarch64)
  - Post-Quantum Crypto Library: `liboqs` 0.16.0 (`liboqs-python`) + OpenSSL 3.5
  - Symmetric Crypto Library: `cryptography` (AES-256-GCM AEAD, HKDF-SHA256)
- **gNodeB Node (MEC Server):** Host Edge Server (Ubuntu 22.04 LTS / WSL2)
  - IP: `172.26.53.139`
  - Transport: UDP Port 14000 (Framed / Reassembly Engine, MTU 1352 bytes)
- **Wireless Link:** IEEE 802.11ac / 5G NR n78 emulation baseline (Sub-10ms RTT)

## Cryptographic Parameters & Primitives (NIST Level 5)
1. **Key Encapsulation Mechanism (KEM):** ML-KEM-1024 (FIPS 203)
   - Public Key Size: 1568 bytes
   - Ciphertext Size: 1568 bytes
   - Shared Secret: 32 bytes
2. **Classical Key Agreement:** X25519 (RFC 7748)
   - Public Key Size: 32 bytes
   - Shared Secret: 32 bytes
3. **Digital Signature Scheme:** ML-DSA-87 (FIPS 204)
   - Public Key Size: 2592 bytes
   - Signature Size: 4627 bytes (corrected from 4595)
   - Authentication: Mutual with Bound Transcript (`ue_id || mobility_hash || pk_x || pk_k`) and Trusted UAV Registry
4. **Key Derivation Function (KDF):** HKDF-SHA256 (RFC 5869)
   - Full Handshake: `HKDF-Extract + Expand(s_x || s_k, salt, "Kyber6G-3GPP-Rel17-MasterKey")`
   - Cached Rekey: `HKDF-Expand(s_cached, ephemeral_salt, "Kyber6G-3GPP-Cached-Rapid-Rekey")`
5. **Data Plane AEAD:** AES-256-GCM (NIST SP 800-38D)
   - Key: 256-bit derived session key
   - Nonce: 96-bit (`uint64_t` monotonic counter + 32-bit random salt)
   - Tag: 128-bit authentication tag

## Empirical Benchmark Summary (100 Iterations)
| Protocol Phase | Physical Hardware Mean (ms) | Physical Hardware Std (ms) | Physical SWaP Energy (mJ) | Simulation Validated Δ (%) |
| :--- | :--- | :--- | :--- | :--- |
| **Full PQC Cold Start (Iteration 1)** | 45.506 ms | — | 66.329 mJ | 0.02% (MATCH) |
| **Full PQC Warm Start (Iteration 51)** | 20.820 ms | — | 22.046 mJ | Calibrated |
| **Cached Rapid Rekey (1-RTT)** | 8.234 ms | ± 1.156 ms | 1.277 mJ | 1.03% (MATCH) |
| **AES-256-GCM Telemetry Turnaround** | 3.904 ms | ± 0.666 ms | — | 1.90% (MATCH) |
