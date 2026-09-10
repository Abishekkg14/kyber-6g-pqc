# Kyber-6G Project — Master Specification Sheet
> **Extracted from:** `/home/abishek14/Kyber-6G project latest/` · **Date:** 2026-09-10
> **Sources:** `pqc_mec_server.py`, `pqc_benchmark_server.py`, `ns-3-dev/contrib/pqc-security/model/`, `docs/`, `scripts/`, `IEEE_Access_LaTeX_template/access_revised.tex`, `experiments/config.yaml`

---

## Domain 1 — Cryptographic Handshake & Authentication Mathematics

### 1.1 X-Wing Hybrid KEM Construction

The Kyber-6G handshake uses the **X-Wing** combiner: dual-KEM running X25519 and ML-KEM-1024 in parallel, combined through HKDF-SHA256.

#### Message Flow (from `pqc_mec_server.py` + `pqc-rrc-extension.cc`)

| Party | Action | Byte Payload |
|-------|--------|-------------|
| **UAV (UE)** | Generate X25519 ephemeral key pair | `ek_X25519_U` = **32 bytes** |
| **UAV (UE)** | Generate ML-KEM-1024 key pair | `ek_MLKEM_U` PK = **1568 bytes** |
| **UAV → gNB** | RRC Connection Request | 32 + 1568 = **1600 bytes** (+ 8-byte nonce = 1608 total on wire) |
| **gNB** | X25519 DH (Core 0) | `sk_server.exchange(pk_ecdh_drone)` → `s_ecdh` = **32 bytes** |
| **gNB** | ML-KEM-1024 Encaps (Core 1) | `kem.encap_secret(pk_kyber_drone)` → `ct_kyber`(1568B) + `s_kyber`(32B) |
| **gNB → UAV** | RRC Connection Setup | 32 (ECC PK) + 1568 (Kyber CT) + 16 (HKDF salt) = **1616 bytes** |

#### HKDF-SHA256 Key Fusion (exact code from `pqc_mec_server.py`)

```python
hkdf_salt = os.urandom(16)          # 16-byte cryptographically random salt per session

k_final = HKDF(
    algorithm=hashes.SHA256(),
    length=32,                       # 256-bit output session key
    salt=hkdf_salt,
    info=b"Kyber6G-3GPP-Rel17-MasterKey"   # Info-string label constant (28 bytes)
).derive(s_ecdh + s_kyber)          # IKM = X25519_ss || ML-KEM-1024_ss (64 bytes total)
```

**NS-3 simulation info-string** (`hybrid-kem-combiner.cc`): `"Kyber6G-HybridKEM-v1"` (20 bytes), FNV-1a 64-bit hash simulation.

#### Mathematical Security Bound (from `access_revised.tex`)

$$\mathrm{Adv}^{\mathrm{IND\text{-}CCA2}}_{\mathcal{H}} \leq \min\bigl(\mathrm{Adv}^{\mathrm{ECDLP}},\, \mathrm{Adv}^{\mathrm{MLWE}}_{k=3}\bigr) + \varepsilon_{\mathrm{HKDF}}$$

| Mode | Security Level |
|------|--------------|
| ECC only (X25519) | 128 classical bits |
| ML-KEM-1024 (NIST Level 5) | **230 quantum bits** |
| Hybrid (disjunction) | floor = **230 quantum bits** |

#### Parallel Execution Model (`hybrid-kem-combiner.cc`)

```cpp
// >= 2 cores (Jetson Nano, RPi 4):
T_parallel = max(T_X25519, T_MLKEM) * 1.1   // 10% memory contention overhead

// Single-core (Pixhawk STM32H7):
T_sequential = T_X25519 + T_MLKEM
```

**Simulated crypto timings (ARM Cortex-A55 baseline, Jetson Nano scaled):**

| Operation | Time |
|-----------|------|
| X25519 KeyGen | 45 µs |
| X25519 DH exchange | 120 µs |
| ML-KEM-1024 KeyGen | 180 µs |
| ML-KEM-1024 Encaps | 220 µs |
| ML-KEM-1024 Decaps | 250 µs |
| HKDF-SHA256 fusion | 5 µs (scaled) |
| Clock jitter model | Log-normal σ = 8% |
| Memory latency jitter | Uniform [0, 5 µs] |

---

### 1.2 ML-DSA-87 Mutual Authentication (`ml-dsa-signer.cc`, `pqc-rrc-extension.cc`)

**An explicit PQ digital signature scheme IS specified.** ML-DSA (FIPS 204 / Dilithium) provides mutual drone-to-gNB identity authentication **before** key derivation.

#### Exact Byte Lengths — FIPS 204 Table 1 (`SIZE_TABLE` in `ml-dsa-signer.cc`)

| Parameter Set | Public Key | Secret Key | Signature |
|--------------|-----------|-----------|----------|
| ML-DSA-44 (Level 2) | 1,312 B | 2,560 B | 2,420 B |
| ML-DSA-65 (Level 3) | 1,952 B | 4,032 B | 3,293 B |
| **ML-DSA-87 (Level 5)** | **2,592 B** | **4,896 B** | **4,595 B** |

> Default in NS-3 simulation: `ML_DSA_65`. Architecture targets `ML-DSA-87` (NIST Level 5).

#### RRC Payload Structural Breakdown (`docs/mathematical_proofs.md` §3.3)

| Field | Size |
|-------|------|
| ML-KEM-1024 Public Key | 1,568 B |
| X25519 Public Key | 64 B |
| ML-DSA-87 Signature | ~4,627 B |
| ML-DSA-87 Certificate (PK) | 2,420 B |
| **Total RRC Request IE** | **~8,679 B** |
| ML-KEM-1024 Ciphertext | 1,568 B |
| X25519 PK (gNB) | 32 B |
| ML-DSA-87 Signature (gNB) | ~4,627 B |
| **Total RRC Response IE** | **~6,227 B** |

#### Signing Timings on Cortex-A72 (`ml-dsa-signer.cc` attributes)

| Operation | Simulated Time |
|-----------|--------------|
| ML-DSA KeyGen | 300 µs |
| ML-DSA Sign | 500 µs |
| ML-DSA Verify | 200 µs |

---

### 1.3 HKDF → PDCP Key Derivation Chain (`hybrid-kem-combiner.cc`)

```cpp
PqcSessionKeys DeriveSessionKeys(combinedSecret[32]) {
    encryptionKey[i] = combinedSecret[i] ^ 0x01;  // 32 bytes — AES-256 key
    integrityKey[i]  = combinedSecret[i] ^ 0x02;  // 32 bytes — HMAC key
    nonceBase[i]     = combinedSecret[i] ^ 0x03;  // 12 bytes — GCM nonce seed
    nonceCounter     = 0;
    // 5G extension point: feeds same KDF chain as classical KASME derivation
}
```

---

## Domain 2 — MEC Edge Caching & 0-RTT Mobility Handover Architecture

### 2.1 PqcKeyCache Data Structure (`pqc-key-cache.cc`)

```cpp
struct CacheEntry {
    uint64_t         keyId;           // Monotonic identifier
    vector<uint8_t>  combinedSecret;  // 32-byte X-Wing session secret
    Time             createdAt;       // NS-3 simulation timestamp
    Time             ttl;             // Default: 300 seconds
    uint32_t         mobilityHash;    // Trajectory vector hash binding
    bool             revoked;         // AMF revocation flag
    uint64_t         nonceCounter;    // Monotonic nonce high-water mark
};
```

### 2.2 Cache Lookup State Machine

```
Lookup(ueIndex, mobilityHash)
  -> NOT FOUND             -> MISS    -> full X-Wing handshake required
  -> entry.revoked==true   -> REVOKED -> full AKA re-authentication
  -> (Now-createdAt) > ttl -> STALE   -> stale_key_events++, full handshake
  -> mobilityHash mismatch -> STALE   -> key invalidated, full handshake
  -> all checks pass       -> HIT     -> return combinedSecret, skip lattice KeyGen
```

### 2.3 TTL & Invalidation Rules

- **Default TTL:** 300 seconds (`cacheTtl: 300.0` in `config.yaml`)
- **Mobility hash:** Computed from drone trajectory vector; any mismatch triggers STALE regardless of TTL
- **Velocity context:** At 25 m/s (5G), cell radius 200 m → max dwell ≈ 8 s. At 120 m/s (6G THz), T_c = 17.86 µs — far shorter than TTL, making physical coherence the binding constraint.

### 2.4 Handover Manager State Machine (`pqc-handover-manager.cc`)

**Pre-computation pool (target size = 3 pairs):**
```
System boot -> PrecomputeHandoverKeys()
  -> while pool.size() < 3: pool.push(HybridKemCombiner::GenerateKeyPair())
```

**RapidRekey() execution path:**
```
Handover Trigger
  -> pool NOT empty -> pop pre-computed pair (zero keygen latency)
  -> pool empty     -> GenerateKeyPair() on-the-fly [+~200 us latency spike]
  -> Encapsulate(targetGnb.ecdhPK, targetGnb.kyberPK) -> hybridResult
  -> DeriveSessionKeys(hybridResult.combinedSecret) -> newKeys (generation++)
  -> Assert: newKeys.combinedSecret != previousKeys.combinedSecret [FS verified]
  -> PdcpLayer.UpdateSessionKeys(newKeys) -> ENCRYPTED mode re-established
  -> Schedule(+100 us): PrecomputeHandoverKeys() [async pool refill]
  -> Traces: HandoverRekeyLatency, HandoverInterruptionTime, ForwardSecrecyVerified
```

### 2.5 Full Handover State Transition Map

```
[UAV IDLE]
  -> (SINR drop / Measurement Report)
  -> [HANDOVER TRIGGERED]
    -> cache HIT:
        [0-RTT RESUMPTION] -> RapidRekey() -> [ENCRYPTED DATA PLANE ACTIVE]
    -> cache MISS / STALE / REVOKED:
        [FULL HANDSHAKE]
          -> GenerateConnectionRequest()  [UE: keygen + ML-DSA sign]
          -> ProcessConnectionRequest()   [gNB: verify + encaps + sign + DeriveKeys]
          -> CompleteKeyExchange()        [UE: verify + decaps + DeriveKeys]
          -> InstallSessionKeys()         [PDCP mode = ENCRYPTED]
          -> PqcKeyCache::Store(ueIndex, combinedSecret, mobilityHash, ttl=300s)
          -> [ENCRYPTED DATA PLANE ACTIVE]
```

---

## Domain 3 — Data-Plane Encryption & Session Management

### 3.1 AES-256-GCM Specification (`aes-gcm-cipher.cc`, `pqc_mec_server.py`)

| Parameter | Value |
|-----------|-------|
| Algorithm | AES-256-GCM (AESGCM) |
| Key | 32 bytes from HKDF output (enc_key) |
| Nonce | 12 bytes |
| Tag | 16 bytes |
| Per-packet overhead | **28 bytes** (NONCE + TAG) |
| Encrypt latency | 1 µs fixed + 1 ns/byte |
| Decrypt latency | 1 µs fixed + 1 ns/byte |

#### Wire Format (exact from `pqc_mec_server.py`)

```
TX: send_nonce(12B) || aesgcm.encrypt(send_nonce, plaintext, aad=None)
RX: recv_nonce = enc_data[:12]
    ciphertext = enc_data[12:]
    pt = aesgcm.decrypt(recv_nonce, ciphertext, aad=None)
```

#### NS-3 Ciphertext Layout (`aes-gcm-cipher.cc`)

```
[nonce:12B][plaintext:nB][simulated_GCM_tag:16B(0xAA)]
GCM auth failure -> ProcessRxPdu returns nullptr (packet dropped)
```

### 3.2 Nonce Generation

- **Real (`pqc_mec_server.py`):** `send_nonce = os.urandom(12)` — fresh OS random per packet
- **NS-3 sim:** `NextNonce()` = `nonceBase[12B] XOR counter` (monotone counter from HKDF-derived base)

### 3.3 Replay Protection (`pqc-key-cache.cc`)

```cpp
bool ValidateNonce(uint32_t ueIndex, uint64_t nonce) {
    if (nonce <= entry.nonceCounter) {
        ++m_replayRejections;
        return false;              // reject replay or duplicate
    }
    entry.nonceCounter = nonce;    // advance high-water mark
    return true;
}
```

**Mechanism:** 64-bit monotone high-water mark (combining frame counter + RRC Transaction ID). **No sliding window** — strict forward-only; out-of-order packets are discarded.

### 3.4 Session Key Rotation

- **Trigger:** Cell-tower handover event only (via `RapidRekey()`)
- **Counter:** `keyGeneration++` per handover
- **FS check:** `newKeys.combinedSecret != previousKeys.combinedSecret`
- **No packet-count or time-based rolling implemented** in current codebase

### 3.5 Application Traffic Rates (`pqc-drone-app.cc`)

| Type | Size | Rate |
|------|------|------|
| Telemetry | 512 B | 50 Hz (20 ms interval) |
| Navigation update | 64 B | 5 Hz (200 ms interval) |
| Swarm command | 128 B | ~0.5 Hz (2 s interval) |

---

## Domain 4 — Transport Protocol & Channel Realism

### 4.1 Transport Layer

**UDP** is the transport protocol (`ns3::UdpSocketFactory` in `pqc-drone-app.cc`). Chosen explicitly to avoid TCP head-of-line (HoL) blocking. TCP RTO cascades are modeled and quantified as a known weakness. A **Raptor Fountain Coder** (`raptor-fountain-coder.cc`, 10% overhead) is implemented as a mitigation but is not in the main simulation loop.

### 4.2 Gilbert-Elliott THz Channel Model (`thz-gilbert-elliott-channel.cc`)

**Two-state Markov model** calibrated to 140 GHz / 120 m/s:

#### Channel Coherence Time

$$T_c = \frac{c}{f_c \cdot v} = \frac{3 \times 10^8}{140 \times 10^9 \times 120} = \mathbf{17.86\ \mu s}$$

#### State Parameters (`config.yaml`)

| Parameter | Value | Meaning |
|-----------|-------|---------|
| p_GB | 0.05 | Good → Bad transition probability per slot |
| p_BG | 0.30 | Bad → Good transition probability per slot |
| ε_G | 0.0001 | Fragment error rate in GOOD state |
| ε_B | 0.30 | Fragment error rate in BAD state |

#### Steady-State Probabilities

$$\pi_G = \frac{p_{BG}}{p_{GB} + p_{BG}} = \frac{0.30}{0.35} = 0.857 \qquad \pi_B = 0.143$$

#### PDR for n-Fragment Payload

$$\text{PDR}(n) = \pi_G \cdot (1 - \varepsilon_G)^n + \pi_B \cdot (1 - \varepsilon_B)^n$$

| n (frags) | p_GB=0.01 | p_GB=0.05 | p_GB=0.10 |
|-----------|-----------|-----------|-----------|
| 1 (ECC) | 0.99997 | 0.99983 | 0.99967 |
| 2 (ML-KEM-768) | 0.99994 | 0.99966 | 0.99933 |
| 3 (ML-KEM-1024) | 0.99991 | 0.99950 | 0.99900 |

#### IP Fragmentation Count (`thz-gilbert-elliott-channel.cc`)

```cpp
// MTU=1400B, IPv6=40B, UDP=8B
firstFragPayload      = 1400 - 40 - 8 = 1352 B
n_frag = 1 + ceil((payloadBytes - 1352) / 1352)
```

#### TCP RTO Cascade Probability

$$P(\text{cascade} \geq F) = (1 - \text{PDR}(n))^F$$

At F=3, RTO_0=200 ms: T_cascade ≥ 1400 ms — exceeds T_c by **~78,600×**

### 4.3 Path Loss & Channel Capacity (`access_revised.tex`)

$$\text{PL} = 28.0 + 22\log_{10}(d) + 20\log_{10}(f_c)$$

$$\text{SINR} = \frac{P_{rx}}{I + N_0} \qquad C = B \log_2(1+\text{SINR}) \qquad P_{\text{deliver}} = (1-P_b)^{8L}$$

LOS path loss exponent: **2.2**. NLoS (3GPP TR 36.777 urban): +10–20 dB penalty.

### 4.4 MAC Serialization Delay (`monte_carlo_mac_serialization.py`)

$$T_{\text{slot}}(\mu) = \frac{1000\ \mu\text{s}}{2^\mu} \qquad \tau_{\text{serial}} = \left\lceil \frac{B}{\text{TBS}(\mu)} \right\rceil \cdot T_{\text{slot}}(\mu)$$

| μ | SCS (kHz) | T_slot | TBS |
|---|-----------|--------|-----|
| 3 | 120 | 125 µs | 12,000 B |
| 4 | 240 | 62.5 µs | 6,000 B |
| 5 | 480 | 31.25 µs | 3,000 B |

TBS scheduling jitter: ±5% uniform.

### 4.5 Target Performance Bounds

| Metric | Target |
|--------|--------|
| E2E latency (URLLC P99) | < 10 ms |
| PDR (6G URLLC) | ≥ 0.99999 |
| Handoff latency — cached HIT | Gamma(3,1) + 0.5 ms |
| Handoff latency — cache MISS | Gamma(4,2) + 4.0 ms |
| ECC handshake (N=10 baseline) | 300–5,000 µs |

---

## Domain 5 — Fail-Safe State Machine & Safety Logic

### 5.1 Authentication Failure (`pqc-rrc-extension.cc`)

```
UE -> gNB: RRC Request [kyber_pk || ecdh_pk || ml_dsa_sig || ml_dsa_cert]
  gNB: ML-DSA.Verify(sig, msg, cert)
    -> FAIL: return PqcRrcIePayload::Rejected()
             m_handshakeComplete = false
             PDCP stays in TRANSPARENT mode (no encryption)
             -> UAV: no keys -> loiter / return-to-home
    -> PASS: Encaps + sign response
      UE: ML-DSA.Verify(gNB response sig)
        -> FAIL: InstallSessionKeys NOT called -> autonomous safe mode
        -> PASS: CompleteKeyExchange() -> ENCRYPTED
```

### 5.2 GCM Tag Failure (`pqc-pdcp-layer.cc`)

```
ProcessRxPdu(packet)
  -> AesGcmCipher::Decrypt() -> authenticated=false
  -> LOG: "PQC-PDCP RX: GCM authentication FAILED!"
  -> return nullptr (packet dropped)
  -> UDP: no retransmit -> telemetry gap detected by application
```

### 5.3 Cache Revocation (`pqc-key-cache.cc`)

```
AMF -> PqcKeyCache::Revoke(ueIndex): entry.revoked=true
Next Lookup -> REVOKED -> m_revokedReuseAttempts++
PqcKeyCache::Purge(ueIndex): entry erased
-> Force full AKA re-authentication
```

### 5.4 Key Pool Exhaustion (`pqc-handover-manager.cc`)

```
m_precomputedKeys.empty()
-> NS_LOG_WARN: "Key pool EMPTY — generating on-the-fly"
-> HybridKemCombiner::GenerateKeyPair() [+~200 us]
-> Simulator::Schedule(MicroSeconds(100), PrecomputeHandoverKeys)
```

### 5.5 Complete Fail-Safe Transition Table

```
[Normal Flight]
  -> SINR drop              -> [Handover Initiated]
    -> cache HIT            -> [0-RTT Rekey]     -> [Secure Flight]
    -> MISS/STALE/REVOKED   -> [Full Handshake Attempt]
      -> ML-DSA FAIL        -> [Connection Rejected] -> [Autonomous Safe Mode]
      -> Timeout            -> [Connection Timeout]  -> [Loiter / RTH]
      -> ML-DSA PASS + KEM  -> [Keys Installed]      -> [Secure Flight]

[Secure Flight]
  -> GCM tag FAIL           -> [Packet Dropped] -> repeated -> [Link Degraded]
  -> Nonce replay           -> [Packet Rejected]  m_replayRejections++
  -> TTL expiry             -> [stale_key_events++] -> [Full Handshake Attempt]
  -> Mobility hash mismatch -> [Key Invalidated]    -> [Full Handshake Attempt]
  -> AMF revocation         -> [REVOKED] -> Purge -> [Full AKA]
  -> Pool exhaustion        -> [Latency Spike] -> async refill
  -> TCP RTO cascade (F>=3) -> T_cascade >= 1400ms -> [Link Lost] -> [RTH / Loiter]
```

---

## Domain 6 — SWaP-C Power Profiling & Peripheral Bus Constraints

### 6.1 Energy Model Formula (`pqc-energy-model.cc`, `docs/technical_changes_report.md`)

$$E_{\text{total}} = P_{\text{cpu}} \cdot T_{\text{proc}} + P_{\text{tx}} \cdot T_{\text{tx}} + P_{\text{mem}} \cdot T_{\text{mem}} + P_{\text{idle}} \cdot T_{\text{idle}}$$

```cpp
e.cryptoComputeMj = profile.cpuPowerW  * cryptoSec * 1000   // W*s*1000 = mJ
e.txMj            = 0.52               * txSec      * 1000
e.rxMj            = 0.16               * rxSec      * 1000
e.idleMj          = profile.idlePowerW * idleSec    * 1000
e.memoryMj        = bytes * 8 * 0.5e-12 * memFactor * 1e9   // ~0.5 pJ/bit
```

### 6.2 Hardware Profiles

| Profile | Crypto Scale | CPU Active (W) | Idle (W) | Max Parallel Ops |
|---------|-------------|---------------|---------|----------------|
| Cortex-A55 (default) | 1.8× | 2.0 | 0.5 | 1 |
| Pixhawk (STM32H7) | 3.5× | 1.5 | 0.3 | 1 |
| **Jetson Nano** (sim target) | 0.6× | 5.0 | 1.0 | 2 |
| Jetson Orin | 0.25× | 15.0 | 2.0 | 4 |
| Edge Server (MEC) | 0.1× | 45.0 | 8.0 | 8 |

**Fixed radio power:** TX = 0.52 W, RX = 0.16 W, mem dynamic = ~0.3 W (large MLKEM poly matrix).

**Battery model:** `BATTERY_WH = 74.0 Wh` → `batteryMj = 74.0 × 3.6e6 mJ`. Battery life projected as `batteryMj / (totalMj_per_second × 60)` (modeled, not measured).

### 6.3 OS / Bus / Jitter Constraints

| Parameter | Value | Source |
|-----------|-------|--------|
| Clock jitter | Log-normal σ=8% | `kyber6g_simulation_engine.py` |
| Memory latency jitter | Uniform [0, 5 µs] | `MEMORY_LATENCY_US = 2.5` (2× range) |
| ML-DSA Sign latency | 500 µs | `ml-dsa-signer.cc` (Cortex-A72 simulated) |
| ML-DSA Verify latency | 200 µs | `ml-dsa-signer.cc` |
| Directional tag overhead | 0.5 µs + 32 B | `docs/mathematical_proofs.md` §4.6 |
| MIMO (gNB) | 8×8 = 64 elements | `docs/technical_changes_report.md` |
| MIMO (UAV) | 4 elements | `docs/technical_changes_report.md` |
| Carrier (5G) | 3.5 GHz, 20 MHz, 30 kHz SCS | `docs/technical_changes_report.md` |
| Carrier (6G) | 140 GHz | `config.yaml` |
| FDD workaround | FDD replaces TDD due to NS-3 TA bug at 120 m/s | `known_limitations.txt` |

---

## Domain 7 — Formal Rule Mapping (All Protocol Sequences)

### 7.1 X-Wing Hybrid Handshake (8 Phases)

```
Phase 0: CSIDH-512 MAC CE Bypass (L2 pre-auth)
  UAV -> gNB: CSIDH-512 MAC Control Element [64-byte key, fragmentation-free]
  -> Low-latency L2 link key without full RRC overhead

Phase 1: UE Key Generation
  (ek_X25519_sk, ek_X25519_pk[32B]) <- X25519.KeyGen()
  (ek_MLKEM_sk, ek_MLKEM_pk[1568B]) <- ML-KEM-1024.KeyGen()
  ml_dsa_sig <- ML-DSA.Sign(sk_UE, ek_MLKEM_pk || ek_X25519_pk)

Phase 2: UAV -> gNB: RRC Connection Request (~8,679 bytes)
  [ek_X25519_pk(32B) || ek_MLKEM_pk(1568B) || ml_dsa_sig || ml_dsa_cert]

Phase 3: gNB Authentication
  ML-DSA.Verify(ek_MLKEM_pk || ek_X25519_pk, ml_dsa_sig, ml_dsa_cert)
    -> FAIL -> Reject() -> [HANDSHAKE FAILED]
    -> PASS -> continue

Phase 4: gNB Parallel Encapsulation
  Core 0: (pk_gNB_X25519[32B], s_ecdh[32B]) <- X25519.KeyGen() + DH(ek_X25519_pk)
  Core 1: (ct_kyber[1568B], s_kyber[32B])   <- ML-KEM-1024.Encaps(ek_MLKEM_pk)
  T_parallel = max(T_X25519, T_MLKEM) * 1.1

Phase 5: gNB Key Fusion
  hkdf_salt[16B] <- os.urandom(16)
  k_final[32B] <- HKDF-SHA256(
    IKM = s_ecdh[32B] || s_kyber[32B],
    salt = hkdf_salt,
    info = "Kyber6G-3GPP-Rel17-MasterKey"
  )
  enc_key[32B]    = k_final XOR 0x01 (per-byte)
  int_key[32B]    = k_final XOR 0x02
  nonce_base[12B] = k_final XOR 0x03
  ml_dsa_resp_sig <- ML-DSA.Sign(sk_gNB, ct_kyber || pk_gNB_X25519)

Phase 6: gNB -> UAV: RRC Connection Setup (~6,227 bytes)
  [pk_gNB_X25519(32B) || ct_kyber(1568B) || hkdf_salt(16B) || ml_dsa_resp_sig]

Phase 7: UE Verification & Decapsulation
  ML-DSA.Verify(ct_kyber || pk_gNB_X25519, ml_dsa_resp_sig, gNB_cert)
    -> FAIL -> Abort -> [HANDSHAKE FAILED]
  s_ecdh_UE[32B] <- X25519.DH(ek_X25519_sk, pk_gNB_X25519)
  s_kyber_UE[32B] <- ML-KEM-1024.Decaps(ek_MLKEM_sk, ct_kyber)
  k_final_UE[32B] <- HKDF-SHA256(s_ecdh_UE||s_kyber_UE, hkdf_salt, "Kyber6G-3GPP-Rel17-MasterKey")
  InstallSessionKeys(enc_key, int_key, nonce_base) -> PDCP = ENCRYPTED

Phase 8: Cache Storage
  PqcKeyCache.Store(ueIndex, k_final, mobilityHash, ttl=300s)
  -> [HANDSHAKE COMPLETE — SECURE DATA PLANE ACTIVE]
```

### 7.2 0-RTT Cached Handover

```
[Handover Trigger]
  PqcHandoverManager.RapidRekey(ctx)
    -> pool NOT empty -> pop HybridKeyPair (T_keygen = 0 us)
    -> pool empty     -> GenerateKeyPair() [+~200 us]
  Encapsulate(targetGnb.ecdhPK, targetGnb.kyberPK) -> combinedSecret_new
  DeriveSessionKeys(combinedSecret_new) -> newKeys (gen = oldGen+1)
  Assert: newKeys.combinedSecret != oldKeys.combinedSecret -> Forward Secrecy VERIFIED
  PdcpLayer.UpdateSessionKeys(newKeys) -> nonce_counter = 0 (reset)
  Schedule(+100 us): PrecomputeHandoverKeys() [async pool refill]
  -> [SECURE FLIGHT RESUMED — 0-RTT]
```

### 7.3 Data-Plane Packet Lifecycle

```
[TX: UAV Telemetry]
  App.SendTelemetry() -> Packet(512B)
  PdcpLayer.ProcessTxSdu(pkt)
    -> nonce <- NextNonce() [12B monotone]
    -> enc <- AES-256-GCM.Encrypt(plaintext[512B], enc_key, nonce)
    -> wire: nonce(12B) || ciphertext(512B) || tag(16B) = 540B
  UDP -> gNB

[RX: gNB Decryption]
  UDP recv (540B)
  recv_nonce <- enc_data[:12]
  ciphertext <- enc_data[12:]
  ValidateNonce(ueIndex, recv_nonce)
    -> nonce <= counter -> REPLAY REJECTED (m_replayRejections++)
    -> nonce > counter  -> advance counter, proceed
  pt <- AES-256-GCM.Decrypt(ciphertext, enc_key, recv_nonce)
    -> GCM tag FAIL -> return nullptr (packet dropped)
    -> GCM tag PASS -> plaintext(512B) -> application
```

### 7.4 EMULSION SIB Broadcast Authentication

```
[Epoch Init]
  k_L[256B] <- random seed
  chain: k_i = SHA256^(L-i)(k_L) for i=0..L
  sigma_anchor <- MAYO.Sign(sk_gNB, k_0 || epoch_id)
  gNB -> ALL_UAVs: sigma_anchor || MAYO.pk

[Per-SIB TX]
  tau_i = HMAC-SHA256(k_i, SIB_i)
  gNB -> UAVs: SIB_i || tau_i      [k_i NOT YET disclosed]
  (after delay Delta_SFN):
  gNB -> UAVs: disclose k_{i-Delta}

[UAV Verification]
  SIB_j || tau_j received
  -> wait for k_j disclosure
  -> verify HMAC-SHA256(k_j, SIB_j) == tau_j
    -> FAIL -> SIB discarded (forged)
    -> PASS -> SIB accepted
```

### 7.5 MORNeS Reflection Attack Defence

```
[Vulnerable original]
  A -> attacker(B): {N_A, ID_A, ID_B}_{K_AS}
  attacker reflects M1 back to A -> A may accept

[Fixed with directional tags]
  TAG_{A->B} = SHA256("REQ"  || ID_A || ID_B)
  TAG_{B->A} = SHA256("RESP" || ID_B || ID_A)
  M1: A -> B: {TAG_{A->B}, N_A, ID_A, ID_B}_{K_AS}
  M2: B -> A: {TAG_{B->A}, N_B, ID_B, ID_A, N_A}_{K_BS}
  A checks: received tag == TAG_{B->A}
    -> TAG_{A->B} != TAG_{B->A} -> REJECT (reflection defeated)
  Overhead: +32 bytes/message, +0.5 us SHA-256 per message
```

### 7.6 All Fail-Safe Transitions

```
ML-DSA Auth Failure
  -> ML-DSA.Verify == FAIL
  -> Connection Rejected
  -> PDCP = TRANSPARENT (no encryption)
  -> UAV: no GCS link -> Loiter / Return-to-Home

GCM Tag Failure
  -> authenticated = false
  -> ProcessRxPdu -> nullptr (drop)
  -> repeated failures -> Link Degraded -> handover attempt

Nonce Replay
  -> nonce <= nonceCounter
  -> m_replayRejections++
  -> packet silently discarded

TTL Expiry
  -> age > entry.ttl
  -> STALE -> m_staleKeyEvents++
  -> Full X-Wing Handshake Required

Mobility Hash Mismatch
  -> mobilityHash != entry.mobilityHash
  -> STALE -> immediate key invalidation
  -> Full Handshake Required

AMF Revocation
  -> Revoke(ueIndex) -> entry.revoked = true
  -> REVOKED -> m_revokedReuseAttempts++
  -> Purge(ueIndex)
  -> Full AKA Re-authentication Required

Key Pool Exhaustion
  -> pool.empty() == true
  -> NS_LOG_WARN fired
  -> on-the-fly GenerateKeyPair() [+~200 us spike]
  -> async refill scheduled at +100 us

TCP RTO Cascade
  -> F >= 3 consecutive fragment losses
  -> T_cascade >= sum(RTO_0 * 2^k, k=0..F-1) = 200+400+800 = 1400 ms
  -> 1400 ms >> T_c (17.86 us) by 78,600x
  -> UAV exits MIMO beamforming envelope
  -> Link Lost -> Emergency Autonomous RTH / Loiter
```

---

## Appendix A — Master Parameter Reference

| Parameter | Value | Source |
|-----------|-------|--------|
| ML-KEM-1024 PK | 1,568 B | FIPS 203 |
| ML-KEM-1024 CT | 1,568 B | FIPS 203 |
| ML-KEM-1024 SS | 32 B | FIPS 203 |
| X25519 PK/SK/SS | 32 B each | RFC 7748 |
| ML-DSA-87 PK | 2,592 B | FIPS 204 |
| ML-DSA-87 SK | 4,896 B | FIPS 204 |
| ML-DSA-87 Sig | 4,595 B | FIPS 204 |
| AES-256-GCM Nonce | 12 B | NIST SP 800-38D |
| AES-256-GCM Tag | 16 B | NIST SP 800-38D |
| HKDF Salt | 16 B OS-random | `pqc_mec_server.py` |
| HKDF Info String | `"Kyber6G-3GPP-Rel17-MasterKey"` | `pqc_mec_server.py` |
| Cache TTL | 300 s | `config.yaml` |
| Key pool size | 3 pairs | `pqc-handover-manager.cc` |
| Monte Carlo N | 50,000 trials | `kyber6g_simulation_engine.py` |
| NS-3 runs | 30 per config | `config.yaml` |
| UAV speed (6G) | 120 m/s | `config.yaml` |
| Carrier (6G) | 140 GHz | `config.yaml` |
| Coherence time T_c | 17.86 µs | T_c = c/(f_c*v) |
| p_GB | 0.05 | `config.yaml` |
| p_BG | 0.30 | `config.yaml` |
| ε_G | 0.0001 | `config.yaml` |
| ε_B | 0.30 | `config.yaml` |
| Swarm sizes | 10,28,56,100,140,200 | `config.yaml` |
| Quantum security | 230-bit (NIST Level 5) | architecture docs |
| URLLC deadline | 10 ms P99 | `swarm_pqc_simulation.py` |
| Battery | 74 Wh | `config.yaml` |
| TX power | 0.52 W | `pqc-energy-model.cc` |
| RX power | 0.16 W | `pqc-energy-model.cc` |

---

## Appendix B — Known Gaps & Explicit Limitations

| # | Gap | Detail |
|---|-----|--------|
| 1 | **FDD workaround** | TDD correct for 140 GHz; FDD used due to NS-3 5g-lena v3.3 TA bug at 120 m/s |
| 2 | **Simulated crypto** | No `liboqs`; wire sizes = exact FIPS, but ops are deterministic FNV hash simulations |
| 3 | **No sliding window** | Strict monotone nonce; out-of-order packets dropped |
| 4 | **No time/count-based key rotation** | Rotation is handover-event-only |
| 5 | **TCP HoL unresolved** | Raptor codes exist in codebase but not in main sim loop |
| 6 | **SWaP-C is modeled** | Power values from datasheets, not physical measurements |
| 7 | **Fixed backhaul** | `edgeBackhaulMs = 2.0 ms`; multi-hop 6G core not modeled |
