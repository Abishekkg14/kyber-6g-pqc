# Military Drone Swarm: Comprehensive Threat Model Assessment

## 1. System Context & Adversary Capabilities
The system operates a swarm of military drones coordinating over a 5G/6G dense-urban network. The base stations (gNBs) function as active cryptographic session endpoints: they receive ML-KEM public keys, perform encapsulation, derive session keys via HKDF, and decrypt AES-256-GCM C2 traffic at the MEC edge. The gNodeB/MEC is a trusted session terminator in this architecture, not a transparent forwarding relay. 
The expected capabilities of adversaries include:
- **Passive Interception:** Persistent logging of encrypted radio frequency (RF) traffic, including the "Store Now, Decrypt Later" strategy utilizing quantum computers (Shor's Algorithm).
- **Active Manipulation:** Injection of unauthorized command updates, replaying old navigation packets, and inducing Denial of Service (DoS) congestion.
- **Node Compromise:** A drone physically captured by hostile forces.

## 2. Threat Analysis & Mitigations

### 2.1 Eavesdropping & The "Store Now, Decrypt Later" Quantum Threat
**Threat:** Adversaries capture the X25519-ECDH Diffie-Hellman handshake over the untrusted gNBs. Years later, a stable quantum computer runs Shor's algorithm, solving the Elliptic Curve Discrete Logarithm Problem (ECDLP) to recover the AES symmetric key, decrypting mission telemetry retroactively.
**Mitigation:** The system mitigates this by enforcing a Hybrid Key Encapsulation Mechanism combining X25519 ECDH with ML-KEM-1024 (FIPS 203). ML-KEM bases its security on the computational hardness of the Module Learning With Errors (MLWE) lattice problem. ML-KEM-1024 provides NIST Level 5 post-quantum security (256-bit classical security equivalent per NIST classification). While the quantum cost to break ECC drops catastrophically under Shor's algorithm, ML-KEM maintains resistance against known quantum sieving and algebraic attacks on lattice problems.

### 2.2 Replay & Active Traffic Manipulation
**Threat:** Adversaries capture legitimate `NAVIGATION_UPDATE` or `COMMAND` packets broadcasted by the Commander Drone and rebroadcast them later to scramble the formation flight path.
**Mitigation:** The Application Layer leverages `AES-256-GCM`. The Galois/Counter Mode provides authenticated encryption. Any bit-flip alteration in the ciphertext invalidates the 16-Byte MAC Tag, resulting in rejection at the application layer. Replay attacks are neutered via the monotonically increasing 12-byte Nonce incorporated into the Initialization Vector.

### 2.3 Denial of Service (DoS) & Congestion-Induced Delays
**Threat:** The large payload sizes of Kyber KEM Public Keys (~1184 Bytes) can trigger RLC layer segmentation when pushed across high-speed drone mobility pathways, causing MAC layer enqueue wait-times to saturate according to M/M/1 formulations.
**Mitigation:** The `PqcAdaptiveKeyManager` mitigates Key Exhaustion and congestion DOS. When the simulated drones enter high-speed movement (e.g. `> 15.0 m/s`), the Adaptive Manager safely extends the rekeying interval and leverages securely cached previous session keys. This dramatically lowers the control plane overhead, restoring the M/M/1 arrival rate ($\lambda$) back below the channel saturation point ($\mu$).

### 2.4 Node Compromise
**Threat:** A follower drone crashes and is captured. The adversary extracts the current AES symmetric key from memory.
**Mitigation:** The framework employs periodic key refresh. Fresh full handshakes (with new ML-KEM-1024 + X25519 ephemeral key generation) provide genuine forward secrecy — a captured key does not compromise past sessions. However, the cached rekey (1-RTT) path uses HKDF key ratcheting from the cached master secret, which provides key evolution but NOT independent forward secrecy. Deployment policy should trigger periodic full re-handshakes (e.g., every `cacheTtl` seconds or on mobility cell change) to maintain forward secrecy guarantees.

## 3. Summary of Security Limits
While Post-Quantum Cryptography successfully shores up confidentiality against future quantum risks, simulations indicate a stark performance trade-off in dense scenarios. Handshake delays constrain highly-mobile latency-sensitive steering. Adaptive caching mechanisms are strictly required to ensure the drone swarm can sustain formation flying integrity without succumbing to crypto-induced starvation.
