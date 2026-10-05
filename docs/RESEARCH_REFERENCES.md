# Research references for the multimodal secure HITL link

This document records how the local research papers informed the `kyber6g/` implementation: which ideas were adopted, where they live in the code, and why the rest were not used.

**Sources reviewed**
- `video encryption papers/`: 11 PDFs (V001–V011).
- `CRYPTO PROJECT RELATED PAPERS/`: 139 PDFs, of which 132 are unique (C012–C150). Seven files are duplicate copies: 038=037, 041=040, 047=046, 057=056, 059=058, 116=115, 131=130. 076 and 077 also have identical content.

**Reading depth** is stated per paper, because reading 150 papers in full was not proportionate for papers outside the build's scope:
- **Full**: the whole text was read.
- **Targeted**: the abstract and conclusion were read, plus the method, threat-model, results and security sections that bear on this build.
- **Screened**: only the abstract and conclusion were read, and the paper was judged out of scope for the HITL media link.

Text was extracted with `pdftotext`. Figures and tables that pdftotext could not extract were not reviewed.

**Standards used alongside the papers:** FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA, considered but not used), SP 800-38D (GCM), RFC 5869 (HKDF), RFC 8446 (TLS 1.3 record nonces), RFC 6479 (anti-replay window), and the Picamera2 / libcamera / gpsd documentation.

---

## 1. Video-encryption papers

| ID | Paper | Depth | Relevant idea | Used? | Where in code | Reason |
|---|---|---|---|---|---|---|
| V001 | Thejaswini P. et al., *A Hardware Efficient Video Compression and Encryption Pipeline for Edge Devices*, IEEE ESL 2026 | Full | Compress first, then encrypt; report CPU use alongside latency. The paper's own cipher, pAES, is an AES variant in ECB mode with MixColumns replaced by rotate/XOR and only empirical security evidence. | **Ordering adopted. pAES rejected.** | `camera/camera.py` (hardware H.264 first), `uav/main.py::on_live_frame` (encrypts the encoded bitstream); CPU reported in the status stream | pAES is non-standard, ECB leaks structure, it has no integrity, and the authors state there is no formal analysis. |
| V002 | Chowdhury, Joshi, Ghorai, Tripathi, *A Novel Image Encryption and Decryption Framework Using Graph Neural Networks*, COMSNETS 2026 | Full | A trained neural network acts as the "cipher". Decryption is lossy (about 33 dB PSNR). | **No** (requirement only) | `transport/blob.py`: the SHA-256 of the decrypted image must equal the original, bit for bit | Lossy, no security proof, and the trained model acts as the key (security through obscurity). |
| V003 | Shenoy, Hemalatha S, Barla, *Adaptive Self-Healing Video Encryption Framework*, ICAECT 2026 | Full | Chunked AES-GCM at rest; a header with magic bytes and a version; per-chunk index; a wrapped key file; XOR-parity "self-healing". | **Partly** | `recording/recorder.py`: `.k6grec` file with `K6GREC01` magic, per-segment AEAD with the segment index and a FINAL flag in the AAD, wrapped content key | PBKDF2 password keys were rejected because keys come from the PQC session and ML-KEM. The parity-FEC idea was evaluated for UDP video and **not implemented**: measured Wi-Fi loss was 0 frames across every hardware run (TEST_REPORT §5). |
| V004 | Hsu, Huang, Yang, Chen, *Real-Time UAV Video Streaming Secured by Physical Layer Key Generation*, INFOCOM 2026 demo | Full | Each frame carries a key-epoch ID; the receiver looks up keys by epoch and drops frames with mismatched keys; a GUI shows end-to-end latency; a Raspberry Pi is the UAV. | **Yes** (epochs, latency display). **No** (PLKG) | `crypto/record.py` (`epoch` in the authenticated header; `RxStream` keeps previous-epoch keys for a grace window), dashboard latency panel | PLKG needs channel-state data from the Wi-Fi radio, which the stock Pi driver does not expose. It also has no peer authentication, so it is open to active man-in-the-middle attacks. |
| V005 | Akilandeswari A., *Hardware Implementation of AES-256 Encryption on FPGA for Real-Time Video Stream Security*, ICOEI 2026 | Full | AES-CTR with a 96-bit nonce and a 32-bit counter. No authentication (GCM is listed as future work). | **Rationale only** | `crypto/record.py` nonce design | There is no FPGA on the Pi. Bare CTR mode is malleable, so we use GCM. |
| V006 | Deng, Wang, Sun, Yang, *Complex-Valued Chaos in Discrete-Time Hopfield NN for Secure Image Encryption*, IEEE TCSVT 2026 | Targeted (abstract, FPGA PRNG, encryption algorithm, start of the security section, conclusion) | Chaotic PRNG on an FPGA; a deterministic image cipher. | **No** | — (all randomness comes from the OS CSPRNG) | Deterministic encryption cannot be IND-CPA secure, there is no integrity, and statistical tests are not a security proof. |
| V007 | Shetty et al., *Image and Video Encryption using DNA Quantum Walk Algorithm*, ICKECS 2026 | Full | A logistic map plus a classically simulated quantum walk plus DNA encoding. | **No** | — | No security analysis. The "quantum" is a classical simulation. An example of the terminology trap these docs avoid. |
| V008 | Li, Wang, Hou, Li, Chen, Feng, *Pixel-Level Video Encryption for Privacy Protection*, IEEE TIFS 2026 | Full | A taxonomy of pre-encoding, encoding-integrated and post-encoding schemes; full-bitstream AES is described as among the most secure. Per-frame keys come from HKDF with context info. Long GOPs hurt recovery. | **Yes** (taxonomy choice, HKDF context, short IDR interval) | Post-encoding full-bitstream AEAD; `crypto/keyschedule.py` labels; `config.py` `iperiod=30` (one IDR per second) | Its pixel cipher is, in the authors' own words, not secure against chosen-plaintext attacks. ABE is not post-quantum and is not needed here. |
| V009 | Poojary, Hegde K, *Real-Time GPU-Accelerated AES for High-Resolution Video using OpenCL*, IC-ICNS 2026 | Full | AES-CTR on raw frames on a GPU; CPU-only manages 2–5 fps; measure the full pipeline, not just the encryption kernel. | **Methodology only** | TEST_REPORT measures capture → decrypt → decode → display | Raw-frame encryption is too costly on a Pi, and the paper re-encodes ciphertext lossily, which breaks decryption. |
| V010 | Cao et al., *RegionLock: Lightweight Cloud Video Encryption (YOLOv8 + Adaptive Frame Multiplexing)*, IEEE IoT-J 2026 | Full | Chained keystreams across frames, which the paper calls "forward secrecy"; one bit error breaks every later frame. | **Negative lesson** | Every datagram decrypts on its own (`record.py`); rekeying happens only at explicit epoch boundaries | The chaotic cipher has no standard security reduction. Chaining fails on lossy UDP and is not forward secrecy. |
| V011 | Li, Lee, Gupta, Yang, Singh, *Syntax Element Encryption for H.265/HEVC (Chaotic Coefficient Scrambling)*, IEEE TCSVT 2026 | Targeted (method, key schedule, discussion and limitations) | Selective encryption inside the CABAC encoder, keyed per slice so a lost slice does not desynchronise decryption. | **Principle only** (the unit of crypto synchronisation is the transport unit) | `record.py` (epoch and sequence number in every packet) | Needs changes inside the encoder, which is impossible with the Pi's fixed hardware H.264 encoder. Selective encryption leaks structure. Its key update is an ad hoc XOR of a hash with the key. |

**Design decisions taken from the video papers**
1. Encode with the Pi's hardware H.264 first, then encrypt the whole encoded stream with a standard AEAD (V001, V008, V009).
2. Every datagram is independently decryptable. The authenticated header carries the version, stream, session, key epoch and sequence number (V004, V010, V011).
3. Epoch-indexed key rotation, with the previous epoch's key kept for a grace window (V004).
4. One IDR keyframe per second, so the receiver recovers quickly after loss or a rekey (V008).
5. Segmented, authenticated at-rest recording format (V003).
6. All chaos, DNA, GNN, pixel-domain, selective and custom ciphers rejected (V001, V002, V006, V007, V008, V010, V011).

---

## 2. Crypto papers: those that shaped the design

| ID | Paper | Depth | Relevant idea | Used? | Where in code | Reason / notes |
|---|---|---|---|---|---|---|
| C049 | Angom, Kar, Debbarma, Biswas, *Design and Implementation of a Post-Quantum Double Ratchet Using ML-KEM*, IEEE PKIA 2025 | Full | Replace the DH ratchet with an ML-KEM ratchet that mixes a fresh shared secret into a root key; symmetric chains with deletion of old keys; refresh KEM keypairs. | **Yes** | `crypto/handshake.py` `PQRatchetInitiator` / `pq_ratchet_respond` (fresh ML-KEM-1024 + X25519 mixed with the current master secret); `crypto/keyschedule.py` `EpochChain` (one-way chain, old values wiped) | No per-message asymmetric ratchet (too costly per video packet). The paper has no formal proof; we claim only standard KDF-chain properties. |
| C142 | Sharma, Prakash, Jayachandran, Rao, *User-Space PQ Key Exchange in WireGuard Using ML-KEM-768*, COMSNETS 2026 | Full | Hybrid PQ + X25519 key mixing. The paper claims MITM resistance from IND-CCA2 alone, which is **incorrect**: an unauthenticated KEM is open to MITM. | **Yes** (hybrid). **Lesson** (authentication) | Handshake signs the transcript with ML-DSA-87 and **pins** the peer key from disk (`crypto/identity.py`, `ClientHandshake.process_server_hello`) | This fixes the original server code, which sent its ML-DSA key in the same message and verified against that key. |
| C065 | Lawo et al., *Falcon/Kyber and Dilithium/Kyber Network Stack on Nvidia's DPU*, IEEE Access 2024 | Targeted (implementation, results and the comparison that includes the Raspberry Pi 4) | Dilithium spreads load evenly between client and server; Falcon is server-heavy; keys are combined by XOR. | **Partly** | ML-DSA-87 kept; identities generated once (`tools/provision.py`); Pi timings measured (TEST_REPORT §3) | Falcon/FN-DSA is not a final FIPS standard yet. The XOR combiner has no transcript binding. |
| C092 | *MIKA: A Minimalist Approach to Hybrid Key Exchange* (IKEv2/strongSwan, RFC 9370 comparison) | Targeted (combiner and design sections) | Concatenation or cascade KDF combiners, secure if either component is secure. | **Yes** | `crypto/keyschedule.derive_session`: IKM = ss_ML-KEM ‖ ss_X25519, salt = transcript hash | — |
| C056 | *Efficient Group Key Generation Based on Satellite Cluster State Information for Drone Swarms* | Targeted (threat model and method) | GNSS satellite state used as a shared key source among nearby drones. | **Repurposed** | A coarse GNSS cell from the real L89 fix (`handshake.mobility_cell`, `uav/main.py::mobility`) replaces the hard-coded `mobility_hash = 0x6A7B8C9D`. A change of cell forces a full handshake. | GNSS state is **not** used as key material: it is low-entropy against a nearby adversary and spoofable. The cell is context, not a secret. |
| C114, C023, C128, C068, C124, C021, C138 | 5G-AKA family: PQ lattice 5G-AKA with PFS (Yadav et al.); secure D2D 5G-AKA (Scyther/ROR); 5G AKA Petri-net analysis (Yan et al.); ProVerif 5G-AKA; randomized 5G AKA; ECC multi-factor 5G-AKA; stealth 5G-AKA | Targeted (abstract, attacks and threat model, conclusion) | Perfect forward secrecy needs ephemeral secrets; explicit key confirmation; avoid sequence numbers that can desynchronise; DoS-bounded processing. | **Yes** | Ephemeral X25519 + ML-KEM every handshake; Finished MACs (`handshake.py`); sequence numbers per session and direction; hello rate limit, bounded half-open sessions and MAC-before-state-change for Cached Rekey (`transport/link.py`, `server_process_rekey`) | Formal verification (ProVerif/Tamarin) was **not** done here. Stated as a limitation. |
| C109 | Setyowati, Wadjdi et al., *Hybrid TLS with ML-KEM-768 for PQ-Secure MQTT in Mobile IIoT* | Targeted | Report end-to-end telemetry latency and CPU, not only crypto micro-benchmarks. | **Methodology** | TEST_REPORT telemetry latency and CPU | No MQTT broker: the link is point to point. |
| C060 | *Enhanced Network Security Protocols for the Quantum Era Combining Classical and PQ (and QKD)* | Targeted | Hybrid combiners; crypto-agility. | **Yes** (agility) | `crypto/suites.py` suite registry; the suite ID is bound into the transcript | No quantum channel, so no QKD. |
| C076/C077 | Tsochev, *Hybrid Cryptography: A Framework for Post-Quantum Agility and Resilience* | Screened | Agility; a hybrid stays secure unless both parts are broken. | **Yes** | `crypto/suites.py` | — |
| C084 | *Integration of QRNG with PQC (Entropy-as-a-Service)* | Targeted | PQC keys are only as good as the entropy behind them. | **Yes** (principle) | All keys, nonces, salts and session IDs come from `os.urandom`. The Pi's kernel random generator is seeded by the BCM2711 hardware RNG (`fe104000.rng`, measured). | No external entropy service (it would add a network dependency). |
| C024, C061, C027, C102, C103 | Side channels: power-analysis attack on Kyber hardware; Chebyshev-filter mitigation; masked SHA-3 for ML-KEM; PUF-based Kyber (P2SE-Kyber, PUF-Kyber on ARM) | Targeted | Software Kyber implementations had timing flaws that were later patched; masking and PUFs are hardware countermeasures. | **Partly** | liboqs 0.16.0 (a current release, after the 2024 KyberSlash timing fixes); FIPS 203 implicit rejection, so the code never branches on decapsulation "success" | Masking and PUFs need hardware the Pi doesn't have. Physical power analysis is out of scope and stated as a limitation. |
| C086 | *Kyber-KEM-Ascon: Benchmarking a Lightweight PQ KEM on IoT Devices* | Targeted | Replace Keccak with Ascon inside Kyber. | **No** | — | Not FIPS 203 conformant and not interoperable. Ascon-AEAD is noted as a possible future suite. |
| C107 | *Kyber-DNA and RSA-Base64 in Symmetric Key Exchange* | Screened | DNA encoding on top of Kyber. | **No** | — | DNA encoding adds no security. |
| C042, C069, C075, C126, C079, C127 | Classical hybrid schemes (AES+RSA email, DH+AES chat, DES/AES/RSA hardware, EC signcryption AKE, password 3-party KE, hybrid group keys) | Screened | Classical hybrid encryption. | Background | — | Nothing beyond the design above. |
| C018, C122, C121, C123, C119, C120, C113, C132, C088, C130, C012, C014 | Surveys and other (QKD+PQC hybrids, quantum cryptography overviews, RSA→ML-KEM survey, lattice bibliometrics, Kyber/BIKE for a BP monitor, SM4 in 5G-AKA, 45 nm AES ASIC) | Screened | Background on PQC migration. | Background | — | No QKD hardware; AES is the standard choice; ASIC not applicable. |

---

## 3. Crypto papers not applicable to this build (screened)

Titles are as in the filenames, so some are truncated.

**PQC hardware accelerators (FPGA/ASIC/GPU).** The Pi 4 has no FPGA or GPU crypto path; liboqs software is used.
- C015 — A Hierarchical Parallel Discrete Gaussian Sampler for Lattice-Based Cryptography
- C016 — A High-Performance and Area-Efficient Unified Butterfly Module for ML-KEM Polynomial Computations
- C017 — A High Speed NTT Accelerator for Lattice-Based Cryptography
- C020 — A Low-Latency Polynomial Arithmetic Unit for ML-KEM and ML-DSA Standards
- C029 — An Area-Time Efficient Hardware Architecture for ML-KEM Post-Quantum Cryptography Standard
- C030 — An Efficient and Configurable Hardware Architecture of Polynomial Modular Operation for CRYSTALS-Kyber and Dilithium
- C035 — Area-Efficient Matrix-Vector Polynomial Multiplication Architecture for ML-KEM
- C045 — DARM: A Low-Complexity and Fast Modular Multiplier for Lattice-Based Cryptography
- C066 — Flexible NTT Accelerators for RLWE Lattice-Based Cryptography
- C071 — HI-Kyber: A Novel High-Performance Implementation Scheme of Kyber Based on GPU
- C072 — High-Speed Modular Multiplier for Lattice-Based Cryptosystems
- C074 — High-Speed and Low-Complexity Modular Reduction Design for CRYSTALS-Kyber
- C087 — Kyberator: A High-Efficiency FPGA-Based Multi-Mode CRYSTALS-Kyber Accelerator
- C090 — Lightweight Hardware Implementation of R-LWE Lattice-Based Cryptography
- C106 — Parallel polynomial multiplication optimized scheme for CRYSTALS-KYBER

**QKD / CV-QKD systems.** There is no quantum channel in this system.
- C037 — CV-QKD Design for Network Integration
- C040 — Calibration of Receiver Noise in CV-QKD Systems
- C046 — Demonstration of a Hybrid Free-Space/Fiber CV-QKD System for Bridging the Last Mile
- C055 — Efficient FPGA Implementation of Syndrome-Assisted Layered Belief Propagation Decoding (CV-QKD)
- C058 — End-To-End Post-Processing for CV-QKD with Heterodyne Detection
- C078 — Hybrid DV-CV QKD Outperforming Existing QKD Protocols in Terms of Secret-Key Rate
- C080 — Hybrid QKD Protocol Outperforming Both DV- and CV-QKD Protocols
- C096 — Modelling Weak-Coherent CV-QKD Systems Using a Classical Simulation Framework
- C100 — Optimized-Eight-State CV-QKD Protocol
- C115 — Potential Impact of CV-QKD Integration on Classical WDM Network Capacity

**Channel and burst-error models, coding, packet delivery and routing.** These relate to the existing NS-3 / Monte-Carlo simulation work (e.g. `scripts/monte_carlo_gilbert_elliott.py`), not to the HITL media link.
- C013, C033, C043, C052, C063, C081, C097, C098, C099, C105, C111, C112, C136, C139 — Gilbert-Elliott channel papers (APP decoding, queue-based approximation, capacity, dispersion, Raptor codes for DVB-H, Reed-Solomon soft decoding, interleaving, online learning, power allocation, pairwise error probability, error-forecasting decoding, burst-error codes, equivalent models, slotted ALOHA)
- C031, C032 — Intelligent Traffic Management in V2N using DORA (vs DSR / ZRP)
- C050 — Detecting malicious node in network using packet delivery ratio
- C053 — Duty-Cycle Control Achieving High Packet Delivery Ratio in Heterogeneous WSNs
- C054 — EROP: A Logical 5G Enabled Data Communication with Improved Packet Delivery Ratio
- C062 — Estimating Packet Delivery Ratio for Arbitrary Packet Sizes Over Wireless Links
- C082 — Improving the Packet Delivery Reliability and Privacy Protection in Monitoring WSNs
- C083 — Increasing Packet Delivery Ratio in GPSR Using Buffer Zone Based Greedy Forwarding
- C089 — LEAD-UWSN: Adaptive Hybrid Lion Dolphin Algorithm for Dynamic Packet Delivery
- C101 — Optimizing Packet Delivery in Underwater Wireless Sensor Networks
- C104 — Packet Delivery Ratio Cost in MANETs With Erasure Coding and Packet Replication
- C117 — Prediction of Packet Delivery Ratio Using Lasso Regression
- C144–C148 — "channel fading 1–5" (chaos-shift-keying index modulation, automatic modulation recognition, fluid-antenna outage, composite-fading physical-layer security, CNN channel estimation)

**Terahertz devices and applications.**
- C022, C025, C028, C073, C091, C108, C133, C134, C135, C149, C150

**Markov models and statistics in other domains.**
- C026, C034, C039, C044, C064, C070, C093, C094, C125, C140, C141, C143, C048 (5G-AKA dependability CTMC), C051 (NFC relay-attack detection)

**Other.**
- C085, C095, C137 — 5G/LTE RRC procedures
- C036 — UAV swarm "mosaic warfare" test
- C019 — handwriting keyword spotting ("lattice" here is a recognition lattice, not cryptography)
- C118 — GGH lattice-cryptosystem leakage (a historical scheme)
- C129 — Stabilizing Qubits

---

## 4. Ideas evaluated and not implemented

| Idea | Source | Decision |
|---|---|---|
| XOR-parity FEC for live UDP video | V003 | Not implemented. Measured loss on the target Wi-Fi was 0 frames in every run, with a 1-second IDR interval for recovery. Revisit if field loss justifies the bandwidth overhead (1/K). |
| SLH-DSA (FIPS 205) as the handshake signature | Brief; NIST | Not used. ML-DSA-87 is already a standardised PQ signature. SLH-DSA-256 signatures are about 30–50 KB, which would need dozens of handshake fragments over UDP. The liboqs build on the Pi also exposes 0 SLH-DSA mechanisms (measured). The suite registry can add it later. |
| Per-message KEM ratchet | C049 | Not used for media: about 1.6 KB per message. A periodic PQ ratchet is used instead. |
| Physical-layer key generation | V004 | Not used: needs channel-state data from the radio and has no authentication. |
| GNSS-signal-derived keys | C056 | Not used as key material; used only as rekey context. |

---

## 5. Detection software and models used on the ground station (not from the paper folders)

These are the published models behind the dashboard's object recognition. They were chosen by measurement, not by reputation: the benchmark and its numbers are in `docs/TEST_REPORT.md` §12.4 (`python -m kyber6g.tools.detect_bench`).

| Component | Role | Outcome in this project |
|---|---|---|
| YOLOE (open-vocabulary YOLO, text and visual prompts; YOLOE-11 and YOLOE-26 in `ultralytics` 8.4.171) | Real-time boxes for ~120 everyday classes; **visual prompts (TEACH)** | Text prompts for *pencil* and *screwdriver* score at chance (AUC ≈ 0.5) in 4 sizes/generations. A visual prompt (one box drawn on the live video) finds the pencil in held-out camera frames |
| OWLv2 (Google, open-vocabulary detector trained on grounding data) | The **FINDER** for named objects | Best of the text-prompted models tried: screwdriver 14/14, pencil 11/11 public photos at confidence ≥ 0.35 with one false hit in 25 scenes; but about 5 s per frame on this CPU and weak on thin objects in the dim, IR-lit camera frames |
| Grounding DINO (tiny) | Evaluated as the finder backend | Kept as a selectable backend; too slow on this CPU to benchmark fully (minutes per image batch) |
| YOLO-World v2 (s, l) | Evaluated | No better than YOLOE for these words |
| ByteTrack | Track ids and association between frames | Used through `ultralytics`; the dashboard adds its own label voting and box smoothing |
| MobileCLIP / MobileCLIP2 | Text encoder inside YOLOE | Loaded once, text embeddings cached per weights |
