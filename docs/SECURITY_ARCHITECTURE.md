# Kyber-6G secure HITL link: security architecture

**In one sentence:** post-quantum-secured session establishment using ML-KEM-1024 + X25519 (hybrid) authenticated with ML-DSA-87, followed by symmetric authenticated encryption (AES-256-GCM) of all application data: telemetry, images, video, recordings, audio, status and control. Photos and recordings stored on the UAV are encrypted under a per-file key that is wrapped with ML-KEM-1024 + X25519 and are signed by the UAV with ML-DSA-87. Audio clips are sealed block by block under a key tree grown from a clip key wrapped the same way, and signed once (§9c).

ML-KEM establishes and wraps keying material. ML-DSA authenticates the handshake and the stored files. Neither encrypts the media. **It is not correct to say the video or the audio is "post-quantum encrypted frame by frame."**

Code: `kyber6g/crypto/` (handshake, key schedule, record layer, replay window, identities), `kyber6g/transport/link.py` (session management), `kyber6g/recording/` (stored photos and recordings) and `kyber6g/audio/` (sealed audio). What an attacker can try against all of this, and what happened when it was tried: `CRYPTANALYSIS_REPORT.txt` and, for sealed audio, `AUDIO_CRYPTANALYSIS_REPORT.txt`. Section 12 lists every place where public-key cryptography is used.

## 1. Threat model

- **Network attacker** (Wi-Fi/IP): can read, drop, delay, reorder, replay, modify and inject datagrams, and can store traffic to attack later with a quantum computer ("harvest now, decrypt later").
- **Trusted endpoints:** the UAV (Raspberry Pi) and the GCS (laptop). Compromise of an endpoint is considered only in the forward-secrecy and post-compromise-security analysis (§6).
- **Out of scope:** physical side channels (power or EM analysis), fault injection, a malicious OS on either endpoint, radio-layer jamming, and GNSS spoofing as an attack on navigation. GNSS is used only as rekey context; it is not a security input.

## 2. Algorithms (suite registry: `crypto/suites.py`)

| Role | Suite 0x0001 (default) | Suite 0x0002 |
|---|---|---|
| Key encapsulation (PQ) | ML-KEM-1024 (FIPS 203) | same |
| Key agreement (classical) | X25519 | same |
| Handshake authentication | ML-DSA-87 (FIPS 204) | same |
| KDF | HKDF-SHA256 (RFC 5869) | same |
| AEAD | AES-256-GCM (SP 800-38D) | ChaCha20-Poly1305 |

The suite ID travels in the signed ClientHello and is bound into the transcript hash. A change of suite in transit makes the signature check fail, so a downgrade is detected.

Protocol logic refers only to suite IDs; algorithm names live in the registry. That is the crypto-agility mechanism.

**Why AES-256-GCM on a Pi without AES instructions:** the BCM2711's Cortex-A72 reports `fp asimd evtstrm crc32 cpuid`, with no `aes` or `pmull` (measured). AES-GCM runs in software at 46–59 MB/s, measured on this Pi. 1080p30 at 6 Mbit/s needs about 0.75 MB/s, roughly 1.5% of one core, so AES-256-GCM stays the default. ChaCha20-Poly1305, at 130–306 MB/s measured, is available as suite 0x0002.

## 3. Identities and pinning (`crypto/identity.py`, `tools/provision.py`)

- Each node generates its ML-DSA-87 keypair **once**, on the node itself. Secret keys are stored at mode 0600 in `~/.kyber6g/`, outside the repository.
- Only **public** keys are exchanged (`deploy/deploy_pi.sh`), into `~/.kyber6g/peers/`.
- The pinned keys are the trust anchors, so who may write them matters as much as who may read the secret key. The key directories are 0700; a node refuses to start with a secret key others can read, with a key or key directory owned by another user, or in a shared directory, and it logs the fingerprint of every pinned key it loads (`identity.private_dir`, `read_secret`, `read_pinned`).
- Each side verifies the peer's signature against the **pinned** key read from disk. **Trust-on-first-use is not used.**
  - This fixes the original `pqc_benchmark_server.py` / `pqc_video_streamer.py` design. There, the server's signing key arrived in the same message as the signature and was verified against itself, which gives no authentication.
- The GCS also holds two **recording** keypairs, ML-KEM-1024 and X25519. The UAV stores only the two public keys (§9); a file can be opened only with both secret keys.

Fingerprints (SHA-256 of the public key, first 128 bits) from provisioning:
- UAV: `f6d538825fd56c2bc1f3fedea194813f`
- GCS: `881a37d9048542825e06685423c94746`
- GCS recording key (ek): `a06059fb3cb111af1755692519151de4`

## 4. Full handshake (1.5 RTT) (`crypto/handshake.py`)

```
UAV (client)                                                 GCS (server)
ClientHello = suite | uav_id | nonce_c(32) | mobility_cell(8) | ts_ms
            | X25519 ephemeral pk | ML-KEM-1024 ephemeral ek
            | sig_uav = ML-DSA-87("KYBER6G/hs/client-hello/v1" || all of the above)   ──►
                          verify sig_uav with PINNED UAV key; check freshness (±120 s) and the nonce replay cache
                          (ct, ss_kem) = Encaps(ek);  ss_x = X25519(eph_s, pk_c)
                          TH  = SHA-256("KYBER6G/hs/th/v1" || ClientHello || sig_uav || ServerHello-body)
                          sig_gcs = ML-DSA-87("KYBER6G/hs/server-sig/v1" || TH)
◄──  ServerHello = suite | session_id(8) | nonce_s(32) | gcs_id | X25519 pk | ML-KEM ct | sig_gcs | Finished_S
verify sig_gcs with PINNED GCS key, check suite, decapsulate, check Finished_S
ClientFinished = session_id | Finished_C                                                ──►  check Finished_C
```

- **Key derivation.**
  - IKM = ss_ML-KEM ‖ ss_X25519 (the concatenation combiner; see RESEARCH_REFERENCES C092).
  - PRK = HKDF-Extract(salt = TH, IKM).
  - master, Finished_S key, Finished_C key and resumption secret = HKDF-Expand(PRK or master, label), with labels of the form `KYBER6G/<purpose>/v1|` + suite + session_id.
- **Session binding.** TH covers the protocol labels and version, the suite, both roles' identities, both nonces, both ephemeral public keys, the KEM ciphertext, the mobility cell and the UAV's signature. The GCS signs TH. Every derived key depends on TH through the HKDF salt.
- **Key confirmation.** Finished_S = HMAC(fin_S, SHA-256(TH ‖ sig_gcs)) and Finished_C = HMAC(fin_C, SHA-256(TH2 ‖ Finished_S)). The GCS accepts a session only after Finished_C, or after the first record that authenticates under the new keys (implicit confirmation).
- **Hybrid security.** Session keys stay secret if **either** ML-KEM-1024 **or** X25519 remains secure, given authentic peer keys from ML-DSA-87 and HKDF modelled as a random oracle/PRF.
- **Perfect forward secrecy.** Ephemeral X25519 and ML-KEM keys are generated for every handshake and freed afterwards. Long-term keys are used only for signing, so a later compromise of an ML-DSA secret key does not reveal past session keys.
- **DoS bounds** (revised in the review of October 2026, `SECURITY_AUDIT.md` findings 3 to 5).
  - Nothing is limited per source address: the source of a UDP datagram can be forged, so such a limit locks out the genuine UAV instead of the forger.
  - The GCS refuses a ClientHello with an unknown UAV identity, a nonce it has already accepted, or a time stamp outside ±120 s *before* it verifies the signature. A replayed hello, the only kind an outsider can send with a valid signature, therefore costs nothing.
  - The one expensive step an outsider can trigger is a signature verification that fails. Those draw on one global ration; when it is empty, hellos are dropped unverified until it refills. A genuine hello is never rationed. The ration is sized when the ground station starts, from the cost of a check measured on that machine: a quarter of one core (`GcsLink._verify_ration`; measured: 3,274 failed checks per second on the laptop, 561 on a Raspberry Pi 4B). A fixed 50 per second, as before, was exhausted by a modest flood and then kept the genuine UAV out as well (`SECURITY_AUDIT.md`, finding 20; measured flood behaviour: `CRYPTANALYSIS_REPORT.txt` §4.12).
  - The signature is checked before encapsulation; only an authenticated hello creates a half-open session (at most 64, each expires after 10 s).
  - The GCS caches its answer to an identical retransmitted ClientHello (10 s) and to a repeated rekey request (5 s) and sends it again instead of recomputing.
  - Fragments of handshake messages cannot be authenticated before the message is complete. The reassembly table (128 messages) drops its oldest entry when full and gives one source address at most four entries.
  - The UAV accepts handshake datagrams from the configured ground-station address only, ignores an answer that does not verify (the attempt keeps waiting for the genuine one), and never acts on the unauthenticated ERROR message.
- **A change of position cell** (§9b) needs a full handshake, because a session belongs to the cell it was made in. That handshake is made in place: the running session carries the traffic until the new one is installed, and if the handshake fails the running session goes on and it is tried again later (`UavLink._mobility_handshake`). Before October 2026 the link left the UP state for it and nothing was sent meanwhile (`SECURITY_AUDIT.md`, finding 19).
- **Measured** (TEST_REPORT §15.2, 150 runs, live video running): median 23.2 ms at the UAV over Wi-Fi, 95 % within 30.8 ms. Timed inside the running programs, the UAV spends 8.2 ms of that (building the hello 3.1 ms, verifying and deriving 3.2 ms, installing the session 1.7 ms) and the ground station 1.9 ms; the remaining 13.2 ms are the link and waiting. The two cryptographic steps of the UAV take 2.3 ms alone in a benchmark loop: on a Pi that is encoding video at the same time they are 2.8 times slower. (First round, four runs: 28.9–49.3 ms.)

## 5. Record layer: nonces, AAD, replay (`crypto/record.py`, `crypto/replay.py`)

```
ver(1) | ptype=0x10(1) | stream(1) | ext_len(1) | session_id(8) | epoch(4) | seq(8) | ext | AEAD ciphertext ‖ tag(16)
```

- **AAD** is every byte before the ciphertext: version, stream, session, epoch, sequence number, plus stream-specific metadata in `ext` (video frame ID, chunk index and count, keyframe flag; blob ID and chunk index; status message number). None of it can be changed without the tag failing.
- **Nonce** = `0x00000000 ‖ seq(8)`.
  - Keys are distinct per (session, stream, direction, epoch).
  - The sequence number is strictly increasing per (session, stream, direction) and never resets within a session.
  - So a (key, nonce) pair is **never reused**.
  - The nonce is derived from the authenticated sequence number, as in TLS 1.3 and WireGuard, rather than sent separately.
  - Retransmitted image or recording chunks are resealed with a fresh sequence number.
  - Exactly one `Session` object exists per set of secrets. Two objects for the same secrets would both start at seq 0 and reuse nonces. This was found and avoided during development (`transport/link.py::_confirm`).
  - Several threads send on one stream (commands, their answers, pings, transfer control). "Rotate the epoch if due, take the next sequence number, encrypt" therefore runs under one lock per stream; without it two threads could take the same number (`SECURITY_AUDIT.md` finding 1). A stream stops sealing before its 64-bit sequence number could wrap.
- **Replay window:** a 2048-entry sliding bitmap per (session, stream, direction), RFC 6479 style. It rejects duplicates and anything older than the window ("stale"). It is updated **only after** the AEAD tag verifies, so forged packets cannot advance it.
- **Reordering vs replay:** packets reordered within the window are accepted. Video reassembly and reordering happen afterwards, in a separate 150 ms jitter buffer (`ground/video_sink.py`).
- **Stale epochs:** a key for an epoch older than the current one is kept only for a 3 s grace period. An epoch more than 8 ahead of the last *authenticated* epoch is refused, so a forged header cannot push the receiver's one-way chain forward.
- **Rejections are counted, never silently accepted:** `auth-fail`, `duplicate`, `stale`, `stale-epoch`, `wrong-session`, `unknown-session`, `malformed`. The dashboard shows the counters.
- **MTU:** every datagram stays under 1472 bytes. IP-fragmented UDP was measured to be dropped on this WSL setup, even on loopback. Handshake messages and large control messages are fragmented at the application layer, and each control fragment is individually AEAD-protected.

## 6. Key separation, rotation and rekeying

| Mechanism | What happens | Cost (measured) | Security property |
|---|---|---|---|
| **Key separation** | Per-session chain keys for each stream × direction, from `KYBER6G/{control,telemetry,image,video,recording,status}/{uav-to-gcs,gcs-to-uav}/chain/v1` | — | A key compromise in one stream or direction says nothing about the others (PRF outputs). |
| **Epoch rotation** (`EpochChain`) | Every 30 s or 2^20 records per stream: chain_{e+1} = HKDF(chain_e), key_e = HKDF′(chain_e); the old chain value is wiped | 43 µs on the Pi | One-way: compromise of the current chain value does not reveal earlier epochs' keys, assuming the deleted values are gone. Bounds data per key well below GCM limits. |
| **1-RTT Cached RapidRekey** (existing project semantics, hardened) | Request: uav_id, old session_id, mobility cell, fresh nonce_c, timestamp, HMAC under a key derived from the resumption secret. New keys = HKDF(salt = H(request ‖ nonce_s ‖ new_sid), IKM = resumption). The response carries a Finished MAC, then ClientFinished. The GCS deletes the old cache entry. | **9.0 ms** median at the UAV over Wi-Fi (95 % within 17.3 ms, 150 runs); 324 bytes in 3 datagrams; no public-key operations | See below. |
| **PQ ratchet** (new; RESEARCH_REFERENCES C049) | Over the authenticated control stream: a fresh ML-KEM-1024 keypair and X25519 key from the UAV; the GCS encapsulates. New master = HKDF(salt = H(transcript), IKM = ss_kem ‖ ss_x ‖ old master). | **14.1 ms** median at the UAV (95 % within 22.0 ms, 150 runs); 4,757 bytes in 5 datagrams; in the running system the Pi computes for 3.1 ms of that and the GCS for 1.9 ms (alone in a loop: 0.9 ms and 0.15 ms) | Forward secrecy **and** post-compromise security: fresh ephemeral PQ + classical secrets are injected. |

**What Cached RapidRekey does and does not provide** (no inflated claims):
- **It is 1-RTT, not 0-RTT.** No application data is sent under the new keys before the response arrives.
- **Authenticated.** An unauthenticated or forged request never changes server state: the MAC is checked before any change. Freshness comes from nonces on both sides, a ±120 s timestamp and the GCS nonce cache.
- **The refusal is not authenticated.** A REJECT tells the UAV to fall back to the full handshake. The UAV honours it only if it names exactly the request that is pending, so a forged one costs time (a full handshake instead of a cached rekey), never security.
- **One at a time.** On the UAV, handshake and rekey are serialised: a rekey asked for from the dashboard waits for one the link manager has in progress.
- **Bound to context.**
  - Allowed only within the same coarse GNSS cell (about 110 m, from the live L89 fix). A different cell gets `STALE_MOBILITY`, which forces a full PQC handshake.
  - Allowed only while the GCS cache entry is younger than 300 s.
- **One-way.** Once the old resumption secret is deleted, compromising the new one does not reveal earlier session keys.
- **No post-compromise security.** Anyone who obtains the current resumption secret can derive every later Cached-RapidRekey session until the next full handshake or PQ ratchet. For this reason the PQ ratchet runs periodically (every 600 s by default), and every change of position cell brings a full handshake.
- **Its quantum resistance is inherited:** it is only as strong as the hybrid handshake its resumption secret descends from.

## 7. Telemetry, image and video data paths

- **Telemetry (stream 2):** real L89 data via gpsd TPV/SKY, 1 Hz JSON. The source field is always set; synthetic data exists only as a test mode labelled `SYNTHETIC`.
- **Images (stream 3):**
  - JPEG from Picamera2, at full 2592×1944 when the camera is idle, or at the video resolution during streaming.
  - Sent as chunks of at most 1100 bytes. Each chunk is its own AEAD record.
  - The receiver NACKs missing chunks over the control channel; retransmissions are resealed.
  - The receiver checks the SHA-256 of the whole image against the value in the authenticated metadata.
- **Video (stream 4):**
  - Picamera2 drives the VideoCore **hardware** H.264 encoder: High profile, IDR every 30 frames, SPS/PPS repeated.
  - Each encoded access unit is split into chunks of at most 1100 bytes. Metadata (frame ID, chunk index and count, keyframe flag) sits in authenticated `ext`; the capture timestamp is inside the ciphertext.
  - The GCS decrypts, reorders (150 ms jitter buffer), declares incomplete frames lost and feeds the decoder nothing until the next IDR, then decodes with ffmpeg.
- **Live and recording share one encode:** the camera feeds a single `FanoutOutput` that hands the same encoded frames to the live sink and the recorder.

## 8. Control channel

- JSON commands (start/stop live, start/stop recording, capture, mode, video settings, fetch recording, rekey) travel on stream 1, under the same AEAD, replay and session rules.
- The dashboard HTTP server listens on **127.0.0.1 only**, because it can command the UAV. It has no login.
- Listening on 127.0.0.1 does not keep out other web pages in the operator's browser, so every request is checked before anything is done (`ground/main.py::request_refused`): the `Host` header must name this machine (stops DNS rebinding), a request the browser marks as coming from another site is refused, a `POST` with an `Origin` other than this server is refused, and a command must have the content type `application/json` (which a cross-site form cannot send). The page is served with a Content-Security-Policy (scripts from this server only, no `eval`, no framing) and every response with `nosniff` and a same-origin resource policy.
- The peer is authenticated but not trusted to be well-formed: JSON from it is parsed with bounds on size and depth and without `NaN`, the fields that enter arithmetic are typed, file names from the UAV must be plain names, and the arguments of a command cannot replace its type.
- Text received from the UAV is escaped before display, to prevent HTML or script injection into the dashboard.
- A command is one message and is not repeated: under packet loss the operator may see "timeout waiting for UAV acknowledgement" and has to send it again (measured: TEST_REPORT §14.3).

## 9. Photos and recordings stored on the UAV (`recording/sealing.py`, `recorder.py`, `photos.py`)

File format 2 (October 2026) applies the link's own two rules to the stored files: never rest on one assumption, and say who you are.

```
CEK      ← 32 random bytes                              (one per file; RAM only)
ct, ss_k ← ML-KEM-1024.Encaps(GCS recording ek)
ss_x     ← X25519(key made for this file, GCS recording X25519 key)
KEK      ← HKDF(salt = SHA-256(header_json ‖ ct ‖ xe_pub), ikm = ss_k ‖ ss_x, info = label ‖ file id)
wrapped  ← AES-256-GCM(KEK, nonce 0, CEK, aad = magic ‖ header_json ‖ ct ‖ xe_pub)        (the KEK is used exactly once)
recording: segment_i ← AES-256-GCM(CEK, nonce = 0^4 ‖ i, frames, aad = SHA-256(file header) ‖ i ‖ flags)
photo:     body      ← AES-256-GCM(CEK, nonce = 0^11 ‖ 1, JPEG, aad = SHA-256(file head))
trailer  ← "K6GSIG01" | length | ML-DSA-87_UAV("KYBER6G/at-rest/sig/v1|" kind "|" ‖ SHA-256(every byte before the trailer))

.k6grec = "K6GREC02" | u16 json_len | header_json | ct(1568) | xe_pub(32) | wrapped(48) | segments … FINAL | trailer
.k6gimg = "K6GIMG02" | u16 json_len | header_json | ct(1568) | xe_pub(32) | wrapped(48) | body | trailer
```

- **Hybrid key wrap.** The file key is wrapped under a key derived from both an ML-KEM-1024 encapsulation and an X25519 exchange. Opening a file needs both secret recording keys of the ground station; breaking one of the two schemes is not enough. This is the KEM-DEM construction with the same concatenation combiner as the handshake.
- **Signed by the UAV.** The UAV signs SHA-256 of the whole file with its ML-DSA-87 identity key, the key the ground station has pinned. The ground station refuses a file that does not carry that signature. With format 1, anyone who knew the ground station's *public* recording key could write a file that decrypted and authenticated; a file planted on the SD card or in the ground station's folders would have been taken for the UAV's.
- **Signature first.** For a photo the signature is checked before the ground station's secret keys are used at all: a forged file costs one verification and gives nothing to probe the long-term keys with. A recording is read as far as it goes even without its trailer (a recording cut short by a power loss has none) and is then reported as cut short and unsigned, never as complete.
- **The UAV cannot decrypt a finished file.** It never stores the CEK, the shared secrets or the X25519 key it made for the file, and it holds only public keys of the ground station. Seizing the Pi's SD card does not expose photos or recorded video. It does expose the UAV's identity key (§11).
- **Tamper evidence.** Segments cannot be modified, reordered, dropped, or moved between files without failing authentication. A file with no FINAL segment is reported as **TRUNCATED**.
- **Starts at a keyframe.** Recording begins at the first IDR, so frames before it (which cannot be decoded) are skipped and counted.
- **Why this differs from the brief's suggestion** of a recording key derived from the session key: session keys are deliberately deleted. A recording encrypted under them would either become undecryptable once the session ended, or would force the system to keep session secrets. Per-file key wrapping gives at-rest confidentiality that is both durable and post-quantum.
- **Decryption:** on the GCS only (`tools/decrypt_recording.py`, or "Fetch & decrypt" on the dashboard). Plaintext `.mp4` and `.jpg` files exist only on the GCS.
- **On disk.** A file is created with mode 0600 and must not exist yet (`O_EXCL` for recordings; photos are written to a temporary name, `fsync`ed and renamed, and an existing photo is never replaced), in a directory of mode 0700. The parsers report every kind of damage as one error type, refuse a key block of the wrong length, and report bytes after the FINAL segment.
- **Format 1** (`K6GREC01`, `K6GIMG01`: ML-KEM-1024 alone, no signature) is still read, and is written only by a UAV that has not been given the X25519 recording key (`run/kyber6g.sh deploy` copies it). The data audit counts how many files of each format there are.
- **Cost** (measured, `paper_plots/tables/plot08_media_protection.csv` and `table_at_rest.csv`): sealing a 200 kB photo on the Pi takes 8.1 ms in format 2 against 5.3 ms in format 1, a 3 MB one 92 ms against 71 ms. The hybrid wrap and the signature cost about 2 ms per file; hashing the file for the signature adds about 6 ms per megabyte. Opening on the laptop, signature check included, takes 0.5 ms (200 kB) and 4.9 ms (3 MB). A format-2 file is 6,761 bytes longer than the JPEG inside it (signature trailer 4,637, ML-KEM ciphertext 1,568, header, X25519 key, wrapped key and tag 556); a format-1 file 1,947. A recording segment holding one second of 3 Mbit/s video (375 kB) is sealed in 6.4 ms on the Pi; the key is wrapped and the file signed once per recording.
- **Tests and attack experiments:** `tests/test_sealing.py`; modified, cut, re-ordered, re-signed and forged files in `tools/attack_bench.py` (`CRYPTANALYSIS_REPORT.txt` §4.13).

### 9a. Photos
Every captured photo is also written to the Pi's SD card (`~/kyber6g_photos`), so a capture survives a dropped link, but the Pi cannot read it back. The header (capture time, size, mode, GNSS position, SHA-256 of the plaintext, signer) is authenticated, not secret. File names carry the capture time to the millisecond. The GCS fetches a photo over the normal encrypted blob channel, verifies the signature, unwraps the key with its two recording keys, decrypts, and checks the SHA-256.

### 9c. Sealed audio (`audio/quaver.py`, `audio/framing.py`, `audio/store.py`, `ground/audio_desk.py`)

Audio is stored and sent in a container of its own (`.k6gaud`), because three things are asked of it that a photo or
a recording file does not give: an observer must not learn from sizes what is being said, a clip that is sent live
over a lossy link must be the same object as the clip on the card, and a part of a recording must be releasable to a
third party without the rest. The full account, with the attack experiments, is `AUDIO_CRYPTANALYSIS_REPORT.txt`.

```
head     "K6GAUD01" | u16 len | public header (JSON) | ML-KEM-1024 ct (1568) | X25519 share (32) | wrapped clip key (48)
block i  commit_i (32) | AES-256-GCM(K_i, nonce 0, plain_i, aad = "K6GAUD01|blk|" ‖ clip id ‖ i ‖ SHA-256(head)) | tag (16)
root     "K6GAROOT" | flags | u32 n | Merkle root over the n blocks          leaf_i = SHA-256(0x00 ‖ clip id ‖ i ‖ block i)
trailer  "K6GSIG01" | u16 len | ML-DSA-87_UAV("KYBER6G/at-rest/sig/v1|audio|" ‖ SHA-256("K6GAUD01|root|" ‖ SHA-256(head) ‖ flags ‖ n ‖ root))

clip key ← 32 random bytes, wrapped as in §9 (ML-KEM-1024 and X25519, both needed)
tree     ← HKDF(clip key, "KYBER6G/audio/v1|tree|" ‖ clip id);  child = HMAC-SHA-256(parent, 0x00 or 0x01), depth 24
K_i      ← HMAC(leaf_i, 0x02 "enc");   commit_i ← HMAC(leaf_i, 0x03 "com")
plain_i  = kind | flags | frames | length | capture time | latitude | longitude | first frame | data | zeros to the block size
```

- **Frames, not samples.** The stream is cut into the encoder's own frames (MPEG audio frames, or 20 ms of PCM) and is
  not decoded; F frames (8 by default, 0.21 s) make a block. Opening gives the file back byte for byte, and the SHA-256
  of the stream is in a sealed summary block and checked.
- **One key per block, used once.** The nonce is fixed because no key seals two messages (tested over 5,280 blocks of
  120 clips on each machine: no key, commitment or tag twice).
- **The sealer forgets.** The UAV walks the key tree leaf by leaf and keeps only the nodes that lead to blocks still
  to come (`SealerTree`); the clip key and the tree's root are overwritten after the first block. Like every UAV-side
  file of §9 the clip cannot be opened on the UAV at all; in addition a UAV taken while it records holds no key of the
  blocks it has already sealed (best effort in CPython, §10).
- **Uniform shape.** Every block of a clip has the same size (F times the largest frame; set `audio_frame_cap` to the
  encoder's largest frame so that this size does not depend on the recording), there is one block per F frames whatever
  is said, and the number of blocks is rounded up (Padmé: at most about 12 %, 2.3 % on average for clips of 1 to 10
  minutes). The description of the clip (codec, rate, source name, start time and place, its number in the chain) is
  block 0, sealed like the rest. The public header names the algorithms, the block size, the fingerprints of the
  recipient's keys and the signer, and nothing about the audio.
- **Sealed once.** The same sealed blocks are written to the card and sent on the link's audio stream (stream 7) inside
  the link's own records. Blocks travel once and are not repeated; the head and the root record with the signature go
  by the reliable transfer. The ground station plays a block as soon as it opens under the clip's key tree, asks for the
  blocks that did not arrive by number (again after 6, 12, 24 … seconds if nothing comes), and stores the clip only when
  every block hashes to the root the UAV signed: so the stored clip is byte for byte the card's.
- **Excerpt release.** For blocks a..b the ground station hands out the sealed blocks, the at most 48 tree nodes that
  cover exactly a..b, a Merkle range proof, and the clip's head, root and signature (`.k6gax`). Anyone verifies it with
  the UAV's public key: the root is the UAV's, the blocks are blocks a..b of that clip, each key matches its block's
  commitment, the blocks open to audio with its capture time and position. Keys of other blocks cannot be derived
  (5,124 attempts with released keys on other blocks: none opened). The ground station's own keys and the clip key do
  not leave it. This is the redactable-signature construction (a key tree and a hash tree) with the hidden values used
  as encryption keys.
- **Chain.** A clip's sealed description names the clip before it by number and root; the ground station reports a
  gap, a number that returns with other content, and a clip that does not follow the one it holds. The last clips of a
  chain can be deleted unnoticed by the chain itself; the UAV's status carries the number of its last clip.
- **Power loss.** A clip whose sealer was lost is closed at the next start from the whole blocks on the card and signed
  as "not closed by its sealer"; it opens, says so, and cannot be passed as complete.
- **No microphone on the prototype.** A file in `~/kyber6g_audio/inbox` (put there with `kyber6g.sh audio-put`) stands
  in for one, is sealed frame by frame at the speed a microphone would deliver it, and is removed afterwards. Until then
  it lies on the card in the clear.
- **Cost** (measured, `paper_plots/tables/plot19_*.csv`): the Pi seals a minute of 128 kbit/s audio in 89 ms; the clip
  grows by 9.0 % (6.7 kB fixed, 76 bytes a block, the rest padding). **Tests and attack experiments:**
  `tests/test_audio.py`; `tools/audio_bench.py` (12,646 attack attempts on both machines, none accepted).

### 9b. The mobility cell and GNSS noise
The cached-rekey context is a coarse position cell. A GNSS fix wanders by tens of metres at rest, so a plain rounded cell flipped every few seconds near an edge and forced a full handshake each time (seen on the hardware: 4 in 2 minutes at ±23 m). `MobilityTracker` changes the cell only after the position is 0.3 cell beyond the old edge, and holds the cell while the fix is briefly lost. The cell stays context, not authentication (see §11).

## 10. Randomness and zeroisation

- **Randomness.** Every key, nonce, salt, session ID, recording ID and CEK comes from `os.urandom` (getrandom). On the Pi, the kernel's random generator is fed by the BCM2711 hardware RNG (`fe104000.rng`, active as measured). `random`/`numpy.random` are never used for security values.
- **Zeroisation.** Long-lived secrets (master, resumption, chain keys, CEK, KEK and IKM buffers) are held in `bytearray`s and overwritten when retired (`crypto/secure_bytes.py`).
  - **Limitation:** CPython cannot guarantee erasure. Immutable `bytes` copies, OpenSSL's internal key schedules inside AEAD objects, and garbage-collector timing can leave copies in memory. Treat this as best effort.

## 11. What is not claimed / limitations

- **Reviewed, not proven.** The implementation was read for vulnerabilities and hardened in October 2026; findings, fixes, tests and the residual risks (no login on the dashboard, flooding beyond the ration, clocks, operating-system updates) are in `SECURITY_AUDIT.md`.
- **The UAV application runs confined** (`deploy/kyber6g-uav.service`: no new privileges, read-only file system except the three media directories, private `/tmp`). The ground station has no such confinement.
- **Live video is not protected against loss.** The link stays up and secure under packet loss; the picture does not stay usable (TEST_REPORT §14.3): there is no keyframe request and no forward error correction.
- **This is not a 5G/6G radio implementation.** The prototype runs over Wi-Fi/IP. The *security architecture* is what transfers to future 5G/6G UAV links.
- **Proved in the symbolic model, not computationally.** The handshake, the cached rekey, the PQ ratchet and the stored-file format are modelled in ProVerif and checked under four attackers (nothing broken, X25519 broken, ML-KEM broken, both): `formal/`, with every query and its outcome in `formal/RESULTS.md`. That model treats the primitives as ideal and knows no timing and no sizes. The computational arguments are for the components (the combiner of the two shared secrets, the record layer, the file format, the audio trees) and are written out, with their assumptions, in `SECURITY_PROOFS.md`; a computational proof of the whole protocol has not been made. The models also show three limits of the design that are meant: the cached rekey does not heal a session whose secret had leaked (§6); the PQ ratchet heals only against an attacker who does no more than listen while it runs; authentication rests on ML-DSA-87 alone (it is not hybrid).
- **The libraries are checked, not trusted blindly.** ML-KEM-1024 and ML-DSA-87 in liboqs 0.16.0 and the classical primitives in OpenSSL give NIST's and the RFCs' known answers on both machines (`kyber6g/tools/pq_conformance.py`, 162 vectors); both programs repeat a short self-test at every start and stop if it fails (`crypto/selftest.py`); every key read from a file or received from the peer has its length checked before the library sees it (`identity.sized`: the Python binding of liboqs would fill a short key with zeros). What is in use, with which parameters and at which level, is listed in `CBOM.json`.
- **Side channels:** liboqs 0.16.0 and OpenSSL 4.0.2 provide constant-time implementations. Physical power/EM analysis, fault attacks and cache attacks were not evaluated.
- **The GNSS mobility cell is context, not authentication.** A spoofed GNSS position can at most force extra full handshakes.
- **Metadata visible on the wire:** packet sizes and timing (which correlate with scene activity in the video), stream IDs, epochs and sequence numbers are visible, though authenticated. No traffic padding is applied to video, telemetry or control. Sealed audio is the exception (§9c): its blocks have one size and one rate; that audio is being sent, and for how long, stays visible.
- **Stored audio has no forward secrecy**, like every file of §9: whoever has the ground station's two recording keys opens every clip sealed to them.
- **A captured UAV can be impersonated.** Its ML-DSA-87 identity key lies on its SD card (mode 0600, not encrypted: the node must start unattended). Until its pinned key is removed at the ground station, whoever holds the card can speak and sign files as that UAV. The photos and recordings on the card stay unreadable.
- **A flood can keep the UAV waiting.** Forged handshakes above a rate that depends on the ground station's processor delay the genuine one; the measured rates are in `CRYPTANALYSIS_REPORT.txt` §4.12. Nothing is disclosed or accepted by a flood.
- **IR illumination is hardware-automatic** (light sensors on the IR boards). Night mode changes camera exposure, gain and colour processing only.

## 12. Where public-key cryptography is used, and with what

| Where | Purpose | Algorithms | Post-quantum? |
|---|---|---|---|
| Full handshake (`crypto/handshake.py`) | session keys | ML-KEM-1024 + X25519 (both secrets into HKDF) | yes, hybrid |
| Full handshake | both ends prove who they are | ML-DSA-87, keys pinned | yes |
| PQ ratchet | fresh secrets inside a session | ML-KEM-1024 + X25519 | yes, hybrid |
| 1-RTT Cached RapidRekey | new session from the cached secret | none (HKDF, HMAC-SHA-256) | inherits from the handshake |
| Stored photos and recordings (`recording/sealing.py`) | wrap the file key | ML-KEM-1024 + X25519 | yes, hybrid |
| Stored photos and recordings | origin of the file | ML-DSA-87 (UAV identity key) | yes |
| Sealed audio (`audio/quaver.py`) | wrap the clip key | ML-KEM-1024 + X25519 | yes, hybrid |
| Sealed audio | one signature over the Merkle root of all blocks: origin and integrity of the clip, of a live clip and of any excerpt | ML-DSA-87 (UAV identity key) | yes |
| Sealed audio | a key per block, commitments | none (HMAC-SHA-256 tree from the clip key) | symmetric, 256-bit |
| Management channel: deploy, service control, measurements (`run/kyber6g.sh`, `tools/sshopts.py`) | SSH key exchange | Streamlined NTRU Prime 761 + X25519, or ML-KEM-768 + X25519 where the OpenSSH client has it | yes, hybrid (OpenSSH's, not this project's code) |
| Management channel | SSH host and user authentication | Ed25519 | **no**: OpenSSH has no post-quantum signature yet. An attacker would have to break it while the connection is being set up; recorded sessions stay confidential. |
| Everything that is sent or stored | bulk encryption | AES-256-GCM (ChaCha20-Poly1305 as suite 2), 256-bit keys | symmetric: about 128 bits against Grover's search |
| Dashboard | HTTP on 127.0.0.1 only | none | not applicable: it does not leave the machine |

No RSA, (EC)DSA or finite-field Diffie-Hellman is used anywhere in the project's code (the data audit greps for it). The classical X25519 is never used alone.
