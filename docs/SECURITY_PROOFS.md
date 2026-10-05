# Kyber-6G: what is proved, how, and under which assumptions

This document states every security claim the paper may make about the cryptography, and for each one gives the
evidence: a **proof by reduction** written out here (P), a **machine-checked** proof in the symbolic model (M, the
ProVerif models in [`formal/`](../formal)), or a **test or measurement** on the two machines (T). It also states
what is *not* proved (section 12). Nothing here is a new cipher or a new hardness assumption: the system composes
standardised primitives, and the proofs are the standard arguments for those compositions, instantiated for the
exact formats of this code.

Status, plainly: the reductions in this file were written for this project and have **not been peer reviewed**.
The symbolic proofs are checked by ProVerif 2.05 and can be re-run in half a minute (`python3 formal/run.py`);
they hold for the *models*, which idealise the primitives (section 4.1). The known-answer tests show that the
libraries on both machines compute the standardised functions; they do not show the absence of side channels.

## 1. Parties, keys, adversary

| | holds | never holds |
|---|---|---|
| UAV | its ML-DSA-87 signing key; the ground station's three **public** keys (ML-DSA-87 identity, ML-KEM-1024 and X25519 recording keys); session secrets while a session lives | any key that opens a stored file |
| ground station | its ML-DSA-87 signing key; the UAV's public key; the two recording secret keys (ML-KEM-1024, X25519); session secrets | the UAV's signing key |

Public keys are pinned from disk on both sides; nothing is trusted on first use.

The adversary controls the network completely (reads, drops, delays, replays, modifies and injects every
datagram), may hold a *second* UAV's signing key that the ground station also pins (a captured UAV), and may later
obtain long-term keys or session state as stated per claim. Two kinds of computing power are considered:

* **classical**: none of the assumptions below is broken;
* **quantum**: X25519 is broken outright (Shor); for the symmetric primitives a quadratic speed-up of exhaustive
  search is assumed (Grover), i.e. 256-bit keys give about 128 bits.

"Hybrid" claims are stated against *three* attackers: X25519 broken, ML-KEM-1024 broken, and (as a check that
the claim can fail) both broken.

## 2. Assumptions and security levels

| | assumption | standard | level claimed by the standard | used for |
|---|---|---|---|---|
| A1 | ML-KEM-1024 is IND-CCA2 | FIPS 203 | category 5 | session establishment, PQ ratchet, key wrap of stored files |
| A2 | gap Diffie-Hellman on Curve25519 (CDH is hard given a DDH oracle) | RFC 7748 | about 128 bits classical, **none** quantum | the classical half of every key establishment |
| A3 | ML-DSA-87 is existentially unforgeable under chosen-message attack | FIPS 204 | category 5 | identities in the handshake; signature of every stored file |
| A4 | AES-256-GCM (and ChaCha20-Poly1305) is a secure AEAD when no nonce repeats under a key | SP 800-38D, RFC 8439 | 256-bit key | every record, every stored block, every key wrap |
| A5 | HMAC-SHA-256 is a PRF; HKDF-Extract behaves as a random oracle on (salt, input) | FIPS 198-1, RFC 5869 | 256-bit key | key schedule, Finished values, key tree of audio clips |
| A6 | SHA-256 is collision resistant (128 bits) and second-preimage resistant (256 bits) | FIPS 180-4 | category 2 for collisions | transcript hash, file digest, Merkle tree |

Two remarks on levels, because "category 5" must not be claimed for the whole system without them.

**SHA-256.** A *collision* in SHA-256 costs about 2^128 work, which is NIST category 2. Collisions matter only
where the adversary can choose both colliding inputs and have an honest party sign one of them. In this system
every signed value is a digest over data that contains fresh randomness of the signer which the adversary does not
choose: the transcript hash contains the signer's own nonce and one-time keys; a file digest is over ciphertext
under a key drawn by the signer. A forger therefore needs a *second preimage* of a digest it did not choose
(2^256 classical, about 2^128 with Grover), not a collision. The exception is an adversary who *is* the signer
(a malicious UAV that wants two files with one signature): that is outside the model, and against it the level is
128 bits. (One more case, for completeness: the ground station signs a hash whose *first* part, the ClientHello,
is chosen by its peer. A peer that found two hellos colliding inside SHA-256 could have one answer fit both; both
hellos are its own, signed with its own pinned key, so it has gained nothing.) A deployment that must match
CNSA 2.0 to the letter would use SHA-384 here; this prototype does not.

**AES-GCM limits.** A record key (one per session, stream, direction and epoch) seals at most 2^20 records
(`rotate_packets`) of about 75 AES blocks (1,200 bytes), i.e. fewer than 2^27 blocks: the usual bound
(blocks^2 / 2^129) is below 2^-75 per key. A content key of a stored file seals one file of at most 256 MB (2^24
blocks): below 2^-81. A key-wrapping key is used for exactly one encryption, which is why its nonce may be zero.

**Conformance of the implementation (T).** On both machines (Raspberry Pi 4B, aarch64; laptop, x86-64) liboqs
0.16.0 reproduces 150 of 150 NIST ACVP vectors for ML-KEM-1024 and ML-DSA-87: key generation from a seed (25 +
25), encapsulation with given coins (25), decapsulation including tampered ciphertexts (10), the encapsulation-
and decapsulation-key checks of FIPS 203 section 7 (10 + 10), signing deterministic and hedged with context (30),
verification of valid and four kinds of damaged signatures (15); and 10 published vectors for X25519, HKDF, HMAC,
SHA-256 and AES-256-GCM through this project's own code paths. `python -m kyber6g.tools.pq_conformance`; results in
`paper_plots/data/pq_conformance_{pi,laptop}.json`. Each node repeats a subset when it starts and refuses to start
if a check fails (`crypto/selftest.py`).

## 3. Theorem 1: the hybrid key (P)

Every key establishment in the system (handshake, PQ ratchet, key wrap of a stored file) has the same shape:

    (c1, k1) <- ML-KEM-1024.Encaps(ek)           c2 = g^x,  k2 = X25519(x, Y)  for the peer's share Y = g^y
    K = HKDF-Expand( HKDF-Extract( salt = SHA-256(ctx || ... c1 ... c2 ... Y ...),  k1 || k2 ),  label )

where `ctx` is everything public that both ends agree on (the whole handshake transcript, or the header of the
file), and `label` separates purposes. Call this construction C.

**Claim.** Model HKDF-Extract as a random oracle. For every adversary A against the IND-CCA security of C that
makes q oracle queries there are adversaries B1 against the IND-CCA security of ML-KEM-1024 and B2 against gap-DH
on Curve25519, of about the same running time, such that

    Adv_C(A)  <=  2 Adv_{ML-KEM}(B1) + q / 2^256        and        Adv_C(A)  <=  2 Adv_{gap-DH}(B2)

(plus the probability of a collision in the SHA-256 that makes the salt, A6).

So C is secure if *either* scheme is: a quantum attacker (A2 gone) is held by the first bound, an attacker who
breaks module lattices (A1 gone) by the second.

**Argument.** *First bound.* Game 0 is the IND-CCA game for C. In game 1 the challenger computes the challenge
key with a uniformly random k1* in place of the real ML-KEM secret. B1 simulates either game: it gets
(c1*, k_b) from its own challenger, draws the X25519 part itself, and answers A's decapsulation queries
(c1, c2) with its own decapsulation oracle when c1 != c1*, and with k_b when c1 = c1* (then c2 != c2*, the salt
differs because c2 is hashed into it, and the answer is the oracle at another point). A notices the change only by
distinguishing k_b, which is B1's advantage. In game 1 the challenge key is the random oracle at a point that
contains 256 uniformly random bits A has never seen; unless A queries that point (probability at most q / 2^256)
the key is independent of its view. *Second bound.* The same two steps with the roles exchanged: B2 embeds its
gap-DH instance (g^x, g^y) as the two shares, answers decapsulation queries and recognises oracle queries that
contain g^xy with the DDH oracle (the argument for DHKEM in HPKE), and wins when A queries the challenge point.
All-zero X25519 outputs are refused by the code, so a low-order share cannot fix k2.

**Why the ciphertexts are in the salt.** Without c1 and c2 under the hash, an adversary could keep one half of
the challenge ciphertext, replace the other half and ask for the decapsulation of the mixture; with them, every
such query is the oracle at a different point. This is the combiner of Giacon, Heuer and Poettering (PKC 2018)
and the reason the TLS 1.3 hybrid design feeds the transcript into the key schedule.

**What is not claimed.** (i) In the standard model the argument needs HMAC-SHA-256 to be a PRF when keyed through
*either half of its message*; that is an assumption about HMAC, not a theorem. (ii) The file key wrap hashes the
ML-KEM ciphertext and the one-time X25519 key into the salt, but not the ground station's two static public keys.
With one recipient that makes no difference to IND-CCA; the stronger "binding" notions (a key is tied to exactly
one public key even against maliciously formed keys) are not claimed for stored files. In the handshake both
one-time public keys are inside the transcript hash.

**Tests (T).** `tests/test_pq.py`: with the real transcript and one real shared secret, substituting anything for
the other secret never yields the session's master secret (and both real secrets do); a stored file's content key
is refused with either recording key replaced; the same for the ratchet with the old master secret replaced.

## 4. Theorem 2: the full handshake (M)

    UAV -> GCS   ClientHello      suite, id, nonce, mobility cell, time, X25519 share, ML-KEM public key, sig_UAV(label || all of it)
    GCS -> UAV   ServerHello      suite, session id, nonce, id, X25519 share, ML-KEM ciphertext, sig_GCS(label || TH), Finished
    UAV -> GCS   ClientFinished   session id, Finished
    TH = SHA-256(label || ClientHello || sig_UAV || ServerHello body);   keys = Theorem 1 with ctx = TH

**Claims, each checked by ProVerif for any number of sessions** (`formal/handshake.pv`):

1. *Secrecy.* What either side sends under the session keys is never known to the attacker.
2. *The ground station authenticates the UAV.* If the ground station completes session (id, key) with the honest
   UAV, that UAV completed the same session with the same key, and to each completion of the ground station
   corresponds a different one of the UAV (no replay is accepted as a new session).
3. *The UAV authenticates the ground station*, likewise.
4. *Forward secrecy.* 1 still holds when both long-term signing keys are given to the attacker after the sessions.
5. *A captured second UAV does not help:* its signing key is public in the model.

| attacker | 1 secrecy | 2 GCS authenticates UAV | 3 UAV authenticates GCS |
|---|---|---|---|
| classical | proved | proved | proved |
| X25519 broken (quantum) | proved | proved | proved |
| ML-KEM-1024 broken | proved | proved | proved |
| both broken | **attack found (as it must be)** | **attack found** | proved |

Read with claim 4, the third row says: *if both lattice schemes were broken one day (ML-KEM always, ML-DSA after
the session), recorded sessions would still be closed, as long as X25519 holds*; the second row is the
harvest-now-decrypt-later case. The last row shows the model can fail, and how: with the session key computable,
the attacker finishes a session the UAV began (the UAV's ClientFinished is a MAC under that key), while the ground
station's signature still binds its own side.

### 4.1 What the symbolic model assumes

Signatures cannot be forged and reveal nothing; a KEM ciphertext yields its secret only to the secret key;
X25519 is a group in which only the stated equation holds; hashes, HKDF and HMAC are functions nobody inverts,
with unrelated outputs; the AEAD opens only with the right key, nonce and associated data. Lengths, timing,
randomness quality, side channels and concrete bounds do not exist in this model. The time stamp and the replay
cache of the ClientHello are not modelled (the attacker may choose the time): they are not needed for the claims
above, they only keep the ground station from doing work for replayed hellos.

## 5. Theorem 3: 1-RTT Cached RapidRekey (M)

A new session from the resumption secret of the old one, with no public-key operation:
`PRK = HKDF-Extract(SHA-256(label || request || GCS nonce || new id), resumption)`. The ground station answers one
request per stored secret and then deletes it. `formal/cached_rekey.pv`:

* secrecy of the new session, and agreement in both directions (the ground station completes only if the UAV
  completed the same rekey, once): **proved**, for all four attackers (nothing here depends on a public-key scheme);
* the same when the *next* resumption secret leaks afterwards: **proved** (the chain cannot be walked backwards:
  forward secrecy of the epochs that are over, provided old secrets are deleted, which the code does);
* **not** post-compromise security: if the resumption secret leaked *before* the rekey, the model finds the
  attack on every claim. A cached rekey moves the keys forward; it does not heal. That is the PQ ratchet's job.

## 6. Theorem 4: the PQ ratchet (M)

A fresh ML-KEM-1024 + X25519 exchange inside the session's own records, mixed with the old master secret:
`PRK = HKDF-Extract(TH, ML-KEM secret || X25519 secret || old master)`. `formal/pq_ratchet*.pv`:

* inside a healthy session: secrecy and agreement **proved** for all four attackers (even with both schemes
  broken, the old master secret is still in the key);
* the old master secret leaks afterwards: secrecy **proved** unless both schemes are broken (then: attack found);
* **post-compromise security against a listener:** the old master secret is given to the attacker beforehand, he
  reads both ratchet messages but does not alter them: the new epoch is secret again, **proved** with X25519
  broken or ML-KEM broken, attack found with both;
* the limit: an attacker who holds the old secret *and is active at that moment* takes the new session over
  (attack found, `pq_ratchet_active.pv`). No ratchet without a new authentication can do better.

## 7. Theorem 5: the record layer (P, T)

Every datagram after the handshake is one AEAD record: header (version, stream, session id, epoch, 64-bit
sequence number, stream-specific fields) as associated data, nonce = 0^32 || sequence number, key
`k_e = HKDF-Expand(chain_e, "epoch-key" || e)` with `chain_{e+1} = HKDF-Expand(chain_e, "epoch-chain" || e)` and
`chain_0 = HKDF-Expand(master, label(stream, direction))`.

**Claim.** If the master secret is indistinguishable from random (Theorems 2 to 4), then (a) record contents are
confidential, (b) the receiver accepts only records the sender sealed, for the stream, session and epoch they
claim, each at most once, and (c) keys of past epochs do not follow from the state of a later epoch.

**Argument.** The chain values and epoch keys of different streams, directions and epochs are outputs of a PRF
at distinct inputs (A5), hence independent keys. Under one key no nonce repeats: the sequence number of a
(session, stream, direction) only increases, is never reset at an epoch change, and "take the next number" and
"encrypt" are one step under a lock. With unique nonces A4 gives confidentiality and ciphertext integrity per
key, and a hybrid argument over the keys gives (a) and the first half of (b); the header is associated data, so a
record cannot be moved to another stream, session or epoch. The receiver's window accepts each sequence number
once. (c): `chain_e` is erased when `chain_{e+1}` is computed, and inverting the step is inverting the PRF.

What a datagram channel cannot give is also not claimed: records may be dropped, delayed and reordered within the
window.

**Tests (T).** 192,000 records sealed by racing threads, no nonce used twice; 339,084 forged, replayed, reordered,
truncated and bit-flipped inputs, none accepted (`docs/CRYPTANALYSIS_REPORT.txt`).

## 8. Theorem 6: stored photos, recordings and audio clips (P, M, T)

A file is sealed once, on the UAV: a random content key encrypts the content; the content key is wrapped under a
key from Theorem 1 with `ctx` = the file's header; the UAV signs SHA-256 of every byte before the signature.

**Claims and evidence** (`formal/sealed_file.pv` for the symbolic part):

| claim | classical | X25519 broken | ML-KEM broken | both |
|---|---|---|---|---|
| the content stays secret | proved | proved | proved | attack found |
| ... also if the UAV is captured later (its signing key is all it has) | proved | proved | proved | attack found |
| ... also if the ML-KEM recording key alone is stolen | proved | attack found | proved | attack found |
| ... also if the X25519 recording key alone is stolen | proved | proved | attack found | attack found |
| ... if both recording keys are stolen | attack found | | | |
| what the ground station opens was sealed by the pinned UAV, with this id and content | proved | proved | proved | proved |

Computationally: confidentiality is the KEM-DEM composition (an IND-CCA KEM, here C of Theorem 1, with an
authenticated cipher gives IND-CCA public-key encryption; Cramer and Shoup) and authenticity is A3 plus second
preimages of SHA-256 (section 2). The signer's identity is in the header, the header is hashed into the wrapping
key and is associated data of the key wrap, so a file cannot be re-signed under another identity and still open.

**The limit that the last secrecy row states:** nothing at rest is forward secret. Whoever holds *both* recording
keys of the ground station opens every stored file. One stolen key is not enough, against a classical attacker.

## 9. Theorem 7: sealed audio, QUAVER (P, T)

Notation as in `kyber6g/audio/quaver.py`: clip key CEK (wrapped as in Theorem 6); tree root
`r = HKDF-Expand(CEK, "tree" || clip id)`; `child(k, b) = HMAC(k, b)`; leaf_i at depth 24; block key
`K_i = HMAC(leaf_i, "enc")`, commitment `c_i = HMAC(leaf_i, "com")`; block_i = c_i || AES-256-GCM(K_i, plain_i,
aad = clip id, i, SHA-256(head)); Merkle tree over the blocks; one ML-DSA-87 signature over (head, flags, n, root).

**7a. Every block has its own, independent key (P).** The tree is the Goldreich-Goldwasser-Micali construction.
For any set S of tree nodes whose keys are given to the adversary, the keys of all leaves that do not lie below a
node of S are indistinguishable from random: replace, one node at a time along the paths from the root, the two
children of a node whose key the adversary does not have by fresh random values; each step is one PRF challenge
(A5), and there are at most 24 steps per leaf. With adaptively chosen S, guessing the challenge leaf costs a
factor n <= 2^24. Consequences:

* *excerpt release:* the at most 48 node keys that cover blocks a..b open exactly those blocks; every other
  block's key, and therefore (A4) its content, stays hidden from the recipient of the excerpt;
* *a sealer that forgets:* after block i the UAV holds only nodes whose leaves are still to come, so capturing it
  mid-recording gives no key of a block already sealed (tested: `test_audio.py`, the object's stored nodes).

**7b. A released excerpt is what the UAV sealed (P).** The verifier holds the UAV's public key only. Accepting
an excerpt means: the signature verifies on (head, flags, n, root); each released block has a Merkle path to
root; each released node key reproduces the commitments c_i of the blocks below it; the blocks decrypt. For a
false excerpt to be accepted one of these must have been broken: a forged signature (A3); a second block or node
with the same hash as one in the UAV's tree (a second preimage among at most 2n targets, A6; leaves and inner
nodes are hashed with different prefixes, and the clip id and the index are in every leaf); a different leaf key
with the same commitment (a second preimage for HMAC under a key the adversary may know, again A6); or, with the
right key, a different plaintext for the same ciphertext and tag (A4). The commitment is necessary: AES-GCM by
itself does not bind a ciphertext to one key, and without c_i a dishonest releaser could hand out a second key
under which a block decrypts to something else.

**7c. What the shape gives away (P).** All blocks of a clip have one size and their number is rounded up with
Padme; an observer of the stored file or of the live stream learns the block size (a setting if `audio_frame_cap`
is set; otherwise the largest frame of that stream) and the padded count, which is at most about log2(log2 n)
bits about the length. Bit-rate variation, silence and the exact duration are not visible.

**Tests (T).** 12,646 attack attempts of 46 kinds on both machines, none accepted, 216 of 216 controls
(`docs/AUDIO_CRYPTANALYSIS_REPORT.txt`). The prior work this arrangement builds on (redactable signatures of
Johnson, Molnar, Song and Wagner; GGM; Merkle) is named there; novelty is claimed for the combination only.

## 10. Text: telemetry, status and motion reports (P)

Telemetry (1 Hz), status and the motion watch's reports are JSON in records of their own streams, so Theorem 5
applies: the ground station accepts only what the UAV of the authenticated session sent, once. Two things follow
from the design rather than from a theorem and are stated as such: telemetry that could not be sent is kept in
memory only (up to two hours) and is never written to the UAV's card, so a captured UAV holds no track at rest;
and these messages are authentic *to the ground station* (a shared key), not signed for third parties, unlike
the stored media.

## 11. Evidence map

| claim | evidence |
|---|---|
| the libraries compute FIPS 203 / FIPS 204 | T: 150 ACVP vectors on each machine; self-test at every start |
| hybrid: either scheme suffices | P: Theorem 1; M: every model under three attackers; T: `test_pq.py` |
| mutual authentication, secrecy, forward secrecy of the handshake | M: `handshake.pv` |
| cached rekey: secrecy, agreement, one-way; no healing | M: `cached_rekey.pv` (the limit is shown as an attack) |
| PQ ratchet: forward secrecy, healing against a listener; not against an active attacker | M: `pq_ratchet*.pv` |
| records: confidentiality, integrity, no replay | P: Theorem 5; T: attack experiments |
| stored files: only the ground station reads, only the UAV writes, both keys needed | P + M: Theorem 6; T: `test_sealing.py`, `test_pq.py` |
| audio: per-block keys, excerpt soundness and privacy, uniform shape | P: Theorem 7; T: audio attack experiments |
| nothing signed can be taken for something else | T: `test_pq.py` (labels are prefix-free; cross-kind verification fails) |
| inventory of all cryptography | `docs/CBOM.json`, generated; T: `test_pq.py` keeps it current |

## 12. What is not proved, and must not be claimed

* **No computational proof of the whole protocol.** The handshake, rekey and ratchet are proved in the symbolic
  model; the computational statements are for the components (Theorems 1, 5 to 7). Bridging the two for this
  protocol (as CryptoVerif or a hand proof in the style of the TLS 1.3 analyses would) has not been done.
* **Authentication is post-quantum only, not hybrid.** If ML-DSA-87 were broken, an *active* attacker could
  impersonate either side from then on. Recorded traffic stays closed (Theorem 2, forward secrecy); this is the
  CNSA 2.0 position, not the "hybrid signatures" position of some European agencies.
* **SHA-256, not SHA-384** (section 2).
* **Side channels, faults, bad randomness.** liboqs 0.16.0 and OpenSSL are relied on for constant-time code; the
  Pi 4 has no AES or SHA instructions, so AES runs in OpenSSL's bit-sliced/vector code. No power or
  electromagnetic measurement was made. Keys are files on an SD card (mode 0600), not in a secure element.
* **Availability.** Jamming, flooding above the ration, and dropping are possible for the network adversary.
* **Traffic analysis** beyond section 9c: sizes and timing of video and telemetry records are visible.
* **Implementation correctness** rests on tests (unit, known-answer, attack experiments), not on verification
  of the Python code.
* **"Unbreakable", "100 % secure", "post-quantum encrypted video".** The data is encrypted with AES-256-GCM;
  ML-KEM-1024 and ML-DSA-87 establish, wrap and sign.

## 13. Reproduce

    python3 formal/run.py                              # 46 ProVerif runs, 177 queries, about 30 s
    python -m kyber6g.tools.pq_conformance             # on each machine: 162 known-answer vectors
    python -m unittest tests.test_pq                   # hybrid, labels, key sizes, self-test, inventory
    python -m kyber6g.tools.cbom                       # docs/CBOM.json

## References

Written from memory; check every entry against the publisher before citing.

1. NIST, FIPS 203, *Module-Lattice-Based Key-Encapsulation Mechanism Standard*, 2024.
2. NIST, FIPS 204, *Module-Lattice-Based Digital Signature Standard*, 2024.
3. F. Giacon, F. Heuer, B. Poettering, "KEM combiners", PKC 2018.
4. N. Bindel, J. Brendel, M. Fischlin, B. Goncalves, D. Stebila, "Hybrid key encapsulation mechanisms and
   authenticated key exchange", PQCrypto 2019.
5. R. Cramer, V. Shoup, "Design and analysis of practical public-key encryption schemes secure against adaptive
   chosen ciphertext attack", SIAM J. Comput., 2003.
6. J. Alwen, B. Blanchet, E. Hauck, E. Kiltz, B. Lipp, D. Riepel, "Analysing the HPKE standard", EUROCRYPT 2021.
7. O. Goldreich, S. Goldwasser, S. Micali, "How to construct random functions", J. ACM, 1986.
8. D. Boneh, B. Waters, "Constrained pseudorandom functions and their applications", ASIACRYPT 2013; A. Kiayias,
   S. Papadopoulos, N. Triandopoulos, T. Zacharias, "Delegatable pseudorandom functions and applications", CCS 2013.
9. R. Johnson, D. Molnar, D. Song, D. Wagner, "Homomorphic signature schemes", CT-RSA 2002.
10. B. Blanchet, "Modeling and verifying security protocols with the applied pi calculus and ProVerif",
    Foundations and Trends in Privacy and Security, 2016.
11. NSA, *Commercial National Security Algorithm Suite 2.0*, 2022; RFC 9794 (terminology for PQ/T hybrid schemes).
12. C. Cremers, A. Dax, N. Medinger, "Keeping up with the KEMs: stronger security notions for KEMs and automated
    analysis of KEM-based protocols", CCS 2024 (the binding notions not claimed in section 3).
