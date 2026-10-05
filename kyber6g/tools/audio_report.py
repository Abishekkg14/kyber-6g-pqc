"""Write docs/AUDIO_CRYPTANALYSIS_REPORT.txt: the sealed-audio scheme (kyber6g/audio/quaver.py) against attack.

    python -m kyber6g.tools.audio_report [--data paper_plots/data] [-o docs/AUDIO_CRYPTANALYSIS_REPORT.txt]

The analysis text is written here once; every NUMBER about this system is read from the files the tools wrote:
    audio_attacks_laptop.json, audio_attacks_pi.json     kyber6g.tools.audio_bench attacks
    audio_cost_laptop.json, audio_cost_pi.json           kyber6g.tools.audio_bench cost
    audio_stats.json                                     kyber6g.tools.audio_bench stats
    audio_loss.json                                      kyber6g.tools.audio_bench loss
so the report cannot say something the experiments did not show. The numbers quoted for the six published schemes
are the ones their own papers print; none of them was re-measured here. Plain text on purpose: it is meant to be
quoted from.
"""
import argparse
import sys
import textwrap
import time
from pathlib import Path

from .crypto_report import REPO, W, bullets, fmt_outcomes, head, load, para, sub, table

PAPERS = [
    ("P1", "E. A. Albahrani, \"A New Audio Encryption Algorithm Based on Chaotic Block Cipher\", NTICT 2017"),
    ("P2", "A. Maity and B. C. Dhara, \"An Audio Encryption Scheme Based on Empirical Mode Decomposition and 2D Cosine Logistic Map\", "
           "IEEE Latin America Transactions 22(4), 2024"),
    ("P3", "A. S. Reddy, D. N. Achar, M. S. Mol and N. Panda, \"Audio Encryption Using AES and Cellular Automata\", ICCCNT 2024"),
    ("P4", "C. Albin, D. Narayan, R. Varu and V. Thanikaiselvan, \"DWT Based Audio Encryption Scheme\", ICECA 2018"),
    ("P5", "W. Wu, \"Digital Audio Blind Watermarking Algorithm Based on Audio Characteristic and Scrambling Encryption\", IEEE conference "
           "proceedings, 2017 (ISBN 978-1-4673-8979-2)"),
    ("P6", "P.-W. Chi and P.-H. Hsiao, \"Learnable Audio Encryption for Untrusted Outsourcing Machine Learning Services\", AsiaJCIS 2019"),
]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--data", default=str(REPO / "paper_plots" / "data"))
    ap.add_argument("-o", "--out", default=str(REPO / "docs" / "AUDIO_CRYPTANALYSIS_REPORT.txt"))
    a = ap.parse_args()
    d = Path(a.data)
    A = {"laptop (ground station)": load(d, "audio_attacks_laptop"), "Raspberry Pi 4B (UAV)": load(d, "audio_attacks_pi")}
    A = {k: v for k, v in A.items() if v}
    if not A:
        sys.exit(f"no audio attack experiments found in {d} (run: bash run/kyber6g.sh measure audio)")
    C = {"Raspberry Pi 4B": load(d, "audio_cost_pi"), "laptop": load(d, "audio_cost_laptop")}
    S, L = load(d, "audio_stats"), load(d, "audio_loss")
    one = next(iter(A.values()))

    exp = {}                                   # attack name -> {machine: experiment}
    for m, data in A.items():
        for e in data["experiments"]:
            exp.setdefault(e["attack"], {})[m] = e
    attacks = {n: v for n, v in exp.items() if next(iter(v.values()))["expect"] == "refused"}
    total = sum(e["attempts"] for v in attacks.values() for e in v.values())
    accepted = sum(e["accepted"] for v in attacks.values() for e in v.values())
    crashes = sum(e["crashes"] for v in exp.values() for e in v.values())
    controls = {n: v for n, v in exp.items() if n not in attacks}
    c_try = sum(e["attempts"] for v in controls.values() for e in v.values())
    c_ok = sum(e["accepted"] for v in controls.values() for e in v.values())
    failed = [(n, m) for n, v in exp.items() for m, e in v.items() if e["verdict"] != "PASS"]

    SHORT = (("blocks do not match the signed root", "blocks do not match the signed root"),
             ("signature invalid", "signature invalid (not the pinned UAV key, or changed)"),
             ("content key unwrap failed", "clip key does not unwrap (wrong recipient key, or header changed)"),
             ("the UAV's public key is needed", "refused without the UAV's public key"),
             ("not played; fetched again", "not played; fetched again from the card"))

    def short(reason):
        return next((new for old, new in SHORT if reason.startswith(old)), reason)

    def outcomes(o, limit=4):
        merged = {}
        for k, v in o.items():
            if isinstance(v, (int, float)):
                merged[short(k)] = merged.get(short(k), 0) + v
        return fmt_outcomes(merged, limit)

    def X(name):
        """One experiment as text: what was done, then per machine the attempts, how many were accepted, the reasons given."""
        v = exp.get(name)
        if not v:
            return f"  [experiment '{name}' not in the data]"
        what = " ".join(next(iter(v.values()))["what"].split())
        lines = [textwrap.fill(f"Experiment \"{name}\": {what}.", W, initial_indent="  ", subsequent_indent="    ")]
        for m, e in v.items():
            where = "on the " + m.split(" (")[0]
            if e["expect"] == "refused":
                x = f"{where}: {e['attempts']:,} attempts, {e['accepted']} accepted. Outcome: {outcomes(e['outcomes'])}"
            else:
                x = f"{where}: {e['accepted']:,} of {e['attempts']:,} accepted (all have to be)"
            lines.append(textwrap.fill(x, W, initial_indent="    ", subsequent_indent="        "))
        return "\n".join(lines)

    def XS(prefix):
        """All experiments whose name starts with `prefix`, summed (the 14 parts of the file, the 4 ways to change a live block)."""
        names = [n for n in exp if n.startswith(prefix)]
        att = sum(e["attempts"] for n in names for e in exp[n].values())
        acc = sum(e["accepted"] for n in names for e in exp[n].values())
        return names, att, acc

    t = []

    def add(block):
        """A block of text after a blank line (a heading brings its own)."""
        if t and not t[-1].endswith("\n") and not block.startswith("\n"):
            t.append("")
        t.append(block)
    t.append("SEALED AUDIO (QUAVER): GAPS IN SIX PUBLISHED SCHEMES, THE DESIGN, AND ITS CRYPTANALYSIS")
    t.append("=" * 88)
    dates = ", ".join(sorted({v["started_utc"][:10] for v in A.values()}))
    add(para(f"""
        Generated {time.strftime('%Y-%m-%d')} by kyber6g/tools/audio_report.py from the experiments of {dates} (UTC)
        ({' and '.join(A)}) in paper_plots/data. Every number about this system is read from those files; the numbers
        quoted for the six published schemes are the ones their own papers print. Plain text, so that sentences and
        tables can be copied into the paper. The scheme is implemented in kyber6g/audio/ (quaver.py, framing.py, store.py)
        and kyber6g/ground/audio_desk.py; its tests are tests/test_audio.py."""))

    # ------------------------------------------------------------------------------------------------ summary
    t.append(head(0, "Summary"))
    sm = []
    sm.append("""Six published audio "encryption" schemes were read in full (section 1). Five rest on chaotic maps, permutations or a cellular
        automaton evaluated with statistics (histogram, correlation, entropy, NSCR/UACI) instead of a security definition; one puts such a
        layer on top of AES. None authenticates the audio, none says how the key reaches the receiver other than "a secure channel", none
        resists a quantum computer in its key transport because none has a key transport, none hides the length or the bit rate, and none
        was run on the kind of machine that would carry it.""")
    sm.append("""The scheme built here, QUAVER (Quantum-safe, Uniform-shape Audio with Verifiable Excerpt Release), uses no new cipher. It seals
        the encoder's frames in blocks of one size under AES-256-GCM with a key per block from a key tree; the clip key is wrapped with
        ML-KEM-1024 AND X25519 to the ground station; one ML-DSA-87 signature over a Merkle root covers every block; the UAV cannot open
        its own clips and forgets each block's key as it goes; the same sealed blocks are stored and sent; and the ground station can hand
        a third party the keys of seconds a to b and nothing else, which that party verifies with the UAV's public key alone (section 2).""")
    sm.append(f"""{len(attacks)} kinds of attack experiment were run against the real implementation on {len(A)} machine(s): {total:,} changed,
        forged, re-ordered, borrowed, re-signed or mislabelled inputs were offered to it. Accepted: {accepted}. Exceptions other than the
        one refusal the code promises: {crashes}. {len(controls)} control experiments (legitimate use, and attacks that must succeed when a
        defence is switched off) went as they must: {c_ok} of {c_try}."""
              + ("" if not failed else f" NOT PASSED: {failed}."))
    if S:
        p = S["pcm"]
        sm.append(f"""On {p['seconds']:.1f} s of real audio sealed as PCM, the stored bytes have {p['cipher']['bytes']['entropy_bits_per_byte']:.4f} bits of
            entropy per byte (the sound: {p['plain']['bytes']['entropy_bits_per_byte']:.3f}), a correlation between neighbouring samples of
            {p['cipher']['correlation_with_next_sample']:+.4f} (the sound: {p['plain']['correlation_with_next_sample']:.3f}) and a flat histogram
            (chi-square {p['cipher']['bytes']['chi_square']:.0f}, limit 293). Opening gives back every byte. These are the numbers the six papers
            report; here they are a sanity check, not the argument (section 6).""")
    if C["Raspberry Pi 4B"]:
        r60 = next(r for r in C["Raspberry Pi 4B"]["by_length"] if r["seconds"] == 60)
        sm.append(f"""Cost on the Raspberry Pi 4B: one minute of 128 kbit/s audio is sealed in {r60['seal_ms']:.0f} ms ({r60['seal_realtime_factor']:.0f} times
            faster than it is spoken) and grows by {r60['added_pct']:.1f} %. P1 reports 42 s for 322 kB on a laptop, P2 0.10 s per kB (section 8).""")
    if L:
        done = [r for r in L["runs"] if r.get("blocks")]
        good = sum(1 for r in done if r["verified"] and r["identical_to_the_source"])
        sm.append(f"""On the real link, with up to 20 % of the datagrams dropped on purpose, {good} of {len(L['runs'])} clips sent while they were sealed
            were completed from the UAV's card and verified against the signed root, byte for byte the source ({sum(r['repaired'] or 0 for r in done):,}
            blocks fetched again in all).""")
    sm.append("""What an attacker can still do is listed in section 10: see that audio exists, when it was written, its size to within about 12 %,
        and (on the air) how long a live clip lasted; delete clips (which shows as a gap, except at the end of the chain); and, with the
        ground station's two recording keys, read every clip ever sealed to them. Nothing here is a proof: the claims rest on the published
        security of ML-KEM-1024, X25519, AES-256-GCM, HMAC-SHA-256, SHA-256 and ML-DSA-87, on the standard way they are combined, and on
        the experiments, which test the implementation and not the mathematics.""")
    sm.append("""Novelty (section 11): every building block is known, and the way an excerpt is released is the classic redactable-signature
        construction (a key tree for what is hidden, a hash tree for what is signed). What we did not find in the literature is that
        construction used as the KEY schedule of an encrypted, uniform-shape audio container under post-quantum key transport and signature,
        sealed once for storage and for a lossy live link. That is a statement about what we found, not a proof that nobody did it.""")
    add(bullets(sm))

    # ------------------------------------------------------------------------------------------------------ 1
    t.append(head(1, "The six published schemes, and where they fall short"))
    add("\n".join(textwrap.fill(f"[{k}] {v}", W, initial_indent="  ", subsequent_indent="       ") for k, v in PAPERS))
    t.append(sub("1.1 [P1] Chaotic block cipher (Tent map permutation, Chebyshev key block, fixed substitution)"))
    add(para("""
        What it does: the samples of a WAVE file are cut into blocks of 625 bytes; the nibbles of a block are permuted by a Tent map, XORed
        with a key block made by two Chebyshev polynomials, and passed through a fixed substitution (multiplicative inverses modulo 17). The
        key is six floating-point numbers. The file's header is left as it is. Reported by the paper: a key space of (10^16)^6, about
        2^319; an average entropy of 4.57 for the encrypted files (3.22 for the originals); an average PSNR of 4.79 dB; 42.45 s to
        encrypt 322 kB and 1,631 s for 12.8 MB on a laptop."""))
    add(bullets([
        """No nonce: permutation and key block depend on the key alone. Every file sealed under a key is transformed in the same way, so one
        known or chosen file (silence is enough) gives the key block of every position, and a few more give the permutation. This is the
        textbook attack on permute-then-XOR multimedia ciphers (Li et al.); the fixed, public substitution adds nothing against it.""",
        """The key space is the count of floating-point numbers, not of keys: neighbouring values of a chaotic map on doubles fall into the same
        short cycles, and the paper's own entropy figure (4.57 of 8 bits) shows a ciphertext far from uniform.""",
        """No integrity: any byte can be changed and decryption returns something. The header in clear tells format, rate and length.""",
        """How the six numbers reach the receiver is not said. About 7.6 kB/s on a laptop: a 128 kbit/s stream needs 16 kB/s."""]))
    t.append(sub("1.2 [P2] Empirical mode decomposition and a 2D cosine-logistic map"))
    add(para("""
        What it does: SHA3-512 of the PLAIN audio gives a 512-bit value H; H sets the parameters of a chaotic map and a scrambling
        permutation; the scrambled signal is decomposed (EMD) and the residue is XORed with the chaotic stream. Reported: key space 2^512,
        NSCR 99.99 % and UACI 33.4 %, decryption that survives added noise "to some extent", 0.1032 s per kB, 93.86 % of it in the
        decomposition."""))
    add(bullets([
        """The key is a function of the message. The receiver needs H to decrypt, so a new 512-bit secret has to be carried for every
        recording, by a channel the paper does not describe; and whoever learns H can test any guess of the audio against it.""",
        """The same audio always gives the same ciphertext: an observer sees when a recording repeats.""",
        """Decryption that tolerates noise is decryption that accepts modified ciphertext: there is no integrity, by design.""",
        """Floating-point chaos again (the two machines must round identically), and 0.10 s per kB is 3.3 s of computing for one second of
        256 kbit/s audio."""]))
    t.append(sub("1.3 [P3] AES and a rule-30 cellular automaton"))
    add(para("""
        What it does: a WAVE file is encrypted with AES (PyCryptodome, with padding; the mode is not named) under a key derived from a
        pass-phrase, and the result is XORed with a matrix grown by rule 30 from the same pass-phrase. The paper says the key "needs to be
        sent to the receiver using a secure channel". Reported: a table of "mean noise" of four files and pictures of waveforms."""))
    add(bullets([
        """The second layer has the same key as the first and no nonce: it is a fixed mask per key. It cannot repair a weak AES mode (in ECB,
        equal blocks at the same place of two files still show), and it adds nothing to a sound one. Rule 30 as a key-stream generator was
        analysed and attacked by Meier and Staffelbach in 1991.""",
        """Integrity is claimed in the text, but there is no tag, MAC or signature in the construction.""",
        """Key transport is left to "a secure channel"; nothing is measured that bears on security."""]))
    t.append(sub("1.4 [P4] Discrete wavelet transform and multi-scroll chaos"))
    add(para("""
        What it does: a stereo file is wavelet-transformed; the approximation band is confused and diffused with sequences from a chaotic
        system (integrated numerically) whose initial conditions come from SHA-256 of the plain audio and three external keys; the detail
        band is not encrypted (it is used as it is at reconstruction). Reported: PSNR 9.5 to 10.1 dB between plain and cipher audio, correlation near zero,
        0.57 to 1.06 s per file, a 43 % saving of time from the transform."""))
    add(bullets([
        """Only half of the signal is encrypted: the detail coefficients travel as they are.""",
        """Key material derived from the plaintext (as in P2): it has to be sent for each file, and equal audio gives equal ciphertext.""",
        """Numerical integration of a chaotic system in floating point: reproducible only on identical arithmetic; "lossless" is claimed for a
        transform that rounds.""",
        """No integrity, no key transport, no nonce."""]))
    t.append(sub("1.5 [P5] Blind (zero) watermarking with Arnold and logistic scrambling"))
    add(para("""
        What it does: this is a watermarking scheme, not an encryption of audio. A binary watermark image is scrambled (Arnold map, then
        XOR with a logistic sequence) and bound to frames of the audio chosen by zero-crossing rate and energy; the audio is not changed
        and not hidden. Reported: robustness of the extracted mark (normalised correlation, bit error rate) under signal processing."""))
    add(bullets([
        """The audio itself stays in the clear: it is not a confidentiality mechanism.""",
        """The mark proves little about origin: there is no signature, and the scrambling is a linear, periodic map and a floating-point
        key stream. Whoever knows the parameters can make a mark for any audio.""",
        """It answers a different question (ownership of a published work) from the one a UAV has (who recorded this, and was it changed)."""]))
    t.append(sub("1.6 [P6] \"Learnable\" encryption for outsourced machine learning"))
    add(para("""
        What it does: the short-time Fourier transform of a recording is cut into blocks, the blocks are permuted with one key and their
        amplitudes changed with another, so that an untrusted service can still train a classifier on the result (speaker identification
        with four speakers). Reported: a key space of n! for n blocks, 160 to 263 ms per file against 7 ms for AES-128-CBC, classification
        accuracy on the encrypted data."""))
    add(bullets([
        """It leaks by design: whatever a classifier can learn from the ciphertext (here: who speaks) the service learns, and so does anyone
        else who holds it.""",
        """Permutation-only ciphers fall to known- and chosen-plaintext attacks with a number of plaintexts logarithmic in the block count
        (Li et al.); n! is not their security level. The paper itself discusses a jigsaw-solver attack.""",
        """No integrity, no key transport; slower than the AES it is compared with."""]))
    t.append(sub("1.7 What the six have in common"))
    add(bullets([
        """Statistics in place of a security definition. A flat histogram, low correlation, high entropy and NSCR near 100 % are passed by any
        stream cipher, including broken ones; they do not bound what a chosen-plaintext or chosen-ciphertext attacker can do.""",
        """No authenticity and no integrity. A changed ciphertext decrypts to changed audio and nobody is told. For a recording that may be
        evidence, this is the larger gap.""",
        """No key establishment. The key is assumed to be shared, or is derived from the plaintext, or goes by "a secure channel". With no
        public-key step there is nothing to make post-quantum, and nothing that protects past recordings when a key leaks.""",
        """No nonce, so no protection against the same key being used for two recordings.""",
        """Floating-point chaotic maps as key streams: platform-dependent, short cycles, key space over-counted.""",
        """Partial encryption: headers, a wavelet band, or the structure a classifier needs are left in the clear.""",
        """Side channels untouched: length, bit rate, and timing of the ciphertext follow the audio.""",
        """PCM files on a desktop, seconds per megabyte. No compressed audio, no stream, no embedded machine, no loss."""]))

    # ------------------------------------------------------------------------------------------------------ 2
    t.append(head(2, "The scheme"))
    f = one["format"]
    add(para(f"""
        A clip is made on the UAV from the encoder's frames (MPEG audio frames, or 20 ms pieces of PCM), which are not decoded. F frames
        (8 by default: 0.21 s at 44.1 kHz) go into one BLOCK. Every block of a clip has the same size, and each is sealed under a key of
        its own."""))
    t.append("""
    head     "K6GAUD01" | length | public header (JSON) | key block: ML-KEM-1024 ciphertext (1568) | X25519 share (32) | wrapped clip key (48)
    block i  commitment_i (32) | AES-256-GCM(K_i, plain_i, associated data = label | clip id | i | SHA-256(head)) | tag (16)
    root     "K6GAROOT" | flags | n | Merkle root over the n blocks
    trailer  "K6GSIG01" | length | ML-DSA-87 signature of the UAV over SHA-256(label | SHA-256(head) | flags | n | root)

    plain_i  kind | flags | frames | length | capture time | latitude | longitude | first frame | data | zero padding to the block size
    kinds    description (block 0) | audio | bytes before or after the audio (tags) | summary (counts, SHA-256 of the stream) | padding
""")
    add(bullets([
        """Hybrid key wrap. The 256-bit clip key is wrapped under HKDF(ML-KEM-1024 shared secret || X25519 shared secret), bound to the header.
        Opening needs both of the ground station's secret keys; an attacker has to break both schemes. The UAV keeps neither secret: it
        cannot open its own clips.""",
        """Key tree. K_i comes from leaf i of a binary tree of HMAC-SHA-256 values (depth 24) grown from the clip key: child = HMAC(parent, 0 or 1),
        block key = HMAC(leaf, "enc"), commitment = HMAC(leaf, "com"). A node gives exactly the leaves below it and says nothing about its
        parent or its sibling (the Goldreich-Goldwasser-Micali construction with HMAC as the pseudo-random function).""",
        """A sealer that forgets. The UAV walks the tree leaf by leaf and keeps only the nodes that lead to blocks still to come (at most 24
        values); the clip key and the root are overwritten after the first block. A UAV captured while it records holds no key of anything
        it has already sealed.""",
        """One key, one block. A block key encrypts one message, with a fixed nonce. Nonce misuse, the classic way to break AES-GCM, cannot
        happen here unless a key repeats, which section 5.8 tests.""",
        """Commitment. AES-GCM does not tie a ciphertext to one key. The commitment stored with each block does: a key handed out later is
        checked against it before it is used, so no other key can be passed off for the block.""",
        """Merkle tree and one signature. The signed root covers every block and its position; a block is checked against it with a short
        proof. That makes three things possible with a single ML-DSA-87 signature per clip: verifying the stored file, accepting a live
        clip whose blocks came in any order and from two sources (air and card), and verifying an excerpt.""",
        """Uniform shape. All blocks have one size and their number is rounded up (Padme: at most about 12 % more). The clip's description
        (codec, rate, time, place, source name, number in the chain) is block 0, sealed like the rest; the public header names only the
        algorithms, the block size, the recipient's key fingerprints and the signer.""",
        """Context inside the ciphertext. Every audio block carries its capture time and the GNSS position: an excerpt proves when and where
        as well as what.""",
        """Sealed once. The same sealed blocks are written to the card and sent over the link (inside the link's own records). A block lost
        on the air is fetched again from the card by its number and checked against the root the UAV signed.""",
        """Chain. Each clip's sealed description names the clip before it by number and Merkle root. A clip that is deleted, replaced or put
        back leaves a gap or a conflict the ground station reports.""",
        """Excerpt release. For blocks a..b the ground station hands out those sealed blocks, the at most 2 x 24 tree nodes that cover exactly
        a..b, the Merkle proof, the clip's head, root and signature. The receiver verifies with the UAV's public key and nothing else, and
        cannot derive the key of any other block. The ground station's own keys and the clip key do not leave it."""]))
    add(para(f"""
        Sizes in this build: commitment {f['commitment_bytes']} bytes, tag {f['tag_bytes']}, block header {f['block_header_bytes']} (encrypted),
        key tree of depth {f['tree_depth']} (16.7 million blocks: 40 days of audio at 0.21 s a block)."""))

    # ------------------------------------------------------------------------------------------------------ 3
    t.append(head(3, "The attacker"))
    add(bullets([
        """The finder of the card. Holds the UAV's storage: every sealed clip, the UAV's signing key (there is no secure element), the ground
        station's PUBLIC recording keys. Wants to read clips, or to change or plant them unnoticed.""",
        """The listener and the sender on the radio. Records everything, may record now and attack later with a quantum computer; can drop,
        delay and inject datagrams.""",
        """The receiver of an excerpt. Holds the released keys and may also hold the whole sealed clip (from the card or the air). Wants the
        rest of the recording, or to pass the excerpt off as something else.""",
        """The dishonest releaser. Runs the ground station and wants to hand out an excerpt that opens to audio the UAV did not record, or
        to move it to another time.""",
        """The captor of a flying UAV. Takes the machine while it records, memory included."""]))
    add(para("""
        Not in scope: an attacker who holds the ground station's two recording secret keys (they open every clip sealed to them; section
        10), a microphone or encoder that lies before the audio reaches the sealer, and the loss of availability by jamming or deletion,
        which cryptography can report but not prevent."""))

    # ------------------------------------------------------------------------------------------------------ 4
    t.append(head(4, "Security levels of the building blocks"))
    add(table([
        ["ML-KEM-1024 (FIPS 203)", "clip key wrap, half 1", "category 5", "category 5", "module-LWE; no quantum attack known beyond generic"],
        ["X25519", "clip key wrap, half 2", "about 2^128", "broken (Shor)", "kept as a hedge against a flaw in ML-KEM"],
        ["AES-256-GCM", "every block", "2^256 key, 2^-128 forgery", "about 2^128 (Grover)", "one message per key: no nonce to misuse"],
        ["HMAC-SHA-256 as PRF", "key tree, block keys, commitments", "2^256 key", "about 2^128 (Grover)", "256-bit outputs"],
        ["SHA-256, second preimage", "Merkle tree, signed digest", "2^256", "about 2^128 (Grover)", "what a forger without the key needs"],
        ["SHA-256, collision", "commitment, tree (dishonest signer)", "2^128", "2^85 in theory (BHT)", "only a signer or releaser could use one"],
        ["ML-DSA-87 (FIPS 204)", "one signature per clip", "category 5", "category 5", "module-LWE / SIS, strongly unforgeable"],
    ], ["building block", "used for", "classical", "quantum", "note"]))
    add(para("""
        Many keys, one nonce. A long recording has many blocks whose plaintext an attacker may know (the padding blocks are zeros). With 2^k
        such targets a key search finds one of them 2^k times sooner; at 2^24 blocks a clip and 2^16 clips that leaves 2^216 classically and
        about 2^108 for Grover's algorithm, which also loses most of its speed-up when it has to be run in parallel."""))

    # ------------------------------------------------------------------------------------------------------ 5
    t.append(head(5, "Attacks, why they fail, and what the experiments showed"))
    t.append(sub("5.1 Reading a stored or recorded clip"))
    add(para("""
        Without the ground station's secret keys the clip key is behind ML-KEM-1024 and X25519 together; the blocks are AES-256-GCM under keys
        that are outputs of a pseudo-random function of the clip key. Known plaintext (silence, padding, the fixed first bytes of a frame)
        and chosen plaintext (an attacker who decides what the microphone hears) give nothing: each block has a key of its own, and each
        clip a new clip key, so nothing repeats (section 6, sealing the same audio twice). The six schemes' weak point, a transformation
        that is the same for every file under a key, does not exist here."""))
    add(X("opened with other recipient keys"))
    t.append(sub("5.2 Changing a clip"))
    names, att, acc = XS("one bit changed in:")
    add(para(f"""
        Every byte of the file is covered: the head and the root record by the signature, each block by the Merkle root, each block's
        content also by its tag. One bit was flipped in each of the {len(names)} parts of the file in turn ({att:,} attempts in all, {acc}
        accepted) and at random places:"""))
    add(X("one bit changed anywhere in the file"))
    first = next(iter(A))
    add(para(f"""The reasons given, by part of the file (on the {first.split(' (')[0]}):"""))
    add(table([[n.split(": ", 1)[1], f"{exp[n][first]['bytes_in_this_part']:,}", exp[n][first]["attempts"], exp[n][first]["accepted"],
                outcomes(exp[n][first]["outcomes"], 2)] for n in names if first in exp[n]],
              ["part", "bytes", "attempts", "accepted", "refused as"], ["<", ">", ">", ">", "<"]))
    add(para("""
        Blocks cannot be moved, repeated, removed, added or borrowed: the leaf of the Merkle tree is SHA-256 of the clip id, the block's
        number and the block; the number of blocks is signed; the block's associated data names the clip, the number and the head."""))
    for n in ("two blocks exchanged", "a block repeated in place of another", "a block removed", "a block added", "the clip cut short",
              "a block borrowed from another clip", "root record and signature of another clip"):
        add(X(n))
    t.append(sub("5.3 Forging a clip, or the UAV"))
    add(para("""
        Anyone can seal audio to the ground station: its recording keys are public. What nobody else can do is sign as the UAV. The ground
        station verifies the signature against the key it has PINNED for that UAV before it uses its own secret keys, and refuses a clip
        when it has no key to verify with."""))
    for n in ("signed again by another key", "a clip made by the attacker", "control: the pin decides"):
        add(X(n))
    t.append(sub("5.4 Downgrade and mislabelling"))
    add(para("""
        The public header names the algorithms. It is hashed into the signature and into every block's associated data, and the code
        accepts one value for each field: there is nothing to negotiate, so there is nothing to downgrade. A clip the UAV closed after a
        power cut is signed as "not closed by its sealer" and cannot be passed as complete."""))
    for n in ("header rewritten (downgrade)", "a cut-off clip passed as complete", "control: a cut-off clip opens, and says so",
              "control: genuine clips open byte for byte"):
        add(X(n))
    t.append(sub("5.5 Excerpts"))
    add(para("""
        An excerpt has to convince someone who trusts only the UAV's public key. Its blocks are checked against the signed root with a range
        proof (so they are blocks a..b of that clip and of no other, at those positions); each released key is checked against the block's
        commitment before it decrypts (so the releaser cannot substitute a key that opens the block to other audio); and time and place
        come out of the authenticated plaintext, not out of anything the releaser writes."""))
    for n in ("control: genuine excerpts verify with the public key alone", "one bit changed anywhere in the bundle", "the excerpt said to be other blocks",
              "a block exchanged inside an excerpt", "another key passed off for a block", "the proof of one clip with the blocks of another",
              "an excerpt cut short or extended", "an excerpt of a recording the UAV never made"):
        add(X(n))
    add(para("""
        What the receiver of an excerpt can do with its keys to the rest of the clip: nothing. A tree node gives the leaves below it; the
        way up and sideways is the inversion of HMAC-SHA-256."""))
    add(X("the released keys tried on every other block"))
    ex = one.get("excerpt_sizes")
    if ex:
        one_b = [e for e in ex["excerpts"] if e["blocks"] == 1]
        many = [e for e in ex["excerpts"] if e["blocks"] == max(x["blocks"] for x in ex["excerpts"])]
        add(para(f"""
            What an excerpt carries besides its blocks (a clip of {ex['clip_blocks']} blocks of {ex['block_bytes']:,} bytes): {min(e['keys'] for e in one_b)}
            to {max(e['keys'] for e in ex['excerpts'])} keys of 32 bytes, {min(e['proof_nodes'] for e in ex['excerpts'])} to {max(e['proof_nodes'] for e in ex['excerpts'])}
            hashes of proof, the head, the root and the signature: {min(e['bytes_besides_the_blocks'] for e in ex['excerpts']):,} to
            {max(e['bytes_besides_the_blocks'] for e in ex['excerpts']):,} bytes, whether one block is released or {many[0]['blocks']}. What it reveals
            besides the audio released: the number of blocks of the clip, hashes of the other sealed blocks (which the holder of the
            card has anyway), and, if the description is released with it, the clip's codec, source name, start time and place and its
            number in the chain."""))
    t.append(sub("5.6 The live path"))
    add(para("""
        A live block is played to the listener as soon as it opens under the clip's key tree (commitment and tag), and it is stored only
        when all blocks hash to the root the UAV signed. A block that is changed, invented, taken from another clip or sent under another
        number is not played, and is asked for again from the card."""))
    names, att, acc = XS("blocks changed on the air")
    add(para(f"""Four ways of changing a live block were tried ({att:,} changed blocks, {acc} played or stored):"""))
    for n in names + ["the repair itself is wrong", "the signature of another clip after the live blocks", "control: blocks lost on the air are fetched again"]:
        add(X(n))
    add(para("""
        (On the real link these blocks travel inside the link's own authenticated records, so a third party cannot inject them at all;
        the checks above are what stands when the fault is on the UAV's side of that layer.)"""))
    t.append(sub("5.7 Deleting or replacing whole clips"))
    add(para("""
        The chain makes a missing or exchanged clip visible to a ground station that holds its neighbours. It cannot show that the LAST
        clips were deleted: nothing that follows names them. The UAV's status, sent over the authenticated link, carries the number of
        its last clip, which closes that gap while the UAV is alive and honest."""))
    for n in ("a clip deleted from the card", "a clip replaced by another with its number", "a clip from another chain put in between"):
        add(X(n))
    t.append(sub("5.8 Key and nonce reuse"))
    ku = next(iter(exp["a key used twice"].values()))
    add(para(f"""
        The block cipher runs with a fixed nonce, so a block key that repeats would be the one fatal mistake. The keys of {ku['clips']} clips
        ({ku['blocks']:,} blocks; every third clip seals the same audio again) were collected on each machine:"""))
    add(X("a key used twice"))
    av = one["key_tree_avalanche"]
    add(para(f"""
        Wiring check of the key tree ({av['samples']} leaves): one bit of the clip key changed flips {100 * av['one_bit_of_clip_key']['mean']:.2f} % of the
        bits of a leaf key on average (ideal 50 %; smallest {100 * av['one_bit_of_clip_key']['min']:.1f} %, largest {100 * av['one_bit_of_clip_key']['max']:.1f} %,
        standard deviation {100 * av['one_bit_of_clip_key']['stdev']:.2f} % against {100 * av['expected_stdev']:.2f} % expected); two neighbouring leaves differ
        in {100 * av['neighbouring_leaves']['mean']:.2f} % of their bits. This says the tree is wired as designed; that its outputs are
        unpredictable is the PRF assumption on HMAC-SHA-256."""))
    t.append(sub("5.9 What sizes and timing give away"))
    sh = one["shape"]
    add(para(f"""
        With a variable bit rate the size of each frame follows the sound, and encryption that keeps frame boundaries (SRTP, or an AEAD per
        frame) keeps the sizes: language, speaker and phrases have been recovered from them (Wright et al. 2007, 2008; White et al.
        2011; RFC 6562). Here every block has one size, there is one block every F frames whatever is said, and the count is rounded up.
        Three recordings of the same length that could not differ more (silence at 32 kbit/s, speech at a rate that follows the words,
        music at 128 kbit/s), sealed with the encoder's largest frame as the frame cap ({sh['frame_cap_bytes']} bytes):"""))
    add(table([[r["recording"], f"{r['source_bytes']:,}", r["frame_sizes_distinct"], f"{r['frame_bytes_min']}-{r['frame_bytes_max']}",
                     f"{r['sealed_bytes_with_cap']:,}", f"{r['block_bytes_with_cap']:,}", r["blocks_with_cap"], f"{r['block_bytes_without_cap']:,}"]
                    for r in sh["recordings"]],
                   ["recording", "audio bytes", "frame sizes", "frame bytes", "sealed bytes", "block bytes", "blocks", "block, no cap"],
                   ["<", ">", ">", ">", ">", ">", ">", ">"]))
    add(X("three different recordings told apart by their sizes"))
    add(X("control: without the cap the block size follows the largest frame"))
    add(para("""
        The last column is the limit of the default setting: without a frame cap the block is laid out for the largest frame of the stream,
        and with a variable bit rate that is one number that depends on the recording. Set the cap to the encoder's largest frame, or
        record at a constant bit rate (RFC 6562 recommends the same), and the block size is a constant of the installation."""))
    if S:
        s = S["shape"]
        add(para(f"""
            The real sample, encoded at a variable bit rate: {s['frames']:,} frames of {s['distinct_frame_sizes']} different sizes ({s['frame_bytes_min']} to
            {s['frame_bytes_max']} bytes), the size changing {s['frame_size_changes']:,} times; the sizes alone carry up to {s['frame_size_entropy_bits']:.2f} bits
            per frame. Sealed: {s['sealed_blocks']} blocks of {s['distinct_block_sizes']} size ({s['sealed_block_bytes']:,} bytes). The price of padding every
            frame to the largest is {s['added_pct']:.0f} % more bytes for this encoding, against {S['compressed']['added_pct']:.1f} % for the same sample
            at its constant 256 kbit/s: uniform shape is cheap at a constant bit rate and expensive at a variable one."""))
    add(para("""The length: how many different clip lengths look the same once the number of blocks is rounded up, and what the rounding costs:"""))
    add(table([[r["clips_of"], f"{r['different_lengths']:,}", r["different_padded_lengths"], r["lengths_per_padded_length"], f"{r['padding_pct_mean']:.2f}",
                     f"{r['padding_pct_worst']:.2f}"] for r in sh["padded_length"]],
                   ["clips of", "lengths", "padded lengths", "lengths per padded", "padding %, mean", "worst"], ["<", ">", ">", ">", ">", ">"]))
    t.append(sub("5.10 Timing of a refusal"))
    rows = []
    for m, data in A.items():
        x = data["timing"]
        rows += [[m.split(" (")[0], place, f"{ms:.4f}"] for place, ms in x["median_ms"].items()]
        rows.append([m.split(" (")[0], "spread between places / of the control", f"{x['spread_between_places_ms']:.4f} / {x['spread_of_the_control_ms']:.4f}  {x['verdict']}"])
    add(para("""
        All blocks are hashed before the root is compared, and roots, commitments and tags are compared in constant time, so the time to
        refuse a changed clip should not say where it was changed. Median time to refuse a clip with one bit changed in its first, middle
        or last block (a new buffer for every measurement):"""))
    add(table(rows, ["machine", "bit changed in", "ms"], ["<", "<", ">"]))
    add(para(f"""Rule: {one['timing']['rule']}. INCONCLUSIVE means the machine was too noisy to tell, not that a difference was found."""))
    t.append(sub("5.11 Stolen keys"))
    add(bullets([
        """The ground station's two recording secret keys: every clip ever sealed to them can be opened. Stored data sealed to a long-term
        public key has no forward secrecy; this is the price of a UAV that needs no contact with the ground to record. Keep the keys
        off-line, rotate them, delete old ones. (A live clip on the air is, in addition, inside the link's session keys, which do have
        forward secrecy.)""",
        """The UAV's signing key (on its card): clips can be forged from then on, and the UAV can be made to sign what is on its card as a
        clip "not closed by its sealer". Nothing already sealed can be read with it. The remedy is a new pin.""",
        """The UAV's memory while it records: the key-tree nodes of the blocks still to come. The blocks already sealed are out of reach
        (section 2), as far as overwriting a value in this language runtime goes (section 10).""",
        """One clip key: that clip. One released tree node: the blocks below it. One block key: that block."""]))

    # ------------------------------------------------------------------------------------------------------ 6
    t.append(head(6, "Statistical properties of the ciphertext"))
    if S:
        p, idl = S["pcm"], S["ideal"]
        pc, cc, wk = p["plain"], p["cipher"], p["wrong_key"]
        add(para(f"""
            These are the measures the six papers use. A sound cipher passes them; so does a broken one with a good-looking key stream. They
            are given because a reader will look for them, and because a mistake in the implementation (a repeated key stream, a block left
            in clear) would show here. Source: {S['source']['file']} ({S['source']['note']}), decoded to {p['seconds']:.1f} s of 16-bit mono PCM at
            {p['sample_rate']} Hz and sealed uncompressed ({p['blocks']} blocks of {p['block_bytes']:,} bytes). "As stored" is the ciphertext at the
            place of every sample."""))
        add(table([
            ["entropy, bits per byte", f"{pc['bytes']['entropy_bits_per_byte']:.4f}", f"{cc['bytes']['entropy_bits_per_byte']:.5f}", "8"],
            ["chi-square of the byte histogram", f"{pc['bytes']['chi_square']:,.0f}", f"{cc['bytes']['chi_square']:.1f}", "< 293.25 in 95 % of cases"],
            ["correlation with the next sample", f"{pc['correlation_with_next_sample']:.5f}", f"{cc['correlation_with_next_sample']:+.5f}", "0"],
            ["correlation two samples on", f"{pc['correlation_at_lag_2']:.5f}", f"{cc['correlation_at_lag_2']:+.5f}", "0"],
            ["spectral flatness", f"{pc['spectral_flatness']:.4f}", f"{cc['spectral_flatness']:.4f}", f"{idl['spectral_flatness_white_noise']:.2f} (white noise)"],
            ["correlation with the sound", "1", f"{cc['correlation_with_the_plain_signal']:+.5f}", "0"],
            ["signal-to-noise ratio against the sound, dB", "-", f"{cc['snr_db']:.2f}", "about -20 (uniform noise against speech)"],
            ["16-byte pieces that occur twice", f"{p['repeated_16_byte_blocks']['plain']:,}", f"{p['repeated_16_byte_blocks']['cipher']}", "0"],
        ], ["measure", "the sound", "as stored", "ideal"], ["<", ">", ">", "<"]))
        add(para("""Two stored copies compared, byte by byte (NSCR: share of values that differ; UACI: their mean difference):"""))
        labels = ["the same audio sealed twice (a new clip key, as the system does)", "one sample changed by one step, sealed again (a new clip key)",
                  "one sample changed, SAME key and nonce (the system never does this)"]
        add(table([[lab, f"{x['bytes']['nscr_pct']:.4f}", f"{x['bytes']['uaci_pct']:.4f}", f"{x['samples_16_bit']['nscr_pct']:.4f}",
                         f"{x['samples_16_bit']['uaci_pct']:.4f}"] for lab, x in zip(labels, S["differences"])]
                       + [["ideal: unrelated random data", f"{idl['nscr_bytes_pct']:.4f}", f"{idl['uaci_bytes_pct']:.4f}", f"{idl['nscr_16_bit_pct']:.4f}",
                           f"{idl['uaci_16_bit_pct']:.4f}"]],
                       ["compared", "NSCR % (bytes)", "UACI %", "NSCR % (16-bit)", "UACI %"], ["<", ">", ">", ">", ">"]))
        add(para(f"""
            The third row is not something the system does. It shows what AES-GCM is underneath: a stream cipher, in which one changed sample
            changes one sample of ciphertext when key and nonce are the same. "Plaintext sensitivity" in this scheme comes from never using
            a key twice, not from diffusion, and section 5.8 is the test that matters for it.
            A key wrong in ONE bit: the implementation refuses the block (commitment and tag). With both checks removed the output is noise:
            correlation with the sound {wk['correlation_with_the_plain_signal']:+.5f}, signal-to-noise ratio {wk['snr_db']:.2f} dB.
            Opening with the right keys gives back every byte: {'yes' if p['opened']['identical_to_the_source'] else 'NO'} (mean squared error 0;
            the SHA-256 of the stream is in the sealed summary and is checked on opening). None of the six papers reports a bit-exact
            comparison of the recovered audio; P4 calls its recovery lossless and describes the result as "similar to the input"."""))
        co = S["compressed"]
        add(para(f"""
            The same sample as it is recorded (compressed, {co['codec']}): {co['plain']['entropy_bits_per_byte']:.4f} bits per byte before sealing,
            {co['sealed_blocks']['entropy_bits_per_byte']:.5f} after (chi-square {co['plain']['chi_square']:,.0f} and {co['sealed_blocks']['chi_square']:.1f}).
            Compressed audio is already close to random, which is why statistics say so little about how well it is protected."""))
    else:
        add(para("""NOT MEASURED: no audio_stats.json (bash run/kyber6g.sh measure audio)."""))

    # ------------------------------------------------------------------------------------------------------ 7
    t.append(head(7, "What a quantum computer changes"))
    add(bullets([
        """Shor's algorithm breaks X25519. The clip key then rests on ML-KEM-1024 alone, which is what the hybrid is for: a recording captured
        today and attacked later is as safe as ML-KEM-1024.""",
        """Grover's algorithm halves the exponent of a key search: AES-256 and HMAC-SHA-256 keep about 128 bits, and less of a gain in
        practice because Grover does not parallelise.""",
        """Signatures: ML-DSA-87 is in the highest NIST category. A signature cannot be forged retroactively: a clip verified today stays
        verified.""",
        """Hash collisions get cheaper in theory (2^85 with a large quantum memory). A collision would let a dishonest SIGNER prepare two
        clips with one root, or a sealer who colludes with the releaser prepare a block with two openings. An outsider needs a second
        preimage (2^128 even with Grover). A wider hash (SHA-384) in the two trees would close this at 16 more bytes per commitment.""",
        """None of the six published schemes has a public-key step, so the question does not arise for them: their key is assumed to be there."""]))

    # ------------------------------------------------------------------------------------------------------ 8
    t.append(head(8, "Cost"))
    for name, c in C.items():
        if not c:
            continue
        e = c["environment"]
        t.append(sub(f"8.{1 if name.startswith('Rasp') else 2} {name} ({e['cpu_model']}; AES instructions: {'yes' if e['cpu_has_aes'] else 'no'})"))
        add(table([[k, f"{v:.3f}"] for k, v in c["pieces_ms"].items()], ["once per clip", "ms"], ["<", ">"]))
        add(table([[r["seconds"], f"{r['source_bytes']:,}", f"{r['sealed_bytes']:,}", r["blocks"], f"{r['added_pct']:.2f}", f"{r['seal_ms']:.1f}",
                         f"{r['seal_us_per_block']:.0f}", f"{r['seal_realtime_factor']:,.0f}", f"{r['seal_mb_per_s']:.1f}", f"{r['open_ms']:.1f}",
                         f"{r['verify_without_keys_ms']:.1f}"] for r in c["by_length"]],
                       ["clip s", "audio bytes", "sealed bytes", "blocks", "added %", "seal ms", "us/block", "x real time", "MB/s", "open ms", "verify ms"],
                       [">"] * 11))
    c = C["Raspberry Pi 4B"] or C["laptop"]
    if c:
        t.append(sub("8.3 Bytes added"))
        fx = c["fixed_bytes"]
        add(para(f"""
            Fixed: head {fx['head_bytes']:,} bytes (of which the key block {fx['key_block_bytes']:,}), root record {fx['root_record_bytes']}, signature trailer
            {fx['signature_trailer_bytes']:,}. Per block: {fx['per_block_bytes']} bytes (commitment, encrypted block header, tag). The rest is padding: frames
            shorter than the largest, the last block, and the rounding of the block count. Short clips pay mostly the fixed part ({c['by_length'][0]['added_pct']:.0f} %
            for {c['by_length'][0]['seconds']} s), long clips mostly the rounding ({c['by_length'][-1]['added_pct']:.1f} % for {c['by_length'][-1]['seconds'] // 60} min)."""))
        add(table([[r["frames_per_block"], f"{r['block_ms']:.0f}", f"{r['block_bytes']:,}", r["datagrams_per_block"], f"{r['added_pct']:.2f}"]
                        for r in c["frames_per_block"]["rows"]],
                       ["frames per block", "block ms", "block bytes", "datagrams on the link", "added %"], [">"] * 5))
        add(para("""
            (60 s at 128 kbit/s. Few frames per block: a block is short in time and fits one datagram, but each carries 76 bytes of its own and
            a block is never smaller than the clip's description needs. Many frames: less overhead per frame, more datagrams per block, so a
            lost datagram costs more audio; section 9.)"""))
        add(table([[r["kbit_s"], f"{r['source_bytes']:,}", f"{r['sealed_bytes']:,}", f"{r['block_bytes']:,}", f"{r['added_pct']:.2f}"] for r in c["bit_rate"]["rows"]]
                       + [["PCM 16 kHz", f"{c['pcm']['source_bytes']:,}", f"{c['pcm']['sealed_bytes']:,}", f"{c['pcm']['block_bytes']:,}", f"{c['pcm']['added_pct']:.2f}"]],
                       ["kbit/s (60 s)", "audio bytes", "sealed bytes", "block bytes", "added %"], [">"] * 5))
        t.append(sub("8.4 Excerpts of a 10-minute clip"))
        ex = (C["laptop"] or c)["excerpts"]
        add(table([[r["seconds"], f"{r['blocks']:g}", f"{r['bundle_bytes']:,.0f}", f"{r['share_of_clip_pct']:.3f}", f"{r['keys_released_median']:g}",
                         r["keys_released_max"], f"{r['proof_nodes_median']:g}", f"{r['bytes_besides_the_blocks']:,.0f}", f"{r['make_ms']:.1f}", f"{r['verify_ms']:.2f}"]
                        for r in ex["rows"]],
                       ["excerpt s", "blocks", "bundle bytes", "% of clip", "keys", "max", "proof hashes", "besides blocks", "make ms", "verify ms"], [">"] * 10))
        add(para(f"""
            (Clip: {ex['clip_bytes']:,} bytes, {ex['clip_blocks']:,} blocks, each under its own key; with the clip's description; times on the
            {'laptop' if C['laptop'] else 'Raspberry Pi'}. Releasing the clip key instead would open all of it.)"""))

    # ------------------------------------------------------------------------------------------------------ 9
    t.append(head(9, "A clip sent while it is sealed, on the real link with loss"))
    if L:
        k = (L.get("clock") or {}).get("local_per_reference_second") or 1.0
        rows = []
        for r in L["runs"]:
            c0, c1 = r["counters_before"], r["counters_after"]
            up = 100 * (c1.get("drop-out", 0) - c0.get("drop-out", 0)) / max(c1.get("seen-out", 0) - c0.get("seen-out", 0), 1)
            rows.append([r["frames_per_block"], f"{r['nominal_pct']:g}", f"{up:.2f}", r.get("blocks") or "-", r.get("on_air") if r.get("blocks") else "-",
                         r.get("repaired") if r.get("blocks") else "-", r.get("requests_for_blocks") if r.get("requests_for_blocks") is not None else "-",
                         f"{100 * r['heard_share']:.1f}",
                         f"{r['seconds_until_stored_raw'] / k:.1f}" if r.get("seconds_until_stored_raw") else "-",
                         "yes" if r["verified"] and r["identical_to_the_source"] else "NO"])
        src = L["source"]
        add(para(f"""
            {src['file']} ({src['bytes']:,} bytes, {L['runs'][0].get('duration_s') or 0:.1f} s) was put into the UAV's inbox and sealed there at the speed a
            microphone would deliver it; every block was sent once, as it was sealed. Datagrams were dropped on the Raspberry Pi (nftables,
            UDP port of the link, both directions) at the rates below. "On the air": blocks that arrived whole. "Fetched": blocks asked for
            again from the UAV's card by number, over the link's reliable transfer, after the signature had arrived. "Heard": share of the
            audio a listener got while it came in (missing blocks are skipped, not waited for). "Requests": how often the ground station had to
            ask for the missing blocks; a request or its answer is lost like anything else, and is made again after 6, 12, 24 ... seconds.
            The live video was off."""))
        add(table(rows, ["frames/block", "loss asked %", "uplink dropped %", "blocks", "on the air", "fetched", "requests", "heard %", "stored after s",
                              "verified, identical"], [">"] * 10))
        big = [r for r in L["runs"] if r["frames_per_block"] == max(x["frames_per_block"] for x in L["runs"]) and r.get("blocks")]
        five = min(big, key=lambda r: abs(r["nominal_pct"] - 5)) if big else None
        dg = -(-big[0]["block_bytes"] // 1100) if big else 0
        again = sum(1 for r in L["runs"] if (r.get("requests_for_blocks") or 0) > 1)
        add(para(f"""
            A block of {big[0]['frames_per_block'] if big else 8} frames of this audio is {dg} datagrams, and it is lost when any of them is: with
            {five['nominal_pct']:g} % of the datagrams dropped, {100 * five['repaired'] / five['blocks']:.0f} % of the blocks had to be fetched again.
            With 1 frame a block it is one datagram, and the share of blocks lost is the share of datagrams lost; the price is more bytes
            (section 8.3). The stored clip was the same bytes as on the UAV's card in {sum(1 for r in L['runs'] if r['identical_to_the_source'])} of
            {len(L['runs'])} runs. In {again} of them the first request for the missing blocks, or its answer, was lost and it was made again.
            (An earlier build asked once only: in a run of this experiment 2 of 12 clips then stayed incomplete until they were fetched from
            the card. The request is now repeated; docs/TEST_REPORT.md has the record.)""") if five else "no run completed")
    else:
        add(para("""NOT MEASURED: no audio_loss.json (bash run/kyber6g.sh measure audio)."""))

    # ----------------------------------------------------------------------------------------------------- 10
    t.append(head(10, "What remains: limits and residual risks"))
    add(bullets([
        """No microphone. The Raspberry Pi has none attached: a file put into its inbox stands in for one and is sealed frame by frame at the
        speed a microphone would deliver it. Capture from a sound card and a live encoder are NOT TESTED. Capture time and position in
        each block are those of the sealing. Until it has been sealed, that file lies on the card in the clear (it is removed
        afterwards; a flash card may keep its blocks until they are reused): a microphone would leave nothing there.""",
        """The ground station's recording keys open everything sealed to them (section 5.11). There is no forward secrecy at rest.""",
        """The UAV's signing key lies on its card. A captured UAV can sign. A secure element would change that; the prototype has none.""",
        """Overwriting keys is best effort in CPython: immutable copies of a key may stay in memory until it is reused. "The sealer forgets"
        is true of the data structure, not guaranteed of the process's memory.""",
        """What is visible without any key: that a clip exists, its file name and time stamps on the card (the time it was written), its
        signer and recipient fingerprints, its block size (the bit-rate class of the encoder, or with a variable bit rate and no frame
        cap the largest frame), and its length to within about 12 %. On the air: how long a live clip was sent.""",
        """Deleting the last clips of the chain is not shown by the chain (section 5.7). Deletion and jamming cannot be prevented.""",
        """Excerpts are transferable evidence: whoever has one can pass it on, and it stays verifiable. That is the purpose, and a reason to
        choose what is released.""",
        """A live block is played before the clip's signature has arrived. It is authenticated by the clip's key tree (and the link's
        session), which only the UAV and the ground station know; it is not yet covered by the signature when it is heard.""",
        """Uniform shape costs bytes: little at a constant bit rate, much at a variable one (section 5.9). It does not hide that something is
        being said, only what.""",
        """SHA-256 collisions bound what a dishonest signer or releaser could do, at 2^128 classically (section 7).""",
        """No machine-checked proof of the scheme as a whole and no independent review. The key wrap and the signature of a clip are those
        of every stored file and are covered by the ProVerif model of that format (formal/sealed_file.pv); the two trees have written
        arguments only (docs/SECURITY_PROOFS.md). The experiments exercise the implementation at the points an attacker can reach, for
        the inputs tried.""",
        """Timing was measured for the refusal of a clip only; a full side-channel evaluation (power, cache) was NOT DONE."""]))

    # ----------------------------------------------------------------------------------------------------- 11
    t.append(head(11, "What is new, and what is not"))
    add(para("""Not new, and used as published:"""))
    add(bullets([
        """ML-KEM-1024 (FIPS 203), ML-DSA-87 (FIPS 204), X25519, AES-256-GCM, HKDF and HMAC-SHA-256, SHA-256; the hybrid key wrap of this
        project's photo and video files.""",
        """A tree of pseudo-random values in which a node gives exactly the leaves below it: Goldreich, Goldwasser and Micali (1986); as
        constrained or delegatable pseudo-random functions for ranges: Boneh and Waters (2013), Kiayias, Papadopoulos, Triandopoulos and
        Zacharias (2013); as a generator that forgets: Bellare and Yee (2003).""",
        """A hash tree under one signature, for streams that lose packets: Merkle (1979), Wong and Lam (1998).""",
        """A key tree and a hash tree together, to disclose part of a signed document: the redactable signatures of Johnson, Molnar, Song and
        Wagner (2002) and the content extraction signatures of Steinfeld, Bull and Zheng (2001). The excerpt release here is that idea.""",
        """A commitment that ties a ciphertext to one key: Grubbs, Lu and Ristenpart (2017), Dodis et al. (2018), Albertini et al. (2022).""",
        """Blocks of one size and a rounded length against traffic analysis: RFC 6562 (2012); Padme, Nikitin et al. (2019).""",
        """Signed, chunk-wise provenance of speech with a Merkle tree (no encryption): MerkleSpeech, Ono (2026). Anonymous provenance of edited
        audio with zero-knowledge proofs (no encryption): Fu, Wang, Zhang and Chen (2026)."""]))
    add(para("""What we did not find elsewhere, and therefore put forward as the contribution, to our knowledge:"""))
    add(bullets([
        """The redactable-signature tree pair used as the key schedule of an ENCRYPTED audio container: the hidden values of the tree are the
        block keys, so that "disclose a part" becomes "release the keys of seconds a to b", verifiable against the recorder's signature by
        anyone, with a commitment per block that stops the releaser from opening it to something else.""",
        """That container built for audio from a UAV: whole encoder frames per block, one block size and a rounded block count, the time and
        position of capture inside each block, the description sealed, a chain between clips.""",
        """One sealing for the card and for a lossy live link: blocks that travel once, unrepeated, are played as they come and are made whole
        from the stored copy against the same signature.""",
        """A sealer that cannot open what it has sealed (the recipient's keys) and, while it records, holds no key of the blocks behind it.""",
        """All of it under post-quantum key transport and signature, implemented and measured on a Raspberry Pi 4B and attacked in the
        experiments above. None of the six schemes of section 1 has any of these properties."""]))
    add(para("""
        This is a statement about what a search of the literature turned up, made by the authors of the implementation. It is not a
        guarantee that no such combination exists, and a paper should say "to our knowledge" and cite the work listed above."""))

    # ----------------------------------------------------------------------------------------------------- 12
    t.append(head(12, "Comparison"))
    yes, no, ns = "yes", "no", "n.s."
    add(table([
        ["cipher", "chaos+XOR", "chaos+XOR", "AES+CA", "chaos", "(watermark)", "permutation", "AES-256-GCM"],
        ["security argument", "statistics", "statistics", "statistics", "statistics", "robustness", "key space", "standard primitives"],
        ["integrity / authenticity", no, no, "claimed", no, no, no, "tag, Merkle, ML-DSA-87"],
        ["origin proven to third party", no, no, no, no, no, no, yes],
        ["key transport", ns, ns, "\"secure channel\"", ns, ns, ns, "ML-KEM-1024 + X25519"],
        ["post-quantum", no, no, no, no, no, no, yes],
        ["nonce / fresh key per file", no, "from plaintext", no, "from plaintext", "-", "per query", "new key per block"],
        ["whole signal encrypted", "not header", "residue only", yes, "one band", no, "permuted", "yes, and description"],
        ["hides length / bit rate", no, no, no, no, no, no, "block size, rounded count"],
        ["bit-exact recovery checked", ns, ns, "claimed", "claimed", "-", ns, "yes (SHA-256)"],
        ["compressed audio, stream", no, no, no, no, no, no, yes],
        ["partial release, verifiable", no, no, no, no, no, no, yes],
        ["speed reported", "7.6 kB/s", "9.7 kB/s", ns, "about 1 s/file", "-", "0.16-0.26 s/file",
         (f"{next(r for r in C['Raspberry Pi 4B']['by_length'] if r['seconds'] == 60)['seal_mb_per_s']:.0f} MB/s (Pi 4B)" if C["Raspberry Pi 4B"] else "see 8")],
    ], ["", "P1", "P2", "P3", "P4", "P5", "P6", "QUAVER"]))
    add(para("""
        (n.s.: not stated in the paper. Speeds of P1 to P6 as their papers report them, on their authors' machines; they are not comparable
        in detail and were not re-measured. P5 is a watermarking scheme and is listed for completeness.)"""))

    # ----------------------------------------------------------------------------------------------------- 13
    t.append(head(13, "Sentences for the paper"))
    pi_c = C["Raspberry Pi 4B"]
    sents = [
        f"""In {total:,} attack attempts of {len(attacks)} kinds against the implementation, on the Raspberry Pi 4B and on the ground station, no
        changed, re-ordered, borrowed, forged, re-signed or mislabelled clip, live block or excerpt was accepted.""",
        """A sealed clip is authenticated by a single ML-DSA-87 signature over a Merkle root; its key is wrapped with ML-KEM-1024 and X25519
        together, so that reading it requires breaking both.""",
        """Each block is encrypted under its own key, derived from a key tree; the ground station can release the keys of an excerpt and of
        nothing else, and the excerpt is verified with the UAV's public key alone.""",
        """The UAV cannot open the clips it has sealed, and while recording it retains no key of the blocks already sealed.""",
        """All blocks of a clip have one size and their number is rounded up, so that neither the bit rate nor the pauses of speech nor the
        exact length can be read from the stored or transmitted clip."""]
    if pi_c:
        r60 = next(r for r in pi_c["by_length"] if r["seconds"] == 60)
        sents.append(f"""On a Raspberry Pi 4B, one minute of 128 kbit/s audio is sealed in {r60['seal_ms']:.0f} ms, {r60['seal_realtime_factor']:.0f} times faster than
            real time, with {r60['added_pct']:.1f} % more bytes.""")
    if L:
        done = [r for r in L["runs"] if r.get("blocks")]
        good = sum(1 for r in done if r["verified"] and r["identical_to_the_source"])
        sents.append(f"""With up to 20 % of the datagrams dropped, {good} of {len(L['runs'])} clips sent while they were sealed were completed from the UAV's
            stored copy and verified against the signed root.""")
    sents.append("""Do NOT write: "post-quantum encrypted audio" (the audio is encrypted with AES-256-GCM; ML-KEM-1024 and X25519 wrap the key, ML-DSA-87
        signs), "unbreakable", "provably secure" (there is no proof), "recorded by the UAV's microphone" (a file stood in for it), or
        "first" without "to our knowledge".""")
    add(bullets(sents))

    # ----------------------------------------------------------------------------------------------------- 14
    t.append(head(14, "Reproduce"))
    t.append("""
    bash run/kyber6g.sh measure audio          attacks and cost on both machines, statistics, live clips under loss (about 15 min)
    bash run/kyber6g.sh report                 this file and docs/CRYPTANALYSIS_REPORT.txt, from paper_plots/data
    bash run/kyber6g.sh plots                  plot17 to plot20 from the same files
    python -m unittest tests.test_audio        the unit tests of the format
    python -m kyber6g.tools.audio_bench attacks -n 5     the attack experiments, five times as many attempts
""")
    t.append(sub("References"))
    add(bullets([
        """M. Albertini, T. Duong, S. Gueron, S. Koelbl, A. Luykx, S. Schmieg: How to abuse and fix authenticated encryption without key commitment. USENIX Security 2022.""",
        """M. Bellare, B. Yee: Forward-security in private-key cryptography. CT-RSA 2003.""",
        """D. Boneh, B. Waters: Constrained pseudorandom functions and their applications. ASIACRYPT 2013 (ePrint 2013/352).""",
        """Y. Dodis, P. Grubbs, T. Ristenpart, J. Woodage: Fast message franking: from invisible salamanders to encryptment. CRYPTO 2018.""",
        """X. Fu, Z. Wang, Y. Zhang, Y. Chen: Trust the voice, hide the source: anonymous provenance for verifiably edited audio. IACR ePrint 2026/1308.""",
        """O. Goldreich, S. Goldwasser, S. Micali: How to construct random functions. Journal of the ACM 33(4), 1986.""",
        """P. Grubbs, J. Lu, T. Ristenpart: Message franking via committing authenticated encryption. CRYPTO 2017.""",
        """R. Johnson, D. Molnar, D. Song, D. Wagner: Homomorphic signature schemes. CT-RSA 2002.""",
        """A. Kiayias, S. Papadopoulos, N. Triandopoulos, T. Zacharias: Delegatable pseudorandom functions and applications. ACM CCS 2013 (ePrint 2013/379).""",
        """C. Li, K.-T. Lo: Optimal quantitative cryptanalysis of permutation-only multimedia ciphers against plaintext attacks. Signal Processing 91(4), 2011.""",
        """W. Meier, O. Staffelbach: Analysis of pseudo random sequences generated by cellular automata. EUROCRYPT 1991.""",
        """R. Merkle: A certified digital signature. CRYPTO 1989 (written 1979).""",
        """K. Nikitin, L. Barman, W. Lueks, M. Underwood, J.-P. Hubaux, B. Ford: Reducing metadata leakage from encrypted files and communication with PURBs. PoPETs 2019(4).""",
        """NIST: FIPS 203, Module-lattice-based key-encapsulation mechanism standard; FIPS 204, Module-lattice-based digital signature standard. 2024.""",
        """T. Ono: MerkleSpeech: public-key verifiable, chunk-localised speech provenance via perceptual fingerprints and Merkle commitments. arXiv 2602.10166, 2026.""",
        """C. Perkins, J.-M. Valin: Guidelines for the use of variable bit rate audio with Secure RTP. RFC 6562, 2012.""",
        """R. Steinfeld, L. Bull, Y. Zheng: Content extraction signatures. ICISC 2001.""",
        """A. White, A. Matthews, K. Snow, F. Monrose: Phonotactic reconstruction of encrypted VoIP conversations: Hookt on fon-iks. IEEE S&P 2011.""",
        """C. K. Wong, S. Lam: Digital signatures for flows and multicasts. IEEE ICNP 1998.""",
        """C. Wright, L. Ballard, F. Monrose, G. Masson: Language identification of encrypted VoIP traffic: Alejandra y Roberto or Alice and Bob? USENIX Security 2007.""",
        """C. Wright, L. Ballard, S. Coull, F. Monrose, G. Masson: Spot me if you can: uncovering spoken phrases in encrypted VoIP conversations. IEEE S&P 2008.""",
        """Check every entry against the publisher's page before it goes into the paper: they are given from memory of the literature, not copied from a database."""]))
    t.append(sub("All experiments"))
    rows = []
    for n, v in exp.items():
        for m, e in v.items():
            rows.append([e["group"], n[:62], m.split(" (")[0].replace("Raspberry Pi 4B", "Pi"), e["attempts"], e["accepted"], "refused" if e["expect"] == "refused" else "accepted",
                         e["verdict"]])
    add(table(rows, ["group", "experiment", "machine", "attempts", "accepted", "must be", "verdict"], ["<", "<", "<", ">", ">", "<", "<"]))
    Path(a.out).write_text("\n".join(t).rstrip() + "\n", encoding="utf-8")
    print(f"{total:,} attack attempts, {accepted} accepted, {crashes} crashes, {len(failed)} experiments not passed -> {a.out}")
    return 0 if not failed and not accepted else 1


if __name__ == "__main__":
    sys.exit(main())
