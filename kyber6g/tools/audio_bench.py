"""Sealed audio (kyber6g/audio/quaver.py) under attack, and what it costs.

    python -m kyber6g.tools.audio_bench attacks [-n 1.0] [-o audio_attacks_<host>.json]
    python -m kyber6g.tools.audio_bench cost    [-n 1.0] [-o audio_cost_<host>.json]
    python -m kyber6g.tools.audio_bench stats   --audio FILE [-o audio_stats.json]            (needs ffmpeg and numpy)
    python -m kyber6g.tools.audio_bench loss    --audio FILE [--pi kyber-pi] [--levels 0,1,2,5,10,20] [-o DIR]

attacks   Every experiment attacks the REAL code with what someone can do who holds the UAV's card, listens on the
          radio, receives an excerpt, or runs the ground station dishonestly, many times over, and counts what
          happened: how many attempts, how many were ACCEPTED (0 for an attack, all for a legitimate use), and the
          reasons the implementation gave for refusing the rest. An exception other than the one the opening functions
          promise (AudioError) counts as a crash and fails the experiment.
cost      Time to seal and to open clips of 1 s to 15 min, bytes added, the size of an excerpt, the choice of frames
          per block. Run it on the Raspberry Pi for the sealing side and on the laptop for the opening side.
stats     The numbers audio-encryption papers report (histogram, entropy, correlation of neighbouring samples, NSCR
          and UACI, signal-to-noise ratio of the cipher signal), for real audio decoded to PCM and sealed; what a
          one-bit-wrong key gives; and what the SIZES of frames give away under conventional per-frame encryption,
          against the sealed blocks. Sanity checks: a broken cipher would show here, a secure one cannot be proven here.
loss      A clip sent while it is sealed, over the real link, with datagrams dropped on the Pi (nftables): blocks
          that arrived on the air, blocks fetched again from the card, what a listener heard, the final verdict.

What such experiments can and cannot show: that the implementation does what the design says at the points an attacker
can reach, for the inputs tried. They are not a proof, and they say nothing about the hardness of ML-KEM, ML-DSA,
X25519, AES or SHA-256: that rests on the public analysis of those algorithms (docs/AUDIO_CRYPTANALYSIS_REPORT.txt).
"""
import argparse
import collections
import hashlib
import json
import math
import os
import platform
import random
import re
import shutil
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..audio import framing, quaver
from ..audio.quaver import AudioError, COMMIT, DEPTH, TAG
from ..crypto import identity as idm
from ..crypto import keyschedule as ks
from ..recording import sealing
from .bench_crypto import environment

RNG = random.Random(20261005)
KBPS = (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320)      # MPEG-1 layer III
MP3_FRAME_S = 1152 / 44100
HDR = quaver.BLOCK_HDR.size


def synth_mp3(n, rate=9, seed=1, vbr=None):
    """n MPEG-1 layer III frames (44.1 kHz) with pseudo-random content and the padding bit a real encoder sets;
    `vbr`: a function k -> bit-rate index for frame k (or a list that is cycled through)."""
    rng, out, acc = random.Random(seed), [], 0
    for k in range(n):
        r = (vbr(k) if callable(vbr) else vbr[k % len(vbr)]) if vbr else rate
        num = 144 * KBPS[r] * 1000
        acc += num % 44100
        pad = 1 if acc >= 44100 else 0
        acc -= 44100 * pad
        out.append(bytes([0xFF, 0xFB, (r << 4) | (pad << 1), 0x64]) + rng.randbytes(num // 44100 + pad - 4))
    return out


class World:
    """Keys of a UAV, of the ground station it seals for, and of an attacker (another UAV key under the same name,
    another ground station's recording keys)."""

    def __init__(self):
        self.dirs = [Path(tempfile.mkdtemp(prefix="k6g_audio_bench_")), Path(tempfile.mkdtemp(prefix="k6g_audio_attacker_"))]
        d, o = self.dirs
        self.upk, self.uav = idm.generate_identity(d, "uav"), idm.load_identity(d, "uav", b"UAV-AUDB")
        self.ek, self.dk = idm.generate_recording_kem(d), idm.load_recording_dk(d)
        self.xpk, self.xsk = idm.generate_recording_x25519(d), idm.load_recording_xsk(d)
        self.apk, self.attacker = idm.generate_identity(o, "uav"), idm.load_identity(o, "uav", b"UAV-AUDB")
        self.other_ek, self.other_dk = idm.generate_recording_kem(o), idm.load_recording_dk(o)
        self.other_xpk, self.other_xsk = idm.generate_recording_x25519(o), idm.load_recording_xsk(o)

    def seal(self, data, signer=None, **kw):
        return quaver.seal_stream(data, self.ek, self.xpk, signer or self.uav, **kw)

    def open(self, raw, dk=None, xsk=None, pk="pinned"):
        return quaver.open_audio(raw, dk or self.dk, xsk or self.xsk, self.upk if pk == "pinned" else pk)

    def cleanup(self):
        for d in self.dirs:
            shutil.rmtree(d, ignore_errors=True)


class Tally:
    def __init__(self, group, attack, what, expect="refused"):
        self.r = {"group": group, "attack": attack, "what": what, "expect": expect, "attempts": 0, "accepted": 0, "crashes": 0,
                  "outcomes": collections.Counter()}
        self.t0 = time.perf_counter()

    def note(self, outcome, accepted=False):
        self.r["attempts"] += 1
        self.r["accepted"] += bool(accepted)
        self.r["outcomes"]["ACCEPTED" if accepted else re.sub(r"\b\d+\b", "N", str(outcome))[:90]] += 1

    def attempt(self, fn, *args, accept=lambda v: True, **kw):
        """Run one attempt: AudioError is a refusal, a value that `accept` approves an acceptance, anything else a crash."""
        try:
            v = fn(*args, **kw)
        except AudioError as e:
            return self.note(e)
        except Exception as e:                                   # noqa: BLE001 - the promise is: nothing but AudioError
            self.r["crashes"] += 1
            return self.note(f"CRASH {type(e).__name__}: {e}")
        self.note("returned, but not what the attacker wanted", accepted=accept(v))

    def done(self, **more):
        self.r["outcomes"] = dict(self.r["outcomes"].most_common())
        self.r["seconds"] = round(time.perf_counter() - self.t0, 2)
        ok = self.r["accepted"] == (0 if self.r["expect"] == "refused" else self.r["attempts"]) and not self.r["crashes"]
        self.r["verdict"] = "PASS" if ok and self.r["attempts"] else "FAIL"
        self.r.update(more)
        print(f"  [{self.r['verdict']}] {self.r['attack']}: {self.r['attempts']} attempts, {self.r['accepted']} accepted"
              f"{', ' + str(self.r['crashes']) + ' CRASHES' if self.r['crashes'] else ''}  {dict(list(self.r['outcomes'].items())[:3])}", flush=True)
        return self.r


def flip(data: bytes, lo: int = 0, hi: int = None) -> bytes:
    """One bit changed, somewhere in bytes lo..hi-1."""
    b = bytearray(data)
    i = RNG.randrange(lo * 8, (len(b) if hi is None else hi) * 8)
    b[i // 8] ^= 1 << (i % 8)
    return bytes(b)


def regions(raw: bytes) -> dict:
    """The parts of a .k6gaud, as byte ranges (a list of ranges for the parts every block has)."""
    sa = quaver.SealedAudio(raw)
    jl = struct.unpack_from("!H", raw, 8)[0]
    k0, b0, S, n = 10 + jl, len(sa.head), sa.S, sa.n
    e = b0 + n * S
    blk = lambda i, a, b: (b0 + i * S + a, b0 + i * S + b)
    return {"magic and header length": [(0, 10)], "public header": [(10, k0)],
            "ML-KEM-1024 ciphertext": [(k0, k0 + sealing.KEM_CT)], "X25519 share": [(k0 + sealing.KEM_CT, k0 + sealing.KEM_CT + sealing.X_LEN)],
            "wrapped clip key": [(k0 + sealing.KEM_CT + sealing.X_LEN, b0)],
            "key commitment of a block": [blk(i, 0, COMMIT) for i in range(n)],
            "ciphertext of a block": [blk(i, COMMIT, S - TAG) for i in range(n)],
            "tag of a block": [blk(i, S - TAG, S) for i in range(n)],
            "root record: magic": [(e, e + 8)], "root record: closed-by-sealer flag": [(e + 8, e + 9)],
            "root record: number of blocks": [(e + 9, e + 13)], "root record: Merkle root": [(e + 13, e + 45)],
            "signature trailer: magic and length": [(e + 45, e + 55)], "ML-DSA-87 signature": [(e + 55, len(raw))]}


def rebuild(raw: bytes, order=None, blocks=None, trailer=None, n=None) -> bytes:
    """The clip with its blocks re-arranged (`order`: indices) or replaced (`blocks`), optionally another number of
    blocks written into the root record, optionally another root record and signature."""
    sa = quaver.SealedAudio(raw)
    h, S = len(sa.head), sa.S
    body = blocks if blocks is not None else [raw[h + i * S:h + (i + 1) * S] for i in (order if order is not None else range(sa.n))]
    tail = bytearray(trailer if trailer is not None else raw[h + sa.n * S:])
    if n is not None:
        struct.pack_into("!I", tail, 9, n)
    return raw[:h] + b"".join(body) + bytes(tail)


def sign_as(raw: bytes, signer, flags=None) -> bytes:
    """Root record and signature over the blocks of `raw` as they are, made with `signer`'s key."""
    sa = quaver.SealedAudio(raw) if flags is None else None
    head, hdr, body = quaver._split_head(raw)
    S = hdr["block"]
    n = (len(body) - 45 - sealing.trailer_len(hdr)) // S
    fr = quaver.Frontier()
    for i in range(n):
        fr.add(quaver._leaf_hash(bytes.fromhex(hdr["clip_id"]), i, body[i * S:(i + 1) * S]))
    return head + body[:n * S] + quaver.trailer_for(hashlib.sha256(head).digest(), fr, sa.flags if flags is None else flags, signer)


# ------------------------------------------------------------------------------------------------ the stored clip
def stored_attacks(w: World, n: float):
    out = []
    tagged = lambda fr: b"ID3\x03\x00\x00\x00\x00\x00\x0a" + b"\x00" * 10 + b"".join(fr) + b"TAG" + b"end".ljust(125, b"\x00")
    data = tagged(synth_mp3(96, seed=11))
    raw, rep = w.seal(data, meta={"uav": "UAV-AUDB", "clip_no": 1})
    other, _ = w.seal(tagged(synth_mp3(96, seed=12)), meta={"uav": "UAV-AUDB", "clip_no": 2})            # same UAV, same shape
    sa = quaver.SealedAudio(raw)
    N, S, h = sa.n, sa.S, len(sa.head)
    assert quaver.SealedAudio(other).n == N and quaver.SealedAudio(other).S == S
    reg = regions(raw)
    opens = lambda t, blob, **kw: t.attempt(w.open, blob, **kw)

    t = Tally("stored clip", "one bit changed anywhere in the file", "a single bit of the .k6gaud flipped at a random place, then opened at the ground station")
    for _ in range(int(600 * n)):
        opens(t, flip(raw))
    out.append(t.done(file_bytes=len(raw)))

    for name, spans in reg.items():
        t = Tally("stored clip", f"one bit changed in: {name}", f"a single bit flipped inside the {name}")
        for _ in range(max(8, int(40 * n))):
            lo, hi = RNG.choice(spans)
            opens(t, flip(raw, lo, hi))
        out.append(t.done(bytes_in_this_part=sum(b - a for a, b in spans)))

    t = Tally("stored clip", "two blocks exchanged", "blocks i and j of the clip swapped (all blocks have the same size)")
    for _ in range(int(120 * n)):
        i, j = RNG.sample(range(N), 2)
        order = list(range(N)); order[i], order[j] = order[j], order[i]
        opens(t, rebuild(raw, order))
    out.append(t.done())

    t = Tally("stored clip", "a block repeated in place of another", "block i written over block j")
    for _ in range(int(120 * n)):
        i, j = RNG.sample(range(N), 2)
        order = list(range(N)); order[j] = i
        opens(t, rebuild(raw, order))
    out.append(t.done())

    t = Tally("stored clip", "a block removed", "one block cut out; root record left as it was, or its block count lowered to match")
    for _ in range(int(60 * n)):
        i = RNG.randrange(N)
        order = [k for k in range(N) if k != i]
        opens(t, rebuild(raw, order))
        opens(t, rebuild(raw, order, n=N - 1))
    out.append(t.done())

    t = Tally("stored clip", "a block added", "a copy of a block, or random bytes of a block's size, inserted or appended; block count raised to match")
    for _ in range(int(60 * n)):
        i, at = RNG.randrange(N), RNG.randrange(N + 1)
        blocks = [raw[h + k * S:h + (k + 1) * S] for k in range(N)]
        blocks.insert(at, blocks[i] if RNG.random() < 0.5 else RNG.randbytes(S))
        opens(t, rebuild(raw, blocks=blocks))
        opens(t, rebuild(raw, blocks=blocks, n=N + 1))
    out.append(t.done())

    t = Tally("stored clip", "the clip cut short", "the file cut at a random length; and cut at a block boundary with the original root record and signature put back")
    for _ in range(int(150 * n)):
        opens(t, raw[:RNG.randrange(len(raw))])
        k = RNG.randrange(1, N)
        opens(t, rebuild(raw, list(range(k))))
        opens(t, rebuild(raw, list(range(k)), n=k))
    out.append(t.done())

    t = Tally("stored clip", "a block borrowed from another clip", "block i replaced by block i of another clip of the same UAV for the same ground station")
    for _ in range(int(120 * n)):
        i = RNG.randrange(N)
        blocks = [raw[h + k * S:h + (k + 1) * S] for k in range(N)]
        blocks[i] = other[h + i * S:h + (i + 1) * S]
        opens(t, rebuild(raw, blocks=blocks))
    out.append(t.done())

    t = Tally("stored clip", "root record and signature of another clip", "the blocks of one clip with the (genuine) root record and signature of another")
    opens(t, rebuild(raw, trailer=other[h + N * S:]))
    opens(t, rebuild(other, trailer=raw[h + N * S:]))
    opens(t, other[:h] + raw[h:])                                    # and the head of another clip
    opens(t, raw[:h] + other[h:])
    out.append(t.done())

    t = Tally("stored clip", "signed again by another key", "the attacker changes blocks and signs the result with a key of its own "
              "(with the header left alone, and with the header's signer fields rewritten to its key)")
    for _ in range(max(4, int(12 * n))):
        changed = flip(raw, h, h + N * S)
        opens(t, sign_as(changed, w.attacker))
        hj = json.loads(raw[10:10 + struct.unpack_from("!H", raw, 8)[0]])
        hj.update(sealing.signer_fields(w.attacker))
        hjb = json.dumps(hj, sort_keys=True).encode()
        forged_head = quaver.MAGIC + struct.pack("!H", len(hjb)) + hjb + raw[10 + struct.unpack_from("!H", raw, 8)[0]:h]
        opens(t, sign_as(forged_head + raw[h:], w.attacker, flags=sa.flags))
        opens(t, sign_as(raw, w.attacker))                           # nothing changed at all, only the signer
    out.append(t.done())

    t = Tally("stored clip", "a clip made by the attacker", "audio of the attacker's choice, sealed to the ground station's PUBLIC recording keys and "
              "signed with the attacker's key, under the UAV's name")
    forged = [w.seal(b"".join(synth_mp3(40, seed=100 + k)), signer=w.attacker, meta={"uav": "UAV-AUDB"})[0] for k in range(max(3, int(8 * n)))]
    for f in forged:
        opens(t, f)
        opens(t, f, pk=None)                                         # and to a station that would not check: refused all the same
    out.append(t.done())

    t = Tally("stored clip", "control: the pin decides", "the same forged clips opened by a station that had pinned the ATTACKER's key (what the pin is for)",
              expect="accepted")
    for f in forged:
        opens(t, f, pk=w.apk)
    out.append(t.done())

    t = Tally("stored clip", "opened with other recipient keys", "the genuine clip opened with another station's ML-KEM-1024 key, with another X25519 key, "
              "and with both: the key wrap needs both of the right ones")
    for _ in range(max(3, int(6 * n))):
        opens(t, raw, dk=w.other_dk)
        opens(t, raw, xsk=w.other_xsk)
        opens(t, raw, dk=w.other_dk, xsk=w.other_xsk)
    out.append(t.done())

    t = Tally("stored clip", "header rewritten (downgrade)", "fields of the public header changed: version, tree depth, block size, key-wrap name, "
              "cipher name, signature algorithm, clip id, recipient fingerprint")
    jl = struct.unpack_from("!H", raw, 8)[0]
    hdr = json.loads(raw[10:10 + jl])
    for key, value in (("v", 2), ("v", 0), ("tree", 16), ("tree", 32), ("block", S - 16), ("block", S + 16), ("kem", "ML-KEM-512"), ("kem", "X25519"),
                       ("aead", "AES-128-GCM"), ("aead", "none"), ("sig", "ML-DSA-44"), ("sig", None), ("clip_id", "00" * 16),
                       ("gcs_ek_fp", idm.fingerprint(w.other_ek)), ("hash", "MD5")):
        hj = json.dumps({**hdr, key: value}, sort_keys=True).encode()
        opens(t, quaver.MAGIC + struct.pack("!H", len(hj)) + hj + raw[10 + jl:])
    hj = json.dumps({k: v for k, v in hdr.items() if k != "sig"}, sort_keys=True).encode()            # "unsigned"
    opens(t, quaver.MAGIC + struct.pack("!H", len(hj)) + hj + raw[10 + jl:h + N * S + 45])
    out.append(t.done())

    # a clip that lost its sealer (power cut) is closed as "not closed by its sealer": it must not be passable as complete
    cut = quaver.recover(raw[:h + (N // 2) * S + 77], w.uav)
    t = Tally("stored clip", "a cut-off clip passed as complete", "the flag 'closed by its sealer' set on a clip the UAV closed after a power cut")
    b = bytearray(cut); b[h + (N // 2) * S + 8] |= quaver.CLEAN_END
    opens(t, bytes(b))
    out.append(t.done())
    t = Tally("stored clip", "control: a cut-off clip opens, and says so", "the same clip untouched: it opens, with complete = False", expect="accepted")
    t.attempt(w.open, cut, accept=lambda v: v[2]["complete"] is False and v[2]["audio_blocks"] > 0)
    out.append(t.done())

    t = Tally("stored clip", "control: genuine clips open byte for byte", "MP3 at a constant and at a variable bit rate, PCM, anything else; 1 frame to "
              "several hundred; with and without tags before and after the audio", expect="accepted")
    for k in range(max(10, int(30 * n))):
        kind = k % 4
        if kind == 0:
            d = b"".join(synth_mp3(RNG.randrange(3, 300), seed=200 + k))
        elif kind == 1:
            d = b"ID3\x03\x00\x00\x00\x00\x00\x05abcde" + b"".join(synth_mp3(RNG.randrange(3, 300), seed=300 + k, vbr=lambda i: 1 + (i * 7 + k) % 14))
        elif kind == 2:
            nb = RNG.randrange(1, 40000) * 2
            d = b"RIFF" + struct.pack("<I", 36 + nb) + b"WAVEfmt " + struct.pack("<IHHIIHH", 16, 1, 1, 16000, 32000, 2, 16) + b"data" + struct.pack("<I", nb) + RNG.randbytes(nb)
        else:
            d = RNG.randbytes(RNG.randrange(1, 9000))
        blob, _ = w.seal(d, frames_per_block=RNG.choice((1, 2, 8, 16)))
        t.attempt(w.open, blob, accept=lambda v, d=d: v[1] == d and v[2]["signature"] == "PASS" and v[2]["complete"])
    out.append(t.done())
    return out


# ------------------------------------------------------------------------------------------------------ excerpts
def excerpt_parts(bundle: bytes) -> dict:
    """Where the parts of a K6GAEX excerpt are (byte offsets), by walking it as verify_excerpt does."""
    (jl,) = struct.unpack_from("!H", bundle, 8)
    info = json.loads(bundle[10:10 + jl])
    off = 10 + jl
    (hl,) = struct.unpack_from("!I", bundle, off)
    p = {"info": (10, 10 + jl), "head": (off + 4, off + 4 + hl)}
    off += 4 + hl
    p["root"] = (off, off + 32)
    (sl,) = struct.unpack_from("!H", bundle, off + 32)
    p["signature"] = (off + 34, off + 34 + sl)
    off += 34 + sl
    p["ranges"] = []
    for lo, hi in info["ranges"]:
        nk, npf = struct.unpack_from("!HH", bundle, off)
        r = {"lo": lo, "hi": hi, "counts": (off, off + 4), "keys": [], "proof": [], "blocks": []}
        off += 4
        for _ in range(nk):
            lv, ix = struct.unpack_from("!BI", bundle, off)
            r["keys"].append({"label": (off, off + 5), "key": (off + 5, off + 37), "level": lv, "index": ix})
            off += 37
        for _ in range(npf):
            r["proof"].append((off, off + 32)); off += 32
        for _ in range(hi - lo + 1):
            r["blocks"].append((off, off + info["block"])); off += info["block"]
        p["ranges"].append(r)
    assert off == len(bundle)
    return p, info


def put(b: bytes, span, new: bytes) -> bytes:
    assert span[1] - span[0] == len(new)
    return b[:span[0]] + new + b[span[1]:]


def reinfo(bundle: bytes, info: dict) -> bytes:
    (jl,) = struct.unpack_from("!H", bundle, 8)
    ij = json.dumps(info, sort_keys=True).encode()
    return quaver.EXCERPT_MAGIC + struct.pack("!H", len(ij)) + ij + bundle[10 + jl:]


def excerpt_attacks(w: World, n: float):
    out = []
    frames = synth_mp3(400, seed=21)
    data = b"".join(frames)
    raw, _ = w.seal(data, meta={"uav": "UAV-AUDB", "clip_no": 5}, context=lambda f: (1_790_000_000_000 + f * 26, 13.1 + f * 1e-6, 80.1))
    raw2, _ = w.seal(b"".join(synth_mp3(400, seed=22)), meta={"uav": "UAV-AUDB", "clip_no": 6})
    sa = quaver.SealedAudio(raw)
    N, S, h = sa.n, sa.S, len(sa.head)
    meta, _, rep = w.open(raw)
    first, last = meta["first_audio_block"], meta["first_audio_block"] + rep["audio_blocks"] - 1
    mk = lambda r, a, b, **kw: quaver.make_excerpt(r, w.dk, w.xsk, w.upk, a, b, **kw)
    ver = lambda t, bundle, pk=None, **kw: t.attempt(quaver.verify_excerpt, bundle, w.upk if pk is None else pk, **kw)
    span = lambda: sorted(RNG.sample(range(first, last + 1), 2))

    t = Tally("excerpt", "control: genuine excerpts verify with the public key alone", "random ranges of blocks released; the receiver gets exactly those "
              "frames, their place in the clip, capture time and position", expect="accepted")
    for _ in range(int(60 * n)):
        a, b = span()
        want = b"".join(frames[(a - first) * 8:(b - first + 1) * 8])
        t.attempt(quaver.verify_excerpt, mk(raw, a, b, with_meta=RNG.random() < 0.5), w.upk,
                  accept=lambda v, want=want, a=a, b=b: v[1] == want and v[0]["signature"] == "PASS" and [x["index"] for x in v[2] if x["kind"] == quaver.AUDIO] == list(range(a, b + 1)))
    out.append(t.done())

    a, b = first + 10, first + 17
    bundle = mk(raw, a, b)
    parts, info = excerpt_parts(bundle)
    rng_part = parts["ranges"][-1]
    t = Tally("excerpt", "one bit changed anywhere in the bundle", "a single bit of a released excerpt flipped at a random place, then verified")
    for _ in range(int(500 * n)):
        ver(t, flip(bundle))
    out.append(t.done(bundle_bytes=len(bundle)))

    t = Tally("excerpt", "the excerpt said to be other blocks", "the range written in the bundle moved (with and without the labels of the keys rewritten to match): "
              "the blocks would be passed off as another part of the recording")
    for da, db in ((1, 1), (-1, -1), (8, 8), (-8, -8), (0, -1), (1, 0), (16, 16), (first - a, first - a)):
        moved = reinfo(bundle, {**info, "ranges": info["ranges"][:-1] + [[a + da, b + db]]})
        ver(t, moved)
        want = quaver.cover(a + da, b + db, DEPTH)
        if len(want) == len(rng_part["keys"]) and db - da == 0:      # the same number of key nodes: relabel them too
            (jl0,), (jl1,) = struct.unpack_from("!H", bundle, 8), struct.unpack_from("!H", moved, 8)
            for k, (lv, ix) in zip(rng_part["keys"], want):
                lo = k["label"][0] + (jl1 - jl0)
                moved = moved[:lo] + struct.pack("!BI", lv, ix) + moved[lo + 5:]
            ver(t, moved)
    ver(t, reinfo(bundle, {**info, "n": info["n"] + 1}))
    ver(t, reinfo(bundle, {**info, "n": info["n"] * 2}))
    ver(t, reinfo(bundle, {**info, "flags": info["flags"] ^ 1}))
    ver(t, reinfo(bundle, {**info, "clip_id": quaver.SealedAudio(raw2).hdr["clip_id"]}))
    ver(t, reinfo(bundle, {**info, "made": "yesterday"}))
    out.append(t.done())

    t = Tally("excerpt", "a block exchanged inside an excerpt", "one released block replaced by another block of the same clip, by the block of the same number "
              "of another clip, or by random bytes")
    for _ in range(int(80 * n)):
        sp = RNG.choice(rng_part["blocks"])
        j = RNG.choice([i for i in range(N) if not a <= i <= b])
        ver(t, put(bundle, sp, raw[h + j * S:h + (j + 1) * S]))
        k = a + rng_part["blocks"].index(sp)
        ver(t, put(bundle, sp, raw2[h + k * S:h + (k + 1) * S]))
        ver(t, put(bundle, sp, RNG.randbytes(S)))
    out.append(t.done())

    other_bundle = mk(raw2, a, b)
    oparts, _ = excerpt_parts(other_bundle)
    t = Tally("excerpt", "another key passed off for a block", "a released key replaced by a random key, by the key with one bit changed, by the key of the same "
              "place in another clip, or by another of the released keys: the block's commitment decides")
    for _ in range(int(60 * n)):
        ki = RNG.randrange(len(rng_part["keys"]))
        sp = rng_part["keys"][ki]["key"]
        ver(t, put(bundle, sp, RNG.randbytes(32)))
        ver(t, flip(bundle, *sp))
        ver(t, put(bundle, sp, other_bundle[slice(*oparts["ranges"][-1]["keys"][ki]["key"])]))
        if len(rng_part["keys"]) > 1:
            kj = RNG.choice([x for x in range(len(rng_part["keys"])) if x != ki])
            ver(t, put(bundle, sp, bundle[slice(*rng_part["keys"][kj]["key"])]))
    out.append(t.done(keys_in_this_excerpt=len(rng_part["keys"])))

    t = Tally("excerpt", "the proof of one clip with the blocks of another", "head, root and signature of clip A in front of the keys, proof and blocks of clip B, and "
              "the reverse; and the proof nodes changed")
    cut_a, cut_b = rng_part["counts"][0], oparts["ranges"][-1]["counts"][0]
    meta_a, meta_b = parts["ranges"][0]["counts"][0], oparts["ranges"][0]["counts"][0]
    ver(t, bundle[:cut_a] + other_bundle[cut_b:])
    ver(t, other_bundle[:cut_b] + bundle[cut_a:])
    ver(t, bundle[:meta_a] + other_bundle[meta_b:])
    for sp in rng_part["proof"]:
        ver(t, put(bundle, sp, RNG.randbytes(32)))
        others = [q for q in rng_part["proof"] if bundle[slice(*q)] != bundle[slice(*sp)]]       # another node of the proof in its place
        ver(t, put(bundle, sp, bundle[slice(*RNG.choice(others))]) if others else flip(bundle, *sp))
    out.append(t.done())

    t = Tally("excerpt", "an excerpt cut short or extended", "the bundle cut at a random length, bytes added at the end, a block added with the range widened to cover it")
    for _ in range(int(120 * n)):
        ver(t, bundle[:RNG.randrange(len(bundle))])
        ver(t, bundle + RNG.randbytes(RNG.randrange(1, 64)))
    ver(t, reinfo(bundle + raw[h + (b + 1) * S:h + (b + 2) * S], {**info, "ranges": info["ranges"][:-1] + [[a, b + 1]]}))
    out.append(t.done())

    t = Tally("excerpt", "an excerpt of a recording the UAV never made", "the attacker seals audio of its choice, signs it with its own key under the UAV's name and "
              "releases an excerpt of it")
    for k in range(max(3, int(8 * n))):
        f, _ = w.seal(b"".join(synth_mp3(80, seed=400 + k)), signer=w.attacker)
        ver(t, quaver.make_excerpt(f, w.dk, w.xsk, w.apk, 3, 6))
    out.append(t.done())

    # what the receiver of an excerpt can do with its keys to the REST of the clip (which it may hold: the card, the radio)
    t = Tally("excerpt", "the released keys tried on every other block", "each released key, and everything that can be derived from it (both children, the block key, "
              "the commitment key), tried on every block outside the excerpt: through the key tree, and directly as an AES-256-GCM key")
    clip_id, head_hash, plain_len = sa.clip_id, sa.head_hash, S - COMMIT - TAG
    for a2, b2 in ((first + 10, first + 17), (first + 3, first + 3), (first, first + 31), (first + 5, first + 40)):
        bun = mk(raw, a2, b2, with_meta=False)
        p2, _ = excerpt_parts(bun)
        nodes = [(k["level"], k["index"], bun[slice(*k["key"])]) for k in p2["ranges"][0]["keys"]]
        for i in [x for x in range(N) if not a2 <= x <= b2]:
            sealed = raw[h + i * S:h + (i + 1) * S]
            aad = quaver.BLOCK_AAD + clip_id + struct.pack("!I", i) + head_hash
            for lv, ix, key in nodes:
                t.attempt(quaver.open_block, quaver.KeyTree(key, DEPTH, lv, ix), clip_id, head_hash, i, sealed, plain_len)
                for cand in (key, ks.hmac256(key, b"\x00"), ks.hmac256(key, b"\x01"), *quaver.block_keys(key)):
                    def direct(cand=cand):
                        if cand == sealed[:COMMIT]:
                            return "commitment reproduced"
                        try:
                            return AESGCM(cand).decrypt(quaver.ZERO_NONCE, sealed[COMMIT:], aad)
                        except Exception:
                            raise AudioError("authentication failed") from None
                    t.attempt(direct)
    out.append(t.done(blocks_in_the_clip=N))

    # sizes: what an excerpt carries besides its blocks
    sizes = []
    for length in (1, 2, 4, 8, 16, 32, 44):
        for _ in range(6):
            a3 = RNG.randrange(first, last - length + 2)
            bun = mk(raw, a3, a3 + length - 1, with_meta=False)
            p3, _ = excerpt_parts(bun)
            sizes.append({"blocks": length, "first": a3, "bundle_bytes": len(bun), "keys": len(p3["ranges"][0]["keys"]), "proof_nodes": len(p3["ranges"][0]["proof"]),
                          "bytes_besides_the_blocks": len(bun) - length * S})
    return out, {"clip_blocks": N, "block_bytes": S, "clip_bytes": len(raw), "excerpts": sizes}


# ---------------------------------------------------------------------------------------------- live path, chain
def live_attacks(w: World, n: float):
    from ..audio.store import AudioStore
    from ..ground.audio_desk import LIVE_EXT, AudioDesk
    out = []
    tmp = Path(tempfile.mkdtemp(prefix="k6g_audio_live_"))
    w.dirs.append(tmp)
    data = b"".join(synth_mp3(160, seed=31))
    other_raw, _ = w.seal(b"".join(synth_mp3(160, seed=32)))
    osa = quaver.SealedAudio(other_raw)

    def run(kind, trial, bad_repair=False, wrong_trailer=False):
        """One clip sent while it is sealed, some of its blocks tampered with on the way. Returns what happened."""
        store = AudioStore(tmp / f"uav_{kind}_{trial}", w.ek, w.xpk, w.uav, "UAV-AUDB")
        notes, asked = [], []

        def ask_uav(cmd, args):
            asked.append(list(args["blocks"]))
            blocks = store.blocks(args["name"], args["blocks"])
            if bad_repair:
                blocks = flip(blocks)
            desk.on_blocks({"name": args["name"], "meta": {"blocks": args["blocks"], "tag": args["tag"]}}, blocks)
            return {"ok": True}
        desk = AudioDesk(tmp / f"gcs_{kind}_{trial}", w.dk, w.xsk, w.upk, lambda k, m: notes.append(m), ask_uav=ask_uav)
        (store.inbox / "voice.mp3").write_bytes(data)
        tag, sent, bad, trailer = "%08x" % RNG.getrandbits(32), {}, set(), []

        def on_block(what, i, b):
            if what == "head":
                return desk.on_head({"name": tag + ".head", "meta": {"tag": tag}}, b)
            if what != "block":
                return trailer.append(b)
            sent[i] = b
            wire, at = b, i
            if kind != "none" and i > 0 and RNG.random() < 0.2:
                bad.add(i)
                if kind == "random bytes":
                    wire = RNG.randbytes(len(b))
                elif kind == "one bit changed":
                    wire = flip(b)
                elif kind == "block of another clip":
                    wire = osa.block(i % osa.n)
                elif kind == "sent under another number":
                    wire = sent[RNG.randrange(i)]                    # an earlier block of this clip again, as block i
                elif kind == "lost":
                    return
            for k in range(0, len(wire), 1100):
                desk.on_live_chunk(LIVE_EXT.pack(b"L", bytes.fromhex(tag), at, k // 1100, -(-len(wire) // 1100)), wire[k:k + 1100])
        res = store.record("voice.mp3", on_block=on_block)
        lc = desk.live[tag]
        heard = b"".join(d for _, d in lc.played)
        desk.on_trailer({"name": tag + ".trailer", "meta": {"tag": tag, "name": res["name"], "blocks": res["blocks"]}},
                        (other_raw[len(osa.head) + osa.n * osa.S:] if wrong_trailer else trailer[0]))
        sa = quaver.SealedAudio(store.read(res["name"]))
        tree = quaver._clip_tree(sa, w.dk, w.xsk)
        good = {}
        for i in range(sa.n):
            blk = quaver.open_block(tree, sa.clip_id, sa.head_hash, i, sa.block(i), sa.S - COMMIT - TAG)
            if blk["kind"] in (quaver.AUDIO, quaver.ANCILLARY) and blk["data"]:
                good[i] = blk["data"]
        stored = desk.dir / "sealed" / res["name"]
        return {"bad": bad, "heard": heard, "good": good, "refused": lc.bad, "asked": asked, "notes": notes, "blocks": res["blocks"],
                "stored": stored.read_bytes() if stored.is_file() else None, "card": store.read(res["name"]),
                "entry": desk.clips[0] if desk.clips else {}}

    for kind in ("random bytes", "one bit changed", "block of another clip", "sent under another number"):
        t = Tally("live clip", f"blocks changed on the air: {kind}", "about one block in five of a clip that is sent while it is sealed arrives changed; "
                  "accepted = a changed block that was played to the listener or ended up in the stored clip")
        played_ok = repaired = clips_ok = 0
        for trial in range(max(3, int(8 * n))):
            r = run(kind, trial)
            # everything the listener heard must be the audio of blocks that were NOT tampered with, in order
            expect = b"".join(d for i, d in sorted(r["good"].items()) if i not in r["bad"])
            clean_stream = r["heard"] == expect
            same_as_card = r["stored"] == r["card"]
            for i in sorted(r["bad"]):
                t.note("not played; fetched again from the card and checked against the signed root", accepted=not (clean_stream and same_as_card))
            played_ok += clean_stream
            repaired += r["entry"].get("live_blocks_repaired", 0)
            clips_ok += same_as_card and r["entry"].get("decrypt") == "PASS" and r["entry"].get("signature") == "PASS"
        out.append(t.done(clips=max(3, int(8 * n)), clips_stored_identical_to_the_card=clips_ok, listener_streams_clean=played_ok, blocks_fetched_again=repaired))

    t = Tally("live clip", "the repair itself is wrong", "blocks were lost on the air and the copies fetched from the card arrive changed: the clip must not be stored")
    for trial in range(max(3, int(8 * n))):
        r = run("lost", trial, bad_repair=True)
        if r["bad"]:
            t.note("clip refused: blocks do not match the signed root", accepted=r["stored"] is not None)
    out.append(t.done())

    t = Tally("live clip", "the signature of another clip after the live blocks", "the live blocks are followed by the (genuine) root record and signature of another clip")
    for trial in range(max(3, int(6 * n))):
        r = run("none", trial, wrong_trailer=True)
        t.note("clip refused", accepted=r["stored"] is not None)
    out.append(t.done())

    t = Tally("live clip", "control: blocks lost on the air are fetched again", "about one block in five does not arrive; the clip is completed from the card "
              "and is byte for byte the card's copy", expect="accepted")
    for trial in range(max(3, int(8 * n))):
        r = run("lost", trial)
        t.note("incomplete", accepted=r["stored"] == r["card"] and r["entry"].get("decrypt") == "PASS" and
               r["entry"].get("live_blocks_repaired") == len(r["bad"]))
    out.append(t.done())
    return out


def chain_attacks(w: World, n: float):
    from ..audio.store import AudioStore
    from ..ground.audio_desk import AudioDesk
    out = []
    tmp = Path(tempfile.mkdtemp(prefix="k6g_audio_chain_"))
    w.dirs.append(tmp)
    info = lambda r: {"name": r["name"], "size": r["bytes"], "integrity": "PASS", "seconds": 0.1}

    def clips(store, k, seed):
        res = []
        for i in range(k):
            (store.inbox / f"c{i}.mp3").write_bytes(b"".join(synth_mp3(24, seed=seed + i)))
            res.append(store.record(f"c{i}.mp3"))
        return res

    t = Tally("chain of clips", "a clip deleted from the card", "one of five clips is deleted; the ground station fetches the rest. accepted = the gap was not reported")
    for trial in range(max(3, int(10 * n))):
        store = AudioStore(tmp / f"u_del_{trial}", w.ek, w.xpk, w.uav, "UAV-AUDB")
        desk = AudioDesk(tmp / f"g_del_{trial}", w.dk, w.xsk, w.upk, lambda k, m: None)
        res = clips(store, 5, 500 + 10 * trial)
        gone = RNG.randrange(1, 4)
        said = [desk.on_clip(info(r), store.read(r["name"]))["chain"] for i, r in enumerate(res) if i != gone]
        t.note(f"reported: clip {gone + 1} not fetched: cannot be checked", accepted=not any("not fetched" in s for s in said))
    out.append(t.done())

    t = Tally("chain of clips", "a clip replaced by another with its number", "the card is put back to an older state and the UAV records again: a clip number "
              "comes back with other content. accepted = no conflict reported")
    for trial in range(max(3, int(10 * n))):
        store = AudioStore(tmp / f"u_rep_{trial}", w.ek, w.xpk, w.uav, "UAV-AUDB")
        desk = AudioDesk(tmp / f"g_rep_{trial}", w.dk, w.xsk, w.upk, lambda k, m: None)
        res = clips(store, 3, 700 + 10 * trial)
        for r in res:
            desk.on_clip(info(r), store.read(r["name"]))
        chain = json.loads((store.dir / "chain.json").read_text())
        back = RNG.randrange(1, 3)                               # the card as it was after `back` clips
        for r in res[back:]:
            store.path(r["name"]).unlink()
        (store.dir / "chain.json").write_text(json.dumps({"clip_no": back, "root": res[back - 1]["root"]}))
        (store.inbox / "new.mp3").write_bytes(b"".join(synth_mp3(24, seed=900 + trial)))
        new = store.record("new.mp3")
        said = desk.on_clip(info(new), store.read(new["name"]))["chain"]
        t.note(said, accepted="CONFLICT" not in said)
        assert chain["clip_no"] == 3
    out.append(t.done())

    t = Tally("chain of clips", "a clip from another chain put in between", "a genuine clip of the same UAV that names another predecessor is given the place of a "
              "clip. accepted = the break was not reported")
    for trial in range(max(3, int(10 * n))):
        s1 = AudioStore(tmp / f"u_brk_{trial}", w.ek, w.xpk, w.uav, "UAV-AUDB")
        s2 = AudioStore(tmp / f"u_brk2_{trial}", w.ek, w.xpk, w.uav, "UAV-AUDB")
        desk = AudioDesk(tmp / f"g_brk_{trial}", w.dk, w.xsk, w.upk, lambda k, m: None)
        r1, r2 = clips(s1, 2, 1100 + 10 * trial), clips(s2, 2, 1300 + 10 * trial)
        desk.on_clip(info(r1[0]), s1.read(r1[0]["name"]))
        said = desk.on_clip(info(r2[1]), s2.read(r2[1]["name"]))["chain"]          # clip 2 of the other chain after clip 1 of this one
        t.note(said, accepted="BROKEN" not in said)
    out.append(t.done())
    return out


# -------------------------------------------------------------------------------------------- keys, shape, timing
def key_checks(w: World, n: float):
    out = []
    clips, per = max(20, int(120 * n)), 40
    commits, enc, leaves, tags, ids = set(), set(), set(), set(), set()
    total = 0
    t = Tally("keys", "a key used twice", "block keys, commitments, tree leaves and tags of many clips collected (the block cipher runs with a fixed nonce, "
              "so a repeated key would be the one fatal mistake). accepted = a value seen twice")
    for c in range(clips):
        raw, _ = w.seal(b"".join(synth_mp3(per * 8 - 5, seed=2000 + c % 3)))              # the same audio again and again: every third clip
        sa = quaver.SealedAudio(raw)
        tree = quaver._clip_tree(sa, w.dk, w.xsk)
        ids.add(sa.clip_id)
        for i in range(sa.n):
            leaf = tree.leaf(i)
            k, com = quaver.block_keys(leaf)
            blk = sa.block(i)
            assert com == blk[:COMMIT]
            for s, v in ((leaves, leaf), (enc, k), (commits, com), (tags, blk[-TAG:])):
                s.add(v)
            total += 1
    for name, s in (("tree leaves", leaves), ("block keys", enc), ("commitments", commits), ("tags", tags)):
        t.note(f"{name}: all different", accepted=len(s) != total)
    t.note("clip ids: all different", accepted=len(ids) != clips)
    t.note("no value serves in two roles", accepted=bool((leaves & enc) | (leaves & commits) | (enc & commits)))
    out.append(t.done(clips=clips, blocks=total))

    # the key tree: one bit of the clip key changed -> every leaf changes in about half of its bits; neighbours unrelated
    dist, sib = [], []
    for _ in range(max(40, int(200 * n))):
        key = RNG.randbytes(32)
        a, b = quaver.KeyTree(key), quaver.KeyTree(flip(key))
        for i in (0, 1, 2, RNG.randrange(1 << DEPTH)):
            la, lb = a.leaf(i), b.leaf(i)
            dist.append(bin(int.from_bytes(la, "big") ^ int.from_bytes(lb, "big")).count("1") / 256)
        l0, l1 = quaver.KeyTree(key).leaf(6), quaver.KeyTree(key).leaf(7)
        sib.append(bin(int.from_bytes(l0, "big") ^ int.from_bytes(l1, "big")).count("1") / 256)
    avalanche = {"what": "share of the 256 bits of a leaf key that change when ONE bit of the clip key changes (ideal 0.5), and the share of bits in which two "
                         "neighbouring leaves differ (ideal 0.5). A sanity check of the wiring, not a proof: the tree is HMAC-SHA-256 used as a PRF",
                 "samples": len(dist), "one_bit_of_clip_key": {"mean": round(statistics.fmean(dist), 4), "min": round(min(dist), 4), "max": round(max(dist), 4),
                                                              "stdev": round(statistics.pstdev(dist), 4)},
                 "neighbouring_leaves": {"mean": round(statistics.fmean(sib), 4), "min": round(min(sib), 4), "max": round(max(sib), 4)},
                 "expected_stdev": round(0.5 / math.sqrt(256), 4)}
    return out, avalanche


def shape_checks(w: World, n: float):
    """What someone sees who holds the card or listens on the radio: sizes. Three recordings of the same length that
    could not differ more (silence at the lowest rate, speech with a rate that follows it, music at the highest rate)."""
    out = []
    frames_n = 1150                                                  # 30 s
    speech = lambda k: (1, 1, 1, 3, 6, 9, 9, 8, 6, 4, 2, 1)[(k // 9) % 12]        # words and pauses, as a variable-rate encoder writes them
    streams = {"silence (32 kbit/s frames)": synth_mp3(frames_n, rate=1, seed=41),
               "speech (variable rate, 32-128 kbit/s)": synth_mp3(frames_n, seed=42, vbr=speech),
               "music (128 kbit/s frames)": synth_mp3(frames_n, rate=9, seed=43)}
    cap = 144 * 128000 // 44100 + 1                                  # the largest frame of an encoder limited to 128 kbit/s
    rows = []
    for name, fr in streams.items():
        data = b"".join(fr)
        capped, rc = w.seal(data, frame_cap=cap)
        free, rf = w.seal(data)
        sa = quaver.SealedAudio(capped)
        rows.append({"recording": name, "source_bytes": len(data), "frame_sizes_distinct": len({len(f) for f in fr}),
                     "frame_bytes_min": min(map(len, fr)), "frame_bytes_max": max(map(len, fr)),
                     "sealed_bytes_with_cap": len(capped), "block_bytes_with_cap": sa.S, "blocks_with_cap": sa.n,
                     "block_sizes_distinct_with_cap": len({len(sa.block(i)) for i in range(sa.n)}),
                     "sealed_bytes_without_cap": len(free), "block_bytes_without_cap": rf["block_bytes"],
                     "per_frame_encryption_bytes": len(data) + 16 * len(fr),          # a tag per frame, lengths as they are
                     "first_frames": [len(f) for f in fr[:240]]})
    t = Tally("shape", "three different recordings told apart by their sizes", "silence, speech and music of the same length, the encoder's largest frame set as "
              "the cap: file size, block size and number of blocks compared. accepted = any of them differs")
    for key in ("sealed_bytes_with_cap", "block_bytes_with_cap", "blocks_with_cap"):
        t.note(f"{key}: the same for all three", accepted=len({r[key] for r in rows}) != 1)
    t.note("every block of every clip has one size", accepted=any(r["block_sizes_distinct_with_cap"] != 1 for r in rows))
    out.append(t.done())
    t = Tally("shape", "control: without the cap the block size follows the largest frame", "the same three recordings sealed with no cap set: the block size is "
              "that of the largest frame of each stream, so silence shows as smaller blocks (documented; set the cap)", expect="accepted")
    t.note("block sizes differ", accepted=len({r["block_bytes_without_cap"] for r in rows}) > 1)
    out.append(t.done())

    # the length: Padme. How many different clip lengths (in blocks) look the same, and what it costs
    padme = []
    for lo, hi, label in ((1, 58, "up to 12 s"), (58, 288, "12 s to 1 min"), (288, 2872, "1 to 10 min"), (2872, 17227, "10 min to 1 h")):
        seen = {quaver.padme(k + 2) for k in range(lo, hi)}          # + description and summary blocks
        worst = max((quaver.padme(k + 2) - (k + 2)) / (k + 2) for k in range(lo, hi))
        mean = statistics.fmean((quaver.padme(k + 2) - (k + 2)) / (k + 2) for k in range(lo, hi))
        padme.append({"clips_of": label, "audio_blocks_from": lo, "to": hi - 1, "different_lengths": hi - lo, "different_padded_lengths": len(seen),
                      "lengths_per_padded_length": round((hi - lo) / len(seen), 1), "padding_pct_worst": round(100 * worst, 2), "padding_pct_mean": round(100 * mean, 2)})
    return out, {"what": "30 s of MPEG-1 layer III at 44.1 kHz, three kinds of content; frames per block 8; cap = the largest frame at 128 kbit/s",
                 "frame_cap_bytes": cap, "recordings": rows, "padded_length": padme}


def timing_checks(w: World, n: float):
    """Does the time to refuse a changed clip depend on WHERE it was changed? (All blocks are hashed before the root is
    compared, in constant time; a commitment is compared in constant time.)"""
    raw, _ = w.seal(b"".join(synth_mp3(2000, seed=51)))
    sa = quaver.SealedAudio(raw)
    h, S, N = len(sa.head), sa.S, sa.n
    spots = {"first block": h + 40, "middle block": h + (N // 2) * S + 40, "last block": h + (N - 1) * S + 40}
    places = {**spots, "first block (again: the control)": spots["first block"]}

    def variant(p):
        # A buffer of its own for every measurement. With one buffer per place, kept for all runs, the places differed
        # by up to 10 % on the laptop and in the other direction on the Pi while the same buffer measured twice agreed to
        # 0.3 %: where a megabyte lies in memory decides how fast it is hashed, and that was taken for a property of the place.
        b = bytearray(raw)
        b[p] ^= 1
        return bytes(b)
    times = {k: [] for k in places}
    reps = max(15, int(60 * n))
    order = list(places)
    for _ in range(reps):
        RNG.shuffle(order)
        for k in order:
            v = variant(places[k])
            t0 = time.perf_counter_ns()
            try:
                quaver.SealedAudio(v).verify(w.upk)
                raise SystemExit("a changed clip verified")
            except AudioError:
                pass
            times[k].append((time.perf_counter_ns() - t0) / 1e6)
    med = {k: round(statistics.median(v), 4) for k, v in times.items()}
    ctrl = abs(med["first block"] - med["first block (again: the control)"])
    spread = max(med[k] for k in spots) - min(med[k] for k in spots)
    ok = spread <= max(0.1 * statistics.median(med.values()), 3 * ctrl)
    return {"what": "time to refuse a clip (signature and Merkle check) with one bit changed in its first, middle or last block, a new buffer for every "
                    "measurement; the first place measured as a second series gives the noise of this machine",
            "clip_blocks": N, "runs_each": reps, "median_ms": med, "spread_between_places_ms": round(spread, 4),
            "spread_of_the_control_ms": round(ctrl, 4), "verdict": "PASS" if ok else "INCONCLUSIVE",
            "rule": "PASS when the spread between the places is at most 10 % of the median or three times the spread of the control"}


def attacks(a):
    w = World()
    t0 = time.time()
    out = {"tool": "kyber6g.tools.audio_bench attacks", "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0)), "scale": a.n,
           "environment": environment(), "format": {"magic": quaver.MAGIC.decode(), "excerpt_magic": quaver.EXCERPT_MAGIC.decode(), "tree_depth": DEPTH,
                                                    "commitment_bytes": COMMIT, "tag_bytes": TAG, "block_header_bytes": HDR}}
    try:
        print("stored clip"); res = stored_attacks(w, a.n)
        print("excerpt"); ex, out["excerpt_sizes"] = excerpt_attacks(w, a.n)
        print("live clip"); lv = live_attacks(w, a.n)
        print("chain of clips"); ch = chain_attacks(w, a.n)
        print("keys"); kk, out["key_tree_avalanche"] = key_checks(w, a.n)
        print("shape"); sh, out["shape"] = shape_checks(w, a.n)
        print("timing"); out["timing"] = timing_checks(w, a.n)
        out["experiments"] = res + ex + lv + ch + kk + sh
    finally:
        w.cleanup()
    ex_ = out["experiments"]
    att = [e for e in ex_ if e["expect"] == "refused"]
    out["summary"] = {"experiments": len(ex_), "attack_experiments": len(att), "attack_attempts": sum(e["attempts"] for e in att),
                      "attacks_accepted": sum(e["accepted"] for e in att), "crashes": sum(e["crashes"] for e in ex_),
                      "controls": len(ex_) - len(att), "control_attempts": sum(e["attempts"] for e in ex_ if e["expect"] == "accepted"),
                      "controls_accepted": sum(e["accepted"] for e in ex_ if e["expect"] == "accepted"),
                      "failed": [e["attack"] for e in ex_ if e["verdict"] != "PASS"], "timing": out["timing"]["verdict"],
                      "seconds": round(time.time() - t0, 1)}
    Path(a.out).write_text(json.dumps(out))
    s = out["summary"]
    print(f"\n{s['attack_experiments']} attack experiments, {s['attack_attempts']} attempts, {s['attacks_accepted']} accepted, {s['crashes']} crashes; "
          f"{s['controls']} controls, {s['controls_accepted']} of {s['control_attempts']} accepted; timing {s['timing']}; failed: {s['failed']}\n-> {a.out}")
    return 0 if not s["failed"] else 1


# ----------------------------------------------------------------------------------------------------------- cost
def med(fn, reps):
    v = []
    for _ in range(reps):
        t0 = time.perf_counter_ns()
        r = fn()
        v.append((time.perf_counter_ns() - t0) / 1e6)
    return round(statistics.median(v), 4), r


def cost(a):
    w = World()
    t0 = time.time()
    out = {"tool": "kyber6g.tools.audio_bench cost", "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0)), "environment": environment(),
           "what": "synthetic MPEG-1 layer III frames, 128 kbit/s at 44.1 kHz (26.1 ms a frame), unless said otherwise; 8 frames a block; times are medians"}
    try:
        fixed = {"head_bytes": None, "root_record_bytes": 45, "signature_trailer_bytes": 10 + 4627, "per_block_bytes": COMMIT + HDR + TAG,
                 "key_block_bytes": sealing.block_len(True)}
        # the pieces
        hj = b"{}"
        wrap_ms, (cek, kb) = med(lambda: sealing.wrap(quaver.MAGIC, quaver.KEK_LABEL, b"\x00" * 16, hj, w.ek, w.xpk), max(15, int(60 * a.n)))
        unwrap_ms, _ = med(lambda: sealing.unwrap(quaver.MAGIC, quaver.KEK_LABEL, b"\x00" * 16, hj, kb, w.dk, w.xsk), max(15, int(60 * a.n)))
        digest = hashlib.sha256(b"x").digest()
        sign_ms, tr = med(lambda: sealing.sign_trailer(b"audio", digest, w.uav), max(15, int(60 * a.n)))
        verify_ms, _ = med(lambda: idm.verify("ML-DSA-87", sealing.SIG_LABEL + b"audio|" + digest, tr[10:], w.upk), max(15, int(60 * a.n)))
        out["pieces_ms"] = {"hybrid key wrap (ML-KEM-1024 encapsulation + X25519 + AES-GCM), once per clip": wrap_ms,
                            "hybrid key unwrap, once per clip": unwrap_ms, "ML-DSA-87 signature, once per clip": sign_ms,
                            "ML-DSA-87 verification, once per clip or excerpt": verify_ms}
        rows = []
        for seconds in (1, 5, 15, 60, 300, 900):
            frames = synth_mp3(max(3, round(seconds / MP3_FRAME_S)), seed=60)
            data = b"".join(frames)
            reps = max(3, int((9 if seconds <= 60 else 3) * a.n))
            inner = []                                           # the blocks alone (cipher, key tree, hashing), as the sealer times them

            def seal_once():
                r = w.seal(data)
                inner.append(r[1]["seal_ms"])
                return r
            seal_ms, (raw, rep) = med(seal_once, reps)
            blocks_ms = statistics.median(inner)
            open_ms, _ = med(lambda: w.open(raw), reps)
            verify_only_ms, _ = med(lambda: quaver.SealedAudio(raw).verify(w.upk), reps)
            sa = quaver.SealedAudio(raw)
            fixed["head_bytes"] = len(sa.head)
            rows.append({"seconds": seconds, "frames": len(frames), "source_bytes": len(data), "sealed_bytes": len(raw), "blocks": sa.n,
                         "audio_blocks": rep["audio_blocks"], "block_bytes": sa.S, "added_pct": round(100 * (len(raw) - len(data)) / len(data), 2),
                         "seal_ms": seal_ms, "seal_blocks_only_ms": round(blocks_ms, 3), "seal_us_per_block": round(1000 * blocks_ms / sa.n, 2),
                         "open_ms": open_ms, "verify_without_keys_ms": verify_only_ms,
                         "seal_realtime_factor": round(seconds * 1000 / seal_ms, 1), "seal_mb_per_s": round(len(data) / 1e6 / (seal_ms / 1000), 1),
                         "open_mb_per_s": round(len(data) / 1e6 / (open_ms / 1000), 1)})
            print(f"  {seconds:4d} s: {len(data):9d} -> {len(raw):9d} B (+{rows[-1]['added_pct']:.2f} %), {sa.n} blocks; seal {seal_ms:.1f} ms "
                  f"({rows[-1]['seal_realtime_factor']:.0f}x real time), open {open_ms:.1f} ms", flush=True)
        out["fixed_bytes"], out["by_length"] = fixed, rows
        # frames per block: how long a block is, what it adds, how many datagrams it is on the link
        data = b"".join(synth_mp3(round(60 / MP3_FRAME_S), seed=61))
        fpb = []
        for F in (1, 2, 4, 8, 16, 32):
            seal_ms, (raw, rep) = med(lambda: w.seal(data, frames_per_block=F), max(3, int(5 * a.n)))
            sa = quaver.SealedAudio(raw)
            fpb.append({"frames_per_block": F, "block_ms": round(F * MP3_FRAME_S * 1000, 1), "block_bytes": sa.S, "blocks": sa.n,
                        "datagrams_per_block": -(-sa.S // 1100), "added_pct": round(100 * (len(raw) - len(data)) / len(data), 2), "seal_ms": seal_ms})
        out["frames_per_block"] = {"what": "60 s at 128 kbit/s", "rows": fpb}
        # bit rate
        br = []
        for idx in (5, 9, 13, 14):
            d = b"".join(synth_mp3(round(60 / MP3_FRAME_S), rate=idx, seed=62))
            raw, rep = w.seal(d)
            br.append({"kbit_s": KBPS[idx], "source_bytes": len(d), "sealed_bytes": len(raw), "block_bytes": rep["block_bytes"],
                       "added_pct": round(100 * (len(raw) - len(d)) / len(d), 2)})
        out["bit_rate"] = {"what": "60 s, 8 frames per block", "rows": br}
        # PCM
        nb = 16000 * 2 * 60
        wav = b"RIFF" + struct.pack("<I", 36 + nb) + b"WAVEfmt " + struct.pack("<IHHIIHH", 16, 1, 1, 16000, 32000, 2, 16) + b"data" + struct.pack("<I", nb) + RNG.randbytes(nb)
        seal_ms, (raw, rep) = med(lambda: w.seal(wav), max(3, int(5 * a.n)))
        open_ms, _ = med(lambda: w.open(raw), max(3, int(5 * a.n)))
        out["pcm"] = {"what": "60 s of 16-bit mono PCM at 16 kHz (a microphone read without a codec)", "source_bytes": len(wav), "sealed_bytes": len(raw),
                      "block_bytes": rep["block_bytes"], "blocks": rep["blocks"], "added_pct": round(100 * (len(raw) - len(wav)) / len(wav), 2),
                      "seal_ms": seal_ms, "open_ms": open_ms}
        # excerpts of a 10-minute clip
        long_raw, _ = w.seal(b"".join(synth_mp3(round(600 / MP3_FRAME_S), seed=63)))
        meta, _, rep = w.open(long_raw)
        sa = quaver.SealedAudio(long_raw)
        ex = []
        for seconds in (1, 5, 15, 60, 300):
            sizes = []
            for _ in range(max(5, int(12 * a.n))):
                t_a = RNG.uniform(0, 600 - seconds)
                lo, hi = quaver.blocks_for_time(meta, rep["audio_blocks"], t_a, t_a + seconds)
                make_ms, bun = med(lambda: quaver.make_excerpt(long_raw, w.dk, w.xsk, w.upk, lo, hi, with_meta=True), 1)
                ver_ms, v = med(lambda: quaver.verify_excerpt(bun, w.upk), 1)
                p, _ = excerpt_parts(bun)
                sizes.append({"blocks": hi - lo + 1, "bundle_bytes": len(bun), "keys": sum(len(r["keys"]) for r in p["ranges"]),
                              "proof_nodes": sum(len(r["proof"]) for r in p["ranges"]), "make_ms": make_ms, "verify_ms": ver_ms,
                              "bytes_besides_the_blocks": len(bun) - (hi - lo + 2) * sa.S})
            m = lambda k: round(statistics.median(s[k] for s in sizes), 3)
            ex.append({"seconds": seconds, "blocks": m("blocks"), "bundle_bytes": m("bundle_bytes"), "share_of_clip_pct": round(100 * m("bundle_bytes") / len(long_raw), 3),
                       "keys_released_median": m("keys"), "keys_released_max": max(s["keys"] for s in sizes), "proof_nodes_median": m("proof_nodes"),
                       "bytes_besides_the_blocks": m("bytes_besides_the_blocks"), "make_ms": m("make_ms"), "verify_ms": m("verify_ms")})
        out["excerpts"] = {"what": "excerpts of a 10-minute clip (with the clip's description), at random places", "clip_bytes": len(long_raw), "clip_blocks": sa.n,
                           "keys_in_the_clip": sa.n, "rows": ex}
    finally:
        w.cleanup()
    out["seconds"] = round(time.time() - t0, 1)
    Path(a.out).write_text(json.dumps(out))
    print(f"pieces: {out['pieces_ms']}\n-> {a.out}")
    return 0


# ---------------------------------------------------------------------------------------------------------- stats
def ffmpeg(*args):
    r = subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"ffmpeg failed: {r.stderr.strip()[:300]}")


def stats(a):
    import numpy as np
    w = World()
    t0 = time.time()
    src = Path(a.audio)
    tmp = Path(tempfile.mkdtemp(prefix="k6g_audio_stats_"))
    w.dirs.append(tmp)
    try:
        ffmpeg("-i", str(src), "-ac", "1", "-c:a", "pcm_s16le", str(tmp / "plain.wav"))
        wav = (tmp / "plain.wav").read_bytes()
        fmt, prefix, frames, suffix = framing.split(wav)
        sr = fmt["sample_rate"]
        sealed, rep = w.seal(wav)
        sa = quaver.SealedAudio(sealed)
        tree = quaver._clip_tree(sa, w.dk, w.xsk)
        plain_len = sa.S - COMMIT - TAG
        P, C, W, keys = [], [], [], []

        def ctr(key, ct):                                    # the cipher stream of AES-256-GCM without its tag check (data counter starts at 2)
            dec = Cipher(algorithms.AES(key), modes.CTR(quaver.ZERO_NONCE + (2).to_bytes(4, "big"))).decryptor()
            return dec.update(ct) + dec.finalize()
        for i in range(sa.n):
            b = quaver.open_block(tree, sa.clip_id, sa.head_hash, i, sa.block(i), plain_len)
            if b["kind"] != quaver.AUDIO:
                continue
            ct = sa.block(i)[COMMIT:COMMIT + plain_len]
            key, _ = quaver.block_keys(tree.leaf(i))
            assert ctr(key, ct)[HDR:HDR + len(b["data"])] == b["data"], "the counter-mode view of GCM does not reproduce the audio"
            P.append(b["data"]); C.append(ct[HDR:HDR + len(b["data"])])
            W.append(ctr(bytes([key[0] ^ 1]) + key[1:], ct)[HDR:HDR + len(b["data"])])           # a key wrong in ONE bit
        P, C, W = b"".join(P), b"".join(C), b"".join(W)
        assert P == b"".join(frames)
        x, c, wk = (np.frombuffer(v, dtype="<i2").astype(np.float64) for v in (P, C, W))
        meta, stream, orep = w.open(sealed)

        def byte_stats(buf):
            h = np.bincount(np.frombuffer(buf, dtype=np.uint8), minlength=256).astype(np.float64)
            p = h[h > 0] / h.sum()
            e = h.sum() / 256
            return {"bytes": len(buf), "entropy_bits_per_byte": round(float(-(p * np.log2(p)).sum()), 6), "chi_square": round(float(((h - e) ** 2 / e).sum()), 1),
                    "histogram": [int(v) for v in h]}

        def sample_stats(s):
            hist, _ = np.histogram(s, bins=128, range=(-32768, 32768))
            frames_ = s[:len(s) // 1024 * 1024].reshape(-1, 1024) * np.hanning(1024)
            pw = np.abs(np.fft.rfft(frames_, axis=1)) ** 2 + 1e-9
            flat = np.exp(np.mean(np.log(pw), axis=1)) / np.mean(pw, axis=1)
            return {"samples": int(s.size), "mean": round(float(s.mean()), 2), "rms": round(float(np.sqrt(np.mean(s ** 2))), 2),
                    "correlation_with_next_sample": round(float(np.corrcoef(s[:-1], s[1:])[0, 1]), 6),
                    "correlation_at_lag_2": round(float(np.corrcoef(s[:-2], s[2:])[0, 1]), 6),
                    "spectral_flatness": round(float(np.mean(flat)), 5), "histogram_128_bins": [int(v) for v in hist]}

        def against_plain(s):
            mse = float(np.mean((x - s) ** 2))
            return {"correlation_with_the_plain_signal": round(float(np.corrcoef(x, s)[0, 1]), 6), "mean_squared_error": round(mse, 1),
                    "snr_db": round(float(10 * np.log10(np.sum(x ** 2) / np.sum((x - s) ** 2))), 3),
                    "psnr_db": round(float(10 * np.log10(32767.0 ** 2 / mse)), 3)}

        def difference(b1, b2):
            u1, u2 = np.frombuffer(b1, dtype=np.uint8).astype(np.int16), np.frombuffer(b2, dtype=np.uint8).astype(np.int16)
            s1, s2 = np.frombuffer(b1, dtype="<u2").astype(np.int64), np.frombuffer(b2, dtype="<u2").astype(np.int64)
            return {"bytes": {"nscr_pct": round(float(100 * np.mean(u1 != u2)), 4), "uaci_pct": round(float(100 * np.mean(np.abs(u1 - u2)) / 255), 4)},
                    "samples_16_bit": {"nscr_pct": round(float(100 * np.mean(s1 != s2)), 5), "uaci_pct": round(float(100 * np.mean(np.abs(s1 - s2)) / 65535), 4)},
                    "values_that_differ": int(np.sum(u1 != u2)), "values": int(u1.size)}

        def cipher_of(blob):
            s = quaver.SealedAudio(blob)
            tr = quaver._clip_tree(s, w.dk, w.xsk)
            out_ = []
            for i in range(s.n):
                b = quaver.open_block(tr, s.clip_id, s.head_hash, i, s.block(i), plain_len)
                if b["kind"] == quaver.AUDIO:
                    out_.append(s.block(i)[COMMIT + HDR:COMMIT + HDR + len(b["data"])])
            return b"".join(out_)

        def envelope(s, bins=900):
            k = len(s) // bins
            m = s[:k * bins].reshape(bins, k)
            return [[int(v) for v in m.min(axis=1)], [int(v) for v in m.max(axis=1)]]

        def spectrogram(s, fbins=72, tbins=260):
            n = 1024
            fr = s[:len(s) // n * n].reshape(-1, n) * np.hanning(n)
            tbins = min(tbins, fr.shape[0])
            pw = np.abs(np.fft.rfft(fr, axis=1))[:, :504] ** 2
            pw = pw.reshape(pw.shape[0], fbins, -1).mean(axis=2)
            k = pw.shape[0] // tbins
            pw = pw[:k * tbins].reshape(tbins, k, fbins).mean(axis=1)
            db = 10 * np.log10(pw + 1e-9)
            return [[round(float(v), 1) for v in row] for row in db.T]          # [frequency][time]

        again = cipher_of(w.seal(wav)[0])
        changed = bytearray(wav)
        pos = len(prefix) + (len(P) // 4) * 2                         # one sample in the middle, by one step
        changed[pos] ^= 1
        one_bit = cipher_of(w.seal(bytes(changed))[0])
        key = RNG.randbytes(32)
        g1 = AESGCM(key).encrypt(quaver.ZERO_NONCE, P, b"")[:-16]
        g2 = AESGCM(key).encrypt(quaver.ZERO_NONCE, bytes(changed[len(prefix):len(prefix) + len(P)]), b"")[:-16]
        blocks16 = [C[k:k + 16] for k in range(0, len(C) - 15, 16)]
        plain16 = [P[k:k + 16] for k in range(0, len(P) - 15, 16)]
        out = {"tool": "kyber6g.tools.audio_bench stats", "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t0)), "environment": environment(),
               "source": {"file": src.name, "bytes": src.stat().st_size, "sha256": hashlib.sha256(src.read_bytes()).hexdigest(), "note": a.source_note},
               "ideal": {"entropy_bits_per_byte": 8.0, "chi_square_5pct_limit": 293.25, "nscr_bytes_pct": 100 * 255 / 256,
                         "uaci_bytes_pct": 100 * (256 ** 2 - 1) / (3 * 256 * 255), "nscr_16_bit_pct": 100 * (1 - 2 ** -16),
                         "uaci_16_bit_pct": 100 * (65536 ** 2 - 1) / (3 * 65536 * 65535), "correlation": 0.0, "spectral_flatness_white_noise": 0.56},
               "pcm": {"what": "the source decoded to 16-bit mono PCM and sealed (PCM frames of 20 ms, 8 a block); 'cipher' is the ciphertext at the place of every sample",
                       "sample_rate": sr, "seconds": round(len(x) / sr, 2), "sealed_bytes": len(sealed), "source_bytes": len(wav), "blocks": sa.n, "block_bytes": sa.S,
                       "plain": {**sample_stats(x), "bytes": byte_stats(P)}, "cipher": {**sample_stats(c), "bytes": byte_stats(C), **against_plain(c)},
                       "wrong_key": {"what": "the keystream of a block key that differs in ONE bit, applied without the tag check (the implementation refuses "
                                             "the block: its commitment and its tag fail)", **sample_stats(wk), **against_plain(wk)},
                       "opened": {"identical_to_the_source": stream == wav, "mean_squared_error": 0.0 if stream == wav else None,
                                  "sha256_matches": orep["sha256"] == hashlib.sha256(wav).hexdigest()},
                       "envelope": {"plain": envelope(x), "cipher": envelope(c), "wrong_key": envelope(wk)},
                       "spectrogram_db": {"plain": spectrogram(x), "cipher": spectrogram(c), "frequency_max_hz": round(504 * sr / 1024), "seconds": round(len(x) / sr, 2)},
                       "repeated_16_byte_blocks": {"plain": len(plain16) - len(set(plain16)), "cipher": len(blocks16) - len(set(blocks16)), "of": len(blocks16)}},
               "differences": [{"what": "the same audio sealed twice (a new clip key each time, as the system does)", **difference(C, again)},
                               {"what": "the audio with ONE sample changed by one step, sealed again (a new clip key)", **difference(C, one_bit)},
                               {"what": "one sample changed, SAME key and nonce (the system never does this): only that byte differs", **difference(g1, g2)}]}
        # the compressed file as it is recorded
        mp3 = src.read_bytes()
        sealed_mp3, rep_mp3 = w.seal(mp3)
        s3 = quaver.SealedAudio(sealed_mp3)
        body = sealed_mp3[len(s3.head):len(s3.head) + s3.n * s3.S]
        seal_ms, _ = med(lambda: w.seal(mp3), 5)
        open_ms, opened = med(lambda: w.open(sealed_mp3), 5)
        out["compressed"] = {"what": "the source file itself (compressed audio is already close to random; the sealed blocks are indistinguishable from random)",
                             "codec": rep_mp3["codec"], "frames": rep_mp3["frames"], "plain": byte_stats(mp3), "sealed_blocks": byte_stats(body),
                             "sealed_bytes": len(sealed_mp3), "added_pct": round(100 * (len(sealed_mp3) - len(mp3)) / len(mp3), 2),
                             "identical_after_opening": opened[1] == mp3, "seal_ms": seal_ms, "open_ms": open_ms}
        for k in ("plain", "sealed_blocks"):
            out["compressed"][k].pop("histogram")
        # what frame SIZES give away: the same audio at a variable bit rate
        ffmpeg("-i", str(tmp / "plain.wav"), "-c:a", "libmp3lame", "-q:a", "5", "-ar", "44100", str(tmp / "vbr.mp3"))
        vbr = (tmp / "vbr.mp3").read_bytes()
        vfmt, vpre, vframes, vsuf = framing.split(vbr)
        ffmpeg("-i", str(tmp / "vbr.mp3"), "-ac", "1", "-ar", "44100", "-c:a", "pcm_s16le", str(tmp / "vbr.wav"))
        vp = framing.split((tmp / "vbr.wav").read_bytes())
        vx = np.frombuffer(b"".join(vp[2]), dtype="<i2").astype(np.float64)
        nfr = min(len(vframes), len(vx) // 1152)
        sizes = np.array([len(f) for f in vframes[:nfr]], dtype=np.float64)
        rms = np.sqrt(np.mean(vx[:nfr * 1152].reshape(nfr, 1152) ** 2, axis=1))
        loud = 20 * np.log10(rms + 1.0)
        sealed_vbr, rep_vbr = w.seal(vbr)
        cap320 = 144 * 320000 // 44100 + 1
        sealed_cap, rep_cap = w.seal(vbr, frame_cap=cap320)
        sv = quaver.SealedAudio(sealed_vbr)
        out["shape"] = {"what": "the same audio encoded at a variable bit rate (libmp3lame -q:a 5): the size of every frame follows the sound. Per-frame "
                                "encryption (SRTP, or AES-GCM per frame) keeps those sizes; the sealed blocks all have one size",
                        "frames": int(nfr), "frame_ms": round(1152 / 44100 * 1000, 2), "frame_bytes": [int(v) for v in sizes[:1500]],
                        "loudness_db": [round(float(v), 1) for v in loud[:1500]], "distinct_frame_sizes": int(len(set(sizes.tolist()))),
                        "frame_bytes_min": int(sizes.min()), "frame_bytes_max": int(sizes.max()),
                        "correlation_frame_size_with_loudness": round(float(np.corrcoef(sizes, loud)[0, 1]), 4),
                        # what one frame size tells at most: the entropy of the sizes (bits a frame), and how often they change
                        "frame_size_entropy_bits": round(float(-sum((c / nfr) * math.log2(c / nfr) for c in collections.Counter(sizes.tolist()).values())), 4),
                        "frame_size_changes": int(np.sum(sizes[1:] != sizes[:-1])),
                        "sealed_block_bytes": sv.S, "sealed_blocks": sv.n, "distinct_block_sizes": len({len(sv.block(i)) for i in range(sv.n)}),
                        "frames_per_block": 8, "block_ms": round(8 * 1152 / 44100 * 1000, 1),
                        "source_bytes": len(vbr), "sealed_bytes": len(sealed_vbr), "added_pct": round(100 * (len(sealed_vbr) - len(vbr)) / len(vbr), 1),
                        "with_cap_320_kbit": {"frame_cap_bytes": cap320, "block_bytes": rep_cap["block_bytes"], "sealed_bytes": len(sealed_cap),
                                              "added_pct": round(100 * (len(sealed_cap) - len(vbr)) / len(vbr), 1)},
                        "per_frame_encryption_bytes": len(vbr) + 16 * len(vframes), "identical_after_opening": w.open(sealed_vbr)[1] == vbr}
    finally:
        w.cleanup()
    out["seconds"] = round(time.time() - t0, 1)
    Path(a.out).write_text(json.dumps(out))
    p = out["pcm"]
    print(f"{src.name}: {p['seconds']} s of PCM at {sr} Hz")
    print(f"  entropy  plain {p['plain']['bytes']['entropy_bits_per_byte']}  cipher {p['cipher']['bytes']['entropy_bits_per_byte']} bits/byte; chi-square "
          f"plain {p['plain']['bytes']['chi_square']} cipher {p['cipher']['bytes']['chi_square']} (5 % limit 293.25)")
    print(f"  correlation with the next sample  plain {p['plain']['correlation_with_next_sample']}  cipher {p['cipher']['correlation_with_next_sample']}; "
          f"cipher against plain {p['cipher']['correlation_with_the_plain_signal']}, SNR {p['cipher']['snr_db']} dB")
    for d in out["differences"]:
        print(f"  NSCR {d['bytes']['nscr_pct']:8.4f} %  UACI {d['bytes']['uaci_pct']:8.4f} %  {d['what']}")
    s = out["shape"]
    print(f"  variable bit rate: {s['distinct_frame_sizes']} frame sizes ({s['frame_bytes_min']}-{s['frame_bytes_max']} B), correlation with loudness "
          f"{s['correlation_frame_size_with_loudness']}; sealed: {s['distinct_block_sizes']} block size ({s['sealed_block_bytes']} B), +{s['added_pct']} %")
    print(f"  opened identical: PCM {p['opened']['identical_to_the_source']}, file {out['compressed']['identical_after_opening']}, VBR {s['identical_after_opening']}\n-> {a.out}")
    return 0 if p["opened"]["identical_to_the_source"] and out["compressed"]["identical_after_opening"] and s["identical_after_opening"] else 1


# ----------------------------------------------------------------------------------------------------------- loss
def loss(a):
    """A clip sent while it is sealed, over the real link, with datagrams dropped on the Pi."""
    from . import bench_link as bl
    api = bl.Api(a.url)
    s0 = api.get("/api/state")
    if s0["link"]["state"] != "UP":
        raise SystemExit("the secure link is not up")
    src = Path(a.audio)
    data = src.read_bytes()
    want = hashlib.sha256(data).hexdigest()
    name = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in src.name)
    repo = Path(__file__).resolve().parents[2]
    cam = (s0.get("uav") or {}).get("camera") or {}
    api.cmd("stop_live")                                         # the clip alone on the link: its numbers are then its own
    time.sleep(3)
    ref = bl.ref_clock(a)
    out = {"what": "a clip sent while it is sealed (every block once, not repeated), with datagrams dropped on the Pi (nftables, UDP 14600, both directions); "
                   "blocks that did not arrive are fetched again from the UAV's card and the clip is accepted against the root the UAV signed",
           "provenance": bl.provenance(api, a, ref), "source": {"file": src.name, "bytes": len(data), "sha256": want}, "runs": []}
    levels = [float(x) for x in a.levels.split(",")]
    fpbs = [int(x) for x in a.frames_per_block.split(",")]
    rc, _, err = bl.ssh(a.pi, "sudo -n systemctl stop k6g-loss-cleanup.timer k6g-loss-cleanup.service 2>/dev/null; "
                              "sudo -n systemctl reset-failed k6g-loss-cleanup.service 2>/dev/null; "
                              f"sudo -n systemd-run --quiet --collect --on-active={int(len(levels) * len(fpbs) * 240 + 600)} "
                              f"--unit k6g-loss-cleanup {bl.NFT} delete table inet k6gloss", 30)
    if rc != 0:
        raise SystemExit(f"could not arm the clean-up timer on the Pi, not injecting loss: {err.strip()[:200]}")

    def clips():
        return (api.get("/api/state").get("audio") or {}).get("clips") or []
    try:
        for F in fpbs:
            for pct in levels:
                p = subprocess.run(["bash", str(repo / "run" / "kyber6g.sh"), "audio-put", str(src)], capture_output=True, text=True, timeout=120)
                if p.returncode != 0:
                    raise SystemExit(f"audio-put failed: {p.stderr.strip()[:200]}")
                bl.nft_set(a.pi, pct)
                time.sleep(3)
                c0, st0, m0 = bl.nft_counters(a.pi), api.get("/api/state"), time.monotonic()
                r = {}
                for _ in range(6):                               # the command or its answer can be lost as well
                    r = api.cmd("record_audio", wait_s=10, source=name, live=True, frames_per_block=F)
                    if r.get("ok") or "already being recorded" in str(r.get("error")):
                        break
                    time.sleep(1)
                tag = (r.get("result") or {}).get("tag")
                if not tag:                                      # the answer was lost: the UAV says which clip it is sending
                    for _ in range(20):
                        tag = ((api.get("/api/state").get("uav") or {}).get("audio_live") or {}).get("tag")
                        if tag:
                            break
                        time.sleep(0.5)
                heard = []

                def listen(tag=tag):
                    try:
                        with urllib.request.urlopen(f"{a.url}/audio_live?tag={tag}", timeout=180) as resp:
                            heard.append(resp.read())
                    except Exception:                            # noqa: BLE001 - "nothing heard" is a result
                        heard.append(b"")
                th = threading.Thread(target=listen, daemon=True)
                th.start()
                got, deadline = None, time.monotonic() + a.wait
                while time.monotonic() < deadline and got is None:
                    time.sleep(1.0)
                    try:
                        got = next((c for c in clips()[:6] if c.get("how") == "live" and (c.get("received_at") or 0) >= st0["now"] and c.get("decrypt")), None)
                    except Exception:                            # noqa: BLE001 - a state request can time out under loss
                        pass
                wall = time.monotonic() - m0
                c1 = bl.nft_counters(a.pi)
                th.join(timeout=20)
                h = heard[0] if heard else b""
                st1 = api.get("/api/state")
                desk0, desk1 = (st0.get("audio") or {}).get("stats") or {}, (st1.get("audio") or {}).get("stats") or {}
                run = {"frames_per_block": F, "nominal_pct": pct, "tag": tag, "counters_before": c0, "counters_after": c1, "wall_s_raw": round(wall, 2),
                       "completed": bool(got), "verified": bool(got and got.get("signature") == "PASS" and got.get("decrypt") == "PASS"),
                       "identical_to_the_source": bool(got and got.get("sha256") == want),
                       "blocks": (got or {}).get("blocks"), "block_bytes": (got or {}).get("block_bytes"), "on_air": (got or {}).get("live_blocks_on_air"),
                       "repaired": (got or {}).get("live_blocks_repaired"), "refused": (got or {}).get("live_blocks_refused"),
                       "requests_for_blocks": (got or {}).get("live_requests_for_blocks"),
                       "seconds_until_stored_raw": (got or {}).get("seconds"), "duration_s": (got or {}).get("duration_s"),
                       "heard_bytes": len(h), "heard_share": round(len(h) / len(data), 4), "heard_is_the_whole_clip": h == data,
                       "desk_stats_delta": {k: desk1.get(k, 0) - desk0.get(k, 0) for k in desk1}}
                out["runs"].append(run)
                seen, dropped = c1.get("seen-out", 0) - c0.get("seen-out", 0), c1.get("drop-out", 0) - c0.get("drop-out", 0)
                print(f"  F={F:2d} loss {pct:5.1f} %: uplink dropped {dropped}/{seen} ({100 * dropped / max(seen, 1):.2f} %)  blocks {run['blocks']} on air {run['on_air']} "
                      f"repaired {run['repaired']}  heard {100 * run['heard_share']:.1f} %  verified {run['verified']} identical {run['identical_to_the_source']} "
                      f"in {run['seconds_until_stored_raw']} s", flush=True)
                bl.nft_set(a.pi, 0)
                time.sleep(2)
                ref.sample()
    finally:
        bl.nft_clear(a.pi)
        if cam.get("live"):
            api.cmd("start_live")
    return 0 if bl.finish(out, ref, a, "audio_loss") and all(r["verified"] and r["identical_to_the_source"] for r in out["runs"]) else 1


def main():
    host = platform.node().split(".")[0]
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="what", required=True)
    p = sub.add_parser("attacks"); p.add_argument("-n", type=float, default=1.0); p.add_argument("-o", "--out", default=f"audio_attacks_{host}.json")
    p = sub.add_parser("cost"); p.add_argument("-n", type=float, default=1.0); p.add_argument("-o", "--out", default=f"audio_cost_{host}.json")
    p = sub.add_parser("stats"); p.add_argument("--audio", required=True); p.add_argument("-o", "--out", default="audio_stats.json")
    p.add_argument("--source-note", default="")
    p = sub.add_parser("loss"); p.add_argument("--audio", required=True); p.add_argument("--pi", default="kyber-pi")
    p.add_argument("--url", default="http://127.0.0.1:8600"); p.add_argument("--levels", default="0,1,2,5,10,20")
    p.add_argument("--frames-per-block", default="8"); p.add_argument("--wait", type=float, default=150.0); p.add_argument("-o", "--out", default=".")
    a = ap.parse_args()
    return {"attacks": attacks, "cost": cost, "stats": stats, "loss": loss}[a.what](a)


if __name__ == "__main__":
    sys.exit(main())
