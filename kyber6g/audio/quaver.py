"""QUAVER: sealed audio clips (.k6gaud) - Quantum-safe, Uniform-shape Audio with Verifiable Excerpt Release.

What a clip is. The audio is not decoded: it is cut into its codec frames (framing.py) and F frames at a time go into
one BLOCK. Every block of a clip has the same size, whatever it holds, and is sealed under a key of its own:

    head     "K6GAUD01" | u16 len | public header (JSON) | key block (ML-KEM-1024 ct | X25519 key | wrapped clip key)
    block i  commit_i (32) | AES-256-GCM(K_i, nonce 0, plain_i, aad = "K6GAUD01|blk|" clip id | i | SHA-256(head))
    root     "K6GAROOT" | flags | u32 n | Merkle root over the n blocks
    trailer  "K6GSIG01" | u16 len | ML-DSA-87 signature of the UAV over (head, flags, n, root)

    plain_i  kind | flags | frames | length | capture time | latitude | longitude | first frame | data | zero padding

The pieces, and what each is for:

  hybrid key wrap    The clip key is wrapped as for photos and recordings (recording/sealing.py): ML-KEM-1024 AND X25519
                     to the ground station's recording keys. The UAV keeps nothing: it cannot open its own clips.
  key tree           K_i is leaf i of a binary tree of HMAC-SHA-256 values grown from the clip key (GGM). A node of the
                     tree opens exactly the blocks below it and says nothing about any other: the ground station can
                     hand out the keys of seconds 40 to 55 of a recording and of nothing else.
  a sealer that      The UAV walks that tree leaf by leaf and keeps only the nodes that lead to blocks it has not sealed
  forgets            yet: the clip key and the root are gone after the first block. A UAV taken while it records gives
                     up what it has not recorded yet, not what is already on its card or on the air.
  commitment         commit_i = HMAC(leaf_i, "com") is stored with the block and covered by the signature. A key that
                     is handed out is checked against it, so nobody can pass off another key (AES-GCM alone does not
                     tie a ciphertext to one key).
  Merkle tree        One signature covers all blocks through the root; a block is checked against it with a short
                     proof. A released excerpt is therefore verified against the UAV's ML-DSA-87 key by anyone, with
                     no secret, and a block lost on the radio can be fetched again from the UAV's copy and checked.
  uniform shape      All blocks are the same size, and their number is padded (Padme): the stored or transmitted clip
                     shows neither a bit rate that follows the speech, nor where it is silent, nor its exact length.
                     The description of the clip (codec, time, place, source) is block 0, sealed like the rest.
                     The size itself is F times the largest frame the encoder may produce (`frame_cap`, a setting);
                     without that setting it is F times the largest frame of the stream, which is one number that
                     depends on what was recorded (with a variable bit rate; not with a constant one or with PCM).
  context            Every audio block carries, inside the ciphertext, the time and the GNSS position at which it was
                     captured: an excerpt proves when and where as well as what.
  sealed once        The same sealed blocks are written to the card and sent over the link; they are never sealed a
                     second time, so one signature serves the stored copy, the live copy and any repair between them.

Confidentiality rests on AES-256-GCM, HMAC-SHA-256 and the two key-encapsulation schemes; authenticity on SHA-256 and
ML-DSA-87. Nothing here is a new cipher. What is put together for audio is the arrangement.
"""
import hashlib
import json
import os
import struct
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..crypto import identity as idm
from ..crypto import keyschedule as ks
from ..crypto.secure_bytes import ct_equal, wipe
from ..recording import sealing
from . import framing

MAGIC = b"K6GAUD01"
EXCERPT_MAGIC = b"K6GAEX01"
ROOT_MAGIC = b"K6GAROOT"
KEK_LABEL = b"KYBER6G/audio/v1|kek|"
TREE_LABEL = b"KYBER6G/audio/v1|tree|"
BLOCK_AAD = b"K6GAUD01|blk|"
ROOT_LABEL = b"K6GAUD01|root|"
DEPTH = 24                                  # key tree: 2^24 blocks, 40 days of audio at 0.2 s a block
COMMIT, TAG = 32, 16
BLOCK_HDR = struct.Struct("!BBHIQiiI")      # kind, flags, frames, data length, capture ms, lat e7, lon e7, first frame
META, AUDIO, PAD, ANCILLARY, SUMMARY = 0, 1, 2, 3, 4
FLAG_LAST = 1                               # block flag: the last audio block of the clip
CLEAN_END = 1                               # root flag: the clip was closed by its sealer (not recovered after a crash)
NO_FIX = -(1 << 31)
ZERO_NONCE = b"\x00" * 12
SIG_ALG = "ML-DSA-87"
MIN_PAYLOAD = 1024                          # a block must hold the clip's description


class AudioError(Exception):
    """A clip, block, key or proof that is not what it must be. The only exception the opening functions raise."""


# ------------------------------------------------------------------------------------------------ the two trees
def cover(a: int, b: int, depth: int):
    """The fewest nodes of a binary tree with 2^depth leaves that cover the leaves a..b exactly: [(level, index)],
    the root being (0, 0) and leaf i being (depth, i). At most 2 * depth nodes."""
    out, lo, hi, level = [], a, b + 1, depth
    while lo < hi:
        if lo & 1:
            out.append((level, lo)); lo += 1
        if hi & 1:
            hi -= 1; out.append((level, hi))
        lo >>= 1; hi >>= 1; level -= 1
    return sorted(out, key=lambda n: n[1] << (depth - n[0]))


class KeyTree:
    """The key of node (level, idx) and everything below it. child(k, bit) = HMAC-SHA-256(k, bit): the two children of
    a node are independent of each other and say nothing about their parent (a PRF used as a length-doubling
    generator, Goldreich-Goldwasser-Micali)."""

    def __init__(self, key: bytes, depth: int = DEPTH, level: int = 0, idx: int = 0):
        self.depth, self.level, self.idx = depth, level, idx
        self._idx, self._key = [idx], [bytes(key)]          # the path to the node asked for last: sealing walks the leaves in order

    def node(self, level: int, idx: int) -> bytes:
        steps = level - self.level
        if not self._key or steps < 0 or level > self.depth or idx < 0 or (idx >> steps) != self.idx:
            raise AudioError("this key does not reach that block")
        for j in range(1, steps + 1):
            want = idx >> (steps - j)
            if j < len(self._idx) and self._idx[j] == want:
                continue
            del self._idx[j:], self._key[j:]
            self._idx.append(want)
            self._key.append(ks.hmac256(self._key[j - 1], b"\x01" if want & 1 else b"\x00"))
        del self._idx[steps + 1:], self._key[steps + 1:]
        return self._key[steps]

    def leaf(self, i: int) -> bytes:
        return self.node(self.depth, i)

    def wipe(self):
        self._idx, self._key = [], []                       # nothing can be derived from this object any more


class SealerTree:
    """The key tree as the sealer walks it: every leaf once, in order, forgetting as it goes.

    It holds the nodes whose leaves are still to come and nothing else: at most one node per level, the top of the
    stack being the one whose leftmost leaf is next. To hand out that leaf the node is replaced by its two children
    all the way down, the right ones staying on the stack. A node is overwritten as soon as its children exist, so
    after leaf i nothing in this object leads to a leaf up to i (a child says nothing about its parent or sibling).
    The leaves are the same as KeyTree gives for the same key: the ground station, which has the root, is not affected.
    """

    def __init__(self, key: bytes, depth: int = DEPTH):
        self.depth, self.next = depth, 0
        self._stack = [(0, 0, bytearray(key))]              # (level, index, key)

    def leaf(self, i: int) -> bytes:
        if i != self.next or not self._stack:
            raise AudioError("the sealer's key tree gives every leaf once, in order")
        level, idx, key = self._stack.pop()
        while level < self.depth:
            left, right = ks.hmac256(bytes(key), b"\x00"), bytearray(ks.hmac256(bytes(key), b"\x01"))
            wipe(key)
            level, idx = level + 1, idx * 2
            self._stack.append((level, idx + 1, right))
            key = bytearray(left)
        self.next += 1
        out = bytes(key)
        wipe(key)
        return out

    def holds(self):
        """[(level, index)] of the nodes kept: together they cover exactly the leaves that are still to come."""
        return [(lv, ix) for lv, ix, _ in self._stack]

    def wipe(self):
        for _, _, k in self._stack:
            wipe(k)
        self._stack = []


def block_keys(leaf: bytes):
    """(encryption key, commitment) of a block from its leaf of the key tree."""
    return ks.hmac256(leaf, b"\x02enc"), ks.hmac256(leaf, b"\x03com")


def _leaf_hash(clip_id: bytes, i: int, sealed: bytes) -> bytes:
    return ks.sha256(b"\x00", clip_id, struct.pack("!I", i), sealed)


def _node_hash(left: bytes, right: bytes) -> bytes:
    return ks.sha256(b"\x01", left, right)


_EMPTY = [ks.sha256(b"\x02K6GAUD01/no-block")]              # a subtree without blocks, by height


def _empty(height: int) -> bytes:
    while len(_EMPTY) <= height:
        _EMPTY.append(_node_hash(_EMPTY[-1], _EMPTY[-1]))
    return _EMPTY[height]


def tree_depth(n: int) -> int:
    """Depth of the Merkle tree over n blocks: the smallest tree with 2^depth >= n leaves."""
    return max(n - 1, 0).bit_length()


class Frontier:
    """The Merkle root of blocks that arrive one by one, in memory logarithmic in their number."""

    def __init__(self):
        self.stack, self.n = [], 0                          # (height, hash)

    def add(self, leaf: bytes):
        self.stack.append((0, leaf))
        self.n += 1
        self._fold(self.stack)

    @staticmethod
    def _fold(st):
        while len(st) >= 2 and st[-1][0] == st[-2][0]:
            (h, r), (_, l) = st.pop(), st.pop()
            st.append((h + 1, _node_hash(l, r)))

    def root(self) -> bytes:
        if not self.n:
            raise AudioError("a clip has at least one block")
        st, d = list(self.stack), tree_depth(self.n)
        while len(st) > 1 or st[0][0] < d:
            st.append((st[-1][0], _empty(st[-1][0])))
            self._fold(st)
        return st[0][1]


def merkle_levels(leaves, d: int):
    """All nodes of the tree, by level: levels[d] are the leaves (blocks that do not exist filled in), levels[0] the root."""
    level = list(leaves) + [_empty(0)] * ((1 << d) - len(leaves))
    levels = [level]
    while len(level) > 1:
        level = [_node_hash(level[k], level[k + 1]) for k in range(0, len(level), 2)]
        levels.append(level)
    return levels[::-1]


def _outside(a: int, b: int, d: int):
    """The nodes a verifier of the leaves a..b needs besides those leaves: the cover of everything else."""
    out = cover(0, a - 1, d) if a > 0 else []
    return out + (cover(b + 1, (1 << d) - 1, d) if b + 1 < (1 << d) else [])


def range_proof(levels, a: int, b: int):
    d = len(levels) - 1
    return [levels[lv][ix] for lv, ix in _outside(a, b, d)]


def root_from_range(leaves, a: int, d: int, proof) -> bytes:
    """The root that the leaves a, a+1, ... and the proof lead to. Raises AudioError if the proof is not of that shape."""
    b = a + len(leaves) - 1
    want = _outside(a, b, d)
    if not leaves or a < 0 or b >= (1 << d) or len(proof) != len(want) or any(len(p) != 32 for p in proof):
        raise AudioError("proof of the wrong shape")
    nodes = {(d, a + k): h for k, h in enumerate(leaves)}
    nodes.update(zip(want, proof))
    for level in range(d, 0, -1):
        for ix in sorted(i for lv, i in nodes if lv == level and not i & 1):
            right = nodes.get((level, ix | 1))
            if right is None:
                raise AudioError("proof of the wrong shape")
            nodes[(level - 1, ix >> 1)] = _node_hash(nodes[(level, ix)], right)
    if (0, 0) not in nodes:
        raise AudioError("proof of the wrong shape")
    return nodes[(0, 0)]


def padme(n: int) -> int:
    """n rounded up so that it has at most as many significant bits as log2(log2 n) allows (Padme, Nikitin et al.
    2019): the padded number shows O(log log n) bits of n and is at most about 12 % larger."""
    if n < 2:
        return n
    e = n.bit_length() - 1
    z = e - e.bit_length()
    mask = (1 << z) - 1 if z > 0 else 0
    return (n + mask) & ~mask


# ---------------------------------------------------------------------------------------------------- sealing
def _signed_digest(head_hash: bytes, flags: int, n: int, root: bytes) -> bytes:
    return ks.sha256(ROOT_LABEL, head_hash, struct.pack("!BI", flags, n), root)


class AudioSealer:
    """Seals one clip block by block (on the UAV). `head` first, then every block that start(), add() and finish()
    return, in that order, then the trailer finish() returns: together they are the .k6gaud file, and the same bytes
    are what is sent over the link.

    fmt       what framing.split() says about the stream (codec, sample rate, samples per frame, largest frame)
    context   callable(frame number) -> (capture time in ms, latitude or None, longitude or None) for the block that
              starts with that frame
    """

    def __init__(self, gcs_ek: bytes, x25519_pk: bytes, signer, fmt: dict, *, frames_per_block: int = 8, prefix: bytes = b"",
                 meta: dict = None, context=None, pad: bool = True, kem_alg: str = "ML-KEM-1024"):
        if x25519_pk is None or signer is None:
            raise ValueError("a sealed audio clip is hybrid-wrapped and signed: both recording keys and the UAV's identity are needed")
        if not 1 <= frames_per_block <= 4096 or not 1 <= int(fmt.get("frame_len_max") or 0) <= 1 << 20:
            raise ValueError("frames per block or frame size out of range")
        self.fmt, self.F = dict(fmt), frames_per_block
        self.payload = max(frames_per_block * int(fmt["frame_len_max"]), MIN_PAYLOAD)
        self.plain_len = BLOCK_HDR.size + self.payload
        self.block_len = COMMIT + self.plain_len + TAG
        self.clip_id = os.urandom(16)
        hdr = {"v": 1, "clip_id": self.clip_id.hex(), "aead": "AES-256-GCM", "kem": sealing.HYBRID_NAME, "hash": "SHA-256",
               "block": self.block_len, "tree": DEPTH, "gcs_ek_fp": idm.fingerprint(gcs_ek), "gcs_x_fp": idm.fingerprint(x25519_pk),
               **sealing.signer_fields(signer)}
        hj = json.dumps(hdr, sort_keys=True).encode()
        cek, key_block = sealing.wrap(MAGIC, KEK_LABEL, self.clip_id, hj, gcs_ek, x25519_pk, kem_alg)
        self.head = MAGIC + struct.pack("!H", len(hj)) + hj + key_block
        self.head_hash = hashlib.sha256(self.head).digest()
        self._tree = SealerTree(ks.hkdf_expand(bytes(cek), TREE_LABEL + self.clip_id))        # forgets as it goes
        wipe(cek)
        self._signer, self._context, self._pad = signer, context or (lambda frame: (int(time.time() * 1000), None, None)), pad
        self._frontier = Frontier()
        self._frames, self._first, self._ctx = [], 0, None
        self._hash = hashlib.sha256()                       # of prefix + frames + suffix: the stream as it was
        self._prefix = bytes(prefix)
        self._meta = {"v": 1, **self.fmt, "frames_per_block": self.F, "first_audio_block": 1 + -(-len(prefix) // self.payload),
                      "started": time.time(), **(meta or {})}
        self.n_frames = self.audio_blocks = self.stream_bytes = 0
        self.closed = False
        self.seal_s = 0.0

    # one block
    def _seal(self, kind: int, data: bytes, frames: int = 0, flags: int = 0, first: int = 0, ctx=None) -> bytes:
        if self.closed:
            raise AudioError("this clip is closed")
        if len(data) > self.payload:
            raise AudioError("block payload too large")
        t0 = time.perf_counter()
        i = self._frontier.n
        t_ms, lat, lon = ctx or (0, None, None)
        e7 = lambda v: NO_FIX if v is None else max(-(1 << 31) + 1, min((1 << 31) - 1, round(v * 1e7)))
        plain = BLOCK_HDR.pack(kind, flags, frames, len(data), int(t_ms) & ((1 << 64) - 1), e7(lat), e7(lon), first) + data
        plain += b"\x00" * (self.plain_len - len(plain))
        key, commit = block_keys(self._tree.leaf(i))
        sealed = commit + AESGCM(key).encrypt(ZERO_NONCE, plain, BLOCK_AAD + self.clip_id + struct.pack("!I", i) + self.head_hash)
        self._frontier.add(_leaf_hash(self.clip_id, i, sealed))
        self.seal_s += time.perf_counter() - t0
        return sealed

    def start(self):
        """The blocks every clip begins with: its description, then whatever came before the first frame."""
        mj = json.dumps(self._meta, sort_keys=True, default=str).encode()
        if len(mj) > self.payload:
            raise AudioError("clip description too long for one block")
        out = [self._seal(META, mj)]
        self._hash.update(self._prefix)
        self.stream_bytes += len(self._prefix)
        out += [self._seal(ANCILLARY, self._prefix[k:k + self.payload]) for k in range(0, len(self._prefix), self.payload)]
        return out

    def _flush(self, last: bool):
        data = b"".join(self._frames)
        blk = self._seal(AUDIO, data, len(self._frames), FLAG_LAST if last else 0, self._first, self._ctx)
        self._first += len(self._frames)
        self._frames, self.audio_blocks = [], self.audio_blocks + 1
        return blk

    def add(self, frame: bytes):
        """One codec frame. Returns the blocks that became complete (none or one)."""
        if len(frame) > int(self.fmt["frame_len_max"]):
            raise AudioError("frame larger than this clip was set up for")
        if not self._frames:
            self._ctx = self._context(self.n_frames)
        self._frames.append(bytes(frame))
        self._hash.update(frame)
        self.n_frames += 1
        self.stream_bytes += len(frame)
        return [self._flush(False)] if len(self._frames) == self.F else []

    def finish(self, suffix: bytes = b"", clean: bool = True):
        """Close the clip: (last blocks, root record + signature trailer)."""
        out = [self._flush(True)] if self._frames else []
        self._hash.update(suffix)
        self.stream_bytes += len(suffix)
        out += [self._seal(ANCILLARY, suffix[k:k + self.payload]) for k in range(0, len(suffix), self.payload)]
        summary = {"audio_blocks": self.audio_blocks, "frames": self.n_frames, "bytes": self.stream_bytes,
                   "duration_s": framing.duration_s(self.fmt, self.n_frames), "sha256": self._hash.hexdigest(), "ended": time.time(),
                   "suffix_bytes": len(suffix)}
        out.append(self._seal(SUMMARY, json.dumps(summary, sort_keys=True).encode()))
        if self._pad:
            out += [self._seal(PAD, b"") for _ in range(padme(self._frontier.n) - self._frontier.n)]
        self._tree.wipe()
        return out, self.trailer(CLEAN_END if clean else 0)

    def trailer(self, flags: int = 0) -> bytes:
        """Root record and signature over the blocks sealed so far. Needs no key but the UAV's own signing key: a
        clip that lost its sealer (power cut) is closed with trailer_for() from the blocks that reached the card."""
        self.closed = True
        return trailer_for(self.head_hash, self._frontier, flags, self._signer)


def trailer_for(head_hash: bytes, frontier: Frontier, flags: int, signer) -> bytes:
    root, n = frontier.root(), frontier.n
    return ROOT_MAGIC + struct.pack("!BI", flags, n) + root + sealing.sign_trailer(b"audio", _signed_digest(head_hash, flags, n, root), signer)


def with_cap(fmt: dict, frame_cap: int = 0) -> dict:
    """`fmt` with the frame size a block is laid out for raised to `frame_cap` (0: left as the stream's largest frame)."""
    cap = int(frame_cap or 0)
    if isinstance(frame_cap, bool) or not 0 <= cap <= 1 << 20:
        raise ValueError("frame cap out of range")
    return {**fmt, "frame_len_max": max(int(fmt["frame_len_max"]), cap)}


def seal_stream(data: bytes, gcs_ek: bytes, x25519_pk: bytes, signer, *, frames_per_block: int = 8, meta: dict = None, context=None,
                pad: bool = True, frame_cap: int = 0):
    """A whole audio file as one clip: (sealed bytes, report). The file is cut into its codec frames, not decoded."""
    fmt, prefix, frames, suffix = framing.split(data)
    fmt = with_cap(fmt, frame_cap)
    s = AudioSealer(gcs_ek, x25519_pk, signer, fmt, frames_per_block=frames_per_block, prefix=prefix, meta=meta, context=context, pad=pad)
    parts = [s.head] + s.start()
    for f in frames:
        parts += s.add(f)
    tail, trailer = s.finish(suffix)
    out = b"".join(parts + tail) + trailer
    return out, {"clip_id": s.clip_id.hex(), "codec": fmt["codec"], "frames": s.n_frames, "audio_blocks": s.audio_blocks,
                 "blocks": s._frontier.n, "block_bytes": s.block_len, "bytes_in": len(data), "bytes_out": len(out),
                 "duration_s": framing.duration_s(fmt, s.n_frames), "seal_ms": round(s.seal_s * 1000, 2)}


def recover(raw: bytes, signer) -> bytes:
    """A clip whose sealer was lost before it was closed (head and some whole blocks on the card, no trailer): the
    same bytes cut to whole blocks, with a root record that says "not closed by its sealer" and the UAV's signature.
    No secret but the signing key is needed, and nothing can be added to the clip: its keys are gone."""
    head, hdr, body = _split_head(raw)
    S = hdr["block"]
    n = len(body) // S
    if n < 1:
        raise AudioError("no whole block to recover")
    clip_id, fr = bytes.fromhex(hdr["clip_id"]), Frontier()
    for i in range(n):
        fr.add(_leaf_hash(clip_id, i, body[i * S:(i + 1) * S]))
    return head + body[:n * S] + trailer_for(hashlib.sha256(head).digest(), fr, 0, signer)


# ---------------------------------------------------------------------------------------------------- opening
def _split_head(raw: bytes):
    try:
        if raw[:8] != MAGIC:
            raise AudioError("not a K6GAUD clip")
        (jl,) = struct.unpack_from("!H", raw, 8)
        hj = raw[10:10 + jl]
        hdr = json.loads(hj)
        end = 10 + jl + sealing.block_len(True)
        if not isinstance(hdr, dict) or len(raw) < end:
            raise AudioError("truncated clip")
        S, depth = hdr.get("block"), hdr.get("tree")
        if hdr.get("v") != 1 or isinstance(S, bool) or not isinstance(S, int) or not COMMIT + BLOCK_HDR.size + MIN_PAYLOAD + TAG <= S <= 1 << 24 \
                or depth != DEPTH or len(bytes.fromhex(hdr.get("clip_id", ""))) != 16 or hdr.get("sig") != SIG_ALG:
            raise AudioError("unsupported or malformed header")
    except (ValueError, KeyError, TypeError, struct.error, RecursionError) as e:
        if isinstance(e, AudioError):
            raise
        raise AudioError(f"malformed header: {type(e).__name__}") from None
    return raw[:end], hdr, raw[end:]


class SealedAudio:
    """A .k6gaud as anyone sees it: head, blocks, root record, signature. Nothing here needs a key."""

    def __init__(self, raw: bytes):
        self.head, self.hdr, body = _split_head(raw)
        self.head_hash = hashlib.sha256(self.head).digest()
        self.clip_id = bytes.fromhex(self.hdr["clip_id"])
        self.S = self.hdr["block"]
        try:
            tl = sealing.trailer_len(self.hdr, SIG_ALG)
        except sealing.SealError as e:
            raise AudioError(str(e)) from None
        rl = 8 + 5 + 32
        if len(body) < self.S + rl + tl:
            raise AudioError("truncated clip")
        rec, self._trailer = body[-(rl + tl):-tl], body[-tl:]
        if rec[:8] != ROOT_MAGIC:
            raise AudioError("no root record (clip cut short or not closed)")
        self.flags, self.n = struct.unpack_from("!BI", rec, 8)
        self.root = rec[13:]
        self._blocks = body[:-(rl + tl)]
        if self.n < 1 or self.n > 1 << DEPTH or len(self._blocks) != self.n * self.S:
            raise AudioError("number of blocks does not match the root record")
        self.d = tree_depth(self.n)
        self._leaves = None

    def block(self, i: int) -> bytes:
        if not 0 <= i < self.n:
            raise AudioError("no such block")
        return self._blocks[i * self.S:(i + 1) * self.S]

    def leaves(self):
        if self._leaves is None:
            self._leaves = [_leaf_hash(self.clip_id, i, self.block(i)) for i in range(self.n)]
        return self._leaves

    def signature(self) -> bytes:
        t = self._trailer
        if t[:8] != sealing.SIG_MAGIC or struct.unpack_from("!H", t, 8)[0] != len(t) - 10:
            raise AudioError("signature missing or cut short")
        return t[10:]

    def verify(self, signer_pk: bytes):
        """Every block against the root, the root against the UAV's signature. Raises AudioError on any difference."""
        fr = Frontier()
        for h in self.leaves():
            fr.add(h)
        if not ct_equal(fr.root(), self.root):
            raise AudioError("blocks do not match the signed root (a block was changed, moved, added or removed)")
        verify_root(self.head_hash, self.flags, self.n, self.root, self.signature(), signer_pk)

    def public(self) -> dict:
        """What the file tells someone without any key."""
        return {"clip_id": self.hdr["clip_id"], "signer": self.hdr.get("signer"), "signer_fp": self.hdr.get("signer_fp"),
                "kem": self.hdr.get("kem"), "blocks": self.n, "block_bytes": self.S, "closed_by_sealer": bool(self.flags & CLEAN_END),
                "bytes": len(self.head) + self.n * self.S + 45 + len(self._trailer)}


def verify_root(head_hash: bytes, flags: int, n: int, root: bytes, sig: bytes, signer_pk: bytes):
    if signer_pk is None:
        raise AudioError("the UAV's public key is needed: a clip is not opened unverified")
    msg = sealing.SIG_LABEL + b"audio|" + _signed_digest(head_hash, flags, n, root)
    if not idm.verify(SIG_ALG, msg, sig, signer_pk):
        raise AudioError("signature invalid: not written by the pinned UAV key, or changed afterwards")


def open_block(tree, clip_id: bytes, head_hash: bytes, i: int, sealed: bytes, plain_len: int) -> dict:
    """One block opened with the key that `tree` gives for it; the key is first checked against the block's commitment."""
    key, commit = block_keys(tree.leaf(i))
    if len(sealed) != COMMIT + plain_len + TAG or not ct_equal(commit, sealed[:COMMIT]):
        raise AudioError(f"block {i}: this key is not the one the block was sealed under")
    try:
        plain = AESGCM(key).decrypt(ZERO_NONCE, sealed[COMMIT:], BLOCK_AAD + clip_id + struct.pack("!I", i) + head_hash)
    except Exception:
        raise AudioError(f"block {i}: authentication failed") from None
    kind, flags, frames, n, t_ms, lat, lon, first = BLOCK_HDR.unpack_from(plain)
    if n > plain_len - BLOCK_HDR.size or kind > SUMMARY or any(plain[BLOCK_HDR.size + n:]):
        raise AudioError(f"block {i}: malformed")
    return {"index": i, "kind": kind, "flags": flags, "frames": frames, "first_frame": first, "t_ms": t_ms or None,
            "lat": None if lat == NO_FIX else lat / 1e7, "lon": None if lon == NO_FIX else lon / 1e7,
            "data": plain[BLOCK_HDR.size:BLOCK_HDR.size + n]}


def _clip_tree(sa: SealedAudio, rec_dk: bytes, x25519_sk: bytes, kem_alg: str = "ML-KEM-1024") -> KeyTree:
    hj = sa.head[10:10 + struct.unpack_from("!H", sa.head, 8)[0]]
    try:
        cek = sealing.unwrap(MAGIC, KEK_LABEL, sa.clip_id, hj, sa.head[10 + len(hj):], rec_dk, x25519_sk, kem_alg)
    except sealing.SealError as e:
        raise AudioError(str(e)) from None
    return KeyTree(ks.hkdf_expand(cek, TREE_LABEL + sa.clip_id))


def _json_block(b: dict) -> dict:
    try:
        v = json.loads(b["data"])
    except (ValueError, RecursionError):
        raise AudioError(f"block {b['index']}: malformed") from None
    if not isinstance(v, dict):
        raise AudioError(f"block {b['index']}: malformed")
    return v


def open_audio(raw: bytes, rec_dk: bytes, x25519_sk: bytes, signer_pk: bytes):
    """A clip opened at the ground station: (description, stream, report). The signature is checked first; the
    station's own secret keys are not used on a clip the pinned UAV key did not sign. `stream` is the audio file as
    it was before sealing, byte for byte. Raises AudioError, and nothing else, on a wrong key or any change."""
    sa = SealedAudio(raw)
    sa.verify(signer_pk)
    tree = _clip_tree(sa, rec_dk, x25519_sk)
    plain_len = sa.S - COMMIT - TAG
    meta, summary, parts, ctx, frames, audio_blocks, ended = None, None, [], [], 0, 0, False
    for i in range(sa.n):
        b = open_block(tree, sa.clip_id, sa.head_hash, i, sa.block(i), plain_len)
        k = b["kind"]
        if (i == 0) != (k == META) or (summary is not None) != (k == PAD) or (ended and k == AUDIO):
            raise AudioError(f"block {i}: out of place")
        if k == META:
            meta = _json_block(b)
        elif k == SUMMARY:
            summary = _json_block(b)
        elif k == AUDIO:
            if b["first_frame"] != frames:
                raise AudioError(f"block {i}: frames out of order")
            frames, audio_blocks, ended = frames + b["frames"], audio_blocks + 1, bool(b["flags"] & FLAG_LAST)
            ctx.append({"block": i, "first_frame": b["first_frame"], "frames": b["frames"], "t_ms": b["t_ms"], "lat": b["lat"], "lon": b["lon"]})
            parts.append(b["data"])
        elif k == ANCILLARY:
            parts.append(b["data"])
    stream = b"".join(parts)
    clean = bool(sa.flags & CLEAN_END)
    if clean and (summary is None or summary.get("sha256") != hashlib.sha256(stream).hexdigest()
                  or summary.get("frames") != frames or summary.get("audio_blocks") != audio_blocks):
        raise AudioError("the clip does not add up to what its last block says")
    report = {**sa.public(), "signature": "PASS", "complete": clean, "audio_blocks": audio_blocks, "frames": frames,
              "duration_s": framing.duration_s(meta, frames), "stream_bytes": len(stream), "sha256": hashlib.sha256(stream).hexdigest(),
              "summary": summary, "context": ctx}
    return meta, stream, report


# ------------------------------------------------------------------------------------------- excerpt release
def make_excerpt(raw: bytes, rec_dk: bytes, x25519_sk: bytes, signer_pk: bytes, a: int, b: int, with_meta: bool = True) -> bytes:
    """Blocks a..b of a clip for someone else: the blocks, the keys of exactly those blocks, and the proof that they
    are blocks a..b of the clip the UAV signed. With `with_meta`, block 0 (the clip's description) as well. The
    ground station's own keys and the clip key do not leave it; the keys of all other blocks cannot be derived."""
    sa = SealedAudio(raw)
    sa.verify(signer_pk)
    if not 0 < a <= b < sa.n:
        raise AudioError("no such range of blocks")
    tree = _clip_tree(sa, rec_dk, x25519_sk)
    levels = merkle_levels(sa.leaves(), sa.d)
    ranges = ([(0, 0)] if with_meta else []) + [(a, b)]
    info = {"v": 1, "clip_id": sa.hdr["clip_id"], "n": sa.n, "flags": sa.flags, "block": sa.S, "ranges": ranges}
    ij = json.dumps(info, sort_keys=True).encode()
    out = [EXCERPT_MAGIC, struct.pack("!H", len(ij)), ij, struct.pack("!I", len(sa.head)), sa.head, sa.root,
           struct.pack("!H", len(sa.signature())), sa.signature()]
    for lo, hi in ranges:
        nodes = cover(lo, hi, DEPTH)
        proof = range_proof(levels, lo, hi)
        out.append(struct.pack("!HH", len(nodes), len(proof)))
        out += [struct.pack("!BI", lv, ix) + tree.node(lv, ix) for lv, ix in nodes]
        out += proof
        out += [sa.block(i) for i in range(lo, hi + 1)]
    return b"".join(out)


def verify_excerpt(bundle: bytes, signer_pk: bytes):
    """What a released excerpt proves, to anyone who has the UAV's public key and nothing else: (info, audio, blocks).
    `audio` is the frames of the released blocks in order; `blocks` gives each block's place in the clip, its frames,
    and the time and position of its capture; info["meta"] is the clip's description if it was released."""
    try:
        if bundle[:8] != EXCERPT_MAGIC:
            raise AudioError("not a K6GAEX excerpt")
        (jl,) = struct.unpack_from("!H", bundle, 8)
        info = json.loads(bundle[10:10 + jl])
        off = 10 + jl
        (hl,) = struct.unpack_from("!I", bundle, off)
        head = bundle[off + 4:off + 4 + hl]
        off += 4 + hl
        root = bundle[off:off + 32]
        (sl,) = struct.unpack_from("!H", bundle, off + 32)
        sig = bundle[off + 34:off + 34 + sl]
        off += 34 + sl
        head2, hdr, rest = _split_head(head)
        n, flags, S, ranges = info["n"], info["flags"], info["block"], info["ranges"]
        if rest or head2 != head or info["v"] != 1 or set(info) != {"v", "clip_id", "n", "flags", "block", "ranges"} or S != hdr["block"] \
                or info["clip_id"] != hdr["clip_id"] or not isinstance(n, int) or isinstance(n, bool) \
                or not 1 <= n <= 1 << DEPTH or not isinstance(flags, int) or not 0 <= flags <= 255 or not isinstance(ranges, list) \
                or not 1 <= len(ranges) <= 2 or len(root) != 32 or len(sig) != sl:
            raise AudioError("malformed excerpt")
        clip_id, head_hash, d, plain_len = bytes.fromhex(hdr["clip_id"]), hashlib.sha256(head).digest(), tree_depth(n), S - COMMIT - TAG
        verify_root(head_hash, flags, n, root, sig, signer_pk)          # the root is the UAV's: now everything against it
        blocks, last = [], -1
        for r in ranges:
            lo, hi = r
            if isinstance(lo, bool) or isinstance(hi, bool) or not isinstance(lo, int) or not isinstance(hi, int) or not last < lo <= hi < n:
                raise AudioError("malformed excerpt")
            last = hi
            nk, npf = struct.unpack_from("!HH", bundle, off)
            off += 4
            want = cover(lo, hi, DEPTH)
            if nk != len(want) or nk > 2 * DEPTH or npf > 2 * DEPTH:
                raise AudioError("malformed excerpt")
            trees = []
            for lv, ix in want:
                glv, gix = struct.unpack_from("!BI", bundle, off)
                if (glv, gix) != (lv, ix):
                    raise AudioError("malformed excerpt")
                trees.append(KeyTree(bundle[off + 5:off + 37], DEPTH, lv, ix))
                off += 37
            proof = [bundle[off + 32 * k:off + 32 * (k + 1)] for k in range(npf)]
            off += 32 * npf
            sealed = [bundle[off + S * k:off + S * (k + 1)] for k in range(hi - lo + 1)]
            off += S * (hi - lo + 1)
            if off > len(bundle) or any(len(x) != S for x in sealed):
                raise AudioError("truncated excerpt")
            got = root_from_range([_leaf_hash(clip_id, lo + k, x) for k, x in enumerate(sealed)], lo, d, proof)
            if not ct_equal(got, root):
                raise AudioError("these are not blocks of the clip the UAV signed")
            for k, x in enumerate(sealed):
                i = lo + k
                t = next(t for t in trees if (i >> (DEPTH - t.level)) == t.idx)
                blocks.append(open_block(t, clip_id, head_hash, i, x, plain_len))
        if off != len(bundle):
            raise AudioError("malformed excerpt")
    except (ValueError, KeyError, TypeError, struct.error, IndexError, StopIteration, RecursionError) as e:
        if isinstance(e, AudioError):
            raise
        raise AudioError(f"malformed excerpt: {type(e).__name__}") from None
    meta = _json_block(blocks[0]) if blocks and blocks[0]["kind"] == META and blocks[0]["index"] == 0 else None
    audio = [b for b in blocks if b["kind"] == AUDIO]
    out = {"clip_id": hdr["clip_id"], "signer": hdr.get("signer"), "signer_fp": hdr.get("signer_fp"), "blocks_in_clip": n,
           "ranges": ranges, "signature": "PASS", "meta": meta, "frames": sum(b["frames"] for b in audio),
           "duration_s": framing.duration_s(meta, sum(b["frames"] for b in audio)) if meta else None}
    return out, b"".join(b["data"] for b in audio), [{k: b[k] for k in ("index", "kind", "frames", "first_frame", "t_ms", "lat", "lon")} for b in blocks]


def blocks_for_time(meta: dict, n_audio_blocks: int, t0: float, t1: float):
    """The blocks (a, b) that hold the audio from second t0 to second t1 of a clip. Every audio block holds the same
    number of frames, so this is arithmetic: no index is stored and nothing is decrypted to seek."""
    spf, sr, F = meta.get("samples_per_frame"), meta.get("sample_rate"), meta.get("frames_per_block")
    if not spf or not sr or not F or n_audio_blocks < 1:
        raise AudioError("this clip has no time base")
    per_block = F * spf / sr
    first = meta["first_audio_block"]
    a = first + min(n_audio_blocks - 1, max(0, int(t0 / per_block)))
    b = first + min(n_audio_blocks - 1, max(0, int(max(t1, t0) / per_block - 1e-9)))
    return a, max(a, b)
