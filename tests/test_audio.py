"""Sealed audio clips (kyber6g/audio): the framing of MP3 / WAVE streams, the key tree, the Merkle tree, sealing and
opening, every way of damaging or forging a clip, the release of an excerpt and what its receiver can and cannot do."""
import hashlib
import json
import random
import struct
import unittest

from kyber6g.audio import framing
from kyber6g.audio import quaver as q
from kyber6g.audio.quaver import AudioError
from kyber6g.crypto import identity as idm
from kyber6g.recording import sealing
from tests.test_sealing import Keys

KBPS = (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320)


def mp3(n, rate=9, pad_every=0, seed=1, vbr=None):
    """n MPEG-1 layer III frames (44.1 kHz, joint stereo) with random content; `vbr`: bitrate indices to cycle through."""
    rng, out = random.Random(seed), []
    for k in range(n):
        r = vbr[k % len(vbr)] if vbr else rate
        pad = 1 if pad_every and k % pad_every == 0 else 0
        size = 144 * KBPS[r] * 1000 // 44100 + pad
        out.append(bytes([0xFF, 0xFB, (r << 4) | (pad << 1), 0x64]) + rng.randbytes(size - 4))
    return out


ID3 = b"ID3\x03\x00\x00\x00\x00\x00\x1f" + b"TIT2\x00\x00\x00\x15\x00\x00\x00SECRET-MISSION-TITLE"     # a 31-byte tag: one text frame
TAG = b"TAG" + b"closing words".ljust(125, b"\x00")


def wav(seconds=1.0, rate=16000, ch=1, seed=3):
    n = int(seconds * rate) * ch * 2
    pcm = random.Random(seed).randbytes(n)
    return b"RIFF" + struct.pack("<I", 36 + n) + b"WAVEfmt " + struct.pack("<IHHIIHH", 16, 1, ch, rate, rate * ch * 2, ch * 2, 16) + \
        b"data" + struct.pack("<I", n) + pcm


class TestFraming(unittest.TestCase):
    def test_an_mp3_stream_is_cut_into_its_frames_and_nothing_is_lost(self):
        frames = mp3(40, pad_every=3)
        data = ID3 + b"".join(frames) + TAG
        fmt, prefix, got, suffix = framing.split(data)
        self.assertEqual((prefix, got, suffix), (ID3, frames, TAG))
        self.assertEqual(prefix + b"".join(got) + suffix, data)
        self.assertEqual((fmt["codec"], fmt["mpeg"], fmt["layer"], fmt["sample_rate"], fmt["channels"], fmt["samples_per_frame"]),
                         ("mp3", 1, 3, 44100, 2, 1152))
        self.assertEqual((fmt["cbr"], fmt["bitrate"], fmt["frame_len_max"]), (True, 128000, 418))
        self.assertAlmostEqual(framing.duration_s(fmt, 40), 40 * 1152 / 44100)

    def test_variable_bit_rate_is_seen(self):
        fmt, _, got, _ = framing.split(b"".join(mp3(30, vbr=(5, 13, 9))))
        self.assertEqual((len(got), fmt["cbr"], fmt["bitrate"], fmt["frame_len_max"]), (30, False, None, 144 * 256000 // 44100))

    def test_frame_headers(self):
        self.assertEqual(framing.mp3_header(bytes([0xFF, 0xFB, 0xD0, 0x00]))["len"], 835)        # 256 kbit/s, 44.1 kHz
        self.assertEqual(framing.mp3_header(bytes([0xFF, 0xFB, 0xD2, 0xC0])), {"len": 836, "sample_rate": 44100, "bitrate": 256000,
                                                                               "channels": 1, "samples": 1152, "mpeg": 1, "layer": 3})
        self.assertEqual(framing.mp3_header(bytes([0xFF, 0xF3, 0x48, 0xC4]))["samples"], 576)    # MPEG-2 layer III, 16 kHz
        for bad in (b"\xff\xfb\x00\x00", b"\xff\xfb\xf0\x00", b"\xff\xfb\x9c\x00", b"\xff\xeb\x90\x00", b"\xff\xf9\x90\x00",
                    b"\xfe\xfb\x90\x00", b"\xff\xfb\x90"):
            self.assertIsNone(framing.mp3_header(bad), bad)                 # free rate, bad rate, bad sample rate, reserved, ...

    def test_wave_and_everything_else(self):
        w = wav(1.0)
        fmt, prefix, frames, suffix = framing.split(w)
        self.assertEqual((fmt["codec"], fmt["sample_rate"], fmt["samples_per_frame"], fmt["frame_len_max"], len(prefix), len(frames)),
                         ("pcm_s16le", 16000, 320, 640, 44, 50))
        self.assertEqual(prefix + b"".join(frames) + suffix, w)
        data = random.Random(5).randbytes(5000)
        fmt, prefix, frames, suffix = framing.split(data)
        self.assertEqual((fmt["codec"], len(frames), framing.duration_s(fmt, len(frames))), ("raw", 5, None))
        self.assertEqual(b"".join(frames), data)
        self.assertEqual(framing.split(b"")[2], [])
        self.assertEqual(framing.split(b"\xff\xfb\x90\x00" * 2)[0]["codec"], "raw")      # two headers are not a stream


class TestTrees(unittest.TestCase):
    def test_a_cover_is_exactly_the_range_and_small(self):
        rng = random.Random(11)
        for depth in (1, 3, 6, 24):
            for _ in range(200):
                a = rng.randrange(1 << depth)
                b = rng.randrange(a, min(1 << depth, a + 3000))
                nodes = q.cover(a, b, depth)
                self.assertLessEqual(len(nodes), 2 * depth)
                spans = [(ix << (depth - lv), ((ix + 1) << (depth - lv)) - 1) for lv, ix in nodes]
                self.assertEqual(spans[0][0], a)
                self.assertEqual(spans[-1][1], b)
                for (_, e), (s, _) in zip(spans, spans[1:]):
                    self.assertEqual(s, e + 1)                               # no gap, no overlap, in order

    def test_a_node_of_the_key_tree_gives_the_keys_below_it_and_no_others(self):
        root = q.KeyTree(b"\x07" * 32)
        leaves = [root.leaf(i) for i in range(64)]
        self.assertEqual(len(set(leaves)), 64)
        self.assertEqual([q.KeyTree(b"\x07" * 32).leaf(i) for i in (63, 5, 5, 0, 31)], [leaves[i] for i in (63, 5, 5, 0, 31)])   # any order
        for a, b in ((5, 20), (0, 0), (17, 63), (32, 47)):
            nodes = q.cover(a, b, q.DEPTH)
            subs = [q.KeyTree(root.node(lv, ix), q.DEPTH, lv, ix) for lv, ix in nodes]
            for i in range(a, b + 1):
                t = next(t for t in subs if (i >> (q.DEPTH - t.level)) == t.idx)
                self.assertEqual(t.leaf(i), leaves[i])
            for i in (a - 1, b + 1):                                         # the neighbours are out of reach
                if 0 <= i:
                    for t in subs:
                        with self.assertRaises(AudioError):
                            t.leaf(i)
        self.assertNotEqual(q.KeyTree(b"\x08" * 32).leaf(0), leaves[0])
        enc, com = q.block_keys(leaves[3])
        self.assertEqual((len(enc), len(com)), (32, 32))
        self.assertNotIn(enc, (com, leaves[3]))
        root.wipe()
        with self.assertRaises(AudioError):
            root.leaf(1)

    def test_the_sealers_tree_gives_the_same_keys_and_forgets_what_it_gave(self):
        """A UAV taken while it records must not give up the blocks it has already sealed: the sealer keeps only the
        nodes of the key tree that lead to blocks still to come."""
        key = b"\x07" * 32
        for depth in (1, 4, 6):
            full = q.KeyTree(key, depth)
            every = {(lv, ix): full.node(lv, ix) for lv in range(depth + 1) for ix in range(1 << lv)}
            s = q.SealerTree(key, depth)
            for i in range(1 << depth):
                self.assertEqual(s.leaf(i), every[(depth, i)])
                held = s.holds()
                spans = sorted((ix << (depth - lv), ((ix + 1) << (depth - lv)) - 1) for lv, ix in held)
                # what is kept covers exactly the leaves i+1 ... and nothing before them
                self.assertEqual([x for a, b in spans for x in range(a, b + 1)], list(range(i + 1, 1 << depth)))
                self.assertLessEqual(len(held), depth)
                kept = {bytes(k) for _, _, k in s._stack}
                gone = {v for (lv, ix), v in every.items() if (ix << (depth - lv)) <= i}        # every node above or at a leaf handed out
                self.assertFalse(kept & gone)
                self.assertEqual(kept, {every[n] for n in held})
            with self.assertRaises(AudioError):
                s.leaf(1 << depth)                                           # nothing is left
        s = q.SealerTree(key)
        self.assertEqual([s.leaf(i) for i in range(40)], [q.KeyTree(key).leaf(i) for i in range(40)])       # the tree of a real clip
        for wrong in (39, 41, 0):                                            # again, ahead, back: each leaf once, in order
            with self.assertRaises(AudioError):
                s.leaf(wrong)
        nodes = [k for _, _, k in s._stack]
        s.wipe()
        self.assertTrue(all(not any(k) for k in nodes))                      # overwritten, not only dropped
        with self.assertRaises(AudioError):
            s.leaf(40)

    def test_the_root_of_blocks_that_arrive_one_by_one_is_the_root_of_the_tree(self):
        leaves = [hashlib.sha256(bytes([i])).digest() for i in range(41)]
        for n in range(1, 42):
            f = q.Frontier()
            for h in leaves[:n]:
                f.add(h)
            levels = q.merkle_levels(leaves[:n], q.tree_depth(n))
            self.assertEqual(f.root(), levels[0][0], n)
        self.assertEqual([q.tree_depth(n) for n in (1, 2, 3, 4, 5, 8, 9)], [0, 1, 2, 2, 3, 3, 4])
        with self.assertRaises(AudioError):
            q.Frontier().root()

    def test_a_range_proof_holds_for_its_range_and_for_no_other(self):
        leaves = [hashlib.sha256(bytes([i, 1])).digest() for i in range(21)]
        for n in (1, 2, 5, 16, 21):
            d = q.tree_depth(n)
            levels = q.merkle_levels(leaves[:n], d)
            root = levels[0][0]
            for a in range(n):
                for b in range(a, n):
                    proof = q.range_proof(levels, a, b)
                    self.assertLessEqual(len(proof), 2 * max(d, 1))
                    self.assertEqual(q.root_from_range(leaves[a:b + 1], a, d, proof), root)
            if n > 2:
                proof = q.range_proof(levels, 1, 1)
                self.assertNotEqual(q.root_from_range([leaves[0]], 1, d, proof), root)          # another block in its place
                try:                                                                              # the same block, another place:
                    self.assertNotEqual(q.root_from_range([leaves[1]], 2, d, proof), root)       # another root, or a proof
                except AudioError:                                                                # of the wrong shape
                    pass
                with self.assertRaises(AudioError):
                    q.root_from_range([leaves[1]], 1, d, proof[:-1])
                with self.assertRaises(AudioError):
                    q.root_from_range([], 1, d, proof)

    def test_padded_block_counts(self):
        self.assertEqual([q.padme(n) for n in (0, 1, 2, 3, 9, 16, 17, 100, 182, 1000, 1000000)],
                         [0, 1, 2, 3, 10, 16, 18, 104, 192, 1024, 1015808])
        last = 0
        for n in range(1, 5000):
            p = q.padme(n)
            self.assertTrue(n <= p <= n * 1.12 + 1 and p >= last and q.padme(p) == p)
            last = p
        self.assertLess(len({q.padme(n) for n in range(4096, 8192)}), 70)       # 4096 lengths show as fewer than 70


class Clip(Keys):
    FRAMES = mp3(60, pad_every=4)
    DATA = ID3 + b"".join(FRAMES) + TAG

    @staticmethod
    def context(frame):
        return 1_790_000_000_000 + frame * 26, 12.5000000 + frame * 1e-6, 79.5000000

    def seal(self, data=None, **kw):
        kw = {"meta": {"uav": "UAV-ALPH", "source": "file:test.mp3", "clip_no": 7}, "context": self.context, **kw}
        return q.seal_stream(self.DATA if data is None else data, self.ek, self.xpk, self.uav, **kw)

    def open(self, blob, **kw):
        kw = {"x25519_sk": self.xsk, "signer_pk": self.upk, **kw}
        return q.open_audio(blob, self.dk, **kw)


class TestSealedAudio(Clip):
    def test_round_trip_gives_the_file_back_byte_for_byte(self):
        blob, rep = self.seal()
        meta, stream, report = self.open(blob)
        self.assertEqual(stream, self.DATA)
        self.assertEqual((meta["codec"], meta["sample_rate"], meta["frames_per_block"], meta["uav"], meta["clip_no"], meta["first_audio_block"]),
                         ("mp3", 44100, 8, "UAV-ALPH", 7, 2))
        self.assertEqual((report["signature"], report["complete"], report["frames"], report["audio_blocks"], report["blocks"]),
                         ("PASS", True, 60, 8, rep["blocks"]))
        self.assertAlmostEqual(report["duration_s"], 60 * 1152 / 44100)
        self.assertEqual(report["sha256"], hashlib.sha256(self.DATA).hexdigest())
        self.assertEqual((rep["frames"], rep["audio_blocks"], rep["bytes_out"]), (60, 8, len(blob)))
        self.assertEqual(blob[:8], q.MAGIC)

    def test_capture_time_and_position_travel_inside_every_block(self):
        _, _, report = self.open(self.seal()[0])
        ctx = report["context"]
        self.assertEqual([c["first_frame"] for c in ctx], [0, 8, 16, 24, 32, 40, 48, 56])
        self.assertEqual([c["frames"] for c in ctx], [8] * 7 + [4])
        for c in ctx:
            t, lat, lon = self.context(c["first_frame"])
            self.assertEqual(c["t_ms"], t)
            self.assertAlmostEqual(c["lat"], lat, places=6)
            self.assertAlmostEqual(c["lon"], lon, places=6)
        _, _, report = self.open(self.seal(context=lambda f: (0, None, None))[0])       # no clock, no fix: said so, not zero
        self.assertEqual({(c["t_ms"], c["lat"], c["lon"]) for c in report["context"]}, {(None, None, None)})

    def test_nothing_of_the_audio_or_of_its_description_is_readable_in_the_file(self):
        blob, _ = self.seal()
        for secret in (b"SECRET-MISSION-TITLE", b"closing words", b'"codec"', b"44100", b"sample_rate", b"file:test.mp3", self.FRAMES[5][:12],
                       self.FRAMES[59][-12:]):
            self.assertNotIn(secret, blob)
        pub = q.SealedAudio(blob).public()
        self.assertEqual(set(pub), {"clip_id", "signer", "signer_fp", "kem", "blocks", "block_bytes", "closed_by_sealer", "bytes"})
        self.assertEqual((pub["signer"], pub["kem"], pub["closed_by_sealer"], pub["bytes"]), ("UAV-ALPH", "ML-KEM-1024+X25519", True, len(blob)))

    def test_every_block_has_the_same_size_whatever_it_holds(self):
        loud, quiet, vbr = b"".join(mp3(64, seed=2)), b"".join(mp3(64, seed=9)), b"".join(mp3(64, vbr=(13, 13, 13, 13)))
        a, ra = self.seal(loud)
        b, rb = self.seal(quiet)
        self.assertEqual(len(a), len(b))                                     # the same length of audio: the same file size
        sa = q.SealedAudio(a)
        self.assertEqual({len(sa.block(i)) for i in range(sa.n)}, {sa.S})
        self.assertEqual(sa.S, 32 + 28 + 8 * 417 + 16)
        # variable bit rate: frames of 64 to 256 kbit/s give blocks of one size (that of the largest frame)
        v, rv = self.seal(b"".join(mp3(64, vbr=(5, 13, 9, 7))))
        sv = q.SealedAudio(v)
        self.assertEqual({len(sv.block(i)) for i in range(sv.n)}, {32 + 28 + 8 * 835 + 16})
        self.assertEqual(len(v), len(self.seal(vbr)[0]))                     # ... and the size of a clip at the top rate throughout
        # the number of blocks shows a bucket, not the length: 465 to 496 frames of audio (12.1 to 13.0 s) all make the same file
        sizes = {len(self.seal(b"".join(mp3(n, seed=4)))[0]) for n in (465, 470, 480, 490, 496)}
        self.assertEqual(len(sizes), 1)
        self.assertEqual(q.SealedAudio(self.seal(b"".join(mp3(480, seed=4)))[0]).n, q.padme(1 + 60 + 1))

    def test_with_a_frame_cap_the_shape_does_not_depend_on_what_was_recorded(self):
        """Without a cap the largest frame of the stream sets the block size: one number that follows the recording when
        the bit rate varies. With the encoder's largest frame as the cap, quiet, loud and mixed audio look the same."""
        quiet, loud, mixed = (b"".join(mp3(64, rate=1, seed=3)), b"".join(mp3(64, rate=9, seed=4)), b"".join(mp3(64, vbr=(1, 9, 5, 3), seed=5)))
        self.assertNotEqual(self.seal(quiet)[1]["block_bytes"], self.seal(loud)[1]["block_bytes"])
        shapes = set()
        for data in (quiet, loud, mixed):
            blob, rep = self.seal(data, frame_cap=418)
            sa = q.SealedAudio(blob)
            shapes.add((len(blob), sa.n, sa.S, rep["block_bytes"]))
            self.assertEqual(self.open(blob)[1], data)
        self.assertEqual(shapes, {(len(blob), sa.n, 32 + 28 + 8 * 418 + 16, 32 + 28 + 8 * 418 + 16)})
        self.assertEqual(self.seal(loud, frame_cap=100)[1]["block_bytes"], 32 + 28 + 8 * 417 + 16)     # a cap below the stream's frames does not cut them
        for bad in (-1, 1 << 21, True):
            with self.assertRaises(ValueError):
                q.with_cap({"frame_len_max": 417}, bad)

    def test_a_sealer_holds_no_key_of_a_block_it_has_sealed(self):
        fmt, prefix, frames, suffix = framing.split(b"".join(mp3(64)))
        s = q.AudioSealer(self.ek, self.xpk, self.uav, fmt)
        blocks = s.start()
        for f in frames[:40]:
            blocks += s.add(f)
        self.assertIsInstance(s._tree, q.SealerTree)
        self.assertEqual(s._tree.next, len(blocks))
        self.assertTrue(all((ix << (q.DEPTH - lv)) >= len(blocks) for lv, ix in s._tree.holds()))            # only blocks still to come
        tail, trailer = s.finish()
        self.assertEqual(s._tree.holds(), [])                                # and nothing at all once the clip is closed
        raw = s.head + b"".join(blocks + tail) + trailer
        self.assertEqual(self.open(raw)[1], b"".join(frames[:40]))

    def test_every_changed_byte_is_detected(self):
        blob, _ = self.seal()
        sa = q.SealedAudio(blob)
        rng = random.Random(21)
        first = len(sa.head)
        positions = {0, 7, 8, 9, 12, first - 1, first, first + 31, first + 32, first + sa.S - 1, len(blob) - 1, len(blob) - 4627,
                     len(blob) - 4637, len(blob) - 4638 - 32, len(blob) - 4638 - 36, len(blob) - 4638 - 37}
        positions |= {rng.randrange(len(blob)) for _ in range(400)}
        for pos in sorted(positions):
            bad = bytearray(blob)
            bad[pos] ^= 1 << rng.randrange(8)
            with self.assertRaises(AudioError, msg=f"byte {pos} of {len(blob)}"):
                self.open(bytes(bad))

    def test_blocks_cannot_be_moved_removed_repeated_or_borrowed(self):
        blob, _ = self.seal()
        sa = q.SealedAudio(blob)
        h, S, n = len(sa.head), sa.S, sa.n
        blk = lambda i: blob[h + i * S:h + (i + 1) * S]
        tail = blob[h + n * S:]
        build = lambda order: blob[:h] + b"".join(blk(i) for i in order) + tail
        order = list(range(n))
        self.assertEqual(build(order), blob)
        for bad_order in (order[:3] + [4, 3] + order[5:],                    # two blocks swapped
                          order[:5] + order[6:],                             # one removed
                          order[:5] + [5] + order[5:],                       # one repeated
                          order[:-1],                                        # the last one cut off
                          order[::-1]):
            with self.assertRaises(AudioError):
                self.open(build(bad_order))
        other, _ = self.seal()                                               # the same audio sealed again: other keys
        ob = other[len(q.SealedAudio(other).head):]
        with self.assertRaises(AudioError):
            self.open(blob[:h + 3 * S] + ob[3 * S:4 * S] + blob[h + 4 * S:])           # a block of another clip in place
        with self.assertRaises(AudioError):
            self.open(blob[:h + n * S] + other[len(other) - len(tail):])               # another clip's root and signature
        with self.assertRaises(AudioError):
            self.open(other[:len(q.SealedAudio(other).head)] + blob[h:])               # another clip's head
        for cut in (len(blob) - 1, len(blob) - 4637, h + n * S, h + S, h, 20, 0):
            with self.assertRaises(AudioError):
                self.open(blob[:cut])
        with self.assertRaises(AudioError):
            self.open(blob + b"\x00")

    def test_two_sealings_of_one_file_share_nothing(self):
        a, _ = self.seal()
        b, _ = self.seal()
        sa, sb = q.SealedAudio(a), q.SealedAudio(b)
        self.assertNotEqual(sa.clip_id, sb.clip_id)
        self.assertEqual(len(a), len(b))
        self.assertFalse(set(sa.block(i) for i in range(sa.n)) & set(sb.block(i) for i in range(sb.n)))
        self.assertFalse(set(sa.block(i)[:32] for i in range(sa.n)) & set(sb.block(i)[:32] for i in range(sb.n)))      # commitments too

    def test_both_recording_keys_and_the_right_uav_are_needed(self):
        blob, _ = self.seal()
        with self.assertRaises(AudioError):
            q.open_audio(blob, self.other_dk, self.xsk, self.upk)             # wrong ML-KEM key
        with self.assertRaises(AudioError):
            q.open_audio(blob, self.dk, self.other_xsk, self.upk)             # wrong X25519 key
        with self.assertRaises(AudioError):
            q.open_audio(blob, self.dk, self.xsk, self.other_pk)              # signed by a UAV that is not the pinned one
        with self.assertRaises(AudioError):
            q.open_audio(blob, self.dk, self.xsk, None)                       # never opened unverified
        with self.assertRaises(ValueError):
            q.seal_stream(self.DATA, self.ek, None, self.uav)                 # never sealed without the hybrid wrap ...
        with self.assertRaises(ValueError):
            q.seal_stream(self.DATA, self.ek, self.xpk, None)                 # ... or without a signature

    def test_a_clip_signed_again_by_someone_else_is_refused(self):
        """Anyone who knows the ground station's public recording keys can seal a clip. Only the pinned UAV can sign one."""
        forged, _ = q.seal_stream(self.DATA, self.ek, self.xpk, self.other, meta={"uav": "UAV-ALPH"})
        with self.assertRaises(AudioError):
            self.open(forged)
        blob, _ = self.seal()                                                # a genuine clip, its signature replaced
        sa = q.SealedAudio(blob)
        fr = q.Frontier()
        for leaf in sa.leaves():
            fr.add(leaf)
        resigned = blob[:len(sa.head) + sa.n * sa.S] + q.trailer_for(sa.head_hash, fr, sa.flags, self.other)
        self.assertEqual(len(resigned), len(blob))
        with self.assertRaises(AudioError):
            self.open(resigned)

    def test_the_stored_copy_can_be_checked_without_any_secret(self):
        """The UAV, or anyone with its public key, can tell that a stored clip is whole: every block against the
        signed root. That is how the data audit checks the card, and how a block fetched again after a loss is checked."""
        blob, _ = self.seal()
        sa = q.SealedAudio(blob)
        sa.verify(self.upk)
        bad = bytearray(blob)
        bad[len(sa.head) + 5 * sa.S + 100] ^= 1
        with self.assertRaises(AudioError):
            q.SealedAudio(bytes(bad)).verify(self.upk)
        # one block against the root, with its proof: what a repair after a lossy transfer needs
        levels = q.merkle_levels(sa.leaves(), sa.d)
        for i in (0, 4, sa.n - 1):
            proof = q.range_proof(levels, i, i)
            self.assertEqual(q.root_from_range([q._leaf_hash(sa.clip_id, i, sa.block(i))], i, sa.d, proof), sa.root)
            self.assertNotEqual(q.root_from_range([q._leaf_hash(sa.clip_id, i, bytes(sa.S))], i, sa.d, proof), sa.root)

    def test_a_clip_cut_off_by_a_power_failure_is_closed_from_what_reached_the_card(self):
        fmt, prefix, frames, suffix = framing.split(self.DATA)
        s = q.AudioSealer(self.ek, self.xpk, self.uav, fmt, prefix=prefix, meta={"uav": "UAV-ALPH"}, context=self.context)
        written = s.head + b"".join(s.start())
        for f in frames[:35]:                                                # 4 whole blocks and 3 frames nobody will see
            written += b"".join(s.add(f))
        on_card = written + b"\x55" * 700                                    # ... and a block that was half written
        with self.assertRaises(AudioError):
            self.open(on_card)                                               # no trailer: not a clip
        saved = q.recover(on_card, self.uav)
        meta, stream, report = self.open(saved)
        self.assertEqual(stream, prefix + b"".join(frames[:32]))
        self.assertEqual((report["complete"], report["closed_by_sealer"], report["frames"], report["audio_blocks"]), (False, False, 32, 4))
        self.assertEqual(meta["uav"], "UAV-ALPH")
        clean, _ = self.seal()                                               # "closed by its sealer" is signed: it cannot be claimed
        sa = q.SealedAudio(clean)
        at = len(sa.head) + sa.n * sa.S + 8
        self.assertEqual(clean[at], q.CLEAN_END)
        with self.assertRaises(AudioError):
            self.open(clean[:at] + b"\x00" + clean[at + 1:])
        with self.assertRaises(AudioError):
            q.recover(s.head + b"\x00" * 100, self.uav)

    def test_the_sealer_refuses_what_would_break_its_promises(self):
        fmt, prefix, frames, suffix = framing.split(self.DATA)
        s = q.AudioSealer(self.ek, self.xpk, self.uav, fmt)
        s.start()
        with self.assertRaises(AudioError):
            s.add(b"\xff\xfb\x90\x00" + bytes(600))                          # larger than the clip was set up for
        s.add(frames[0])
        s.finish()
        with self.assertRaises(AudioError):
            for f in frames[:8]:
                s.add(f)                                                     # closed: its keys are gone
        with self.assertRaises(ValueError):
            q.AudioSealer(self.ek, self.xpk, self.uav, {**fmt, "frame_len_max": 0})
        with self.assertRaises(ValueError):
            q.AudioSealer(self.ek, self.xpk, self.uav, fmt, frames_per_block=0)

    def test_wave_and_raw_streams_are_sealed_the_same_way(self):
        w = wav(2.0)
        blob, rep = self.seal(w, frames_per_block=10)
        meta, stream, report = self.open(blob)
        self.assertEqual(stream, w)
        self.assertEqual((meta["codec"], rep["audio_blocks"], report["frames"]), ("pcm_s16le", 10, 100))
        self.assertAlmostEqual(report["duration_s"], 2.0)
        raw = random.Random(8).randbytes(20000)
        meta, stream, report = self.open(self.seal(raw)[0])
        self.assertEqual((stream, meta["codec"], report["duration_s"]), (raw, "raw", None))
        self.assertEqual(self.open(self.seal(b"")[0])[1], b"")               # even nothing at all


class TestExcerpt(Clip):
    def setUp(self):
        self.blob, _ = self.seal()
        self.meta, _, self.report = self.open(self.blob)

    def excerpt(self, a=3, b=5, **kw):
        return q.make_excerpt(self.blob, self.dk, self.xsk, self.upk, a, b, **kw)

    def test_an_excerpt_proves_itself_to_anyone_with_the_public_key(self):
        ex = self.excerpt()                                                  # blocks 3..5 are audio blocks 1..3: frames 8..31
        info, audio, blocks = q.verify_excerpt(ex, self.upk)
        self.assertEqual(audio, b"".join(self.FRAMES[8:32]))
        self.assertEqual((info["signature"], info["signer"], info["frames"], info["ranges"], info["blocks_in_clip"]),
                         ("PASS", "UAV-ALPH", 24, [[0, 0], [3, 5]], self.report["blocks"]))
        self.assertEqual((info["meta"]["codec"], info["meta"]["uav"]), ("mp3", "UAV-ALPH"))
        self.assertAlmostEqual(info["duration_s"], 24 * 1152 / 44100)
        self.assertEqual([(b["index"], b["first_frame"], b["frames"]) for b in blocks[1:]], [(3, 8, 8), (4, 16, 8), (5, 24, 8)])
        self.assertEqual(blocks[1]["t_ms"], self.context(8)[0])              # when and where, with what was said
        self.assertAlmostEqual(blocks[1]["lat"], self.context(8)[1], places=6)
        self.assertLess(len(ex), len(self.blob) // 2)

    def test_the_description_stays_behind_if_it_is_not_released(self):
        info, audio, blocks = q.verify_excerpt(self.excerpt(with_meta=False), self.upk)
        self.assertEqual((info["meta"], info["duration_s"], info["ranges"], len(blocks)), (None, None, [[3, 5]], 3))
        self.assertEqual(audio, b"".join(self.FRAMES[8:32]))
        for sealed_away in (b"file:test.mp3", b"clip_no", b'"codec"'):
            self.assertNotIn(sealed_away, self.excerpt(with_meta=False))

    def test_the_released_keys_open_nothing_else(self):
        ex = self.excerpt(with_meta=False)
        sa = q.SealedAudio(self.blob)
        # the keys in the bundle, as its receiver has them
        off = 10 + struct.unpack_from("!H", ex, 8)[0]
        off += 4 + struct.unpack_from("!I", ex, off)[0] + 32
        off += 2 + struct.unpack_from("!H", ex, off)[0]
        nk, npf = struct.unpack_from("!HH", ex, off)
        trees = []
        for k in range(nk):
            lv, ix = struct.unpack_from("!BI", ex, off + 4 + 37 * k)
            trees.append(q.KeyTree(ex[off + 9 + 37 * k:off + 41 + 37 * k], q.DEPTH, lv, ix))
        plain_len = sa.S - 48
        opened = 0
        for i in range(sa.n):
            for t in trees:
                try:
                    q.open_block(t, sa.clip_id, sa.head_hash, i, sa.block(i), plain_len)
                    opened += 1
                    self.assertIn(i, (3, 4, 5))
                except AudioError:
                    pass
        self.assertEqual(opened, 3)
        # and a key cannot be passed off for another block: the commitment says which key a block was sealed under
        wrong = q.KeyTree(b"\x01" * 32)
        with self.assertRaises(AudioError) as cm:
            q.open_block(wrong, sa.clip_id, sa.head_hash, 3, sa.block(3), plain_len)
        self.assertIn("not the one the block was sealed under", str(cm.exception))

    def test_an_excerpt_changed_anywhere_is_refused(self):
        ex = self.excerpt()
        rng = random.Random(33)
        for pos in sorted({0, 8, 9, 11, len(ex) - 1} | {rng.randrange(len(ex)) for _ in range(400)}):
            bad = bytearray(ex)
            bad[pos] ^= 1 << rng.randrange(8)
            with self.assertRaises(AudioError, msg=f"byte {pos} of {len(ex)}"):
                q.verify_excerpt(bytes(bad), self.upk)
        for cut in (len(ex) - 1, len(ex) // 2, 40, 9, 0):
            with self.assertRaises(AudioError):
                q.verify_excerpt(ex[:cut], self.upk)
        with self.assertRaises(AudioError):
            q.verify_excerpt(ex + b"\x00", self.upk)
        with self.assertRaises(AudioError):
            q.verify_excerpt(ex, self.other_pk)                              # not this UAV's clip
        with self.assertRaises(AudioError):
            q.verify_excerpt(ex, None)

    def test_blocks_cannot_be_presented_as_other_blocks_of_the_clip(self):
        """An excerpt of blocks 3..5 relabelled as 4..6, or taken from another sealing of the same audio."""
        ex = self.excerpt(with_meta=False)
        jl = struct.unpack_from("!H", ex, 8)[0]
        info = json.loads(ex[10:10 + jl])
        info["ranges"] = [[4, 6]]
        ij = json.dumps(info, sort_keys=True).encode()
        self.assertEqual(len(ij), jl)
        with self.assertRaises(AudioError):
            q.verify_excerpt(ex[:10] + ij + ex[10 + jl:], self.upk)
        other, _ = self.seal()
        ex2 = q.make_excerpt(other, self.dk, self.xsk, self.upk, 3, 5, with_meta=False)
        S = q.SealedAudio(self.blob).S
        with self.assertRaises(AudioError):
            q.verify_excerpt(ex[:-3 * S] + ex2[-3 * S:], self.upk)           # the other clip's blocks under this clip's proof
        for a, b in ((0, 3), (5, 3), (3, 99), (-1, 2)):
            with self.assertRaises(AudioError):
                self.excerpt(a, b)

    def test_seconds_become_blocks_by_arithmetic(self):
        per = 8 * 1152 / 44100                                               # 0.209 s a block
        n = self.report["audio_blocks"]
        self.assertEqual(q.blocks_for_time(self.meta, n, 0.0, 0.1), (2, 2))
        self.assertEqual(q.blocks_for_time(self.meta, n, per, 3 * per), (3, 4))
        self.assertEqual(q.blocks_for_time(self.meta, n, 0.25, 0.9), (3, 6))
        self.assertEqual(q.blocks_for_time(self.meta, n, 0.0, 1e6), (2, 9))
        self.assertEqual(q.blocks_for_time(self.meta, n, 50.0, 60.0), (9, 9))
        a, b = q.blocks_for_time(self.meta, n, 0.25, 0.9)
        info, audio, _ = q.verify_excerpt(self.excerpt(a, b), self.upk)
        self.assertEqual(audio, b"".join(self.FRAMES[8:40]))
        with self.assertRaises(AudioError):
            q.blocks_for_time({"codec": "raw", "frames_per_block": 8}, 4, 0, 1)


class TestStoreAndDesk(Clip):
    """The UAV's store (the file that stands in for a microphone, the chain of clips) and the ground station's desk
    (clips from the card, clips that come in live with blocks missing, excerpts)."""
    FIX = {"mode": 3, "lat": 12.5000000, "lon": 79.5000000, "alt_m": 31.0, "time": "2026-10-05T03:00:00Z", "sats_used": 11}

    def setUp(self):
        import tempfile
        from pathlib import Path
        from kyber6g.audio.store import AudioStore
        from kyber6g.ground.audio_desk import AudioDesk
        self.tmp = Path(tempfile.mkdtemp())
        self.store = AudioStore(self.tmp / "uav", self.ek, self.xpk, self.uav, "UAV-ALPH", gnss=lambda: dict(self.FIX))
        self.notes = []
        self.desk = AudioDesk(self.tmp / "gcs", self.dk, self.xsk, self.upk, lambda k, m: self.notes.append((k, m)), ask_uav=self.ask_uav)
        self.asked = []

    def put(self, name="voice.mp3", data=None):
        (self.store.inbox / name).write_bytes(self.DATA if data is None else data)

    def ask_uav(self, cmd, args):                                            # the UAV's answer to a request for blocks
        self.asked.append((cmd, dict(args)))
        data = self.store.blocks(args["name"], args["blocks"])
        self.desk.on_blocks({"name": args["name"], "meta": {"blocks": args["blocks"], "tag": args["tag"]}}, data)
        return {"ok": True}

    def test_a_source_file_becomes_a_clip_the_uav_cannot_read_and_the_source_is_gone(self):
        import stat
        self.assertEqual(self.store.usage(), {"count": 0, "bytes": 0, "sources": 0, "last_clip_no": 0})
        self.put()
        self.assertEqual(self.store.sources(), [{"name": "voice.mp3", "bytes": len(self.DATA)}])
        # what `list_audio` answers: the waiting files by name (the dashboard lists them), beside the counts
        waiting = self.store.listing()
        self.assertEqual((waiting["sources"], waiting["clips"], waiting["count"]), ([{"name": "voice.mp3", "bytes": len(self.DATA)}], [], 0))
        res = self.store.record("voice.mp3")
        self.assertEqual((self.store.listing()["sources"], [c["name"] for c in self.store.listing()["clips"]]), ([], [res["name"]]))
        self.assertEqual((res["clip_no"], res["frames"], res["audio_blocks"], res["codec"], res["source_kept"]), (1, 60, 8, "mp3", False))
        self.assertEqual(self.store.sources(), [])                           # the plain file is not kept
        path = self.store.path(res["name"])
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.store.dir.stat().st_mode), 0o700)
        self.assertEqual([p.name for p in self.store.dir.glob("*.part")], [])
        raw = self.store.read(res["name"])
        self.assertNotIn(self.FRAMES[3][:16], raw)
        self.assertEqual(self.store.check(res["name"], self.upk)["blocks"], res["blocks"])      # whole, by its own signature
        meta, stream, rep = self.open(raw)
        self.assertEqual(stream, self.DATA)
        self.assertEqual((meta["uav"], meta["source"], meta["source_name"], meta["clip_no"], meta["prev_root"]),
                         ("UAV-ALPH", "file", "voice.mp3", 1, None))
        self.assertAlmostEqual(rep["context"][0]["lat"], 12.5000000, places=6)
        self.assertEqual(self.store.list()[0]["name"], res["name"])
        with self.assertRaises(FileNotFoundError):
            self.store.record("voice.mp3")
        with self.assertRaises(FileNotFoundError):
            self.store.read("../../etc/passwd")

    def test_every_clip_names_the_one_before_it(self):
        self.put("a.mp3"); r1 = self.store.record("a.mp3")
        self.put("b.mp3"); r2 = self.store.record("b.mp3")
        self.put("c.mp3"); r3 = self.store.record("c.mp3")
        m2 = self.open(self.store.read(r2["name"]))[0]
        self.assertEqual((m2["clip_no"], m2["prev_root"]), (2, r1["root"]))
        info = lambda r: {"name": r["name"], "size": r["bytes"], "integrity": "PASS", "seconds": 0.1}
        e1 = self.desk.on_clip(info(r1), self.store.read(r1["name"]))
        e3 = self.desk.on_clip(info(r3), self.store.read(r3["name"]))        # clip 2 was not fetched (or was deleted on the card)
        e2 = self.desk.on_clip(info(r2), self.store.read(r2["name"]))
        self.assertEqual((e1["chain"], e2["chain"]), ("first clip", "OK: follows clip 1"))
        self.assertIn("clip 2 not fetched", e3["chain"])
        self.assertEqual((e1["decrypt"], e1["signature"], e1["codec"], e1["frames"], e1["how"]), ("PASS", "PASS", "mp3", 60, "from the UAV's card"))
        self.assertEqual((self.desk.dir / e1["file"]).read_bytes(), self.DATA)
        self.assertEqual([c["name"] for c in self.desk.state()["clips"]], [r2["name"], r3["name"], r1["name"]])
        # a clip number that comes back with other content (the card was put back to an older state and used again)
        import shutil
        shutil.rmtree(self.store.dir)
        from kyber6g.audio.store import AudioStore
        again = AudioStore(self.store.dir, self.ek, self.xpk, self.uav, "UAV-ALPH")
        (again.inbox / "x.mp3").write_bytes(self.DATA)
        rx = again.record("x.mp3")
        ex = self.desk.on_clip(info(rx), again.read(rx["name"]))
        self.assertIn("CONFLICT", ex["chain"])

    def test_a_damaged_clip_is_refused_and_nothing_is_stored(self):
        self.put(); res = self.store.record("voice.mp3")
        raw = bytearray(self.store.read(res["name"]))
        raw[len(raw) // 2] ^= 1
        e = self.desk.on_clip({"name": res["name"], "size": len(raw), "integrity": "PASS"}, bytes(raw))
        self.assertTrue(e["decrypt"].startswith("FAILED"))
        self.assertNotIn("url", e)
        self.assertEqual(self.desk.stats["clips_refused"], 1)
        self.assertEqual(list((self.desk.dir / "sealed").iterdir()), [])
        e = self.desk.on_clip({"name": res["name"], "size": 5, "integrity": "FAIL"}, None)
        self.assertIn("transfer incomplete", e["decrypt"])

    def live(self, drop=(), forge=(), tag="a1b2c3d4"):
        """A clip sent while it is sealed; blocks in `drop` are lost on the air, blocks in `forge` arrive changed."""
        from kyber6g.ground.audio_desk import LIVE_EXT
        self.put()
        got = {"blocks": 0}

        def on_block(kind, i, b):
            if kind == "head":
                self.desk.on_head({"name": tag + ".head", "meta": {"tag": tag}}, b)
            elif kind == "block":
                got["blocks"] += 1
                if i in drop:
                    return
                if i in forge:
                    b = b[:100] + bytes([b[100] ^ 1]) + b[101:]
                parts = [b[k:k + 1100] for k in range(0, len(b), 1100)]
                for k, p in enumerate(parts):
                    self.desk.on_live_chunk(LIVE_EXT.pack(b"L", bytes.fromhex(tag), i, k, len(parts)), p)
            else:
                got["trailer"] = b
        res = self.store.record("voice.mp3", on_block=on_block)
        heard = b"".join(self.desk.listen(tag, timeout=0.05)) if not drop else None
        self.desk.on_trailer({"name": tag + ".trailer", "meta": {"tag": tag, "name": res["name"], "blocks": res["blocks"]}}, got["trailer"])
        return res, heard

    def test_a_live_clip_is_heard_as_it_comes_and_stored_when_its_signature_is_there(self):
        res, heard = self.live()
        self.assertEqual(heard, self.DATA)                                   # opened block by block, before the trailer
        e = self.desk.clips[0]
        self.assertEqual((e["how"], e["decrypt"], e["signature"], e["live_blocks_on_air"], e["live_blocks_repaired"], e["chain"]),
                         ("live", "PASS", "PASS", res["blocks"], 0, "first clip"))
        self.assertEqual(self.asked, [])
        self.assertEqual((self.desk.dir / e["file"]).read_bytes(), self.DATA)
        self.assertEqual((self.desk.dir / "sealed" / res["name"]).read_bytes(), self.store.read(res["name"]))     # the same bytes as on the card
        self.assertEqual(self.desk.state()["live"]["done"], True)

    def test_blocks_lost_on_the_air_are_fetched_from_the_card_and_checked_against_the_signed_root(self):
        res, _ = self.live(drop={3, 4, 9})
        self.assertEqual(self.asked, [("audio_blocks", {"name": res["name"], "blocks": [3, 4, 9], "tag": "a1b2c3d4"})])
        e = self.desk.clips[0]
        self.assertEqual((e["decrypt"], e["signature"], e["live_blocks_on_air"], e["live_blocks_repaired"]), ("PASS", "PASS", res["blocks"] - 3, 3))
        self.assertEqual((self.desk.dir / e["file"]).read_bytes(), self.DATA)
        self.assertEqual(self.desk.stats["blocks_repaired"], 3)

    def test_a_request_for_missing_blocks_that_gets_no_answer_is_made_again(self):
        """Found on the real link with datagrams dropped: the request for the missing blocks, or its answer, was lost,
        nothing asked again, and the clip was never completed."""
        from kyber6g.ground import audio_desk
        answer, real = [False, False, True], self.ask_uav             # the first two requests go unanswered

        def lossy(cmd, args):
            if answer.pop(0):
                return real(cmd, args)
            self.asked.append((cmd, dict(args)))
        self.desk.ask_uav = lossy
        res, _ = self.live(drop={3, 4, 9})
        lc = self.desk.live["a1b2c3d4"]
        self.assertEqual((len(self.asked), lc.done, self.desk.clips), (1, False, []))
        self.desk.tick()                                                     # too early: nothing is asked again
        self.assertEqual(len(self.asked), 1)
        lc.asked_at -= audio_desk.REPAIR_RETRY_S + 0.1
        self.desk.tick()                                                     # the second request (lost as well)
        self.assertEqual((len(self.asked), lc.done), (2, False))
        lc.asked_at -= audio_desk.REPAIR_RETRY_S + 0.1
        self.desk.tick()                                                     # not yet: the wait doubles
        self.assertEqual(len(self.asked), 2)
        lc.asked_at -= audio_desk.REPAIR_RETRY_S
        self.desk.tick()                                                     # the third is answered
        e = self.desk.clips[0]
        self.assertEqual((len(self.asked), lc.done, e["decrypt"], e["signature"], e["live_blocks_repaired"], e["live_requests_for_blocks"]),
                         (3, True, "PASS", "PASS", 3, 3))
        self.assertEqual((self.desk.dir / e["file"]).read_bytes(), self.DATA)
        self.assertTrue(all(a[1]["blocks"] == [3, 4, 9] for a in self.asked))
        self.desk.tick()                                                     # done: nothing more is asked
        self.assertEqual(len(self.asked), 3)

    def test_a_clip_whose_blocks_never_come_is_given_up_and_said_so(self):
        from kyber6g.ground import audio_desk
        self.desk.ask_uav = lambda cmd, args: self.asked.append((cmd, dict(args)))       # the UAV never answers
        res, _ = self.live(drop={5})
        lc = self.desk.live["a1b2c3d4"]
        for _ in range(audio_desk.REPAIR_TRIES + 3):
            if lc.asked_at is not None:
                lc.asked_at -= audio_desk.REPAIR_RETRY_S * 2 ** audio_desk.REPAIR_TRIES
            self.desk.tick()
        self.assertEqual((len(self.asked), lc.done, self.desk.clips), (audio_desk.REPAIR_TRIES, True, []))
        self.assertTrue(any("did not come" in m and "fetch the clip from the card" in m for _, m in self.notes))
        self.assertEqual(list((self.desk.dir / "sealed").iterdir()), [])     # nothing half-finished is stored

    def test_a_block_changed_on_the_air_is_not_played_and_is_replaced(self):
        res, heard = self.live(forge={5})
        self.assertEqual(heard, self.DATA[:41] + b"".join(self.FRAMES[:24]) + b"".join(self.FRAMES[32:]) + TAG)    # block 5: frames 24..31
        self.assertEqual(self.asked[0][1]["blocks"], [5])
        e = self.desk.clips[0]
        self.assertEqual((e["decrypt"], e["live_blocks_refused"], e["live_blocks_repaired"]), ("PASS", 1, 1))
        self.assertEqual((self.desk.dir / e["file"]).read_bytes(), self.DATA)

    def test_a_listener_is_not_kept_waiting_for_a_block_that_never_comes(self):
        import time as _t
        from kyber6g.ground import audio_desk
        from kyber6g.ground.audio_desk import LIVE_EXT
        self.put()
        blocks = {}
        self.store.record("voice.mp3", on_block=lambda kind, i, b: blocks.__setitem__(i if kind == "block" else kind, b))
        tag = "0badf00d"
        self.desk.on_head({"meta": {"tag": tag}}, blocks["head"])
        send = lambda i: [self.desk.on_live_chunk(LIVE_EXT.pack(b"L", bytes.fromhex(tag), i, k, 4), blocks[i][k * 1100:(k + 1) * 1100]) for k in range(4)]
        for i in (0, 1, 2, 4):                                               # block 3 is missing
            send(i)
        lc = self.desk.live[tag]
        self.assertEqual(lc.next_play, 3)                                    # waiting for it ...
        _t.sleep(audio_desk.SKIP_AFTER_S + 0.1)
        self.desk.tick()
        self.assertEqual(lc.next_play, 5)                                    # ... but not for long
        self.assertEqual(b"".join(d for _, d in lc.played), self.DATA[:41] + b"".join(self.FRAMES[:8]) + b"".join(self.FRAMES[16:24]))

    def test_a_listener_that_comes_before_the_clip_waits_for_it(self):
        """The dashboard's player asks for the clip by the tag in the UAV's answer, and that answer is usually here
        before the clip's head. (Found on the real link: the player got "no live audio".)"""
        import threading
        import time as _t
        from kyber6g.ground import audio_desk
        heard = []
        th = threading.Thread(target=lambda: heard.append(b"".join(self.desk.listen("a1b2c3d4", timeout=5))), daemon=True)
        th.start()
        _t.sleep(0.3)                                                        # the listener is waiting; nothing has come yet
        self.assertTrue(th.is_alive())
        self.live()
        th.join(timeout=10)
        self.assertEqual(heard, [self.DATA])
        # a clip that never begins does not hold the listener (a server thread) for long
        old, audio_desk.LISTEN_WAIT_S = audio_desk.LISTEN_WAIT_S, 0.2
        try:
            t0 = _t.monotonic()
            self.assertEqual(list(self.desk.listen("ffffffff", timeout=30)), [])
            self.assertLess(_t.monotonic() - t0, 2.0)
        finally:
            audio_desk.LISTEN_WAIT_S = old

    def test_a_finished_live_clip_gives_its_memory_back(self):
        from kyber6g.ground import audio_desk
        res, _ = self.live()
        lc = self.desk.live["a1b2c3d4"]
        self.desk.tick()                                                     # notes when it was finished
        self.assertEqual((len(lc.blocks), self.desk.state()["live"]["blocks"]), (res["blocks"], res["blocks"]))
        self.assertEqual(b"".join(self.desk.listen("a1b2c3d4", timeout=0.05)), self.DATA)       # a late listener still gets it
        lc.done_at -= audio_desk.KEEP_DONE_S + 1
        self.desk.tick()
        self.assertEqual((len(lc.blocks), len(lc.played)), (0, 0))
        self.assertEqual((self.desk.state()["live"]["blocks"], self.desk.state()["live"]["done"]), (res["blocks"], True))
        self.assertEqual((self.desk.dir / self.desk.clips[0]["file"]).read_bytes(), self.DATA)   # the clip itself is on disk

    def test_an_excerpt_from_the_desk_is_checked_the_way_its_receiver_would(self):
        self.put(); res = self.store.record("voice.mp3")
        self.desk.on_clip({"name": res["name"], "size": res["bytes"], "integrity": "PASS"}, self.store.read(res["name"]))
        r = self.desk.excerpt(res["name"], 0.25, 0.9)
        self.assertEqual((r["blocks"], r["frames"], r["verified_with_public_key_only"], r["with_description"]), ([3, 6], 32, "PASS", True))
        self.assertAlmostEqual(r["lat"], 12.5000000, places=6)
        bundle = (self.desk.dir / "excerpts" / r["bundle"].rsplit("/", 1)[1]).read_bytes()
        info, audio, blocks = q.verify_excerpt(bundle, self.upk)
        self.assertEqual(audio, b"".join(self.FRAMES[8:40]))
        self.assertEqual((self.desk.dir / "excerpts" / r["audio"].rsplit("/", 1)[1]).read_bytes(), audio)
        self.assertLess(r["bundle_bytes"], r["clip_bytes"])
        with self.assertRaises(FileNotFoundError):
            self.desk.excerpt("nothing.k6gaud", 0, 1)

    def test_a_clip_cut_off_while_it_was_written_is_closed_at_the_next_start(self):
        from kyber6g.audio.store import AudioStore
        self.put(); res = self.store.record("voice.mp3", keep_source=True)
        whole = self.store.read(res["name"])
        sa = q.SealedAudio(whole)
        (self.store.dir / "aud_cut_000002.k6gaud.part").write_bytes(whole[:len(sa.head) + 5 * sa.S + 123])       # as a power cut leaves it
        (self.store.dir / "aud_cut_000003.k6gaud.part").write_bytes(whole[:len(sa.head) + 10])                    # not one whole block
        again = AudioStore(self.store.dir, self.ek, self.xpk, self.uav, "UAV-ALPH")
        self.assertEqual(again.recover_parts(), ["aud_cut_000002.k6gaud"])
        self.assertEqual(list(again.dir.glob("*.part")), [])
        meta, stream, rep = self.open(again.read("aud_cut_000002.k6gaud"))
        self.assertEqual((rep["complete"], rep["audio_blocks"], stream), (False, 3, self.DATA[:41] + b"".join(self.FRAMES[:24])))


if __name__ == "__main__":
    unittest.main()
