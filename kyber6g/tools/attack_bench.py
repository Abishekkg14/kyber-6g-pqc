"""Attack experiments against the implementation itself.

    python -m kyber6g.tools.attack_bench [-n 1.0] [-o attacks_<host>.json] [--media DIR]

Every experiment here attacks the REAL code (the handshake, the rekey and ratchet, the record layer, the parsers of
stored photos and recordings, a ground-station link object on a real socket) with what an attacker on the network or
with access to the storage can do, many times over, and counts what happened. Nothing is simulated and nothing is
assumed: an experiment reports how many attempts were made, how many were ACCEPTED (the number that matters; it has
to be 0 for an attack and "all" for a legitimate use), and the reasons the implementation gave for refusing the rest.

What such experiments can and cannot show: that the implementation does what the design says at the points an
attacker can reach, for the inputs tried. They are not a proof, and they say nothing about the hardness of ML-KEM,
ML-DSA, X25519 or AES - that rests on the public analysis of those algorithms (see docs/CRYPTANALYSIS_REPORT.txt).

Groups
  record      forged, modified, replayed, reordered, spliced and truncated records; uniqueness of (key, nonce)
  handshake   impersonation with another key, modified messages, downgrade, replay, mixed transcripts, bad key shares
  rekey       forged, replayed, stale and out-of-context 1-RTT Cached RapidRekey requests; modified answers
  stored      modified, cut, re-ordered, re-signed and forged photos and recordings (file format 2)
  flood       forged ClientHellos sent to a ground-station link on a real socket while a genuine UAV connects
  timing      does the time to refuse a record or a Finished value depend on WHERE it is wrong?
  statistics  byte statistics of ciphertext against plaintext for stored photos and video (needs --media: the ground
              station's data directory, which holds both), and how two encryptions of the same picture differ

`-n` scales the number of attempts (1.0: about a minute on the laptop, several on the Raspberry Pi).
"""
import argparse
import collections
import hashlib
import json
import math
import os
import platform
import random
import socket
import statistics
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from ..crypto import handshake as hs
from ..crypto import identity as idm
from ..crypto import keyschedule as ks
from ..crypto.record import HDR, HDR_LEN, PTYPE_RECORD, RecordError, Session
from ..crypto.secure_bytes import ct_equal
from ..crypto.suites import get_suite
from ..recording import sealing
from ..recording.photos import PhotoError, open_image, seal_image
from ..recording.recorder import EncryptedRecorder, RecordingError, SEG_HDR, decrypt_recording
from ..transport import framing
from .bench_crypto import environment

UAV_ID, GCS_ID = b"UAV-ATTK", b"GCS-ATTK"
CFG = SimpleNamespace(rotate_seconds=3600.0, rotate_packets=1 << 30, epoch_grace_seconds=3.0, replay_window=2048)
MOB = b"\x00" * 8
RNG = random.Random(20261004)


class World:
    """Keys of a UAV, a ground station and an attacker, and ways to make genuine sessions."""

    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="k6g_attack_"))
        self.upk, self.gpk = idm.generate_identity(self.dir, "uav"), idm.generate_identity(self.dir, "gcs")
        self.uav, self.gcs = idm.load_identity(self.dir, "uav", UAV_ID), idm.load_identity(self.dir, "gcs", GCS_ID)
        other = Path(tempfile.mkdtemp(prefix="k6g_attacker_"))
        self.apk_u, self.apk_g = idm.generate_identity(other, "uav"), idm.generate_identity(other, "gcs")
        self.att_uav, self.att_gcs = idm.load_identity(other, "uav", UAV_ID), idm.load_identity(other, "gcs", GCS_ID)
        self.suite = get_suite(1)
        self.ek = idm.generate_recording_kem(self.dir)
        self.dk = idm.load_recording_dk(self.dir)
        self.xpk = idm.generate_recording_x25519(self.dir)
        self.xsk = idm.load_recording_xsk(self.dir)
        self.other_dk = (lambda d: (idm.generate_recording_kem(d), idm.load_recording_dk(d))[1])(Path(tempfile.mkdtemp(prefix="k6g_otherkey_")))
        self.other_xsk = x25519.X25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def server(self):
        return hs.ServerHandshake(self.gcs, {UAV_ID: self.upk})

    def handshake(self, server=None, suite=1):
        """A genuine full handshake: (client secrets, server secrets, server, messages)."""
        server = server or self.server()
        ch = hs.ClientHandshake(self.uav, self.gpk, suite, MOB)
        hello = ch.client_hello()
        sh = server.process_client_hello(hello)
        c, cf = ch.process_server_hello(sh)
        s, *_ = server.process_client_finished(cf)
        return c, s, server, (hello, sh, cf)

    def sessions(self, suite=1):
        c, s, *_ = self.handshake(suite=suite)
        return Session(c, get_suite(suite), "uav", CFG), Session(s, get_suite(suite), "gcs", CFG)

    def cleanup(self):
        for d in (self.dir,):
            for p in sorted(d.glob("**/*"), reverse=True):
                try:
                    p.unlink() if p.is_file() else p.rmdir()
                except OSError:
                    pass


def flip(data: bytes, pos_bits=None) -> bytes:
    b = bytearray(data)
    i = RNG.randrange(len(b) * 8) if pos_bits is None else pos_bits
    b[i // 8] ^= 1 << (i % 8)
    return bytes(b)


class Tally:
    def __init__(self, attack, what, expect="refused"):
        self.r = {"attack": attack, "what": what, "expect": expect, "attempts": 0, "accepted": 0, "outcomes": collections.Counter()}
        self.t0 = time.perf_counter()

    def note(self, outcome, accepted=False):
        self.r["attempts"] += 1
        self.r["accepted"] += bool(accepted)
        self.r["outcomes"]["ACCEPTED" if accepted else str(outcome)[:70]] += 1

    def done(self, **more):
        self.r["outcomes"] = dict(self.r["outcomes"].most_common())
        self.r["seconds"] = round(time.perf_counter() - self.t0, 2)
        ok = self.r["accepted"] == (0 if self.r["expect"] == "refused" else self.r["attempts"])
        self.r["verdict"] = "PASS" if ok and self.r["attempts"] else "FAIL"
        self.r.update(more)
        return self.r


def try_open(sess, pkt):
    try:
        sess.open(pkt)
        return None
    except RecordError as e:
        return e.reason


# ------------------------------------------------------------------------------------------------------ records
def record_attacks(w: World, n):
    out = []
    tx, rx = w.sessions()
    payload, ext = os.urandom(1100), os.urandom(9)

    t = Tally("record: one bit changed", "a genuine record with one random bit flipped anywhere (header, extension, ciphertext, tag)")
    still = 0
    for _ in range(int(40000 * n)):
        rec = tx.seal(ks.STREAM_VIDEO, payload, ext)
        why = try_open(rx, flip(rec))
        t.note(why, accepted=why is None)
        still += try_open(rx, rec) is None        # the forgery must not have used up the genuine record's place
    out.append(t.done(genuine_record_still_accepted_afterwards=still))

    t = Tally("record: forged", "random bytes behind a correct header (right session, stream, epoch, a fresh sequence number)")
    for i in range(int(40000 * n)):
        pkt = HDR.pack(1, PTYPE_RECORD, ks.STREAM_VIDEO, 9, tx.session_id, 0, tx.tx[ks.STREAM_VIDEO].seq + 5 + i) + os.urandom(9 + 1100 + 16)
        why = try_open(rx, pkt)
        t.note(why, accepted=why is None)
    out.append(t.done())

    tx, rx = w.sessions(suite=2)
    t = Tally("record: second suite (ChaCha20-Poly1305)", "the same two attacks on a session of suite 0x0002: one bit changed, and "
                                                           "random bytes behind a correct header")
    for i in range(int(15000 * n)):
        rec = tx.seal(ks.STREAM_VIDEO, payload, ext)
        why = try_open(rx, flip(rec))
        t.note(why, accepted=why is None)
        assert try_open(rx, rec) is None
        pkt = HDR.pack(1, PTYPE_RECORD, ks.STREAM_VIDEO, 9, tx.session_id, 0, tx.tx[ks.STREAM_VIDEO].seq + 5 + i) + os.urandom(9 + 1100 + 16)
        why = try_open(rx, pkt)
        t.note(why, accepted=why is None)
    out.append(t.done(aead=get_suite(2).aead_name))

    tx, rx = w.sessions()
    t = Tally("record: replayed", "every record of a stream delivered again, at once and after 5000 more records")
    recs = [tx.seal(ks.STREAM_TELEMETRY, b"tm%06d" % i) for i in range(int(8000 * n) + 5000)]
    first = recs[:len(recs) - 5000]
    for r in first:
        assert try_open(rx, r) is None
        why = try_open(rx, r)
        t.note(why, accepted=why is None)
    for r in recs[len(first):]:
        try_open(rx, r)
    for r in first:
        why = try_open(rx, r)
        t.note(why, accepted=why is None)
    out.append(t.done())

    tx, rx = w.sessions()
    t = Tally("record: reordered (legitimate)", "records delivered out of order within the replay window: each must be accepted exactly once",
              expect="accepted")
    recs = [tx.seal(ks.STREAM_VIDEO, payload, ext) for _ in range(int(20000 * n))]
    for i in range(0, len(recs), 500):
        block = recs[i:i + 500]
        RNG.shuffle(block)
        for r in block:
            why = try_open(rx, r)
            t.note(why, accepted=why is None)
    twice = sum(try_open(rx, r) is None for r in recs[-500:])
    out.append(t.done(accepted_a_second_time=twice))

    # splicing: a genuine record moved to where it does not belong
    tx, rx = w.sessions()
    tx2, rx2 = w.sessions()
    t = Tally("record: spliced", "a genuine record moved to another stream, sent back to its sender, to another session, to another "
                                 "epoch; its extension changed; cut short; extended")
    for _ in range(int(3000 * n)):
        rec = tx.seal(ks.STREAM_VIDEO, payload, ext)
        variants = [
            rec[:2] + bytes([ks.STREAM_CONTROL]) + rec[3:],                       # another stream
            rec[:4] + tx2.session_id + rec[12:],                                  # relabelled for another session
            rec[:12] + struct.pack("!I", struct.unpack("!I", rec[12:16])[0] + RNG.randrange(1, 9)) + rec[16:],   # a later epoch
            rec[:HDR_LEN] + flip(rec[HDR_LEN:HDR_LEN + 9]) + rec[HDR_LEN + 9:],   # frame number / chunk index / keyframe flag
            rec[:len(rec) - RNG.randrange(1, 40)],                                # cut short
            rec + os.urandom(RNG.randrange(1, 40)),                               # extended
        ]
        for v in variants:
            why = try_open(rx if v[4:12] == rx.session_id else rx2, v)
            t.note(why, accepted=why is None)
        why = try_open(tx, rec)                                                   # reflected to the sender (other direction's keys)
        t.note(why, accepted=why is None)
        why = try_open(rx2, rec)                                                  # delivered to another session as it is
        t.note(why, accepted=why is None)
    out.append(t.done())

    # (key, nonce) pairs under concurrency and across epoch rotations
    cfg = SimpleNamespace(rotate_seconds=3600.0, rotate_packets=997, epoch_grace_seconds=3.0, replay_window=2048)
    c, s, *_ = w.handshake()
    txs = Session(c, w.suite, "uav", cfg)
    seen, lock = collections.Counter(), threading.Lock()
    per = int(12000 * n)

    def worker():
        local = []
        for _ in range(per):
            rec = txs.seal(ks.STREAM_CONTROL, b"x")
            local.append((struct.unpack_from("!I", rec, 12)[0], struct.unpack_from("!Q", rec, 16)[0]))
        with lock:
            seen.update(local)
    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-6)                     # the interpreter switches threads as often as it can
    try:
        th = [threading.Thread(target=worker) for _ in range(8)]
        [x.start() for x in th]
        [x.join() for x in th]
    finally:
        sys.setswitchinterval(old)
    reused = sum(1 for v in seen.values() if v > 1)
    out.append({"attack": "record: nonce reuse", "what": "8 threads sealing on one stream at once, the key rotating every 997 records: "
                "is any (epoch key, sequence number) pair used twice?", "expect": "refused", "attempts": 8 * per, "accepted": reused,
                "outcomes": {"unique (epoch, sequence) pairs": len(seen), "pairs used twice": reused, "epochs": len({e for e, _ in seen})},
                "verdict": "PASS" if reused == 0 and len(seen) == 8 * per else "FAIL"})
    return out


# ---------------------------------------------------------------------------------------------------- handshake
def handshake_attacks(w: World, n):
    out = []

    def attempt(t, fn):
        try:
            fn()
            t.note(None, accepted=True)
        except (hs.HandshakeError, ValueError, struct.error) as e:
            t.note(type(e).__name__ + ": " + str(e).split(":")[0])

    t = Tally("handshake: ground station impersonated", "an attacker answers the UAV's ClientHello with a ServerHello signed by its own "
                                                        "ML-DSA-87 key (the UAV has the real key pinned)")
    for _ in range(int(150 * n)):
        ch = hs.ClientHandshake(w.uav, w.gpk, 1, MOB)
        fake = hs.ServerHandshake(w.att_gcs, {UAV_ID: w.upk}).process_client_hello(ch.client_hello())
        attempt(t, lambda: ch.process_server_hello(fake))
    out.append(t.done())

    t = Tally("handshake: UAV impersonated", "an attacker sends a ClientHello under the UAV's name, signed with its own key")
    for _ in range(int(150 * n)):
        hello = hs.ClientHandshake(w.att_uav, w.gpk, 1, MOB).client_hello()
        attempt(t, lambda: w.server().process_client_hello(hello))
    out.append(t.done())

    t = Tally("handshake: message modified", "one random bit of a genuine ClientHello, ServerHello or ClientFinished flipped in transit")
    survived = 0
    for _ in range(int(400 * n)):
        server = w.server()
        ch = hs.ClientHandshake(w.uav, w.gpk, 1, MOB)
        hello = ch.client_hello()
        attempt(t, lambda: w.server().process_client_hello(flip(hello)))
        sh = server.process_client_hello(hello)
        attempt(t, lambda: ch.process_server_hello(flip(sh)))
        c, cf = ch.process_server_hello(sh)                 # the genuine answer still works after the bad one
        attempt(t, lambda: server.process_client_finished(flip(cf)))
        server.process_client_finished(cf)                  # ... and so does the genuine Finished
        survived += 1
    out.append(t.done(genuine_handshake_completed_after_the_modified_messages=survived))

    t = Tally("handshake: downgrade", "the suite number in the ClientHello or in the ServerHello changed in transit "
                                      "(to the other supported suite, or to an unknown one)")
    for _ in range(int(100 * n)):
        server = w.server()
        ch = hs.ClientHandshake(w.uav, w.gpk, 1, MOB)
        hello = ch.client_hello()
        for suite in (2, 3, 0x7FFF):
            bad = struct.pack("!H", suite) + hello[2:]
            attempt(t, lambda: w.server().process_client_hello(bad))
        sh = server.process_client_hello(hello)
        for suite in (2, 3):
            bad = struct.pack("!H", suite) + sh[2:]
            attempt(t, lambda: ch.process_server_hello(bad))
    out.append(t.done())

    t = Tally("handshake: replay", "a recorded genuine ClientHello sent again (at once; and one whose time stamp is 130 s old)")
    real_now = hs.now_ms
    for _ in range(int(150 * n)):
        server = w.server()
        hello = hs.ClientHandshake(w.uav, w.gpk, 1, MOB).client_hello()
        server.process_client_hello(hello)
        attempt(t, lambda: server.process_client_hello(hello))
        hs.now_ms = lambda: real_now() - 130_000            # a hello made 130 s ago (outside the 120 s window)
        try:
            old = hs.ClientHandshake(w.uav, w.gpk, 1, MOB).client_hello()
        finally:
            hs.now_ms = real_now
        attempt(t, lambda: server.process_client_hello(old))
    out.append(t.done())

    t = Tally("handshake: answers mixed", "the ServerHello of one handshake given to the UAV as the answer to another "
                                          "(both genuine, same two parties)")
    for _ in range(int(150 * n)):
        server = w.server()
        a, b = hs.ClientHandshake(w.uav, w.gpk, 1, MOB), hs.ClientHandshake(w.uav, w.gpk, 1, MOB)
        sh_b = server.process_client_hello(b.client_hello())
        server.process_client_hello(a.client_hello())
        attempt(t, lambda: a.process_server_hello(sh_b))
    out.append(t.done())

    t = Tally("handshake: key share replaced", "the ML-KEM ciphertext or the X25519 key in a genuine ServerHello replaced by the "
                                               "attacker's own (signature left as it is)")
    fl = hs.SH_FIXED.size
    for _ in range(int(150 * n)):
        server = w.server()
        ch = hs.ClientHandshake(w.uav, w.gpk, 1, MOB)
        sh = server.process_client_hello(ch.client_hello())
        bad_x = sh[:fl] + os.urandom(32) + sh[fl + 32:]
        bad_ct = sh[:fl + 32] + os.urandom(w.suite.kem_ct_len) + sh[fl + 32 + w.suite.kem_ct_len:]
        attempt(t, lambda: ch.process_server_hello(bad_x))
        attempt(t, lambda: ch.process_server_hello(bad_ct))
    out.append(t.done())

    t = Tally("handshake: degenerate X25519 key", "a ClientHello, correctly signed by the UAV's own key, whose X25519 key is a point "
                                                  "of low order (the shared secret would be all zeros)")
    low = [bytes(32), b"\x01" + bytes(31), bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")]
    for i in range(int(60 * n)):
        ch = hs.ClientHandshake(w.uav, w.gpk, 1, MOB)
        signed = ch.signed[:hs.CH_FIXED.size] + low[i % len(low)] + ch.signed[hs.CH_FIXED.size + 32:]
        sig = w.uav.sign(hs.LBL_CH + signed)
        hello = signed + struct.pack("!H", len(sig)) + sig
        attempt(t, lambda: w.server().process_client_hello(hello))
    out.append(t.done())

    # Handshake fragments are not authenticated one by one (the message is verified when it is complete). An attacker
    # who sees a ClientHello in flight and can send under the UAV's address can replace one of its fragments.
    t = Tally("handshake: forged fragment injected", "a forged fragment (same message id, same position, random content) sent under the "
                                                     "UAV's address while a genuine ClientHello is being received, before or after the genuine one")
    addr, recovered, spoiled = ("192.0.2.7", 40000), 0, 0
    for i in range(int(200 * n)):
        server, ra = w.server(), framing.Reassembler()
        hello = hs.ClientHandshake(w.uav, w.gpk, 1, MOB).client_hello()
        frags = framing.fragment(hs.MSG_CLIENT_HELLO, hello)
        k = RNG.randrange(len(frags) - 1)                                   # not the last one: that one completes the message
        forged = frags[k][:framing.HS_HDR.size] + os.urandom(len(frags[k]) - framing.HS_HDR.size)
        arrival = frags[:k] + ([forged, frags[k]] if i % 2 else [frags[k], forged]) + frags[k + 1:]
        got = None
        for f in arrival:
            got = ra.add(addr, f) or got
        if got is None:
            t.note("nothing completed")
        elif got[1] == hello:
            t.note("no effect: the genuine fragment arrived after the forged one")
        else:
            spoiled += 1
            attempt(t, lambda: server.process_client_hello(got[1]))
        got = None
        for f in reversed(frags):                                            # the UAV's repeat (fragments in the other order)
            got = ra.add(addr, f) or got
        try:
            recovered += got is not None and got[1] == hello and bool(server.process_client_hello(got[1]))
        except hs.HandshakeError:
            pass
    out.append(t.done(transmissions_spoiled=spoiled, genuine_hello_accepted_on_the_repeat=recovered))
    return out


# -------------------------------------------------------------------------------------------------------- rekey
def rekey_attacks(w: World, n):
    out = []
    t = Tally("cached rekey: forged or misused request", "a request with a wrong MAC; with a changed field; a genuine one sent a second "
                                                         "time; one for another position cell; one after the cache entry expired")
    fresh_ok = 0
    for _ in range(int(150 * n)):
        c, s, server, _ = w.handshake()
        cache = hs.RekeyCache(300)
        cache.put(UAV_ID, s, MOB, 1)
        req = hs.build_rekey_request(UAV_ID, c, MOB)

        def ask(body, cache=cache, server=server):
            mtype, resp, new, _ = hs.server_process_rekey(cache, server, body)
            return mtype == hs.MSG_REKEY_RESP, hs.REJECT_NAMES.get(resp[16], "?") if mtype == hs.MSG_REKEY_REJECT else None
        for bad in (req[:-1] + bytes([req[-1] ^ 1]),                                   # MAC wrong
                    flip(req[:hs.RK_FIXED.size]) + req[hs.RK_FIXED.size:]):            # a field changed, MAC as it was
            ok, why = ask(bad)
            t.note("refused: " + str(why), accepted=ok)
        ok, why = ask(req)                                                             # the genuine one: accepted, once
        fresh_ok += ok
        ok, why = ask(req)                                                             # ... and replayed
        t.note("refused: " + str(why), accepted=ok)
        # another cell: refused, and the cached secret is dropped (the next step must be a full handshake)
        c, s, server, _ = w.handshake()
        cache = hs.RekeyCache(300); cache.put(UAV_ID, s, MOB, 1)
        ok, why = ask(hs.build_rekey_request(UAV_ID, c, b"\x01" * 8), cache, server)
        t.note("refused: " + str(why), accepted=ok)
        cache = hs.RekeyCache(0.0); cache.put(UAV_ID, s, MOB, 1)                       # an entry that has expired
        time.sleep(0.001)
        ok, why = ask(hs.build_rekey_request(UAV_ID, c, MOB), cache, server)
        t.note("refused: " + str(why), accepted=ok)
    out.append(t.done(genuine_requests_accepted=fresh_ok))

    t = Tally("cached rekey: answer modified", "one random bit of the ground station's genuine answer flipped in transit")
    for _ in range(int(300 * n)):
        c, s, server, _ = w.handshake()
        cache = hs.RekeyCache(300); cache.put(UAV_ID, s, MOB, 1)
        req = hs.build_rekey_request(UAV_ID, c, MOB)
        _, resp, _, _ = hs.server_process_rekey(cache, server, req)
        try:
            hs.client_process_rekey_resp(req, c, flip(resp))
            t.note(None, accepted=True)
        except hs.HandshakeError as e:
            t.note("HandshakeError: " + str(e))
    out.append(t.done())

    t = Tally("PQ ratchet: key share replaced", "the ground station's X25519 key or ML-KEM ciphertext in a ratchet answer replaced: do "
                                                "the two ends still end up with keys that open each other's records?")
    for _ in range(int(100 * n)):
        c, s, *_ = w.handshake()
        init = hs.PQRatchetInitiator(1, 7)
        x_s, ct, sid, new_s = hs.pq_ratchet_respond(s, 7, init.x_pub, init.ek)
        for bad_x, bad_ct in ((os.urandom(32), ct), (x_s, os.urandom(len(ct)))):
            init2 = hs.PQRatchetInitiator(1, 7)
            x2, ct2, sid2, new_s2 = hs.pq_ratchet_respond(s, 7, init2.x_pub, init2.ek)
            try:
                new_c = init2.finish(c, bad_x if bad_x is not x_s else x2, bad_ct if bad_ct is not ct else ct2, sid2)
            except Exception as e:
                t.note(type(e).__name__)
                continue
            a, b = Session(new_c, w.suite, "uav", CFG), Session(new_s2, w.suite, "gcs", CFG)
            why = try_open(b, a.seal(ks.STREAM_CONTROL, b"hello"))
            t.note("keys differ: record " + str(why), accepted=why is None)
    out.append(t.done())
    return out


# ------------------------------------------------------------------------------------------------- stored files
def stored_attacks(w: World, n):
    out = []
    jpeg = b"\xff\xd8" + os.urandom(60_000)
    blob = seal_image(w.ek, jpeg, {"width": 1280, "height": 720}, x25519_pk=w.xpk, signer=w.uav)
    op = lambda b, **kw: open_image(b, w.dk, **{"x25519_sk": w.xsk, "signer_pk": w.upk, **kw})
    assert op(blob)[1] == jpeg

    def attempt(t, fn, exc):
        try:
            fn()
            t.note(None, accepted=True)
        except exc as e:
            t.note(str(e)[:60])

    t = Tally("stored photo: modified", "one random bit of a stored photo flipped (header, key block, picture, signature)")
    for _ in range(int(6000 * n)):
        attempt(t, lambda: op(flip(blob)), PhotoError)
    out.append(t.done(file_bytes=len(blob)))

    t = Tally("stored photo: cut or extended", "the file cut at a random length, or bytes appended")
    for _ in range(int(3000 * n)):
        attempt(t, lambda: op(blob[:RNG.randrange(len(blob))]), PhotoError)
        attempt(t, lambda: op(blob + os.urandom(RNG.randrange(1, 64))), PhotoError)
    out.append(t.done())

    t = Tally("stored photo: forged or re-signed", "a photo made by someone who knows only the ground station's PUBLIC keys: unsigned; "
                                                   "signed with another key; a genuine photo carrying another photo's signature; "
                                                   "the signature cut off")
    other = seal_image(w.ek, jpeg, {"width": 1}, x25519_pk=w.xpk, signer=w.uav)
    tl = 10 + 4627
    for _ in range(int(40 * n)):
        attempt(t, lambda: op(seal_image(w.ek, jpeg, {"width": 1}, x25519_pk=w.xpk)), PhotoError)
        attempt(t, lambda: op(seal_image(w.ek, jpeg, {"width": 1}, x25519_pk=w.xpk, signer=w.att_uav)), PhotoError)
        attempt(t, lambda: op(blob[:-tl] + other[-tl:]), PhotoError)
        attempt(t, lambda: op(blob[:-tl]), PhotoError)
    out.append(t.done())

    t = Tally("stored photo: wrong keys", "opened with only one of the two secret recording keys right (ML-KEM right and X25519 wrong, "
                                          "X25519 right and ML-KEM wrong), or with no X25519 key")
    for _ in range(int(60 * n)):
        attempt(t, lambda: op(blob, x25519_sk=w.other_xsk), PhotoError)
        attempt(t, lambda: open_image(blob, w.other_dk, x25519_sk=w.xsk, signer_pk=w.upk), PhotoError)
        attempt(t, lambda: open_image(blob, w.dk, signer_pk=w.upk), PhotoError)
    out.append(t.done())

    # recordings
    d = w.dir / "rec"
    rec = EncryptedRecorder(d, w.ek, {"codec": "h264", "fps": 30}, x25519_pk=w.xpk, signer=w.uav)
    frames = []
    for i in range(150):
        f = os.urandom(RNG.randint(300, 2500))
        frames.append(f)
        rec.add_frame(f, keyframe=(i % 30 == 0), ts_us=i * 33333)
    rec.close()
    raw, plain = rec.path.read_bytes(), b"".join(frames)
    tmp = d / "attacked.k6grec"
    dec = lambda data, **kw: (tmp.write_bytes(data), decrypt_recording(tmp, w.dk, **{"x25519_sk": w.xsk, "signer_pk": w.upk, **kw}))[1]
    assert dec(raw)[1] == plain

    def rattempt(t, data, **kw):
        try:
            _, h264, rep = dec(data, **kw)
        except RecordingError as e:
            t.note(str(e)[:60])
            return
        # not refused: it only counts as accepted if it is taken for a complete, signed recording
        t.note(rep["status"], accepted=rep["status"] == "PASS" and rep["signature"] == "PASS")

    t = Tally("stored recording: modified", "one random bit of a recording flipped (header, key block, any segment, signature)")
    for _ in range(int(2500 * n)):
        rattempt(t, flip(raw))
    out.append(t.done(file_bytes=len(raw)))

    # the segments of the file, to move them about
    off = 10 + struct.unpack_from("!H", raw, 8)[0] + sealing.block_len(True)
    head, segs, p = raw[:off], [], off
    while p < len(raw) - tl:
        clen = SEG_HDR.unpack_from(raw, p)[0]
        segs.append(raw[p:p + SEG_HDR.size + clen])
        p += SEG_HDR.size + clen
    trailer = raw[p:]
    rec2 = EncryptedRecorder(d, w.ek, {"codec": "h264", "fps": 30}, x25519_pk=w.xpk, signer=w.uav)
    for i in range(60):
        rec2.add_frame(os.urandom(800), keyframe=(i % 30 == 0), ts_us=i * 33333)
    rec2.close()
    raw2 = rec2.path.read_bytes()
    off2 = 10 + struct.unpack_from("!H", raw2, 8)[0] + sealing.block_len(True)
    seg2 = raw2[off2:off2 + SEG_HDR.size + SEG_HDR.unpack_from(raw2, off2)[0]]
    t = Tally("stored recording: segments rearranged", "two segments swapped; one dropped; one repeated; one replaced by a segment of "
                                                       "another recording; the file cut after a segment; the signature cut off, or "
                                                       "replaced by that of another recording")
    for _ in range(int(60 * n)):
        i, j = RNG.sample(range(len(segs)), 2)
        sw = list(segs); sw[i], sw[j] = sw[j], sw[i]
        rattempt(t, head + b"".join(sw) + trailer)
        rattempt(t, head + b"".join(segs[:i] + segs[i + 1:]) + trailer)
        rattempt(t, head + b"".join(segs[:i] + [segs[i]] + segs[i:]) + trailer)
        rattempt(t, head + b"".join(segs[:i] + [seg2] + segs[i + 1:]) + trailer)
        rattempt(t, head + b"".join(segs[:max(1, i)]))                              # cut after a segment: TRUNCATED, not complete
        rattempt(t, head + b"".join(segs))                                          # signature cut off
        rattempt(t, head + b"".join(segs) + raw2[-tl:])                             # another recording's signature
    out.append(t.done(segments=len(segs)))

    t = Tally("stored recording: forged", "a recording made by someone who knows only the ground station's PUBLIC keys: unsigned, or "
                                          "signed with another key")
    for signer in (None, w.att_uav) * int(10 * n + 1):
        r = EncryptedRecorder(d, w.ek, {"codec": "h264", "fps": 30}, x25519_pk=w.xpk, signer=signer)
        r.add_frame(os.urandom(900), keyframe=True, ts_us=0)
        r.close()
        rattempt(t, r.path.read_bytes())
        r.path.unlink()
    out.append(t.done())
    return out


# -------------------------------------------------------------------------------------------------------- flood
# The flood generator: a process of its own (it must not share the interpreter of the ground station it attacks).
# Forged ClientHellos of the right size and layout, under the UAV's name, each with a new nonce and the current time
# (so each one gets as far as the signature check), a random key share and a random signature; fragmented as the
# link fragments them. argv: port, hellos per second (0 = as fast as it can), then what it needs to build them.
FLOOD_PROG = r'''
import hashlib, os, signal, socket, struct, sys, time
port, rate = int(sys.argv[1]), float(sys.argv[2])
ch_fmt, uav_id, mob, mtype, hs_fmt, frag, tail = sys.argv[3], bytes.fromhex(sys.argv[4]), bytes.fromhex(sys.argv[5]), int(sys.argv[6]), sys.argv[7], int(sys.argv[8]), int(sys.argv[9])
ch, hh = struct.Struct(ch_fmt), struct.Struct(hs_fmt)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
stop = []
signal.signal(signal.SIGTERM, lambda *a: stop.append(1))
sent, t0, addr = 0, time.perf_counter(), ("127.0.0.1", port)
nxt = t0
while not stop:
    body = ch.pack(1, uav_id, os.urandom(32), mob, int(time.time() * 1000)) + os.urandom(tail) + struct.pack("!H", 4627) + os.urandom(4627)
    hid = hashlib.sha256(bytes([mtype]) + body).digest()[:4]
    parts = [body[i:i + frag] for i in range(0, len(body), frag)]
    try:
        for i, c in enumerate(parts):
            s.sendto(hh.pack(1, mtype, hid, i, len(parts)) + c, addr)
    except OSError:
        time.sleep(0.0005)
        continue
    sent += 1
    if rate > 0:
        nxt += 1.0 / rate
        d = nxt - time.perf_counter()
        if d > 0:
            time.sleep(d)
        elif d < -0.5:
            nxt = time.perf_counter()
print(sent, time.perf_counter() - t0, flush=True)
'''


def flood_attack(w: World, n):
    """Forged ClientHellos sent to a ground-station link on a real socket at a set rate (and, last, as fast as a
    process on this machine can) while a genuine UAV connects again and again: does it still get in, and how fast?"""
    import signal
    import subprocess
    from ..config import LinkConfig
    from ..transport.link import GcsLink, UavLink
    cfg = LinkConfig(gcs_host="127.0.0.1", gcs_port=0, cached_rekey_interval_s=0, pq_ratchet_interval_s=0,
                     uav_id=UAV_ID.decode(), gcs_id=GCS_ID.decode())
    gcs = GcsLink(cfg, w.gcs, {UAV_ID: w.upk}, bind=("127.0.0.1", 0))
    port = gcs.sock.getsockname()[1]
    gcs.start()
    hello_wire = len(hs.ClientHandshake(w.uav, w.gpk, 1, MOB).client_hello())
    wire = hello_wire + len(framing.fragment(hs.MSG_CLIENT_HELLO, bytes(hello_wire))) * (framing.HS_HDR.size + 28)
    levels, limit_s = [], 60.0
    try:
        for rate in (0, 100, 300, 1000, 3000, None):
            proc = None
            if rate != 0:
                proc = subprocess.Popen([sys.executable, "-c", FLOOD_PROG, str(port), str(rate or 0), hs.CH_FIXED.format, UAV_ID.hex(), MOB.hex(),
                                         str(hs.MSG_CLIENT_HELLO), framing.HS_HDR.format, str(framing.MAX_FRAG_PAYLOAD), str(32 + w.suite.kem_ek_len)],
                                        stdout=subprocess.PIPE, text=True)
                time.sleep(1.5)                                        # the flood is under way before the UAV tries
            before = dict(gcs.stats.get("drops") or {})
            times = []
            for _ in range(max(3, int(6 * n))):
                uav = UavLink(LinkConfig(**{**cfg.__dict__, "gcs_port": port}), w.uav, w.gpk, lambda: MOB)
                t0 = time.perf_counter()
                uav.start()
                while uav.state != "UP" and time.perf_counter() - t0 < limit_s:
                    time.sleep(0.002)
                times.append(round((time.perf_counter() - t0) * 1000, 1) if uav.state == "UP" else None)
                uav.stop()
                time.sleep(0.3)
            sent, seconds = 0, 1.0
            if proc is not None:
                proc.send_signal(signal.SIGTERM)
                try:
                    sent, seconds = (float(x) for x in proc.communicate(timeout=10)[0].split())
                except Exception:
                    proc.kill()
            after = dict(gcs.stats.get("drops") or {})
            ok = [x for x in times if x is not None]
            levels.append({"target_per_s": rate if rate is not None else "as fast as one process can", "forged_hellos_sent": int(sent),
                           "forged_per_s": round(sent / seconds), "mbit_per_s": round(sent * wire * 8 / seconds / 1e6, 2),
                           "connections": len(times), "connected": len(ok), "connect_ms": times,
                           "median_ms": round(statistics.median(ok), 1) if ok else None, "max_ms": max(ok) if ok else None,
                           "refused_after_signature_check": after.get("handshake-invalid", 0) - before.get("handshake-invalid", 0),
                           "dropped_unverified_by_the_ration": after.get("hello-flood", 0) - before.get("hello-flood", 0)})
            time.sleep(1.0)
    finally:
        ration = gcs.bad_sigs.rate
        gcs.stop()
    attempts, connected = sum(l["connections"] for l in levels), sum(l["connected"] for l in levels)
    full = [l["forged_per_s"] for l in levels if l["connected"] == l["connections"]]
    return [{"attack": "flood: forged ClientHellos", "what": "forged ClientHellos under the UAV's name (new nonce, current time, random signature: "
             "each reaches the signature check) sent to the ground station from another process at 100 to 3000 per second and then as fast as "
             f"it can, while a genuine UAV connects: does it get in within {limit_s:.0f} s, and how long does it take?",
             "expect": "accepted", "attempts": attempts, "accepted": connected,
             "outcomes": {"genuine connections made": connected, "of": attempts, "highest flood rate at which all connected, per second": max(full) if full else 0,
                          "ration of failed signature checks per second": ration},
             "levels": levels, "bytes_per_forged_hello_on_the_wire": wire,
             "verdict": "PASS" if connected == attempts else "FAIL"}]


# ------------------------------------------------------------------------------------------------------- timing
def welch_t(a, b):
    va, vb = statistics.variance(a), statistics.variance(b)
    return (statistics.fmean(a) - statistics.fmean(b)) / math.sqrt(va / len(a) + vb / len(b))


def timing_tests(w: World, n):
    """Does refusing take longer when the value is wrong at its end than when it is wrong at its start? Two classes
    of input, measured in random order; Welch's t between them (|t| < 4.5 is the usual bound for "no difference
    found" in this kind of test). A comparison that stops at the first wrong byte would show a clear difference."""
    out = []
    ROUNDS = 5                                                        # every test is made five times over: one t value can be chance
    reps, N = 20, int(2400 * n)
    tx, rx = w.sessions()
    payload, ext = os.urandom(1100), os.urandom(9)
    pc = time.perf_counter_ns

    def trimmed(v):                                                   # the slowest 5 % are scheduler noise, not the comparison
        v = sorted(v)
        return v[:int(len(v) * 0.95)]

    def result(name, rounds, calls):
        """rounds: list of (samples of class "first", samples of class "last")."""
        per = [(trimmed(a), trimmed(b)) for a, b in rounds]
        ts = [round(welch_t(a, b), 2) for a, b in per]
        alla, allb = [x for a, _ in per for x in a], [x for _, b in per for x in b]
        worst = max(ts, key=abs)
        return {"test": name, "rounds": len(per), "samples_per_class": [len(alla), len(allb)], "calls_per_sample": calls,
                "mean_ns": [round(statistics.fmean(alla), 1), round(statistics.fmean(allb), 1)],
                "difference_ns": round(statistics.fmean(allb) - statistics.fmean(alla), 2),
                "difference_ns_rounds": [round(statistics.fmean(b) - statistics.fmean(a), 2) for a, b in per],
                "t_rounds": ts, "t": worst, "t_all_samples": round(welch_t(alla, allb), 2),
                "rounds_over_4.5": sum(abs(x) > 4.5 for x in ts)}

    rounds = []
    for _ in range(ROUNDS):
        samples = {"first": [], "last": []}
        for _ in range(N):
            cls = "first" if RNG.random() < 0.5 else "last"
            batch = []
            for _ in range(reps):
                rec = bytearray(tx.seal(ks.STREAM_VIDEO, payload, ext))
                rec[-16 if cls == "first" else -1] ^= 0x55           # the tag wrong in its first / its last byte
                batch.append(bytes(rec))
            t0 = pc()
            for r in batch:
                try:
                    rx.open(r)
                except RecordError:
                    pass
            samples[cls].append((pc() - t0) / reps)
        rounds.append((samples["first"], samples["last"]))
    out.append(result("record: tag wrong in its first byte vs in its last byte", rounds, reps))
    # The MAC comparison of Finished and rekey messages. Every sample has a new MAC value and new objects: with one
    # fixed pair of buffers per class, where the two buffers happen to lie in memory shows up as a "difference"
    # (seen on the Raspberry Pi: 0.2 ns, t = -22, with fixed buffers).
    def leaky(a, b):                                                  # the control: stops at the first wrong byte
        for i in range(len(a)):
            if a[i] != b[i]:
                return False
        return True

    for name, fn, calls, count in (("Finished / rekey MAC: wrong in its first byte vs in its last byte", ct_equal, 200, N * 2),
                                   ("control - a comparison that stops at the first wrong byte (not used in the link), same test", leaky, 20, max(200, N // 10))):
        rounds = []
        for _ in range(ROUNDS):
            samples = {"first": [], "last": []}
            for _ in range(count):
                cls = "first" if RNG.random() < 0.5 else "last"
                good = ks.hmac256(os.urandom(32), os.urandom(64))
                x = bytearray(good)
                x[0 if cls == "first" else -1] ^= 0x55
                x = bytes(x)
                t0 = pc()
                for _ in range(calls):
                    fn(good, x)
                samples[cls].append((pc() - t0) / calls)
            rounds.append((samples["first"], samples["last"]))
        out.append(result(name, rounds, calls))
    return out


# --------------------------------------------------------------------------------------------------- statistics
def byte_stats(data: bytes):
    n = len(data)
    counts = collections.Counter(data)
    ent = -sum(c / n * math.log2(c / n) for c in counts.values())
    exp = n / 256
    chi2 = sum((counts.get(i, 0) - exp) ** 2 / exp for i in range(256))
    # Wilson-Hilferty: chi-square with 255 degrees of freedom as a normal deviate; p = chance of a value this large from uniform bytes
    z = ((chi2 / 255) ** (1 / 3) - (1 - 2 / (9 * 255))) / math.sqrt(2 / (9 * 255))
    p = 0.5 * math.erfc(z / math.sqrt(2))
    m = min(n, 2_000_000)
    xs, ys = data[:m - 1], data[1:m]
    mx, my = sum(xs) / len(xs), sum(ys) / len(ys)
    cov = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    sx, sy = math.sqrt(sum((x - mx) ** 2 for x in xs)), math.sqrt(sum((y - my) ** 2 for y in ys))
    ones = sum(bin(b).count("1") for b in data[:m]) / (8 * m)
    return {"bytes": n, "entropy_bits_per_byte": round(ent, 6), "chi_square": round(chi2, 1), "chi_square_p": round(p, 4),
            "serial_correlation": round(cov / (sx * sy), 6) if sx and sy else None, "share_of_one_bits": round(ones, 6)}


def diff_stats(a: bytes, b: bytes):
    n = min(len(a), len(b))
    a, b = a[:n], b[:n]
    return {"bytes": n, "bytes_that_differ_pct": round(100 * sum(x != y for x, y in zip(a, b)) / n, 4),
            "mean_absolute_difference_pct_of_255": round(100 * sum(abs(x - y) for x, y in zip(a, b)) / (255 * n), 4),
            "bits_that_differ_pct": round(100 * sum(bin(x ^ y).count("1") for x, y in zip(a, b)) / (8 * n), 4)}


def statistics_tests(w: World, n, media):
    out = {"files": [], "fresh_encryption": [], "key_and_nonce_sensitivity": [], "note": "ideal values for independent uniform bytes: "
           "entropy 8 bits per byte, chi-square p anywhere in (0.01, 0.99), serial correlation 0, 50 % one bits; two unrelated uniform "
           "byte strings differ in 99.61 % of their bytes, by 33.46 % of 255 on average, in 50 % of their bits"}
    media = Path(media) if media else None
    pairs = []
    if media and (media / "images" / "encrypted").is_dir():
        dk, xsk = idm.load_recording_dk(idm.DEFAULT_DIR), idm.load_recording_xsk(idm.DEFAULT_DIR)
        for p in sorted((media / "images" / "encrypted").glob("*.k6gimg"), key=lambda p: p.stat().st_mtime)[-int(8 * max(1, n)):]:
            try:
                hdr, jpeg = open_image(p.read_bytes(), dk, x25519_sk=xsk)
            except PhotoError:
                continue
            raw = p.read_bytes()
            body = raw[len(raw) - len(jpeg) - 16 - (4637 if hdr.get("sig") else 0):len(raw) - (4637 if hdr.get("sig") else 0)]
            pairs.append(("photo (JPEG)", p.name, jpeg, body))
        for p in sorted((media / "recordings").glob("*.k6grec"), key=lambda p: p.stat().st_mtime)[-int(3 * max(1, n)):]:
            if p.stat().st_size > 60_000_000:
                continue
            try:
                _, h264, rep = decrypt_recording(p, dk, x25519_sk=xsk)
            except RecordingError:
                continue
            raw = p.read_bytes()
            pairs.append(("video (H.264)", p.name, h264, raw[-len(h264):] if not rep["format"] == 2 else raw[len(raw) - 4637 - len(h264):len(raw) - 4637]))
    for kind, name, plain, cipher in pairs:
        out["files"].append({"kind": kind, "file": name, "plaintext": byte_stats(plain), "ciphertext": byte_stats(cipher)})
    # a structured plaintext (what a raw picture is like): rows of slowly changing values
    structured = bytes((x // 4 + y // 3) % 256 for y in range(600) for x in range(800))
    for label, plain in (("structured plaintext (smooth gradient, 480 kB)", structured), ("all-zero plaintext (480 kB)", bytes(480_000))):
        blob1 = seal_image(w.ek, plain, {}, x25519_pk=w.xpk, signer=w.uav)
        blob2 = seal_image(w.ek, plain, {}, x25519_pk=w.xpk, signer=w.uav)
        body = lambda b: b[len(b) - 4637 - 16 - len(plain):len(b) - 4637 - 16]
        out["files"].append({"kind": "synthetic", "file": label, "plaintext": byte_stats(plain), "ciphertext": byte_stats(body(blob1))})
        out["fresh_encryption"].append({"what": f"the same {label} stored twice (as the system stores it: a new key each time)",
                                        **diff_stats(body(blob1), body(blob2))})
    # the record layer: the same payload sealed twice in a row; under a key that differs in one bit; one sequence number on
    tx, _ = w.sessions()
    p = structured[:1100]
    r1, r2 = tx.seal(ks.STREAM_VIDEO, p, b"\x00" * 9), tx.seal(ks.STREAM_VIDEO, p, b"\x00" * 9)
    out["fresh_encryption"].append({"what": "the same 1100-byte payload sent twice in a row on the video stream", **diff_stats(r1[33:-16], r2[33:-16])})
    key = os.urandom(32)
    key2 = bytes([key[0] ^ 1]) + key[1:]
    big = structured
    c0 = AESGCM(key).encrypt(bytes(12), big, b"")[:-16]
    out["key_and_nonce_sensitivity"].append({"what": "AES-256-GCM, same plaintext and nonce, keys that differ in ONE bit",
                                             **diff_stats(c0, AESGCM(key2).encrypt(bytes(12), big, b"")[:-16])})
    out["key_and_nonce_sensitivity"].append({"what": "AES-256-GCM, same plaintext and key, nonce one higher (the next sequence number)",
                                             **diff_stats(c0, AESGCM(key).encrypt(bytes(11) + b"\x01", big, b"")[:-16])})
    th, ikm, sid = os.urandom(32), os.urandom(64), os.urandom(8)
    a = ks.derive_session(th, ikm, 1, sid)
    b = ks.derive_session(th, bytes([ikm[0] ^ 1]) + ikm[1:], 1, sid)
    ka, kb = bytes(a.chain_key(ks.STREAM_VIDEO, ks.DIR_U2G)), bytes(b.chain_key(ks.STREAM_VIDEO, ks.DIR_U2G))
    out["key_and_nonce_sensitivity"].append({"what": "key schedule: the video key from two shared secrets that differ in ONE bit",
                                             **diff_stats(hashlib.sha512(ka).digest() + ka, hashlib.sha512(kb).digest() + kb)})
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("-n", type=float, default=1.0, help="scale of the number of attempts (default 1.0)")
    ap.add_argument("-o", "--out", help="output file (default attacks_<host>.json)")
    ap.add_argument("--media", help="the ground station's data directory (photos and recordings, encrypted and decrypted)")
    ap.add_argument("--only", help="comma-separated groups: record,handshake,rekey,stored,flood,timing,statistics")
    a = ap.parse_args()
    only = set(a.only.split(",")) if a.only else None
    want = lambda g: only is None or g in only
    t_start, env = time.time(), environment()
    w = World()
    experiments, timing, stats = [], [], None
    try:
        for group, fn in (("record", record_attacks), ("handshake", handshake_attacks), ("rekey", rekey_attacks), ("stored", stored_attacks),
                          ("flood", flood_attack)):
            if want(group):
                t0 = time.time()
                res = fn(w, a.n)
                for r in res:
                    r["group"] = group
                experiments += res
                print(f"{group:10s} {len(res)} experiments, {sum(r['attempts'] for r in res):8d} attempts, "
                      f"{sum(r['accepted'] for r in res if r['expect'] == 'refused')} attacks accepted, {time.time() - t0:.1f} s", flush=True)
        if want("timing"):
            timing = timing_tests(w, a.n)
        if want("statistics"):
            stats = statistics_tests(w, a.n, a.media)
    finally:
        w.cleanup()
    out = {"tool": "kyber6g.tools.attack_bench", "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t_start)),
           "duration_s": round(time.time() - t_start, 1), "scale": a.n, "environment": env, "experiments": experiments,
           "timing": timing, "statistics": stats}
    path = Path(a.out or f"attacks_{platform.node()}.json")
    path.write_text(json.dumps(out))
    bad = [e for e in experiments if e["verdict"] != "PASS"]
    for e in experiments:
        acc = e["accepted"] if e["expect"] == "refused" else f"{e['accepted']} of {e['attempts']} (must be all)"
        print(f"  [{e['verdict']}] {e['attack']:42s} attempts {e['attempts']:7d}  accepted {acc}")
    for t in timing:
        print(f"  [timing] {t['test']}: difference {t['difference_ns']} ns, t per round {t['t_rounds']}")
    print(f"-> {path}   ({len(experiments)} experiments, {len(bad)} not as required)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
