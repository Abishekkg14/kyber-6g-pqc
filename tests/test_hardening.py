"""Regression tests for the security review of October 2026 (docs/SECURITY_AUDIT.md).

Each class covers one finding: the test fails on the code as it was and passes on the fix. The fuzz tests at the
end feed random and mutated input to every parser that takes bytes from the network or from a file and require
that nothing but the documented, handled outcome ever happens."""
import base64
import collections
import hashlib
import http.client
import json
import os
import random
import socket
import stat
import struct
import sys
import tempfile
import threading
import time
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from kyber6g.config import LinkConfig
from kyber6g.crypto import handshake as hs
from kyber6g.crypto import identity as idm
from kyber6g.crypto import keyschedule as ks
from kyber6g.crypto.record import HDR, RecordError, Session, parse_header
from kyber6g.transport import blob, framing, jsonmsg
from kyber6g.transport import link as linkmod
from kyber6g.transport.link import GcsLink, TokenBucket, UavLink

from .test_crypto import CFG, GCS_ID, UAV_ID, full_handshake, make_ids
from .test_link import LossyProxy, wait


def session_pair(rotate_packets=1 << 30):
    uav, gcs, upk, gpk = make_ids()
    _, c, s = full_handshake(uav, gcs, gpk, upk)
    cfg = SimpleNamespace(**{**CFG.__dict__, "rotate_packets": rotate_packets})
    return Session(c, hs.get_suite(1), "uav", cfg), Session(s, hs.get_suite(1), "gcs", cfg)


# ============================================================ record layer
class TestSealIsThreadSafe(unittest.TestCase):
    """Finding 1: TxStream.seal read and advanced the sequence number without a lock. Two threads on one stream could
    seal two records with the same number, i.e. the same AES-GCM nonce under the same key."""

    def run_threads(self, tx, rx, threads=8, per_thread=400):
        out, lock = [], threading.Lock()
        old = sys.getswitchinterval()
        sys.setswitchinterval(1e-6)                     # switch threads as often as possible: provoke the race
        self.addCleanup(sys.setswitchinterval, old)

        def work(n):
            mine = [tx.seal(ks.STREAM_CONTROL, b"%d:%d" % (n, i)) for i in range(per_thread)]
            with lock:
                out.extend(mine)
        ts = [threading.Thread(target=work, args=(n,)) for n in range(threads)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        sys.setswitchinterval(old)
        return out

    def test_no_sequence_number_is_used_twice(self):
        tx, rx = session_pair()
        pkts = self.run_threads(tx, rx)
        seqs = [HDR.unpack_from(p)[6] for p in pkts]
        self.assertEqual(len(seqs), 3200)
        self.assertEqual(len(set(seqs)), 3200)                              # every nonce distinct
        self.assertEqual(sorted(seqs), list(range(3200)))                   # and none skipped
        opened = {rx.open(p)[2] for p in sorted(pkts, key=lambda p: HDR.unpack_from(p)[6])}    # every record authenticates
        self.assertEqual(len(opened), 3200)

    def test_rotation_under_concurrency_keeps_key_and_nonce_pairs_unique(self):
        tx, rx = session_pair(rotate_packets=37)                            # the key changes every 37 records
        pkts = self.run_threads(tx, rx, threads=6, per_thread=300)
        pairs = [(HDR.unpack_from(p)[5], HDR.unpack_from(p)[6]) for p in pkts]
        self.assertEqual(len(set(pairs)), len(pairs))
        self.assertGreater(len({e for e, _ in pairs}), 40)                  # it really rotated many times
        for p in sorted(pkts, key=lambda p: HDR.unpack_from(p)[6]):
            rx.open(p)

    def test_a_record_offered_twice_at_once_is_accepted_once(self):
        tx, rx = session_pair()
        pkt = tx.seal(ks.STREAM_TELEMETRY, b"once")
        results, barrier = [], threading.Barrier(8)

        def work():
            barrier.wait()
            try:
                rx.open(pkt)
                results.append("ok")
            except RecordError as e:
                results.append(e.reason)
        ts = [threading.Thread(target=work) for _ in range(8)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertEqual(results.count("ok"), 1)
        self.assertEqual(results.count("duplicate"), 7)

    def test_extension_longer_than_the_header_can_say_is_refused(self):
        tx, _ = session_pair()
        with self.assertRaises(ValueError):
            tx.seal(ks.STREAM_VIDEO, b"x", ext=b"e" * 256)


# ====================================================== handshake reassembly
class TestHandshakeReassembly(unittest.TestCase):
    """Finding 6: with 32 partly received messages in the table every NEW message was refused, so 32 forged first
    fragments every 5 s locked every genuine handshake out."""

    def first_fragment(self, n):
        return framing.HS_HDR.pack(1, hs.MSG_CLIENT_HELLO, struct.pack("!I", n), 0, 3) + b"x" * 100

    def test_a_full_table_makes_room_for_a_new_message(self):
        r = framing.Reassembler()
        for n in range(1000):                                               # forged, each from another source address
            self.assertIsNone(r.add((f"10.0.{n // 250}.{n % 250}", 4000 + n), self.first_fragment(n)))
        self.assertLessEqual(len(r.buf), framing.MAX_PENDING)
        self.assertGreater(r.evicted, 800)
        frags = framing.fragment(hs.MSG_CLIENT_HELLO, os.urandom(3000))     # the genuine message still gets through
        done = [r.add(("10.9.9.9", 5555), f) for f in frags]
        self.assertEqual(done[-1], (hs.MSG_CLIENT_HELLO, b"".join(f[framing.HS_HDR.size:] for f in frags)))

    def test_one_source_cannot_fill_the_table(self):
        r = framing.Reassembler()
        for n in range(50):
            r.add(("10.0.0.1", 4000), self.first_fragment(n))
        self.assertEqual(len(r.buf), framing.MAX_PENDING_PER_SOURCE)

    def test_oversized_and_malformed_fragments_are_dropped(self):
        r = framing.Reassembler()
        big = framing.HS_HDR.pack(1, 1, b"abcd", 0, 2) + b"x" * (framing.MAX_FRAG_PAYLOAD + 1)
        self.assertIsNone(r.add(("a", 1), big))
        self.assertEqual(r.buf, {})
        for bad in (b"", b"\x01", framing.HS_HDR.pack(1, 1, b"abcd", 0, 0), framing.HS_HDR.pack(1, 1, b"abcd", 5, 2),
                    framing.HS_HDR.pack(1, 1, b"abcd", 0, 17)):
            self.assertIsNone(r.add(("a", 1), bad))
        self.assertEqual(r.buf, {})


# ============================================================ UAV handshake
class TestUavIgnoresUnverifiedAnswers(unittest.TestCase):
    """Findings 17-19: the first ServerHello that failed to verify, or an unauthenticated ERROR message, ended the
    handshake attempt - one forged datagram per attempt kept the link down - and a duplicate of the genuine
    ServerHello could reach the ephemeral KEM key after it had been freed."""

    @classmethod
    def setUpClass(cls):
        cls.uav, cls.gcs, cls.upk, cls.gpk = make_ids()

    def link(self, host="127.0.0.1"):
        u = UavLink(LinkConfig(gcs_host=host, gcs_port=47999), self.uav, self.gpk, lambda: b"\x00" * 8)
        self.addCleanup(u.stop)
        return u

    def test_forged_and_duplicate_messages_do_not_end_the_attempt(self):
        u = self.link()
        server = hs.ServerHandshake(self.gcs, {UAV_ID: self.upk})
        ch = hs.ClientHandshake(self.uav, self.gpk, 1, b"\x00" * 8)
        sh = server.process_client_hello(ch.client_hello())
        u._hs = ("full", ch)
        addr = ("127.0.0.1", 47999)
        u._on_handshake(hs.MSG_SERVER_HELLO, os.urandom(len(sh)), addr)             # garbage of the right size
        tampered = bytearray(sh); tampered[60] ^= 1
        u._on_handshake(hs.MSG_SERVER_HELLO, bytes(tampered), addr)                 # the real one, one bit changed
        u._on_handshake(hs.MSG_SERVER_HELLO, b"", addr)
        u._on_handshake(hs.MSG_HS_ERROR, b"go away", addr)                          # unauthenticated complaint
        u._on_handshake(hs.MSG_REKEY_REJECT, b"x" * 17, addr)                       # not for this kind of attempt
        self.assertIsNone(u._hs_result)
        self.assertFalse(u._hs_event.is_set())
        self.assertEqual(u.stats["drops"]["handshake-invalid"], 3)
        self.assertEqual(u._hs_note, "go away")
        u._on_handshake(hs.MSG_SERVER_HELLO, sh, addr)                              # the genuine answer still works
        self.assertEqual(u._hs_result[0], "ok")
        self.assertTrue(u._hs_event.is_set())
        first = u._hs_result
        u._on_handshake(hs.MSG_SERVER_HELLO, sh, addr)                              # a duplicate changes nothing
        self.assertIs(u._hs_result, first)
        with self.assertRaises(hs.HandshakeError):                                  # and can never reach the freed key
            ch.process_server_hello(sh)

    def test_a_reject_must_name_our_own_request(self):
        u = self.link()
        _, c, s = full_handshake(self.uav, self.gcs, self.gpk, self.upk)
        req = hs.build_rekey_request(UAV_ID, c, b"\x00" * 8)
        u._hs = ("rekey", req, c)
        addr = ("127.0.0.1", 47999)
        u._on_handshake(hs.MSG_REKEY_REJECT, UAV_ID + os.urandom(8) + bytes([hs.REJECT_MISS]), addr)
        u._on_handshake(hs.MSG_REKEY_REJECT, b"", addr)
        u._on_handshake(hs.MSG_REKEY_RESP, os.urandom(80), addr)
        self.assertIsNone(u._hs_result)                                             # forged: ignored
        self.assertEqual(u.stats["drops"]["handshake-invalid"], 3)
        u._on_handshake(hs.MSG_REKEY_REJECT, UAV_ID + c.session_id + bytes([hs.REJECT_MISS]), addr)
        self.assertEqual(u._hs_result, ("reject", "CACHE_MISS"))

    def test_handshake_answers_are_taken_from_the_ground_station_address_only(self):
        u = self.link("10.1.2.3")
        self.assertTrue(u._hs_source_ok(("10.1.2.3", 47999)))
        self.assertFalse(u._hs_source_ok(("10.1.2.4", 47999)))
        self.assertFalse(u._hs_source_ok(("10.1.2.3", 47998)))
        self.assertTrue(self.link("ground.example")._hs_source_ok(("10.1.2.4", 9)))  # configured by name: not filtered

    def test_link_comes_up_while_forged_answers_are_injected(self):
        """End to end over UDP: for every datagram the UAV sends, three forged answers reach it first."""
        d = Path(tempfile.mkdtemp())
        upk, gpk = idm.generate_identity(d, "uav"), idm.generate_identity(d, "gcs")
        cfg = LinkConfig(gcs_host="127.0.0.1", gcs_port=0, heartbeat_s=0.3, link_timeout_s=1.5,
                         cached_rekey_interval_s=0, pq_ratchet_interval_s=0)
        gcs = GcsLink(cfg, idm.load_identity(d, "gcs", GCS_ID), {UAV_ID: upk}, bind=("127.0.0.1", 0))
        proxy = LossyProxy(gcs.sock.getsockname()[1])
        forged = [framing.fragment(hs.MSG_SERVER_HELLO, os.urandom(6311)), framing.fragment(hs.MSG_HS_ERROR, b"no"),
                  framing.fragment(hs.MSG_REKEY_REJECT, b"r" * 17)]
        real_loop_send = proxy.sock.sendto

        class Noisy:
            def __getattr__(self, name):
                return getattr(proxy_sock, name)

            def sendto(self, pkt, dst):
                if dst == proxy.gcs and proxy.uav:                # the UAV just sent something: answer with forgeries
                    for msg in forged:
                        for f in msg:
                            real_loop_send(f, proxy.uav)
                return real_loop_send(pkt, dst)
        proxy_sock = proxy.sock
        proxy.sock = Noisy()
        uav = UavLink(LinkConfig(**{**cfg.__dict__, "gcs_port": proxy.port}), idm.load_identity(d, "uav", UAV_ID), gpk,
                      lambda: b"\x00" * 8)
        got = []
        gcs.on_message = lambda st, ext, pt, meta: got.append(pt)
        gcs.start(); uav.start()
        self.addCleanup(lambda: (uav.stop(), gcs.stop(), setattr(proxy, "running", False)))
        self.assertTrue(wait(lambda: uav.state == "UP" and gcs.link_up(), 12), uav.stats)
        self.assertGreater(uav.stats["drops"].get("handshake-invalid", 0), 0)       # the forgeries did arrive
        self.assertEqual(uav.stats["handshakes_fail"], 0)
        self.assertTrue(uav._cached_rekey("test"))                                  # forged REJECTs do not stop a rekey either
        uav.send(ks.STREAM_TELEMETRY, b"through")
        self.assertTrue(wait(lambda: b"through" in got))
        self.assertNotIn("internal", uav.stats["drops"])


# ====================================================== ground-station link
class TestGroundStationFloodHandling(unittest.TestCase):
    """Findings 7 and 20: the per-address limit of 8 ClientHellos in 10 s could be used against the UAV by anyone
    writing the UAV's address on forged datagrams; a lost answer to a cached rekey forced a full handshake; and a
    junk record carrying a pending session id cost a full key derivation each time."""

    @classmethod
    def setUpClass(cls):
        cls.uav, cls.gcs, cls.upk, cls.gpk = make_ids()

    def gcs_link(self):
        g = GcsLink(LinkConfig(gcs_host="127.0.0.1", gcs_port=0), self.gcs, {UAV_ID: self.upk}, bind=("127.0.0.1", 0))
        self.addCleanup(g.stop)
        g.sent = []
        g._send_hs = lambda mtype, body, addr, reverse=False: g.sent.append((mtype, body, addr))
        return g

    def hello(self):
        return hs.ClientHandshake(self.uav, self.gpk, 1, b"\x00" * 8).client_hello()

    def test_genuine_hellos_are_not_limited_by_the_address_they_come_from(self):
        g = self.gcs_link()
        for _ in range(20):                                      # was: refused from the ninth on ("hello-rate-limit")
            g._on_handshake(hs.MSG_CLIENT_HELLO, self.hello(), ("10.0.0.5", 4000))
        self.assertEqual(len([m for m in g.sent if m[0] == hs.MSG_SERVER_HELLO]), 20)
        self.assertEqual(g.stats["drops"], {})

    def test_the_ration_follows_from_the_cost_of_a_check_on_this_machine(self):
        g = self.gcs_link()
        rate, burst = g._verify_ration()
        self.assertGreaterEqual(rate, 50)                        # never less than the old fixed ration
        self.assertLessEqual(rate, 20000)
        self.assertEqual((g.bad_sigs.rate, g.bad_sigs.burst), (g.bad_sigs.rate, max(100.0, g.bad_sigs.rate)))
        # a quarter of a core: `rate` failed checks must take about 0.25 s, far from a whole second
        sig, msg = self.gcs.sign(b"x"), b"x"
        t0 = time.perf_counter()
        for _ in range(20):
            idm.verify("ML-DSA-87", msg, sig, self.gcs.pk)
        per_check = (time.perf_counter() - t0) / 20
        self.assertLess(rate * per_check, 0.9)
        g.ident = None                                           # cost cannot be measured: the conservative ration
        self.assertEqual(g._verify_ration(), (50.0, 100.0))

    def test_forged_hellos_are_rationed_and_a_genuine_one_gets_through_afterwards(self):
        g = self.gcs_link()
        g.bad_sigs = TokenBucket(rate=50, burst=100)             # a small ration, to see the mechanism with 300 hellos
        base = bytearray(self.hello())
        for n in range(300):                                     # right size, fresh time, known UAV id, wrong signature
            forged = bytearray(base)
            forged[10:14] = struct.pack("!I", n)                 # another nonce each time (inside the signed part)
            g._on_handshake(hs.MSG_CLIENT_HELLO, bytes(forged), (f"10.1.{n // 250}.{n % 250}", 4000))
        self.assertGreaterEqual(g.stats["drops"].get("hello-flood", 0), 150)     # most were dropped without verifying
        self.assertLessEqual(g.stats["drops"]["handshake-invalid"], 150)
        self.assertEqual(g.sent, [])                             # and none was answered
        g.bad_sigs.at -= 1.0                                     # one second later the ration has refilled
        g._on_handshake(hs.MSG_CLIENT_HELLO, self.hello(), ("10.0.0.5", 4000))
        self.assertEqual([m[0] for m in g.sent], [hs.MSG_SERVER_HELLO])

    def test_a_replayed_hello_is_refused_before_the_signature_is_checked(self):
        g = self.gcs_link()
        ch = self.hello()
        g._on_handshake(hs.MSG_CLIENT_HELLO, ch, ("10.0.0.5", 4000))
        g.hello_cache.clear()                                    # as if the retransmission window (10 s) had passed
        with mock.patch.object(idm, "verify", side_effect=AssertionError("signature checked for a replay")):
            g._on_handshake(hs.MSG_CLIENT_HELLO, ch, ("10.0.0.5", 4000))
        self.assertIn("replayed", g.stats["last_error"])
        self.assertEqual(g.bad_sigs.tokens, g.bad_sigs.burst)    # costs nothing from the ration
        old = bytearray(ch)
        old[10:14] = b"abcd"                                     # (another nonce, so it is not refused as a replay first)
        old[50:58] = struct.pack("!Q", hs.now_ms() - 3_600_000)  # a ClientHello stamped an hour ago
        with mock.patch.object(idm, "verify", side_effect=AssertionError("signature checked for a stale hello")):
            g._on_handshake(hs.MSG_CLIENT_HELLO, bytes(old), ("10.0.0.5", 4000))
        self.assertIn("3600 s away", g.stats["last_error"])      # and the reason names the clock difference

    def test_a_repeated_rekey_request_gets_the_same_answer(self):
        g = self.gcs_link()
        _, c, s = full_handshake(self.uav, self.gcs, self.gpk, self.upk)
        g.cache.put(UAV_ID, s, b"\x00" * 8, 1)
        req = hs.build_rekey_request(UAV_ID, c, b"\x00" * 8)
        for _ in range(3):                                       # the UAV repeats it: the answers were lost
            g._on_handshake(hs.MSG_REKEY_REQ, req, ("10.0.0.5", 4000))
        self.assertEqual([m[0] for m in g.sent], [hs.MSG_REKEY_RESP] * 3)
        self.assertEqual(len({m[1] for m in g.sent}), 1)         # identical: computed once
        self.assertEqual((g.stats["cached_rekeys_ok"], g.stats["cached_rekey_rejects"]), (1, 0))
        new, cf = hs.client_process_rekey_resp(req, c, g.sent[0][1])
        g._on_handshake(hs.MSG_CLIENT_FINISHED, cf, ("10.0.0.5", 4000))
        self.assertEqual(g.active, new.session_id)

    def test_refusals_of_forged_rekey_requests_are_rationed(self):
        g = self.gcs_link()
        for _ in range(200):
            g._on_handshake(hs.MSG_REKEY_REQ, os.urandom(hs.RK_FIXED.size + 32), ("10.0.0.6", 4000))
        self.assertTrue(40 <= len(g.sent) <= 46, len(g.sent))    # the burst allowance (plus what refilled meanwhile), then silence
        self.assertEqual(g.stats["drops"]["reject-not-sent"], 200 - len(g.sent))

    def test_junk_for_a_pending_session_costs_one_key_derivation(self):
        g = self.gcs_link()
        ch = hs.ClientHandshake(self.uav, self.gpk, 1, b"\x00" * 8)
        g._on_handshake(hs.MSG_CLIENT_HELLO, ch.client_hello(), ("10.0.0.5", 4000))
        secrets, cf = ch.process_server_hello(g.sent[0][1])
        sid = secrets.session_id
        with mock.patch.object(linkmod, "Session", wraps=linkmod.Session) as made:
            for _ in range(200):
                g._on_record(HDR.pack(1, 0x10, ks.STREAM_VIDEO, 0, sid, 0, random.getrandbits(40)) + os.urandom(60), ("10.9.9.9", 1))
            self.assertEqual(made.call_count, 1)
        self.assertEqual(g.stats["drops"]["unknown-session"], 200)
        client = Session(secrets, hs.get_suite(1), "uav", g.cfg)                 # the genuine first record still confirms it
        g._on_record(client.seal(ks.STREAM_TELEMETRY, b"hi"), ("10.0.0.5", 4000))
        self.assertEqual(g.active, sid)
        self.assertEqual(g._trial, {})

    def test_token_bucket(self):
        with mock.patch.object(linkmod.time, "monotonic", return_value=100.0):
            b = TokenBucket(rate=10, burst=3)
            self.assertEqual([b.take() for _ in range(5)], [True, True, True, False, False])
        with mock.patch.object(linkmod.time, "monotonic", return_value=100.25):
            self.assertEqual([b.take() for _ in range(4)], [True, True, False, False])     # 2.5 tokens after 0.25 s
        with mock.patch.object(linkmod.time, "monotonic", return_value=500.0):
            self.assertTrue(b.available())
            self.assertEqual(b.tokens, 3)                        # never more than the burst


class TestControlMessagesFromThePeer(unittest.TestCase):
    """Findings 8 and 9: fields of authenticated control messages were used without checking their type."""

    @classmethod
    def setUpClass(cls):
        cls.uav, cls.gcs, cls.upk, cls.gpk = make_ids()

    def test_json_from_the_peer_is_tamed(self):
        self.assertIsNone(jsonmsg.loads(b'{"a": NaN}'))                            # not JSON; a browser cannot parse it
        self.assertIsNone(jsonmsg.loads(b'{"a": -Infinity}'))
        self.assertIsNone(jsonmsg.loads(b"[1, 2]"))                                # a message is an object
        self.assertIsNone(jsonmsg.loads(b"[" * 100000))                            # nesting bomb
        self.assertIsNone(jsonmsg.loads(b"\xff\xfe"))
        m = jsonmsg.loads(b'{"big": 1e999, "s": "%s", "deep": %s1%s, "n": 12345678901234567890123, "ok": [1, "a", null, true]}'
                          % (b"x" * 10000, b"[" * 20, b"]" * 20))
        self.assertIsNone(m["big"])                                                # 1e999 parses to infinity
        self.assertEqual(len(m["s"]), jsonmsg.MAX_STR)
        self.assertIsNone(m["n"])
        self.assertEqual(m["ok"], [1, "a", None, True])
        d = m["deep"]
        for _ in range(jsonmsg.MAX_DEPTH - 1):
            d = d[0]
        self.assertIsNone(d)                                                       # cut at the depth limit
        self.assertEqual(jsonmsg.num(3), 3)
        for bad in (True, "3", None, float("nan"), float("inf"), [3]):
            self.assertIsNone(jsonmsg.num(bad))
        self.assertIsNone(jsonmsg.num(91, -90, 90))

    def test_split_messages_with_clashing_numbers_do_not_raise(self):
        r = jsonmsg.Reassembler()
        self.assertIsNone(r.add(jsonmsg.EXT.pack(7, 1, 3), b"b"))
        self.assertIsNone(r.add(jsonmsg.EXT.pack(7, 2, 3), b"c"))
        self.assertIsNone(r.add(jsonmsg.EXT.pack(7, 0, 2), b"a"))                  # same number, other piece count
        self.assertEqual(r.add(jsonmsg.EXT.pack(8, 0, 1), b'{"t":"x"}'), {"t": "x"})

    def test_malformed_pong_and_ratchet_request_are_counted_not_raised(self):
        g = GcsLink(LinkConfig(gcs_host="127.0.0.1", gcs_port=0), self.gcs, {UAV_ID: self.upk}, bind=("127.0.0.1", 0))
        self.addCleanup(g.stop)
        _, c, s = full_handshake(self.uav, self.gcs, self.gpk, self.upk)
        e = SimpleNamespace(session=Session(s, hs.get_suite(1), "gcs", g.cfg), uav_id=UAV_ID, addr=("a", 1), mobility=b"\x00" * 8)
        for pong in ({"t": "pong"}, {"t": "pong", "t1": "x", "t2": 1, "t3": 2}, {"t": "pong", "t1": None, "t2": [], "t3": {}},
                     {"t": "pong", "t1": time.time(), "t2": 5.0, "t3": 4.0}, {"t": "pong", "t1": 1.0, "t2": 2.0, "t3": 3.0},
                     {"t": "pong", "t1": True, "t2": True, "t3": True}):
            self.assertTrue(g._link_control(pong, e))
        self.assertEqual(g.stats["drops"]["bad-pong"], 6)
        self.assertIsNone(g.clock.offset)
        init = hs.PQRatchetInitiator(1, 1)
        x, ek = linkmod.b64e(init.x_pub), linkmod.b64e(init.ek)
        bad = [{"rid": "1", "x": x, "ek": ek}, {"rid": -1, "x": x, "ek": ek}, {"rid": 2**40, "x": x, "ek": ek},
               {"rid": True, "x": x, "ek": ek}, {"rid": 1, "x": "!!", "ek": ek}, {"rid": 2, "x": x, "ek": ek[:40]},
               {"rid": 3, "x": 5, "ek": None}, {"rid": 4}, {"rid": 5, "x": linkmod.b64e(b"\x00" * 32), "ek": ek}]
        for m in bad:
            self.assertTrue(g._link_control({"t": "ratchet_req", **m}, e), m)
        self.assertEqual(g.stats["drops"]["ratchet-invalid"], len(bad))            # (the last: X25519 refuses the all-zero key)
        self.assertEqual((g.stats["pq_ratchets"], len(g.sessions)), (0, 0))
        sent = []
        g.send_control = sent.append
        self.assertTrue(g._link_control({"t": "ratchet_req", "rid": 9, "x": x, "ek": ek}, e))       # a proper one works
        self.assertEqual((g.stats["pq_ratchets"], sent[0]["rid"]), (1, 9))
        init2 = hs.PQRatchetInitiator(1, 10)
        g._link_control({"t": "ratchet_req", "rid": 10, "x": linkmod.b64e(init2.x_pub), "ek": linkmod.b64e(init2.ek)}, e)
        self.assertEqual((g.stats["pq_ratchets"], g.stats["drops"]["ratchet-rate"]), (1, 1))        # not twice within 0.5 s

    def test_malformed_ratchet_answer_ends_the_attempt_cleanly(self):
        u = UavLink(LinkConfig(gcs_host="127.0.0.1", gcs_port=47999), self.uav, self.gpk, lambda: b"\x00" * 8)
        self.addCleanup(u.stop)
        _, c, s = full_handshake(self.uav, self.gcs, self.gpk, self.upk)
        u.session, u.state = Session(c, hs.get_suite(1), "uav", u.cfg), "UP"
        for bad in ({"x": "AA==", "ct": "AA==", "sid": "00" * 8}, {"x": 1, "ct": 2, "sid": 3}, {}, {"sid": "zz"},
                    {"x": linkmod.b64e(b"\x01" * 32), "ct": linkmod.b64e(b"c" * 1568), "sid": "00"}):
            self.assertTrue(u.request_pq_ratchet())
            self.assertTrue(u._link_control({"t": "ratchet_resp", "rid": u._rid, **bad}))
            self.assertIsNone(u._ratchet)
        self.assertEqual(u.stats["drops"]["ratchet-invalid"], 5)
        self.assertEqual(u.stats["pq_ratchets"], 0)

    def test_control_reassembly_never_refuses_a_new_message(self):
        r = linkmod.ControlReassembler()
        for n in range(100):                                                        # 100 messages that never complete
            self.assertIsNone(r.add(b"F" + struct.pack("!I", n) + bytes([0, 2]), b"x"))
        self.assertLessEqual(len(r.buf), 16)
        self.assertIsNone(r.add(b"F" + b"zzzz" + bytes([0, 2]), b'{"t":'))
        self.assertEqual(r.add(b"F" + b"zzzz" + bytes([1, 2]), b'"hb"}'), b'{"t":"hb"}')


# =================================================================== blobs
class TestBlobTransferHardening(unittest.TestCase):
    """Finding 9: the metadata of a transfer (name, size, chunk count, hash) was used as received."""

    GOOD = {"id": "00", "kind": "image", "name": "img_20261004_042600.jpg", "size": 2500, "chunks": 3,
            "sha256": "ab" * 32, "meta": {}}

    def test_metadata_is_checked_field_by_field(self):
        self.assertTrue(blob.valid_info(self.GOOD))
        for k, v in (("name", "../../.ssh/authorized_keys"), ("name", "/etc/passwd"), ("name", "a\r\nb.jpg"), ("name", ""),
                     ("name", 7), ("name", "x" * 200), ("name", ".hidden"), ("size", "2500"), ("size", -1), ("size", True),
                     ("size", blob.MAX_BLOB + 1), ("chunks", 2), ("chunks", 3.0), ("chunks", 10**9), ("sha256", "zz" * 32),
                     ("sha256", None), ("kind", 5), ("meta", [1])):
            self.assertFalse(blob.valid_info({**self.GOOD, k: v}), (k, v))
        self.assertFalse(blob.valid_info([1]))
        self.assertTrue(blob.valid_info({**self.GOOD, "size": 0, "chunks": 1}))

    def receiver(self):
        done, ctl = [], []
        return blob.BlobReceiver(ctl.append, lambda info, data: done.append((info, data))), done, ctl

    def send(self, rx, bid, data, info=None, order=None):
        chunks = [data[i:i + blob.CHUNK] for i in range(0, len(data), blob.CHUNK)] or [b""]
        info = info or {"id": bid.hex(), "kind": "image", "name": "a.jpg", "size": len(data),
                        "sha256": hashlib.sha256(data).hexdigest(), "chunks": len(chunks), "meta": {}}
        rx.on_record(b"M" + bid, json.dumps(info).encode())
        for i in (order or range(len(chunks))):
            rx.on_record(b"C" + bid + struct.pack("!I", i), chunks[i])

    def test_unacceptable_metadata_drops_the_transfer(self):
        rx, done, _ = self.receiver()
        data = os.urandom(3000)
        self.send(rx, b"\x00\x00\x00\x01", data, {"id": "1", "kind": "image", "name": "../x.jpg", "size": 3000,
                                                  "sha256": hashlib.sha256(data).hexdigest(), "chunks": 3, "meta": {}})
        rx.on_record(b"M\x00\x00\x00\x02", b'{"size": "many", "chunks": 1}')
        rx.on_record(b"M\x00\x00\x00\x03", b"[1,2,3]")
        rx.on_record(b"M\x00\x00\x00\x04", b'{"size": NaN}')
        self.assertEqual((done, rx.refused), ([], 4))
        self.send(rx, b"\x00\x00\x00\x05", data)                                    # a proper transfer still works
        self.assertEqual((done[0][1], done[0][0]["integrity"]), (data, "PASS"))

    def test_the_first_metadata_stands(self):
        rx, done, _ = self.receiver()
        data = os.urandom(5000)
        bid = b"\x00\x00\x00\x07"
        chunks = [data[i:i + blob.CHUNK] for i in range(0, len(data), blob.CHUNK)]
        info = {"id": bid.hex(), "kind": "image", "name": "a.jpg", "size": 5000, "sha256": hashlib.sha256(data).hexdigest(),
                "chunks": 5, "meta": {}}
        for i in (4, 3):                                                            # chunks before the metadata
            rx.on_record(b"C" + bid + struct.pack("!I", i), chunks[i])
        rx.on_record(b"C" + bid + struct.pack("!I", 900), b"stray")                 # beyond the end: dropped with the metadata
        rx.on_record(b"M" + bid, json.dumps(info).encode())
        rx.on_record(b"M" + bid, json.dumps({**info, "name": "evil.jpg", "size": 1100, "chunks": 1}).encode())
        rx.on_record(b"C" + bid + struct.pack("!I", 0), b"z" * 2000)                # longer than a chunk can be: dropped
        for i in (0, 1, 2):
            rx.on_record(b"C" + bid + struct.pack("!I", i), chunks[i])
        self.assertEqual((done[0][0]["name"], done[0][1]), ("a.jpg", data))

    def test_memory_for_all_transfers_together_is_bounded(self):
        rx, done, _ = self.receiver()
        with mock.patch.object(blob, "MAX_BUFFERED", 50 * blob.CHUNK):
            for b in range(6):
                for i in range(20):
                    rx.on_record(b"C" + bytes([0, 0, 0, b]) + struct.pack("!I", i), b"x" * blob.CHUNK)
        self.assertEqual(sum(len(e["parts"]) for e in rx.rx.values()), 50)

    def test_nacks_cannot_multiply_senders_and_bad_ones_are_ignored(self):
        sent, gate = [], threading.Event()

        def send_record(stream, payload, ext):
            sent.append(ext)
            gate.wait(5)                                                            # the "radio" is slow
            return True
        tx = blob.BlobSender(send_record, pace_s=0)
        info = tx.send(ks.STREAM_IMAGE, "image", "a.jpg", os.urandom(20000))
        self.assertTrue(wait(lambda: len(sent) == 1, 3))
        before = threading.active_count()
        for _ in range(50):                                                         # a storm of NACKs while it is sending
            self.assertTrue(tx.on_control({"t": "blob_nack", "id": info["id"], "missing": list(range(19)), "meta": True}))
        self.assertLessEqual(threading.active_count(), before)                      # no new thread per NACK
        for junk in ({"t": "blob_nack", "id": "zz"}, {"t": "blob_nack", "id": 5}, {"t": "blob_nack"}, {"t": "blob_done", "id": None},
                     {"t": "blob_nack", "id": info["id"], "missing": "all"}, {"t": "blob_nack", "id": info["id"], "missing": [None, "1", -1, 10**9, True, 2.5]}):
            self.assertTrue(tx.on_control(junk), junk)
        gate.set()
        self.assertTrue(wait(lambda: len(sent) == 20, 5))                           # metadata + 19 chunks, once
        self.assertTrue(wait(lambda: not tx.active[bytes.fromhex(info["id"])]["pushing"], 3))
        tx.on_control({"t": "blob_nack", "id": info["id"], "missing": [3, 3000, 4], "meta": False})
        self.assertTrue(wait(lambda: len(sent) == 22, 3))                           # now a NACK is served: chunks 3 and 4
        tx.on_control({"t": "blob_done", "id": info["id"]})
        self.assertEqual(tx.active, {})


# ==================================================== files at rest: parsers
class TestStoredFileParsers(unittest.TestCase):
    """Finding 10: decrypt_recording raised struct.error / KeyError / JSONDecodeError on damaged files; the callers
    handle RecordingError only."""

    @classmethod
    def setUpClass(cls):
        from kyber6g.recording.recorder import EncryptedRecorder
        cls.d = Path(tempfile.mkdtemp())
        cls.ek = idm.generate_recording_kem(cls.d)
        cls.dk = idm.load_recording_dk(cls.d)
        rec = EncryptedRecorder(cls.d / "rec", cls.ek, {"codec": "h264", "fps": 30})
        for i in range(90):
            rec.add_frame(os.urandom(700), i % 30 == 0, i * 33333)
        rec.close()
        cls.path, cls.raw = rec.path, rec.path.read_bytes()

    def decrypt(self, raw):
        from kyber6g.recording.recorder import RecordingError, decrypt_recording
        p = self.d / "probe.k6grec"
        p.write_bytes(raw)
        try:
            return decrypt_recording(p, self.dk)
        except RecordingError as e:
            return e

    def test_the_recording_itself_is_fine_and_private(self):
        hdr, data, rep = self.decrypt(self.raw)
        self.assertEqual((rep["frames"], rep["complete"], rep["trailing_bytes"]), (90, True, 0))
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)

    def test_every_truncation_is_reported_as_a_recording_error_or_as_truncated(self):
        from kyber6g.recording.recorder import RecordingError
        rng = random.Random(7)
        cuts = sorted(set(list(range(0, 1700)) + [rng.randrange(len(self.raw)) for _ in range(120)]))
        for n in cuts:
            r = self.decrypt(self.raw[:n])
            if isinstance(r, RecordingError):
                continue
            self.assertFalse(r[2]["complete"], n)                                   # cut between two segments: says so
            self.assertIn("TRUNCATED", r[2]["status"])

    def test_random_damage_never_escapes_as_another_exception(self):
        from kyber6g.recording.recorder import RecordingError
        rng = random.Random(11)
        outcomes = collections.Counter()
        for _ in range(400):
            raw = bytearray(self.raw)
            for _ in range(rng.choice((1, 1, 2, 8))):
                pos = rng.randrange(len(raw)) if rng.random() < 0.5 else rng.randrange(min(len(raw), 1800))
                raw[pos] ^= 1 << rng.randrange(8)
            r = self.decrypt(bytes(raw))
            outcomes["error" if isinstance(r, RecordingError) else "accepted"] += 1
        self.assertEqual(outcomes["accepted"], 0)                                   # every single-bit change is detected
        for junk in (b"", b"K6GREC01", b"K6GREC01\xff\xff", b"K6GREC01\x00\x02{}" + b"\x00" * 1616, os.urandom(5000),
                     b"K6GREC01\x00\x05[1,2]" + b"\x00" * 1616, b"K6GREC01\x00\x10" + b'{"rec_id":"zz"}_' + b"\x00" * 1616):
            self.assertIsInstance(self.decrypt(junk), RecordingError, junk[:20])

    def test_bytes_after_the_final_segment_are_reported(self):
        hdr, data, rep = self.decrypt(self.raw + b"appended by someone")
        self.assertEqual((rep["complete"], rep["trailing_bytes"]), (True, 19))

    def test_frame_rate_for_the_remux_command_is_a_plain_number(self):
        from kyber6g.recording.recorder import frame_rate
        self.assertEqual([frame_rate(h) for h in ({"fps": 25}, {"fps": 29.97}, {}, {"fps": "-i /etc/passwd"}, {"fps": 0},
                                                 {"fps": 1e9}, {"fps": True}, {"fps": None}, None)],
                         [25, 29.97, 30, 30, 30, 30, 30, 30, 30])

    def test_photo_parser_reports_photo_errors_only(self):
        from kyber6g.recording.photos import PhotoError, PhotoStore, open_image, seal_image
        blob_ = seal_image(self.ek, b"\xff\xd8" + os.urandom(4000), {"width": 4})
        self.assertEqual(open_image(blob_, self.dk)[1][:2], b"\xff\xd8")
        rng = random.Random(3)
        for n in list(range(0, 1700, 7)) + [len(blob_) - 1]:
            with self.assertRaises(PhotoError):
                open_image(blob_[:n], self.dk)
        for _ in range(200):
            raw = bytearray(blob_)
            raw[rng.randrange(len(raw))] ^= 1 << rng.randrange(8)
            with self.assertRaises(PhotoError):
                open_image(bytes(raw), self.dk)
        st = PhotoStore(self.d / "photos", self.ek)
        st.save("img_1.jpg", b"\xff\xd8abc", {})
        (st.dir / "broken.k6gimg").write_bytes(b"K6GIMG01\xff")
        self.assertEqual(sorted((x["name"], x.get("error")) for x in st.list()), [("broken.k6gimg", "unreadable"), ("img_1.k6gimg", None)])
        self.assertEqual(stat.S_IMODE(st.dir.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((st.dir / "img_1.k6gimg").stat().st_mode), 0o600)

    def test_two_photos_never_share_a_file(self):
        """Found by the stored-data audit after the measurement campaign: photos taken within one second had the
        same name (whole seconds) and the second replaced the first."""
        from kyber6g.ground.main import safe_name
        from kyber6g.recording.photos import PhotoStore, open_image
        from kyber6g.uav.main import photo_name
        t = 1791075204.25
        names = [photo_name(t), photo_name(t + 0.4), photo_name(t + 0.999)]
        self.assertEqual(len(set(names)), 3)                                # same second, three names
        self.assertTrue(all(safe_name(n) == n and n.endswith(".jpg") for n in names), names)
        st = PhotoStore(self.d / "photos_same_name", self.ek)
        a = st.save("img_x.jpg", b"\xff\xd8first", {})
        b = st.save("img_x.jpg", b"\xff\xd8second", {})                     # even with the very same name
        self.assertNotEqual(a["stored_as"], b["stored_as"])
        self.assertEqual(open_image(st.read(a["stored_as"]), self.dk)[1], b"\xff\xd8first")
        self.assertEqual(open_image(st.read(b["stored_as"]), self.dk)[1], b"\xff\xd8second")


# ================================================== keys and trust anchors
@unittest.skipUnless(os.name == "posix", "POSIX permissions")
class TestKeyDirectoryPermissions(unittest.TestCase):
    """Finding 5: the key directory and the pinned public keys were created with the default umask (0775 / 0664 on
    the Pi): whoever may write them decides whom the node trusts."""

    def setUp(self):
        self.d = Path(tempfile.mkdtemp()) / "keys"
        old = os.umask(0o002)                               # the umask of a stock Raspberry Pi OS login
        self.addCleanup(os.umask, old)

    def test_new_keys_are_created_private(self):
        idm.generate_identity(self.d, "uav")
        idm.generate_recording_kem(self.d)
        mode = lambda p: stat.S_IMODE(p.stat().st_mode)
        self.assertEqual(mode(self.d), 0o700)
        self.assertEqual(mode(self.d / "uav_ML-DSA-87.sk"), 0o600)
        self.assertEqual(mode(self.d / "gcs_recording_ML-KEM-1024.dk"), 0o600)
        self.assertEqual(mode(self.d / "uav_ML-DSA-87.pk"), 0o644)

    def test_a_loose_directory_and_pinned_key_are_tightened_and_reported(self):
        (self.d / "peers").mkdir(parents=True)
        pk = self.d / "peers" / "gcs_ML-DSA-87.pk"
        key = b"pinned public key".ljust(2592, b".")                               # the size of an ML-DSA-87 public key
        pk.write_bytes(key)
        os.chmod(self.d, 0o775); os.chmod(self.d / "peers", 0o775); os.chmod(pk, 0o664)
        with self.assertLogs("kyber6g.identity", "WARNING") as logs:
            self.assertEqual(idm.load_pinned_peer(self.d, "gcs"), key)
        self.assertEqual(stat.S_IMODE((self.d / "peers").stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(pk.stat().st_mode), 0o644)
        self.assertTrue(any(idm.fingerprint(key) in line for line in logs.output))   # so the operator can compare
        with self.assertNoLogs("kyber6g.identity", "WARNING"):
            idm.load_pinned_peer(self.d, "gcs")                                     # nothing left to fix

    def test_a_readable_secret_key_is_refused(self):
        idm.generate_identity(self.d, "uav")
        os.chmod(self.d / "uav_ML-DSA-87.sk", 0o640)
        with self.assertRaises(PermissionError):
            idm.load_identity(self.d, "uav", UAV_ID)
        idm.generate_recording_kem(self.d)
        os.chmod(self.d / "gcs_recording_ML-KEM-1024.dk", 0o604)
        with self.assertRaises(PermissionError):
            idm.load_recording_dk(self.d)

    def test_a_shared_directory_is_never_taken_over(self):
        shared = Path(tempfile.mkdtemp())
        os.chmod(shared, 0o1777)                                                    # like /tmp
        with self.assertRaises(PermissionError):
            idm.private_dir(shared)
        self.assertEqual(stat.S_IMODE(shared.stat().st_mode), 0o1777)               # left exactly as it was
        with self.assertRaises(PermissionError):
            idm.private_dir(Path("/"))

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "needs root to create a file of another user")
    def test_keys_of_another_user_are_refused(self):
        self.d.mkdir(parents=True)
        (self.d / "peers").mkdir()
        pk = self.d / "peers" / "gcs_ML-DSA-87.pk"
        pk.write_bytes(b"k")
        os.chown(pk, 12345, 12345)
        with self.assertRaises(PermissionError):
            idm.load_pinned_peer(self.d, "gcs")
        os.chown(self.d / "peers", 12345, 12345)
        with self.assertRaises(PermissionError):
            idm.private_dir(self.d / "peers")


# ============================================================== dashboard
class TestDashboardRequestChecks(unittest.TestCase):
    """Finding 2: any web page open in the operator's browser could send commands to http://127.0.0.1:8600 (a
    cross-site POST with a text/plain body needs no permission), and a DNS-rebinding page could read everything."""

    @classmethod
    def setUpClass(cls):
        from kyber6g.ground.main import GroundApp, make_handler
        from .test_http_api import StubDetector, StubStore
        app = GroundApp.__new__(GroundApp)
        app.detector, app.finder, app.store = StubDetector(), None, StubStore()
        app.log = collections.deque(maxlen=50)
        app.data = Path(tempfile.mkdtemp())
        app.home = app.last_fix = app.home_source = None
        cls.commands = []
        app.command = lambda cmd, args, timeout=20: cls.commands.append((cmd, args)) or {"ok": True}
        app.detections_latest = lambda: {"now": time.time()}
        cls.app = app
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(app))
        cls.srv.daemon_threads = True
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.port = cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def req(self, method, path, body=None, headers=None, host=None):
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        c.putrequest(method, path, skip_host=True)
        c.putheader("Host", f"127.0.0.1:{self.port}" if host is None else host)
        data = json.dumps(body).encode() if isinstance(body, (dict, list)) else body
        hdrs = dict(headers or {})
        if data is not None:
            hdrs.setdefault("Content-Type", "application/json")
            hdrs["Content-Length"] = str(len(data))
        for k, v in hdrs.items():
            c.putheader(k, v)
        c.endheaders(data)
        r = c.getresponse()
        txt = r.read()
        c.close()
        return r.status, dict(r.getheaders()), txt

    def post(self, body={"cmd": "status"}, **kw):
        return self.req("POST", "/api/cmd", body, **kw)[0]

    def test_host_header(self):
        self.assertEqual(self.req("GET", "/api/detections/latest")[0], 200)
        self.assertEqual(self.req("GET", "/api/detections/latest", host=f"localhost:{self.port}")[0], 200)
        self.assertEqual(self.req("GET", "/api/detections/latest", host=f"[::1]:{self.port}")[0], 200)
        for evil in (f"evil.example:{self.port}", "evil.example", f"127.0.0.1.evil.example:{self.port}", f"127.0.0.1:{self.port + 1}",
                     "", f"localhost.:{self.port}", f"127.0.0.1:{self.port}@evil.example", "a b"):
            s, _, body = self.req("GET", "/api/detections/latest", host=evil)
            self.assertEqual(s, 403, evil)
            self.assertIn(b"host not allowed", body)
            self.assertEqual(self.post(host=evil), 403, evil)
        from kyber6g.ground.main import host_allowed
        self.assertTrue(host_allowed("gcs.lab:8600", 8600, ["gcs.lab"]))            # a name the operator listed
        self.assertTrue(host_allowed("192.168.1.20:8600", 8600))                    # an address cannot be rebound
        self.assertFalse(host_allowed("gcs.lab:8600", 8600))
        self.assertTrue(host_allowed("localhost", 80))

    def test_commands_from_another_site_are_refused(self):
        n = len(self.commands)
        me = f"http://127.0.0.1:{self.port}"
        self.assertEqual(self.post(headers={"Origin": "http://evil.example"}), 403)
        self.assertEqual(self.post(headers={"Origin": "null"}), 403)                            # sandboxed frame, file://
        self.assertEqual(self.post(headers={"Origin": f"http://localhost:{self.port}"}), 403)   # other origin than Host
        self.assertEqual(self.post(headers={"Sec-Fetch-Site": "cross-site", "Origin": me}), 403)
        self.assertEqual(self.post(headers={"Sec-Fetch-Site": "same-site"}), 403)               # another port of this machine
        self.assertEqual(self.post(headers={"Content-Type": "text/plain"}), 415)                # the "simple request" trick
        self.assertEqual(self.post(headers={"Content-Type": "application/x-www-form-urlencoded"}), 415)
        self.assertEqual(self.post(body=b'{"cmd":"status"}', headers={"Content-Type": ""}), 415)
        self.assertEqual(len(self.commands), n)                                                 # none of them was carried out
        self.assertEqual(self.post(headers={"Origin": me, "Sec-Fetch-Site": "same-origin"}), 200)       # our own page
        self.assertEqual(self.post(headers={"Content-Type": "application/json; charset=utf-8"}), 200)
        self.assertEqual(self.post(), 200)                                                      # curl, the test tools
        self.assertEqual(len(self.commands), n + 3)
        self.assertGreaterEqual(sum(self.app.http_refused.values()), 5)

    def test_another_site_cannot_read_or_embed_anything(self):
        for path in ("/api/state", "/api/detections/latest", "/video.mjpg", "/static/app.js", "/images/x.jpg", "/api/export/db"):
            for hdrs in ({"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"},
                         {"Sec-Fetch-Site": "same-site", "Sec-Fetch-Mode": "cors"},
                         {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe"},
                         {"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"}):
                self.assertEqual(self.req("GET", path, headers=hdrs)[0], 403, (path, hdrs))
        # a link to the dashboard from another page may open the page itself, nothing else
        s, h, body = self.req("GET", "/", headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"})
        self.assertEqual(s, 200)
        self.assertEqual(self.req("GET", "/", headers={"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe"})[0], 403)

    def test_security_headers(self):
        s, h, body = self.req("GET", "/")
        self.assertEqual(s, 200)
        csp = h["Content-Security-Policy"]
        import re
        inline = re.search(rb'<script type="importmap">(.*?)</script>', body, re.S).group(1)
        digest = base64.b64encode(hashlib.sha256(inline).digest()).decode()
        self.assertIn(f"script-src 'self' 'sha256-{digest}'", csp)                  # the page's own import map, nothing else inline
        self.assertNotIn("unsafe-inline", csp.split("script-src")[1].split(";")[0])
        self.assertNotIn("unsafe-eval", csp)
        for part in ("default-src 'self'", "object-src 'none'", "base-uri 'none'", "frame-ancestors 'none'", "connect-src 'self'", "form-action 'none'"):
            self.assertIn(part, csp)
        self.assertNotIn(b"onclick=", body)                                         # nothing in the page needs inline handlers
        for path in ("/", "/static/app.js", "/api/detections/latest", "/nope"):
            h = self.req("GET", path)[1]
            self.assertEqual((h["X-Content-Type-Options"], h["X-Frame-Options"], h["Cross-Origin-Resource-Policy"]),
                             ("nosniff", "DENY", "same-origin"), path)

    def test_command_arguments_cannot_replace_the_envelope(self):
        n = len(self.commands)
        for args in ({"t": "blob_done"}, {"id": 7}, {"t": "ping", "id": 1, "name": "x"}):
            s, _, body = self.req("POST", "/api/cmd", {"cmd": "status", "args": args})
            self.assertEqual((s, json.loads(body)["error"]), (400, "reserved argument name"))
        self.assertEqual(len(self.commands), n)
        from kyber6g.ground.main import GroundApp
        app = GroundApp.__new__(GroundApp)
        sent = []
        app.link = SimpleNamespace(send_control=lambda m: sent.append(m) or False)
        app.ids = iter(range(5, 9))
        GroundApp.command(app, "status", {"t": "ratchet_req", "id": 99, "x": 1})    # even if a caller inside the program tries
        self.assertEqual(sent, [{"t": "status", "id": 5, "x": 1}])

    def test_row_limits_are_clamped(self):
        for q in ("-1", "0", "999999999", "5"):
            s, _, body = self.req("GET", f"/api/events?limit={q}")
            self.assertEqual(s, 200, q)
            self.assertGreaterEqual(len(json.loads(body)), 1)                       # a negative LIMIT is "no limit" in SQLite
        self.assertEqual(self.req("GET", "/api/events?limit=abc")[0], 400)
        self.assertEqual(self.req("GET", "/api/series?minutes=nan")[0], 400)
        self.assertEqual(self.req("POST", "/api/cmd", {"cmd": "detector", "args": {"teach": "x"}})[0], 200)   # ok:false, not a crash
        self.assertEqual(self.req("POST", "/api/cmd", {"cmd": "detector", "args": {"teach": {"image": 5}}})[0], 200)

    def test_file_names_from_the_uav(self):
        from kyber6g.ground.main import GroundApp, safe_name
        self.assertEqual(safe_name("img_20261004_042600.jpg"), "img_20261004_042600.jpg")
        self.assertEqual(safe_name("/home/pi/rec_1.k6grec"), "rec_1.k6grec")        # reduced to its last component
        for bad in ("", "..", ".bashrc", "a b.jpg", 'x".jpg', "a\r\nSet-Cookie: x", "x" * 121, "é.jpg", "a;b", None, 5):
            with self.assertRaises(ValueError):
                safe_name(bad)
        app = GroundApp.__new__(GroundApp)
        app.data = Path(tempfile.mkdtemp())
        (app.data / "images").mkdir(); (app.data / "recordings").mkdir()
        with self.assertRaises(ValueError):                                         # HTML under an image URL would be an XSS
            GroundApp.on_image(app, {"name": "x.jpg", "size": 9, "kind": "image"}, b"<script>")
        with self.assertRaises(ValueError):
            GroundApp.on_image(app, {"name": "x.html", "size": 9, "kind": "image"}, b"\xff\xd8..")
        with self.assertRaises(ValueError):
            GroundApp.on_recording(app, {"name": "evil.mp4", "size": 3}, b"abc")
        self.assertEqual(list((app.data / "images").iterdir()) + list((app.data / "recordings").iterdir()), [])


class TestMediaLibrary(unittest.TestCase):
    """The MEDIA page: everything the ground station holds can be listed, newest first, and a recording that has just
    been saved on the UAV is fetched without being asked for. (Recordings that nobody had fetched were taken for lost:
    30 of the 73 on the UAV's card on 6 October 2026.)"""

    def app(self, auto_fetch_mb=64):
        from kyber6g.ground.main import GroundApp
        app = GroundApp.__new__(GroundApp)
        app.data = Path(tempfile.mkdtemp())
        (app.data / "images").mkdir(); (app.data / "recordings").mkdir()
        app.cfg = SimpleNamespace(auto_fetch_mb=auto_fetch_mb)
        app.rows, app.asked, app.notes = [], [], []
        app.store = SimpleNamespace(query=lambda sql, *a: [{"meta": json.dumps(r)} for r in app.rows])
        app.command = lambda cmd, args, timeout=20.0: app.asked.append((cmd, args)) or {"ok": True}
        app.note = lambda kind, text: app.notes.append((kind, text))
        return app

    def test_everything_on_disk_is_listed_newest_first(self):
        app = self.app()
        for k in range(40):                                                 # more than the 16 the page's state carries
            name = f"img_{k:03d}.jpg"
            (app.data / "images" / name).write_bytes(b"\xff\xd8")
            (app.data / "images" / (name + ".json")).write_text(json.dumps({
                "name": name, "size": 2, "integrity": "PASS", "received_at": 1000.0 + k, "sha256": "ab" * 32,
                "meta": {"width": 1280, "height": 720, "mode": "NORMAL", "wrapped_key": "00" * 1600}}))
            os.utime(app.data / "images" / (name + ".json"), (1000 + k, 1000 + k))
        (app.data / "images" / "gone.jpg.json").write_text(json.dumps({"name": "gone.jpg"}))        # its picture was deleted
        (app.data / "images" / "bad.jpg.json").write_text("{not json")
        (app.data / "images" / "bad.jpg").write_bytes(b"\xff\xd8")
        for k in range(14):                                                 # more than the 10 of the state
            (app.data / "recordings" / f"rec_{k:02d}.mp4").write_bytes(b"mp4")
            app.rows.append({"name": f"rec_{k:02d}.k6grec", "mp4": f"/recordings/rec_{k:02d}.mp4", "received_at": 2000.0 + k,
                             "decrypt": "PASS", "frames": 100 + k, "header": {"kem_ct": "00" * 1568}})
        app.rows.append({"name": "rec_lost.k6grec", "mp4": "/recordings/rec_lost.mp4", "received_at": 9000.0})   # no file any more
        (app.data / "recordings" / "rec_copied.mp4").write_bytes(b"mp4")    # copied with `kyber6g.sh pull`, not in the database
        m = app.media()
        self.assertEqual(m["counts"], {"images": 40, "recordings": 15})
        self.assertEqual([i["name"] for i in m["images"]], [f"img_{k:03d}.jpg" for k in range(39, -1, -1)])
        self.assertEqual(m["images"][0]["url"], "/images/img_039.jpg")
        self.assertEqual(m["images"][0]["meta"], {"width": 1280, "height": 720, "mode": "NORMAL"})  # what the page shows, no more
        self.assertNotIn("sha256", m["images"][0])
        names = [r["name"] for r in m["recordings"]]
        self.assertEqual(names[0], "rec_copied.k6grec")                     # its file is the newest
        self.assertEqual(names[1:], [f"rec_{k:02d}.k6grec" for k in range(13, -1, -1)])
        self.assertTrue(all("header" not in r for r in m["recordings"]))
        self.assertLess(len(json.dumps(m)), 20000)
        # after a restart the page's state shows the newest 16 and 10 of the same lists
        app.images, app.recordings = [], []
        app._restore_media()
        self.assertEqual([i["name"] for i in app.images], [f"img_{k:03d}.jpg" for k in range(39, 23, -1)])
        self.assertEqual([r["name"] for r in app.recordings], names[:10])
        self.assertEqual(app.media_counts(), {"images": 41, "recordings": 15})  # counted from the files alone ("bad" has a picture)

    def test_a_saved_recording_is_fetched_by_itself(self):
        from kyber6g.ground.main import GroundApp
        app = self.app()
        app._fetch_saved({"name": "rec_a.k6grec", "parts": ["rec_a.k6grec"], "file_bytes": 17 << 20})
        self.assertTrue(wait(lambda: app.asked == [("fetch_recording", {"name": "rec_a.k6grec"})], 3), app.asked)
        # too large to take the link from the live video unasked: left on the page with its button, and said so
        app.asked.clear()
        app._fetch_saved({"name": "rec_b.k6grec", "parts": ["rec_b.k6grec", "rec_b_p2.k6grec"], "file_bytes": 300 << 20})
        time.sleep(0.1)
        self.assertEqual(app.asked, [])
        self.assertIn("FETCH & DECRYPT", app.notes[-1][1])
        # several parts within the limit: each is fetched
        app._fetch_saved({"name": "rec_c.k6grec", "parts": ["rec_c.k6grec", "rec_c_p2.k6grec"], "file_bytes": 40 << 20})
        self.assertTrue(wait(lambda: [a[1]["name"] for a in app.asked] == ["rec_c.k6grec", "rec_c_p2.k6grec"], 3), app.asked)
        # switched off, or an answer that is not a summary: nothing is asked for
        for off, summary in ((self.app(auto_fetch_mb=0), {"name": "rec_d.k6grec", "file_bytes": 1}), (app, None), (app, {"frames": 3}), (app, {"name": 7})):
            off.asked.clear()
            off._fetch_saved(summary)
            time.sleep(0.05)
            self.assertEqual(off.asked, [])
        # it is the acknowledged SAVE that starts it: GroundApp.command hands the UAV's summary over
        app = self.app()
        app.link = SimpleNamespace(send_control=lambda msg: True)
        app.ids, app.acks, app.ack_cv = iter(range(1, 99)), {1: {"ok": True, "result": {"name": "rec_e.k6grec", "file_bytes": 5}}}, threading.Condition()
        fetched = []
        app._fetch_saved = fetched.append
        self.assertTrue(GroundApp.command(app, "stop_rec", {})["ok"])
        self.assertEqual(fetched, [{"name": "rec_e.k6grec", "file_bytes": 5}])
        app.acks[2] = {"ok": False, "error": "not recording"}
        GroundApp.command(app, "stop_rec", {})
        self.assertEqual(len(fetched), 1)


class TestTelemetryCleaning(unittest.TestCase):
    """Finding 12: values from the UAV went into SQLite, the analytics and the page as received."""

    def test_types_and_ranges(self):
        from kyber6g.ground.main import clean_telemetry
        t = clean_telemetry({"ts": 1791068216.5, "n": 7, "boot": 1791060000.1, "mode": 3, "fix": "3D", "lat": 12.97, "lon": 79.15,
                             "alt_m": 90.5, "sats_used": 9, "sats_seen": "<img src=x onerror=alert(1)>", "hdop": "0.9",
                             "speed_mps": -3, "source": "L" * 500, "satellites": [["GPS", 3, 120.0, 45.0, 38.0, 1], ["GPS", 4],
                             "junk", ["GLONASS" * 5, "x", None, 200, 30, 0]], "backfill": 0, "extra": {"a": 1}})
        self.assertEqual((t["lat"], t["lon"], t["mode"], t["n"], t["sats_used"]), (12.97, 79.15, 3, 7, 9))
        self.assertIsNone(t["sats_seen"])                                           # text where a number belongs
        self.assertIsNone(t["hdop"])
        self.assertIsNone(t["speed_mps"])                                           # out of range
        self.assertEqual(len(t["source"]), 160)
        self.assertEqual(t["satellites"], [["GPS", 3, 120.0, 45.0, 38.0, 1], ["GLONASSGLONA", None, None, None, 30, 0]])
        self.assertIs(t["backfill"], False)
        self.assertEqual(t["extra"], {"a": 1})
        half = clean_telemetry({"ts": 5, "lat": 12.0, "lon": 500})
        self.assertEqual((half["lat"], half["lon"]), (None, None))                  # never half a position
        for bad in ({}, {"ts": "now"}, {"ts": None}, {"ts": True}, {"ts": float("nan")}, [1], None, "x"):
            self.assertIsNone(clean_telemetry(bad))

    def test_a_malformed_sample_is_counted_and_nothing_is_stored(self):
        from kyber6g.ground.main import GroundApp
        app = GroundApp.__new__(GroundApp)
        stored = []
        app.tm = {"rx": 0, "backfill": 0, "latency_ms": None, "last_n": None, "gaps": 0, "dup": 0}
        app._tm_seen, app._tm_order, app._tm_lat = set(), collections.deque(), collections.deque(maxlen=30)
        app._last_sat_store, app.telemetry, app.sky, app.sky_ts = 0, None, [], None
        app.track, app.home, app.home_source, app.last_fix = collections.deque(), None, None, None
        app.link = SimpleNamespace(time_offset=None)
        app.store = SimpleNamespace(telemetry=lambda *a: stored.append(a), satellites=lambda *a: None, event=lambda *a: None)
        app.log = collections.deque()
        for bad in ({"n": 1}, {"ts": "x", "n": 2}, {"ts": [1]}):
            GroundApp._telemetry(app, bad, {})
        self.assertEqual((app.tm["malformed"], app.tm["rx"], stored), (3, 0, []))
        GroundApp._telemetry(app, {"ts": 100.0, "n": 1, "boot": 5.0, "mode": 3, "lat": "12.9", "lon": 79.1, "satellites": "x"}, {})
        self.assertEqual((app.tm["rx"], app.telemetry["lat"], app.telemetry["lon"], app.telemetry["satellites"]), (1, None, None, []))
        self.assertEqual(len(app.track), 0)                                         # no point on the map from a bad position
        self.assertIsNone(app.home)


class TestDashboardScriptEscapes(unittest.TestCase):
    """Finding 12 (page side): f() inserted any non-number unescaped."""

    def test_format_helper_escapes_text(self):
        src = (Path(__file__).resolve().parent.parent / "kyber6g/ground/static/app.js").read_text()
        self.assertIn('(typeof v === "number" ? v.toFixed(d) : esc(v)) + u', src)
        self.assertNotIn("${t.sats_used ?? 0}/${t.sats_seen ?? 0}`);", src.split("posKv")[0])
        self.assertIn("const limit = Number(", src)


# ===================================================== GNSS and video input
class TestGnssReaderSurvivesBadLines(unittest.TestCase):
    """Finding 16: one sentence with a valid checksum and a field that is not a number ended the reader thread."""

    def test_reader_keeps_running(self):
        from kyber6g.telemetry.gnss import GnssState, GpsdReader

        def nmea(body):
            x = 0
            for ch in body:
                x ^= ord(ch)
            return f"${body}*{x:02X}\r\n".encode()
        lines = [nmea("GPGSV,1,1,01,05,45,1.2.3,40"),                       # azimuth "1.2.3": float() raises
                 b"[1, 2, 3]\n", b'"text"\n', b'{"class":"TPV","mode":null}\n',  # JSON of unexpected shape
                 b"x" * 70000,                                              # 70 kB without a line end
                 b"\n" + nmea("GPGSV,1,1,01,07,50,180,41"),
                 b'{"class":"TPV","mode":3,"lat":12.5,"lon":79.5,"altMSL":90.0}\n']
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        self.addCleanup(srv.close)

        def serve():
            c, _ = srv.accept()
            c.recv(200)
            for l in lines:
                c.sendall(l)
                time.sleep(0.05)
            time.sleep(1.0)
            c.close()
        threading.Thread(target=serve, daemon=True).start()
        st = GnssState()
        r = GpsdReader(st, "127.0.0.1", srv.getsockname()[1])
        r.start()
        self.addCleanup(setattr, r, "running", False)
        self.assertTrue(wait(lambda: st.snapshot()["mode"] == 3, 5), st.snapshot())
        s = st.snapshot(with_sats=True)
        self.assertTrue(r.is_alive())
        self.assertEqual((s["lat"], s["lon"], s["alt_m"]), (12.5, 79.5, 90.0))
        self.assertGreaterEqual(s["gnss_parse_errors"], 2)                  # the bad sentence and the null mode
        self.assertEqual([x[1] for x in s["satellites"]], [7])              # the good sentence after the bad ones arrived


class TestCameraSettingsFromTheGroundStation(unittest.TestCase):
    """Video settings arrive in a command: values outside what the sensor and the encoder can do, or of the wrong
    type, are refused, and settings the encoder cannot start with are put back."""

    def camera(self, fail_on=None):
        from kyber6g.camera.camera import CameraService
        from kyber6g.config import CameraConfig
        cam = CameraService.__new__(CameraService)
        cam.cfg, cam.lock, cam.recorder, cam.encoding, cam.live = CameraConfig(), threading.RLock(), None, True, True
        cam.motion_set = {"enabled": True, "sentry": False, "hz": 8.0}
        cam.started = []

        def ensure():
            if fail_on and (cam.cfg.width, cam.cfg.height) == fail_on and cam.live:
                raise RuntimeError("encoder refused the configuration")
            cam.started.append((cam.cfg.width, cam.cfg.height, cam.cfg.fps, cam.cfg.bitrate, cam.live))
        cam._ensure_encoder = ensure
        return cam

    def test_values_are_checked(self):
        cam = self.camera()
        for bad in ({"width": 100000}, {"width": 641, "height": 480}, {"fps": 1000}, {"bitrate": 10}, {"width": "1280"},
                    {"height": [720]}, {"fps": 29.5}, {"bitrate": True}, {"width": -640}, {"height": 100}):
            with self.assertRaises(ValueError, msg=bad):
                cam.set_video(**bad)
        self.assertEqual((cam.cfg.width, cam.cfg.height, cam.cfg.fps, cam.cfg.bitrate), (1280, 720, 30, 3_000_000))
        self.assertEqual(cam.started, [])                                   # nothing was restarted for a refused request
        cam.set_video(640, 480, 30.0, 1_500_000)
        self.assertEqual((cam.cfg.width, cam.cfg.height, cam.cfg.fps, cam.cfg.bitrate), (640, 480, 30, 1_500_000))
        cam.set_video(None, None, 15, 0)                                    # None / 0: keep what is set
        self.assertEqual((cam.cfg.width, cam.cfg.fps, cam.cfg.bitrate), (640, 15, 1_500_000))

    # What the camera of the Pi reported in the two modes (6 October 2026): the colour matrix and the colour gains.
    DAY_REPORT = {"ColourCorrectionMatrix": (1.85, -0.47, -0.39, -0.42, 1.74, -0.32, -0.08, -0.71, 1.79), "ColourGains": (1.14, 1.19)}
    NIGHT_REPORT = {"ColourCorrectionMatrix": (0.30, 0.75, -0.05) * 3, "ColourGains": (1.0, 1.0)}

    def running_camera(self, starts=1):
        """A camera that is streaming and has been started `starts` times, with a stand-in for picamera2 that notes
        every request for controls; restarts are noted instead of made."""
        cam = self.camera()
        cam.asked, cam.restarts = [], []
        cam.picam2 = type("P", (), {"set_controls": lambda _, c: cam.asked.append(c)})()
        cam._mode_controls = lambda: {"mode": cam.mode}                     # the real controls need libcamera
        cam._restart_camera = lambda: cam.restarts.append(cam.mode)
        cam.mode, cam.stats, cam._starts, cam._mode_asked, cam._mode_tries = "NORMAL", {"mode_arrived": True}, starts, 0.0, 0
        return cam

    def test_whether_the_cameras_report_shows_the_mode(self):
        from kyber6g.camera.camera import CameraService
        arrived = CameraService.mode_arrived
        self.assertIs(arrived("NORMAL", self.DAY_REPORT), True)
        self.assertIs(arrived("NIGHT", self.NIGHT_REPORT), True)
        # the fault that was seen: DAY asked for, the exposure followed, and the picture stayed grey
        self.assertIs(arrived("NORMAL", self.NIGHT_REPORT), False)
        self.assertIs(arrived("NIGHT", self.DAY_REPORT), False)
        # and its other face: colour again, but the white balance still held at 1 (a colour cast)
        self.assertIs(arrived("NORMAL", dict(self.DAY_REPORT, ColourGains=(1.0, 1.0))), False)
        self.assertIs(arrived("NIGHT", dict(self.NIGHT_REPORT, ColourGains=(1.14, 1.19))), False)
        for nothing in ({}, {"ColourGains": (1.0, 1.0)}, {"ColourCorrectionMatrix": (1.0, 0.0), "ColourGains": (1.0, 1.0)}):
            self.assertIsNone(arrived("NORMAL", nothing))

    def test_how_a_running_camera_is_put_into_a_mode(self):
        # started once since the program began: a request for the controls is enough, the stream goes on
        cam = self.running_camera(starts=1)
        cam.set_mode("NIGHT")
        self.assertEqual((cam.asked, cam.restarts, cam.stats["mode_arrived"]), ([{"mode": "NIGHT"}], [], None))
        # restarted before (new video settings, a photo while idle): such a request arrives only in part, so the
        # camera is started again with the mode among its start controls
        cam = self.running_camera(starts=2)
        cam.set_mode("NIGHT")
        cam.set_mode("NORMAL")
        self.assertEqual((cam.asked, cam.restarts), ([], ["NIGHT", "NORMAL"]))
        # not running although it should be (the fixture's camera is live): the mode is kept and the camera started,
        # in that mode; a camera that nobody needs is left alone by the same call
        cam = self.running_camera(starts=2)
        cam.encoding = False
        cam.set_mode("NIGHT")
        self.assertEqual((cam.mode, cam.asked, cam.restarts, len(cam.started)), ("NIGHT", [], [], 1))
        with self.assertRaises(ValueError):
            cam.set_mode("DUSK")

    def test_a_mode_that_did_not_arrive_restarts_the_camera(self):
        cam = self.running_camera(starts=1)
        cam.set_mode("NORMAL")
        cam._check_mode(self.NIGHT_REPORT)                                  # too soon after the request: no verdict yet
        self.assertEqual((cam.stats["mode_arrived"], cam.restarts), (None, []))
        for n in range(1, cam.MODE_RETRIES + 3):
            cam._mode_asked = 0.0                                           # as if MODE_SETTLE had passed
            cam._check_mode(self.NIGHT_REPORT)                              # the picture is still grey
            self.assertIs(cam.stats["mode_arrived"], False)
            self.assertEqual(len(cam.restarts), min(n, cam.MODE_RETRIES))   # then it gives up, and keeps saying so
        cam._mode_asked = 0.0
        cam._check_mode(self.DAY_REPORT)
        self.assertIs(cam.stats["mode_arrived"], True)
        cam._mode_asked = 0.0
        cam._check_mode({})                                                 # a report that does not say: nothing changes
        self.assertEqual((cam.stats["mode_arrived"], len(cam.restarts)), (True, cam.MODE_RETRIES))
        cam.set_mode("NIGHT")                                               # a new switch starts the count again
        self.assertEqual(cam._mode_tries, 0)
        cam._mode_asked = 0.0
        cam.encoding = False                                                # stopped meanwhile: nothing to restart
        cam._check_mode(self.DAY_REPORT)
        self.assertEqual(len(cam.restarts), cam.MODE_RETRIES)

    def test_a_photo_with_the_stream_stopped_takes_the_streams_white_balance(self):
        # Measured: 1.2 s after its start the automatic white balance of the still mode is not right yet (blue photos)
        cam = self.running_camera()
        cam._white = None
        self.assertEqual(cam._still_controls(), {"mode": "NORMAL"})         # nothing to go by: the automatic one, waited for
        cam._mode_asked = 0.0
        cam._check_mode(self.DAY_REPORT)                                    # the stream runs in NORMAL and says so
        self.assertEqual(cam._white[1], (1.14, 1.19))
        self.assertEqual(cam._still_controls(), {"mode": "NORMAL", "AwbEnable": False, "ColourGains": (1.14, 1.19)})
        cam.mode = "NIGHT"
        cam._mode_asked = 0.0
        cam._check_mode(self.NIGHT_REPORT)                                  # NIGHT has fixed gains: not a white balance to keep
        self.assertEqual(cam._white[1], (1.14, 1.19))
        self.assertEqual(cam._still_controls(), {"mode": "NIGHT"})
        cam.mode = "NORMAL"
        cam._white = (time.monotonic() - cam.WHITE_KEEPS_S - 1, (1.14, 1.19))   # too long ago: the light may have changed
        self.assertEqual(cam._still_controls(), {"mode": "NORMAL"})

    def test_settings_the_encoder_refuses_are_rolled_back(self):
        cam = self.camera(fail_on=(1920, 1080))
        with self.assertRaises(RuntimeError):
            cam.set_video(1920, 1080, 30, 6_000_000)
        self.assertEqual((cam.cfg.width, cam.cfg.height, cam.cfg.bitrate, cam.live), (1280, 720, 3_000_000, True))
        self.assertEqual(cam.started[-1], (1280, 720, 30, 3_000_000, True))  # streaming again with the old settings
        cam.recorder = object()
        with self.assertRaises(RuntimeError):                               # and never while a recording runs
            cam.set_video(640, 480)

    def test_sentry_does_not_keep_the_old_settings_alive(self):
        """The motion watch's sentry keeps the encoder running without a viewer. New video settings must still stop
        and start it (it would otherwise go on with the old ones), and sentry must be on again afterwards."""
        cam = self.camera()
        cam.live, cam.motion_set["sentry"] = False, True
        seen = []
        cam._ensure_encoder = lambda: seen.append((cam.cfg.width, cam.live, cam.motion_set["sentry"]))
        cam.set_video(640, 480)
        self.assertEqual(seen, [(640, False, False), (640, False, True)])    # stopped with nothing that needs it, then as before
        self.assertTrue(cam.motion_set["sentry"])


class TestVideoSinkInput(unittest.TestCase):
    def test_short_frames_and_many_unfinished_frames(self):
        from kyber6g.ground.video_sink import VIDEO_EXT, VideoSink
        v = VideoSink(ffmpeg="/nonexistent")
        self.addCleanup(setattr, v, "running", False)
        v.on_chunk(VIDEO_EXT.pack(1, 0, 1, 1), b"abc")                      # a "frame" too short for its time stamp
        v.on_chunk(VIDEO_EXT.pack(2, 0, 1, 0), b"")
        self.assertEqual(v.s["malformed_frames"], 2)
        for fid in range(10, 2000):                                         # frames that never complete
            v.on_chunk(VIDEO_EXT.pack(fid, 0, 5, 0), b"x" * 100)
        self.assertLessEqual(len(v.pending), VideoSink.MAX_PENDING)
        for junk in (b"", b"x" * 3, VIDEO_EXT.pack(5, 9, 2, 0), VIDEO_EXT.pack(5, 0, 0, 0), VIDEO_EXT.pack(5, 0, 5000, 0)):
            v.on_chunk(junk, b"data")


# ==================================================== measurement hooks
class TestMeasurementHooks(unittest.TestCase):
    """What the benchmark tools rely on: a session operation carried out on request and timed on the UAV's own clock,
    the UAV's log of every such operation, and the round-trip probe."""

    def test_operations_on_request_are_timed_and_logged(self):
        d = Path(tempfile.mkdtemp())
        upk, gpk = idm.generate_identity(d, "uav"), idm.generate_identity(d, "gcs")
        cfg = LinkConfig(gcs_host="127.0.0.1", gcs_port=0, heartbeat_s=0.3, link_timeout_s=5,
                         cached_rekey_interval_s=0, pq_ratchet_interval_s=0)
        gcs = GcsLink(cfg, idm.load_identity(d, "gcs", GCS_ID), {UAV_ID: upk}, bind=("127.0.0.1", 0))
        uav = UavLink(LinkConfig(**{**cfg.__dict__, "gcs_port": gcs.sock.getsockname()[1]}), idm.load_identity(d, "uav", UAV_ID), gpk,
                      lambda: b"\x00" * 8)
        got = []
        gcs.on_message = lambda st, ext, pt, meta: got.append(pt)
        self.assertEqual(uav.rekey_now("full")["ok"], False)                 # not while the link is down
        gcs.start(); uav.start()
        self.addCleanup(lambda: (uav.stop(), gcs.stop()))
        self.assertTrue(wait(lambda: uav.state == "UP" and gcs.link_up(), 10))
        sids = {uav.session.session_id}
        for kind, call in (("full", lambda: uav.rekey_now("full", "t1")), ("cached", lambda: uav.rekey_now("cached", "t1")),
                           ("ratchet", lambda: uav.pq_ratchet_now("t1"))):
            r = call()
            self.assertTrue(r["ok"], (kind, r))
            self.assertTrue(0 < r["ms"] < 5000, r)
            self.assertEqual(r["session"], uav.session.session_id.hex())
            sids.add(uav.session.session_id)
            uav.send(ks.STREAM_TELEMETRY, kind.encode())                     # traffic continues under each new session
            self.assertTrue(wait(lambda: kind.encode() in got, 5), kind)
            self.assertEqual(uav.state, "UP")
        self.assertEqual(len(sids), 4)                                       # a new session every time
        log = list(uav.oplog)
        self.assertEqual([(e["kind"], e["tag"], e["ok"]) for e in log],
                         [("full", "auto", True), ("full", "t1", True), ("cached", "t1", True), ("ratchet", "t1", True)])
        full = log[1]
        self.assertEqual(full["hello_sent"], 1)
        # building and waiting lie inside the total; what is left is installing the session and sending Finished. That
        # rest is under a millisecond on an idle machine and was 10 ms when this suite ran beside the detector and
        # the finder (it then failed a check that allowed 20 % of the total): only its sign and a wide bound are fixed
        rest = full["ms"] - full["build_ms"] - full["wait_ms"]
        self.assertTrue(-0.05 <= rest < 500, full)
        self.assertLessEqual(full["process_ms"], full["wait_ms"])            # verifying the answer happens while waiting
        self.assertEqual([e["n"] for e in log], [1, 2, 3, 4])
        self.assertIsNotNone(gcs.stats["last_cached_rekey_ms"])
        r = uav.rtt_probe(n=30, interval=0.005)
        self.assertEqual((r["sent"], r["lost"], len(r["rtt_ms"])), (30, 0, 30))
        self.assertTrue(all(0 < x < 1000 for x in r["rtt_ms"]), r["rtt_ms"])
        self.assertEqual(uav.session.session_id, gcs.sessions[gcs.active].session.session_id)


# ==================================================================== fuzz
class TestFuzzTheLink(unittest.TestCase):
    """Random and mutated datagrams, and random authenticated control messages, against a running pair of links.
    Whatever arrives, the receive threads must count it and carry on: an unexpected exception shows up in the
    "internal" counter, which has to stay absent, and the link must still pass traffic afterwards."""

    @classmethod
    def setUpClass(cls):
        d = Path(tempfile.mkdtemp())
        cls.upk, cls.gpk = idm.generate_identity(d, "uav"), idm.generate_identity(d, "gcs")
        cls.uav_id, cls.gcs_id = idm.load_identity(d, "uav", UAV_ID), idm.load_identity(d, "gcs", GCS_ID)

    def pair(self):
        cfg = LinkConfig(gcs_host="127.0.0.1", gcs_port=0, heartbeat_s=0.3, link_timeout_s=30,
                         cached_rekey_interval_s=0, pq_ratchet_interval_s=0)
        gcs = GcsLink(cfg, self.gcs_id, {UAV_ID: self.upk}, bind=("127.0.0.1", 0))
        proxy = LossyProxy(gcs.sock.getsockname()[1])
        uav = UavLink(LinkConfig(**{**cfg.__dict__, "gcs_port": proxy.port}), self.uav_id, self.gpk, lambda: b"\x00" * 8)
        got, uctl, gctl = [], [], []
        gcs.on_message = lambda st, ext, pt, meta: got.append(pt)
        uav.on_control, gcs.on_control = uctl.append, gctl.append
        gcs.start(); uav.start()
        self.addCleanup(lambda: (uav.stop(), gcs.stop(), setattr(proxy, "running", False)))
        self.assertTrue(wait(lambda: uav.state == "UP" and gcs.link_up(), 10))
        return uav, gcs, proxy, got, uctl, gctl

    def datagrams(self, rng, sid, captured):
        for _ in range(4000):
            kind = rng.randrange(8)
            if kind == 0:
                yield rng.randbytes(rng.choice((0, 1, 2, 7, 8, 23, 24, 39, 40, 41, 200, 1500)))
            elif kind == 1:                                                  # a record header for the live session, junk body
                yield HDR.pack(rng.randrange(256), 0x10, rng.randrange(256), rng.choice((0, 0, 7, 9, 255)),
                               sid, rng.choice((0, 1, 8, 9, 2**32 - 1)), rng.getrandbits(64)) + rng.randbytes(rng.randrange(0, 300))
            elif kind == 2:                                                  # handshake framing with every message type
                yield framing.HS_HDR.pack(rng.randrange(256), rng.choice((1, 2, 3, 5, 6, 7, 8, 9, 0, 255)), rng.randbytes(4),
                                          rng.randrange(20), rng.randrange(20)) + rng.randbytes(rng.choice((0, 5, 40, 90, 1180, 1300)))
            elif kind == 3:                                                  # complete one-fragment handshake messages
                size = rng.choice((0, 1, 17, 40, 72, 80, 100, 1700, 1180))
                yield framing.HS_HDR.pack(1, rng.choice((1, 2, 3, 5, 6, 7, 8)), rng.randbytes(4), 0, 1) + rng.randbytes(size)
            elif captured:                                                   # a genuine datagram with a few bits changed, or cut
                p = bytearray(rng.choice(captured))
                for _ in range(rng.choice((0, 1, 1, 3))):
                    p[rng.randrange(len(p))] ^= 1 << rng.randrange(8)
                yield bytes(p[:rng.choice((len(p), len(p), rng.randrange(1, len(p) + 1)))])

    def test_random_and_mutated_datagrams(self):
        uav, gcs, proxy, got, uctl, gctl = self.pair()
        for i in range(30):
            uav.send(ks.STREAM_TELEMETRY, b"t%d" % i)
        self.assertTrue(wait(lambda: len(got) == 30))
        rng = random.Random(20261004)
        sid = uav.session.session_id
        captured = list(proxy.capture)
        raw = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.addCleanup(raw.close)
        uav_addr, gcs_addr = uav.sock.getsockname(), gcs.sock.getsockname()
        n = 0
        for pkt in self.datagrams(rng, sid, captured):
            raw.sendto(pkt, ("127.0.0.1", gcs_addr[1]))                      # to the ground station from a stranger
            proxy.sock.sendto(pkt, ("127.0.0.1", uav_addr[1]))               # to the UAV from "the ground station's address"
            n += 1
            if n % 200 == 0:
                time.sleep(0.02)
        time.sleep(0.5)
        self.assertNotIn("internal", gcs.stats["drops"], gcs.stats["last_error"])
        self.assertNotIn("internal", uav.stats["drops"], uav.stats["last_error"])
        self.assertGreater(sum(gcs.stats["drops"].values()), 1000)           # it did arrive and was counted
        self.assertEqual(len(got), 30)                                       # nothing forged was delivered
        self.assertEqual(uav.session.session_id, sid)                        # and the session was not disturbed
        uav.send(ks.STREAM_TELEMETRY, b"after-fuzz")
        self.assertTrue(wait(lambda: b"after-fuzz" in got))
        gcs.send_control({"t": "capture_image", "id": 1})
        self.assertTrue(wait(lambda: any(m.get("t") == "capture_image" for m in uctl)))

    def values(self, rng, depth=0):
        r = rng.randrange(13)
        if r < 3:
            return rng.choice((0, 1, -1, 2**31, 2**70, 1.5, -0.0, 1e308))
        if r < 5:
            return rng.choice(("", "x", "AA==", "00" * 8, "zz", "x" * 5000, "\u0000", "../../etc"))
        if r < 7:
            return rng.choice((None, True, False))
        if r < 9 and depth < 3:
            return [self.values(rng, depth + 1) for _ in range(rng.randrange(4))]
        if r < 11 and depth < 3:
            return {rng.choice(("t", "id", "rid", "x", "a")): self.values(rng, depth + 1) for _ in range(rng.randrange(4))}
        return rng.choice((0, "abc", None))

    def test_random_authenticated_control_messages(self):
        """What a faulty or taken-over peer could send inside the session: every link-level message type with fields
        of every JSON type."""
        uav, gcs, proxy, got, uctl, gctl = self.pair()
        rng = random.Random(77)
        types = ["ping", "pong", "hb", "hb_ack", "welcome", "ratchet_req", "ratchet_resp", "blob_nack", "blob_done", "ack",
                 "status", 5, None, "", "x" * 300]
        keys = ["t1", "t2", "t3", "rid", "x", "ek", "ct", "sid", "id", "missing", "meta", "cmd", "ok", "name"]
        sender = blob.BlobSender(lambda *a: True)
        for i in range(1500):
            msg = {"t": rng.choice(types), **{k: self.values(rng) for k in rng.sample(keys, rng.randrange(0, 6))}}
            try:
                (uav if rng.random() < 0.5 else gcs).send_control(msg)
            except ValueError:                                               # longer than a control message may be: not sent
                continue
            sender.on_control(jsonmsg.tame(msg))                             # the transfer layer sees every control message too
            if i % 100 == 0:
                time.sleep(0.02)
        # raw records on the control stream that are not JSON at all, and split messages with pieces missing
        s = uav.session
        for junk in (b"", b"{", b"[1]", b"null", b"\xff" * 50, b'{"t":"pong","t1":NaN}', b'{"t":' + b"[" * 3000):
            uav._send_raw(s.seal(ks.STREAM_CONTROL, junk), uav.gcs_addr)
            uav._send_raw(s.seal(ks.STREAM_CONTROL, junk, b"F" + os.urandom(4) + bytes([0, 2])), uav.gcs_addr)
            uav._send_raw(s.seal(ks.STREAM_CONTROL, junk, os.urandom(rng.randrange(1, 12))), uav.gcs_addr)
        time.sleep(1.0)
        self.assertNotIn("internal", gcs.stats["drops"], gcs.stats["last_error"])
        self.assertNotIn("internal", uav.stats["drops"], uav.stats["last_error"])
        self.assertTrue(wait(lambda: uav.state == "UP" and gcs.link_up(), 5))
        uav.send(ks.STREAM_TELEMETRY, b"after-fuzz")
        self.assertTrue(wait(lambda: b"after-fuzz" in got))
        self.assertTrue(uav.request_pq_ratchet() or wait(uav.request_pq_ratchet, 5))     # the real thing still works
        self.assertTrue(wait(lambda: uav.stats["pq_ratchets"] >= 1, 6))

    def test_record_and_handshake_parsers_alone(self):
        rng = random.Random(5)
        tx, rx = session_pair()
        good = tx.seal(ks.STREAM_VIDEO, b"payload", b"ext-data")
        for _ in range(3000):
            p = bytearray(good)
            for _ in range(rng.choice((1, 1, 2, 5))):
                p[rng.randrange(len(p))] ^= 1 << rng.randrange(8)
            p = bytes(p[:rng.choice((len(p), len(p), rng.randrange(len(p) + 1)))])
            if p == good:
                continue
            with self.assertRaises(RecordError):                             # every change is refused, with a reason
                rx.open(p)
        self.assertEqual(rx.open(good)[2], b"payload")                       # and the genuine record is still new
        for _ in range(2000):
            junk = rng.randbytes(rng.randrange(0, 80))
            try:
                parse_header(junk)
            except RecordError:
                pass
        uav, gcs, upk, gpk = make_ids()
        server = hs.ServerHandshake(gcs, {UAV_ID: upk})
        ch = hs.ClientHandshake(uav, gpk, 1, b"\x00" * 8).client_hello()
        for n in list(range(0, 80)) + [1657, 1658, 1659, 1660, len(ch) - 1]:
            with self.assertRaises(hs.HandshakeError):
                server.process_client_hello(ch[:n])
        for _ in range(60):
            p = bytearray(ch)
            p[rng.randrange(len(p))] ^= 1 << rng.randrange(8)
            with self.assertRaises(hs.HandshakeError):
                server.process_client_hello(bytes(p))
        sh = server.process_client_hello(ch)                                 # the untouched hello is still accepted
        sid = sh[2:10]                                                       # the session id the server just issued
        self.assertIn(sid, server.pending)
        for body in (b"", os.urandom(40), os.urandom(41), sh[:40], sid + b"\x00" * 32):
            with self.assertRaises(hs.HandshakeError):
                server.process_client_finished(body)
        self.assertIn(sid, server.pending)                                   # a wrong Finished does not use the session up
        cache = hs.RekeyCache(300)
        for n in (0, 1, 95, 96, 97, 200):
            try:
                hs.server_process_rekey(cache, server, os.urandom(n))
            except hs.HandshakeError:
                pass


if __name__ == "__main__":
    unittest.main()
