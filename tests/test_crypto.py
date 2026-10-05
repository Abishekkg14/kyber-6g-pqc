import os
import struct
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

import oqs
from cryptography.hazmat.primitives.asymmetric import x25519

from kyber6g.crypto import handshake as hs
from kyber6g.crypto import identity as idm
from kyber6g.crypto import keyschedule as ks
from kyber6g.crypto.record import RecordError, Session, nonce_for
from kyber6g.crypto.replay import ACCEPT, DUPLICATE, STALE, ReplayWindow

CFG = SimpleNamespace(rotate_seconds=3600, rotate_packets=1 << 30, epoch_grace_seconds=2.0, replay_window=2048)
UAV_ID = b"UAV-ALPH"
GCS_ID = b"GCS-MEC1"


def make_ids():
    d = Path(tempfile.mkdtemp())
    upk = idm.generate_identity(d, "uav")
    gpk = idm.generate_identity(d, "gcs")
    return (idm.load_identity(d, "uav", UAV_ID), idm.load_identity(d, "gcs", GCS_ID), upk, gpk)


def full_handshake(uav, gcs, gpk, upk, suite=1, mobility=b"\x00" * 8):
    server = hs.ServerHandshake(gcs, {UAV_ID: upk})
    client = hs.ClientHandshake(uav, gpk, suite, mobility)
    sh = server.process_client_hello(client.client_hello())
    c_secrets, cf = client.process_server_hello(sh)
    s_secrets, uav_id, mob, suite_obj = server.process_client_finished(cf)
    return server, c_secrets, s_secrets


class TestPrimitives(unittest.TestCase):
    def test_hkdf_rfc5869_case1(self):
        ikm = bytes.fromhex("0b" * 22)
        salt = bytes.fromhex("000102030405060708090a0b0c")
        info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
        prk = ks.hkdf_extract(salt, ikm)
        self.assertEqual(prk.hex(), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        okm = ks.hkdf_expand(prk, info, 42)
        self.assertEqual(okm.hex(), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")

    def test_mlkem_roundtrip(self):
        for alg in ("ML-KEM-768", "ML-KEM-1024"):
            k = oqs.KeyEncapsulation(alg)
            ek = k.generate_keypair()
            ct, ss = oqs.KeyEncapsulation(alg).encap_secret(ek)
            self.assertEqual(k.decap_secret(ct), ss)
            bad = bytearray(ct); bad[0] ^= 1
            self.assertNotEqual(k.decap_secret(bytes(bad)), ss)  # implicit rejection

    def test_x25519(self):
        a, b = x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate()
        self.assertEqual(a.exchange(b.public_key()), b.exchange(a.public_key()))

    def test_mldsa(self):
        s = oqs.Signature("ML-DSA-87")
        pk = s.generate_keypair()
        sig = s.sign(b"msg")
        self.assertTrue(idm.verify("ML-DSA-87", b"msg", sig, pk))
        self.assertFalse(idm.verify("ML-DSA-87", b"msh", sig, pk))

    def test_label_separation(self):
        sid = os.urandom(8)
        prk = os.urandom(32)
        a = ks.hkdf_expand(prk, ks.label("telemetry/uav-to-gcs/chain", 1, sid))
        b = ks.hkdf_expand(prk, ks.label("video/uav-to-gcs/chain", 1, sid))
        c = ks.hkdf_expand(prk, ks.label("telemetry/uav-to-gcs/chain", 2, sid))
        self.assertEqual(len({a, b, c}), 3)


class TestReplay(unittest.TestCase):
    def test_window(self):
        w = ReplayWindow(64)
        for s in (5, 3, 4):
            self.assertEqual(w.check(s), ACCEPT); w.commit(s)
        self.assertEqual(w.check(4), DUPLICATE)
        w.commit(200)
        self.assertEqual(w.check(100), STALE)
        self.assertEqual(w.check(150), ACCEPT)


class TestRecordLayer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.uav, cls.gcs, cls.upk, cls.gpk = make_ids()

    def sessions(self, cfg=CFG):
        _, c, s = full_handshake(self.uav, self.gcs, self.gpk, self.upk)
        return Session(c, hs.get_suite(1), "uav", cfg), Session(s, hs.get_suite(1), "gcs", cfg)

    def test_roundtrip_all_streams(self):
        u, g = self.sessions()
        for stream in ks.STREAM_NAMES:
            pkt = u.seal(stream, b"payload-%d" % stream, ext=b"EXT")
            st, ext, pt, *_ = g.open(pkt)
            self.assertEqual((st, ext, pt), (stream, b"EXT", b"payload-%d" % stream))
            back = g.seal(stream, b"down")
            self.assertEqual(u.open(back)[2], b"down")

    def test_tamper_header_payload_tag(self):
        u, g = self.sessions()
        pkt = u.seal(ks.STREAM_TELEMETRY, b"x" * 50, ext=b"meta")
        for pos in (2, 13, 20, 25, 40, len(pkt) - 1):
            bad = bytearray(pkt); bad[pos] ^= 0x01
            with self.assertRaises(RecordError):
                g.open(bytes(bad))
        self.assertEqual(g.open(pkt)[2], b"x" * 50)  # original still accepted

    def test_replay_and_reorder(self):
        u, g = self.sessions()
        pkts = [u.seal(ks.STREAM_VIDEO, b"%d" % i) for i in range(10)]
        for p in reversed(pkts):
            g.open(p)  # reordered delivery is accepted
        with self.assertRaises(RecordError) as cm:
            g.open(pkts[3])
        self.assertEqual(cm.exception.reason, "duplicate")

    def test_wrong_session_and_key(self):
        u, g = self.sessions()
        u2, g2 = self.sessions()
        pkt = u.seal(ks.STREAM_CONTROL, b"hi")
        with self.assertRaises(RecordError) as cm:
            g2.open(pkt)
        self.assertEqual(cm.exception.reason, "wrong-session")
        forged = pkt[:4] + g2.session_id + pkt[12:]
        with self.assertRaises(RecordError) as cm:
            g2.open(forged)
        self.assertEqual(cm.exception.reason, "auth-fail")

    def test_malformed(self):
        u, g = self.sessions()
        for junk in (b"", b"\x01", os.urandom(30), b"\x01\x10\x02\xff" + os.urandom(40)):
            with self.assertRaises(RecordError):
                g.open(junk)

    def test_epoch_rotation_and_nonce_uniqueness(self):
        cfg = SimpleNamespace(rotate_seconds=3600, rotate_packets=5, epoch_grace_seconds=0.2, replay_window=2048)
        u, g = self.sessions(cfg)
        pkts = [u.seal(ks.STREAM_VIDEO, b"%d" % i) for i in range(23)]
        seen = set()
        for p in pkts:
            _, _, _, epoch, seq = g.open(p)
            self.assertNotIn((epoch, seq), seen)
            seen.add((epoch, seq))
        self.assertEqual(u.tx[ks.STREAM_VIDEO].epoch, 4)
        self.assertEqual(len({s for _, s in seen}), 23)  # seq never repeats across epochs

    def test_old_epoch_retired_after_grace(self):
        cfg = SimpleNamespace(rotate_seconds=3600, rotate_packets=2, epoch_grace_seconds=0.1, replay_window=2048)
        u, g = self.sessions(cfg)
        p = [u.seal(ks.STREAM_VIDEO, b"%d" % i) for i in range(6)]
        late = p[0]
        for x in p[1:]:
            g.open(x)
        time.sleep(0.15)
        g.open(u.seal(ks.STREAM_VIDEO, b"trigger-expiry"))
        with self.assertRaises(RecordError) as cm:
            g.open(late)
        self.assertEqual(cm.exception.reason, "stale-epoch")

    def test_forged_far_epoch_rejected(self):
        u, g = self.sessions()
        pkt = bytearray(u.seal(ks.STREAM_VIDEO, b"a"))
        struct.pack_into("!I", pkt, 12, 1000)
        with self.assertRaises(RecordError) as cm:
            g.open(bytes(pkt))
        self.assertEqual(cm.exception.reason, "stale-epoch")
        self.assertLessEqual(g.rx[ks.STREAM_VIDEO].chain.epoch, 8)

    def test_nonce_format(self):
        self.assertEqual(nonce_for(1), b"\x00" * 11 + b"\x01")
        self.assertEqual(len(nonce_for(2**63)), 12)


class TestHandshake(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.uav, cls.gcs, cls.upk, cls.gpk = make_ids()

    def test_full_handshake_agrees(self):
        _, c, s = full_handshake(self.uav, self.gcs, self.gpk, self.upk)
        self.assertEqual(bytes(c.master), bytes(s.master))
        self.assertEqual(c.session_id, s.session_id)

    def test_chacha_suite(self):
        _, c, s = full_handshake(self.uav, self.gcs, self.gpk, self.upk, suite=2)
        self.assertEqual(bytes(c.master), bytes(s.master))

    def test_wrong_pinned_gcs_key(self):
        server = hs.ServerHandshake(self.gcs, {UAV_ID: self.upk})
        other_pk = oqs.Signature("ML-DSA-87").generate_keypair()
        client = hs.ClientHandshake(self.uav, other_pk, 1, b"\x00" * 8)
        sh = server.process_client_hello(client.client_hello())
        with self.assertRaises(hs.HandshakeError):
            client.process_server_hello(sh)

    def test_unknown_or_forged_uav(self):
        other = oqs.Signature("ML-DSA-87").generate_keypair()
        server = hs.ServerHandshake(self.gcs, {UAV_ID: other})
        client = hs.ClientHandshake(self.uav, self.gpk, 1, b"\x00" * 8)
        with self.assertRaises(hs.HandshakeError):
            server.process_client_hello(client.client_hello())

    def test_replayed_client_hello(self):
        server = hs.ServerHandshake(self.gcs, {UAV_ID: self.upk})
        ch = hs.ClientHandshake(self.uav, self.gpk, 1, b"\x00" * 8).client_hello()
        server.process_client_hello(ch)
        with self.assertRaises(hs.HandshakeError):
            server.process_client_hello(ch)

    def test_tampered_server_hello(self):
        server = hs.ServerHandshake(self.gcs, {UAV_ID: self.upk})
        client = hs.ClientHandshake(self.uav, self.gpk, 1, b"\x00" * 8)
        sh = bytearray(server.process_client_hello(client.client_hello()))
        sh[60] ^= 1  # inside the X25519 public key
        with self.assertRaises(hs.HandshakeError):
            client.process_server_hello(bytes(sh))

    def test_bad_client_finished(self):
        server = hs.ServerHandshake(self.gcs, {UAV_ID: self.upk})
        client = hs.ClientHandshake(self.uav, self.gpk, 1, b"\x00" * 8)
        _, cf = client.process_server_hello(server.process_client_hello(client.client_hello()))
        bad = bytearray(cf); bad[-1] ^= 1
        with self.assertRaises(hs.HandshakeError):
            server.process_client_finished(bytes(bad))

    def _cached(self, mobility_req=b"\x00" * 8):
        server, c, s = full_handshake(self.uav, self.gcs, self.gpk, self.upk)
        cache = hs.RekeyCache(ttl_s=300)
        cache.put(UAV_ID, s, b"\x00" * 8, 1)
        req = hs.build_rekey_request(UAV_ID, c, mobility_req)
        return server, cache, c, req

    def test_cached_rekey_ok_and_one_way(self):
        server, cache, c, req = self._cached()
        mtype, body, new_s, _ = hs.server_process_rekey(cache, server, req)
        self.assertEqual(mtype, hs.MSG_REKEY_RESP)
        new_c, cf = hs.client_process_rekey_resp(req, c, body)
        s2, *_ = server.process_client_finished(cf)
        self.assertEqual(bytes(new_c.master), bytes(s2.master))
        self.assertNotEqual(bytes(new_c.master), bytes(c.master))
        self.assertNotIn(UAV_ID, cache.entries)  # old resumption secret deleted

    def test_cached_rekey_stale_mobility(self):
        server, cache, c, req = self._cached(mobility_req=b"\x11" * 8)
        mtype, body, _, _ = hs.server_process_rekey(cache, server, req)
        self.assertEqual((mtype, body[-1]), (hs.MSG_REKEY_REJECT, hs.REJECT_STALE_MOBILITY))

    def test_cached_rekey_forged_mac_does_not_change_state(self):
        server, cache, c, req = self._cached()
        bad = req[:-1] + bytes([req[-1] ^ 1])
        mtype, body, _, _ = hs.server_process_rekey(cache, server, bad)
        self.assertEqual((mtype, body[-1]), (hs.MSG_REKEY_REJECT, hs.REJECT_AUTH))
        self.assertIn(UAV_ID, cache.entries)

    def test_cached_rekey_replay(self):
        server, cache, c, req = self._cached()
        hs.server_process_rekey(cache, server, req)
        mtype, body, _, _ = hs.server_process_rekey(cache, server, req)
        self.assertEqual(mtype, hs.MSG_REKEY_REJECT)

    def test_pq_ratchet(self):
        _, c, s = full_handshake(self.uav, self.gcs, self.gpk, self.upk)
        init = hs.PQRatchetInitiator(1, rid=7)
        x_s, ct, sid, new_s = hs.pq_ratchet_respond(s, 7, init.x_pub, init.ek)
        new_c = init.finish(c, x_s, ct, sid)
        self.assertEqual(bytes(new_c.master), bytes(new_s.master))
        self.assertNotEqual(bytes(new_c.master), bytes(c.master))

    def test_mobility_cell(self):
        a = hs.mobility_cell(12.97161, 79.15867, 0.001)
        b = hs.mobility_cell(12.97162, 79.15868, 0.001)
        c = hs.mobility_cell(12.98, 79.16, 0.001)
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)
        self.assertEqual(hs.mobility_cell(None, None, 0.001), hs.mobility_cell(None, 5, 0.001))

    def test_mobility_tracker_ignores_gnss_noise_at_a_cell_edge(self):
        import math
        deg = 0.001
        edge = (round(12.50005 / deg) + 0.5) * deg                      # exactly on the boundary between two cells
        t = hs.MobilityTracker(deg)
        first = t.update(edge - 1e-6, 79.5)
        seen = {first}
        for i in range(500):                                            # +/-25 m (= +/-0.22 cell) of jitter around the edge
            seen.add(t.update(edge + 0.00022 * math.sin(i * 0.7), 79.5 + 0.00005 * math.sin(i * 1.3)))
        self.assertLessEqual(len(seen), 2)                              # at most one switch, never a flip-flop
        flips, last = 0, None
        for i in range(500):
            c = t.update(edge + 0.00022 * math.sin(i * 0.7), 79.5)
            flips += (c != last and last is not None)
            last = c
        self.assertEqual(flips, 0)
        far = t.update(edge + 5 * deg, 79.5)                         # a real move of 5 cells does change it
        self.assertNotEqual(far, last)
        self.assertEqual(t.update(None, None), far)                     # fix lost: cell is held
        # both ends must derive the same id for the same cell
        self.assertEqual(hs.MobilityTracker(deg).update(12.97161, 79.15867), hs.mobility_cell(12.97161, 79.15867, deg))


if __name__ == "__main__":
    unittest.main()
