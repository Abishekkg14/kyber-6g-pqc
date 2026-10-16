"""The changes made after the manuscript review of 14 October 2026: the repeat timer that follows the measured round
trip, the keyframe that the ground station asks for after a lost frame, and the position binding of the cached rekey
as a setting. Each test fails on the code as it was before."""
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from kyber6g.config import GroundConfig, LinkConfig
from kyber6g.crypto import handshake as hs
from kyber6g.crypto import identity as idm
from kyber6g.transport.link import GcsLink, UavLink

from tests.test_crypto import UAV_ID, full_handshake, make_ids
from tests.test_link import LossyProxy, wait


class DropOneHello(LossyProxy):
    """Drops the datagrams of the next ClientHello from the UAV (all its fragments), then passes everything."""

    def __init__(self, gcs_port):
        self.to_drop = 0
        super().__init__(gcs_port)

    def loop(self):
        while self.running:
            try:
                pkt, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            from_uav = addr[1] != self.gcs[1]
            if from_uav and self.to_drop and len(pkt) > 1 and pkt[1] != 0x10:
                self.to_drop -= 1
                continue
            if from_uav:
                self.uav = addr
            dst = self.gcs if from_uav else self.uav
            if dst:
                self.sock.sendto(pkt, dst)


def waits_of(retx_timer, rtt=None, kind="full"):
    """UavLink._waits for a link that is never started (no socket traffic)."""
    link = UavLink.__new__(UavLink)
    link.cfg = SimpleNamespace(retx_timer=retx_timer)
    link._rtt = {} if rtt is None else {kind: rtt}
    return link._waits(kind)


class TestRepeatTimer(unittest.TestCase):
    def test_the_fixed_timers_are_those_of_the_measurements(self):
        self.assertEqual(waits_of("fixed", 0.02, "full"), [1.2] * 5)
        self.assertEqual(waits_of("fixed", 0.007, "cached"), [0.7] * 3)
        self.assertEqual(waits_of("fixed", 0.012, "ratchet"), [0.35] * 5)

    def test_without_a_round_trip_the_rtt_timer_is_the_fixed_one(self):
        self.assertEqual(waits_of("rtt", None, "full"), [1.2] * 5)

    def test_three_round_trips_doubled_up_to_the_fixed_timer(self):
        w = waits_of("rtt", 0.020, "full")
        self.assertAlmostEqual(w[0], 0.060)
        self.assertAlmostEqual(w[1], 0.120)
        self.assertEqual(max(w), 1.2)                             # never later than the fixed timer
        self.assertTrue(all(b >= a for a, b in zip(w, w[1:])))    # never shorter after a repeat
        # the exchange waits in total at least as long as with the fixed timers: a slow ground station is still heard
        self.assertGreaterEqual(sum(w), 1.2 * 5)
        self.assertLess(sum(w[:-1]), 1.2 * 5)

    def test_a_very_short_round_trip_gives_at_least_30_ms(self):
        self.assertAlmostEqual(waits_of("rtt", 0.002, "cached")[0], 0.030)

    def test_a_lost_client_hello_is_repeated_after_milliseconds_not_after_1_2_s(self):
        d = Path(tempfile.mkdtemp())
        upk, gpk = idm.generate_identity(d, "uav"), idm.generate_identity(d, "gcs")
        uav_id, gcs_id = idm.load_identity(d, "uav", b"UAV-ALPH"), idm.load_identity(d, "gcs", b"GCS-MEC1")
        cfg = LinkConfig(gcs_host="127.0.0.1", gcs_port=0, heartbeat_s=0.3, link_timeout_s=1.5,
                         cached_rekey_interval_s=0, pq_ratchet_interval_s=0, retx_timer="rtt")
        gcs = GcsLink(cfg, gcs_id, {b"UAV-ALPH": upk}, bind=("127.0.0.1", 0))
        proxy = DropOneHello(gcs.sock.getsockname()[1])
        uav = UavLink(LinkConfig(**{**cfg.__dict__, "gcs_port": proxy.port}), uav_id, gpk, lambda: b"\x00" * 8)
        gcs.start(); uav.start()
        self.addCleanup(lambda: (uav.stop(), gcs.stop(), setattr(proxy, "running", False)))
        self.assertTrue(wait(lambda: uav.state == "UP"))
        self.assertIn("full", uav._rtt)                           # the first handshake, answered at once, gave a round trip
        # the next ClientHello is lost entirely (its 6 fragments); its repeat gets through
        proxy.to_drop = -(-6287 // 1180)
        res = uav.rekey_now("full", "test")
        self.assertTrue(res["ok"], res)
        self.assertGreaterEqual(res["parts"]["hello_sent"], 2)
        self.assertLess(res["ms"], 600)                           # with the fixed timer: more than 1,200 ms
        # the operation log says which timer the operation used (the A/B measurement counts by this record)
        e = [x for x in uav.oplog if x["tag"] == "test"][-1]
        self.assertEqual(e["retx"], "rtt")
        self.assertLess(e["first_wait_ms"], 1200)
        uav.cfg.retx_timer = "fixed"
        self.assertTrue(uav.rekey_now("full", "test2")["ok"])
        e = [x for x in uav.oplog if x["tag"] == "test2"][-1]
        self.assertEqual((e["retx"], e["first_wait_ms"]), ("fixed", 1200.0))


class TestCellBinding(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.uav, cls.gcs, cls.upk, cls.gpk = make_ids()

    def rekey_from_another_cell(self, binding):
        server, c, s = full_handshake(self.uav, self.gcs, self.gpk, self.upk)
        cache = hs.RekeyCache(ttl_s=300, cell_binding=binding)
        cache.put(UAV_ID, s, b"\x00" * 8, 1)
        req = hs.build_rekey_request(UAV_ID, c, b"\x11" * 8)
        return hs.server_process_rekey(cache, server, req), c, req, server

    def test_bound_by_default(self):
        self.assertTrue(LinkConfig().cell_binding)
        (mtype, body, _, _), *_ = self.rekey_from_another_cell(True)
        self.assertEqual((mtype, body[-1]), (hs.MSG_REKEY_REJECT, hs.REJECT_STALE_MOBILITY))

    def test_unbound_a_rekey_from_another_cell_is_accepted_and_still_authenticated(self):
        (mtype, body, new_s, _), c, req, server = self.rekey_from_another_cell(False)
        self.assertEqual(mtype, hs.MSG_REKEY_RESP)
        new_c, cf = hs.client_process_rekey_resp(req, c, body)
        s2, _, mobility, _ = server.process_client_finished(cf)
        self.assertEqual(bytes(new_c.master), bytes(s2.master))
        self.assertEqual(mobility, b"\x11" * 8)                   # the new session belongs to the new cell
        # the request is still bound to the resumption secret: a forged one is refused
        server, c, s = full_handshake(self.uav, self.gcs, self.gpk, self.upk)
        cache = hs.RekeyCache(ttl_s=300, cell_binding=False)
        cache.put(UAV_ID, s, b"\x00" * 8, 1)
        forged = bytearray(hs.build_rekey_request(UAV_ID, c, b"\x11" * 8)); forged[-1] ^= 1
        mtype, body, _, _ = hs.server_process_rekey(cache, server, bytes(forged))
        self.assertEqual((mtype, body[-1]), (hs.MSG_REKEY_REJECT, hs.REJECT_AUTH))

    def test_unbound_uav_makes_no_handshake_when_its_cell_changes(self):
        d = Path(tempfile.mkdtemp())
        upk, gpk = idm.generate_identity(d, "uav"), idm.generate_identity(d, "gcs")
        uav_id, gcs_id = idm.load_identity(d, "uav", b"UAV-ALPH"), idm.load_identity(d, "gcs", b"GCS-MEC1")
        cfg = LinkConfig(gcs_host="127.0.0.1", gcs_port=0, heartbeat_s=0.3, link_timeout_s=1.5,
                         cached_rekey_interval_s=0, pq_ratchet_interval_s=0, cell_binding=False)
        gcs = GcsLink(cfg, gcs_id, {b"UAV-ALPH": upk}, bind=("127.0.0.1", 0))
        cell = [b"\x00" * 8]
        uav = UavLink(LinkConfig(**{**cfg.__dict__, "gcs_port": gcs.sock.getsockname()[1]}), uav_id, gpk, lambda: cell[0])
        gcs.start(); uav.start()
        self.addCleanup(lambda: (uav.stop(), gcs.stop()))
        self.assertTrue(wait(lambda: uav.state == "UP"))
        n = uav.stats["handshakes_ok"]
        cell[0] = b"\x01" * 8
        time.sleep(1.5)
        self.assertEqual(uav.stats["handshakes_ok"], n)          # with the binding (the default) a full handshake follows
        self.assertTrue(uav._cached_rekey("test"))                 # and the cached rekey from the new cell works


class TestKeyframeRequest(unittest.TestCase):
    def sink(self, cb):
        from kyber6g.ground.video_sink import VideoSink
        from kyber6g.ground.video_sink import VIDEO_EXT
        v = VideoSink(ffmpeg="ffmpeg-not-needed", on_need_key=cb)
        v._ensure_decoder = lambda: None                          # no decoder process in this test
        self.addCleanup(setattr, v, "running", False)
        return v, VIDEO_EXT

    def test_a_lost_frame_brings_requests_at_most_every_quarter_second(self):
        asked = []
        v, ext = self.sink(lambda: asked.append(time.monotonic()))
        frame = lambda fid, key: v.on_chunk(ext.pack(fid, 0, 1, 1 if key else 0), (fid * 1000).to_bytes(8, "big") + b"x" * 20)
        frame(0, True)                                            # a keyframe: the decoder can start
        v.need_key = False
        asked.clear()
        t0 = time.monotonic()
        fid = 2                                                   # frame 1 never arrives: lost
        while time.monotonic() - t0 < 1.0:                        # frames keep arriving, none of them a keyframe
            frame(fid, False)
            fid += 1
            time.sleep(0.03)
        self.assertGreaterEqual(len(asked), 3)
        self.assertLessEqual(len(asked), 5)                       # 1 s / 0.25 s, not one per frame
        self.assertTrue(all(b - a >= v.KF_REQUEST_GAP - 0.01 for a, b in zip(asked, asked[1:])))
        frame(fid, True)                                          # the keyframe arrives: no more requests
        time.sleep(0.15)
        n = len(asked)
        for k in range(1, 10):
            frame(fid + k, False)
            time.sleep(0.03)
        self.assertEqual(len(asked), n)
        self.assertEqual(v.s["keyframe_requests"], n)

    def test_no_requests_when_switched_off_or_when_no_video_arrives(self):
        v, ext = self.sink(None)
        v.on_chunk(ext.pack(5, 0, 1, 0), (1).to_bytes(8, "big") + b"x")
        time.sleep(0.3)
        self.assertEqual(v.s["keyframe_requests"], 0)
        asked = []
        v, ext = self.sink(lambda: asked.append(1))
        time.sleep(0.3)                                           # waiting for a keyframe, but no video at all
        self.assertEqual(asked, [])

    def test_on_by_default_at_the_ground_station(self):
        self.assertTrue(GroundConfig().video_keyframe_request)

    def test_the_uav_carries_out_at_most_four_requests_a_second(self):
        from kyber6g.uav.main import UavApp
        app = UavApp.__new__(UavApp)
        app._kf_at = 0.0
        calls = []
        app.camera = SimpleNamespace(request_keyframe=lambda: calls.append(1) or True)
        for _ in range(20):
            app.on_keyframe_request()
            time.sleep(0.02)
        self.assertEqual(len(calls), 2)                           # 0.4 s of requests: at 0 and after 0.25 s

    def test_the_camera_refuses_without_a_running_encoder_and_counts_it(self):
        from kyber6g.camera.camera import CameraService
        cam = CameraService.__new__(CameraService)
        cam.stats, cam.encoding, cam.encoder = {}, False, None
        self.assertFalse(cam.request_keyframe())
        self.assertEqual(cam.stats["keyframe_requests_failed"], 1)
        with tempfile.TemporaryFile() as f:                       # an encoder whose device is not a V4L2 device
            cam.encoding, cam.encoder = True, SimpleNamespace(vd=f)
            self.assertFalse(cam.request_keyframe())
            self.assertIn("OSError", cam.stats["keyframe_request_error"])
        self.assertEqual(cam.stats["keyframe_requests_failed"], 2)


if __name__ == "__main__":
    unittest.main()
