"""Loopback integration tests: real UDP sockets on 127.0.0.1, both roles."""
import random
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from kyber6g.config import LinkConfig
from kyber6g.crypto import identity as idm
from kyber6g.crypto import keyschedule as ks
from kyber6g.transport.link import GcsLink, UavLink


class TestClockFilter(unittest.TestCase):
    """The ping/pong clock offset must come from the lowest-RTT recent sample and must not freeze (a stale 'best RTT ever'
    gate once left the offset 50 ms off and the telemetry latency negative)."""

    def feed(self, g, true_offset, rtt, asym, mono, t4=1000.0):
        # UAV clock = GCS clock + true_offset. Forward delay d1, return delay d2, rtt = d1 + d2, asym = d1 - d2.
        d1, d2 = (rtt + asym) / 2, (rtt - asym) / 2
        t1_gcs = t4 - rtt
        msg = {"t": "pong", "t1": t1_gcs, "t2": t1_gcs + d1 + true_offset, "t3": t1_gcs + d1 + true_offset}
        from unittest import mock
        with mock.patch("kyber6g.transport.link.time.time", return_value=t4), \
                mock.patch("kyber6g.transport.link.time.monotonic", return_value=mono):
            g._link_control(msg, None)

    def gcs(self):
        from collections import deque
        from kyber6g.transport.link import ClockSync
        g = GcsLink.__new__(GcsLink)
        g.clock, g.rtt_ms, g.events = ClockSync(), None, deque(maxlen=50)
        return g

    def test_lowest_rtt_sample_wins_and_old_samples_expire(self):
        g = self.gcs()
        self.feed(g, 0.500, rtt=0.004, asym=0.0, mono=100.0)             # accurate sample
        self.assertAlmostEqual(g.clock.at_time(100.0), 0.500, places=4)
        for i in range(10):                                              # loaded machine: slow, lopsided exchanges
            self.feed(g, 0.500, rtt=0.060, asym=0.050, mono=102.0 + 2 * i)
        self.assertAlmostEqual(g.clock.at_time(120.0), 0.500, delta=0.0021)   # still the 4 ms sample (error <= rtt/2)
        for i in range(20):                                              # 30 s later the good sample has expired
            self.feed(g, 0.520, rtt=0.010, asym=0.0, mono=140.0 + 2 * i)  # and the clocks have drifted apart by 20 ms
        self.assertAlmostEqual(g.clock.at_time(178.0), 0.520, delta=0.0006)
        self.assertEqual(g.clock.steps, 0)
        self.assertAlmostEqual(g.clock.rate, 0.0, delta=0.0005)

    def test_a_clock_running_at_the_wrong_rate_is_followed(self):
        """Measured in WSL after the laptop woke from sleep: the local clock ran 8.33 % slow, so the UAV's clock gained
        91 ms on it every local second. The offset must be right BETWEEN the 2 s pings too (it is used for every frame)."""
        g = self.gcs()
        drift, rng = 1 / 0.9167 - 1, random.Random(3)                    # +0.0909 s of offset per local second
        true = lambda mono: 0.300 + drift * (mono - 500.0)
        for i in range(15):
            mono = 500.0 + 2 * i
            self.feed(g, true(mono), rtt=0.006 + rng.random() * 0.004, asym=rng.uniform(-0.002, 0.002), mono=mono)
        self.assertAlmostEqual(g.clock.rate, drift, delta=0.002)
        for mono in (528.0, 528.7, 529.9):                               # also 1.9 s after the last exchange
            self.assertAlmostEqual(g.clock.at_time(mono), true(mono), delta=0.006)
        self.assertEqual(g.clock.steps, 0)
        # the old filter (lowest-RTT sample of the last 30 s, no drift) would be wrong by up to 30 s * 9 % = 2.7 s here

    def test_a_clock_step_is_adopted_at_once(self):
        """The host's time sync pushed the WSL clock forward by 2.9 s every 35 s: samples from before a jump are
        worthless, however good their RTT was."""
        g = self.gcs()
        for i in range(10):
            self.feed(g, 1.000, rtt=0.005, asym=0.0, mono=200.0 + 2 * i)
        self.assertAlmostEqual(g.clock.at_time(218.0), 1.000, delta=0.001)
        self.feed(g, 1.000 - 2.9, rtt=0.030, asym=0.010, mono=220.0)     # local clock jumped forward by 2.9 s; a mediocre exchange
        self.assertEqual(g.clock.steps, 1)
        self.assertAlmostEqual(g.clock.at_time(220.0), -1.900, delta=0.006)     # taken over immediately (error <= asym/2)
        self.assertTrue(any(k == "CLOCK_STEP" for _, k, _ in g.events))
        for i in range(6):
            self.feed(g, 1.000 - 2.9, rtt=0.005, asym=0.0, mono=222.0 + 2 * i)
        self.assertAlmostEqual(g.clock.at_time(232.0), -1.900, delta=0.001)
        self.feed(g, -1.900, rtt=0.450, asym=0.400, mono=234.0)          # one very slow, lopsided exchange is NOT a step
        self.assertEqual(g.clock.steps, 1)
        self.assertAlmostEqual(g.clock.at_time(234.0), -1.900, delta=0.002)


def wait(pred, timeout=8.0):
    t = time.monotonic()                 # not the wall clock: a clock step would cut the timeout short (seen under WSL)
    while time.monotonic() - t < timeout:
        if pred():
            return True
        time.sleep(0.05)
    return False


class LossyProxy:
    """UDP proxy between UAV and GCS that can drop/duplicate/reorder/block."""

    def __init__(self, gcs_port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.gcs = ("127.0.0.1", gcs_port)
        self.uav = None
        self.loss = 0.0
        self.rng = random.Random(1234)
        self.blocked = False
        self.block_handshake = False       # drop everything that is not a record (ptype 0x10): handshakes cannot complete
        self.capture = []
        self.n = 0
        self.sock.settimeout(0.2)
        self.running = True
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while self.running:
            try:
                pkt, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self.n += 1
            if self.blocked or (self.loss and self.rng.random() < self.loss):
                continue
            if self.block_handshake and len(pkt) > 1 and pkt[1] != 0x10:
                continue
            if addr[1] == self.gcs[1]:
                dst = self.uav
            else:
                self.uav = addr
                dst = self.gcs
                self.capture.append(pkt)
            if dst:
                self.sock.sendto(pkt, dst)

    def inject_to_gcs(self, pkt):
        self.sock.sendto(pkt, self.gcs)


class TestLink(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        d = Path(tempfile.mkdtemp())
        upk = idm.generate_identity(d, "uav")
        gpk = idm.generate_identity(d, "gcs")
        cls.uav_id, cls.gpk, cls.upk, cls.dir = idm.load_identity(d, "uav", b"UAV-ALPH"), gpk, upk, d
        cls.gcs_id = idm.load_identity(d, "gcs", b"GCS-MEC1")

    def make(self, **kw):
        cfg = LinkConfig(gcs_host="127.0.0.1", gcs_port=0, heartbeat_s=0.3, link_timeout_s=1.5,
                         cached_rekey_interval_s=0, pq_ratchet_interval_s=0, **kw)
        gcs = GcsLink(cfg, self.gcs_id, {b"UAV-ALPH": self.upk}, bind=("127.0.0.1", 0))
        gport = gcs.sock.getsockname()[1]
        proxy = LossyProxy(gport)
        cfg_u = LinkConfig(**{**cfg.__dict__, "gcs_port": proxy.port})
        self.cell = b"\x00" * 8
        uav = UavLink(cfg_u, self.uav_id, self.gpk, lambda: self.cell)
        got = []
        gcs.on_message = lambda st, ext, pt, meta: got.append((st, ext, pt))
        uav_ctrl = []
        uav.on_control = uav_ctrl.append
        gcs.start(); uav.start()
        self.addCleanup(lambda: (uav.stop(), gcs.stop(), setattr(proxy, "running", False)))
        return uav, gcs, proxy, got, uav_ctrl

    def test_handshake_and_data_both_ways(self):
        uav, gcs, proxy, got, ctrl = self.make()
        self.assertTrue(wait(lambda: uav.state == "UP" and gcs.link_up()))
        for i in range(20):
            uav.send(ks.STREAM_TELEMETRY, b"tm%d" % i)
        self.assertTrue(wait(lambda: len(got) == 20))
        gcs.send_control({"t": "capture_image", "id": 1})
        self.assertTrue(wait(lambda: any(m.get("t") == "capture_image" for m in ctrl)))
        self.assertEqual(uav.session.session_id, gcs.sessions[gcs.active].session.session_id)

    def test_handshake_survives_loss(self):
        uav, gcs, proxy, got, ctrl = self.make()
        proxy.loss = 0.25   # 25 % random loss in both directions
        self.assertTrue(wait(lambda: uav.state == "UP", 25))

    def test_replay_injected_packets_rejected(self):
        uav, gcs, proxy, got, ctrl = self.make()
        self.assertTrue(wait(lambda: uav.state == "UP"))
        uav.send(ks.STREAM_TELEMETRY, b"once")
        self.assertTrue(wait(lambda: len(got) == 1))
        rec = [p for p in proxy.capture if p[1] == 0x10][-1]
        for _ in range(5):
            proxy.inject_to_gcs(rec)
        time.sleep(0.5)
        self.assertEqual(len(got), 1)
        self.assertGreaterEqual(gcs.stats["drops"].get("duplicate", 0), 1)

    def test_cached_rekey_and_pq_ratchet(self):
        uav, gcs, proxy, got, ctrl = self.make()
        self.assertTrue(wait(lambda: uav.state == "UP"))
        sid0 = uav.session.session_id
        self.assertTrue(uav._cached_rekey("test"))
        self.assertTrue(wait(lambda: uav.state == "UP" and gcs.active == uav.session.session_id))
        sid1 = uav.session.session_id
        self.assertNotEqual(sid0, sid1)
        self.assertTrue(uav.request_pq_ratchet())
        self.assertTrue(wait(lambda: uav.stats["pq_ratchets"] == 1))
        uav.send(ks.STREAM_TELEMETRY, b"after-ratchet")
        self.assertTrue(wait(lambda: gcs.active == uav.session.session_id))
        self.assertTrue(wait(lambda: any(p == b"after-ratchet" for _, _, p in got)))
        self.assertNotEqual(uav.session.session_id, sid1)

    def test_recovery_after_interruption(self):
        uav, gcs, proxy, got, ctrl = self.make()
        self.assertTrue(wait(lambda: uav.state == "UP"))
        proxy.blocked = True
        self.assertTrue(wait(lambda: uav.state != "UP", 5))
        proxy.blocked = False
        self.assertTrue(wait(lambda: uav.state == "UP", 15))
        self.assertGreaterEqual(uav.stats["cached_rekeys_ok"] + uav.stats["handshakes_ok"], 2)

    def test_mobility_change_forces_full_handshake(self):
        uav, gcs, proxy, got, ctrl = self.make()
        self.assertTrue(wait(lambda: uav.state == "UP"))
        n = uav.stats["handshakes_ok"]
        self.cell = b"\x01" * 8
        self.assertTrue(wait(lambda: uav.stats["handshakes_ok"] == n + 1 and uav.state == "UP", 15))

    def _stream(self, uav, stop, sent, refused):
        """Send a numbered record every 2 ms, as the video does, noting every one the link refuses to send."""
        i = 0
        while not stop.is_set():
            (sent if uav.send(ks.STREAM_TELEMETRY, b"f%06d" % i) else refused).append(i)
            i += 1
            time.sleep(0.002)

    def test_a_change_of_cell_does_not_interrupt_the_stream(self):
        """The handshake after a change of cell used to take the link out of the UP state: nothing was sent while it
        ran, so every cell crossed in flight cost a video frame (and the picture up to the next keyframe)."""
        uav, gcs, proxy, got, ctrl = self.make()
        self.assertTrue(wait(lambda: uav.state == "UP" and gcs.link_up()))
        states, set_state = [], uav._set_state
        uav._set_state = lambda st, why="": (states.append(st) if st != uav.state else None, set_state(st, why))[1]
        stop, sent, refused = threading.Event(), [], []
        t = threading.Thread(target=self._stream, args=(uav, stop, sent, refused), daemon=True)
        t.start()
        n, sid0 = uav.stats["handshakes_ok"], uav.session.session_id
        time.sleep(0.2)
        for cell in (b"\x01" * 8, b"\x02" * 8, b"\x03" * 8):                 # three cells crossed, one after the other
            k = uav.stats["handshakes_ok"]
            self.cell = cell
            self.assertTrue(wait(lambda: uav.stats["handshakes_ok"] == k + 1, 15))
            time.sleep(0.15)
        stop.set(); t.join(2)
        self.assertEqual(uav.stats["handshakes_ok"], n + 3)
        self.assertNotEqual(uav.session.session_id, sid0)
        self.assertEqual(uav.session_mobility, b"\x03" * 8)
        self.assertEqual(states, [], "the link must stay UP during the handshakes")
        self.assertEqual(refused, [], "no record may be refused while a handshake runs")
        self.assertTrue(wait(lambda: len(got) == len(sent)), f"{len(got)} of {len(sent)} records arrived")
        self.assertEqual(sorted(p for _, _, p in got), [b"f%06d" % i for i in sent])   # every record, exactly once

    def test_a_change_of_cell_with_no_handshake_possible_keeps_the_running_session(self):
        """If the handshake after a change of cell cannot complete, the session that works is kept and the handshake
        is tried again later; when it becomes possible, it is made."""
        uav, gcs, proxy, got, ctrl = self.make()
        self.assertTrue(wait(lambda: uav.state == "UP" and gcs.link_up()))
        stop, sent, refused = threading.Event(), [], []
        t = threading.Thread(target=self._stream, args=(uav, stop, sent, refused), daemon=True)
        t.start()
        n, fails, sid0 = uav.stats["handshakes_ok"], uav.stats["handshakes_fail"], uav.session.session_id
        proxy.block_handshake = True
        self.cell = b"\x07" * 8
        self.assertTrue(wait(lambda: uav.stats["handshakes_fail"] == fails + 1, 12))    # five ClientHellos, 6 s
        self.assertEqual((uav.state, uav.session.session_id), ("UP", sid0))
        self.assertEqual(refused, [])
        proxy.block_handshake = False
        self.assertTrue(wait(lambda: uav.stats["handshakes_ok"] == n + 1 and uav.session_mobility == b"\x07" * 8, 15))
        stop.set(); t.join(2)
        self.assertEqual((uav.state, refused), ("UP", []))
        self.assertTrue(wait(lambda: len(got) == len(sent)), f"{len(got)} of {len(sent)} records arrived")

    def test_gcs_counts_full_handshakes_and_cached_rekeys_separately(self):
        """The SECURITY tab showed 'handshakes ok 96' after 2 real handshakes: every cached rekey was counted as one."""
        uav, gcs, proxy, got, ctrl = self.make()
        self.assertTrue(wait(lambda: uav.state == "UP" and gcs.link_up()))
        self.assertEqual((gcs.stats["handshakes_ok"], gcs.stats["cached_rekeys_ok"]), (1, 0))
        for n in (1, 2, 3):
            self.assertTrue(uav._cached_rekey("test"))
            self.assertTrue(wait(lambda: uav.state == "UP" and gcs.active == uav.session.session_id))
            self.assertEqual((gcs.stats["handshakes_ok"], gcs.stats["cached_rekeys_ok"]), (1, n))
        self.assertTrue(uav.request_pq_ratchet())
        self.assertTrue(wait(lambda: uav.stats["pq_ratchets"] == 1))
        self.assertEqual((gcs.stats["handshakes_ok"], gcs.stats["pq_ratchets"]), (1, 1))
        self.assertEqual((uav.stats["handshakes_ok"], uav.stats["cached_rekeys_ok"]), (1, 3))     # both ends agree
        self.assertEqual(gcs._rekey_sids, set())

    def test_pq_ratchet_survives_a_lost_answer_and_a_silent_peer(self):
        """Request and answer are single datagrams on a lossy link. One lost answer used to leave the ratchet 'in
        flight' for ever: every later PQ ratchet (periodic or from the dashboard) was refused."""
        uav, gcs, proxy, got, ctrl = self.make()
        self.assertTrue(wait(lambda: uav.state == "UP" and gcs.link_up()))
        real_send, dropped = gcs.send_control, []

        def lose_first_answer(msg):
            if msg.get("t") == "ratchet_resp" and not dropped:
                dropped.append(msg)
                return True
            return real_send(msg)
        gcs.send_control = lose_first_answer
        self.assertTrue(uav.request_pq_ratchet())
        self.assertFalse(uav.request_pq_ratchet())                       # one in flight: not started twice
        self.assertTrue(wait(lambda: uav.stats["pq_ratchets"] == 1, 5))  # the request was repeated and answered
        self.assertEqual(len(dropped), 1)
        self.assertEqual(uav.session.session_id.hex(), dropped[0]["sid"])    # the repeat got the SAME answer ...
        self.assertEqual(gcs.stats["pq_ratchets"], 1)                        # ... computed once, not once per repeat
        uav.send(ks.STREAM_TELEMETRY, b"after-ratchet")
        self.assertTrue(wait(lambda: any(p == b"after-ratchet" for _, _, p in got)))
        # the answer never arrives: the attempt is given up, the link stays usable, and a later attempt works
        gcs.send_control = lambda msg: True if msg.get("t") == "ratchet_resp" else real_send(msg)
        self.assertTrue(uav.request_pq_ratchet())
        self.assertTrue(wait(lambda: uav._ratchet is None, 6))
        self.assertEqual(uav.stats.get("pq_ratchet_timeouts"), 1)
        self.assertEqual(uav.state, "UP")
        gcs.send_control = real_send
        self.assertTrue(uav.request_pq_ratchet())
        self.assertTrue(wait(lambda: uav.stats["pq_ratchets"] == 2, 5))
        uav.send(ks.STREAM_TELEMETRY, b"still-alive")
        self.assertTrue(wait(lambda: any(p == b"still-alive" for _, _, p in got)))

    def test_link_manager_survives_an_internal_error(self):
        import logging
        link_log = logging.getLogger("kyber6g.link")           # the simulated failure is logged with its traceback
        link_log.disabled = True
        self.addCleanup(setattr, link_log, "disabled", False)
        uav, gcs, proxy, got, ctrl = self.make()
        self.assertTrue(wait(lambda: uav.state == "UP"))
        real, hits = uav._full_handshake, []

        def broken_once():
            if not hits:
                hits.append(1)
                raise RuntimeError("simulated failure inside the handshake")
            return real()
        uav._full_handshake = broken_once
        uav._cached_rekey = lambda reason: False            # force the full-handshake path on recovery
        proxy.blocked = True
        self.assertTrue(wait(lambda: uav.state != "UP", 5))
        proxy.blocked = False
        self.assertTrue(wait(lambda: uav.state == "UP", 20), uav.stats["last_error"])
        self.assertEqual(hits, [1])                         # the error happened, and the manager thread kept going
        uav.send(ks.STREAM_TELEMETRY, b"alive")
        self.assertTrue(wait(lambda: any(p == b"alive" for _, _, p in got)))


if __name__ == "__main__":
    unittest.main()
