"""Failure paths: things that used to stop a thread, block the link or exhaust memory must now be survived and reported."""
import queue
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from kyber6g import config as cfgmod
from kyber6g.transport import link as linkmod


def wait(pred, timeout=5.0):
    t0 = time.monotonic()                # not the wall clock: a clock step would cut the timeout short (seen under WSL)
    while not pred() and time.monotonic() - t0 < timeout:
        time.sleep(0.02)
    return pred()


class TestControlMessages(unittest.TestCase):
    def test_oversize_control_message_is_an_error_not_a_silent_loss(self):
        ok = linkmod.control_records(b"x" * (linkmod.CONTROL_CHUNK * linkmod.MAX_CONTROL_PARTS))
        self.assertEqual(len(ok), linkmod.MAX_CONTROL_PARTS)
        r = linkmod.ControlReassembler()
        out = [r.add(ext, chunk) for ext, chunk in ok]
        self.assertEqual(len(out[-1]), linkmod.CONTROL_CHUNK * linkmod.MAX_CONTROL_PARTS)   # the largest allowed one arrives
        with self.assertRaises(ValueError):
            linkmod.control_records(b"x" * (linkmod.CONTROL_CHUNK * linkmod.MAX_CONTROL_PARTS + 1))


class TestUavCommands(unittest.TestCase):
    """UAV command handling without hardware: commands run on a worker, never in the link's receive thread."""

    def app(self, handle=None):
        from kyber6g.uav.main import UavApp
        app = UavApp.__new__(UavApp)
        app._cmds = queue.Queue(maxsize=4)
        app.running = True
        app.sent = []
        app.link = SimpleNamespace(send_control=lambda m: app.sent.append(m) or True)
        app.blobs = SimpleNamespace(on_control=lambda m: m.get("t") in ("blob_nack", "blob_done"),
                                    send=lambda *a: {"id": "00", "name": a[2], "size": len(a[3]), "sha256": "", "chunks": 1})
        app.camera = None
        app.lcd = None
        app.events = []
        app.cfg = cfgmod.UavConfig()
        app.cfg.camera.recordings_dir = tempfile.mkdtemp()
        if handle:
            app.handle = handle
        t = threading.Thread(target=app.command_loop, daemon=True)
        t.start()
        self.addCleanup(lambda: (setattr(app, "running", False), t.join(2)))
        return app

    def test_a_slow_command_does_not_block_the_receive_thread(self):
        def slow(t, msg):
            time.sleep(0.6)
            return {"done": t}
        app = self.app(slow)
        t0 = time.perf_counter()
        app.on_control({"t": "capture_image", "id": 7})
        self.assertLess(time.perf_counter() - t0, 0.05)                 # queued, not executed, by the caller
        self.assertEqual(app.sent, [])
        self.assertTrue(wait(lambda: app.sent))
        self.assertEqual(app.sent[0], {"t": "ack", "id": 7, "cmd": "capture_image", "ok": True, "result": {"done": "capture_image"}})

    def test_failures_are_acknowledged_and_the_worker_lives_on(self):
        import logging
        uav_log = logging.getLogger("kyber6g.uav")              # the failure is logged with its traceback: not test output
        uav_log.disabled = True
        self.addCleanup(setattr, uav_log, "disabled", False)

        def flaky(t, msg):
            if t == "boom":
                raise RuntimeError("camera exploded")
            return None
        app = self.app(flaky)
        app.on_control({"t": "boom", "id": 1})
        app.on_control({"t": "status", "id": 2})
        self.assertTrue(wait(lambda: len(app.sent) == 2))
        self.assertEqual((app.sent[0]["ok"], app.sent[0]["error"]), (False, "RuntimeError: camera exploded"))
        self.assertTrue(app.sent[1]["ok"])

    def test_a_flood_of_commands_gets_a_busy_answer(self):
        gate = threading.Event()
        app = self.app(lambda t, msg: gate.wait(5))
        for i in range(12):
            app.on_control({"t": "status", "id": i})
        busy = [m for m in app.sent if not m["ok"]]
        self.assertGreaterEqual(len(busy), 6)
        self.assertIn("busy", busy[0]["error"])
        gate.set()

    def test_transfer_control_messages_bypass_the_queue(self):
        app = self.app(lambda t, msg: self.fail("blob control must not reach the command handler"))
        app.on_control({"t": "blob_nack", "id": "aabbccdd", "missing": []})
        time.sleep(0.2)
        self.assertEqual(app.sent, [])

    def test_recording_list_and_the_transfer_limit(self):
        app = self.app()
        d = Path(app.cfg.camera.recordings_dir)
        (d / "rec_small.k6grec").write_bytes(b"s" * 800)
        (d / "rec_huge.k6grec").write_bytes(b"h" * 5000)
        with mock.patch("kyber6g.uav.main.MAX_BLOB", 2000):
            rows = {r["name"]: r for r in app.handle("list_recordings", {})}
            self.assertEqual((rows["rec_small.k6grec"]["fetchable"], rows["rec_huge.k6grec"]["fetchable"]), (True, False))
            self.assertEqual(app.handle("fetch_recording", {"name": "rec_small.k6grec"})["size"], 800)
            with self.assertRaises(RuntimeError) as cm:                 # refused BEFORE the file is read into memory
                app.handle("fetch_recording", {"name": "rec_huge.k6grec"})
            self.assertIn("pull rec_huge.k6grec", str(cm.exception))
            with self.assertRaises(FileNotFoundError):
                app.handle("fetch_recording", {"name": "../../etc/passwd"})
        with self.assertRaises(RuntimeError):                           # camera commands before the camera is up
            app.handle("start_live", {})

    def test_recording_is_refused_when_the_card_is_almost_full(self):
        app = self.app()
        app.camera = SimpleNamespace(recorder=None)
        with mock.patch.object(type(app), "free_mb", lambda self: 120.0):
            with self.assertRaises(RuntimeError) as cm:
                app.handle("start_rec", {})
        self.assertIn("almost full", str(cm.exception))
        self.assertEqual(list(Path(app.cfg.camera.recordings_dir).glob("*")), [])      # and no orphan file

    def test_a_running_recording_is_closed_before_the_card_is_full(self):
        app = self.app()
        stopped = []
        app.camera = SimpleNamespace(recorder=object(), take_rec_failure=lambda: None,
                                     stop_recording=lambda: stopped.append(1) or {"frames": 10})
        with mock.patch.object(type(app), "free_mb", lambda self: 900.0):
            app._watch_recording()
        self.assertEqual(stopped, [])
        with mock.patch.object(type(app), "free_mb", lambda self: 180.0):
            app._watch_recording()
        self.assertEqual(stopped, [1])
        self.assertIn("automatically", app.events[-1]["msg"])


class TestTelemetryStoreAndForward(unittest.TestCase):
    def test_no_sample_is_lost_or_stored_twice_across_a_link_loss(self):
        """The link layer notices a dead link only after link_timeout seconds; what was sent meanwhile never arrived
        (measured: 22 samples missing around a 43-minute standby of the ground station)."""
        from kyber6g.ground.main import GroundApp
        from kyber6g.uav.main import TelemetryQueue
        stored = []
        gcs = GroundApp.__new__(GroundApp)
        gcs.tm = {"rx": 0, "backfill": 0, "latency_ms": None, "last_n": None, "gaps": 0, "dup": 0}
        import collections
        gcs._tm_seen, gcs._tm_order, gcs._tm_lat, gcs._last_sat_store = set(), collections.deque(), collections.deque(maxlen=30), 0
        gcs.link = SimpleNamespace(time_offset=None)
        gcs.sky, gcs.sky_ts, gcs.telemetry, gcs.home, gcs.last_fix = [], None, None, (0.0, 0.0), None
        gcs.track = collections.deque(maxlen=10)
        gcs.store = SimpleNamespace(telemetry=lambda tm, *a: stored.append((tm["n"], bool(tm.get("backfill")))), satellites=lambda *a: None)
        alive = [True]                                   # is the ground station really receiving?

        def send(p):
            if alive[0]:
                gcs._telemetry(dict(p), {})
            return True                                  # UDP: the sender cannot tell
        q = TelemetryQueue(unacked=7)
        n = 0

        def run(steps, up):
            nonlocal n
            for _ in range(steps):
                n += 1
                q.step({"ts": 1000.0 + n, "n": n, "boot": 42.5, "satellites": [["GPS", 1, 1, 1, 30, 1]]}, up, send)
        run(10, up=True)                                 # 1..10 arrive live
        alive[0] = False
        run(5, up=True)                                  # 11..15 are sent into the void: the UAV still believes the link is up
        run(30, up=False)                                # timeout noticed: 16..45 are kept
        self.assertEqual(len(q.backlog), 30 + 7)         # ... together with the last 7 that were sent (9..15)
        alive[0] = True
        run(5, up=True)                                  # link back: 46..50 live, the backlog drains 20 per step
        got = sorted(k for k, _ in stored)
        self.assertEqual(got, list(range(1, 51)))        # every sample exactly once
        self.assertEqual(gcs.tm["dup"], 2)               # 9 and 10 had arrived before; their second copies were dropped
        self.assertEqual([k for k, late in stored if late], list(range(11, 46)))      # 11..45 arrived late, in order
        self.assertEqual(len(q.backlog), 0)

    def test_a_failed_send_while_draining_keeps_the_sample(self):
        from kyber6g.uav.main import TelemetryQueue
        q = TelemetryQueue(unacked=3)
        for i in range(1, 6):
            q.step({"n": i}, False, lambda p: True)
        sent = []

        def flaky(p):
            if p["n"] == 2 and not any(x["n"] == 2 for x in sent) and not sent[-1:] == [{"n": -1}]:
                sent.append({"n": -1})                   # the first attempt to send sample 2 fails
                return False
            sent.append(p)
            return True
        q.step({"n": 6}, True, flaky)
        self.assertEqual([p["n"] for p in sent if p["n"] > 0], [6, 1])
        self.assertEqual([p["n"] for p in q.backlog], [2, 3, 4, 5])      # 2 is still first in line


class TestCameraRecordingFailure(unittest.TestCase):
    def test_a_write_error_detaches_the_recorder_and_keeps_the_live_stream(self):
        from kyber6g.camera.camera import CameraService
        cam = CameraService.__new__(CameraService)
        live = []
        cam.stats = {"frames": 0, "keyframes": 0, "bytes": 0}
        cam._win, cam.live, cam.error, cam.rec_failure = [], True, None, None
        cam.encoder = SimpleNamespace(firsttimestamp=None)
        cam.on_live_frame = lambda data, key, ts: live.append(data)
        cam.lock, cam.available, cam.encoding = threading.RLock(), False, False

        class FullDisk:
            name, frames, aborted = "rec_x.k6grec", 42, False
            def add_frame(self, *a): raise OSError(28, "No space left on device")
            def abort(self): self.aborted = True
        rec = cam.recorder = FullDisk()
        cam._on_frame(b"frame-1", True, None)            # must not raise into the encoder thread
        cam._on_frame(b"frame-2", False, None)
        self.assertEqual(live, [b"frame-1", b"frame-2"])
        self.assertIsNone(cam.recorder)
        f = cam.take_rec_failure()
        self.assertEqual((f["name"], f["frames"]), ("rec_x.k6grec", 42))
        self.assertIn("No space left", f["error"])
        self.assertTrue(rec.aborted)
        self.assertIsNone(cam.take_rec_failure())        # reported once


class TestNoCoreDumps(unittest.TestCase):
    def test_process_becomes_non_dumpable(self):
        """A crash must not write keys to disk: checked in a child process, from the kernel's own view of it."""
        import subprocess
        import sys
        code = ("import sys; from kyber6g.crypto.secure_bytes import no_core_dumps; ok = no_core_dumps(); "
                "import resource; print(ok, resource.getrlimit(resource.RLIMIT_CORE)[0], "
                "open('/proc/self/coredump_filter').read().strip() if False else '')")
        r = subprocess.run([sys.executable, "-W", "ignore", "-c", code], capture_output=True, text=True, timeout=60,
                           cwd=str(Path(__file__).resolve().parents[1]))
        self.assertEqual(r.returncode, 0, r.stderr[-300:])
        ok, core_limit = r.stdout.split()[:2]
        if sys.platform != "linux":
            self.skipTest("prctl is Linux-only")
        self.assertEqual((ok, core_limit), ("True", "0"))


class TestStoreWriter(unittest.TestCase):
    def test_one_bad_row_costs_one_row_and_never_the_writer(self):
        from kyber6g.ground.store import Store
        s = Store(Path(tempfile.mkdtemp()) / "t.db")
        for i in range(10):
            s.event("GOOD", f"row {i}")
            if i == 3:
                s._put("INSERT INTO no_such_table(x) VALUES (?)", (1,))                      # sqlite3.OperationalError
            if i == 6:
                s._put("INSERT INTO events(ts, kind, msg) VALUES (?,?,?)", (2 ** 70, "X", "y"))   # OverflowError (not sqlite3.Error)
        self.assertTrue(wait(lambda: s.written + s.dropped >= 12, 10))
        c = s.counts()
        self.assertEqual((c["events"], c["dropped"]), (10, 2))
        self.assertIn("last_error", c)
        s.event("GOOD", "after the bad rows")                                                # the writer thread is still alive
        self.assertTrue(wait(lambda: s.counts()["events"] == 11, 10))

    def test_malformed_satellite_rows_are_skipped(self):
        from kyber6g.ground.store import Store
        s = Store(Path(tempfile.mkdtemp()) / "t.db")
        s.satellites(1.0, [["GPS", 1, 10.0, 20.0, 30.0, 1], ["GPS", 2], "junk", None, ["Galileo", 3, None, None, None, 0, "extra"]])
        self.assertTrue(wait(lambda: s.counts()["satellites"] == 2, 10))


class TestGroundLoops(unittest.TestCase):
    def app(self):
        from kyber6g.ground.main import GroundApp
        app = GroundApp.__new__(GroundApp)
        app.notes = []
        app.note = lambda kind, msg: app.notes.append((kind, msg))
        app._work = queue.Queue()
        threading.Thread(target=app.work_loop, daemon=True).start()
        return app

    def test_transfer_processing_errors_are_reported_and_the_worker_continues(self):
        import logging
        gcs_log = logging.getLogger("kyber6g.ground")           # the failure is logged with its traceback: not test output
        gcs_log.disabled = True
        self.addCleanup(setattr, gcs_log, "disabled", False)
        app, done = self.app(), []
        app._work.put((lambda info, data: 1 / 0, {"name": "bad.k6grec"}, b""))
        app._work.put((lambda info, data: done.append(info["name"]), {"name": "good.jpg"}, b""))
        self.assertTrue(wait(lambda: done == ["good.jpg"]))
        self.assertEqual(app.notes[0][0], "ERROR")
        self.assertIn("bad.k6grec", app.notes[0][1])

    def test_failed_transfer_is_written_to_the_event_log(self):
        app = self.app()
        app.on_transfer_failed({"name": "rec_1.k6grec", "chunks": 5000}, 1234)
        self.assertEqual(app.notes[0][0], "TRANSFER")
        self.assertIn("1234 of 5000", app.notes[0][1])


if __name__ == "__main__":
    unittest.main()
