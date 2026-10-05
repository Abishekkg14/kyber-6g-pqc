"""FINDER logic that needs no model: box maths, de-duplication and the multi-pass confirmation/tracking."""
import json
import threading
import time
import unittest

try:
    from kyber6g.ground import finder as fd
except ImportError:                                   # finder imports nothing heavy at module level
    fd = None


class FakeVideo:
    def __init__(self):
        self.latest, self.jpeg_seq, self.latest_ts, self.cond = None, 0, None, threading.Condition()


@unittest.skipIf(fd is None, "finder module not importable")
class TestFinderLogic(unittest.TestCase):
    def finder(self):
        f = fd.Finder(FakeVideo(), words=["pencil"], min_hits=2)
        self.addCleanup(f.close, 3)
        return f

    def test_iou_and_nms(self):
        a, b, c = [0.1, 0.1, 0.3, 0.3], [0.12, 0.12, 0.32, 0.32], [0.6, 0.6, 0.8, 0.8]
        self.assertAlmostEqual(fd.iou(a, a), 1.0)
        self.assertEqual(fd.iou(a, c), 0.0)
        self.assertGreater(fd.iou(a, b), 0.6)
        kept = fd.nms([{"cls": "x", "conf": 0.5, "box": a}, {"cls": "x", "conf": 0.9, "box": b}, {"cls": "x", "conf": 0.4, "box": c},
                       {"cls": "y", "conf": 0.3, "box": a}])
        self.assertEqual(sorted((d["cls"], d["conf"]) for d in kept), [("x", 0.4), ("x", 0.9), ("y", 0.3)])

    def test_box_appears_only_after_min_hits_and_keeps_its_id(self):
        f = self.finder()
        det = lambda x: [{"cls": "pencil", "conf": 0.4, "box": [x, 0.2, x + 0.05, 0.6]}]
        t = time.time()
        self.assertEqual(f._track(det(0.40), t, t), [])                         # first sighting: not shown (could be a ghost)
        shown = f._track(det(0.41), t + 0.3, t + 0.3)                           # confirmed on the second pass
        self.assertEqual([d["cls"] for d in shown], ["pencil"])
        pid = shown[0]["id"]
        self.assertGreaterEqual(pid, 1000)                                      # separate id space from the real-time tracker
        self.assertEqual(shown[0]["src"], "finder")
        self.assertEqual(shown[0]["ts"], t + 0.3)                               # carries the capture time of ITS frame
        shown = f._track(det(0.42), t + 0.6, t + 0.6)
        self.assertEqual(shown[0]["id"], pid)                                   # moved a little: same object, same id
        self.assertEqual(f._track([], t + 1.0, t + 1.0)[0]["id"], pid)          # one empty pass: still held (no blinking)
        held = f._track([], t + 1.0, t + 1.0)[0]
        self.assertTrue(held["static"] and held["hold"] >= 2.5)                  # tells the browser: slow source, keep it
        self.assertEqual(f._track([], t + 7.0, t + 7.0), [])                    # long without a sighting: dropped

    def test_a_strong_hit_is_shown_after_one_pass(self):
        f = self.finder()
        t = time.time()
        shown = f._track([{"cls": "pencil", "conf": 0.62, "box": [0.4, 0.2, 0.45, 0.6]},
                          {"cls": "pencil", "conf": 0.37, "box": [0.1, 0.2, 0.15, 0.6]}], t, t)
        self.assertEqual([d["conf"] for d in shown], [0.62])                    # the weak one waits for a second sighting

    def test_two_pencils_get_two_ids_and_other_words_do_not_merge(self):
        f = self.finder()
        d = [{"cls": "pencil", "conf": 0.5, "box": [0.1, 0.1, 0.15, 0.5]}, {"cls": "pencil", "conf": 0.4, "box": [0.6, 0.1, 0.65, 0.5]},
             {"cls": "pen", "conf": 0.4, "box": [0.1, 0.1, 0.15, 0.5]}]
        t = time.time()
        f._track(d, t, t)
        shown = f._track(d, t + 0.3, t + 0.3)
        self.assertEqual(len({x["id"] for x in shown}), 3)

    def test_candidate_frames_are_kept_rate_limited_and_pruned(self):
        try:
            import cv2
            import numpy as np
        except ImportError:
            self.skipTest("OpenCV not installed")
        import tempfile
        from pathlib import Path
        d = Path(tempfile.mkdtemp())
        f = fd.Finder(FakeVideo(), words=["pencil"], candidates_dir=d)
        self.addCleanup(f.close, 3)
        frame = np.zeros((72, 128, 3), np.uint8)
        t = time.time()
        f._save_candidate(frame, {"pencil": 0.05}, 0.3, t)                          # too weak: nothing kept
        self.assertEqual(list(d.glob("*.jpg")), [])
        f._save_candidate(frame, {"pencil": 0.22}, 0.3, t + 10)                     # weak but interesting: kept
        f._save_candidate(frame, {"pencil": 0.40}, 0.3, t + 11)                     # within 4 s: rate limited
        self.assertEqual(len(list(d.glob("cand_*pencil_22.jpg"))), 1)
        self.assertEqual(len(list(d.glob("*.jpg"))), 1)
        f._save_candidate(frame, {"pencil": 0.40}, 0.3, t + 20)
        self.assertEqual(len(list(d.glob("cand_*_SHOWN.jpg"))), 1)                  # frames above the threshold are marked

    def test_status_reports_weak_signal(self):
        f = self.finder()
        f.close(3)                                                                  # no worker: the state below is set by hand
        f.enabled = True
        f.s["best"] = {"pencil": 0.18, "screwdriver": 0.41}
        f.latest = {"ts": time.time(), "mono": time.monotonic(), "frame_ts": time.time(),
                    "dets": [{"cls": "screwdriver", "conf": 0.41}]}                 # a pass just finished
        st = f.status()
        self.assertEqual(st["weak"], [{"cls": "pencil", "conf": 0.18}])             # below the 0.35 default: shown as a hint only
        self.assertEqual(st["shown"], [{"cls": "screwdriver", "conf": 0.41}])
        self.assertTrue(st["looking"])
        self.assertAlmostEqual(st["threshold"], 0.35)

    def test_status_goes_quiet_when_the_video_stops(self):
        """No pass for a while (video stopped): 'FOUND pencil' / 'weak signal' must not stay on the screen."""
        f = self.finder()
        f.close(3)
        f.enabled = True
        f.s["best"] = {"pencil": 0.18}
        f.latest = {"ts": time.time() - 60, "mono": time.monotonic() - 60, "frame_ts": time.time() - 60,
                    "dets": [{"cls": "screwdriver", "conf": 0.6}]}
        st = f.status()
        self.assertEqual((st["looking"], st["shown"], st["weak"]), (False, [], []))
        self.assertFalse(st["worker_alive"])                                        # and a stopped worker is reported as such

    def test_configure_validates(self):
        f = self.finder()
        f.configure(words=[" Pencil ", "pencil", "", "Screw Driver"], enabled=True, threshold=5)
        self.assertEqual(f.words, ["pencil", "screw driver"])
        self.assertEqual(f.default_threshold(), 0.9)                            # clamped
        f.configure(threshold=0.01)
        self.assertEqual(f.default_threshold(), 0.12)
        with self.assertRaises(ValueError):
            f.configure(backend="nonsense")
        f.configure(enabled=False)


class TestFinderModel(unittest.TestCase):
    """The real OWLv2 path (decoding of logits/boxes). Skipped where transformers/torch are not installed (the Pi)."""

    @classmethod
    def setUpClass(cls):
        try:
            import cv2
            import transformers  # noqa: F401
            import torch  # noqa: F401
            import ultralytics
        except ImportError:
            raise unittest.SkipTest("ML packages not installed (ground-station feature)")
        from pathlib import Path
        cls.img = Path(ultralytics.__file__).parent / "assets" / "bus.jpg"
        if not cls.img.exists():
            raise unittest.SkipTest("sample image missing")
        cls.cv2 = cv2

    def test_owlv2_finds_the_bus_with_valid_boxes(self):
        f = fd.Finder(FakeVideo(), words=["bus"], input_size=640)
        self.addCleanup(f.close, 3)
        f._load()
        rgb = self.cv2.cvtColor(self.cv2.imread(str(self.img)), self.cv2.COLOR_BGR2RGB)
        h, w = rgb.shape[:2]
        dets = f.detect(rgb, ["bus", "person", "pencil"], 0.30)
        by = {}
        for d in dets:
            by.setdefault(d["cls"], []).append(d)
            x1, y1, x2, y2 = d["box"]
            self.assertTrue(0 <= x1 < x2 <= 1 and 0 <= y1 < y2 <= 1, d)
        self.assertIn("bus", by)
        self.assertGreater(max(d["conf"] for d in by["bus"]), 0.5)
        b = max(by["bus"], key=lambda d: d["conf"])["box"]
        self.assertGreater((b[2] - b[0]) * (b[3] - b[1]), 0.3)              # the bus fills much of that photo
        self.assertLess(b[0], 0.1)                                           # ... starting at its left edge (coordinates are right)
        self.assertGreater(b[2], 0.6)


class TestFinderEndToEnd(unittest.TestCase):
    """The finder thread on a 'live' feed of real photos (needs the benchmark photos: python -m kyber6g.tools.detect_bench fetch)."""

    def test_screwdriver_photo_is_found_confirmed_and_not_confused_with_a_pencil(self):
        try:
            import cv2  # noqa: F401
            import transformers  # noqa: F401
        except ImportError:
            self.skipTest("ML packages not installed")
        from pathlib import Path
        photos = sorted((Path.home() / "kyber6g_bench" / "set_screwdriver").glob("*.jpg"))
        if not photos:
            self.skipTest("benchmark photos not downloaded")
        jpg = photos[len(photos) // 2].read_bytes()
        video = FakeVideo()
        video.latest = jpg
        stop = threading.Event()

        def feed():                                                           # a new frame every 0.2 s, like a camera
            while not stop.is_set():
                time.sleep(0.2)
                with video.cond:
                    video.jpeg_seq += 1
                    video.latest_ts = time.time()
                    video.cond.notify_all()
        threading.Thread(target=feed, daemon=True).start()
        self.addCleanup(stop.set)
        passes = []
        f = fd.Finder(video, words=["pencil", "screwdriver"], input_size=640, period=0.0)
        f.on_pass = passes.append
        self.addCleanup(f.close, 20)
        f.configure(enabled=True)
        t0 = time.time()
        while time.time() - t0 < 180 and not (f.latest["dets"] and len(passes) >= 2):
            time.sleep(0.5)
        self.assertIsNone(f.error, f.error)
        self.assertTrue(f.latest["dets"], f"nothing confirmed after {len(passes)} passes; best={f.s['best']}")
        d = f.latest["dets"][0]
        self.assertEqual(d["cls"], "screwdriver")
        self.assertGreater(d["conf"], 0.35)
        self.assertTrue(d["static"] and d["hold"] >= 2.5 and d["src"] == "finder")
        self.assertGreater(d["ts"], 0)
        info = passes[-1]
        self.assertEqual(set(info), {"shown", "best", "frame", "frame_ts", "now", "infer_ms", "threshold", "words"})
        self.assertGreater(info["best"].get("screwdriver", 0), info["best"].get("pencil", 0))
        json.dumps(f.status())                                               # what /api/state serves must be JSON-safe


if __name__ == "__main__":
    unittest.main()
