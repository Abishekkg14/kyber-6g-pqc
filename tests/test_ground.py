import json
import math
import tempfile
import threading
import time
import unittest
from pathlib import Path

from kyber6g.ground import analytics
from kyber6g.telemetry.gnss import GnssState, GpsdReader
from kyber6g.transport import jsonmsg


class TestJsonMsg(unittest.TestCase):
    def test_split_reassemble_out_of_order(self):
        obj = {"satellites": [["GPS", i, 10.0 * i, 45.0, 30.0, 1] for i in range(80)], "x": "y" * 500}
        parts = jsonmsg.split(obj, 7)
        self.assertGreater(len(parts), 2)
        self.assertTrue(all(len(p) <= 1100 for _, p in parts))
        r = jsonmsg.Reassembler()
        out = None
        for ext, p in reversed(parts):
            out = r.add(ext, p) or out
        self.assertEqual(out, obj)

    def test_bad_ext_ignored(self):
        self.assertIsNone(jsonmsg.Reassembler().add(b"\x00\x00\x00\x01\x00\x05\x00\x02", b"{}"))


class TestAnalytics(unittest.TestCase):
    def test_haversine(self):
        self.assertAlmostEqual(analytics.haversine_m(0, 0, 1, 0), 111195, delta=5)

    def test_cep_on_ring(self):
        lat0, lon0 = 12.9716, 79.1586
        rows = []
        for i in range(360):
            a = math.radians(i)
            dlat = 5 * math.cos(a) / 111195
            dlon = 5 * math.sin(a) / (111195 * math.cos(math.radians(lat0)))
            rows.append({"ts": i, "mode": 3, "lat": lat0 + dlat, "lon": lon0 + dlon, "alt_m": 90.0, "speed_mps": 0.1,
                         "eph_m": 10, "sats_used": 8, "sats_seen": 12, "hdop": 0.9})
        s = analytics.summarize(rows, home=(lat0, lon0))
        self.assertAlmostEqual(s["accuracy_m"]["cep50"], 5.0, delta=0.05)
        self.assertAlmostEqual(s["accuracy_m"]["drms2"], 10.0, delta=0.1)
        self.assertEqual(s["fix_availability_pct"], 100.0)
        self.assertEqual(s["distance_m"], 0.0)          # jitter below eph is not counted as travel
        self.assertAlmostEqual(s["from_home_m"]["max"], 5.0, delta=0.05)

    def test_no_fix(self):
        s = analytics.summarize([{"ts": 0, "mode": 1, "lat": None}, {"ts": 1, "mode": 1, "lat": None}])
        self.assertEqual(s["fix_availability_pct"], 0.0)
        self.assertNotIn("accuracy_m", s)

    def test_density_grid(self):
        g = analytics.density_grid([(10.0, 20.0)] * 5 + [(10.001, 20.001)] * 2, cells=8)
        self.assertEqual(sum(map(sum, g["grid"])), 7)
        self.assertEqual(max(map(max, g["grid"])), 5)


class TestNmea(unittest.TestCase):
    """Sentences captured from the real 7Semi L89 on 2026-10-03."""

    def reader(self):
        st = GnssState()
        return st, GpsdReader(st)

    def test_gsv_without_az_el(self):
        st, r = self.reader()
        r._on_line(b"$GPGSV,1,1,03,28,,,32,32,,,28,10,,,28,1*6C")
        r._on_line(b"$GAGSV,1,1,00,7*73")
        d = st.snapshot(with_sats=True)
        self.assertEqual(d["sats_seen"], 3)
        self.assertEqual([s[1] for s in d["satellites"]], [10, 28, 32])
        self.assertEqual(d["satellites"][1], ["GPS", 28, None, None, 32.0, 0])

    def test_a_fix_without_a_position_is_no_fix(self):
        # gpsd said "3D" in a report that carried no position, once, after the receiver had stalled for 58 s
        st, r = self.reader()
        r._on_line(b'{"class":"TPV","mode":3,"lat":12.5001,"lon":79.5001,"altMSL":23.7}')
        self.assertEqual((st.snapshot()["mode"], st.snapshot()["lat"]), (3, 12.5001))
        for line in (b'{"class":"TPV","mode":3,"speed":0.123,"track":92.9}', b'{"class":"TPV","mode":2,"lat":12.5001}'):
            r._on_line(line)
            d = st.snapshot()
            self.assertEqual((d["mode"], d["fix"], d["lat"], d["lon"], d["alt_m"]), (1, "NO FIX", None, None, None))
        r._on_line(b'{"class":"TPV","mode":3,"lat":12.5002,"lon":79.5002,"altMSL":23.8}')
        self.assertEqual((st.snapshot()["mode"], st.snapshot()["lon"]), (3, 79.5002))

    def test_bad_checksum_rejected(self):
        st, r = self.reader()
        r._on_line(b"$GPGSV,1,1,03,28,,,32,32,,,28,10,,,28,1*6D")
        self.assertEqual(st.snapshot()["sats_seen"], 0)

    def test_multi_message_and_gsa_used(self):
        st, r = self.reader()
        def nmea(body):
            x = 0
            for ch in body:
                x ^= ord(ch)
            return f"${body}*{x:02X}".encode()
        r._on_line(nmea("GPGSV,2,1,05,01,40,083,41,02,17,308,35,03,07,120,22,04,60,010,45,1"))
        r._on_line(nmea("GPGSV,2,2,05,05,25,200,30,1"))
        r._on_line(nmea("GNGSA,A,3,01,02,04,05,,,,,,,,,1.8,0.9,1.5,1"))
        d = st.snapshot(with_sats=True)
        self.assertEqual(d["sats_seen"], 5)
        self.assertEqual(sum(s[5] for s in d["satellites"]), 4)
        self.assertEqual(d["satellites"][0], ["GPS", 1, 83.0, 40.0, 41.0, 1])

    def test_antenna_status(self):
        st, r = self.reader()
        r._on_line(b"$PQTMANTENNASTATUS,1,0,1*4F")
        self.assertEqual(st.snapshot()["antenna_status_raw"], "1,0,1")

    @staticmethod
    def nmea(body):
        x = 0
        for ch in body:
            x ^= ord(ch)
        return f"${body}*{x:02X}".encode()

    def test_rmc_time_without_fix(self):
        st, r = self.reader()
        r._on_line(self.nmea("GNRMC,094012.000,V,,,,,,,031026,,,N,V"))
        d = st.snapshot()
        self.assertEqual(d["receiver_utc"], "2026-10-03T09:40:12.000Z")
        self.assertEqual(d["rmc_status"], "VOID")
        self.assertEqual(d["nav_mode"], "NO FIX")
        self.assertFalse(d["utc_valid"])
        self.assertIsNone(d["lat"])                       # RMC never invents a position

    def test_rmc_valid_and_gga_quality(self):
        st, r = self.reader()
        r._on_line(self.nmea("GNRMC,094012.000,A,1258.2960,N,07909.5160,E,0.10,0.00,031026,,,A,V"))
        r._on_line(self.nmea("GNGGA,094012.000,1258.2960,N,07909.5160,E,1,07,1.10,215.3,M,-86.0,M,,"))
        d = st.snapshot()
        self.assertTrue(d["utc_valid"])
        self.assertEqual(d["nav_mode"], "AUTONOMOUS")
        self.assertEqual((d["gga_quality"], d["gga_quality_name"], d["gga_sats"]), (1, "GPS FIX", 7))
        self.assertIn("GN", d["talkers"])

    def test_txt_messages_kept(self):
        st, r = self.reader()
        r._on_line(self.nmea("GPTXT,01,01,02,ANTSTATUS=OK"))
        self.assertIn("ANTSTATUS=OK", st.snapshot()["receiver_text"][-1])


class TestLcdPages(unittest.TestCase):
    def test_camcorder_layout_while_recording(self):
        from kyber6g.lcd.display_manager import hms, pages
        from kyber6g.lcd.lcd import REC_DOT
        self.assertEqual(hms(3725.9), "01:02:05")
        st = {"gnss": {"fix": "NO FIX"}, "link": {"state": "UP"},
              "camera": {"recording": True, "recording_elapsed_s": 65, "recording_bytes": 12_300_000}}
        pg = pages(st)
        self.assertTrue(all(l1.strip(REC_DOT + " ").startswith("REC 00:01:05") for l1, _ in pg))
        self.assertTrue(all(len(l1) <= 16 and len(l2) <= 16 for l1, l2 in pg))
        self.assertEqual(pg[0][1], "SIZE: 12.3MB ENC")
        st["camera"]["recording"] = False
        self.assertEqual(pages(st)[0], ("KYBER-6G", "LINK: SECURE"))


class TestStore(unittest.TestCase):
    def test_write_query_export(self):
        from kyber6g.ground.main import rows_to_csv, rows_to_geojson, rows_to_kml
        from kyber6g.ground.store import Store
        s = Store(Path(tempfile.mkdtemp()) / "t.db")
        for i in range(20):
            s.telemetry({"ts": time.time() + i, "n": i, "mode": 3, "fix": "3D", "lat": 12.97 + i * 1e-5, "lon": 79.15,
                         "alt_m": 90 + i, "sats_used": 7}, 12.5, 0, "ab")
        s.satellites(time.time(), [["GPS", 1, 10.0, 20.0, 30.0, 1]])
        s.event("TEST", "hello")
        t0 = time.time()
        while s.counts()["telemetry"] < 20 and time.time() - t0 < 5:
            time.sleep(0.05)
        c = s.counts()
        self.assertEqual((c["telemetry"], c["satellites"], c["events"]), (20, 1, 1))
        rows = s.query("SELECT * FROM telemetry ORDER BY ts")
        self.assertEqual(rows[5]["alt_m"], 95)
        self.assertEqual(rows_to_csv(rows).decode().splitlines()[0].split(",")[:3], ["id", "run_id", "ts"])
        gj = json.loads(rows_to_geojson(rows))
        self.assertEqual(len(gj["features"]), 21)        # 20 points + track line
        self.assertIn(b"<LineString>", rows_to_kml(rows))


class TestStoreMigration(unittest.TestCase):
    def test_old_database_gains_new_columns_and_keeps_rows(self):
        import sqlite3
        from kyber6g.ground.store import SCHEMA, Store
        p = Path(tempfile.mkdtemp()) / "old.db"
        con = sqlite3.connect(p)
        con.executescript(SCHEMA)
        con.execute("INSERT INTO telemetry(ts, mode, lat, lon, alt_m) VALUES (1.0, 3, 12.9, 79.1, 55.5)")
        con.commit(); con.close()
        s = Store(p)
        cols = {r["name"] for r in s.query("PRAGMA table_info(telemetry)")}
        self.assertTrue({"alt_hae_m", "geoid_sep_m", "receiver_utc", "gga_quality", "cn0_max", "cn0_mean"} <= cols)
        s.telemetry({"ts": 2.0, "n": 1, "mode": 3, "fix": "3D", "lat": 12.9, "lon": 79.1, "alt_m": 28.0, "alt_hae_m": -60.5,
                     "geoid_sep_m": -88.5, "receiver_utc": "2026-10-03T04:39:54.000Z", "gga_quality": 1,
                     "satellites": [["GPS", 1, 10.0, 20.0, 31.0, 1], ["GPS", 2, 10.0, 20.0, 27.0, 0]]}, None, 0, "ab")
        t0 = time.time()
        while s.counts()["telemetry"] < 2 and time.time() - t0 < 5:
            time.sleep(0.05)
        rows = s.query("SELECT * FROM telemetry ORDER BY ts")
        self.assertEqual(rows[0]["alt_m"], 55.5)                       # old row untouched
        self.assertEqual((rows[1]["cn0_max"], rows[1]["cn0_mean"], rows[1]["alt_hae_m"]), (31.0, 29.0, -60.5))


class TestDetector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            import cv2  # noqa
            import ultralytics  # noqa
        except ImportError:
            raise unittest.SkipTest("ML packages not installed in this environment (GCS-only feature)")
        cls.asset = Path(ultralytics.__file__).parent / "assets" / "bus.jpg"
        if not cls.asset.exists():
            raise unittest.SkipTest("ultralytics sample image not bundled")

    class FakeVideo:
        """Feeds the same JPEG as a 'live' stream (new sequence number every 0.25 s)."""

        def __init__(self, jpg):
            self.latest, self.jpeg_seq, self.latest_ts, self.cond = jpg, 1, time.time(), threading.Condition()
            self.alive = True
            threading.Thread(target=self._feed, daemon=True).start()

        def _feed(self):
            while self.alive:
                time.sleep(0.25)
                with self.cond:
                    self.jpeg_seq += 1
                    self.latest_ts = time.time()
                    self.cond.notify_all()

    class RecStore:
        def __init__(self):
            self.dets, self.tracks = [], []

        def detection(self, ts, seq, det, lat, lon): self.dets.append(det)
        def track(self, *a): self.tracks.append(a)

    def _detector(self, profile, store=None):
        from kyber6g.ground.detector import Detector
        video = self.FakeVideo(self.asset.read_bytes())
        self.addCleanup(setattr, video, "alive", False)
        # snapshots go to a temporary folder (not the operator's real one); the downloaded weights are reused
        d = Detector(video, store or self.RecStore(), Path(tempfile.mkdtemp()), lambda: (12.97, 79.15),
                     profile=profile, on_event=lambda k, m: None, uid_base=lambda: 7,
                     models_dir=Path.home() / "kyber6g_ground" / "models")
        self.addCleanup(d.close)
        return d

    def _wait(self, pred, timeout=900):                           # first run may download weights
        t0 = time.time()
        while not pred() and time.time() - t0 < timeout:
            time.sleep(0.2)
        return pred()

    def _run_profile(self, profile):
        d = self._detector(profile)
        self.assertTrue(self._wait(lambda: d.latest["seq"] is not None and d.latest["dets"]), d.error)
        self.assertTrue(d.available, d.error)
        classes = {x["cls"] for x in d.latest["dets"]}
        self.assertIn("person", classes)
        self.assertIn("bus", classes)
        for x in d.latest["dets"]:
            self.assertTrue(all(0 <= v <= 1 for v in x["box"]))
            self.assertGreaterEqual(x["uid"], 7 * 10_000_000)       # database ids carry the run number
        self.assertGreater(d.latest["frame_ts"], 0)
        return d

    def test_vote_hysteresis_keeps_label_stable(self):
        from kyber6g.ground.detector import Detector
        t = {"votes": {}, "label": "cup"}
        for cls, c in [("cup", .5), ("mug", .6), ("cup", .5), ("mug", .55), ("cup", .5)]:
            self.assertEqual(Detector._vote(None, t, cls, c), "cup")      # flicker never flips the label
        for _ in range(8):
            last = Detector._vote(None, t, "mug", .9)
        self.assertEqual(last, "mug")                                       # a clear majority does

    def test_fast_coco_profile(self):
        d = self._run_profile("fast")
        self.assertEqual(len(d.names), 80)
        self.assertNotIn("pencil", d.names.values())

    def test_general_profile_has_everyday_vocabulary(self):
        d = self._run_profile("general")
        names = set(d.names.values())
        for w in ("pencil", "pen", "eraser", "scissors", "cell phone", "key", "water bottle"):
            self.assertIn(w, names)
        self.assertGreater(len(names), 100)

    def test_vocab_parsing(self):
        from kyber6g.ground.detector import clean_name, parse_vocab
        self.assertEqual(parse_vocab(" Pencil, red  pen,,pencil\nMug "), ["pencil", "red pen", "mug"])
        self.assertEqual(parse_vocab(" , "), [])
        self.assertEqual(clean_name("  Red   Pen "), "red pen")
        for bad in ("", "  ", "a;b", "x" * 5 + "/../etc"):
            with self.assertRaises(ValueError):
                clean_name(bad)

    def test_teach_by_example_and_forget(self):
        """Teach 'unittest bus' from a box on bus.jpg, then find it with the ACCURATE profile; forget it again."""
        d = self._detector("fast")
        self.assertTrue(self._wait(lambda: d.latest["dets"]), d.error)
        bus = [x for x in d.latest["dets"] if x["cls"] == "bus"][0]
        self.addCleanup(d.forget, "unittest bus")
        with self.assertRaises(ValueError):                              # too small / whole frame are rejected
            d.teach("unittest bus", self.asset.read_bytes(), [0.1, 0.1, 0.1005, 0.1005])
        with self.assertRaises(ValueError):
            d.teach("unittest bus", self.asset.read_bytes(), [0.0, 0.0, 1.0, 1.0])
        r = d.teach("unittest bus", self.asset.read_bytes(), bus["box"])
        self.assertEqual(r["examples"], 1)
        self.assertIn({"name": "unittest bus", "examples": 1}, d.taught_summary())
        self.assertTrue(self._wait(lambda: d.profile == "accurate" and "unittest bus" in d.names.values()
                                   and d.latest.get("profile") == "accurate" and d.latest["dets"]), d.error)
        labels = {x["cls"]: x["conf"] for x in d.latest["dets"]}
        self.assertTrue("unittest bus" in labels or "bus" in labels, labels)
        d.forget("unittest bus")
        self.assertNotIn("unittest bus", [t["name"] for t in d.taught_summary()])
        self.assertEqual(list((Path.home() / "kyber6g_ground" / "models" / "taught").glob("taught_unittest_bus_*.jpg")), [])

    def test_counters_go_idle_when_the_video_stops_and_the_worker_survives_errors(self):
        d = self._detector("fast")
        self.assertTrue(self._wait(lambda: d.latest["dets"]), d.error)
        self.assertTrue(self._wait(lambda: d.live_stats()["fps"] > 0, 60))
        st = d.live_stats()
        self.assertTrue(st["analysing"] and st["objects_now"] > 0 and st["worker_alive"], st)
        # a failure while storing / drawing one frame (e.g. a full disk) is reported and does not end the worker
        real = d._handle

        def full_disk(*a):
            raise OSError(28, "No space left on device")
        d._handle = full_disk
        self.assertTrue(self._wait(lambda: (d.error or "").startswith("post-processing"), 30), d.error)
        d._handle = real
        self.assertTrue(self._wait(lambda: d.error is None, 30), d.error)
        n = d.s["frames"]
        self.assertTrue(self._wait(lambda: d.s["frames"] > n + 1, 30))
        # the stream stops: "right now" values must not stay at the last frame's numbers
        d.video.alive = False
        time.sleep(3.8)
        st = d.live_stats()
        self.assertEqual((st["analysing"], st["fps"], st["objects_now"], st["counts_now"]), (False, 0.0, 0, {}))
        self.assertTrue(st["worker_alive"])
        self.assertEqual(d.status()["fps"], 0.0)
        self.assertGreater(d.status()["frames"], 0)                     # totals are kept

    def test_database_ids_are_unique_across_runs(self):
        from kyber6g.ground.detector import Detector
        s1, s2 = self.RecStore(), self.RecStore()
        self._detector("fast", s1)                                      # run 7
        video2 = self.FakeVideo(self.asset.read_bytes())
        self.addCleanup(setattr, video2, "alive", False)
        d2 = Detector(video2, s2, Path(tempfile.mkdtemp()), lambda: None, profile="fast", on_event=lambda k, m: None,
                      uid_base=lambda: 8, models_dir=Path.home() / "kyber6g_ground" / "models")      # run 8
        self.addCleanup(d2.close)
        self.assertTrue(self._wait(lambda: s1.dets and s2.dets), "no detections")
        self.assertTrue(all(x["uid"] // 10_000_000 == 7 for x in s1.dets))
        self.assertTrue(all(x["uid"] // 10_000_000 == 8 for x in s2.dets))


if __name__ == "__main__":
    unittest.main()
