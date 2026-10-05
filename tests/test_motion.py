"""The motion watch (camera/motion.py): what it reports for scenes in which everything is known."""
import math
import queue
import sys
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

import numpy as np

from kyber6g import config as cfgmod
from kyber6g.camera import motion as mo
from kyber6g.camera import motion_eval as me

SHAPE = (120, 192)          # smaller than the camera's 180 x 320: the tests run on the Pi as well


def scipy_only(fn):
    return unittest.skipIf(mo.ndi is None, "needs SciPy (rotation, zoom, fractions of a pixel)")(fn)


def frames_of(seed, n, noise=me.DAY, shape=SHAPE, pose=lambda i: (0.0, 0.0, 0.0, 1.0), border=24):
    rng = np.random.default_rng(seed)
    scene = me.make_scene(rng, *shape, border=border)
    return rng, [me.render(scene, *shape, *pose(i)) for i in range(n)]


def looks(det, pictures, dt=0.125, t0=0.0):
    return [det.step(p, t0 + i * dt) for i, p in enumerate(pictures)]


class TestStillCamera(unittest.TestCase):
    def test_first_look_has_nothing_to_compare_with(self):
        rng, fr = frames_of(1, 2)
        det = mo.MotionDetector()
        first = det.step(me.add_noise(rng, fr[0]), 10.0)
        self.assertEqual((first["regions"], first["ego"], first["scene"]), ([], None, False))
        second = det.step(me.add_noise(rng, fr[1]), 10.125)
        self.assertIsNotNone(second["ego"])
        gap = det.step(me.add_noise(rng, fr[1]), 20.0)               # the watch stood still for ten seconds: start over
        self.assertIsNone(gap["ego"])
        back = det.step(me.add_noise(rng, fr[1]), 19.0)              # a clock that jumped back is a gap too
        self.assertIsNone(back["ego"])

    def test_noise_alone_is_not_movement(self):
        for noise in (me.DAY, me.NIGHT):
            rng, fr = frames_of(2, 40)
            res = looks(mo.MotionDetector("high"), [me.add_noise(rng, f, noise) for f in fr])
            self.assertEqual(sum(len(r["regions"]) for r in res), 0, f"noise {noise}")
            self.assertFalse(any(r["scene"] for r in res))
            self.assertFalse(any(r["ego"]["moving"] for r in res[1:]))

    def test_a_moving_target_is_found_where_it_is(self):
        r = me.synthetic(11, shape=SHAPE, looks=30, size=8, contrast=25, speed=2)
        self.assertGreaterEqual(r["hits"], 0.9 * r["looks_with_target"], r)
        self.assertEqual(r["false_regions"], 0, r)

    def test_regions_are_fractions_inside_the_picture(self):
        rng, fr = frames_of(3, 20)
        boxes = me.target_path(rng, 20, SHAPE, 10, 3)
        det, seen = mo.MotionDetector(), 0
        for i, (f, b) in enumerate(zip(fr, boxes)):
            for x, y, w, h, s in det.step(me.add_noise(rng, me.add_target(f, b, 40)), i * 0.125)["regions"]:
                seen += 1
                self.assertTrue(0 <= x <= 1 and 0 <= y <= 1 and 0 < w and 0 < h and x + w <= 1.0001 and y + h <= 1.0001)
                self.assertTrue(0 < s <= 1)
        self.assertGreater(seen, 5)

    def test_flickering_lamp_and_exposure_changes_are_not_movement(self):
        for kw in ({"flicker": 0.05}, {"exposure": 0.02}, {"flicker": 0.05, "noise": me.NIGHT}):
            r = me.synthetic(21, shape=SHAPE, looks=40, target=False, **kw)
            self.assertEqual(r["false_regions"], 0, (kw, r))
            self.assertEqual(r["scene_changes"], 0, (kw, r))

    def test_a_target_is_found_under_a_flickering_lamp(self):
        r = me.synthetic(22, shape=SHAPE, looks=30, flicker=0.05)
        self.assertGreaterEqual(r["hits"], 0.9 * r["looks_with_target"], r)
        self.assertEqual(r["false_regions"], 0, r)                   # the target must not light up its rows

    def test_a_slow_target_is_found_by_the_picture_of_a_second_ago(self):
        r = me.synthetic(31, shape=SHAPE, looks=44, speed=0.25)      # a quarter of a pixel per look
        self.assertGreaterEqual(r["hits"], 0.9 * r["looks_with_target"], r)
        self.assertEqual(r["false_regions"], 0, r)

    def test_a_new_scene_is_a_scene_change_not_a_thousand_regions(self):
        rng, a = frames_of(4, 12)
        _, b = frames_of(99, 12)
        det = mo.MotionDetector()
        res = looks(det, [me.add_noise(rng, f) for f in a + b])
        self.assertTrue(res[12]["scene"])
        self.assertEqual(res[12]["regions"], [])
        self.assertEqual(sum(len(r["regions"]) for r in res[14:]), 0)       # quiet again once the new scene is known

    def test_lens_covered_in_the_dark_gives_no_alarm(self):
        rng = np.random.default_rng(5)
        dark = [np.clip(rng.normal(3, 1.5, SHAPE), 0, 255).astype(np.uint8) for _ in range(30)]
        res = looks(mo.MotionDetector("high"), dark)
        self.assertEqual(sum(len(r["regions"]) for r in res), 0)
        self.assertFalse(res[-1]["ego"]["known"])                    # nothing to hold on to: said, not guessed


class TestMovingCamera(unittest.TestCase):
    def test_shift_is_measured_and_taken_out(self):
        rng, fr = frames_of(6, 24, shape=(180, 320), pose=lambda i: (1.25 * i, -0.75 * i, 0.0, 1.0), border=40)
        res = looks(mo.MotionDetector("high"), [me.add_noise(rng, f) for f in fr])
        for r in res[1:]:
            self.assertTrue(r["ego"]["moving"])
            self.assertLess(max(abs(r["ego"]["a"]), abs(r["ego"]["b"])), 0.002)   # at most 0.3 pixel at the edge made up from the tiles' scatter
            self.assertAlmostEqual(r["ego"]["dx"], 1.25, delta=0.15)
            self.assertAlmostEqual(r["ego"]["dy"], -0.75, delta=0.15)
        self.assertEqual(sum(len(r["regions"]) for r in res), 0)

    @scipy_only
    def test_rotation_and_zoom_are_taken_out(self):
        r = me.synthetic(41, shape=SHAPE, looks=36, target=False, pan=1.5, rot=0.3, zoom=0.004, sensitivity="high")
        self.assertEqual(r["false_regions"], 0, r)
        self.assertEqual(r["scene_changes"], 0, r)
        self.assertEqual(r["looks_camera_moving"], r["looks"])

    @scipy_only
    def test_rotation_is_measured(self):
        rng, fr = frames_of(7, 10, shape=(180, 320), pose=lambda i: (0.0, 0.0, 0.4 * i, 1.0), border=32)
        res = looks(mo.MotionDetector(), [me.add_noise(rng, f) for f in fr])
        turn = [abs(r["ego"]["b"]) for r in res[1:]]
        self.assertAlmostEqual(float(np.median(turn)), math.radians(0.4), delta=math.radians(0.4) * 0.25)
        self.assertEqual(sum(len(r["regions"]) for r in res), 0)

    @scipy_only
    def test_a_target_is_found_while_the_camera_pans(self):
        r = me.synthetic(51, shape=SHAPE, looks=36, pan=2.3, jitter=0.3, size=8, contrast=30, speed=5.5)
        self.assertGreaterEqual(r["hits"], 0.8 * r["looks_with_target"], r)
        self.assertEqual(r["false_regions"], 0, r)

    def test_whole_pixel_pan_without_scipy(self):
        # speed 5 against a pan of 2: whatever the two directions, the target moves 3 pixels per look over the ground
        with mock.patch.object(mo, "ndi", None):
            r = me.synthetic(61, shape=SHAPE, looks=30, pan=2.0, size=8, contrast=30, speed=5, target=True)
            quiet = me.synthetic(62, shape=SHAPE, looks=30, pan=2.0, target=False)
        self.assertGreaterEqual(r["hits"], 0.8 * r["looks_with_target"], r)
        self.assertEqual((r["false_regions"], quiet["false_regions"]), (0, 0), (r, quiet))

    def test_movement_that_was_not_measured_gives_no_regions(self):
        """In a dim, flat scene the correlation finds nothing to hold on to (seen on the real camera at 12 lux). If
        the camera moves then, edges all over the picture differ: that must be reported as "the picture changed",
        not as things that move."""
        # a small movement the tiles did not give: the edges of the picture give it (and it is taken out)
        rng, fr = frames_of(81, 24, pose=lambda i: (1.5 * i, -0.5 * i, 0.0, 1.0), border=44)
        det = mo.MotionDetector("high")
        with mock.patch.object(det, "_fit", lambda d, w: None):      # as if no tile could be used
            res = looks(det, [me.add_noise(rng, f) for f in fr])
        self.assertEqual(sum(len(r["regions"]) for r in res), 0)
        self.assertEqual(sum(r["scene"] for r in res), 0)
        for r in res[1:]:
            self.assertTrue(r["ego"]["known"] and r["ego"]["refined"] and r["ego"]["moving"])
            self.assertAlmostEqual(r["ego"]["dx"], 1.5, delta=0.3)
            self.assertAlmostEqual(r["ego"]["dy"], -0.5, delta=0.3)
        # a larger one: the small pictures measure it in most looks; in the others it is said that the picture changed
        rng, fr = frames_of(83, 16, pose=lambda i: (9.0 * i, 4.0 * i, 0.0, 1.0), border=150)
        det = mo.MotionDetector("high")
        with mock.patch.object(det, "_fit", lambda d, w: None):
            res = looks(det, [me.add_noise(rng, f) for f in fr])
        self.assertEqual(sum(len(r["regions"]) for r in res), 0)
        for r in res[1:]:
            self.assertTrue(r["scene"] or (abs(r["ego"]["dx"] - 9.0) < 0.5 and abs(r["ego"]["dy"] - 4.0) < 0.5), r["ego"])
        self.assertGreaterEqual(sum(not r["scene"] for r in res[1:]), 8)
        # one that nothing can measure: no regions, and it is said that the picture changed
        rng, fr = frames_of(83, 16, pose=lambda i: (30.0 * i, 12.0 * i, 0.0, 1.0), border=480)
        det = mo.MotionDetector("high")
        with mock.patch.object(det, "_fit", lambda d, w: None):
            res = looks(det, [me.add_noise(rng, f) for f in fr])
        self.assertEqual(sum(len(r["regions"]) for r in res), 0)
        self.assertGreaterEqual(sum(r["scene"] for r in res[1:]), 13)

    def test_under_way_and_no_measure_of_the_cameras_movement_means_no_report(self):
        """A dark, flat scene gives no way to measure how the camera moved. At rest that is fine (a thing that
        moves is still seen). Under way - the GNSS says so - what differs may be the ground going by: no report."""
        rng = np.random.default_rng(84)
        flat = np.full((180, 320), 60.0, np.float32)
        boxes = me.target_path(rng, 30, (180, 320), 10, 3)
        pictures = [me.add_noise(rng, me.add_target(flat.copy(), b, 40)) for b in boxes]
        det = mo.MotionDetector()
        at_rest = [det.step(p, i * 0.125) for i, p in enumerate(pictures)]
        det = mo.MotionDetector()
        under_way = [det.step(p, i * 0.125, platform_moving=True) for i, p in enumerate(pictures)]
        # the one thing in an empty picture is a thing that moves, not a camera that pans (it was taken for one)
        self.assertGreater(sum(bool(r["regions"]) for r in at_rest), 24)
        self.assertFalse(any(r["ego"]["known"] or r["ego"]["moving"] for r in at_rest[1:]))
        self.assertEqual(sum(len(r["regions"]) for r in under_way), 0)
        self.assertTrue(all(r["scene"] for r in under_way[1:]))
        # with a scene that can be measured, being under way changes nothing
        r = me.synthetic(85, shape=SHAPE, looks=30, pan=2.0, size=8, contrast=30, speed=5)
        self.assertGreaterEqual(r["hits"], 0.8 * r["looks_with_target"], r)

    def test_gnss_speed_tells_the_watch_that_the_uav_is_under_way(self):
        from kyber6g.uav.main import UavApp
        app = UavApp.__new__(UavApp)
        for snap, want in (({"mode": 3, "speed_mps": 4.2}, True), ({"mode": 3, "speed_mps": 0.3}, False),
                           ({"mode": 0, "speed_mps": 9.0}, False), ({"mode": 2, "speed_mps": None}, False), ({}, False)):
            app.gnss = SimpleNamespace(snapshot=lambda s=snap: s)
            self.assertIs(app.platform_moving(), want, snap)

    def test_a_large_thing_nearby_is_still_a_thing(self):
        """The safeguard above must not swallow a real, large mover: its edges change where it is, not everywhere."""
        rng, fr = frames_of(82, 30)
        boxes = me.target_path(rng, 30, SHAPE, 40, 3)                # 40 x 53 pixels of a 192 x 120 picture
        det, hits = mo.MotionDetector(), 0
        for i, (f, b) in enumerate(zip(fr, boxes)):
            res = det.step(me.add_noise(rng, me.add_target(f, b, 35)), i * 0.125)
            self.assertFalse(res["scene"])
            hits += me.judge(res["regions"], b, SHAPE)[0]
        self.assertGreaterEqual(hits, 24)

    def test_a_turn_too_far_between_two_looks_is_a_scene_change(self):
        rng, fr = frames_of(8, 6, pose=lambda i: (60.0 * (i % 2), 0.0, 0.0, 1.0), border=72)
        res = looks(mo.MotionDetector(), [me.add_noise(rng, f) for f in fr])
        self.assertTrue(all(r["scene"] or not r["regions"] for r in res))


class TestWhatTheFirstMeasurementsShowed(unittest.TestCase):
    """Two faults that the first measurement campaign brought out (5 October 2026). Both tests fail with the code
    as it was then."""
    DARK = dict(flat=0.03, noise=me.NIGHT, row_noise=1.5)        # a dark room: hardly any structure, a sensor at high gain

    def test_more_contrast_is_never_found_less_often(self):
        """A target of medium contrast was found in FEWER looks than a fainter one (at night: 48 of 96 looks at
        contrast 16 against 58 at contrast 12): where the comparison of neighbouring looks had lit up now and then,
        the comparison with the picture of a second ago was closed. The two no longer know of each other."""
        seeds = (7000, 7131, 7262)
        for kw, (fainter, stronger) in ((dict(noise=me.NIGHT), (12, 16)), (dict(sensitivity="low"), (8, 12))):
            found = [sum(me.synthetic(s, shape=SHAPE, contrast=c, **kw)["hits"] for s in seeds) for c in (fainter, stronger)]
            self.assertLess(found[0], found[1], (kw, found))
            self.assertGreaterEqual(found[1], 86, (kw, found))   # of 96 looks with a target

    def test_a_lamp_in_a_dark_room_that_the_camera_passes_is_not_a_thing_that_moves(self):
        """On the real camera in NIGHT mode a pan of 2 pixels per look was not measured, and what was lit in the
        room was reported as moving in 95 of 102 looks. The same scene, generated: the pan must be measured (on the
        small pictures, where the noise is averaged away) and nothing reported."""
        r = me.synthetic(7000, target=False, lamps=1, pan=2, **self.DARK)
        self.assertEqual(r["false_regions"], 0, r)
        self.assertGreaterEqual(r["looks_camera_known"], r["looks"] - 2, r)
        self.assertAlmostEqual(r["camera_shift_sum"] / r["looks"], 2.0, delta=0.2)
        still = me.synthetic(7000, target=False, lamps=1, **self.DARK)
        self.assertEqual(still["false_regions"], 0, still)
        self.assertLessEqual(still["looks_camera_moving"], 1, still)

    def test_a_thing_carried_through_a_dark_room_is_a_thing_that_moves(self):
        """The other side of the same question: the camera stands still and ONE bright thing moves. It must not be
        taken for a pan (the rest of the picture does not move with it). Under way, where what differs may be the
        ground going by and the picture cannot say, nothing is reported."""
        kw = dict(contrast=40, size=10, speed=3, **self.DARK)
        r = me.synthetic(7000, **kw)
        self.assertGreaterEqual(r["hits"], 0.9 * r["looks_with_target"], r)
        self.assertEqual(r["false_regions"], 0, r)
        way = me.synthetic(7000, under_way=True, **kw)
        self.assertLessEqual(way["hits"], 2, way)
        self.assertGreaterEqual(way["scene_changes"], 0.8 * way["looks"], way)

    def test_it_is_known_whether_a_picture_would_show_a_misfit(self):
        """`known` is also true when nothing measured the camera's movement but the picture has enough in it that a
        misfit of a pixel would have shown; a blank picture gives no such assurance (and no regions)."""
        rng, fr = frames_of(5, 12)
        det = mo.MotionDetector()
        with mock.patch.object(det, "_fit", lambda d, w: None):      # as if no tile could be used
            res = looks(det, [me.add_noise(rng, f) for f in fr])
        self.assertTrue(all(r["ego"]["known"] and not r["ego"]["moving"] for r in res[1:]))
        blank = [me.add_noise(rng, np.full(SHAPE, 60.0, np.float32), me.NIGHT) for _ in range(12)]
        res = looks(mo.MotionDetector(), blank)
        self.assertFalse(any(r["ego"]["known"] for r in res[1:]))
        self.assertEqual(sum(len(r["regions"]) for r in res), 0)


class TestHabitAndSettings(unittest.TestCase):
    def test_something_that_never_stops_is_muted_and_the_rest_is_still_seen(self):
        rng = np.random.default_rng(9)
        scene = me.make_scene(rng, *SHAPE, border=8)
        base = me.render(scene, *SHAPE)
        det, dt, with_region = mo.MotionDetector(), 0.125, []
        for i in range(400):                                         # 50 s: a "screen" of 16 x 16 pixels that changes every look
            f = base.copy()
            f[20:36, 20:36] += rng.uniform(-60, 60)
            with_region.append(bool(det.step(me.add_noise(rng, f), i * dt)["regions"]))
        self.assertGreater(sum(with_region[:80]), 60)                # reported at first
        self.assertEqual(sum(with_region[-80:]), 0)                  # then known as part of the scene
        boxes = me.target_path(rng, 30, SHAPE, 8, 2)
        boxes = [(b[0], 70.0, b[2], b[3]) for b in boxes]            # a target elsewhere in the picture
        hits = 0
        for j, b in enumerate(boxes):
            f = base.copy()
            f[20:36, 20:36] += rng.uniform(-60, 60)
            res = det.step(me.add_noise(rng, me.add_target(f, b, 30)), (400 + j) * dt)
            hits += me.judge(res["regions"], b, SHAPE)[0]
            self.assertGreater(res["muted"], 0)
        self.assertGreaterEqual(hits, 24)

    def test_sensitivity(self):
        with self.assertRaises(ValueError):
            mo.MotionDetector("extreme")
        found = {}
        for level in ("low", "medium", "high"):
            runs = [me.synthetic(70 + s, shape=SHAPE, looks=30, size=5, contrast=7, speed=2, sensitivity=level) for s in range(3)]
            found[level] = sum(r["hits"] for r in runs)
            self.assertEqual(sum(r["false_regions"] for r in runs), 0)
        self.assertLessEqual(found["low"], found["medium"])
        self.assertLessEqual(found["medium"], found["high"])
        self.assertLess(found["low"], found["high"])

    def test_picture_size(self):
        det = mo.MotionDetector()
        with self.assertRaises(ValueError):
            det.step(np.zeros((16, 16), np.uint8), 0.0)
        with self.assertRaises(ValueError):
            det.step(np.zeros((120, 160, 3), np.uint8), 0.0)
        rng, fr = frames_of(10, 3)
        det.step(me.add_noise(rng, fr[0]), 0.0)
        det.step(me.add_noise(rng, fr[1]), 0.125)
        other = det.step(np.zeros((96, 128), np.uint8), 0.25)        # the video settings changed: start over, no error
        self.assertIsNone(other["ego"])

    def test_events(self):
        st = mo.MotionState(hold=1.0)
        look = lambda t, n=0, scene=False: st.update({"ts": t, "regions": [[0, 0, .1, .1, .5]] * n, "scene": scene})
        self.assertIsNone(look(0.0))
        self.assertEqual(look(0.5, 1), "start")
        self.assertIsNone(look(0.75, 2))
        self.assertIsNone(look(1.0))                                 # a moment without a region is not the end
        self.assertIsNone(look(1.5, 1))
        self.assertIsNone(look(2.4))
        self.assertEqual(look(2.6), "end")
        self.assertIsNone(look(3.0, scene=True))
        self.assertEqual(look(4.0, 1), "start")
        s = st.summary()
        self.assertEqual((s["events"], s["on"], s["looks"], s["looks_with_motion"], s["scene_changes"]), (2, True, 9, 4, 1))
        self.assertEqual(s["last"], {"since": 0.5, "until": 1.5, "looks": 3})


class TestCameraServiceSettings(unittest.TestCase):
    """The settings of the watch, without a camera (the import of the camera library is made to fail)."""

    def cam(self, **cfg):
        from kyber6g.camera.camera import CameraService
        c = cfgmod.CameraConfig(**cfg)
        with mock.patch.dict(sys.modules, {"picamera2": None}):
            return CameraService(c, lambda *a: None)

    def test_size_of_the_small_picture(self):
        for (w, h), want in (((1280, 720), (320, 180)), ((1920, 1080), (320, 180)), ((640, 480), (320, 240)), ((320, 240), (320, 240))):
            self.assertEqual(self.cam(width=w, height=h)._lores_size(), want)

    def test_settings_are_checked(self):
        cam = self.cam()
        self.assertFalse(cam.available)
        st = cam.set_motion(enabled=False, sensitivity="high", hz=4)
        self.assertEqual((st["enabled"], st["sensitivity"], st["hz"], st["sentry"], st["watching"]), (False, "high", 4.0, False, False))
        for bad in ({"enabled": 1}, {"sentry": "yes"}, {"hz": 0.2}, {"hz": 100}, {"hz": True}, {"sensitivity": "max"}, {"sensitivity": 3}):
            with self.assertRaises(ValueError, msg=bad):
                cam.set_motion(**bad)
        with self.assertRaises(RuntimeError):                        # sentry needs a camera
            cam.set_motion(sentry=True)
        self.assertFalse(cam.motion_set["sentry"])
        self.assertEqual(cam.status()["motion"]["sensitivity"], "high")

    def test_self_test_scores_targets_drawn_into_the_cameras_own_pictures(self):
        import json
        import time
        cam = self.cam()
        with self.assertRaises(RuntimeError):                        # nothing to look at: the watch is not running
            cam.motion_selftest([{"size": 8}])
        cam.encoding = True                                          # as if the camera ran; the test plays the watch thread
        for bad in ([], "x", [{"size": 1000}], [{"pan": True}], [{}] * 49, [5]):
            with self.assertRaises(ValueError, msg=bad):
                cam.motion_selftest(bad)
        with self.assertRaises(ValueError):
            cam.motion_selftest([{}], looks=5)
        rng, pictures = frames_of(12, 32, shape=(180, 320))
        pictures = [me.add_noise(rng, f) for f in pictures]
        out = {}
        cases = [{"target": False}, {"size": 10, "contrast": 40, "speed": 3}, {"size": 10, "contrast": 40, "speed": 3, "pan": 2},
                 {"target": False, "pan": 2, "sensitivity": "high"}]
        t = threading.Thread(target=lambda: out.update(cam.motion_selftest(cases, looks=32, seed=3)))
        t.start()
        t0 = time.monotonic()
        while cam._grab is None and time.monotonic() - t0 < 5:
            time.sleep(0.01)
        grab = cam._grab
        for i, p in enumerate(pictures):
            grab["frames"].append(p)
            grab["ts"].append(100.0 + i * 0.125)
        grab["full"].set()
        t.join(120)
        self.assertIsNone(cam._grab)
        self.assertEqual((out["looks"], out["dt"], out["size"]), (32, 0.125, [320, 180]))
        quiet, hit, hit_pan, quiet_pan = out["results"]
        self.assertEqual((quiet["false_regions"], quiet_pan["false_regions"]), (0, 0))
        self.assertGreaterEqual(hit["hits"], 0.9 * hit["looks_with_target"])
        self.assertGreaterEqual(hit_pan["hits"], 0.8 * hit_pan["looks_with_target"])
        self.assertEqual(hit_pan["looks_camera_moving"], hit_pan["looks"])
        self.assertLess(len(json.dumps(out)), 3000)                  # numbers only: no picture leaves the function

    def test_watch_switched_off_in_the_settings(self):
        cam = self.cam(motion=False)
        self.assertEqual(cam.status()["motion"]["available"], False)
        with self.assertRaises(RuntimeError):
            cam.set_motion(enabled=True)


class TestReports(unittest.TestCase):
    def uav(self):
        from kyber6g.uav.main import UavApp
        app = UavApp.__new__(UavApp)
        app.cfg = cfgmod.UavConfig()
        app._cmds, app.sent, app.events, app.lcd = queue.Queue(maxsize=4), [], [], None
        app._msg_no, app._msg_lock = 0, threading.Lock()
        app.link = SimpleNamespace(send=lambda stream, piece, ext: app.sent.append((stream, piece)) or True)
        app.motion_state, app.motion_photo = mo.MotionState(hold=1.0), False
        app._motion_photo_at = app._motion_logged = 0.0
        app._motion_scene = False
        return app

    def test_reports_go_out_while_something_moves_and_when_it_ends(self):
        import json
        from kyber6g.crypto import keyschedule as ks
        app = self.uav()
        quiet = {"ts": 1.0, "regions": [], "scene": False, "ego": {"moving": False}}
        app.on_motion(quiet)
        self.assertEqual(app.sent, [])                               # nothing moves: nothing is sent
        app.on_motion({"ts": 2.0, "regions": [[.1, .2, .05, .05, .6]], "scene": False, "ego": {"moving": True}})
        stream, piece = app.sent[-1]
        m = json.loads(piece)
        self.assertEqual(stream, ks.STREAM_STATUS)
        self.assertEqual((m["t"], m["on"], m["ev"], m["cam"], m["regions"]), ("motion", True, "start", True, [[.1, .2, .05, .05, .6]]))
        self.assertLess(len(piece), 300)
        app.on_motion({**quiet, "ts": 2.5})
        self.assertEqual(json.loads(app.sent[-1][1])["on"], True)    # still held: reports continue
        app.on_motion({**quiet, "ts": 3.6})
        self.assertEqual(json.loads(app.sent[-1][1])["ev"], "end")
        n = len(app.sent)
        app.on_motion({**quiet, "ts": 4.0})
        self.assertEqual(len(app.sent), n)
        self.assertEqual([e["kind"] for e in app.events], ["MOTION"])

    def test_photo_on_motion_is_rationed(self):
        app = self.uav()
        app.motion_photo = True
        move = lambda t: app.on_motion({"ts": t, "regions": [[.1, .2, .05, .05, .6]], "scene": False, "ego": None})
        still = lambda t: app.on_motion({"ts": t, "regions": [], "scene": False, "ego": None})
        move(1.0); still(3.0); move(4.0); still(6.0); move(7.0)      # three movements within seconds
        queued = []
        while not app._cmds.empty():
            queued.append(app._cmds.get_nowait())
        self.assertEqual(queued, [{"t": "capture_image", "id": None, "trigger": "motion"}])

    def test_ground_station_takes_only_well_formed_reports(self):
        from kyber6g.ground.main import clean_motion
        good = {"t": "motion", "ts": 1.7e9, "on": True, "ev": "start", "since": 1.7e9, "regions": [[0, .5, .1, .1, 1]], "scene": False, "cam": True}
        self.assertEqual(clean_motion(good), {"ts": 1.7e9, "on": True, "ev": "start", "since": 1.7e9, "regions": [[0.0, .5, .1, .1, 1.0]],
                                              "scene": False, "cam": True})
        for bad in (None, [], {"ts": "now"}, {"ts": float("nan")}, {"regions": []}):
            self.assertIsNone(clean_motion(bad))
        odd = clean_motion({"ts": 5, "on": "yes", "ev": "<script>", "since": "x", "scene": 1, "cam": None,
                            "regions": [[0, 0, 2, 1, 1], [0, 0, .1, .1], "x", [True, 0, .1, .1, .5], [0, 0, .1, .1, .5]] + [[0, 0, .1, .1, .5]] * 20})
        self.assertEqual((odd["on"], odd["ev"], odd["since"], odd["scene"], odd["cam"]), (False, None, None, False, False))
        self.assertEqual(odd["regions"], [[0.0, 0.0, .1, .1, .5]] * 4)       # the first eight are looked at, the bad ones dropped

    def test_ground_station_logs_a_movement_and_keeps_the_report_for_the_overlay(self):
        from kyber6g.ground.main import GroundApp
        app = GroundApp.__new__(GroundApp)
        app.notes = []
        app.note = lambda kind, msg: app.notes.append((kind, msg))
        app.motion = {"last": None, "rx_at": None, "reports": 0, "events": 0, "malformed": 0, "since": None, "last_event": None}
        self.assertIsNone(app.motion_latest())
        app._motion({"t": "motion", "ts": 100.0, "on": True, "ev": "start", "since": 100.0, "regions": [[.1, .1, .1, .1, .5]]})
        self.assertEqual(app.motion_latest()["regions"], [[.1, .1, .1, .1, .5]])
        app._motion({"t": "motion", "ts": 104.0, "on": False, "ev": "end", "regions": []})
        app._motion({"t": "motion", "ts": "x"})
        self.assertEqual((app.motion["events"], app.motion["reports"], app.motion["malformed"]), (1, 2, 1))
        self.assertEqual(app.motion["last_event"], {"since": 100.0, "until": 104.0, "seconds": 4.0})
        self.assertEqual([k for k, _ in app.notes], ["MOTION", "MOTION"])
        self.assertIn("after 4 s", app.notes[1][1])
        for i in range(5):                                           # a thing that starts and stops every second: one line, not five
            app._motion({"t": "motion", "ts": 110.0 + i, "on": True, "ev": "start", "regions": [[.1, .1, .1, .1, .5]]})
            app._motion({"t": "motion", "ts": 110.5 + i, "on": False, "ev": "end", "regions": []})
        self.assertEqual(len(app.notes), 2)
        self.assertEqual(app.motion["events"], 6)


if __name__ == "__main__":
    unittest.main()
