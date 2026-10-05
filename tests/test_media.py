import os
import random
import struct
import tempfile
import time
import unittest
from pathlib import Path

from kyber6g.crypto import identity as idm
from kyber6g.ground.video_sink import VIDEO_EXT, VideoSink
from kyber6g.recording.recorder import EncryptedRecorder, RecordingError, decrypt_recording
from kyber6g.transport.blob import BlobReceiver, BlobSender


class TestRecording(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Path(tempfile.mkdtemp())
        cls.ek = idm.generate_recording_kem(cls.d)
        cls.dk = (cls.d / "gcs_recording_ML-KEM-1024.dk").read_bytes()

    def record(self, n=95):
        rec = EncryptedRecorder(self.d / "rec", self.ek, {"codec": "h264", "fps": 30})
        frames = []
        for i in range(n):
            data = os.urandom(random.randint(200, 3000))
            frames.append(data)
            rec.add_frame(data, keyframe=(i % 30 == 0), ts_us=i * 33333)
        summary = rec.close()
        return rec.path, b"".join(frames), summary

    def test_roundtrip(self):
        path, plain, summary = self.record()
        hdr, h264, rep = decrypt_recording(path, self.dk)
        self.assertEqual(h264, plain)
        self.assertTrue(rep["complete"])
        self.assertEqual(rep["segments"], 4)          # 3 GOPs + final
        self.assertNotIn(plain[:64], path.read_bytes())  # no plaintext at rest

    def test_tamper_detected(self):
        path, _, _ = self.record()
        raw = bytearray(path.read_bytes())
        raw[-100] ^= 1
        path.write_bytes(bytes(raw))
        with self.assertRaises(RecordingError):
            decrypt_recording(path, self.dk)

    def test_truncation_detected(self):
        path, _, _ = self.record()
        raw = path.read_bytes()
        path.write_bytes(raw[:len(raw) // 2])
        try:
            _, _, rep = decrypt_recording(path, self.dk)
            self.assertFalse(rep["complete"])
        except RecordingError:
            pass  # cut inside a segment is also detected

    def test_wrong_key(self):
        path, _, _ = self.record(10)
        other = Path(tempfile.mkdtemp())
        idm.generate_recording_kem(other)
        with self.assertRaises(RecordingError):
            decrypt_recording(path, (other / "gcs_recording_ML-KEM-1024.dk").read_bytes())

    def test_live_status_for_rec_indicator(self):
        rec = EncryptedRecorder(self.d / "rec", self.ek, {"codec": "h264", "fps": 30})
        rec.add_frame(b"p" * 100, keyframe=False, ts_us=0)            # before first IDR: skipped
        for i in range(61):
            rec.add_frame(b"x" * 1000, keyframe=(i % 30 == 0), ts_us=(i + 1) * 33333)
        st = rec.live_status()
        self.assertEqual(st["recording_frames"], 61)
        self.assertAlmostEqual(st["recording_media_s"], 2.0, places=1)
        self.assertGreaterEqual(st["recording_elapsed_s"], 0)
        self.assertGreater(st["recording_bytes"], 61 * 1000)
        rec.close()
        self.assertLessEqual(abs(rec.file_bytes - rec.path.stat().st_size), 0)

    def test_abort_leaves_no_orphan(self):
        rec = EncryptedRecorder(self.d / "abort", self.ek, {"codec": "h264"})
        self.assertTrue(rec.path.exists())
        rec.abort()
        self.assertFalse(rec.path.exists())


class TestRollingRecorder(unittest.TestCase):
    """A long recording is split into parts that each decrypt on their own and stay below the transfer limit."""

    @classmethod
    def setUpClass(cls):
        cls.d = Path(tempfile.mkdtemp())
        cls.ek = idm.generate_recording_kem(cls.d)
        cls.dk = (cls.d / "gcs_recording_ML-KEM-1024.dk").read_bytes()

    def test_long_recording_splits_into_independent_parts(self):
        from kyber6g.recording.recorder import RollingRecorder
        rec = RollingRecorder(self.d / "roll", self.ek, {"codec": "h264", "fps": 30}, max_bytes=60_000)
        frames = []
        rec.add_frame(b"p" * 100, keyframe=False, ts_us=0)               # before the first IDR: skipped, as before
        for i in range(300):
            data = os.urandom(1000)
            frames.append(data)
            rec.add_frame(data, keyframe=(i % 30 == 0), ts_us=(i + 1) * 33333)
        st = rec.live_status()
        self.assertEqual(st["recording_frames"], 300)                     # the REC indicator counts across parts
        self.assertGreater(st["recording_part"], 2)
        self.assertGreater(st["recording_bytes"], 300 * 1000)
        self.assertEqual(st["recording_first"], rec.name)
        current = rec.current_name
        self.assertNotEqual(current, rec.name)                            # finished parts are fetchable while recording
        summary = rec.close()
        self.assertGreater(len(summary["parts"]), 2)
        self.assertEqual((summary["name"], summary["parts"][0], summary["parts"][-1]), (rec.name, rec.name, current))
        self.assertEqual(summary["frames"], 300)
        self.assertEqual(summary["plain_bytes"], 300 * 1000)
        self.assertEqual(summary["skipped_before_first_idr"], 1)
        out = b""
        for n, name in enumerate(summary["parts"], 1):
            path = self.d / "roll" / name
            hdr, h264, rep = decrypt_recording(path, self.dk)
            self.assertTrue(rep["complete"], name)                        # every part has its own FINAL segment
            self.assertEqual(hdr["part"], n)
            self.assertLess(path.stat().st_size, 60_000 + 31 * 1100)      # limit + at most one GOP
            self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
            out += h264
        self.assertEqual(out, b"".join(frames))                          # nothing lost or repeated at the joins
        self.assertEqual(summary["file_bytes"], sum((self.d / "roll" / n).stat().st_size for n in summary["parts"]))
        self.assertIsNone(rec.close())                                   # a second close is harmless
        rec.add_frame(b"late", True, 0)                                  # and so is a late frame

    def test_short_recording_stays_one_file(self):
        from kyber6g.recording.recorder import RollingRecorder
        rec = RollingRecorder(self.d / "short", self.ek, {"codec": "h264", "fps": 30})
        for i in range(60):
            rec.add_frame(b"x" * 500, keyframe=(i % 30 == 0), ts_us=i * 33333)
        self.assertEqual(rec.current_name, rec.name)
        s = rec.close()
        self.assertEqual((s["parts"], s["frames"], s["segments"]), ([rec.name], 60, 2))      # two GOPs, the second one FINAL
        self.assertGreater(s["throughput_MBps"], 0)
        self.assertEqual(len(list((self.d / "short").glob("*.k6grec"))), 1)

    def test_abort_before_the_first_frame_leaves_no_file(self):
        from kyber6g.recording.recorder import RollingRecorder
        rec = RollingRecorder(self.d / "abort2", self.ek, {"codec": "h264"})
        rec.abort()
        self.assertEqual(list((self.d / "abort2").glob("*")), [])
        self.assertEqual(rec.live_status()["recording_name"], None)


class TestPhotos(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Path(tempfile.mkdtemp())
        cls.ek = idm.generate_recording_kem(cls.d)
        cls.dk = (cls.d / "gcs_recording_ML-KEM-1024.dk").read_bytes()

    def test_store_roundtrip_and_no_plaintext(self):
        from kyber6g.recording.photos import PhotoStore, open_image
        st = PhotoStore(self.d / "photos", self.ek)
        jpeg = b"\xff\xd8" + os.urandom(50000) + b"\xff\xd9"
        info = st.save("img_20261003_101010.jpg", jpeg, {"width": 1280, "height": 720, "mode": "NORMAL"})
        raw = st.read(info["stored_as"])
        self.assertNotIn(jpeg[100:164], raw)
        self.assertEqual(oct((self.d / "photos" / info["stored_as"]).stat().st_mode & 0o777), "0o600")
        hdr, out = open_image(raw, self.dk)
        self.assertEqual(out, jpeg)
        self.assertEqual(hdr["width"], 1280)
        self.assertEqual(st.list()[0]["name"], "img_20261003_101010.k6gimg")
        self.assertEqual(st.usage()["count"], 1)

    def test_tamper_and_wrong_key(self):
        from kyber6g.recording.photos import PhotoError, open_image, seal_image
        raw = bytearray(seal_image(self.ek, b"jpegdata" * 100, {"width": 1}))
        for pos in (20, len(raw) - 5, len(raw) // 2):          # header json, body, KEM ct region
            bad = bytearray(raw)
            bad[pos] ^= 1
            with self.assertRaises(PhotoError):
                open_image(bytes(bad), self.dk)
        with self.assertRaises(PhotoError):
            open_image(bytes(raw[:-20]), self.dk)            # truncated body
        with self.assertRaises(PhotoError):
            open_image(bytes(raw[:1000]), self.dk)           # truncated inside the KEM ciphertext
        other = Path(tempfile.mkdtemp())
        idm.generate_recording_kem(other)
        with self.assertRaises(PhotoError):
            open_image(bytes(raw), (other / "gcs_recording_ML-KEM-1024.dk").read_bytes())

    def test_store_rejects_path_traversal(self):
        from kyber6g.recording.photos import PhotoStore
        st = PhotoStore(self.d / "photos2", self.ek)
        with self.assertRaises(FileNotFoundError):
            st.read("../../etc/passwd")


class TestBlob(unittest.TestCase):
    def test_lossy_transfer_with_nacks(self):
        rng = random.Random(7)
        inbox, ctrl_to_sender, done = [], [], []
        def lossy_send(stream, payload, ext):
            if rng.random() > 0.2:              # 20 % loss
                inbox.append((ext, payload))
            return True
        sender = BlobSender(lossy_send, pace_s=0)
        recv = BlobReceiver(lambda m: ctrl_to_sender.append(m), lambda info, data: done.append((info, data)))
        data = os.urandom(300_000)
        sender.send(3, "image", "x.jpg", data, {"w": 1})
        t0 = time.time()
        while not done and time.time() - t0 < 20:
            time.sleep(0.02)
            while inbox:
                recv.on_record(*inbox.pop(0))
            for _ in range(len(ctrl_to_sender)):
                sender.on_control(ctrl_to_sender.pop(0))
            recv.tick()
        self.assertTrue(done)
        info, got = done[0]
        self.assertEqual(info["integrity"], "PASS")
        self.assertEqual(got, data)

    def test_oversize_file_is_refused_before_anything_is_sent(self):
        from unittest import mock
        sent = []
        sender = BlobSender(lambda *a: sent.append(a) or True, pace_s=0)
        with mock.patch("kyber6g.transport.blob.MAX_BLOB", 5000):
            with self.assertRaises(ValueError) as cm:
                sender.send(4, "recording", "huge.k6grec", b"x" * 6000)
        self.assertIn("transfer limit", str(cm.exception))
        self.assertEqual((sent, sender.active), ([], {}))

    def test_a_slow_transfer_is_kept_and_a_stalled_one_is_reported(self):
        failed, done = [], []
        recv = BlobReceiver(lambda m: None, lambda info, data: done.append(info), on_fail=lambda info, got: failed.append((info, got)))
        meta = {"id": "aabbccdd", "kind": "recording", "name": "r.k6grec", "size": 3300, "sha256": "0" * 64, "chunks": 3, "meta": {}}
        bid = bytes.fromhex("aabbccdd")
        recv.on_record(b"M" + bid, __import__("json").dumps(meta).encode())
        recv.on_record(b"C" + bid + struct.pack("!I", 0), b"a" * 1100)
        e = recv.rx[bid]
        e["t0"] -= 600                                   # ten minutes old, but data is still arriving: must be kept
        recv.tick()
        self.assertIn(bid, recv.rx)
        self.assertEqual(failed, [])
        e["progress"] -= 31                              # nothing new for 31 s: stalled
        recv.tick()
        self.assertNotIn(bid, recv.rx)
        self.assertEqual((recv.failed, failed[0][0]["name"], failed[0][1]), (1, "r.k6grec", 1))
        self.assertEqual(done, [])

    def test_chunks_without_metadata_are_not_buffered_without_limit(self):
        recv = BlobReceiver(lambda m: None, lambda info, data: None)
        bid = b"\x01\x02\x03\x04"
        for i in range(5000):
            recv.on_record(b"C" + bid + struct.pack("!I", i), b"z" * 10)
        self.assertLessEqual(len(recv.rx[bid]["parts"]), 4097)
        recv.on_record(b"M" + bid, b'[1, 2, 3]')          # valid JSON that is not a metadata object
        self.assertNotIn(bid, recv.rx)

    def test_sender_forgets_idle_transfers_not_active_ones(self):
        sender = BlobSender(lambda *a: True, pace_s=0)
        info = sender.send(3, "image", "x.jpg", b"d" * 5000)
        bid = bytes.fromhex(info["id"])
        time.sleep(0.2)
        sender.active[bid]["t0"] -= 900                  # an old transfer the receiver is still asking about
        sender.on_control({"t": "blob_nack", "id": info["id"], "missing": [1], "meta": False})
        sender.expire()
        self.assertIn(bid, sender.active)
        sender.active[bid]["last"] -= 61                 # nobody asked for a minute
        sender.expire()
        self.assertNotIn(bid, sender.active)


class TestVideoSink(unittest.TestCase):
    def sink(self):
        s = VideoSink(jitter_ms=50, clock_offset=lambda: 0.0)
        s.fed = []
        s._ensure_decoder = lambda: None
        s.inq.put_nowait = lambda item: s.fed.append(item)
        return s

    def test_rates_read_zero_when_the_stream_stops(self):
        s = self.sink()
        for fid in range(8):
            for ext, p in self.chunks(fid, b"K" * 250, fid == 0):
                s.on_chunk(ext, p)
            time.sleep(0.03)
        st = s.stats()
        self.assertTrue(st["streaming"])
        self.assertGreater(st["fps"], 5)
        s._last_frame -= 5                               # no frame for 5 s
        st = s.stats()
        self.assertEqual((st["streaming"], st["fps"], st["kbps"]), (False, 0.0, 0.0))
        self.assertGreaterEqual(st["frame_age_s"], 5)
        self.assertEqual(st["frames_complete"], 8)       # totals are kept

    def test_a_wall_clock_step_does_not_lose_the_frame_being_received(self):
        """The host's time sync pushed the WSL wall clock forward by 2.9 s every 35 s. With wall-clock ages the frame
        that was half received at that instant looked 2.9 s old and was counted as lost (and the picture froze until
        the next keyframe). Ages are measured on the monotonic clock, which cannot be stepped."""
        from unittest import mock
        s = self.sink()
        for ext, p in self.chunks(0, b"K" * 250, True):
            s.on_chunk(ext, p)
        parts = self.chunks(1, b"P" * 250, False)
        s.on_chunk(*parts[0])                            # frame 1 is half received ...
        real = time.time
        with mock.patch("kyber6g.ground.video_sink.time.time", lambda: real() + 2.9):     # ... when the wall clock jumps
            with s.lock:
                s._deliver()
            for ext, p in parts[1:]:
                s.on_chunk(ext, p)
        self.assertEqual(s.s["frames_lost"], 0)
        self.assertEqual([x[1][:1] for x in s.fed], [b"K", b"P"])
        self.assertTrue(s.stats()["streaming"])

    def test_an_interrupted_stream_resumes_at_the_next_keyframe_and_is_not_counted_as_lost_frames(self):
        """The laptop went into standby for 43 minutes while the UAV kept streaming. On wake-up the frame numbers had
        advanced by ~77,000; the sink walked through every one of them and reported 92,966 'frames lost'."""
        s = self.sink()
        for fid in range(3):
            for ext, p in self.chunks(fid, (b"K" if fid == 0 else b"P") * 250, fid == 0):
                s.on_chunk(ext, p)
        for fid in (77000, 77001):                       # ... 43 minutes later
            for ext, p in self.chunks(fid, (b"L" if fid == 77000 else b"Q") * 250, fid == 77000):
                s.on_chunk(ext, p)
        time.sleep(0.12)
        with s.lock:
            s._deliver()
        self.assertEqual([x[1][:1] for x in s.fed], [b"K", b"P", b"P", b"L", b"Q"])
        self.assertEqual((s.s["frames_lost"], s.s["stream_gaps"], s.s["last_gap"]), (0, 1, "stream interrupted"))
        for ext, p in self.chunks(76999, b"x" * 250, False):     # a straggler from just before: late, ignored
            s.on_chunk(ext, p)
        self.assertEqual((s.s["late_chunks"], len(s.fed)), (3, 5))
        # the UAV app restarted: its frame numbers start at 0 again. Must play without anybody pressing LIVE.
        for fid in range(2):
            for ext, p in self.chunks(fid, (b"N" if fid == 0 else b"R") * 250, fid == 0):
                s.on_chunk(ext, p)
        self.assertEqual([x[1][:1] for x in s.fed][-2:], [b"N", b"R"])
        self.assertEqual((s.s["stream_gaps"], s.s["last_gap"], s.s["frames_lost"]), (2, "frame numbering restarted", 0))

    def test_frame_rate_is_not_inflated_by_bursty_delivery(self):
        """A busy machine delivers a 30 fps stream in bursts; the dashboard read 34.5 'fps' from a 30 fps camera."""
        from unittest import mock
        s = self.sink()
        s.need_key = False
        clock = [1000.0]
        with mock.patch("kyber6g.ground.video_sink.time.monotonic", lambda: clock[0]):
            seen = []
            for burst in range(16):                      # 8 s of video, 15 frames arriving together every 0.5 s
                for i in range(15):
                    clock[0] = 1000.0 + burst * 0.5 + i * 0.001
                    s._emit(0, b"P" * 1000, False)
                seen.append(s.s["fps"])
        self.assertTrue(all(28.0 <= f <= 31.0 for f in seen[5:]), seen)
        self.assertAlmostEqual(s.s["kbps"], 30 * 1000 * 8 / 1000, delta=20)

    def test_frame_rate_is_measured_on_the_camera_clock(self):
        """A ground-station clock running 8.33 % slow (WSL after the laptop woke from sleep) made a 30 fps camera read
        32.7 fps. The capture times in the frames give 30.0 whatever the local clock does, and show real frame loss."""
        from unittest import mock
        s = self.sink()
        s.need_key = False
        clock = [5000.0]
        with mock.patch("kyber6g.ground.video_sink.time.monotonic", lambda: clock[0]):
            for i in range(240):                         # 8 s of camera time ...
                clock[0] = 5000.0 + i / 30 * 0.9167      # ... seen through a clock that runs slow
                s._emit(int((777.0 + i / 30) * 1e6), b"P" * 12500, False)
            self.assertAlmostEqual(s.s["fps"], 30.0, delta=0.11)
            self.assertAlmostEqual(s.s["kbps"], 3000.0, delta=15)
            for i in range(240, 480):                    # every 10th frame lost on the way
                if i % 10:
                    clock[0] = 5000.0 + i / 30 * 0.9167
                    s._emit(int((777.0 + i / 30) * 1e6), b"P" * 12500, False)
            self.assertAlmostEqual(s.s["fps"], 27.0, delta=0.6)
        self.assertEqual(s.view_ts(), None)              # nothing decoded yet: no picture on screen

    def test_a_slow_decoder_makes_the_picture_skip_not_fall_behind(self):
        """Measured on the laptop: with the ACCURATE detector and the finder running, the processor was throttled for
        about 50 s every few minutes and the decoder ran at a fifth of its speed. The queue in front of it was bounded
        in frames only (120), so the picture fell 20 s behind the camera. Now a frame that has waited more than
        BACKLOG_S is given up with everything behind it, and decoding starts again at the next keyframe."""
        from unittest import mock
        from kyber6g.ground.video_sink import BACKLOG_S
        s = VideoSink(jitter_ms=50, clock_offset=lambda: 0.0)
        s._ensure_decoder = lambda: None                 # a decoder that takes nothing: the queue only grows
        clock = [3000.0]
        with mock.patch("kyber6g.ground.video_sink.time.monotonic", lambda: clock[0]):
            self.assertEqual(s.decoder_lag(), 0.0)
            for i in range(31):                          # one second of video: a keyframe and 30 others, none decoded
                clock[0] = 3000.0 + i / 30
                s._emit(int(i / 30 * 1e6), (b"K" if i == 0 else b"P") * 500, i == 0)
            self.assertEqual(s.inq.qsize(), 31)
            self.assertAlmostEqual(s.decoder_lag(), 1.0, delta=0.01)
            self.assertEqual(s.s["decoder_behind"], 0)
            clock[0] = 3000.0 + BACKLOG_S + 0.05         # the oldest waiting frame is now older than the limit
            s._emit(int(1.05e6), b"P" * 500, False)
            self.assertEqual(s.inq.qsize(), 0)           # everything that waited is given up, this frame too ...
            self.assertEqual((s.s["decoder_behind"], s.s["frames_dropped_decoder_behind"], s.s["frames_skipped_wait_key"]), (1, 31, 1))
            self.assertTrue(s.need_key)
            self.assertEqual(s.decoder_lag(), 0.0)
            clock[0] += 0.033
            s._emit(int(1.08e6), b"P" * 500, False)      # ... and nothing is decoded from a broken chain
            self.assertEqual((s.inq.qsize(), s.s["frames_skipped_wait_key"]), (0, 2))
            clock[0] += 0.033
            s._emit(int(1.12e6), b"K" * 500, True)       # the next keyframe starts the picture again, live
            s._emit(int(1.15e6), b"P" * 500, False)
            self.assertEqual(s.inq.qsize(), 2)
            self.assertFalse(s.need_key)
            self.assertEqual(s.s["frames_complete"], 35)     # arrived complete: none of this is network loss
            self.assertEqual(s.s["frames_lost"], 0)

    EASE_FRESH = dict(level=0, until=0.0, episodes=0, last=-1e9, first=-1e9, counted=True, raised_at=-1e9)

    def test_the_ml_workers_yield_while_the_decoder_is_behind(self):
        from unittest import mock
        from kyber6g.ground import sched
        from kyber6g.ground.sched import video_behind
        s = VideoSink(jitter_ms=50, clock_offset=lambda: 0.0)
        s._ensure_decoder = lambda: None
        clock = [100.0]
        with mock.patch("kyber6g.ground.video_sink.time.monotonic", lambda: clock[0]),                 mock.patch.dict(sched._ease, dict(self.EASE_FRESH, hold=sched.EASE_HOLD_S)):
            self.assertFalse(video_behind(s))            # nothing waits: the normal state
            s._emit(0, b"K" * 500, True)
            clock[0] += 0.1
            self.assertFalse(video_behind(s))            # a frame waiting 100 ms is not "behind"
            clock[0] += 0.3
            self.assertTrue(video_behind(s))             # 400 ms: the workers start no new inference
            self.assertEqual(sched.ease_factor(), 1)     # one late frame does not slow them down afterwards ...
            clock[0] += 2.5
            self.assertTrue(video_behind(s))             # ... a decoder that stays behind for seconds does
            self.assertEqual(sched.ease_factor(), 2)
            self.assertFalse(video_behind(object()))     # a video source without that measure never blocks them

    def test_after_an_episode_the_ml_workers_run_slower_until_the_machine_copes(self):
        """Yielding while the decoder is behind does not remove the cause when the cause is heat. Measured on the laptop:
        with the ACCURATE detector and the finder its processor reached 89 degrees C after about 105 s and the firmware
        ran it at 17 % of its speed for 55 s, again and again, and at half the ML load the same. So every episode
        halves the rate of the workers once more; after ten quiet minutes the rate is raised one step to try; a try
        that fails doubles the wait before the next one."""
        from unittest import mock
        from kyber6g.ground import sched
        H = sched.EASE_HOLD_S

        def episode(t0, seconds=50):                     # the decoder is behind for `seconds`, seen once a second
            for k in range(seconds + 1):
                sched._note_behind(t0 + k)
            return t0 + seconds

        with mock.patch.dict(sched._ease, dict(self.EASE_FRESH, hold=H)):
            self.assertEqual(sched.ease_factor(1000.0), 1)
            sched._note_behind(1000.0)                   # one late frame is not an episode
            self.assertEqual((sched.ease_factor(1001.0), sched.ease_state(1001.0)["episodes"]), (1, 0))
            t = episode(2000.0)                          # behind for 50 s: half rate
            self.assertEqual(sched.ease_state(t), {"factor": 2, "seconds_left": H, "episodes": 1, "hold_s": H})
            t = episode(t + 105)                         # at half rate the same again 105 s later: a quarter
            self.assertEqual(sched.ease_state(t), {"factor": 4, "seconds_left": H, "episodes": 2, "hold_s": H})
            self.assertEqual(sched.ease_factor(t + H - 1), 4)     # held as long as there is no episode ...
            self.assertEqual(sched.ease_factor(t + H), 2)         # ... then one step back up, to try
            t = episode(t + H + 105)                     # the try fails: a quarter again, and twice the wait before the next
            self.assertEqual(sched.ease_state(t), {"factor": 4, "seconds_left": 2 * H, "episodes": 3, "hold_s": 2 * H})
            for _ in range(6):                           # every failed try doubles the wait, up to an hour
                h = sched._ease["hold"]
                self.assertEqual(sched.ease_factor(t + h), 2)
                t = episode(t + h + 105)
            self.assertEqual((sched.ease_state(t)["hold_s"], sched.ease_state(t)["factor"]), (sched.EASE_HOLD_MAX_S, 4))
            h = sched._ease["hold"]                      # the machine copes again: step by step back to full rate
            self.assertEqual([sched.ease_factor(t + h), sched.ease_factor(t + 2 * h), sched.ease_factor(t + 3 * h)], [2, 1, 1])
            t = episode(t + 3 * h + 5000)                # much later, at full rate: an ordinary first episode again
            self.assertEqual((sched.ease_state(t)["factor"], sched.ease_state(t)["seconds_left"], sched.ease_state(t)["hold_s"]), (2, H, H))
            for _ in range(5):                           # it never goes below an eighth
                t = episode(t + 105)
            self.assertEqual(sched.ease_factor(t), 8)

    def test_every_frame_goes_to_the_decoder_with_a_delimiter_behind_it(self):
        """ffmpeg's H.264 parser knows that a frame has ended only when the next one begins. Fed one frame at a time it
        held every frame until the next arrived (measured: 41 ms from frame to picture at 30 fps, of which 33 ms were
        waiting). An access unit delimiter written behind each frame tells it at once."""
        import threading
        from kyber6g.ground.video_sink import AUD, _starts_with_aud

        class FakeProc:
            def __init__(self): self.stdin, self.wrote, self.alive = self, [], True
            def write(self, b): self.wrote.append(bytes(b))
            def poll(self): return None if self.alive else 0

        s = VideoSink(jitter_ms=50, clock_offset=lambda: 0.0)
        p, fifo = FakeProc(), __import__("collections").deque()
        t = threading.Thread(target=s._writer, args=(p, s.inq, fifo), daemon=True)
        t.start()
        plain = b"\x00\x00\x00\x01\x41" + b"\x9a" * 40                     # a P slice, as the Pi's encoder writes it
        own = b"\x00\x00\x00\x01\x09\xf0\x00\x00\x00\x01\x41" + b"\x9a" * 40    # an encoder that writes delimiters itself
        s.inq.put((1000, plain, time.monotonic()))
        s.inq.put((2000, own, time.monotonic()))
        for _ in range(100):
            if len(p.wrote) == 2:
                break
            time.sleep(0.01)
        self.assertEqual(p.wrote, [plain + AUD, own])
        self.assertEqual([x[0] for x in fifo], [1000, 2000])               # capture times wait for their pictures, in order
        self.assertTrue(_starts_with_aud(own) and _starts_with_aud(AUD) and not _starts_with_aud(plain))
        self.assertFalse(_starts_with_aud(b"") or _starts_with_aud(b"\x00\x00\x01"))
        # No picture came for these two frames and nothing more is written: after a second their capture times are
        # dropped, so that the next picture is not paired with the capture time of an older frame.
        time.sleep(1.8)
        self.assertEqual((len(fifo), s.s["frames_without_picture"]), (0, 2))
        p.alive = False
        t.join(timeout=2)
        self.assertFalse(t.is_alive())

    def test_the_decoder_gives_each_picture_before_the_next_frame_arrives(self):
        """The real decoder, with a real H.264 stream fed one frame at a time: the picture of every frame is there
        before the next frame is written, there are as many pictures as frames, and each carries the capture time of
        its own frame."""
        import shutil
        import subprocess
        if not shutil.which("ffmpeg"):
            self.skipTest("no ffmpeg on this machine")
        made = subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-f", "lavfi", "-i", "testsrc=size=320x240:rate=30",
                               "-frames:v", "24", "-c:v", "libx264", "-preset", "ultrafast", "-bf", "0", "-g", "8",
                               "-x264-params", "repeat-headers=1:aud=0", "-bsf:v", "h264_mp4toannexb", "-f", "h264", "pipe:1"],
                              capture_output=True, timeout=60)
        raw = made.stdout
        if made.returncode != 0 or len(raw) < 1000:
            self.skipTest("this ffmpeg cannot make an H.264 test stream")
        # split into access units: a new one begins at SEI / SPS / PPS after a slice, or at a slice that starts a picture
        starts, i = [], raw.find(b"\x00\x00\x01")
        while i >= 0:
            starts.append(i - 1 if i > 0 and raw[i - 1] == 0 else i)
            i = raw.find(b"\x00\x00\x01", i + 3)
        aus, cur, have_slice = [], b"", False
        for k, a in enumerate(starts):
            nal = raw[a:starts[k + 1] if k + 1 < len(starts) else len(raw)]
            hdr = nal[4] if nal[:4] == b"\x00\x00\x00\x01" else nal[3]
            kind = hdr & 0x1F
            first = kind in (1, 5) and (nal[5 if nal[:4] == b"\x00\x00\x00\x01" else 4] & 0x80)
            if have_slice and (kind in (6, 7, 8) or first):
                aus.append(cur); cur, have_slice = b"", False
            cur += nal
            have_slice = have_slice or kind in (1, 5)
        aus.append(cur)
        self.assertEqual(len(aus), 24)
        s = VideoSink(jitter_ms=50, clock_offset=lambda: 0.0)
        try:
            waited = []
            for n, au in enumerate(aus):
                seq = s.jpeg_seq
                t0 = time.monotonic()
                s._emit(1_000_000 + n * 33_333, au, n % 8 == 0)
                with s.cond:
                    got = s.cond.wait_for(lambda: s.jpeg_seq > seq, timeout=5.0 if n == 0 else 1.0)
                self.assertTrue(got, f"no picture for frame {n} before the next frame")      # with the hold: never for the last one
                waited.append(time.monotonic() - t0)
                self.assertEqual(s.jpeg_seq, n + 1)                          # one picture for one frame
                self.assertAlmostEqual(s.latest_ts, 1.0 + n * 0.033333, places=4)     # ... with that frame's capture time
                self.assertTrue(s.latest.startswith(b"\xff\xd8") and s.latest.endswith(b"\xff\xd9"))
            self.assertEqual(s.s["frames_decoded"], 24)
            self.assertLess(sorted(waited[1:])[len(waited) // 2], 0.5)
        finally:
            s.running = False
            s._stop_decoder()

    def test_view_time_follows_the_newest_decoded_frame(self):
        s = self.sink()
        with s.cond:
            s.latest, s.latest_ts, s._latest_mono = b"jpg", 4242.5, time.monotonic() - 0.040
        self.assertAlmostEqual(s.view_ts(), 4242.54, delta=0.02)        # camera clock, 40 ms after that frame
        with s.cond:
            s._latest_mono = time.monotonic() - 5.0                      # stream stopped 5 s ago
        self.assertIsNone(s.view_ts())

    def test_a_new_resolution_gets_a_fresh_decoder(self):
        from kyber6g.ground.video_sink import _sps_of

        class FakeProc:
            def __init__(self): self.stdin, self.terminated = self, False
            def close(self): pass
            def terminate(self): self.terminated = True
            def poll(self): return None

        def idr(sps):
            return b"\x00\x00\x00\x01\x67" + sps + b"\x00\x00\x00\x01\x68\xce\x3c\x80" + b"\x00\x00\x01\x65" + b"\x88" * 300

        a, b = b"\x64\x00\x1f\xac\xd9\x40\x50\x05\xbb", b"\x64\x00\x28\xac\xd9\x40\x78\x02\x27"
        self.assertEqual(_sps_of(idr(a)), b"\x67" + a)
        self.assertIsNone(_sps_of(b"\x00\x00\x01\x41" + b"\x9a" * 50))        # a P frame carries no parameter set
        self.assertIsNone(_sps_of(b"no start code at all"))
        s = self.sink()
        s.need_key = False
        s._emit(0, idr(a), True)
        first = s.dec = FakeProc()
        s._emit(0, b"\x00\x00\x01\x41" + b"\x9a" * 50, False)
        s._emit(0, idr(a), True)                         # same stream: the decoder is kept
        self.assertEqual((s.s["decoder_restarts"], first.terminated), (0, False))
        s._emit(0, idr(b), True)                         # the UAV changed resolution
        self.assertEqual((s.s["decoder_restarts"], first.terminated, s.dec), (1, True, None))
        s.dec = second = FakeProc()
        s.reset()                                        # ▶ LIVE pressed again: also a fresh decoder
        self.assertTrue(second.terminated)
        self.assertEqual(s.s["decoder_restarts"], 2)
        self.assertEqual(s.stats()["decoder"], "stopped")

    def chunks(self, fid, data, key):
        body = struct.pack("!Q", int(time.time() * 1e6)) + data
        parts = [body[i:i + 100] for i in range(0, len(body), 100)]
        return [(VIDEO_EXT.pack(fid, i, len(parts), 1 if key else 0), p) for i, p in enumerate(parts)]

    def test_reorder_within_jitter(self):
        s = self.sink()
        a = self.chunks(0, b"K" * 250, True)
        b = self.chunks(1, b"P" * 250, False)
        self.assertEqual((len(a), len(b)), (3, 3))
        for ext, p in [b[2], a[1], b[0], a[0], b[1], a[2]]:   # interleaved + reordered
            s.on_chunk(ext, p)
        self.assertEqual([x[1][:1] for x in s.fed], [b"K", b"P"])

    def test_loss_waits_for_keyframe(self):
        s = self.sink()
        for ext, p in self.chunks(0, b"K" * 250, True):
            s.on_chunk(ext, p)
        lost = self.chunks(1, b"P" * 250, False)
        s.on_chunk(*lost[0])                          # incomplete frame 1
        for ext, p in self.chunks(2, b"Q" * 250, False):
            s.on_chunk(ext, p)
        time.sleep(0.12)
        with s.lock:
            s._deliver()
        for ext, p in self.chunks(3, b"R" * 250, True):  # next IDR
            s.on_chunk(ext, p)
        self.assertEqual([x[1][:1] for x in s.fed], [b"K", b"R"])
        self.assertEqual(s.s["frames_lost"], 1)
        self.assertEqual(s.s["frames_skipped_wait_key"], 1)


if __name__ == "__main__":
    unittest.main()
