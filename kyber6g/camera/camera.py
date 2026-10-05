"""Camera service: Waveshare RPi Camera (F), OV5647, via Picamera2/libcamera.

ONE hardware H.264 encode feeds every consumer:

    sensor -> ISP -> H264Encoder (VideoCore) -> FanoutOutput -+-> live sink (AEAD -> UDP)
                                                               +-> recorder (AEAD -> SD card)

Night mode changes exposure/gain/colour processing only. The two 850 nm IR
LED boards are powered from the camera board and switched by their own
light-dependent resistors; they are NOT software-controllable, and the
camera does not see in darkness without that illumination.
"""
import collections
import io
import os
import threading
import time

import numpy as np

MODES = ("NORMAL", "NIGHT")


def _sensor_to_wall(sensor_us):
    """Map a libcamera SensorTimestamp (us) to wall-clock time.

    Picamera2 passes encoders `SensorTimestamp - first SensorTimestamp`; the
    caller adds the encoder's stored first timestamp back. The kernel clock
    behind SensorTimestamp is BOOTTIME or MONOTONIC depending on the stack,
    so we accept whichever gives a plausible (0..2 s) capture age.
    """
    for clk in (getattr(time, "CLOCK_BOOTTIME", None), time.CLOCK_MONOTONIC):
        if clk is None:
            continue
        delta = time.clock_gettime(clk) - sensor_us / 1e6
        if 0 <= delta < 2:
            return time.time() - delta, True
    return time.time(), False


def yuv420_to_rgb(arr, w, h):
    """I420 planar -> RGB uint8 (BT.601 full range), used for stills during video."""
    stride = arr.shape[1]
    y = arr[:h, :w].astype(np.float32)
    u = arr[h:h + h // 4, :].reshape(h // 2, stride // 2)[:, :w // 2]
    v = arr[h + h // 4:h + h // 2, :].reshape(h // 2, stride // 2)[:, :w // 2]
    u = u.repeat(2, 0).repeat(2, 1).astype(np.float32) - 128
    v = v.repeat(2, 0).repeat(2, 1).astype(np.float32) - 128
    rgb = np.stack([y + 1.402 * v, y - 0.344136 * u - 0.714136 * v, y + 1.772 * u], axis=-1)
    return np.clip(rgb, 0, 255).astype(np.uint8)


def sharpness(gray: np.ndarray) -> float:
    g = gray.astype(np.float32)
    lap = 4 * g[1:-1, 1:-1] - g[:-2, 1:-1] - g[2:, 1:-1] - g[1:-1, :-2] - g[1:-1, 2:]
    return float(lap.var())


class CameraService:
    MOTION_HZ = (1.0, 15.0)

    def __init__(self, cfg, on_live_frame, on_motion=None, platform_moving=None):
        self.cfg = cfg
        self.on_live_frame = on_live_frame
        # `platform_moving()`: True while the UAV is under way (GNSS). The motion watch then reports nothing for a
        # look in which the picture gave it no way to measure the camera's own movement.
        self.platform_moving = platform_moving
        # Motion watch (motion.py): `on_motion(result)` gets every look. `sentry`: keep the camera running for the
        # watch when nobody watches the video and nothing is recorded (then nothing is sent but the reports).
        self.on_motion = on_motion
        self.motion = None
        self.motion_set = {"enabled": bool(getattr(cfg, "motion", True)), "sentry": False,
                           "hz": min(max(float(getattr(cfg, "motion_hz", 8.0)), self.MOTION_HZ[0]), self.MOTION_HZ[1])}
        self.motion_stats = {"looks": 0, "ms": None, "ms_max": None, "errors": 0, "error": None, "lores": None, "hz_measured": None}
        self._gen = 0                        # counts starts of the encoder: a watch thread of an earlier start ends itself
        self._lores = None                   # (width, height) of the small picture while the camera is configured for video
        self._motion_trace = collections.deque(maxlen=60)      # what the last looks measured (numbers, not pictures)
        self._grab = None                    # pictures being collected in memory for a self-test, if one runs
        if getattr(cfg, "motion", True):
            try:
                from .motion import MotionDetector
                self.motion = MotionDetector(getattr(cfg, "motion_sensitivity", "medium"))
            except Exception as e:           # a wrong setting must not cost the camera
                self.motion_stats["error"] = f"{type(e).__name__}: {e}"
        self.lock = threading.RLock()
        self._buffers = threading.Lock()     # configuring the camera, or giving back a frame of the configuration before
        self.available = False
        self.error = None
        self.model = None
        self.live = False
        self.recorder = None
        self.mode = "NORMAL"
        self.encoding = False
        self.stats = {"frames": 0, "keyframes": 0, "bytes": 0, "fps": 0.0, "kbps": 0.0,
                      "encode_latency_ms": None, "exposure_us": None, "gain": None, "lux": None,
                      "mode_arrived": None}  # does the picture show the mode? (None: not looked at yet; see _check_mode)
        self._starts = 0                     # how often the camera has been started since the program began
        self._mode_asked = 0.0               # when the camera was last put into its mode (monotonic clock)
        self._mode_tries = 0                 # restarts since the last switch because the mode had not arrived
        self._white = None                   # (when, colour gains) of the running stream's white balance in NORMAL mode
        self._win = []
        self.tuning = None
        self.rec_failure = None              # (recorder, reason) when a recording had to be cut off (see _on_frame)
        try:
            from picamera2 import Picamera2
            tuning = None
            if getattr(cfg, "tuning", None):
                try:
                    tuning = Picamera2.load_tuning_file(cfg.tuning)
                    self.tuning = cfg.tuning
                except Exception as e:           # missing file: run with the default tuning rather than not at all
                    self.error = f"tuning {cfg.tuning} not loaded ({type(e).__name__}); using default"
            self.picam2 = Picamera2(tuning=tuning) if tuning else Picamera2()
            self.model = self.picam2.camera_properties.get("Model")
            self.sensor_res = self.picam2.camera_properties.get("PixelArraySize")
            self.available = True
        except Exception as e:  # no camera / ribbon unplugged
            self.picam2 = None
            self.error = f"{type(e).__name__}: {e}"

    # --------------------------------------------------------------- config
    def _transform(self):
        from libcamera import Transform
        r = self.cfg.rotation % 360
        return Transform(hflip=1, vflip=1) if r == 180 else Transform()

    def _mode_controls(self):
        from libcamera import controls
        fps = self.cfg.fps
        if self.mode == "NIGHT":
            # greyscale removes the magenta cast of a no-IR-cut sensor under
            # 850 nm light; allow longer exposure (down to 10 fps) and more gain
            return {"Saturation": 0.0, "AwbEnable": False, "ColourGains": (1.0, 1.0),
                    "AeExposureMode": controls.AeExposureModeEnum.Long,
                    "FrameDurationLimits": (int(1e6 / fps), 100000)}
        return {"Saturation": 1.0, "AwbEnable": True, "ExposureValue": float(getattr(self.cfg, "exposure_value", 0.0)),
                "AeExposureMode": controls.AeExposureModeEnum.Normal,
                "FrameDurationLimits": (int(1e6 / fps), int(1e6 / fps))}

    # A change of mode while the camera runs. Measured on this Pi (libcamera 0.7.2, picamera2 0.3.37, 6 October 2026):
    # as long as the camera has been started only once since the program began, a request for the mode's controls
    # arrives whole (13 of 13 switches). Once it has been stopped and started again, which every change of the video
    # settings does, such a request arrives only in part: the exposure follows, the colour and the white balance do
    # not. After NIGHT at 1920 x 1080 the DAY button left the picture grey, however often it was pressed (8 of 12
    # switches wrong; still 5 of 9 wrong with the request repeated on five frames in a row). A camera that is STARTED
    # with the mode among its start controls is in it from the first frame, every time (10 of 10). So: the mode is
    # part of every configuration; a switch on a camera that has been restarted before restarts it once more (half
    # a second without pictures, as for new video settings); and once a second the camera's own report of a frame
    # is held against the mode (_check_mode), with one more restart if the two disagree.
    MODE_SETTLE = 2.5           # seconds before the camera's report is held against the mode (white balance needs frames)
    MODE_RETRIES = 3            # restarts for a mode that did not arrive, before the status only says so

    def _request_mode(self):
        """Put the running camera into the current mode (call with the lock held)."""
        self._mode_tries = 0
        if self._starts > 1:
            self._restart_camera()
        else:
            self.picam2.set_controls(self._mode_controls())
            self._mode_asked = time.monotonic()
            self.stats["mode_arrived"] = None

    def _restart_camera(self):
        """Stop the camera and start it again as it is set now: its mode is among the start controls."""
        self.picam2.stop_encoder(self.encoder)
        self.picam2.stop()
        self.encoding = False
        try:
            self._ensure_encoder()
        except Exception:
            time.sleep(0.3)                      # once more before the operator is told: a camera that is to stream must not stay off
            self._ensure_encoder()

    @staticmethod
    def mode_arrived(mode, md):
        """Does the camera's report of a frame show the mode? NIGHT: a grey picture (saturation 0 makes the three rows
        of the colour matrix the same) and both colour gains held at 1. NORMAL: a colour matrix, and gains that the
        white balance has set. None if the report does not say."""
        ccm, gains = md.get("ColourCorrectionMatrix"), md.get("ColourGains")
        if not ccm or len(ccm) != 9 or not gains or len(gains) != 2:
            return None
        grey = max(abs(ccm[i] - ccm[i + 3]) + abs(ccm[i] - ccm[i + 6]) for i in range(3)) < 1e-3
        held = abs(gains[0] - 1.0) < 1e-3 and abs(gains[1] - 1.0) < 1e-3
        return (grey and held) if mode == "NIGHT" else (not grey and not held)

    def _check_mode(self, md):
        """Hold the camera's report of a frame against the mode. If they disagree the camera is restarted (at most
        MODE_RETRIES times for one switch; after that the status goes on saying that the mode did not arrive)."""
        if time.monotonic() - self._mode_asked < self.MODE_SETTLE:
            return
        ok = self.mode_arrived(self.mode, md)
        if ok is None:
            return
        self.stats["mode_arrived"] = ok
        if ok and self.mode == "NORMAL":
            self._white = (time.monotonic(), tuple(md["ColourGains"]))       # for a photo with the stream stopped
        if not ok and self._mode_tries < self.MODE_RETRIES:
            with self.lock:
                if self.encoding and self.mode_arrived(self.mode, md) is False:      # the mode may have changed meanwhile
                    self._mode_tries += 1
                    self._restart_camera()

    def _configure(self, conf):
        """Configure the stopped camera. picamera2 then clears away the buffers of the configuration before, and it does
        the same clearing when a frame of that configuration is given back. Seen once in 20 restarts: "KeyError: 24"
        out of that clearing during configure(), and the camera stayed off. The motion watch is the one that may
        still hold such a frame, so it gives it back under the same lock and the two cannot run at once."""
        with self._buffers:
            self.picam2.configure(conf)

    def _lores_size(self):
        """Size of the small picture for the motion watch: the shape of the video, even numbers, never larger."""
        c = self.cfg
        w = min(int(getattr(c, "motion_width", 320)), c.width) // 2 * 2
        return w, max(2, round(w * c.height / c.width / 2) * 2)

    def _configure_video(self):
        c = self.cfg
        extra = {}
        self._lores = None
        if self.motion is not None:
            self._lores = self._lores_size()
            extra["lores"] = {"size": self._lores, "format": "YUV420"}
        # the mode is among the start controls: the camera is in it from its first frame (see _request_mode)
        conf = self.picam2.create_video_configuration(
            main={"size": (c.width, c.height), "format": "YUV420"},
            transform=self._transform(), controls={"FrameRate": c.fps, **self._mode_controls()}, **extra)
        self._configure(conf)
        self.motion_stats["lores"] = list(self._lores) if self._lores else None

    # ------------------------------------------------------------ encoding
    def _ensure_encoder(self):
        from picamera2.encoders import H264Encoder
        from picamera2.outputs import Output

        svc = self

        class FanoutOutput(Output):
            def outputframe(self, frame, keyframe=True, timestamp=None, packet=None, audio=False):
                svc._on_frame(bytes(frame), bool(keyframe), timestamp)

        sentry = self.motion is not None and self.motion_set["enabled"] and self.motion_set["sentry"]
        need = self.live or self.recorder is not None or sentry
        if need and not self.encoding:
            self._configure_video()
            self.encoder = H264Encoder(bitrate=self.cfg.bitrate, repeat=True, iperiod=self.cfg.iperiod)
            self.picam2.start_encoder(self.encoder, FanoutOutput())
            self.picam2.start()
            self._starts += 1
            self._mode_asked = time.monotonic()
            self.stats["mode_arrived"] = None
            self.encoding = True
            self._win = []
            self._gen += 1
            threading.Thread(target=self._metadata_loop, args=(self._gen,), daemon=True).start()
            if self.motion is not None:
                threading.Thread(target=self._motion_loop, args=(self._gen,), daemon=True, name="motion").start()
        elif not need and self.encoding:
            self.picam2.stop_encoder(self.encoder)
            self.picam2.stop()
            self.encoding = False
            self.stats.update(fps=0.0, kbps=0.0)

    def _on_frame(self, data, keyframe, ts):
        t_cb = time.time()
        first = getattr(self.encoder, "firsttimestamp", None)
        cap, exact = _sensor_to_wall(ts + first) if (ts is not None and first) else (t_cb, False)
        ts_us = int(cap * 1e6)
        st = self.stats
        st["frames"] += 1
        st["keyframes"] += keyframe
        st["bytes"] += len(data)
        st["capture_ts_source"] = "sensor" if exact else "callback"
        st["encode_latency_ms"] = round((t_cb - cap) * 1000, 2) if exact else None
        self._win.append((t_cb, len(data)))
        while self._win and t_cb - self._win[0][0] > 2.0:
            self._win.pop(0)
        if len(self._win) > 1:
            span = self._win[-1][0] - self._win[0][0]
            if span > 0:
                st["fps"] = round((len(self._win) - 1) / span, 2)
                st["kbps"] = round(sum(b for _, b in self._win[1:]) * 8 / span / 1000, 1)
        if self.live:
            try:
                self.on_live_frame(data, keyframe, ts_us)
            except Exception as e:
                self.error = f"live sink: {e}"
        rec = self.recorder
        if rec is not None:
            try:
                rec.add_frame(data, keyframe, ts_us)
            except Exception as e:
                # SD card full / I/O error. This runs in the encoder's thread: an exception here would end the
                # live stream as well. Detach the recorder; what was written so far stays decryptable (the file
                # is reported as TRUNCATED). The UAV app reports it and stops the encoder if nobody is watching.
                self.recorder = None
                self.rec_failure = (rec, f"{type(e).__name__}: {e}")

    def _metadata_loop(self, gen):
        """Once a second: what the camera reports of a frame (exposure, gain, light), and whether that frame is in
        the mode that was asked for. `gen`: the loop of an earlier start of the encoder ends itself."""
        while self.encoding and gen == self._gen:
            try:
                md = self.picam2.capture_metadata()
                self.stats.update(exposure_us=md.get("ExposureTime"), gain=round(md.get("AnalogueGain", 0), 2),
                                  lux=round(md.get("Lux", 0), 1) if md.get("Lux") is not None else None)
                self._check_mode(md)
            except Exception:
                pass
            time.sleep(1.0)

    def _motion_loop(self, gen):
        """The motion watch: a few times a second the small picture of the newest frame goes through motion.py.

        Its own thread at a lower priority: the encoder's callback (which seals and sends the video) comes first.
        The request for a frame waits for the next one the camera completes; it is given back at once, after its
        brightness plane has been copied. A request that is answered only after the camera was stopped and started
        again belongs to nobody: it is given back and this thread ends (the new start has its own)."""
        try:
            os.setpriority(os.PRIO_PROCESS, threading.get_native_id(), 5)
        except (AttributeError, OSError):
            pass
        det, st = self.motion, self.motion_stats
        det.reset()
        acc, t_last = [], None
        while self.encoding and gen == self._gen:
            if not self.motion_set["enabled"]:
                det.reset()
                time.sleep(0.25)
                continue
            t0 = time.monotonic()
            try:
                req = self.picam2.capture_request()
                try:
                    if not self.encoding or gen != self._gen or self._lores is None:
                        break
                    lw, lh = self._lores
                    luma = np.array(req.make_array("lores")[:lh, :lw])
                    sensor_ns = req.get_metadata().get("SensorTimestamp")
                finally:
                    with self._buffers:              # not while the camera is being configured (see _configure)
                        req.release()
                ts = _sensor_to_wall(sensor_ns / 1000)[0] if sensor_ns else time.time()
                grab = self._grab
                if grab is not None and len(grab["frames"]) < grab["want"]:
                    grab["frames"].append(luma)              # for the self-test: kept in memory only (see motion_selftest)
                    grab["ts"].append(ts)
                    if len(grab["frames"]) >= grab["want"]:
                        grab["full"].set()
                t1 = time.perf_counter()
                res = det.step(luma, ts, bool(self.platform_moving and self.platform_moving()))
                ms = (time.perf_counter() - t1) * 1000
                st["looks"] += 1
                self._motion_trace.append(self._trace_row(res, ms, luma, det))
                acc.append(ms)
                if len(acc) >= 16:
                    st["ms"], st["ms_max"] = round(sum(acc) / len(acc), 2), round(max(acc), 2)
                    if t_last is not None:
                        st["hz_measured"] = round(len(acc) / (t0 - t_last), 2)
                    acc, t_last = [], t0
                elif t_last is None:
                    t_last = t0
                if self.on_motion:
                    self.on_motion(res)
                st["error"] = None
            except Exception as e:                   # the camera was stopped under us, a look failed: keep watching
                st["errors"] += 1
                st["error"] = f"{type(e).__name__}: {e}"
                time.sleep(0.2)
            time.sleep(max(0.0, 1.0 / self.motion_set["hz"] - (time.monotonic() - t0)))

    @staticmethod
    def _trace_row(res, ms, luma, det):
        """What one look measured, as numbers only (never the picture): for the `motion` command's "trace"."""
        e = res.get("ego") or {}
        tiles = det.last_tiles
        row = {"ts": round(res["ts"], 3), "ms": round(ms, 1), "mean": round(float(luma.mean()), 1), "noise": res.get("noise"),
               "active": res.get("active"), "muted": res.get("muted"), "regions": len(res["regions"]), "scene": res["scene"],
               "pattern": res.get("pattern"), "slow": res.get("slow"),
               "known": e.get("known"), "moving": e.get("moving"), "dx": e.get("dx"), "dy": e.get("dy"), "a": e.get("a"),
               "b": e.get("b"), "tiles": e.get("tiles"), "resid": e.get("resid")}
        if tiles is not None:
            d, w, texture = tiles
            row["tile_dx"] = [round(float(v), 2) for v in d[:, 0]]
            row["tile_dy"] = [round(float(v), 2) for v in d[:, 1]]
            row["tile_w"] = [round(float(v), 2) for v in w]
            row["tile_psr"] = [round(float(v), 1) for v in det.last_psr]
            row["tile_texture"] = [round(float(v), 1) for v in texture]
        return row

    def motion_trace(self, n=40):
        """The last n looks of the watch as numbers (at most 60: the answer is one control message)."""
        return list(self._motion_trace)[-max(1, min(int(n), 60)):]

    SELFTEST_KEYS = {"size": (2, 64), "contrast": (-200, 200), "speed": (0, 32), "pan": (0, 4)}

    def motion_selftest(self, cases, looks=40, seed=1):
        """How well the watch does on THIS camera, in THIS light: `looks` pictures of the small stream are taken
        into memory, and for every case a target of known size, contrast and speed is drawn into them (and, with
        `pan`, the camera's movement is imitated by a sliding window) before a fresh detector looks at them
        (motion_eval.real). Only numbers leave this function: the pictures are never stored or sent."""
        from . import motion_eval
        if self.motion is None or not (self.encoding and self.motion_set["enabled"]):
            raise RuntimeError("the motion watch is not watching (start the live video or sentry first)")
        if not isinstance(cases, list) or not 1 <= len(cases) <= 48 or isinstance(looks, bool) or not isinstance(looks, int) or not 16 <= looks <= 64:
            raise ValueError("selftest needs 1..48 cases and 16..64 looks")
        clean = []
        for c in cases:
            if not isinstance(c, dict):
                raise ValueError("a case is an object")
            kw = {"target": c.get("target") is not False, "sensitivity": c.get("sensitivity") if isinstance(c.get("sensitivity"), str) else "medium"}
            if c.get("under_way") is True:                       # the detector is told that the UAV moves (as its GNSS would)
                kw["under_way"] = True
            for k, (lo, hi) in self.SELFTEST_KEYS.items():
                if k in c:
                    v = c[k]
                    if isinstance(v, bool) or not isinstance(v, (int, float)) or not lo <= v <= hi:
                        raise ValueError(f"{k} must be {lo}..{hi}")
                    kw[k] = int(v) if k == "pan" else float(v)
            clean.append(kw)
        if self._grab is not None:
            raise RuntimeError("a self-test is already running")
        grab = self._grab = {"want": looks, "frames": [], "ts": [], "full": threading.Event()}
        try:
            if not grab["full"].wait(looks / self.motion_set["hz"] * 2 + 10):
                raise RuntimeError(f"only {len(grab['frames'])} of {looks} pictures came")
        finally:
            self._grab = None
        frames, ts = grab["frames"], grab["ts"]
        dt = (ts[-1] - ts[0]) / (len(ts) - 1)
        out = {"looks": len(frames), "dt": round(dt, 4), "size": list(frames[0].shape[::-1]), "mode": self.mode,
               "mean": round(float(np.mean([f.mean() for f in frames])), 1), "exposure_us": self.stats.get("exposure_us"),
               "gain": self.stats.get("gain"), "lux": self.stats.get("lux"), "results": []}
        for i, kw in enumerate(clean):
            r = motion_eval.real(frames, seed + i, dt=dt, **kw)
            out["results"].append({**{k: v for k, v in kw.items()}, **r})
        return out

    # --------------------------------------------------------------- public
    def set_motion(self, enabled=None, sensitivity=None, hz=None, sentry=None):
        """Settings of the motion watch (a value left out or None keeps the current one); returns them."""
        if self.motion is None:
            raise RuntimeError(self.motion_stats["error"] or "the motion watch is switched off in this UAV's settings")
        for name, v in (("enabled", enabled), ("sentry", sentry)):
            if v is not None and not isinstance(v, bool):
                raise ValueError(f"{name} must be true or false")
        if hz is not None and (isinstance(hz, bool) or not isinstance(hz, (int, float)) or not self.MOTION_HZ[0] <= hz <= self.MOTION_HZ[1]):
            raise ValueError(f"hz must be between {self.MOTION_HZ[0]:g} and {self.MOTION_HZ[1]:g}")
        if sensitivity is not None:
            if not isinstance(sensitivity, str):
                raise ValueError("sensitivity must be low, medium or high")
            self.motion.set_sensitivity(sensitivity)
        with self.lock:
            s = self.motion_set
            if hz is not None:
                s["hz"] = float(hz)
            if enabled is not None:
                s["enabled"] = enabled
            if sentry is not None:
                if sentry and not self.available:
                    raise RuntimeError(self.error or "camera not available")
                s["sentry"] = sentry
            if self.available:
                self._ensure_encoder()               # sentry on: the camera starts; off: it stops if nobody else needs it
        return self.motion_status()

    def motion_status(self):
        if self.motion is None:
            return {"available": False, "error": self.motion_stats["error"]}
        return {"available": True, **self.motion_set, "sensitivity": self.motion.sensitivity,
                "watching": bool(self.encoding and self.motion_set["enabled"]), **self.motion_stats}

    def set_live(self, on: bool):
        with self.lock:
            if not self.available:
                raise RuntimeError(self.error or "camera not available")
            self.live = on
            self._ensure_encoder()

    def start_recording(self, recorder):
        with self.lock:
            if not self.available:
                raise RuntimeError(self.error or "camera not available")
            if self.recorder is not None:
                raise RuntimeError("already recording")
            self.recorder = recorder
            self._ensure_encoder()

    def stop_recording(self):
        with self.lock:
            rec, self.recorder = self.recorder, None
            self._ensure_encoder()
        return rec.close() if rec else None

    def take_rec_failure(self):
        """If a recording was cut off by a write error: release its file, stop an encoder nobody needs any more
        and return the reason (once)."""
        f, self.rec_failure = self.rec_failure, None
        if f is None:
            return None
        rec, why = f
        try:
            rec.abort()
        except Exception:
            pass
        with self.lock:
            if self.available:
                self._ensure_encoder()
        return {"name": getattr(rec, "name", None), "frames": getattr(rec, "frames", None), "error": why}

    def set_mode(self, mode: str):
        if mode not in MODES:
            raise ValueError("mode must be NORMAL or NIGHT")
        with self.lock:
            self.mode = mode
            if self.encoding:
                self._request_mode()
            else:
                self._ensure_encoder()               # nothing to do if nobody needs it; a camera that should run is started

    # what the sensor (OV5647) and the hardware H.264 encoder of the Pi 4 can be asked for
    VIDEO_LIMITS = {"width": (320, 1920), "height": (240, 1080), "fps": (1, 60), "bitrate": (100_000, 12_000_000)}

    def set_video(self, width=None, height=None, fps=None, bitrate=None):
        """Change the video settings (a value left out, None or 0 keeps the current one). The values come from the
        ground station: each must be a whole number within VIDEO_LIMITS, and if the encoder does not start with
        the new settings the old ones are put back, so a bad request cannot leave the camera without a stream."""
        new = {}
        for k, v in (("width", width), ("height", height), ("fps", fps), ("bitrate", bitrate)):
            if not v:
                continue
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v != int(v):
                raise ValueError(f"{k} must be a whole number")
            lo, hi = self.VIDEO_LIMITS[k]
            if not lo <= v <= hi:
                raise ValueError(f"{k} must be between {lo} and {hi}")
            new[k] = int(v)
        if new.get("width", 0) % 2 or new.get("height", 0) % 2:
            raise ValueError("width and height must be even")
        with self.lock:
            if self.recorder is not None:
                raise RuntimeError("stop recording before changing video settings")
            old = {k: getattr(self.cfg, k) for k in new}
            for k, v in new.items():
                setattr(self.cfg, k, v)
            if self.encoding:
                live, sentry = self.live, self.motion_set["sentry"]     # everything that keeps the encoder running
                try:
                    self.live, self.motion_set["sentry"] = False, False
                    self._ensure_encoder()
                    self.live, self.motion_set["sentry"] = live, sentry
                    self._ensure_encoder()
                except Exception:
                    for k, v in old.items():
                        setattr(self.cfg, k, v)
                    self.live, self.motion_set["sentry"] = live, sentry
                    try:
                        self._ensure_encoder()
                    except Exception:
                        pass                    # reported through status(); the original error is the one to raise
                    raise

    WHITE_KEEPS_S = 600.0       # for so long the stream's white balance is taken for a photo with the stream stopped

    def _still_controls(self):
        """The mode's controls for a photo with the stream stopped. Measured: in NORMAL mode the automatic white balance,
        started anew with the camera, is not right when the photo is taken 1.2 s later. It overshoots (blue gain 1.37
        to 1.52 where 1.07 is right; photos with a blue cast, one with red at a tenth of green) and needs about 4 s.
        The white balance the running stream had settled on is right from the first frame, so it is held for the
        photo if the stream ran in NORMAL mode within the last WHITE_KEEPS_S seconds."""
        ctrl = self._mode_controls()
        if self.mode == "NORMAL" and self._white and time.monotonic() - self._white[0] <= self.WHITE_KEEPS_S:
            ctrl.update(AwbEnable=False, ColourGains=self._white[1])
        return ctrl

    def _white_settled(self, limit=4.0):
        """Wait until the automatic white balance has stopped moving (five frames in a row within 1 %), at most
        `limit` seconds: the photo of a camera that has no white balance of the stream to go by."""
        t0, last, still = time.monotonic(), None, 0
        while time.monotonic() - t0 < limit and still < 5:
            gains = self.picam2.capture_metadata().get("ColourGains")
            if not gains:
                return
            still = still + 1 if last and all(abs(a - b) <= 0.01 * b for a, b in zip(gains, last)) else 0
            last = gains

    def capture_still(self):
        """Returns (jpeg_bytes, info). Full sensor resolution when not streaming,
        otherwise the current video resolution (one encode path is kept)."""
        from PIL import Image
        with self.lock:
            if not self.available:
                raise RuntimeError(self.error or "camera not available")
            t0 = time.perf_counter()
            if self.encoding:
                req = self.picam2.capture_request()
                try:
                    arr = req.make_array("main")
                    md = req.get_metadata()
                finally:
                    req.release()
                rgb = yuv420_to_rgb(arr, self.cfg.width, self.cfg.height)
                size = (self.cfg.width, self.cfg.height)
                source = "video-stream"
            else:
                conf = self.picam2.create_still_configuration(
                    main={"size": (self.cfg.still_width, self.cfg.still_height), "format": "RGB888"},
                    transform=self._transform(), controls=self._still_controls())  # in the mode from the first frame
                self._configure(conf)
                self.picam2.start()
                self._starts += 1                   # this, too, is a start after which a later request arrives only in part
                time.sleep(1.2)                     # let the exposure settle
                if conf["controls"].get("AwbEnable"):
                    self._white_settled()
                arr = self.picam2.capture_array("main")
                md = self.picam2.capture_metadata()
                self.picam2.stop()
                rgb = arr[:, :, ::-1]                # libcamera RGB888 is B,G,R in memory
                size = (self.cfg.still_width, self.cfg.still_height)
                source = "still-mode"
            buf = io.BytesIO()
            Image.fromarray(rgb).save(buf, format="JPEG", quality=self.cfg.jpeg_quality)
            gray = rgb.mean(axis=2)
            info = {"width": size[0], "height": size[1], "source": source, "mode": self.mode,
                    "capture_ms": round((time.perf_counter() - t0) * 1000, 1),
                    "exposure_us": md.get("ExposureTime"), "gain": md.get("AnalogueGain"),
                    "mean_luma": round(float(gray.mean()), 1), "sharpness": round(sharpness(gray[::2, ::2]), 1),
                    "sensor": self.model}
            return buf.getvalue(), info

    def status(self):
        rec = self.recorder
        recst = rec.live_status() if rec else {"recording_name": None, "recording_frames": None}
        return {"available": self.available, "error": self.error, "sensor": self.model, "tuning": self.tuning or "default",
                "live": self.live, "recording": rec is not None, **recst, "mode": self.mode, "encoding": self.encoding,
                "ir": "AUTO (LDR on IR boards, not software-controlled)",
                "width": self.cfg.width, "height": self.cfg.height, "fps_target": self.cfg.fps,
                "bitrate_target": self.cfg.bitrate, "codec": "H.264 (VideoCore hardware encoder)", **self.stats,                "motion": self.motion_status()}

    def close(self):
        try:
            if self.recorder:
                self.stop_recording()
            self.live = False
            self.motion_set["sentry"] = False
            self._ensure_encoder()
            if self.picam2:
                self.picam2.close()
        except Exception:
            pass
