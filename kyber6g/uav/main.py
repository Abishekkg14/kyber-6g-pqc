"""UAV (Raspberry Pi 4B) application.

    python -m kyber6g.uav.main [-c uav.json]

Hardware: Waveshare RPi Camera (F) (OV5647 + 850 nm IR boards), 7Semi L89
GNSS (USB, via gpsd), 16x2 I2C LCD. All traffic to the GCS goes over the
Kyber-6G link: post-quantum-secured session establishment (ML-KEM-1024 +
X25519, ML-DSA-87) followed by AES-256-GCM authenticated encryption.
"""
import argparse
import collections
import logging
import os
import queue
import shutil
import signal
import struct
import threading
import time
from pathlib import Path

from .. import config as cfgmod
from ..crypto import handshake as hs
from ..crypto import identity as idm
from ..crypto import keyschedule as ks
from ..crypto.suites import get_suite
from ..lcd.display_manager import DisplayManager
from ..telemetry.gnss import GnssState, GpsdReader, SyntheticGnss
from ..transport import jsonmsg
from ..transport.blob import MAX_BLOB, BlobSender
from ..transport.link import UavLink
from .system import SystemMonitor

log = logging.getLogger("kyber6g.uav")
VIDEO_EXT = struct.Struct("!IHHB")     # frame_id, chunk_idx, chunk_count, flags
AUDIO_EXT = struct.Struct("!c4sIHH")   # b"L", tag of the live clip, block number, chunk_idx, chunk_count
VIDEO_CHUNK = 1100
FLAG_KEY = 1


def photo_name(t: float) -> str:
    """File name of a photo taken at time t, to the millisecond. With whole seconds, two photos taken within one
    second had the same name and the second replaced the first, on the UAV's card and on the ground station."""
    return time.strftime("img_%Y%m%d_%H%M%S", time.localtime(t)) + f"_{int(t * 1000) % 1000:03d}.jpg"


class TelemetryQueue:
    """Store-and-forward for telemetry: nothing is lost while the link is down (up to 2 h is kept and sent afterwards,
    marked backfill), and nothing is lost at the MOMENT it goes down either.

    The link layer only notices a dead link after link_timeout seconds of silence. What was sent during those
    seconds left this machine but never arrived (measured: 22 samples missing around a 43-minute standby of the
    ground station, 0 during it). The samples of that window are therefore kept and queued again when the link is
    declared down; the ground station ignores a sample it already has (same boot time and number)."""

    def __init__(self, unacked: int, capacity: int = 7200, drain: int = 20):
        self.backlog = collections.deque(maxlen=capacity)
        self.recent = collections.deque(maxlen=max(1, unacked))       # sent while "UP", not known to have arrived
        self.drain = drain                                            # old samples sent per step after recovery
        self.was_up = False

    def step(self, payload: dict, up: bool, send) -> None:
        """One telemetry period. `send(payload) -> bool` puts one sample on the link."""
        if self.was_up and not up:                                    # just declared dead: the last window is in doubt
            self.backlog.extendleft(reversed(self.recent))
            self.recent.clear()
        self.was_up = up
        if up and send(payload):
            self.recent.append(payload)
            for _ in range(min(len(self.backlog), self.drain)):       # oldest first, a few per period
                old = self.backlog.popleft()
                if not send({**old, "backfill": True, "satellites": []}):      # backfill is kept light
                    self.backlog.appendleft(old)
                    break
        else:
            self.backlog.append(payload)


class UavApp:
    MIN_FREE_START_MB = 500            # a recording is not started with less free space than this ...
    MIN_FREE_STOP_MB = 250             # ... and is closed cleanly when the card gets this full (3 Mbit/s = 22 MB/min)

    def __init__(self, cfg: cfgmod.UavConfig):
        self.cfg = cfg
        self._cmds = queue.Queue(maxsize=32)
        keydir = Path(cfg.link.keydir).expanduser() if cfg.link.keydir else idm.DEFAULT_DIR
        self.ident = idm.load_identity(keydir, "uav", cfg.link.uav_id.encode()[:8].ljust(8, b"-"))
        gcs_pk = idm.load_pinned_peer(keydir, "gcs")
        self.rec_ek = idm.load_recording_ek(keydir)
        # the classical half of the recording key: with it, stored photos and recordings get the hybrid key wrap
        # (ML-KEM-1024 + X25519) and this UAV's ML-DSA-87 signature (recording/sealing.py)
        self.rec_xpk = idm.load_recording_xpk(keydir)
        if self.rec_xpk is None:
            log.warning("no X25519 recording key from the ground station (peers/%s.pk): stored photos and recordings are "
                        "written in format 1 (ML-KEM-1024 alone, unsigned). `kyber6g.sh deploy` installs the key.", idm.RECORDING_X)
        # the cryptography is checked against published values, and this node's key pair against itself, before
        # anything is sent with it: a node that computes wrong does not start (crypto/selftest.py)
        from ..crypto import selftest
        self.crypto_selftest = selftest.summary(selftest.require(ident=self.ident))
        log.info("cryptographic self-test passed: %d checks in %.0f ms (liboqs %s)", self.crypto_selftest["checks"],
                 self.crypto_selftest["ms"], self.crypto_selftest["liboqs"])
        self.gnss = GnssState()
        self.gnss_thread = SyntheticGnss(self.gnss) if cfg.gnss_synthetic else GpsdReader(self.gnss, cfg.gpsd_host, cfg.gpsd_port)
        self.mob = hs.MobilityTracker(cfg.link.mobility_cell_deg)
        self.link = UavLink(cfg.link, self.ident, gcs_pk, self.mobility)
        self.link.on_control = self.on_control
        self.blobs = BlobSender(self.link.send)
        self.sysmon = SystemMonitor()
        self.camera = None
        self.frame_id = 0
        self.video_stats = {"frames_sent": 0, "chunks_sent": 0, "send_failures": 0, "seal_us_avg": None}
        self._seal_acc = [0.0, 0]
        self.events = []
        self.lcd = DisplayManager(self.lcd_state, cfg.lcd_bus, cfg.lcd_addr, cfg.lcd_screen_s) if cfg.lcd_enabled else None
        self.tm_seq = 0
        self.boot_ts = round(time.time(), 3)       # identifies this run of the UAV app: telemetry numbers restart at 1 with it
        self._msg_no = 0
        self._msg_lock = threading.Lock()
        self.telemetry_backlog = 0
        self.running = True
        # owner-only (0700): the files in it are encrypted, but whoever can write the directory can delete or swap them
        idm.private_dir(Path(cfg.camera.recordings_dir).expanduser())
        from ..recording.photos import PhotoStore
        self.photos = PhotoStore(cfg.camera.photos_dir, self.rec_ek, x25519_pk=self.rec_xpk, signer=self.ident)
        # sealed audio clips (audio/quaver.py): always hybrid-wrapped and signed, so both recording keys are needed
        self.audio = None
        if self.rec_xpk is not None:
            from ..audio.store import AudioStore
            self.audio = AudioStore(cfg.audio_dir, self.rec_ek, self.rec_xpk, self.ident, cfg.link.uav_id, gnss=self.gnss.snapshot)
        self.audio_live = None             # the clip that is being sent while it is sealed, if any
        self.audio_stats = {"clips_sealed": 0, "live_blocks_sent": 0, "live_send_failures": 0}
        # motion watch (camera/motion.py): looks -> events; PHOTO ON MOTION takes a sealed photo when movement begins
        from ..camera.motion import MotionState
        self.motion_state = MotionState()
        self.motion_photo = False
        self._motion_photo_at = self._motion_logged = 0.0
        self._motion_scene = False

    # ------------------------------------------------------------ context
    def mobility(self):
        g = self.gnss.snapshot()
        return self.mob.update(g["lat"], g["lon"])        # hysteresis: GNSS noise must not flip the cell (and force handshakes)

    def lcd_state(self):
        return {"gnss": self.gnss.snapshot(), "link": {"state": self.link.state},
                "camera": self.camera.status() if self.camera else {}, "system": self.sysmon.snapshot(),
                "aead": "AES-GCM" if self.link.suite.suite_id == 1 else "CHACHA"}

    def event(self, kind, msg):
        self.events.append({"t": time.time(), "kind": kind, "msg": msg})
        self.events = self.events[-100:]
        log.info("%s: %s", kind, msg)

    # --------------------------------------------------------------- video
    def on_live_frame(self, data: bytes, keyframe: bool, ts_us: int):
        fid = self.frame_id
        self.frame_id = (self.frame_id + 1) & 0xFFFFFFFF
        body = struct.pack("!Q", ts_us) + data
        parts = [body[i:i + VIDEO_CHUNK] for i in range(0, len(body), VIDEO_CHUNK)]
        flags = FLAG_KEY if keyframe else 0
        t0 = time.perf_counter()
        for i, p in enumerate(parts):
            if not self.link.send(ks.STREAM_VIDEO, p, VIDEO_EXT.pack(fid, i, len(parts), flags)):
                self.video_stats["send_failures"] += 1
                return
        dt = (time.perf_counter() - t0) * 1e6 / len(parts)
        a = self._seal_acc
        a[0] += dt; a[1] += 1
        if a[1] >= 30:
            self.video_stats["seal_us_avg"] = round(a[0] / a[1], 1)
            a[0], a[1] = 0.0, 0
        self.video_stats["frames_sent"] += 1
        self.video_stats["chunks_sent"] += len(parts)

    # -------------------------------------------------------------- motion
    def platform_moving(self) -> bool:
        """Is the UAV under way? Asked by the motion watch before every look: with a GNSS fix and more than 1 m/s
        over the ground (a receiver at rest reads a few tenths), yes."""
        g = self.gnss.snapshot()
        speed = g.get("speed_mps")
        return (g.get("mode") or 0) >= 2 and isinstance(speed, (int, float)) and speed > 1.0

    def on_motion(self, res: dict):
        """Every look of the motion watch (called in its thread). While something moves, and when that begins or ends,
        a short report goes out in the status stream: text in the link's authenticated records, a few hundred bytes,
        whether or not any video is on the air."""
        st = self.motion_state
        ev = st.update(res)
        now = time.time()
        if ev == "start":
            if now - self._motion_logged > 10:       # a thing that keeps starting and stopping must not fill the event log
                self._motion_logged = now
                self.event("MOTION", f"movement seen in {len(res['regions'])} place(s) of the picture")
            if self.motion_photo and now - self._motion_photo_at >= self.cfg.camera.motion_photo_gap_s:
                self._motion_photo_at = now
                try:                                 # like a command from the ground station, but nobody waits for the answer
                    self._cmds.put_nowait({"t": "capture_image", "id": None, "trigger": "motion"})
                except queue.Full:
                    pass
        if st.on or ev or res["scene"] != self._motion_scene:
            self._send_json(ks.STREAM_STATUS, {
                "t": "motion", "ts": res["ts"], "on": st.on, "ev": ev, "since": st.since if st.on else None, "n": st.events,
                "regions": res["regions"], "scene": res["scene"], "cam": bool((res.get("ego") or {}).get("moving"))})
        self._motion_scene = res["scene"]

    # ------------------------------------------------------------ commands
    def on_control(self, msg):
        """Called in the link's receive thread: only queue the command. A slow one (a still capture, closing a
        recording, reading a 50 MB file) run here would stop keepalives being processed and look like a dead link."""
        if self.blobs.on_control(msg):
            return
        try:
            self._cmds.put_nowait(msg)
        except queue.Full:
            self.link.send_control({"t": "ack", "id": msg.get("id"), "cmd": msg.get("t"), "ok": False,
                                    "error": "UAV busy: too many commands waiting"})

    def command_loop(self):
        while self.running:
            try:
                msg = self._cmds.get(timeout=0.5)
            except queue.Empty:
                continue
            t, cid = msg.get("t"), msg.get("id")
            try:
                result = self.handle(t, msg)
                ack = {"t": "ack", "id": cid, "cmd": t, "ok": True, "result": result}
            except (RuntimeError, ValueError, FileNotFoundError) as e:
                # a command that is refused on purpose ("already recording", a value out of range, no such file): the
                # ground station gets the reason; here one line, not a traceback that looks like a fault in the log
                log.warning("command %s refused: %s: %s", t, type(e).__name__, e)
                ack = {"t": "ack", "id": cid, "cmd": t, "ok": False, "error": f"{type(e).__name__}: {e}"}
            except Exception as e:
                log.exception("command %s failed", t)
                ack = {"t": "ack", "id": cid, "cmd": t, "ok": False, "error": f"{type(e).__name__}: {e}"}
            try:
                self.link.send_control(ack)
            except Exception:                    # e.g. a result that is not JSON-serialisable: still answer
                log.exception("ack for %s", t)
                self.link.send_control({"t": "ack", "id": cid, "cmd": t, "ok": False, "error": "internal: bad result"})

    def free_mb(self):
        try:
            return shutil.disk_usage(Path(self.cfg.camera.recordings_dir).expanduser()).free / 1e6
        except OSError:
            return None

    def handle(self, t, msg):
        cam = self.camera
        if cam is None and t in ("start_live", "stop_live", "start_rec", "stop_rec", "capture_image", "set_mode",
                                 "set_video", "focus", "motion"):
            raise RuntimeError("camera is still starting")
        if t == "start_live":
            cam.set_live(True); self.event("VIDEO", "live stream started")
            if self.lcd: self.lcd.show_now("KYBER-6G", "LIVE: ON")
        elif t == "stop_live":
            cam.set_live(False); self.event("VIDEO", "live stream stopped")
        elif t == "start_rec":
            from ..recording.recorder import RollingRecorder
            if cam.recorder is not None:
                # check before creating a file, so a second REC press leaves no orphan
                raise RuntimeError(f"already recording {cam.recorder.name}")
            free = self.free_mb()
            if free is not None and free < self.MIN_FREE_START_MB:
                raise RuntimeError(f"SD card almost full ({free:.0f} MB free): delete old recordings on the Pi first")
            c = self.cfg.camera
            rec = RollingRecorder(c.recordings_dir, self.rec_ek,
                                  {"codec": "h264", "width": c.width, "height": c.height, "fps": c.fps,
                                   "bitrate": c.bitrate, "uav": self.cfg.link.uav_id},
                                  max_bytes=int(c.recording_part_mb) << 20, x25519_pk=self.rec_xpk, signer=self.ident)
            try:
                cam.start_recording(rec)
            except Exception:
                rec.abort()
                raise
            self.event("REC", f"recording started {rec.name}")
            if self.lcd: self.lcd.show_now("KYBER-6G", "REC: STARTED")
            return {"name": rec.name, "started_at": rec.t0}
        elif t == "stop_rec":
            summary = cam.stop_recording()
            if summary is None:
                raise RuntimeError("not recording")
            self.event("REC", f"recording stopped {summary}")
            if self.lcd: self.lcd.show_now("KYBER-6G", "REC: SAVED ENC")
            return summary
        elif t == "capture_image":
            jpeg, info = cam.capture_still()
            info["gnss"] = {k: self.gnss.snapshot()[k] for k in ("fix", "lat", "lon", "alt_m", "time", "sats_used")}
            info["captured_at"] = time.time()
            if msg.get("trigger") == "motion":      # taken by PHOTO ON MOTION, not by the operator
                info["trigger"] = "motion"
            name = photo_name(info["captured_at"])
            # keep an encrypted copy on the SD card first (only the GCS can open it), then send
            info.update(self.photos.save(name, jpeg, {k: info.get(k) for k in
                                                      ("width", "height", "mode", "source", "captured_at", "gnss", "trigger")
                                                      if k in info}))
            t0 = time.perf_counter()
            meta = self.blobs.send(ks.STREAM_IMAGE, "image", name, jpeg, info)
            meta["queue_ms"] = round((time.perf_counter() - t0) * 1000, 2)
            self.event("IMAGE", f"captured {name} {len(jpeg)} B, stored encrypted as {info['stored_as']}")
            if self.lcd: self.lcd.show_now("IMG: SAVED ENC", "IMG: SENT ENC")
            return {k: meta[k] for k in ("id", "name", "size", "sha256", "chunks")} | {"info": info}
        elif t == "list_photos":
            # newest 120: the reply is one control message (35 KB at most)
            return {"photos": self.photos.list()[-120:], **self.photos.usage(), "dir": str(self.photos.dir)}
        elif t == "fetch_photo":
            name = Path(msg["name"]).name
            meta = self.blobs.send(ks.STREAM_IMAGE, "photo_enc", name, self.photos.read(name), {"encrypted_at_rest": True})
            return {k: meta[k] for k in ("id", "name", "size", "sha256", "chunks")}
        elif t == "set_mode":
            cam.set_mode(msg["mode"]); self.event("CAMERA", f"mode {msg['mode']}")
            if self.lcd: self.lcd.show_now("CAMERA MODE", msg["mode"])
        elif t == "set_video":
            cam.set_video(msg.get("width"), msg.get("height"), msg.get("fps"), msg.get("bitrate"))
        elif t == "motion":
            # the motion watch: {enabled, sensitivity: low|medium|high, hz, sentry (keep the camera running for the watch
            # when nobody watches the video), photo (a sealed photo when movement begins)}; without arguments: its state
            if isinstance(msg.get("selftest"), dict):    # a measurement: targets drawn into pictures of this camera (in memory)
                st = msg["selftest"]
                seed = st.get("seed") if isinstance(st.get("seed"), int) and not isinstance(st.get("seed"), bool) else 1
                return cam.motion_selftest(st.get("cases"), st.get("looks", 40), seed)
            if msg.get("trace"):                     # what the last looks measured (numbers only), for diagnosis
                n = msg.get("trace")
                return {"trace": cam.motion_trace(n if isinstance(n, int) and not isinstance(n, bool) else 40)}
            photo = msg.get("photo")
            if photo is not None and not isinstance(photo, bool):
                raise ValueError("photo must be true or false")
            st = cam.set_motion(msg.get("enabled"), msg.get("sensitivity"), msg.get("hz"), msg.get("sentry"))
            if photo is not None:
                self.motion_photo = photo
            changed = {k: msg[k] for k in ("enabled", "sensitivity", "hz", "sentry", "photo") if msg.get(k) is not None}
            if changed:
                self.event("MOTION", f"watch set: {changed}")
            return {**st, "photo": self.motion_photo, **self.motion_state.summary()}
        elif t == "list_recordings":
            d = Path(self.cfg.camera.recordings_dir).expanduser()
            out = []
            for p in sorted(d.glob("*.k6grec")):
                try:
                    st = p.stat()
                except OSError:                 # deleted between the listing and the stat
                    continue
                out.append({"name": p.name, "bytes": st.st_size, "mtime": st.st_mtime,
                            "fetchable": st.st_size <= MAX_BLOB})
            return out[-200:]                   # the reply travels as one control message: keep it bounded
        elif t == "fetch_recording":
            p = Path(self.cfg.camera.recordings_dir).expanduser() / Path(msg["name"]).name
            if cam is not None and cam.recorder is not None and p.name == getattr(cam.recorder, "current_name", cam.recorder.name):
                raise RuntimeError("recording still in progress")
            if not p.is_file():
                raise FileNotFoundError(f"no such recording on the UAV: {p.name}")
            size = p.stat().st_size
            if size > MAX_BLOB:
                # Reading it would need more than twice its size in RAM on the Pi; the receiver would refuse it anyway.
                raise RuntimeError(f"{p.name} is {size / 1e6:.0f} MB, over the {MAX_BLOB >> 20} MB limit of one transfer. "
                                   f"Copy it instead: bash run/kyber6g.sh pull {p.name}")
            meta = self.blobs.send(ks.STREAM_RECORDING, "recording", p.name, p.read_bytes(), {})
            return {k: meta[k] for k in ("id", "name", "size", "sha256", "chunks")}
        elif t == "focus":
            _, info = cam.capture_still()
            return {"sharpness": info["sharpness"], "mean_luma": info["mean_luma"]}
        elif t in ("list_audio", "record_audio", "stop_audio", "fetch_audio", "audio_blocks", "check_audio"):
            return self.handle_audio(t, msg)
        elif t in ("pq_ratchet", "cached_rekey", "full_handshake"):
            # `tag` labels the entry in the link's operation log (see "oplog"); `wait` = carry it out here and answer
            # with the time it took on this clock (a full handshake always does)
            tag = str(msg.get("tag") or "manual")[:24]
            if t == "pq_ratchet":
                return self.link.pq_ratchet_now(tag) if msg.get("wait") else {"started": self.link.request_pq_ratchet(tag)}
            if t == "cached_rekey" and not msg.get("wait"):
                self.link.request_cached_rekey(); return {"started": True}
            return self.link.rekey_now("cached" if t == "cached_rekey" else "full", tag)
        elif t == "rtt_probe":
            n, interval, pad = msg.get("n"), msg.get("interval"), msg.get("pad")
            ok = lambda v: isinstance(v, (int, float)) and not isinstance(v, bool)
            return self.link.rtt_probe(n if ok(n) else 100, interval if ok(interval) else 0.05, pad=pad if ok(pad) else 0)
        elif t == "oplog":
            # the link's own record of every handshake / rekey / ratchet (time on this clock, outcome, duration),
            # 150 entries per answer starting at number `since`: a control message is limited to 35 kB
            since = msg.get("since")
            since = since if isinstance(since, int) and not isinstance(since, bool) else 0
            entries = [e for e in list(self.link.oplog) if e["n"] > since][:150]
            return {"entries": entries, "last": self.link._op_n, "more": bool(entries) and entries[-1]["n"] < self.link._op_n}
        elif t == "status":
            return self.status()
        else:
            raise ValueError(f"unknown command {t!r}")
        return None

    # --------------------------------------------------------------- audio
    def handle_audio(self, t, msg):
        a = self.audio
        if a is None:
            raise RuntimeError("no X25519 recording key from the ground station: sealed audio needs it (run kyber6g.sh deploy)")
        if t == "list_audio":
            # newest 120 clips: the reply is one control message
            return {**a.listing(120, 40),
                    "live": {k: v for k, v in self.audio_live.items() if k != "stop"} if self.audio_live else None}
        if t == "record_audio":
            sources = a.sources()
            name = Path(str(msg.get("source") or (sources[0]["name"] if sources else ""))).name
            if not name:
                raise FileNotFoundError("no audio source on the UAV (no microphone is attached): copy a file into its inbox "
                                        "with: bash run/kyber6g.sh audio-put FILE")
            if self.audio_live is not None:
                raise RuntimeError(f"an audio clip is already being recorded ({self.audio_live['source']})")
            free = self.free_mb()
            if free is not None and free < self.MIN_FREE_STOP_MB:
                raise RuntimeError(f"SD card almost full ({free:.0f} MB free)")
            keep = bool(msg.get("keep"))
            # frames per block and frame cap: the settings, unless the command names others (measurements do)
            opt = {}
            for key, default, low, top in (("frames_per_block", self.cfg.audio_frames_per_block, 1, 64),
                                           ("frame_cap", self.cfg.audio_frame_cap, 0, 4096)):
                v = msg.get(key, default)
                if isinstance(v, bool) or not isinstance(v, int) or not low <= v <= top:
                    raise ValueError(f"{key} must be {low}..{top}")
                opt[key] = v
            if msg.get("live"):
                if not (a.inbox / name).is_file():
                    raise FileNotFoundError(f"no such audio source on the UAV: {name}")
                self.audio_live = {"source": name, "tag": os.urandom(4).hex(), "t0": time.time(), "blocks": 0, "stop": False}
                threading.Thread(target=self._audio_live_run, args=(name, keep, opt), daemon=True, name="audio-live").start()
                return {"started": True, "live": True, "source": name, "tag": self.audio_live["tag"]}
            res = a.record(name, opt["frames_per_block"], keep_source=keep, frame_cap=opt["frame_cap"])
            self.audio_stats["clips_sealed"] += 1
            self.event("AUDIO", f"sealed {res['name']}: {res['frames']} frames in {res['blocks']} blocks, {res['bytes']} B, "
                                f"{res['seal_ms']} ms; only the ground station can open it")
            if self.lcd: self.lcd.show_now("AUDIO: SEALED", f"CLIP {res['clip_no']}")
            return res
        if t == "stop_audio":
            if self.audio_live is None:
                raise RuntimeError("no audio clip is being recorded")
            self.audio_live["stop"] = True
            return {"stopping": self.audio_live["source"]}
        name = Path(str(msg.get("name") or "")).name
        if t == "fetch_audio":
            meta = self.blobs.send(ks.STREAM_AUDIO, "audio_enc", name, a.read(name), {"encrypted_at_rest": True})
            return {k: meta[k] for k in ("id", "name", "size", "sha256", "chunks")}
        if t == "audio_blocks":
            want = msg.get("blocks")
            idx = [i for i in (want if isinstance(want, list) else []) if isinstance(i, int) and not isinstance(i, bool)][:2048]
            meta = self.blobs.send(ks.STREAM_AUDIO, "audio_blocks", name, a.blocks(name, idx), {"blocks": idx, "tag": str(msg.get("tag") or "")[:16]})
            return {k: meta[k] for k in ("id", "name", "size", "chunks")} | {"blocks": len(idx)}
        if t == "check_audio":             # the stored clip against this UAV's own signature: no secret involved
            return a.check(name, self.ident.pk)
        raise ValueError(f"unknown command {t!r}")

    def _audio_send(self, tag: bytes, index: int, block: bytes) -> bool:
        """One sealed block on the air as it is on the card: the link's records carry it, nothing seals it again
        under another key that the stored copy would not have."""
        parts = [block[i:i + VIDEO_CHUNK] for i in range(0, len(block), VIDEO_CHUNK)]
        for i, p in enumerate(parts):
            if not self.link.send(ks.STREAM_AUDIO, p, AUDIO_EXT.pack(b"L", tag, index, i, len(parts))):
                self.audio_stats["live_send_failures"] += 1
                return False
        self.audio_stats["live_blocks_sent"] += 1
        return True

    def _audio_live_run(self, name: str, keep: bool, opt: dict):
        st = self.audio_live
        tag, trailer = bytes.fromhex(st["tag"]), []
        try:
            def on_block(kind, i, b):
                if kind == "block":
                    self._audio_send(tag, i, b)
                    st["blocks"] = i + 1
                elif kind == "head":       # without the head nothing can be opened: sent with retransmission
                    self.blobs.send(ks.STREAM_AUDIO, "audio_head", st["tag"] + ".head", b, {"tag": st["tag"], "source": "file"})
                else:
                    trailer.append(b)
            res = self.audio.record(name, opt["frames_per_block"], keep_source=keep, on_block=on_block, realtime=True,
                                    should_stop=lambda: st["stop"] or not self.running, frame_cap=opt["frame_cap"])
            self.audio_stats["clips_sealed"] += 1
            info = {k: res[k] for k in ("name", "clip_id", "clip_no", "blocks", "block_bytes", "bytes", "frames", "duration_s")}
            self.blobs.send(ks.STREAM_AUDIO, "audio_trailer", st["tag"] + ".trailer", trailer[0], {"tag": st["tag"], **info})
            self.event("AUDIO", f"live clip {res['name']}: {res['frames']} frames in {res['blocks']} blocks, sealed once for the card and the link")
            if self.lcd: self.lcd.show_now("AUDIO: SENT ENC", f"CLIP {res['clip_no']}")
        except Exception as e:
            log.exception("live audio")
            self.event("AUDIO", f"live recording of {name} failed: {type(e).__name__}: {e}")
        finally:
            self.audio_live = None

    # ------------------------------------------------------------- loops
    def status(self):
        free = self.free_mb()
        cam = self.camera.status() if self.camera else {"available": False}
        if isinstance(cam.get("motion"), dict):
            cam["motion"] = {**cam["motion"], "photo": self.motion_photo, **self.motion_state.summary()}
        return {"t": "status", "ts": time.time(), "system": self.sysmon.snapshot(),
                "camera": cam,
                "video_tx": self.video_stats, "link": self.link.status(),
                "lcd": {"ok": self.lcd.ok, "error": self.lcd.error, "updates": self.lcd.updates} if self.lcd else None,
                "gnss_source": self.gnss.snapshot()["source"], "telemetry_backlog": self.telemetry_backlog,
                "photos_on_uav": self.photos.usage(),
                "audio_on_uav": self.audio.usage() if self.audio else None, "audio_tx": self.audio_stats,
                "audio_live": {k: v for k, v in self.audio_live.items() if k != "stop"} if self.audio_live else None,
                "crypto": getattr(self, "crypto_selftest", None),
                "storage": {"free_mb": round(free) if free is not None else None, "transfer_limit_mb": MAX_BLOB >> 20,
                            "recording_part_mb": self.cfg.camera.recording_part_mb},
                "events": self.events[-15:] + [{"t": t, "kind": k, "msg": m} for t, k, m in list(self.link.events)[-10:]],
                "blobs_done": self.blobs.completed[-5:]}

    def _send_json(self, stream, obj):
        with self._msg_lock:                 # telemetry and status threads both number their messages here
            self._msg_no += 1
            no = self._msg_no
        ok = True
        for ext, piece in jsonmsg.split(obj, no):
            ok = self.link.send(stream, piece, ext) and ok
        return ok

    def telemetry_loop(self):
        """1 Hz telemetry. While the link is down, samples are kept (store-and-
        forward, up to 2 h) and sent after recovery marked backfill=true."""
        period = 1.0 / self.cfg.telemetry_hz
        q = TelemetryQueue(unacked=int(self.cfg.link.link_timeout_s * self.cfg.telemetry_hz) + 2)
        while self.running:
            t0 = time.time()
            try:
                g = self.gnss.snapshot(with_sats=True)
                self.tm_seq += 1
                payload = {"ts": t0, "n": self.tm_seq, "boot": self.boot_ts, **g}
                q.step(payload, self.link.state == "UP", lambda p: self._send_json(ks.STREAM_TELEMETRY, p))
                self.telemetry_backlog = len(q.backlog)
            except Exception:                    # one bad sample must not end telemetry for the rest of the flight
                log.exception("telemetry loop")
            time.sleep(max(0.0, period - (time.time() - t0)))

    def status_loop(self):
        while self.running:
            try:
                self._watch_recording()
                self._send_json(ks.STREAM_STATUS, self.status())
                self.blobs.expire()
            except Exception:
                log.exception("status loop")
            time.sleep(1.0)

    def _watch_recording(self):
        """Once a second: report a recording that was cut off by a write error, and close a running recording
        cleanly before the SD card is full (a full card would also break logging and the photo store)."""
        cam = self.camera
        if cam is None:
            return
        failed = cam.take_rec_failure()
        if failed:
            self.event("REC", f"recording {failed['name']} stopped by a write error after {failed['frames']} frames: {failed['error']}")
            if self.lcd: self.lcd.show_now("REC: STOPPED", "WRITE ERROR")
        if cam.recorder is not None:
            free = self.free_mb()
            if free is not None and free < self.MIN_FREE_STOP_MB:
                summary = cam.stop_recording()
                self.event("REC", f"recording closed automatically: only {free:.0f} MB free on the SD card {summary}")
                if self.lcd: self.lcd.show_now("REC: STOPPED", "SD CARD FULL")

    def run(self):
        self.gnss_thread.start()
        if self.lcd:
            self.lcd.start()
        from ..camera.camera import CameraService
        self.camera = CameraService(self.cfg.camera, self.on_live_frame, self.on_motion, self.platform_moving)
        if not self.camera.available:
            self.event("CAMERA", f"not available: {self.camera.error}")
        else:
            self.event("CAMERA", f"{self.camera.model} ready")
        if self.audio is not None:
            for name in self.audio.recover_parts():
                self.event("AUDIO", f"{name}: sealing was cut off (power?); closed from the blocks on the card and signed as incomplete")
        self.link.start()
        threading.Thread(target=self.telemetry_loop, daemon=True, name="telemetry").start()
        threading.Thread(target=self.status_loop, daemon=True, name="status").start()
        threading.Thread(target=self.command_loop, daemon=True, name="commands").start()
        self.event("START", f"suite {get_suite(self.cfg.link.suite_id).name}; GCS {self.cfg.link.gcs_host}:{self.cfg.link.gcs_port}")
        stop = threading.Event()
        signal.signal(signal.SIGTERM, lambda *a: stop.set())
        signal.signal(signal.SIGINT, lambda *a: stop.set())
        stop.wait()
        self.shutdown()

    def shutdown(self):
        self.running = False
        try:
            if self.camera and self.camera.recorder:
                self.event("REC", f"closed on shutdown {self.camera.stop_recording()}")
        finally:
            if self.camera:
                self.camera.close()
            if self.lcd and self.lcd.lcd:
                try:
                    self.lcd.running = False
                    time.sleep(0.6)
                    self.lcd.lcd.show("KYBER-6G", "STOPPED")
                except Exception:
                    pass
            self.link.stop()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--config")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if a.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    from ..crypto.secure_bytes import no_core_dumps
    if not no_core_dumps():             # the UAV's signing key is in memory: a crash must not leave it in a core file
        log.warning("could not disable core dumps: a crash may write key material to disk")
    UavApp(cfgmod.load(cfgmod.UavConfig, a.config)).run()


if __name__ == "__main__":
    main()
