"""Ground control station (laptop / WSL): secure receiver, storage, analytics,
object detection and the dashboard.

    python -m kyber6g.ground.main [-c ground.json]      ->  http://127.0.0.1:8600

The dashboard listens on 127.0.0.1 only (it can command the UAV). It has no login, so the web API defends itself
against the two ways another web page in the operator's browser could reach it (see `request_refused`): requests
sent across origins, and DNS rebinding.
"""
import argparse
import base64
import collections
import csv
import hashlib
import io
import ipaddress
import itertools
import json
import logging
import mimetypes
import queue
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .. import config as cfgmod
from ..crypto import identity as idm
from ..crypto import keyschedule as ks
from ..recording.photos import PhotoError, open_image
from ..audio.quaver import AudioError
from ..recording.recorder import RecordingError, decrypt_recording, frame_rate
from ..transport import jsonmsg
from ..transport.blob import BlobReceiver
from ..transport.link import GcsLink
from . import analytics
from .audio_desk import AudioDesk
from .store import Store
from .video_sink import VideoSink

log = logging.getLogger("kyber6g.ground")
STATIC = Path(__file__).with_name("static")
# types the browser is strict about (a module script or a font with the wrong type is refused)
CONTENT_TYPES = {".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css", ".woff2": "font/woff2",
                 ".html": "text/html; charset=utf-8", ".png": "image/png", ".jpg": "image/jpeg", ".mp4": "video/mp4",
                 ".json": "application/json", ".svg": "image/svg+xml", ".mp3": "audio/mpeg", ".wav": "audio/wav"}
UAV_COMMANDS = {"start_live", "stop_live", "start_rec", "stop_rec", "capture_image", "set_mode", "set_video",
                "list_recordings", "fetch_recording", "list_photos", "fetch_photo", "focus", "pq_ratchet",
                "cached_rekey", "full_handshake", "oplog", "rtt_probe", "status",
                "list_audio", "record_audio", "stop_audio", "fetch_audio", "check_audio", "motion"}
RESERVED_ARGS = {"t", "id"}              # the envelope of a command; never taken from the request's arguments
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}")     # file names accepted from the UAV / put in a header


def safe_name(name) -> str:
    """A file name received from the UAV, reduced to its last component and refused unless it is plain: it becomes
    a path on this machine, a URL and an HTTP header, and the UAV is not trusted to choose those freely."""
    name = Path(name).name if isinstance(name, str) else ""
    if not SAFE_NAME.fullmatch(name):
        raise ValueError(f"unacceptable file name {name[:60]!r}")
    return name


# Telemetry fields that go into arithmetic, the database's numeric columns, the map and the charts: each must be a
# finite number within its range or it is stored as "not available" (None). Text fields are cut to 160 characters.
TM_NUMBERS = {"ts": (0, 1e11), "n": (0, 2**53), "boot": (0, 1e11), "mode": (0, 3), "lat": (-90, 90), "lon": (-180, 180),
              "alt_m": (-1000, 100000), "alt_msl_m": (-1000, 100000), "alt_hae_m": (-1000, 100000),
              "geoid_sep_m": (-200, 200), "speed_mps": (0, 1000), "track_deg": (-360, 360), "climb_mps": (-500, 500),
              "eph_m": (0, 1e6), "epv_m": (0, 1e6), "hdop": (0, 1000), "vdop": (0, 1000), "pdop": (0, 1000),
              "sats_used": (0, 500), "sats_seen": (0, 500), "ttff_s": (0, 1e7), "gga_quality": (0, 9),
              "gga_sats": (0, 500), "nmea_rate_hz": (0, 1000), "receiver_minus_system_s": (-1e10, 1e10)}


def clean_telemetry(tm):
    """One telemetry sample from the UAV with every field of the expected type, or None if it has no usable time.

    The sample is authenticated, so this is not about an outsider: it keeps a faulty or taken-over UAV from putting
    text where a number is expected (it would end up in SQLite, in the analytics and on the map)."""
    if not isinstance(tm, dict) or jsonmsg.num(tm.get("ts"), *TM_NUMBERS["ts"]) is None:
        return None
    out = {}
    for k, v in tm.items():
        if k in TM_NUMBERS:
            v = jsonmsg.num(v, *TM_NUMBERS[k])
        elif isinstance(v, str):
            v = v[:160]
        out[k] = v
    if isinstance(out.get("n"), float):
        out["n"] = int(out["n"]) if out["n"].is_integer() else None
    if isinstance(out.get("mode"), float):
        out["mode"] = int(out["mode"])
    if out.get("lat") is None or out.get("lon") is None:
        out["lat"] = out["lon"] = None                   # a position is both coordinates or nothing
    sats = []
    for s in (tm.get("satellites") if isinstance(tm.get("satellites"), list) else [])[:96]:
        # [constellation, PRN, azimuth, elevation, C/N0, used]
        if isinstance(s, list) and len(s) >= 6 and isinstance(s[0], str):
            sats.append([s[0][:12], jsonmsg.num(s[1], 0, 1000), jsonmsg.num(s[2], -360, 360), jsonmsg.num(s[3], -90, 90),
                         jsonmsg.num(s[4], 0, 100), 1 if s[5] else 0])
    out["satellites"] = sats
    out["backfill"] = bool(tm.get("backfill"))
    return out


def clean_motion(m):
    """A report of the UAV's motion watch, reduced to what this side uses and every value checked (the page draws the
    regions; the times go into arithmetic): None if it is not one. Regions are [x, y, w, h, strength], each 0..1."""
    if not isinstance(m, dict) or jsonmsg.num(m.get("ts"), 0, 1e11) is None:
        return None
    regions = []
    for r in (m.get("regions") if isinstance(m.get("regions"), list) else [])[:8]:
        if isinstance(r, list) and len(r) == 5 and all(jsonmsg.num(v, 0, 1) is not None for v in r):
            regions.append([float(v) for v in r])
    return {"ts": float(m["ts"]), "on": m.get("on") is True, "ev": m.get("ev") if m.get("ev") in ("start", "end") else None,
            "since": jsonmsg.num(m.get("since"), 0, 1e11), "regions": regions, "scene": m.get("scene") is True,
            "cam": m.get("cam") is True}


def host_allowed(host: str, port: int, extra=()) -> bool:
    """Is this the Host header of a request really meant for the dashboard?

    DNS rebinding: a web page served from evil.example can make its own name resolve to 127.0.0.1 and then talk to
    this server as "same origin". Such a request always carries the attacker's NAME in its Host header, so only
    `localhost`, IP-address literals and names the operator listed (`http_allowed_hosts`) are accepted."""
    host = (host or "").strip().lower()
    m = re.fullmatch(r"(\[[0-9a-f:.]+\]|[^:\[\]]+)(?::(\d{1,5}))?", host)
    if not m or int(m.group(2) or 80) != port:
        return False
    name = m.group(1)
    if name == "localhost" or name in {str(e).lower() for e in extra}:
        return True
    try:
        ipaddress.ip_address(name.strip("[]"))
        return True
    except ValueError:
        return False


def request_refused(method: str, path: str, headers, port: int, extra_hosts=()):
    """Why a request must not be served (None = serve it). Three checks, all on headers a web page cannot forge:

    Host            see `host_allowed` (DNS rebinding).
    Sec-Fetch-Site  sent by every current browser: `same-origin` (our own page) and `none` (address bar, bookmark)
                    pass; from any other site only a plain navigation to the page itself is allowed, never the API,
                    the video or the files - a foreign page cannot trigger commands, exports or streams.
    Origin          on a POST it must be this server (older browsers without Sec-Fetch-Site).

    Programs that are not browsers (curl, the test tools) send none of these headers and are served: they run on
    this machine already, and the dashboard binds to 127.0.0.1."""
    host = headers.get("Host", "")
    if not host_allowed(host, port, extra_hosts):
        return "host not allowed"
    site = (headers.get("Sec-Fetch-Site") or "").lower()
    if site and site not in ("same-origin", "none"):
        navigation = method == "GET" and (headers.get("Sec-Fetch-Mode") or "").lower() == "navigate" and \
            (headers.get("Sec-Fetch-Dest") or "document").lower() == "document" and path in ("/", "/index.html")
        if not navigation:
            return "cross-site request refused"
    origin = headers.get("Origin")
    if method != "GET" and origin is not None and origin.lower() != f"http://{host.strip().lower()}":
        return "cross-origin request refused"
    return None


def page_csp(html: bytes) -> str:
    """Content-Security-Policy of the dashboard page: scripts only from this server (plus the page's own inline
    import map, allowed by its hash), no plug-ins, no framing, data sent nowhere but here. Images may also come from
    the two map-tile servers. Should text from the UAV ever slip past the escaping in app.js, it cannot run."""
    hashes = ["'sha256-" + base64.b64encode(hashlib.sha256(m.group(2)).digest()).decode() + "'"
              for m in re.finditer(rb"<script\b([^>]*)>(.*?)</script>", html, re.S | re.I)
              if m.group(2).strip() and b"src=" not in m.group(1).lower()]
    return "; ".join([
        "default-src 'self'", "script-src 'self' " + " ".join(hashes), "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: blob: https://server.arcgisonline.com https://tile.openstreetmap.org",
        "media-src 'self' blob:", "connect-src 'self'", "font-src 'self' data:", "worker-src 'self' blob:",
        "object-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'"])


class GroundApp:
    def __init__(self, cfg: cfgmod.GroundConfig, detector=True):
        self.cfg = cfg
        keydir = Path(cfg.link.keydir).expanduser() if cfg.link.keydir else idm.DEFAULT_DIR
        self.ident = idm.load_identity(keydir, "gcs", cfg.link.gcs_id.encode()[:8].ljust(8, b"-"))
        uav_pk = self.uav_pk = idm.load_pinned_peer(keydir, "uav")
        self.rec_dk = idm.load_recording_dk(keydir)
        # the classical half of the recording key (files of format 2: hybrid key wrap + the UAV's ML-DSA-87 signature,
        # checked against the pinned key above). None on a station provisioned before that format.
        self.rec_xsk = idm.load_recording_xsk(keydir)
        # the cryptography is checked against published values, and every key pair of this station against itself,
        # before anything is opened or signed with it: a station that computes wrong does not start
        from ..crypto import selftest

        def public(name):                               # this station's own public key files (the UAV has copies)
            p = keydir / name
            return p.read_bytes() if p.is_file() else None
        self.crypto_selftest = selftest.summary(selftest.require(
            ident=self.ident, rec_ek=public("gcs_recording_ML-KEM-1024.ek"), rec_dk=self.rec_dk,
            rec_xpk=public(f"{idm.RECORDING_X}.pk"), rec_xsk=self.rec_xsk))
        log.info("cryptographic self-test passed: %d checks in %.0f ms (liboqs %s)", self.crypto_selftest["checks"],
                 self.crypto_selftest["ms"], self.crypto_selftest["liboqs"])
        # owner-only (0700): decrypted video, pictures, the track and the database live below it
        self.data = idm.private_dir(Path(cfg.data_dir).expanduser())
        self.http_refused = {}                  # reason -> number of web requests refused (see request_refused)
        for sub in ("images", "recordings", "detections", "exports", "audio"):
            (self.data / sub).mkdir(parents=True, exist_ok=True)
        self.store = Store(self.data / "kyber6g.db")
        uav_id = cfg.link.uav_id.encode()[:8].ljust(8, b"-")
        self.link = GcsLink(cfg.link, self.ident, {uav_id: uav_pk}, bind=(cfg.bind_host, cfg.link.gcs_port))
        self.link.on_message = self.on_message
        self.link.on_control = self.on_control
        self.video = VideoSink(cfg.ffmpeg, clock_offset=lambda: self.link.time_offset)
        # A finished transfer is decrypted / remuxed on a worker thread: doing it in the link's receive thread would
        # stop video, keepalives and pings for as long as a large recording takes to decrypt.
        self.started = time.time()
        self._work = queue.Queue()
        self.img_rx = BlobReceiver(self.link.send_control, lambda info, data: self._work.put((self.on_image, info, data)),
                                   on_fail=self.on_transfer_failed)
        self.rec_rx = BlobReceiver(self.link.send_control, lambda info, data: self._work.put((self.on_recording, info, data)),
                                   on_fail=self.on_transfer_failed)
        self.aud_rx = BlobReceiver(self.link.send_control, lambda info, data: self._work.put((self.on_audio, info, data)),
                                   on_fail=self.on_transfer_failed)
        # sealed audio clips (audio/quaver.py): hybrid-wrapped and signed, so both recording keys are needed
        # Its requests to the UAV (the blocks a live clip is missing) are sent without waiting for the answer: the desk
        # is called from the worker and the timer thread, which must not stand still for a lost acknowledgement, and it
        # asks again by itself when the blocks do not come.
        self.audio = AudioDesk(self.data, self.rec_dk, self.rec_xsk, uav_pk, self.note,
                               ask_uav=lambda c, a: threading.Thread(target=self.command, args=(c, a), kwargs={"timeout": 8}, daemon=True,
                                                                     name="audio-ask").start()) if self.rec_xsk is not None else None
        self.tm_reasm = jsonmsg.Reassembler()
        self.st_reasm = jsonmsg.Reassembler()
        self.telemetry = None
        self.sky = []
        self.sky_ts = None
        self.home = None
        self.home_source = None
        self.last_fix = None
        self.track = collections.deque(maxlen=3600)
        self.tm = {"rx": 0, "backfill": 0, "latency_ms": None, "last_n": None, "gaps": 0, "dup": 0}
        self._tm_seen, self._tm_order = set(), collections.deque()       # (UAV boot, sample number) already stored
        self._tm_lat = collections.deque(maxlen=30)
        self._last_sat_store = 0
        self.uav_status = None
        # reports of the UAV's motion watch (text in the status stream): the newest one for the overlay, and counts
        self.motion = {"last": None, "rx_at": None, "reports": 0, "events": 0, "malformed": 0, "since": None, "last_event": None}
        self.images, self.recordings = [], []
        self.acks = {}
        self.ack_cv = threading.Condition()
        self.ids = itertools.count(1)
        self.log = collections.deque(maxlen=300)
        self.analytics_cache = {"summary": {}, "grid": {}, "sky": {}, "computed": None}
        self.db_counts = {}
        self.detector = None
        self.finder = None
        self.finder_seen = {}
        self.finder_totals = collections.Counter()
        if detector:
            from .detector import Detector
            from .detector import PROFILES
            self.detector = Detector(self.video, self.store, self.data, lambda: self.last_fix,
                                     profile=cfg.detector_profile if cfg.detector_profile in PROFILES else "general",
                                     on_event=self.note, uid_base=lambda: self.store.run_id)
            from .finder import Finder
            self.finder = Finder(self.video, on_event=self.note, backend=cfg.finder_backend, words=cfg.finder_words,
                                 input_size=cfg.finder_size, candidates_dir=self.data / "finder_candidates",
                                 period=cfg.finder_period)
            self.finder.on_pass = self._finder_pass
            self.finder.enabled = bool(cfg.finder_enabled)
        self._settings_path = self.data / "settings.json"
        self._restore_media()
        self._load_settings()
        try:                    # samples stored just before a restart must still be recognised as "already have it"
            for r in self.store.query("SELECT uav_boot, n FROM telemetry ORDER BY id DESC LIMIT 300"):
                if r["n"] is not None:
                    self._tm_seen.add((r["uav_boot"], r["n"]))
                    self._tm_order.appendleft((r["uav_boot"], r["n"]))
        except sqlite3.Error as e:
            log.warning("reading recent telemetry: %s", e)

    # ------------------------------------------------- state that survives a restart
    def _images_on_disk(self, limit=None):
        """Every received photo that is still on disk (its .jpg and the .json beside it), newest first."""
        metas = sorted((self.data / "images").glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        out = []
        for m in metas:
            if limit is not None and len(out) >= limit:
                break
            try:
                e = json.loads(m.read_text())
            except (OSError, ValueError):
                continue                                    # one unreadable entry does not cost the others
            jpg = self.data / "images" / m.name[:-5]
            if isinstance(e, dict) and jpg.is_file():
                e["url"] = f"/images/{jpg.name}"
                e.setdefault("received_at", m.stat().st_mtime)
                out.append(e)
        return out

    def _recordings_on_disk(self, limit=None):
        """Every recording that was decrypted here and whose .mp4 is still on disk, newest first."""
        out, seen = [], set()
        for r in self.store.query("SELECT meta FROM recordings ORDER BY ts DESC"):
            try:
                e = json.loads(r["meta"] or "{}")
            except ValueError:
                continue
            mp4 = e.get("mp4") if isinstance(e, dict) else None
            if mp4 and e.get("name") not in seen and (self.data / "recordings" / Path(mp4).name).is_file():
                seen.add(e.get("name"))
                out.append(e)
        # recordings that were copied and decrypted outside the link (`kyber6g.sh pull`, decrypt_recording): the
        # .mp4 next to its .k6grec is the proof that decryption passed
        for mp4 in (self.data / "recordings").glob("*.mp4"):
            name = mp4.with_suffix(".k6grec").name
            if name not in seen:
                seen.add(name)
                out.append({"name": name, "size": mp4.stat().st_size, "integrity": "copied (scp)",
                            "decrypt": "PASS", "frames": "—", "decrypt_ms": "—",
                            "mp4": f"/recordings/{mp4.name}", "received_at": mp4.stat().st_mtime})
        out.sort(key=lambda x: -(x.get("received_at") or 0))
        return out if limit is None else out[:limit]

    def _restore_media(self):
        """After a restart (or a crash + automatic restart) the gallery shows what is on disk again: the newest
        received images and the decrypted recordings. Without this the MEDIA tab came up empty although every file
        was still there."""
        try:
            self.images.extend(self._images_on_disk(16))
        except (OSError, ValueError) as e:
            log.warning("restoring the image list: %s", e)
        try:
            self.recordings.extend(self._recordings_on_disk(10))
        except (sqlite3.Error, ValueError, OSError) as e:
            log.warning("restoring the recording list: %s", e)

    IMAGE_KEYS = ("name", "url", "received_at", "size", "size_plain", "integrity", "seconds", "kind", "decrypt", "decrypt_ms")
    IMAGE_META = ("width", "height", "mode", "stored_as", "source", "trigger", "captured_at")
    RECORDING_KEYS = ("name", "mp4", "received_at", "size", "integrity", "decrypt", "decrypt_ms", "frames", "segments", "signature")

    def media(self):
        """ALL photos and ALL decrypted recordings the ground station holds, newest first, for the MEDIA page's
        "show all". (The state that the page polls every second carries the newest 16 and 10 only.) An entry is cut
        down to what the page shows: a file's header, with its wrapped keys, is not sent 170 times."""
        images = [{**{k: e.get(k) for k in self.IMAGE_KEYS if e.get(k) is not None},
                   "meta": {k: e["meta"].get(k) for k in self.IMAGE_META if e["meta"].get(k) is not None} if isinstance(e.get("meta"), dict) else {}}
                  for e in self._images_on_disk()]
        recordings = [{k: e.get(k) for k in self.RECORDING_KEYS if e.get(k) is not None} for e in self._recordings_on_disk()]
        return {"images": images, "recordings": recordings, "counts": {"images": len(images), "recordings": len(recordings)}}

    def media_counts(self):
        """How many photos and decrypted recordings are on disk (counted at most every 5 s: the state is polled every second)."""
        now = time.monotonic()
        if now - getattr(self, "_media_n_at", -1e9) > 5:
            try:
                n_img = sum(1 for m in (self.data / "images").glob("*.json") if (self.data / "images" / m.name[:-5]).is_file())
                self._media_n = {"images": n_img, "recordings": sum(1 for _ in (self.data / "recordings").glob("*.mp4"))}
            except OSError:
                self._media_n = getattr(self, "_media_n", {"images": 0, "recordings": 0})
            self._media_n_at = now
        return self._media_n

    def _save_settings(self):
        """What the operator set from the dashboard (reference point, detector and finder choices), so a restart
        comes back the way it was left."""
        if not getattr(self, "_settings_path", None):
            return
        try:
            s = {"home": list(self.home) if self.home and self.home_source != "first GNSS fix" else None,
                 "home_source": self.home_source}
            if self.finder:
                f = self.finder
                s["finder"] = {"enabled": f.enabled, "words": f.words, "threshold": f.threshold, "period": f.period}
            if self.detector:
                d = self.detector
                s["detector"] = {"enabled": d.enabled, "profile": d._want, "conf": d.conf, "imgsz": d.imgsz,
                                 "enhance": d.enhance, "custom_vocab": d.custom_vocab}
            tmp = self._settings_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(s, indent=1))
            tmp.replace(self._settings_path)
        except OSError as e:
            log.warning("saving settings: %s", e)

    def _load_settings(self):
        try:
            s = json.loads(self._settings_path.read_text())
        except (OSError, ValueError):
            return
        try:                                              # a damaged or outdated file must never stop the start-up
            h = s.get("home")
            if h and len(h) == 2 and -90 <= float(h[0]) <= 90 and -180 <= float(h[1]) <= 180:
                self.home, self.home_source = (float(h[0]), float(h[1])), str(s.get("home_source") or "operator")[:40]
            f = s.get("finder") or {}
            if self.finder and f:
                self.finder.configure(enabled=f.get("enabled"), words=f.get("words"), threshold=f.get("threshold"),
                                      period=f.get("period"))
            d = s.get("detector") or {}
            if self.detector and d:
                prof = d.get("profile")
                if prof == "custom" and d.get("custom_vocab"):
                    self.detector.configure(vocab=", ".join(d["custom_vocab"]))
                elif prof:
                    self.detector.configure(profile=prof)
                self.detector.configure(conf=d.get("conf"), imgsz=d.get("imgsz"), enhance=d.get("enhance"))
                self.detector.enabled = bool(d.get("enabled", True))
            self.note("START", f"operator settings restored from {self._settings_path.name}")
        except Exception as e:
            log.warning("settings file ignored: %s: %s", type(e).__name__, e)

    # ------------------------------------------------------------ finder
    def _finder_pass(self, info):
        """Persist every finder pass, and what it confirmed: detection rows, a snapshot + event for each new object, track rows."""
        now = time.time()
        dets, frame = info["shown"], info["frame"]
        self.store.finder_pass(now, info["frame_ts"], info["infer_ms"], info["threshold"], info["best"], dets)
        lat, lon = self.last_fix or (None, None)
        base = self.store.run_id * 10_000_000 + 99_000
        for d in dets:
            row = {**d, "uid": base + d["id"]}
            self.store.detection(now, 0, row, lat, lon)
            t = self.finder_seen.get(d["id"])
            if t is None:
                snap = self.detector._snapshot(frame, d, now) if self.detector else None
                t = self.finder_seen[d["id"]] = {"cls": d["cls"], "first": now, "hits": 0, "conf": 0.0, "snap": snap}
                self.finder_totals[d["cls"]] += 1
                self.note("FOUND", f"{d['cls']} #{d['id']} ({d['conf']:.2f}) by the finder")
            t["hits"] += 1
            t["last"] = now
            t["conf"] = max(t["conf"], d["conf"])
            if t["hits"] in (1, 5, 20) or t["hits"] % 50 == 0:
                self.store.track(row["uid"], t["cls"], t["first"], now, t["hits"], t["conf"], t["snap"], lat, lon)
        if len(self.finder_seen) > 500:
            for k in sorted(self.finder_seen, key=lambda k: self.finder_seen[k].get("last", 0))[:200]:
                del self.finder_seen[k]

    def detections_latest(self):
        """Overlay feed: the real-time detector's boxes plus the finder's confirmed boxes (each with its own frame time)."""
        base = dict(self.detector.latest) if self.detector else {"dets": [], "seq": None}
        dets = list(base.get("dets") or [])
        now, mono = time.time(), time.monotonic()
        f = self.finder
        if f and f.latest.get("dets") and f.fresh(f.keep_s() + 1.0):
            from .finder import iou
            for d in f.latest["dets"]:
                if mono - d.get("seen", mono) > d.get("hold", 3.0):    # last sighting too long ago (finder pass still running)
                    continue
                if not any(o["cls"] == d["cls"] and iou(o["box"], d["box"]) > 0.5 for o in dets):
                    dets.append(d)
        base["dets"] = dets
        base["now"] = now
        base["motion"] = self.motion_latest()          # where the UAV's motion watch sees movement (capture-clock time)
        # Capture time (camera clock, like every frame_ts / ts above) of the picture a viewer sees at this moment.
        # The browser places each box by (view_ts - its frame's capture time): no clock of this machine is involved,
        # so a ground-station clock that drifts or is stepped cannot detach the boxes from the objects.
        base["view_ts"] = self.video.view_ts()
        return base

    def note(self, kind, msg):
        self.log.append({"t": time.time(), "kind": kind, "msg": str(msg)})
        self.store.event(kind, msg)
        log.info("%s %s", kind, msg)

    # ------------------------------------------------------------ inbound
    def on_message(self, stream, ext, payload, meta):
        if stream == ks.STREAM_VIDEO:
            self.video.on_chunk(ext, payload)
        elif stream == ks.STREAM_TELEMETRY:
            tm = self.tm_reasm.add(ext, payload)
            if tm:
                self._telemetry(tm, meta)
        elif stream == ks.STREAM_STATUS:
            st = self.st_reasm.add(ext, payload)
            if st and st.get("t") == "motion":
                self._motion(st)
            elif st:
                st["rx_at"] = time.time()
                self.uav_status = st
        elif stream == ks.STREAM_IMAGE:
            self.img_rx.on_record(ext, payload)
        elif stream == ks.STREAM_RECORDING:
            self.rec_rx.on_record(ext, payload)
        elif stream == ks.STREAM_AUDIO:
            if ext[:1] == b"L":                           # a sealed block of a clip that is being recorded now
                if self.audio:
                    self.audio.on_live_chunk(ext, payload)
            else:
                self.aud_rx.on_record(ext, payload)

    def _motion(self, msg):
        """A report of the UAV's motion watch: kept for the overlay; the beginning and the end of a movement go into
        the event log (and with it into the database)."""
        m = clean_motion(msg)
        mo = self.motion
        if m is None:
            mo["malformed"] += 1
            return
        mo["reports"] += 1
        mo["last"], mo["rx_at"] = m, time.time()
        if m["ev"] == "start":
            mo["events"] += 1
            mo["since"] = m["since"] or m["ts"]
            # the log gets a movement at most every 10 s: a thing that keeps starting and stopping must not bury the rest
            mo["_logged"] = time.time() - mo.get("_logged_at", 0) >= 10
            if mo["_logged"]:
                more, mo["_unlisted"], mo["_logged_at"] = mo.get("_unlisted", 0), 0, time.time()
                self.note("MOTION", f"movement seen by the UAV in {len(m['regions'])} place(s) of the picture"
                                    + (" (its camera is moving)" if m["cam"] else "")
                                    + (f"; {more} short movement(s) before it not listed" if more else ""))
            else:
                mo["_unlisted"] = mo.get("_unlisted", 0) + 1
        elif m["ev"] == "end":
            dur = m["ts"] - mo["since"] if mo["since"] else None
            mo["last_event"] = {"since": mo["since"], "until": m["ts"], "seconds": round(dur, 1) if dur is not None else None}
            mo["since"] = None
            if mo.get("_logged"):
                self.note("MOTION", "movement ended" + (f" after {dur:.0f} s" if dur is not None and 0 <= dur < 86400 else ""))

    def motion_latest(self):
        """The newest motion report if it is fresh (the UAV sends one per look while something moves)."""
        mo = self.motion
        if mo["last"] is None or time.time() - mo["rx_at"] > 2.0:
            return None
        return mo["last"]

    def _telemetry(self, tm, meta):
        tm = clean_telemetry(tm)
        if tm is None:
            self.tm["malformed"] = self.tm.get("malformed", 0) + 1
            return
        # The UAV sends again what it had sent just before a link loss was noticed (it cannot know what arrived):
        # a sample that is already stored (same UAV start time and number) is counted and dropped.
        key = (tm.get("boot"), tm.get("n"))
        if key[1] is not None:
            if key in self._tm_seen:
                self.tm["dup"] = self.tm.get("dup", 0) + 1
                return
            self._tm_seen.add(key)
            self._tm_order.append(key)
            if len(self._tm_order) > 20000:
                self._tm_seen.discard(self._tm_order.popleft())
        latency = None
        off = self.link.time_offset
        if off is not None and not tm.get("backfill"):
            latency = (time.time() - (tm["ts"] - off)) * 1000
            self._tm_lat.append(latency)
            self.tm["latency_ms"] = round(sorted(self._tm_lat)[len(self._tm_lat) // 2], 1)
        if tm.get("backfill"):
            self.tm["backfill"] += 1
        else:
            n = tm.get("n")
            if n is not None:
                if self.tm["last_n"] is not None and n != self.tm["last_n"] + 1:
                    self.tm["gaps"] += 1
                self.tm["last_n"] = n
            sats = tm["satellites"]
            self.sky, self.sky_ts = sats, tm["ts"]
            if sats and time.time() - self._last_sat_store > 5:
                self.store.satellites(tm["ts"], sats)
                self._last_sat_store = time.time()
            self.telemetry = tm
        self.tm["rx"] += 1
        self.store.telemetry(tm, latency, meta.get("epoch"), meta.get("sid", b"").hex() if meta.get("sid") else None)
        if tm.get("lat") is not None and (tm.get("mode") or 0) >= 2:
            self.track.append((tm["ts"], tm["lat"], tm["lon"], tm.get("speed_mps")))
            if not tm.get("backfill"):
                self.last_fix = (tm["lat"], tm["lon"])
                if self.home is None:
                    self.home = (tm["lat"], tm["lon"])
                    self.home_source = "first GNSS fix"
                    self.note("HOME", f"home set to first fix {tm['lat']:.6f}, {tm['lon']:.6f}")

    def on_control(self, msg):
        if msg.get("t") == "ack":
            cid = msg.get("id")
            if isinstance(cid, bool) or not isinstance(cid, int):        # the number of one of our commands, nothing else
                return
            with self.ack_cv:
                self.acks[cid] = {**msg, "_rx": time.time()}
                while len(self.acks) > 64:                               # answers nobody waits for (any more) are not kept
                    self.acks.pop(next(iter(self.acks)))
                self.ack_cv.notify_all()
            self.note("ACK", f"{str(msg.get('cmd'))[:40]} ok={msg.get('ok')} {str(msg.get('error') or '')[:200]}")

    def on_transfer_failed(self, info, got):
        self.note("TRANSFER", f"{info.get('name') or info.get('id')} FAILED: stalled after {got} of "
                              f"{info.get('chunks', '?')} chunks (link too lossy or UAV stopped sending) - try again")

    def on_image(self, info, data):
        if info.get("kind") == "photo_enc":
            return self.on_stored_photo(info, data)
        entry = {**info, "received_at": time.time()}
        if data is not None:
            name = safe_name(info["name"])
            if not name.lower().endswith((".jpg", ".jpeg")) or not data.startswith(b"\xff\xd8"):
                raise ValueError(f"{name}: not a JPEG image")       # it is served to the browser as image/jpeg
            (self.data / "images" / name).write_bytes(data)
            (self.data / "images" / (name + ".json")).write_text(json.dumps(entry, indent=1, default=str))
            entry["url"] = f"/images/{name}"
        g = (info.get("meta") or {}).get("gnss") or {}
        self.store.image(info, g.get("lat"), g.get("lon"))
        self.images.insert(0, entry)
        del self.images[64:]
        self.note("IMAGE", f"{info['name']} {info['size']} B integrity={info.get('integrity')} in {info.get('seconds')} s"
                           + (" (taken by PHOTO ON MOTION)" if (info.get("meta") or {}).get("trigger") == "motion" else ""))

    def on_stored_photo(self, info, data):
        """A .k6gimg fetched from the UAV's SD card: decrypt with the GCS recording key."""
        entry = {**info, "received_at": time.time()}
        if data is not None:
            name = safe_name(info["name"])
            (self.data / "images" / "encrypted").mkdir(exist_ok=True)
            (self.data / "images" / "encrypted" / name).write_bytes(data)
            t0 = time.perf_counter()
            try:
                # format 2: hybrid key wrap (both recording keys needed) and the UAV's ML-DSA-87 signature, checked
                # against the pinned key - a photo that is not signed by this UAV is refused
                hdr, jpeg = open_image(data, self.rec_dk, x25519_sk=self.rec_xsk, signer_pk=self.uav_pk)
                jpg_name = Path(name).stem + ".jpg"
                (self.data / "images" / jpg_name).write_bytes(jpeg)
                entry.update(decrypt="PASS", decrypt_ms=round((time.perf_counter() - t0) * 1000, 1),
                             signature=hdr.get("sig_status"), format=hdr.get("v"),
                             url=f"/images/{jpg_name}", meta=hdr, size_plain=len(jpeg))
                (self.data / "images" / (jpg_name + ".json")).write_text(json.dumps(entry, indent=1, default=str))
            except PhotoError as e:
                entry["decrypt"] = f"FAILED: {e}"
        self.images.insert(0, entry)
        del self.images[64:]
        self.note("PHOTO", f"{info['name']} fetched from UAV storage integrity={info.get('integrity')} "
                           f"decrypt={entry.get('decrypt')} signature={entry.get('signature')}")

    def on_audio(self, info, data):
        """A finished transfer on the audio stream: a whole clip from the UAV's card, or the head, the trailer or
        re-fetched blocks of a clip that came in live."""
        if self.audio is None:
            return self.note("AUDIO", f"{info.get('name')}: no X25519 recording key on this station, sealed audio cannot be opened")
        kind = info.get("kind")
        if kind == "audio_enc":
            if data is not None and not safe_name(info["name"]).endswith(".k6gaud"):
                raise ValueError(f"{info['name']}: not a .k6gaud clip")
            self.audio.on_clip(info, data)
        elif kind == "audio_head":
            self.audio.on_head(info, data)
        elif kind == "audio_trailer":
            if data is not None and (info.get("meta") or {}).get("name"):
                info["meta"]["name"] = safe_name(info["meta"]["name"])
            self.audio.on_trailer(info, data)
        elif kind == "audio_blocks":
            self.audio.on_blocks(info, data)

    def on_recording(self, info, data):
        entry = {**info, "received_at": time.time()}
        if data is not None:
            name = safe_name(info["name"])
            if not name.endswith(".k6grec"):              # the .mp4 beside it is derived from this name
                raise ValueError(f"{name}: not a .k6grec recording")
            enc = self.data / "recordings" / name
            enc.write_bytes(data)
            entry.update(self.decrypt_and_remux(enc))
        self.store.recording(entry)
        self.recordings[:] = [entry] + [r for r in self.recordings if r.get("name") != entry.get("name")][:30]
        self.note("RECORDING", f"{info['name']} {info['size']} B integrity={info.get('integrity')} decrypt={entry.get('decrypt')} "
                               f"signature={entry.get('signature')}")

    def decrypt_and_remux(self, enc: Path):
        t0 = time.perf_counter()
        try:
            # as for photos: both recording keys, and the UAV's signature against the pinned key (format 2)
            hdr, h264, report = decrypt_recording(enc, self.rec_dk, x25519_sk=self.rec_xsk, signer_pk=self.uav_pk)
        except RecordingError as e:
            return {"decrypt": f"FAILED: {e}"}
        dt = time.perf_counter() - t0
        mp4 = enc.with_suffix(".mp4")
        r = subprocess.run([self.cfg.ffmpeg, "-y", "-loglevel", "error", "-framerate", str(frame_rate(hdr)),
                            "-f", "h264", "-i", "pipe:0", "-c", "copy", "-movflags", "+faststart", str(mp4)],
                           input=h264, capture_output=True)
        return {"decrypt": report["status"], "decrypt_ms": round(dt * 1000, 1), "frames": report["frames"],
                "signature": report.get("signature"), "format": report.get("format"),
                "segments": report["segments"], "mp4": f"/recordings/{mp4.name}" if r.returncode == 0 else None,
                "remux_error": r.stderr.decode(errors="replace").strip()[:200] or None, "header": hdr}

    # ----------------------------------------------------------- commands
    def command(self, cmd: str, args: dict, timeout: float = 20.0):
        cid = next(self.ids)
        # the envelope last: an argument named "t" or "id" can never replace the command type or its number
        if not self.link.send_control({**args, "t": cmd, "id": cid}):
            return {"ok": False, "error": "UAV not connected (no authenticated session). Is the UAV app running on the Pi?"}
        self.note("CMD", f"{cmd} {args or ''}")
        deadline = time.time() + timeout
        with self.ack_cv:
            while cid not in self.acks and time.time() < deadline:
                self.ack_cv.wait(0.2)
            ack = self.acks.pop(cid, {"ok": False, "error": "timeout waiting for UAV acknowledgement"})
        ack.pop("_rx", None)
        if cmd == "stop_rec" and ack.get("ok"):
            self._fetch_saved(ack.get("result"))
        return ack

    def _fetch_saved(self, summary):
        """A recording has just been saved on the UAV's card (SAVE). It is fetched and decrypted at once, so that the
        operator finds it on the MEDIA page without having to list the card and ask for it: recordings that were
        made and never asked for (30 of 73 on 6 October 2026) looked as if they had been lost. Only up to
        `auto_fetch_mb` (0: never): a long recording would take the link from the live video for minutes; it stays
        in the page's list with its FETCH & DECRYPT button."""
        limit = int(getattr(self.cfg, "auto_fetch_mb", 0) or 0) << 20
        if not limit or not isinstance(summary, dict):
            return
        parts = [p for p in (summary.get("parts") or [summary.get("name")]) if isinstance(p, str)]
        size = summary.get("file_bytes") or 0
        if not parts:
            return
        if size > limit:
            return self.note("RECORDING", f"{summary.get('name')} saved on the UAV: {size / 1e6:.0f} MB, over the {limit >> 20} MB that are "
                                          "fetched by themselves. FETCH & DECRYPT it on the MEDIA page")

        def fetch():
            for name in parts:
                r = self.command("fetch_recording", {"name": name}, timeout=60)
                if not r.get("ok"):
                    self.note("RECORDING", f"{name} saved on the UAV, fetching it failed: {str(r.get('error'))[:160]}")
        threading.Thread(target=fetch, daemon=True, name="fetch-saved").start()

    def local_command(self, cmd, args):
        if cmd == "set_home":
            if args.get("lat") is not None:
                lat, lon = float(args["lat"]), float(args["lon"])
                if not (-90 <= lat <= 90 and -180 <= lon <= 180):
                    return {"ok": False, "error": "lat/lon out of range"}
                self.home = (lat, lon)
                self.home_source = str(args.get("source") or "operator")[:40]
            elif self.last_fix:
                self.home = self.last_fix
                self.home_source = "UAV GNSS fix"
            else:
                return {"ok": False, "error": "no GNSS fix yet — use PICK REFERENCE ON MAP instead"}
            self.note("HOME", f"home/reference set to {self.home[0]:.6f}, {self.home[1]:.6f} ({self.home_source})")
            self._save_settings()
            return {"ok": True, "result": {"home": self.home, "source": self.home_source}}
        if cmd == "audio_excerpt":
            if not self.audio:
                return {"ok": False, "error": "sealed audio is not set up on this station"}
            try:
                t0, t1 = jsonmsg.num(args.get("t0"), 0, 1e7), jsonmsg.num(args.get("t1"), 0, 1e7)
                if t0 is None or t1 is None or t1 < t0:
                    return {"ok": False, "error": "t0 and t1 must be seconds, t0 <= t1"}
                return {"ok": True, "result": self.audio.excerpt(safe_name(args.get("name")), t0, t1, args.get("with_meta", True) is not False)}
            except (ValueError, FileNotFoundError, AudioError) as e:
                return {"ok": False, "error": str(e)}
        if cmd == "finder":
            if not self.finder:
                return {"ok": False, "error": "finder disabled"}
            try:
                words = args.get("words")
                if isinstance(words, str):
                    words = [w for w in words.replace("\n", ",").split(",")]
                self.finder.configure(enabled=args.get("enabled"), words=words, backend=args.get("backend"),
                                      threshold=args.get("threshold"), period=args.get("period"))
            except (ValueError, TypeError) as e:
                return {"ok": False, "error": str(e)}
            self._save_settings()
            return {"ok": True, "result": {k: self.finder.status()[k] for k in ("enabled", "words", "backend", "threshold")}}
        if cmd == "detector":
            if not self.detector:
                return {"ok": False, "error": "detector disabled"}
            d = self.detector
            try:
                if "teach" in args:                       # {name, box:[x1,y1,x2,y2] 0..1, image: base64 JPEG of the frame shown}
                    t = args["teach"]
                    if not isinstance(t, dict) or not isinstance(t.get("image") or "", str):
                        return {"ok": False, "error": "teach needs {name, box, image}"}
                    jpeg = base64.b64decode(t.get("image") or "", validate=True)
                    if not jpeg.startswith(b"\xff\xd8") or len(jpeg) > 3_000_000:
                        return {"ok": False, "error": "image must be a JPEG under 3 MB"}
                    res = d.teach(t.get("name"), jpeg, t.get("box"))
                    self._save_settings()                 # teaching switches to the ACCURATE profile: keep that over a restart
                    return {"ok": True, "result": res}
                if "forget" in args:
                    return {"ok": True, "result": d.forget(args["forget"] or None)}
                if "enabled" in args:
                    d.enabled = bool(args["enabled"])
                d.configure(profile=args.get("profile"), vocab=args.get("vocab"), conf=args.get("conf"),
                            imgsz=args.get("imgsz"), enhance=args.get("enhance"))
            except (ValueError, TypeError, TimeoutError, KeyError) as e:
                return {"ok": False, "error": str(e) or type(e).__name__}
            self._save_settings()
            if args.get("profile") or args.get("vocab"):
                self.note("DETECTOR", f"switching to {d._want}" + (f" {d.custom_vocab}" if d._want == "custom" else ""))
            return {"ok": True, "result": {"enabled": d.enabled, "conf": d.conf, "profile": d._want,
                                           "imgsz": d.imgsz, "enhance": d.enhance}}
        return {"ok": False, "error": "unknown command"}

    # ----------------------------------------------------------- queries
    def telemetry_rows(self, minutes=60, limit=20000):
        return self.store.query(
            "SELECT * FROM telemetry WHERE ts >= ? ORDER BY ts LIMIT ?", (time.time() - minutes * 60, limit))

    def refresh_analytics(self):
        rows = self.telemetry_rows(60)
        self.analytics_cache = {
            "summary": analytics.summarize(rows, self.home),
            "grid": analytics.density_grid([(r["lat"], r["lon"]) for r in rows if (r["mode"] or 0) >= 2]),
            "sky": analytics.sky_summary(self.sky), "computed": time.time(), "window_min": 60}

    def series(self, minutes=30):
        t0 = time.time() - minutes * 60
        tm = self.store.query("SELECT ts, alt_m, speed_mps, sats_used, sats_seen, hdop, vdop, pdop, latency_ms, mode "
                              "FROM telemetry WHERE ts >= ? AND backfill = 0 ORDER BY ts", (t0,))
        ls = self.store.query("SELECT ts, rtt_ms, auth_fail, duplicate, stale FROM link_stats WHERE ts >= ? ORDER BY ts", (t0,))
        vs = self.store.query("SELECT ts, fps, kbps, display_latency_ms, network_latency_ms, det_fps, det_ms "
                              "FROM video_stats WHERE ts >= ? ORDER BY ts", (t0,))
        ss = self.store.query("SELECT ts, cpu, temp_c, wifi_dbm, cam_fps FROM system_stats WHERE ts >= ? ORDER BY ts", (t0,))
        det = self.store.query("SELECT cls, count(*) AS n FROM detections WHERE ts >= ? GROUP BY cls ORDER BY n DESC", (t0,))
        return {"telemetry": tm, "link": ls, "video": vs, "system": ss, "detections_by_class": det}

    def state(self):
        tm = dict(self.telemetry) if self.telemetry else None
        if tm:
            tm["satellites"] = self.sky
        det = self.detector.status() if self.detector else {"available": False, "error": "disabled"}
        if self.finder:
            fs = self.finder.status()
            now_counts = collections.Counter(det.get("counts_now") or {})
            if self.finder.fresh(self.finder.keep_s() + 1.0):
                now_counts.update(d["cls"] for d in self.finder.latest.get("dets", []))
            det["counts_now"] = dict(now_counts)
            uniq = collections.Counter(det.get("by_class_unique") or {})
            uniq.update(self.finder_totals)
            det["by_class_unique"] = dict(uniq)
            det["objects_now"] = sum(now_counts.values())
            det["unique_tracks"] = sum(uniq.values())
            det["finder"] = fs
        build = int(max(p.stat().st_mtime for p in STATIC.glob("*") if p.is_file()))
        # "started" changes when the ground station restarts: the dashboard then reconnects its video stream
        return {"now": time.time(), "build": build, "started": getattr(self, "started", None),
                "link": self.link.status(), "telemetry": tm, "telemetry_stats": self.tm,
                "home": self.home, "home_source": self.home_source, "track": [[a, b, s] for _, a, b, s in list(self.track)[-600:]],
                "video": self.video.stats(), "uav": self.uav_status, "detector": det,
                "detections": self.detector.latest if self.detector else None,
                "images": self.images[:16], "recordings": self.recordings[:10], "media_counts": self.media_counts(),
                "auto_fetch_mb": getattr(self.cfg, "auto_fetch_mb", 0),
                "audio": self.audio.state() if getattr(self, "audio", None) else None,
                "motion": {**{k: v for k, v in self.motion.items() if k not in ("last", "rx_at") and not k.startswith("_")},
                           "now": self.motion_latest()},
                "blobs": {"img_ok": self.img_rx.ok, "img_fail": self.img_rx.failed, "rec_ok": self.rec_rx.ok,
                          "rec_fail": self.rec_rx.failed, "aud_ok": self.aud_rx.ok, "aud_fail": self.aud_rx.failed,
                          "refused": self.img_rx.refused + self.rec_rx.refused + self.aud_rx.refused},
                "http_refused": dict(self.http_refused), "crypto": getattr(self, "crypto_selftest", None),
                "db": self.db_counts, "analytics": self.analytics_cache, "log": list(self.log)[-60:]}

    # ------------------------------------------------------------- loops
    # Every background loop survives its own errors: a thread that dies silently leaves a dashboard that looks
    # alive but no longer stores, NACKs or analyses anything.
    def tick_loop(self):
        while True:
            try:
                self.img_rx.tick()
                self.rec_rx.tick()
                self.aud_rx.tick()
                if self.audio:
                    self.audio.tick()
            except Exception:
                log.exception("blob tick")
            time.sleep(0.1)

    def work_loop(self):
        while True:
            fn, info, data = self._work.get()
            try:
                fn(info, data)
            except Exception as e:
                log.exception("processing %s", info.get("name") if isinstance(info, dict) else info)
                self.note("ERROR", f"could not process {info.get('name') if isinstance(info, dict) else 'transfer'}: "
                                   f"{type(e).__name__}: {e}")

    def stats_loop(self):
        last_event_t = 0.0
        while True:
            try:
                self.db_counts = self.store.counts()
                L = self.link.status()
                self.store.link_stats(L)
                if L["state"] == "UP":
                    self.store.video_stats(self.video.stats(), self.detector.live_stats() if self.detector else {})
                    if self.uav_status:
                        self.store.system_stats(self.uav_status)
                for t, k, m in list(self.link.events):
                    if t > last_event_t:
                        self.store.event("LINK:" + k, m)
                        last_event_t = t
                with self.ack_cv:                       # acknowledgements nobody waited for (the caller timed out)
                    for cid in [c for c, a in self.acks.items() if time.time() - a.get("_rx", 0) > 120]:
                        del self.acks[cid]
                self.refresh_analytics()
            except Exception as e:
                log.warning("stats loop: %s: %s", type(e).__name__, e)
            time.sleep(5)

    def run(self):
        self.link.start()
        threading.Thread(target=self.tick_loop, daemon=True, name="blob-tick").start()
        threading.Thread(target=self.work_loop, daemon=True, name="blob-work").start()
        threading.Thread(target=self.stats_loop, daemon=True, name="stats").start()
        srv = QuietServer((self.cfg.http_host, self.cfg.http_port), make_handler(self))
        srv.daemon_threads = True
        if self.cfg.http_host not in ("127.0.0.1", "localhost", "::1"):
            log.warning("the dashboard listens on %s and has no login: every machine that can reach that address "
                        "can watch the video and command the UAV", self.cfg.http_host)
        self.note("START", f"GCS UDP {self.cfg.bind_host}:{self.cfg.link.gcs_port}; dashboard "
                           f"http://{self.cfg.http_host}:{self.cfg.http_port}; db {self.store.path}")
        srv.serve_forever()


# ================================================================== exports
def rows_to_csv(rows, columns=()):
    """CSV with a header line. `columns`: the header when there are no rows (an empty time span must not give an
    empty file: a reader could not tell it from a failed download)."""
    buf = io.StringIO()
    names = list(rows[0].keys()) if rows else list(columns)
    if names:
        w = csv.DictWriter(buf, fieldnames=names)
        w.writeheader()
        w.writerows(rows)
    return buf.getvalue().encode()


def rows_to_geojson(rows):
    feats = [{"type": "Feature", "geometry": {"type": "Point", "coordinates": [r["lon"], r["lat"]] +
                                              ([r["alt_m"]] if r.get("alt_m") is not None else [])},
              "properties": {k: v for k, v in r.items() if k not in ("lat", "lon")}}
             for r in rows if r.get("lat") is not None]
    line = [[f["geometry"]["coordinates"][0], f["geometry"]["coordinates"][1]] for f in feats]
    if len(line) > 1:
        feats.append({"type": "Feature", "geometry": {"type": "LineString", "coordinates": line},
                      "properties": {"name": "UAV track"}})
    return json.dumps({"type": "FeatureCollection", "features": feats}).encode()


def rows_to_kml(rows):
    pts = [r for r in rows if r.get("lat") is not None]
    coords = " ".join(f"{r['lon']},{r['lat']},{r.get('alt_m') or 0}" for r in pts)
    marks = "".join(f"<Placemark><TimeStamp><when>{time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(r['ts']))}</when>"
                    f"</TimeStamp><Point><coordinates>{r['lon']},{r['lat']},{r.get('alt_m') or 0}</coordinates></Point>"
                    f"</Placemark>" for r in pts[:: max(1, len(pts) // 500)])
    return (f'<?xml version="1.0" encoding="UTF-8"?><kml xmlns="http://www.opengis.net/kml/2.2"><Document>'
            f"<name>Kyber-6G UAV track</name><Placemark><name>track</name><LineString><altitudeMode>absolute"
            f"</altitudeMode><coordinates>{coords}</coordinates></LineString></Placemark>{marks}</Document></kml>").encode()


class QuietServer(ThreadingHTTPServer):
    """A browser tab that closes, or resets a kept-alive connection, is not an error of the ground station: the default
    handler printed a full traceback for each one (48 in one evening's log). Anything else is logged in one line."""

    def handle_error(self, request, client_address):
        import sys
        e = sys.exc_info()[1]
        if isinstance(e, (ConnectionError, TimeoutError)):
            return
        log.error("HTTP handler for %s failed: %s: %s", client_address[0], type(e).__name__, e)


def make_handler(app: GroundApp):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        timeout = 120            # an idle keep-alive connection (closed laptop lid, dead tab) must not hold a thread forever
        _page_cache = (None, "")

        def log_message(self, *a):
            pass

        def _guard(self, method):
            """True if the request was refused (and answered). See `request_refused`."""
            why = request_refused(method, urlparse(self.path).path, self.headers, self.server.server_address[1],
                                  getattr(getattr(app, "cfg", None), "http_allowed_hosts", ()))
            if why is None:
                return False
            refused = app.__dict__.setdefault("http_refused", {})
            refused[why] = refused.get(why, 0) + 1
            self.close_connection = True                  # a body we did not read must not be taken for the next request
            try:
                self._json({"ok": False, "error": why}, 403)
            except OSError:
                pass
            return True

        def _protect(self):
            """Headers on every response: the content type is final (no sniffing), other origins may neither embed
            nor frame what this server sends, and only the origin (never a path) is given to the map-tile servers."""
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")

        def _send(self, body: bytes, ctype, code=200, extra=None):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self._protect()
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _json(self, obj, code=200):
            self._send(json.dumps(obj, default=str).encode(), "application/json", code)

        def _page(self):
            """The dashboard page, with its Content-Security-Policy (recomputed when index.html changes)."""
            path = STATIC / "index.html"
            mtime = path.stat().st_mtime_ns
            if H._page_cache[0] != mtime:
                H._page_cache = (mtime, page_csp(path.read_bytes()))
            return self._file(path, "text/html; charset=utf-8",
                              extra={"Content-Security-Policy": H._page_cache[1], "Cross-Origin-Opener-Policy": "same-origin"})

        def _file(self, path: Path, ctype=None, download=None, cache=False, extra=None):
            """Serve a file in pieces, with byte ranges: the browser's video player asks for 'Range: bytes=a-b'
            (without it a recording cannot be scrubbed and every preview downloads the whole file).
            `download`: offer it as a download under this name."""
            if not path.is_file():
                return self._json({"error": "not found"}, 404)
            ctype = ctype or CONTENT_TYPES.get(path.suffix.lower()) or mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            size = path.stat().st_size
            start, end, code = 0, size - 1, 200
            rng = self.headers.get("Range", "")
            if rng.startswith("bytes=") and "," not in rng and size:
                a, _, b = rng[6:].strip().partition("-")
                try:
                    if a == "":                               # suffix range: the last N bytes
                        start, end = max(0, size - int(b)), size - 1
                    else:
                        start, end = int(a), min(int(b), size - 1) if b else size - 1
                    if not 0 <= start <= end < size:
                        raise ValueError
                    code = 206
                except ValueError:
                    self.send_response(416)
                    self.send_header("Content-Range", f"bytes */{size}")
                    self.send_header("Content-Length", "0")
                    self._protect()
                    self.end_headers()
                    return
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "public, max-age=86400" if cache else "no-store")
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", str(end - start + 1))
            self._protect()
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            if code == 206:
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            if download:
                self.send_header("Content-Disposition", f'attachment; filename="{safe_name(download)}"')
            self.end_headers()
            with open(path, "rb") as f:
                f.seek(start)
                left = end - start + 1
                while left > 0:
                    chunk = f.read(min(262144, left))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    left -= len(chunk)

        def _download(self, body, name, ctype):
            self._send(body, ctype, extra={"Content-Disposition": f'attachment; filename="{name}"'})

        def do_GET(self):
            if self._guard("GET"):
                return
            u = urlparse(self.path)
            p, qs = u.path, parse_qs(u.query)

            def limit(default, most):                     # a row limit from the query string, kept within 1..most
                return max(1, min(int(qs.get("limit", [str(default)])[0]), most))    # (a negative LIMIT means "all" in SQLite)
            try:
                minutes = float(qs.get("minutes", ["60"])[0])
                if minutes != minutes:                    # "nan" is a float, and not a time span
                    raise ValueError("minutes must be a number")
                minutes = max(0.0, min(minutes, 30 * 24 * 60.0))
                if p in ("/", "/index.html"):
                    return self._page()
                if p.startswith("/static/"):
                    # any file below static/ (the third-party libraries live in static/vendor/), never above it
                    target = (STATIC / unquote(p[8:])).resolve()
                    if STATIC.resolve() not in target.parents:
                        return self._json({"error": "not found"}, 404)
                    return self._file(target, cache="vendor" in target.parts)
                if p == "/api/state":
                    return self._json(app.state())
                if p == "/api/detections/latest":
                    # "now" lets the browser line its clock up with the GCS clock (frame_ts is on that clock)
                    return self._json(app.detections_latest())
                if p == "/api/series":
                    return self._json(app.series(minutes))
                if p == "/api/telemetry":
                    if "latest" in qs:                  # the newest N rows (descending), for the live data table
                        return self._json(app.store.query("SELECT * FROM telemetry ORDER BY ts DESC LIMIT ?",
                                                          (max(1, min(int(qs["latest"][0]), 20000)),)))
                    return self._json(app.telemetry_rows(minutes, limit(2000, 20000)))
                if p == "/api/tracks":
                    return self._json(app.store.query("SELECT * FROM tracks ORDER BY first_ts DESC LIMIT 200"))
                if p == "/api/events":
                    return self._json(app.store.query("SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit(200, 5000),)))
                if p == "/api/db":
                    return self._json(app.store.counts())
                if p == "/api/media":
                    return self._json(app.media())
                cols = getattr(app.store, "columns", lambda table: ())
                if p == "/api/export/telemetry.csv":
                    return self._download(rows_to_csv(app.telemetry_rows(minutes, 10**7), cols("telemetry")), "telemetry.csv", "text/csv")
                if p == "/api/export/telemetry.geojson":
                    return self._download(rows_to_geojson(app.telemetry_rows(minutes, 10**7)), "telemetry.geojson",
                                          "application/geo+json")
                if p == "/api/export/telemetry.kml":
                    return self._download(rows_to_kml(app.telemetry_rows(minutes, 10**7)), "telemetry.kml",
                                          "application/vnd.google-earth.kml+xml")
                if p == "/api/export/detections.csv":
                    rows = app.store.query("SELECT * FROM detections WHERE ts >= ? ORDER BY ts", (time.time() - minutes * 60,))
                    return self._download(rows_to_csv(rows, cols("detections")), "detections.csv", "text/csv")
                if p == "/api/export/satellites.csv":
                    rows = app.store.query("SELECT * FROM satellites WHERE ts >= ? ORDER BY ts", (time.time() - minutes * 60,))
                    return self._download(rows_to_csv(rows, cols("satellites")), "satellites.csv", "text/csv")
                if p == "/api/export/db":
                    with tempfile.NamedTemporaryFile(suffix=".db") as tmp:
                        src = sqlite3.connect(app.store.path)
                        dst = sqlite3.connect(tmp.name)
                        src.backup(dst)             # consistent snapshot while the writer keeps running
                        dst.close(); src.close()
                        # sent in pieces from the snapshot: the database grows without limit, so it is never read into memory
                        return self._file(Path(tmp.name), "application/vnd.sqlite3", download="kyber6g.db")
                if p.startswith("/images/"):
                    return self._file(app.data / "images" / Path(unquote(p[8:])).name, "image/jpeg")
                if p.startswith("/detections/"):
                    return self._file(app.data / "detections" / Path(unquote(p[12:])).name, "image/jpeg")
                if p.startswith("/recordings/"):
                    return self._file(app.data / "recordings" / Path(unquote(p[12:])).name, "video/mp4")
                if p.startswith("/audio/excerpts/"):
                    name = Path(unquote(p[16:])).name
                    return self._file(app.data / "audio" / "excerpts" / name, download=name if name.endswith(".k6gax") else None)
                if p.startswith("/audio/"):
                    return self._file(app.data / "audio" / Path(unquote(p[7:])).name)
                if p == "/audio_live" and getattr(app, "audio", None):
                    return self._audio_live(app.audio, (qs.get("tag") or [None])[0])
                if p == "/video.mjpg":
                    return self._mjpeg(app.video, "latest", "jpeg_seq")
                if p == "/video_annotated.mjpg" and app.detector:
                    return self._mjpeg(app.detector, "annotated", "annotated_seq")
                return self._json({"error": "not found"}, 404)
            except (BrokenPipeError, ConnectionResetError):
                pass
            except (ValueError, KeyError, IndexError) as e:      # malformed query parameters: the caller's mistake, not ours
                try:
                    self._json({"error": f"bad request: {type(e).__name__}: {e}"}, 400)
                except OSError:
                    pass
            except Exception as e:                      # one bad request must never take a handler thread down silently
                log.exception("GET %s failed", self.path)
                try:
                    self._json({"error": f"{type(e).__name__}: {e}"}, 500)
                except OSError:
                    pass

        def _mjpeg(self, src, attr, seq_attr):
            self.send_response(200)
            self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=k6gframe")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self._protect()
            self.end_headers()
            seq = -1
            try:
                while True:
                    if hasattr(src, "want_annotated"):
                        src.want_annotated()            # the annotated stream is encoded only while watched
                    with src.cond:
                        src.cond.wait_for(lambda: getattr(src, seq_attr) != seq, timeout=5)
                        jpg, seq = getattr(src, attr), getattr(src, seq_attr)
                    if jpg is None:
                        continue
                    self.wfile.write(b"--k6gframe\r\nContent-Type: image/jpeg\r\nContent-Length: "
                                     + str(len(jpg)).encode() + b"\r\n\r\n" + jpg + b"\r\n")
            except OSError:                             # viewer closed the tab / stalled for longer than the socket timeout
                pass
            self.close_connection = True

        def _audio_live(self, desk, tag):
            """The clip that is coming in live, opened block by block, as one growing audio file."""
            gen = desk.listen(tag)
            first = next(gen, None)
            if first is None:
                return self._json({"error": "no live audio"}, 404)
            self.send_response(200)
            self.send_header("Content-Type", "audio/wav" if first[:4] == b"RIFF" else "audio/mpeg")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self._protect()
            self.end_headers()
            try:
                self.wfile.write(first)
                for chunk in gen:
                    self.wfile.write(chunk)
            except OSError:                             # the listener went away
                pass
            self.close_connection = True

        def do_POST(self):
            if self._guard("POST"):
                return
            if urlparse(self.path).path != "/api/cmd":
                self.close_connection = True
                return self._json({"error": "not found"}, 404)
            # Only JSON: a web page can send text/plain or a form to another origin without asking first (a "simple"
            # request); application/json makes the browser ask (CORS preflight), and this server never says yes.
            if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
                self.close_connection = True
                return self._json({"ok": False, "error": "Content-Type must be application/json"}, 415)
            try:
                n = int(self.headers.get("Content-Length", 0))
                if not 0 <= n <= 4_500_000:               # teach-by-example carries one base64 JPEG; everything else is tiny
                    self.close_connection = True          # the unread body would corrupt a keep-alive connection
                    return self._json({"ok": False, "error": "request too large"}, 413)
                req = json.loads(self.rfile.read(n) or b"{}")
                if not isinstance(req, dict):             # valid JSON, but not a command object ([1,2], "x", 5 ...)
                    return self._json({"ok": False, "error": "bad request"}, 400)
                cmd, args = req.get("cmd"), req.get("args") or {}
                if not isinstance(cmd, str) or not isinstance(args, dict) or (n > 65536 and cmd != "detector"):
                    return self._json({"ok": False, "error": "bad request"}, 400)
                if RESERVED_ARGS & set(args):             # "t" would turn an allowed command into any message type
                    return self._json({"ok": False, "error": "reserved argument name"}, 400)
                # how long to wait for the UAV's answer (default 25 s; a measurement on a lossy link asks for less)
                wait = req.get("timeout")
                wait = float(wait) if isinstance(wait, (int, float)) and not isinstance(wait, bool) and 1 <= wait <= 120 else None
            except (ValueError, TypeError, RecursionError):
                return self._json({"ok": False, "error": "bad json"}, 400)
            except OSError:                               # client went away mid-body
                self.close_connection = True
                return
            try:
                if cmd in ("set_home", "detector", "finder", "audio_excerpt"):
                    return self._json(app.local_command(cmd, args))
                if cmd not in UAV_COMMANDS:
                    return self._json({"ok": False, "error": "unknown command"}, 400)
                if cmd == "start_live":
                    app.video.reset()
                return self._json(app.command(cmd, args, timeout=wait or (60 if cmd in ("fetch_recording", "fetch_audio", "record_audio") else 25)))
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as e:
                log.exception("command %s failed", cmd)
                try:
                    self._json({"ok": False, "error": f"{type(e).__name__}: {e}"}, 500)
                except OSError:
                    pass

    return H


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-c", "--config")
    ap.add_argument("--no-detector", action="store_true")
    a = ap.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    from ..crypto.secure_bytes import no_core_dumps
    if not no_core_dumps():
        log.warning("could not disable core dumps: a crash may write key material to disk")
    cfg = cfgmod.load(cfgmod.GroundConfig, a.config)
    if not shutil.which(cfg.ffmpeg):
        raise SystemExit("ffmpeg not found (needed to decode H.264 for the dashboard): sudo apt install ffmpeg")
    GroundApp(cfg, detector=not a.no_detector).run()


if __name__ == "__main__":
    main()
