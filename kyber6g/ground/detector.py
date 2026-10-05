"""Live object detection + recognition + tracking on the decrypted video (GCS).

Profiles (switchable at runtime from the dashboard):

  general   YOLOE-11s, ~120 everyday classes by text prompt            (default, ~5 fps)
  accurate  YOLOE-11L, same classes + objects you TEACH it by example  (~3 fps; a little more trustworthy)
  fast      YOLOv8n, COCO-80 (no pencil / pen class)                   (~10 fps)
  open      YOLOE-11s prompt-free, 4585 built-in classes (slow, noisy)
  custom    YOLOE-11s with the operator's own comma-separated words

Why TEACH exists: thin objects such as a pencil are not recognised from the
word alone by any open-vocabulary model tried here (YOLOE-11s/m/l, YOLO-World
s/l: score ~0 on the real camera frames). Drawing one box around the object
on the live view gives YOLOE a *visual prompt*; with the 11L model that found
the pencil in 7/7 held-out frames with no false 'pencil' on three other images.
Taught embeddings are tied to the weights that produced them, so they apply to
the ACCURATE profile only, and are kept in models/taught.json.

Stability (what the dashboard relies on):
  * a track's label is a confidence-weighted vote with hysteresis, so a box does
    not flip between 'cup' and 'mug' from frame to frame;
  * every detection carries the capture time of the frame it was computed on,
    so the browser can extrapolate the box to the frame it is showing;
  * track ids stored in the database are unique across runs and model reloads;
  * a gap in the video resets the tracker instead of linking unrelated objects.

Inference always runs on the newest decoded frame only: frames that arrive
while the model is busy are skipped, so slow inference never builds a backlog
and never delays the live video. It runs on the GCS because the Pi 4's CPU is
already handling capture, H.264 bookkeeping and AES-GCM, and it has no NPU.
"""
import collections
import hashlib
import json
import os
import queue
import threading
import time
from contextlib import contextmanager
from pathlib import Path

from .sched import ease_state, lower_priority, next_frame, video_behind

EVERYDAY = [
    # people
    "person", "face", "hand",
    # stationery
    "pencil", "pen", "marker pen", "highlighter", "eraser", "pencil sharpener", "ruler", "scissors", "stapler",
    "adhesive tape", "glue stick", "notebook", "book", "sheet of paper", "envelope", "sticky note", "calculator",
    "paper clip", "pencil case",
    # electronics
    "cell phone", "laptop", "computer keyboard", "computer mouse", "computer monitor", "television",
    "remote control", "headphones", "earphones", "phone charger", "power bank", "usb cable", "usb flash drive",
    "camera", "speaker", "wristwatch", "smartwatch", "router", "circuit board", "battery", "power strip",
    # personal items
    "eyeglasses", "wallet", "key", "id card", "coin", "banknote", "ring", "hat", "helmet",
    "face mask", "backpack", "handbag", "shoe", "slipper", "umbrella", "comb", "toothbrush", "towel",
    "t-shirt", "jacket", "belt",
    # kitchen / food
    "water bottle", "cup", "plate", "bowl", "spoon", "fork", "knife", "lunch box",
    "apple", "banana", "orange", "bread", "biscuit packet",
    # home
    "chair", "table", "sofa", "bed", "pillow", "door", "window", "curtain", "lamp", "light bulb", "fan",
    "clock", "mirror", "potted plant", "trash can", "cardboard box", "shelf", "bucket", "toy",
    # tools
    "screwdriver", "pliers", "hammer", "wrench", "soldering iron", "multimeter", "tape measure", "flashlight",
    # outdoor
    "car", "bicycle", "motorcycle", "auto rickshaw", "bus", "truck", "drone", "airplane", "traffic light",
    "dog", "cat", "bird", "cow", "tree", "ball", "cricket bat",
]

# Confidence thresholds are set from a measurement, not by feel: 128 labelled photos (COCO128, 697 objects of classes
# the vocabulary covers), every box judged against the labels (docs/TEST_REPORT.md 13.6):
#     GENERAL  at 0.25: 311 correct, 173 wrong (precision 64 %)      at 0.40: 264 correct,  88 wrong (75 %)
#     ACCURATE at 0.30: 341 correct, 122 wrong (74 %)                at 0.40: 308 correct,  81 wrong (79 %)
# Raising GENERAL from 0.25 to 0.40 halves the wrong labels (173 -> 88) and keeps 85 % of the correct ones; ACCURATE at
# 0.40 finds as many objects as GENERAL did at 0.25. Both therefore start at 0.40. GENERAL stays the default profile
# because it is twice as fast (boxes follow movement better); see GroundConfig.detector_profile.
PROFILES = {
    "general": {"label": "GENERAL - YOLOE-11s, everyday objects (fast)", "weights": "yoloe-11s-seg.pt", "kind": "yoloe",
                "vocab": EVERYDAY, "imgsz": 640, "conf": 0.40, "max_fps": 6.0},
    "accurate": {"label": "ACCURATE - YOLOE-11L + taught objects", "weights": "yoloe-11l-seg.pt", "kind": "yoloe",
                 "vocab": EVERYDAY, "taught": True, "imgsz": 512, "conf": 0.40, "max_fps": 3.0},
    "fast": {"label": "FAST - YOLOv8n, COCO-80", "weights": "yolov8n.pt", "kind": "yolo",
             "imgsz": 640, "conf": 0.35, "max_fps": 10.0},
    "open": {"label": "OPEN - YOLOE-11s prompt-free, 4585 classes", "weights": "yoloe-11s-seg-pf.pt", "kind": "yoloe-pf",
             "imgsz": 640, "conf": 0.30, "max_fps": 2.0},
    "custom": {"label": "CUSTOM - YOLOE-11s, your words", "weights": "yoloe-11s-seg.pt", "kind": "yoloe",
               "vocab": ["pencil"], "imgsz": 640, "conf": 0.20, "max_fps": 6.0},
}
FALLBACK = {"general": "fast", "accurate": "general", "custom": "general", "open": "general"}
MAX_TAUGHT_PER_NAME, MAX_TAUGHT_TOTAL = 8, 40

_CWD_LOCK = threading.Lock()


@contextmanager
def _in_dir(path):
    """ultralytics resolves/downloads weights relative to the working directory."""
    with _CWD_LOCK:
        old = os.getcwd()
        os.chdir(path)
        try:
            yield
        finally:
            os.chdir(old)


def parse_vocab(text):
    words, seen = [], set()
    for w in str(text).replace("\n", ",").split(","):
        w = " ".join(w.strip().lower().split())[:40]
        if w and w not in seen:
            seen.add(w)
            words.append(w)
    return words[:200]


def clean_name(name):
    name = " ".join(str(name).strip().lower().split())[:40]
    if not name or not all(ch.isalnum() or ch in " -_" for ch in name):
        raise ValueError("name must be letters, digits, spaces, '-' or '_'")
    return name


class Detector:
    def __init__(self, video, store, data_dir, get_position, profile="general", threads=4, on_event=None,
                 uid_base=lambda: 0, models_dir=None):
        self.video = video
        self.store = store
        self.dir = Path(data_dir).expanduser() / "detections"
        self.dir.mkdir(parents=True, exist_ok=True)
        # models_dir: weights and taught examples; separate from data_dir so tests can reuse the downloaded weights
        # without writing snapshots into the operator's real detections folder
        self.models_dir = Path(models_dir).expanduser() if models_dir else Path(data_dir).expanduser() / "models"
        self.models_dir.mkdir(parents=True, exist_ok=True)
        (self.models_dir / "taught").mkdir(exist_ok=True)
        # Once every model file is on disk the ML libraries get no network access: the ground station then starts
        # the same with or without internet, and a station that handles secured video does not report usage
        # statistics to third parties (ultralytics does by default when it finds itself online).
        need = {p["weights"] for p in PROFILES.values()} | {"mobileclip_blt.ts"}
        self.offline = all((self.models_dir / n).exists() for n in need)
        if self.offline:
            os.environ.setdefault("YOLO_OFFLINE", "true")
        os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
        self.get_position = get_position
        self.threads = threads
        self.on_event = on_event or (lambda k, m: None)
        self.uid_base = uid_base
        self.enabled = True
        self.available = False
        self.loading = None
        self.error = None
        self.notice = None
        self.model = None
        self.names = {}
        self.profile = None
        self.custom_vocab = list(PROFILES["custom"]["vocab"])
        self.conf = PROFILES[profile]["conf"]
        self.imgsz = PROFILES[profile]["imgsz"]
        self.enhance = False
        self.min_dt = 0.1
        self.generation = 0
        self._want = profile
        self._loaded_vocab = None
        self._reload = False
        self._jobs = queue.Queue()
        self._want_ann = 0.0
        self.latest = {"seq": None, "dets": [], "ts": None}
        self.annotated = None
        self.annotated_seq = 0
        self.cond = threading.Condition()
        self.tracks = {}            # local id -> {first,last,hits,conf,votes,label,cls,snap}
        self.class_totals = collections.Counter()
        self.s = {"fps": 0.0, "infer_ms": None, "frames": 0, "objects_now": 0, "counts_now": {},
                  "unique_tracks": 0, "by_class_unique": {}, "model": None, "device": "cpu"}
        self._times = collections.deque(maxlen=30)
        self._caps = collections.deque(maxlen=60)       # (local time, capture time on the camera's clock) of analysed frames
        self._taught_path = self.models_dir / "taught.json"
        self.last_teach = None
        self._stop = False
        self._thread = threading.Thread(target=self._run, name="detector", daemon=True)
        self._thread.start()

    def close(self, timeout=15):
        """Stop the worker (used by tests and on shutdown); waits for an in-flight inference."""
        self._stop = True
        self._thread.join(timeout)

    # ------------------------------------------------------------- control
    def configure(self, profile=None, vocab=None, conf=None, imgsz=None, enhance=None):
        """Called from the HTTP thread; model (re)loads happen in the worker thread."""
        if vocab is not None:
            words = parse_vocab(vocab)
            if not words:
                raise ValueError("vocabulary is empty")
            self.custom_vocab = words
            profile = profile or "custom"
        if profile is not None:
            if profile not in PROFILES:
                raise ValueError(f"profile must be one of {sorted(PROFILES)}")
            self._want = profile
            if conf is None:
                self.conf = PROFILES[profile]["conf"]
            if imgsz is None:
                self.imgsz = PROFILES[profile]["imgsz"]
        if conf is not None:
            self.conf = max(0.05, min(0.95, float(conf)))
        if imgsz is not None:
            self.imgsz = int(min(1280, max(320, int(imgsz) // 32 * 32)))
        if enhance is not None:
            self.enhance = bool(enhance)

    def want_annotated(self):
        self._want_ann = time.monotonic()

    # ---------------------------------------------------- taught examples
    def _taught_db(self):
        try:
            return json.loads(self._taught_path.read_text())
        except (OSError, ValueError):
            return {"examples": []}

    def _save_taught(self, db):
        tmp = self._taught_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(db))
        os.replace(tmp, self._taught_path)

    def taught_summary(self):
        names = collections.Counter(e["name"] for e in self._taught_db()["examples"]
                                    if e["weights"] == PROFILES["accurate"]["weights"])
        return [{"name": n, "examples": c} for n, c in sorted(names.items())]

    def _taught_vectors(self, weights):
        import torch
        groups = collections.defaultdict(list)
        for e in self._taught_db()["examples"]:
            if e["weights"] == weights and len(e["vpe"]) == 512:
                groups[e["name"]].append(torch.tensor(e["vpe"], dtype=torch.float32))
        out = {}
        for name, vs in groups.items():
            m = torch.stack(vs).mean(0)
            out[name] = m / m.norm().clamp_min(1e-6)
        return out

    def teach(self, name, jpeg, box, timeout=90):
        """Learn `name` from one box (normalised xyxy) on one frame. Blocks until done."""
        name = clean_name(name)
        if not (isinstance(box, (list, tuple)) and len(box) == 4):
            raise ValueError("box must be [x1,y1,x2,y2] (0..1)")
        job = {"kind": "teach", "name": name, "jpeg": jpeg, "box": [float(v) for v in box], "done": threading.Event(),
               "result": None}
        self._jobs.put(job)
        if not job["done"].wait(timeout):
            raise TimeoutError("teach timed out (detector busy or model loading)")
        if job["result"].get("error"):
            raise ValueError(job["result"]["error"])
        return job["result"]

    def forget(self, name=None):
        name = clean_name(name) if name else None
        job = {"kind": "forget", "name": name, "done": threading.Event(), "result": None}
        self._jobs.put(job)
        job["done"].wait(30)
        return job["result"] or {}

    def _service_jobs(self):
        while True:
            try:
                job = self._jobs.get_nowait()
            except queue.Empty:
                return
            try:
                job["result"] = self._do_teach(job) if job["kind"] == "teach" else self._do_forget(job)
            except Exception as e:                      # reported to the caller, never kills the worker
                job["result"] = {"error": f"{type(e).__name__}: {e}"}
            self.last_teach = {"kind": job["kind"], "name": job.get("name"), "ts": time.time(), **job["result"]}
            job["done"].set()

    def _do_teach(self, job):
        import cv2
        import numpy as np
        from ultralytics import YOLOE
        from ultralytics.models.yolo.yoloe import YOLOEVPSegPredictor
        frame = cv2.imdecode(np.frombuffer(job["jpeg"], np.uint8), cv2.IMREAD_COLOR)
        if frame is None:
            return {"error": "could not decode the frame"}
        h, w = frame.shape[:2]
        x1, y1, x2, y2 = (min(max(v, 0.0), 1.0) for v in job["box"])
        x1, x2, y1, y2 = min(x1, x2) * w, max(x1, x2) * w, min(y1, y2) * h, max(y1, y2) * h
        if x2 - x1 < 6 or y2 - y1 < 6:
            return {"error": "box is too small - draw it tightly around the object"}
        if (x2 - x1) * (y2 - y1) > 0.9 * w * h:
            return {"error": "box covers almost the whole frame - draw it around the object only"}
        weights = PROFILES["accurate"]["weights"]
        db = self._taught_db()
        same = [e for e in db["examples"] if e["name"] == job["name"] and e["weights"] == weights]
        if len(same) >= MAX_TAUGHT_PER_NAME:
            return {"error": f"already {MAX_TAUGHT_PER_NAME} examples of '{job['name']}' - forget it first"}
        if len(db["examples"]) >= MAX_TAUGHT_TOTAL:
            return {"error": f"limit of {MAX_TAUGHT_TOTAL} taught examples reached"}
        t0 = time.time()
        with _in_dir(self.models_dir):
            m = YOLOE(self._weights(weights))
            m.predict(frame, refer_image=frame, verbose=False, imgsz=PROFILES["accurate"]["imgsz"],
                      visual_prompts={"bboxes": np.array([[x1, y1, x2, y2]], np.float32), "cls": np.array([0])},
                      predictor=YOLOEVPSegPredictor)
            vpe = m.model.pe.detach().cpu().reshape(-1)
        del m
        if vpe.numel() != 512 or not bool(vpe.isfinite().all()):
            return {"error": "visual prompt produced an invalid embedding"}
        pad = 0.15
        cx1, cx2 = int(max(0, x1 - pad * (x2 - x1))), int(min(w, x2 + pad * (x2 - x1)))
        cy1, cy2 = int(max(0, y1 - pad * (y2 - y1))), int(min(h, y2 + pad * (y2 - y1)))
        thumb = f"taught_{job['name'].replace(' ', '_')}_{int(time.time())}.jpg"
        cv2.imwrite(str(self.models_dir / "taught" / thumb), frame[cy1:cy2, cx1:cx2], [cv2.IMWRITE_JPEG_QUALITY, 85])
        db["examples"].append({"name": job["name"], "weights": weights, "vpe": [round(float(v), 6) for v in vpe],
                               "ts": time.time(), "thumb": thumb, "box": [round(v, 1) for v in (x1, y1, x2, y2)]})
        self._save_taught(db)
        self.on_event("TEACH", f"learned '{job['name']}' (example {len(same) + 1}) in {time.time() - t0:.1f} s")
        if self.profile != "accurate":
            self.conf, self.imgsz = PROFILES["accurate"]["conf"], PROFILES["accurate"]["imgsz"]
        self._want, self._reload = "accurate", True      # (re)load ACCURATE with the new embedding
        return {"name": job["name"], "examples": len(same) + 1, "seconds": round(time.time() - t0, 1)}

    def _do_forget(self, job):
        db = self._taught_db()
        before = len(db["examples"])
        keep = [e for e in db["examples"] if job["name"] and e["name"] != job["name"]]
        for e in db["examples"]:
            if e not in keep and e.get("thumb"):
                (self.models_dir / "taught" / Path(e["thumb"]).name).unlink(missing_ok=True)       # no orphan crops left behind
        db["examples"] = keep
        self._save_taught(db)
        self._reload = True
        self.on_event("TEACH", f"forgot {job['name'] or 'everything'} ({before - len(db['examples'])} examples)")
        return {"removed": before - len(db["examples"])}

    # ------------------------------------------------------------- loading
    def _weights(self, name):
        path = self.models_dir / name
        if not path.exists():
            with _in_dir(self.models_dir):                # official weights are downloaded into the cwd
                from ultralytics import YOLO
                YOLO(name)
        return str(path)

    def _text_pe(self, model, vocab, weights):
        """Text embeddings for the vocabulary (MobileCLIP, ~35 s once, then cached on disk).

        The embeddings pass through the model's own text adapter, so they are specific to the weights:
        a cache made with YOLOE-11s is wrong for 11L (it silently scores everything ~0.02)."""
        import torch
        digest = hashlib.sha256((weights + "\n" + "\n".join(vocab)).encode()).hexdigest()[:16]
        cache = self.models_dir / f"textpe-{Path(weights).stem}-{digest}.pt"
        if cache.exists():
            try:
                # weights_only: the cache holds a tensor and strings; a file that needs anything else (pickle can
                # run code when loaded) is not ours and is thrown away below
                c = torch.load(cache, map_location="cpu", weights_only=True)
                if c["names"] == vocab and c.get("weights") == weights:
                    return c["emb"]
            except Exception:
                cache.unlink(missing_ok=True)
        with _in_dir(self.models_dir):
            emb = model.get_text_pe(vocab).detach().cpu()
        torch.save({"names": vocab, "emb": emb, "weights": weights}, cache)
        return emb

    def _load(self, key):
        import cv2  # noqa: F401  (fail early if OpenCV is missing)
        import torch
        torch.set_num_threads(self.threads)
        p = PROFILES[key]
        vocab = self.custom_vocab if key == "custom" else p.get("vocab")
        t0 = time.time()
        taught_names = []
        if p["kind"] == "yolo":
            from ultralytics import YOLO
            model = YOLO(self._weights(p["weights"]))
        else:
            from ultralytics import YOLOE
            model = YOLOE(self._weights(p["weights"]))
            if vocab:
                names, emb = list(vocab), self._text_pe(model, vocab, p["weights"])
                if p.get("taught"):
                    for n, v in self._taught_vectors(p["weights"]).items():
                        names.append(n)
                        emb = torch.cat([emb, v.view(1, 1, -1)], dim=1)
                        taught_names.append(n)
                model.set_classes(names, emb)
        # warm-up through track() (so the tracker is registered): the first inference allocates buffers and
        # would otherwise show as a latency spike; the tracker is cleared again afterwards
        try:
            import numpy as np
            model.track(np.zeros((p["imgsz"], p["imgsz"], 3), np.uint8), persist=True, tracker="bytetrack.yaml",
                        verbose=False, imgsz=p["imgsz"])
            model.predictor.trackers[0].reset()
        except Exception as e:
            self.on_event("DETECTOR", f"warm-up skipped: {type(e).__name__}: {e}")
        self.model = model
        self.names = model.names
        self.profile = key
        self.generation += 1
        self.min_dt = 1.0 / p["max_fps"]
        self.tracks.clear()
        self.s.update(model=p["weights"], profile=key, profile_label=p["label"], classes=len(self.names),
                      taught_loaded=taught_names, load_s=round(time.time() - t0, 1))
        self.available = True
        self.on_event("DETECTOR", f"{p['label']} loaded ({len(self.names)} classes"
                                  f"{', taught: ' + ', '.join(taught_names) if taught_names else ''}, "
                                  f"CPU, {self.threads} threads, {time.time() - t0:.1f} s)")

    def _switch(self, want):
        self.loading = want
        try:
            try:
                self._load(want)
                self._loaded_vocab = list(self.custom_vocab) if want == "custom" else None
                self.error = self.notice = None
            except Exception as e:
                self.error = f"{type(e).__name__}: {e}"
                self.on_event("DETECTOR", f"{want} unavailable: {self.error}")
                fb = FALLBACK.get(want)
                if self.model is not None:
                    self._want = self.profile                       # keep the model that is running
                elif fb:
                    self._want = fb
                    self.notice = f"{want} could not load - using {fb}"
                else:
                    time.sleep(5)
        finally:
            self.loading = None
            self._reload = False

    def _enhance(self, frame):
        import cv2
        lab = cv2.cvtColor(frame, cv2.COLOR_BGR2LAB)
        lab[:, :, 0] = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8, 8)).apply(lab[:, :, 0])
        return cv2.cvtColor(lab, cv2.COLOR_LAB2BGR)

    def _reset_tracker(self):
        try:
            self.model.predictor.trackers[0].reset()
        except Exception:
            pass
        self.tracks.clear()
        self.generation += 1

    # ----------------------------------------------------------------- run
    def _run(self):
        try:
            import cv2
            import numpy as np
        except ImportError as e:
            self.error = f"unavailable here: {e}"
            return
        self.s["nice"] = lower_priority(5)            # the secure-link receiver and the video decoder must win over inference
        while not self._stop:
            try:
                self._loop(cv2, np)
            except Exception as e:                    # nothing may end the worker for good: report, pause, carry on
                self.error = f"detector worker: {type(e).__name__}: {e}"
                self.s["worker_errors"] = self.s.get("worker_errors", 0) + 1
                self.on_event("DETECTOR", f"worker error ({self.error}); continuing")
                time.sleep(2.0)

    def _loop(self, cv2, np):
        # Durations are measured on the monotonic clock. With the wall clock, a forward step (host time sync after the
        # laptop woke from sleep: +2.9 s every 35 s) looked like a 2.5 s pause in the video: the tracker was reset and
        # every object in view was announced as "new" again, twice a minute.
        last_seq, last_t, fails = -1, time.monotonic(), 0
        episodes = ease_state()["episodes"]
        while not self._stop:
            self._service_jobs()
            want = self._want
            if self.model is None or want != self.profile or self._reload or \
                    (want == "custom" and self._loaded_vocab != self.custom_vocab):
                self._switch(want)
                last_t = time.monotonic()
                continue
            if not self.enabled:
                time.sleep(0.2)
                continue
            if video_behind(self.video):                 # the decoder has fallen behind: the picture comes before the boxes
                self.s["yielded"] = self.s.get("yielded", 0) + 1
                st = self.s["ease"] = ease_state()
                if st["episodes"] != episodes:           # once per episode, not once per late frame
                    episodes = st["episodes"]
                    self.on_event("DETECTOR", "the video decoder fell behind (this machine is busy, or its processor is throttled): "
                                              f"detection now runs at 1/{st['factor']} of its rate; the next try at a higher rate "
                                              f"comes after {st['hold_s'] // 60} min without trouble")
                time.sleep(0.25)
                continue
            got = next_frame(self.video, last_seq)       # blocks (up to 0.5 s) while there is nothing new
            if got is None:
                continue
            jpg, seq, fts = got
            last_seq = seq
            t0 = time.perf_counter()
            frame = cv2.imdecode(np.frombuffer(jpg, np.uint8), cv2.IMREAD_COLOR)
            if frame is None:
                continue
            if time.monotonic() - last_t > 2.5:          # video was paused / restarted: old tracks are meaningless
                self._reset_tracker()
            last_t = time.monotonic()
            src = self._enhance(frame) if self.enhance else frame
            try:
                res = self.model.track(src, persist=True, tracker="bytetrack.yaml", conf=self.conf,
                                       imgsz=self.imgsz, agnostic_nms=True, verbose=False)[0]
                fails = 0
            except Exception as e:
                fails += 1
                self.error = f"inference: {type(e).__name__}: {e}"
                if fails >= 3:                           # model/tracker state is bad: rebuild it
                    self.on_event("DETECTOR", f"inference failed {fails}x ({self.error}); reloading model")
                    self._reload, fails = True, 0
                time.sleep(0.5)
                continue
            dt = time.perf_counter() - t0
            try:
                self._handle(res, frame, seq, dt, fts)
            except Exception as e:                       # e.g. a snapshot that cannot be written: this frame only
                self.error = f"post-processing: {type(e).__name__}: {e}"
                time.sleep(0.5)
                continue
            if self.error and self.error.startswith(("inference", "post-processing", "detector worker")):
                self.error = None
            took = time.perf_counter() - t0
            st = self.s["ease"] = ease_state()
            # eased (the machine was too busy or too hot for the video): a half, a quarter or an eighth of the time
            spare = max(self.min_dt - took, took * (st["factor"] - 1))
            if spare > 0:
                time.sleep(spare)

    # ---------------------------------------------------------- per frame
    def _vote(self, t, cls, conf):
        v = t["votes"]
        v[cls] = v.get(cls, 0.0) + conf
        best = max(v, key=v.get)
        if best != t["label"] and v[best] > 1.3 * v.get(t["label"], 0.0):
            t["label"] = best                            # hysteresis: switch only on a clear majority
        return t["label"]

    def _handle(self, res, frame, seq, dt, fts):
        import cv2
        now = time.time()
        h, w = frame.shape[:2]
        dets = []
        b = res.boxes
        pos = self.get_position()
        lat, lon = (pos or (None, None))
        base = self.uid_base() * 10_000_000 + (self.generation % 100) * 100_000
        if b is not None and len(b) and b.id is not None:
            for box, c, p, tid in zip(b.xyxyn.tolist(), (int(x) for x in b.cls.tolist()), b.conf.tolist(),
                                      (int(i) for i in b.id.tolist())):
                cls = self.names.get(c, str(c))
                t = self.tracks.get(tid)
                if t is None:
                    t = self.tracks[tid] = {"first": now, "last": now, "hits": 0, "conf": 0.0, "votes": {},
                                            "label": cls, "cls": None, "snap": None}
                t["last"] = now
                t["hits"] += 1
                t["conf"] = max(t["conf"], p)
                label = self._vote(t, cls, p)
                d = {"cls": label, "conf": round(p, 3), "box": [round(v, 4) for v in box], "id": tid, "hits": t["hits"],
                     "uid": base + tid}
                dets.append(d)
                self.store.detection(now, seq, d, lat, lon)
                if t["hits"] == 3:                       # confirmed track (suppresses one-frame flicker)
                    t["cls"] = label
                    self.class_totals[label] += 1
                    t["snap"] = self._snapshot(frame, d, now)
                    self.on_event("DETECT", f"new {label} #{tid} ({p:.2f})")
                if t["cls"] and (t["hits"] in (3, 30, 300) or t["hits"] % 100 == 0):
                    self.store.track(d["uid"], t["cls"], t["first"], t["last"], t["hits"], t["conf"], t["snap"], lat, lon)
        counts = collections.Counter(d["cls"] for d in dets)
        if len(self.tracks) > 2000:                      # forget long-gone tracks
            for k in sorted(self.tracks, key=lambda k: self.tracks[k]["last"])[:500]:
                del self.tracks[k]
        ok, enc = False, None
        mono = time.monotonic()                          # `now` (wall clock) is for stored timestamps only
        if mono - self._want_ann < 8:                    # annotated stream is encoded only while someone watches it
            ann = frame.copy()
            for d in dets:
                x1, y1, x2, y2 = (int(d["box"][0] * w), int(d["box"][1] * h), int(d["box"][2] * w), int(d["box"][3] * h))
                cv2.rectangle(ann, (x1, y1), (x2, y2), (0, 0, 0), 5)
                cv2.rectangle(ann, (x1, y1), (x2, y2), (60, 230, 60), 2)
                label = f"{d['cls']} {d['conf'] * 100:.0f}%"
                (tw, th), _ = cv2.getTextSize(label, cv2.FONT_HERSHEY_DUPLEX, 0.65, 1)
                ty = y1 - 6 if y1 - th - 10 > 0 else y1 + th + 8
                cv2.rectangle(ann, (x1, ty - th - 5), (x1 + tw + 8, ty + 5), (60, 230, 60), -1)
                cv2.putText(ann, label, (x1 + 4, ty), cv2.FONT_HERSHEY_DUPLEX, 0.65, (0, 0, 0), 1, cv2.LINE_AA)
            ok, enc = cv2.imencode(".jpg", ann, [cv2.IMWRITE_JPEG_QUALITY, 75])
        self._times.append(mono)
        self._caps.append((mono, fts))
        s = self.s
        s["frames"] += 1
        s["infer_ms"] = round(dt * 1000, 1)
        recent = [t for t in self._times if mono - t <= 5.0]          # a pause (video stopped) must not drag the rate down for long
        caps = [c for t, c in self._caps if mono - t <= 5.0 and c]
        if len(caps) > 2 and caps[-1] - caps[0] > 1.0:
            # analysed frames per second of CAMERA time: right even when this machine's clock runs at the wrong rate
            s["fps"] = round((len(caps) - 1) / (caps[-1] - caps[0]), 2)
        elif len(recent) > 1 and recent[-1] > recent[0]:
            s["fps"] = round((len(recent) - 1) / (recent[-1] - recent[0]), 2)
        s["objects_now"] = len(dets)
        s["counts_now"] = dict(counts)
        s["unique_tracks"] = sum(self.class_totals.values())
        s["by_class_unique"] = dict(self.class_totals)
        with self.cond:
            self.latest = {"seq": seq, "ts": now, "frame_ts": fts or now, "w": w, "h": h, "dets": dets,
                           "infer_ms": s["infer_ms"], "profile": self.profile}
            if ok:
                self.annotated = enc.tobytes()
                self.annotated_seq += 1
            self.cond.notify_all()

    def _snapshot(self, frame, d, now):
        import cv2
        h, w = frame.shape[:2]
        img = frame.copy()
        x1, y1, x2, y2 = (int(d["box"][0] * w), int(d["box"][1] * h), int(d["box"][2] * w), int(d["box"][3] * h))
        cv2.rectangle(img, (x1, y1), (x2, y2), (0, 0, 0), 5)
        cv2.rectangle(img, (x1, y1), (x2, y2), (60, 230, 60), 2)
        safe = "".join(ch if ch.isalnum() else "_" for ch in d["cls"])[:40]
        name = f"det_{time.strftime('%Y%m%d_%H%M%S', time.localtime(now))}_{safe}_{d['id']}.jpg"
        cv2.imwrite(str(self.dir / name), img, [cv2.IMWRITE_JPEG_QUALITY, 85])
        return name

    def live_stats(self):
        """The counters, with the 'right now' values zeroed while no frames are being analysed: the rate and the
        object counts are measured per frame, so on a stopped stream they would show the last frame's values forever."""
        s = dict(self.s)
        times = list(self._times)
        s["analysing"] = bool(times) and time.monotonic() - times[-1] < 3.0
        if not s["analysing"]:
            s.update(fps=0.0, objects_now=0, counts_now={})
        s["worker_alive"] = self._thread.is_alive()
        return s

    def status(self):
        recent = sorted(((k, v) for k, v in list(self.tracks.items()) if v["snap"]), key=lambda kv: -kv[1]["first"])[:12]
        p = PROFILES.get(self.profile or "", {})
        vocab = self.custom_vocab if self.profile == "custom" else p.get("vocab")
        return {"available": self.available, "enabled": self.enabled, "error": self.error, "notice": self.notice,
                "loading": self.loading, "conf": self.conf, "imgsz": self.imgsz, "enhance": self.enhance,
                "profiles": {k: v["label"] for k, v in PROFILES.items()}, "custom_vocab": self.custom_vocab,
                "vocab_size": len(self.names), "vocab_sample": (vocab or [])[:200] if vocab else None,
                "taught": self.taught_summary(), "last_teach": self.last_teach, **self.live_stats(),
                "recent_tracks": [{"id": k, "cls": v["cls"] or v["label"], "first": v["first"], "last": v["last"],
                                   "hits": v["hits"], "conf": round(v["conf"], 3),
                                   "snapshot": f"/detections/{v['snap']}"} for k, v in recent]}
