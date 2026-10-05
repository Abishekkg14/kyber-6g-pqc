"""FINDER: slower, much more accurate open-vocabulary search for named objects (pencil, screwdriver, ...).

Why it exists: the real-time YOLOE detector cannot recognise thin hand tools from a word. Measured on 25 public photos
(11 pencil / 14 screwdriver, 25 negatives) plus real camera frames, YOLOE-11s/11L and YOLOE-26s/26m scored an AUC of
about 0.5 (= chance) for both words (tests/bench results in docs/TEST_REPORT.md). Detectors trained on grounding data
(OWLv2, Grounding DINO) do find them, but need 1-3 s per frame on this CPU, so they run in a background worker on the
newest frame while YOLOE keeps the live boxes at full rate. Finder boxes are tracked, confirmed over consecutive passes
(no one-frame ghosts) and merged into the same overlay with their own capture timestamp, so the browser can still
extrapolate them onto the frame being displayed.

Backends (transformers, CPU):
  owlv2  google/owlv2-base-patch16-ensemble   per-word sigmoid scores, boxes in a padded square
  gdino  IDEA-Research/grounding-dino-tiny    one text prompt "a pencil. a screwdriver." -> labelled boxes
"""
import collections
import threading
import time
from pathlib import Path

from .sched import ease_factor, lower_priority, next_frame, video_behind


def iou(a, b):
    ix = max(0.0, min(a[2], b[2]) - max(a[0], b[0]))
    iy = max(0.0, min(a[3], b[3]) - max(a[1], b[1]))
    inter = ix * iy
    ua = (a[2] - a[0]) * (a[3] - a[1]) + (b[2] - b[0]) * (b[3] - b[1]) - inter
    return inter / ua if ua > 0 else 0.0


def nms(dets, thr=0.5):
    out = []
    for d in sorted(dets, key=lambda x: -x["conf"]):
        if all(not (o["cls"] == d["cls"] and iou(o["box"], d["box"]) > thr) for o in out):
            out.append(d)
    return out


class Finder:
    BACKENDS = {"owlv2": "google/owlv2-base-patch16-ensemble", "gdino": "IDEA-Research/grounding-dino-tiny"}
    STRONG = 0.50         # a score this high is shown after ONE pass (no false hit scored above it on the benchmark at 640 px);
                          # weaker hits must repeat on `min_hits` passes
    FLOOR = 0.10          # candidates below this are not even reported
    CANDIDATE = 0.18      # frames scoring above this are saved to candidates_dir (see _save_candidate)

    def __init__(self, video, on_event=None, backend="owlv2", words=None, threshold=None, threads=4, min_hits=2,
                 input_size=640, candidates_dir=None, period=4.0):
        self.input_size = input_size       # OWLv2 input side in px (multiple of 16): 960 = trained size, smaller = faster
        self.period = period               # seconds between the START of two passes: leaves CPU for the real-time detector
        self.candidates_dir = Path(candidates_dir) if candidates_dir else None
        self._last_cand = 0.0
        self._pass_started = 0.0
        self._clear = False
        self.video = video
        self.on_event = on_event or (lambda k, m: None)
        self.backend = backend
        self.words = list(words or [])
        self.threshold = threshold
        self.threads = threads
        self.min_hits = min_hits
        self.enabled = False
        self.loading = False
        self.available = False
        self.error = None
        self.latest = {"ts": None, "frame_ts": None, "dets": []}
        self.on_pass = None          # callable(info dict: shown, best, frame, frame_ts, now, infer_ms, threshold, words)
        self.s = {"passes": 0, "infer_ms": None, "fps": 0.0, "backend": backend, "model": self.BACKENDS[backend], "best": {}}
        self._model = self._proc = None
        self._loaded = None
        self._tracks = {}
        self._next_id = 1000
        self._times = collections.deque(maxlen=10)
        self._stop = False
        self._thread = threading.Thread(target=self._run, name="finder", daemon=True)
        self._thread.start()

    # ------------------------------------------------------------ control
    def configure(self, enabled=None, words=None, backend=None, threshold=None, period=None):
        if period is not None:
            self.period = max(0.0, min(30.0, float(period)))
        if words is not None:
            ws = []
            for w in words:
                w = " ".join(str(w).strip().lower().split())[:40]
                if w and w not in ws:
                    ws.append(w)
            self.words = ws[:12]
            self._clear = True                       # the worker thread clears its own tracks (no cross-thread dict mutation)
        if backend is not None:
            if backend not in self.BACKENDS:
                raise ValueError(f"backend must be one of {sorted(self.BACKENDS)}")
            self.backend = backend
            self.s.update(backend=backend, model=self.BACKENDS[backend])
        if threshold is not None:
            self.threshold = max(0.12, min(0.9, float(threshold)))
        if enabled is not None:
            self.enabled = bool(enabled)

    def close(self, timeout=20):
        self._stop = True
        self._thread.join(timeout)

    def default_threshold(self):
        # OWLv2 at 640 px on the benchmark: 11/11 pencil and 14/14 screwdriver photos score >= 0.5 / 0.4; 25 negative scenes
        # give 4 pencil false hits at 0.35, 2 at 0.40, 0 at 0.50. A false hit must also repeat on two passes in the same
        # place (min_hits) before a box is shown. Adjustable from the dashboard.
        return self.threshold if self.threshold is not None else 0.35

    # ------------------------------------------------------------- models
    @staticmethod
    def _pretrained(cls, name):
        """The copy already on disk if there is one: no request to huggingface.co at every start (the ground station
        must come up without internet, and the look-ups alone took seconds), the network only for the first download."""
        try:
            return cls.from_pretrained(name, local_files_only=True), "local copy"
        except Exception:
            return cls.from_pretrained(name), "downloaded"

    def _load(self):
        import torch
        torch.set_num_threads(self.threads)
        t0 = time.monotonic()
        name = self.BACKENDS[self.backend]
        if self.backend == "owlv2":
            from transformers import Owlv2ForObjectDetection, Owlv2Processor
            self._proc, _ = self._pretrained(Owlv2Processor, name)
            self._proc.image_processor.size = {"height": self.input_size, "width": self.input_size}
            model, src = self._pretrained(Owlv2ForObjectDetection, name)
        else:
            from transformers import AutoModelForZeroShotObjectDetection, AutoProcessor
            self._proc, _ = self._pretrained(AutoProcessor, name)
            model, src = self._pretrained(AutoModelForZeroShotObjectDetection, name)
        self._model = model.eval()
        self._loaded = self.backend
        self.available = True
        self.on_event("FINDER", f"{name} loaded in {time.monotonic() - t0:.1f} s ({src})")

    def detect(self, rgb, words, threshold):
        """rgb: HxWx3 uint8. Returns [{'cls','conf','box'(normalised xyxy)}]."""
        import torch
        h, w = rgb.shape[:2]
        out = []
        if self.backend == "owlv2":
            inputs = self._proc(text=[[f"a photo of a {x}" for x in words]], images=rgb, return_tensors="pt")
            with torch.no_grad():
                o = self._model(**inputs, interpolate_pos_encoding=(self.input_size != 960))
            # Decoded by hand (the post-processing helper moved between transformers versions): one sigmoid score per
            # (patch, word); pred_boxes are (cx, cy, w, h) normalised to the square the image was padded to.
            side = max(h, w)
            scores = torch.sigmoid(o.logits[0])                      # (patches, words)
            boxes = o.pred_boxes[0]
            for wi, word in enumerate(words):
                sc = scores[:, wi]
                idx = torch.nonzero(sc >= threshold).flatten()
                if len(idx) > 40:                                    # a flat, weak map: keep the best few only
                    idx = idx[torch.topk(sc[idx], 40).indices]
                for i in idx.tolist():
                    cx, cy, bw, bh = boxes[i].tolist()
                    x1, y1, x2, y2 = (cx - bw / 2) * side / w, (cy - bh / 2) * side / h, (cx + bw / 2) * side / w, (cy + bh / 2) * side / h
                    out.append({"cls": word, "conf": float(sc[i]), "box": [max(0.0, x1), max(0.0, y1), min(1.0, x2), min(1.0, y2)]})
        else:
            text = ". ".join(f"a {x}" for x in words) + "."
            inputs = self._proc(images=rgb, text=text, return_tensors="pt")
            with torch.no_grad():
                o = self._model(**inputs)
            res = self._proc.post_process_grounded_object_detection(o, inputs.input_ids, threshold=threshold, text_threshold=threshold,
                                                                    target_sizes=[(h, w)])[0]
            labels = res.get("text_labels") or res.get("labels")
            for sc, lb, bx in zip(res["scores"].tolist(), labels, res["boxes"].tolist()):
                lb = str(lb).replace("a ", "", 1).strip()
                match = next((x for x in words if x == lb or x in lb), None)
                if match is None:
                    continue
                out.append({"cls": match, "conf": sc, "box": [max(0, bx[0] / w), max(0, bx[1] / h), min(1, bx[2] / w), min(1, bx[3] / h)]})
        # a plausible object never fills the frame; drop degenerate boxes (and the padding region of a padded square)
        return nms([d for d in out if 1e-4 < (d["box"][2] - d["box"][0]) * (d["box"][3] - d["box"][1]) < 0.85
                    and d["box"][2] - d["box"][0] > 0.004 and d["box"][3] - d["box"][1] > 0.004])

    # -------------------------------------------------------------- track
    def _track(self, dets, frame_ts, now):
        """Greedy IoU association; a box is shown after `min_hits` consecutive passes and kept 2.5 s without one.
        `now` is a monotonic time (it becomes each box's "seen"); `frame_ts` is the capture time on the camera's clock."""
        for t in self._tracks.values():
            t["matched"] = False
        for d in sorted(dets, key=lambda x: -x["conf"]):
            best, bi = None, 0.3
            for t in self._tracks.values():
                if not t["matched"] and t["cls"] == d["cls"]:
                    v = iou(t["box"], d["box"])
                    if v > bi:
                        best, bi = t, v
            if best is None:
                best = self._tracks[self._next_id] = {"id": self._next_id, "cls": d["cls"], "hits": 0, "first": now}
                self._next_id += 1
            best.update(box=d["box"], conf=d["conf"], ts=frame_ts, seen=now, matched=True, hits=best["hits"] + 1)
        keep = self.keep_s()
        for k in [k for k, t in self._tracks.items() if now - t["seen"] > keep]:
            del self._tracks[k]
        return [{"cls": t["cls"], "conf": round(t["conf"], 3), "box": [round(v, 4) for v in t["box"]], "id": t["id"],
                 "ts": t["ts"], "hits": t["hits"], "src": "finder", "static": True, "hold": round(keep, 1), "seen": t["seen"]}
                for t in self._tracks.values() if (t["hits"] >= self.min_hits or t["conf"] >= self.STRONG) and now - t["seen"] <= keep]

    def keep_s(self):
        """How long a box outlives its last sighting: a pass takes seconds, so one missed pass must not make it blink -
        but a box must also not stay where an object used to be: gone after about one more missed pass."""
        fps = self.s.get("fps") or 0
        return max(2.5, 1.35 / fps) if fps > 0 else 5.0

    # ---------------------------------------------------------------- run
    def _run(self):
        try:
            import cv2
            import numpy as np
        except ImportError as e:                      # e.g. the Pi, which has no ML stack: the finder is a ground-station feature
            self.error = f"unavailable here: {e}"
            return
        self.s["nice"] = lower_priority(10)           # lowest priority of all: it is a 2.5 s burst of full-CPU work every few seconds
        while not self._stop:
            try:
                self._loop(cv2, np)
            except Exception as e:                    # e.g. a candidate frame that cannot be written: never ends the worker
                self.error = f"finder worker: {type(e).__name__}: {e}"
                self.on_event("FINDER", f"worker error ({self.error}); continuing")
                time.sleep(2.0)

    def _loop(self, cv2, np):
        last_seq = -1
        while not self._stop:
            if not self.enabled or not self.words:
                self.latest = {"ts": time.time(), "mono": time.monotonic(), "frame_ts": None, "dets": []}
                time.sleep(0.3)
                continue
            if self._loaded != self.backend:
                self.loading = True
                try:
                    self._load()
                    self.error = None
                except Exception as e:
                    self.error = f"{type(e).__name__}: {e}"
                    self.on_event("FINDER", f"unavailable: {self.error}")
                    self.enabled = False
                finally:
                    self.loading = False
                continue
            # after the video decoder was behind, passes come 2, 4 or 8 times less often for a while (sched.ease_factor)
            wait = self.period * ease_factor() - (time.monotonic() - self._pass_started)
            if wait > 0:                                             # duty-cycle: the detector gets the CPU in between
                time.sleep(min(wait, 0.25))
                continue
            if video_behind(self.video):                             # the decoder is behind: no pass (2.5 s on every core) now
                self.s["yielded"] = self.s.get("yielded", 0) + 1
                time.sleep(0.25)
                continue
            got = next_frame(self.video, last_seq)                   # blocks (up to 0.5 s) while there is nothing new
            if got is None:
                continue
            jpg, seq, fts = got
            last_seq = seq
            self._pass_started = time.monotonic()
            frame = cv2.imdecode(np.frombuffer(jpg, np.uint8), cv2.IMREAD_COLOR)
            if frame is None:
                continue
            t0 = time.perf_counter()
            thr = self.default_threshold()
            try:
                cands = self.detect(cv2.cvtColor(frame, cv2.COLOR_BGR2RGB), list(self.words), min(self.FLOOR, thr))
            except Exception as e:
                self.error = f"inference: {type(e).__name__}: {e}"
                time.sleep(1.0)
                continue
            self.error = None
            # `now`: wall clock, for stored records and file names. `mono`: for how long ago something was seen
            # (a wall clock that is stepped forward would make every confirmed box look expired at once).
            now, mono = time.time(), time.monotonic()
            strong = [d for d in cands if d["conf"] >= thr]
            best = {}
            for d in cands:                                          # strongest evidence per word, shown or not
                best[d["cls"]] = max(best.get(d["cls"], 0.0), round(d["conf"], 3))
            if self._clear:
                self._tracks.clear()
                self._clear = False
            shown = self._track(strong, fts or now, mono)
            self.latest = {"ts": now, "mono": mono, "frame_ts": fts or now, "dets": shown}
            self.s["passes"] += 1
            self.s["infer_ms"] = round((time.perf_counter() - t0) * 1000)
            self.s["best"] = best
            self._times.append(mono)
            if len(self._times) > 1 and self._times[-1] > self._times[0]:
                self.s["fps"] = round((len(self._times) - 1) / (self._times[-1] - self._times[0]), 2)
            self._save_candidate(frame, best, thr, now)
            if self.on_pass:
                try:                                                 # storage / events (never lets the worker die)
                    self.on_pass({"shown": shown, "best": best, "frame": frame, "frame_ts": fts or now, "now": now,
                                  "infer_ms": self.s["infer_ms"], "threshold": thr, "words": list(self.words)})
                except Exception as e:
                    self.on_event("FINDER", f"on_pass failed: {type(e).__name__}: {e}")

    def _save_candidate(self, frame, best, thr, now):
        """Keep frames in which a word scored above CANDIDATE: real-camera evidence for tuning the threshold later."""
        if not self.candidates_dir or not best or now - self._last_cand < 4.0:
            return
        word, sc = max(best.items(), key=lambda kv: kv[1])
        if sc < self.CANDIDATE:
            return
        import cv2
        self._last_cand = now
        d = self.candidates_dir
        d.mkdir(parents=True, exist_ok=True)
        cv2.imwrite(str(d / f"cand_{time.strftime('%Y%m%d_%H%M%S', time.localtime(now))}_{word.replace(' ', '_')}_{int(sc * 100):02d}"
                          f"{'_SHOWN' if sc >= thr else ''}.jpg"), frame, [cv2.IMWRITE_JPEG_QUALITY, 88])
        old = sorted(d.glob("cand_*.jpg"), key=lambda p: p.stat().st_mtime)
        for p in old[:-150]:
            p.unlink(missing_ok=True)

    def fresh(self, margin=None):
        """True while the last pass is recent enough to describe what the camera sees now (monotonic clock)."""
        margin = max(self.keep_s(), self.period) + 4.0 if margin is None else margin
        return bool(self.enabled) and time.monotonic() - (self.latest.get("mono") or 0) < margin

    def status(self):
        thr = self.default_threshold()
        latest, fresh = self.latest, self.fresh()       # a stopped video must not leave "FOUND pencil" on the screen
        return {"enabled": self.enabled, "loading": self.loading, "available": self.available, "error": self.error,
                "words": self.words, "threshold": thr, "period": self.period, "backends": list(self.BACKENDS), **self.s,
                "looking": fresh, "worker_alive": self._thread.is_alive(),
                "shown": [{"cls": d["cls"], "conf": d["conf"]} for d in latest["dets"]] if fresh else [],
                "weak": [{"cls": w, "conf": c} for w, c in sorted(self.s.get("best", {}).items(), key=lambda kv: -kv[1])
                         if c < thr] if fresh else []}
