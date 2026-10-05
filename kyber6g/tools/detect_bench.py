"""Open-vocabulary detection benchmark for 'pencil' and 'screwdriver' (reproduces the numbers in docs/TEST_REPORT.md).

    python -m kyber6g.tools.detect_bench fetch                       # download the vetted CC photos from Wikimedia Commons
    python -m kyber6g.tools.detect_bench run yoloe yoloe-26l-seg.pt 640
    python -m kyber6g.tools.detect_bench run owl google/owlv2-base-patch16-ensemble
    python -m kyber6g.tools.detect_bench run gdino IDEA-Research/grounding-dino-tiny
    python -m kyber6g.tools.detect_bench report

Data (all under ~/kyber6g_bench): positives (11 pencil, 14 screwdriver photos), negatives (20 everyday scenes + the two
ultralytics sample images + real camera frames without the objects), "hard" negatives (pens, brushes, chopsticks) and the
8 real camera frames in which a pencil was held up. The photo list is tests/data_detect_bench_titles.json (Commons titles).
Score = the highest confidence of the target label in the image; no ground-truth boxes are needed because the positive
images show the object as their main subject. Reported per model: AUC (positives vs negatives; 0.5 = chance), recall at
confidence 0.1/0.2/0.3, false positives on the 25 negatives and on the hard negatives, seconds per image.
"""
import glob
import json
import os
import shutil
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

import numpy as np

ROOT = Path.home() / "kyber6g_bench"
HERE = Path(__file__).resolve().parents[2]
TITLES = HERE / "tests" / "data_detect_bench_titles.json"
GROUND = Path.home() / "kyber6g_ground"
TARGETS = ["pencil", "screwdriver"]
UA = {"User-Agent": "kyber6g-bench/1.0 (research test)"}


def fetch():
    import cv2
    titles = json.loads(TITLES.read_text())
    manifest = {}
    for cat, names in titles.items():
        d = ROOT / f"set_{cat}"
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True)
        files = []
        for i, t in enumerate(names):
            url = "https://commons.wikimedia.org/wiki/Special:FilePath/" + urllib.parse.quote(t.replace("File:", "")) + "?width=900"
            try:
                data = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=40).read()
                im = cv2.imdecode(np.frombuffer(data, np.uint8), cv2.IMREAD_COLOR)
                if im is None:
                    raise ValueError("not an image")
                cv2.imwrite(str(d / f"{i:02d}.jpg"), im)
                files.append(str(d / f"{i:02d}.jpg"))
            except Exception as e:
                print(f"  skipped {t}: {type(e).__name__}")
            time.sleep(0.2)
        manifest[cat] = files
    import ultralytics
    assets = Path(ultralytics.__file__).parent / "assets"
    manifest["neg"] += [str(assets / "bus.jpg"), str(assets / "zidane.jpg")]
    manifest["real_neg"] = [str(p) for p in (GROUND / "live_test.jpg", GROUND / "live_now.jpg", GROUND / "acc_frame.jpg") if p.exists()]
    manifest["real_pencil"] = sorted(glob.glob(str(GROUND / "pencil_[0-9].jpg")))
    (ROOT / "manifest.json").write_text(json.dumps(manifest, indent=1))
    print({k: len(v) for k, v in manifest.items()})


def _images():
    man = json.loads((ROOT / "manifest.json").read_text())
    return [(cat, p) for cat, ps in man.items() for p in ps]


def _result(name, res, secs):
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / f"{name}.json").write_text(json.dumps({"res": res, "sec_per_img": secs}))
    print(f"saved {name} ({secs:.2f} s/img)")


def run_yoloe(weights, imgsz=640):
    import cv2
    from ultralytics import YOLOE
    from ..ground.detector import EVERYDAY
    os.chdir(GROUND / "models")
    m = YOLOE(weights)
    m.set_classes(EVERYDAY, m.get_text_pe(EVERYDAY))
    out, ts = {}, []
    for cat, p in _images():
        t = time.perf_counter()
        r = m.predict(cv2.imread(p), verbose=False, conf=0.005, imgsz=imgsz)[0]
        ts.append(time.perf_counter() - t)
        s = {k: 0.0 for k in TARGETS}
        for c, cf in zip(r.boxes.cls.tolist(), r.boxes.conf.tolist()):
            if m.names[int(c)] in s:
                s[m.names[int(c)]] = max(s[m.names[int(c)]], cf)
        out[p] = {"cat": cat, **s}
    _result(f"yoloe_{Path(weights).stem}_{imgsz}", out, float(np.median(ts)))


def run_owl(hf):
    import cv2
    import torch
    from transformers import Owlv2ForObjectDetection, Owlv2Processor
    proc, model = Owlv2Processor.from_pretrained(hf), Owlv2ForObjectDetection.from_pretrained(hf).eval()
    out, ts = {}, []
    for cat, p in _images():
        im = cv2.cvtColor(cv2.imread(p), cv2.COLOR_BGR2RGB)
        t = time.perf_counter()
        inputs = proc(text=[[f"a photo of a {x}" for x in TARGETS]], images=im, return_tensors="pt")
        with torch.no_grad():
            lg = torch.sigmoid(model(**inputs).logits[0])
        ts.append(time.perf_counter() - t)
        out[p] = {"cat": cat, **{k: float(lg[:, i].max()) for i, k in enumerate(TARGETS)}}
    _result("owl_" + hf.split("/")[-1], out, float(np.median(ts)))


def run_gdino(hf):
    import cv2
    import torch
    from transformers import AutoModelForZeroShotObjectDetection, AutoProcessor
    proc, model = AutoProcessor.from_pretrained(hf), AutoModelForZeroShotObjectDetection.from_pretrained(hf).eval()
    out, ts = {}, []
    for cat, p in _images():
        im = cv2.cvtColor(cv2.imread(p), cv2.COLOR_BGR2RGB)
        s, t = {k: 0.0 for k in TARGETS}, time.perf_counter()
        for k in TARGETS:
            inputs = proc(images=im, text=f"a {k}.", return_tensors="pt")
            with torch.no_grad():
                o = model(**inputs)
            r = proc.post_process_grounded_object_detection(o, inputs.input_ids, threshold=0.05, text_threshold=0.05,
                                                            target_sizes=[im.shape[:2]])[0]
            if len(r["scores"]):
                s[k] = float(r["scores"].max())
        ts.append((time.perf_counter() - t) / len(TARGETS))
        out[p] = {"cat": cat, **s}
    _result("gdino_" + hf.split("/")[-1], out, float(np.median(ts)))


def auc(pos, neg):
    return float(np.mean([(p > n) + 0.5 * (p == n) for p in pos for n in neg])) if pos and neg else float("nan")


def report():
    rows = []
    for f in sorted(glob.glob(str(ROOT / "results" / "*.json"))):
        d = json.loads(Path(f).read_text())
        for tgt, posset in (("pencil", ("pencil", "real_pencil")), ("screwdriver", ("screwdriver",))):
            v = list(d["res"].values())
            pos = [x[tgt] for x in v if x["cat"] in posset]
            neg = [x[tgt] for x in v if x["cat"] in ("neg", "real_neg")]
            hard = [x[tgt] for x in v if x["cat"] == "hard"]
            row = {"model": Path(f).stem, "target": tgt, "s/img": round(d["sec_per_img"], 2), "AUC": round(auc(pos, neg), 3)}
            for th in (0.1, 0.2, 0.3):
                row[f"rec@{th}"] = f"{sum(x >= th for x in pos)}/{len(pos)}"
                row[f"fp@{th}"] = f"{sum(x >= th for x in neg)}/{len(neg)}"
            row["hardfp@.2"] = f"{sum(x >= 0.2 for x in hard)}/{len(hard)}"
            rows.append(row)
    if rows:
        keys = list(rows[0])
        w = {k: max(len(k), *(len(str(r[k])) for r in rows)) for k in keys}
        print("  ".join(k.ljust(w[k]) for k in keys))
        for r in rows:
            print("  ".join(str(r[k]).ljust(w[k]) for k in keys))


def main():
    a = sys.argv[1:]
    if not a:
        print(__doc__)
    elif a[0] == "fetch":
        fetch()
    elif a[0] == "report":
        report()
    elif a[0] == "run":
        {"yoloe": run_yoloe, "owl": run_owl, "gdino": run_gdino}[a[1]](a[2], *[int(x) for x in a[3:]])


if __name__ == "__main__":
    main()
