#!/usr/bin/env python3
"""Build the paper figures.

    python3 scripts/build.py              all figures
    python3 scripts/build.py fig03 fig07  only these (prefix match)
    python3 scripts/build.py --no-export  write the .drawio files and run the layout checks only

Per figure:  figures.py -> raw_drawio/<name>.drawio
             draw.io CLI (headless) -> PDF -> pdfcrop (tight box) -> scaled so the width is exactly 90 / 190 mm
             -> exported_pdf/<name>.pdf, exported_eps/<name>.eps (pdftops), exported_png/<name>.png (600 dpi)
             -> checks/gray/<name>.png (greyscale proof) and checks/build_report.md
Nothing is reported as passed unless it was measured on the produced files.
"""
import argparse
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import figlib  # noqa: E402
import figures  # noqa: E402

ROOT = figlib.ROOT
WORK = ROOT / ".build"
DIRS = {k: ROOT / k for k in ("raw_drawio", "exported_pdf", "exported_eps", "exported_png")}
GRAY = ROOT / "checks" / "gray"
PT_PER_MM = 72 / 25.4


def run(*cmd, ok=(0,)):
    r = subprocess.run([str(c) for c in cmd], capture_output=True, text=True)
    if r.returncode not in ok:
        raise RuntimeError(f"{' '.join(str(c) for c in cmd[:3])} ... failed ({r.returncode}): {(r.stderr or r.stdout)[-400:]}")
    return r.stdout + r.stderr


def drawio_export(fmt, src_dir, out_dir, *extra):
    out_dir.mkdir(parents=True, exist_ok=True)
    run("xvfb-run", "-a", "drawio", "--no-sandbox", "--disable-gpu", "-x", "-f", fmt, *extra, "-o", out_dir, src_dir)


def bbox(pdf, dpi=1200):
    """Bounding box of everything that is not pure white, in PDF points (left, bottom, right, top).
    Measured on a 1200 dpi rendering rather than with Ghostscript's bbox device: that device is 1-bit and dithers
    the near-white registration marks, so it saw them in some figures and not in others."""
    return _bbox(pdf, dpi)[0]


def _bbox(pdf, dpi=1200):
    """(bounding box, marks_ok): marks_ok says that the outermost ink on the left and on the right is a registration
    mark (very light, a few pixels), i.e. both marks survived the export and nothing was drawn outside them."""
    from PIL import Image, ImageChops
    Image.MAX_IMAGE_PIXELS = None
    stem = WORK / "bbox"
    run("pdftoppm", "-r", dpi, "-gray", "-singlefile", pdf, stem)
    im = Image.open(f"{stem}.pgm")
    box = ImageChops.invert(im).getbbox()
    if not box:
        raise RuntimeError(f"{pdf} is empty")

    def is_mark(x):
        col = [v for v in im.crop((x, box[1], x + 1, box[3])).tobytes() if v < 255]
        return bool(col) and min(col) > 235 and len(col) < 0.02 * dpi
    k = 72 / dpi
    return ((box[0] * k, (im.size[1] - box[3]) * k, box[2] * k, (im.size[1] - box[1]) * k),
            is_mark(box[0] + 1) and is_mark(box[2] - 2))


EM_HEIGHT = 1.117        # Arial: ascent 0.905 + descent 0.212 em (what poppler uses for a word box)


def text_sizes(pdf):
    """Font sizes in the finished PDF, measured from the word boxes poppler reports."""
    html = run("pdftotext", "-bbox", pdf, "-")
    sizes = set()
    for x0, y0, x1, y1, word in re.findall(r'<word xMin="(-?[\d.]+)" yMin="(-?[\d.]+)" xMax="(-?[\d.]+)" yMax="(-?[\d.]+)">([^<]*)</word>', html):
        w, h = float(x1) - float(x0), float(y1) - float(y0)
        upright = not (len(word) >= 4 and h > 1.6 * w)           # a long word standing on its side: its em height is the box width
        sizes.add(round((h if upright else w) / EM_HEIGHT, 1))
    return sorted(sizes)


def raster_images(pdf):
    """(count, lowest resolution in ppi) of the raster pictures inside the PDF."""
    rows = [l.split() for l in run("pdfimages", "-list", pdf).splitlines()[2:] if l.strip()]
    rows = [r for r in rows if r[2] == "image"]                       # soft masks are not pictures
    return len(rows), min((min(float(r[12]), float(r[13])) for r in rows), default=None)


def normalise(tight_pdf, final_pdf, width_pt, title, margin_pt=0.0):
    """Scale the cropped page so that the finished page is exactly width_pt wide. The cropped page runs from the left
    registration mark to the right one, which sit margin_pt inside the design width. Lossless: one transformation
    in front of the page."""
    from pypdf import PdfReader, PdfWriter, Transformation
    from pypdf.generic import RectangleObject
    page = PdfReader(str(tight_pdf)).pages[0]
    box = page.mediabox
    w, h, llx, lly = float(box.width), float(box.height), float(box.left), float(box.bottom)
    s = (width_pt - 2 * margin_pt) / w
    page.add_transformation(Transformation().translate(-llx, -lly).scale(s, s).translate(margin_pt, 0))
    rect = RectangleObject([0, 0, round(width_pt, 3), round(h * s, 3)])
    page.mediabox = page.cropbox = page.trimbox = page.bleedbox = page.artbox = rect
    out = PdfWriter()
    out.add_page(page)
    out.add_metadata({"/Title": title, "/Creator": "draw.io Desktop (CLI) + pdfcrop", "/Producer": "kyber6g paper_figures/scripts/build.py"})
    with open(final_pdf, "wb") as f:
        out.write(f)
    return s, h * s


def straighten(pts):
    """Remove repeated points and points in the middle of a straight run."""
    out = []
    for p in pts:
        if out and abs(p[0] - out[-1][0]) < 0.01 and abs(p[1] - out[-1][1]) < 0.01:
            continue
        while len(out) >= 2 and ((abs(out[-2][0] - out[-1][0]) < 0.01 and abs(out[-1][0] - p[0]) < 0.01)
                                 or (abs(out[-2][1] - out[-1][1]) < 0.01 and abs(out[-1][1] - p[1]) < 0.01)):
            out.pop()
        out.append(p)
    return out


def svg_edges(svg_text):
    """Polylines of the connectors as draw.io rendered them. A rounded corner is a quadratic curve (Q) whose control
    point is the corner itself; a line jump is a cubic curve (C) that starts and ends on the line. Taking the corner
    of every Q and the end point of every other command, then straightening, gives the route back."""
    out = []
    for d in re.findall(r'<path d="([^"]+)" fill="none" stroke="#[0-9a-fA-F]{6}"', svg_text):
        if re.search(r"[AZaz]", d):
            continue
        pts = []
        for cmd, args in re.findall(r"([MLCQ])([^MLCQ]*)", d):
            nums = [float(v) for v in re.findall(r"-?\d+(?:\.\d+)?", args)]
            if cmd == "Q":
                pts.append((nums[0], nums[1]))
            pts.append((nums[-2], nums[-1]))
        out.append(straighten(pts))
    return out


def verify_routes(fig, svg_text):
    """Compare each designed connector with what draw.io actually drew. Returns (matched, total, problems)."""
    drawn = svg_edges(svg_text)
    design = [dict(e, pts=straighten(e["draw"])) for e in fig.lines]      # "draw": the line stops inside its arrowhead
    if not design:
        return 0, 0, []

    def same(a, b, off, arrow):
        if len(a) != len(b):
            return False
        for (ax, ay), (bx, by) in zip(a, b):
            if abs(ax - off[0] - bx) > 0.75 or abs(ay - off[1] - by) > 0.75:
                return False
        return True

    best, best_off = -1, (0, 0)
    for e in design[:6]:
        for d in drawn:
            off = (e["pts"][0][0] - d[0][0], e["pts"][0][1] - d[0][1])
            if abs(off[0]) > 12 or abs(off[1]) > 12:
                continue
            n = sum(any(same(x["pts"], y, off, x["arrow"]) for y in drawn) for x in design)
            if n > best:
                best, best_off = n, off
    problems = [f"connector {e['id']} {e['pts']} was not drawn as designed" for e in design
                if not any(same(e["pts"], y, best_off, e["arrow"]) for y in drawn)]
    return len(design) - len(problems), len(design), problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("names", nargs="*")
    ap.add_argument("--no-export", action="store_true")
    ap.add_argument("--keep", action="store_true", help="keep the .build working directory")
    a = ap.parse_args()
    figs = [f() for f in figures.FIGURES]
    if a.names:
        figs = [f for f in figs if any(f.name.startswith(n) for n in a.names)]
    for d in DIRS.values():
        d.mkdir(parents=True, exist_ok=True)
    GRAY.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(WORK, ignore_errors=True)
    (WORK / "in").mkdir(parents=True)
    report = {}
    for f in figs:
        path = f.save()
        shutil.copy(path, WORK / "in" / path.name)
        report[f.name] = {"fig": f, "layout": f.check()}
    if a.no_export:
        for name, r in report.items():
            print(f"{name}: {len(r['layout'])} layout issue(s)")
            for i in r["layout"]:
                print("    -", i)
        return 0
    t0 = time.time()
    drawio_export("pdf", WORK / "in", WORK / "raw", "--crop")
    drawio_export("svg", WORK / "in", WORK / "svg")
    print(f"draw.io exported {len(figs)} figure(s) in {time.time() - t0:.0f} s")
    rows = []
    for name, r in report.items():
        f = r["fig"]
        raw, tight = WORK / "raw" / f"{name}.pdf", WORK / f"{name}.tight.pdf"
        pdf, eps, png = DIRS["exported_pdf"] / f"{name}.pdf", DIRS["exported_eps"] / f"{name}.eps", DIRS["exported_png"] / f"{name}.png"
        problems = list(r["layout"])
        if not raw.exists():
            problems.append("draw.io produced no PDF")
            rows.append((name, f, None, problems))
            continue
        raw_box, marks_ok = _bbox(raw)
        if not marks_ok:
            problems.append("a registration mark is missing or something is drawn outside the marks: the scale is not trustworthy")
        pad = 1.2                                                                           # pt above and below, so no letter touches the page edge
        raw_box = (raw_box[0], raw_box[1] - pad, raw_box[2], raw_box[3] + pad)
        run("pdfcrop", "--bbox", " ".join(f"{v:.3f}" for v in raw_box), raw, tight)         # tight box, from mark to mark
        width_pt = f.W * 0.75
        scale, height_pt = normalise(tight, pdf, width_pt, f.caption or name, figlib.MARGIN * 0.75)
        run("pdftops", "-eps", "-level3", pdf, eps)
        run("pdftoppm", "-r", "600", "-png", "-singlefile", pdf, str(png)[:-4])
        run("pdftoppm", "-r", "300", "-gray", "-png", "-singlefile", pdf, str(GRAY / name))
        # ---- measurements on the produced files
        x0, y0, x1, y1 = bbox(pdf)
        m = figlib.MARGIN * 0.75
        if abs(x0 - m) > 0.15 or abs(x1 - (width_pt - m)) > 0.15:
            problems.append(f"ink spans {x0:.2f} .. {x1:.2f} pt, expected {m:.2f} .. {width_pt - m:.2f} pt")
        fonts = [l.split()[0] for l in run("pdffonts", pdf).splitlines()[2:] if l.strip()]
        emb = [l for l in run("pdffonts", pdf).splitlines()[2:] if l.strip() and " yes " not in l[36:]]
        bad = [n for n in fonts if "Arial" not in n]
        if bad:
            problems.append(f"fonts other than Arial in the PDF: {bad}")
        if emb:
            problems.append("a font is not embedded")
        n_img, ppi = raster_images(pdf)
        wanted = sum(1 for p in f.pics if p["raster"])
        if n_img != wanted:
            problems.append(f"{n_img} raster picture(s) in the PDF, {wanted} placed (a pictogram was rasterised?)")
        if ppi is not None and ppi < 300:
            problems.append(f"a picture has only {ppi:.0f} ppi at its printed size (300 needed)")
        sizes = text_sizes(pdf)
        if sizes and sizes[0] < 6.45:
            problems.append(f"text of {sizes[0]} pt in the PDF (minimum is 6.5 pt)")
        svg = WORK / "svg" / f"{name}.svg"
        ok, total, route = verify_routes(f, svg.read_text()) if svg.exists() else (0, len(f.lines), ["no SVG for the route check"])
        problems += route
        eps_bb = re.search(r"%%HiResBoundingBox: (.*)", eps.read_text(errors="replace"))
        rows.append((name, f, dict(width_mm=width_pt / PT_PER_MM, height_mm=height_pt / PT_PER_MM, scale=scale, sizes=sizes,
                                   images=f"{n_img}" + (f" (min {ppi:.0f} ppi)" if ppi else ""),
                                   ink=(x0, y0, x1, y1), fonts=sorted({n.split("+")[-1] for n in fonts}), routes=(ok, total),
                                   eps_bbox=eps_bb.group(1).strip() if eps_bb else "?", png=png), problems))
    # ---- report
    version = [l.strip() for l in run("xvfb-run", "-a", "drawio", "--no-sandbox", "--version").splitlines() if re.fullmatch(r"[0-9.]+", l.strip())]
    lines = ["# Build report", "", f"Built {time.strftime('%Y-%m-%d %H:%M')} with draw.io Desktop {version[-1] if version else '?'}, pdfcrop, "
             f"Ghostscript {run('gs', '--version').strip()} and poppler. Every value below was measured on the produced files.", "",
             "| Figure | Width × height (mm) | Text sizes (pt) | Fonts embedded | Raster pictures | Connectors drawn as designed | Layout problems |",
             "|---|---|---|---|---|---|---|"]
    for name, f, m, problems in rows:
        if m is None:
            lines.append(f"| {name} | — | — | — | — | — | {'; '.join(problems)} |")
            continue
        lines.append(f"| {name} | {m['width_mm']:.2f} × {m['height_mm']:.2f} | {', '.join(f'{s:g}' for s in m['sizes'])} | {', '.join(m['fonts'])} | {m['images']} "
                     f"| {m['routes'][0]} of {m['routes'][1]} | {'none' if not problems else '<br>'.join(problems)} |")
        print(f"{name}: {m['width_mm']:.2f} x {m['height_mm']:.2f} mm, text {m['sizes']} pt, fonts {m['fonts']}, routes {m['routes'][0]}/{m['routes'][1]}, "
              f"{len(problems)} problem(s)")
        for p in problems:
            print("    -", p)
    (ROOT / "checks").mkdir(exist_ok=True)
    if not a.names:
        (ROOT / "checks" / "build_report.md").write_text("\n".join(lines) + "\n")
    if not a.keep:
        shutil.rmtree(WORK, ignore_errors=True)
    return 1 if any(p for *_, p in rows) else 0


if __name__ == "__main__":
    sys.exit(main())
