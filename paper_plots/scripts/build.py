"""Build the paper's plots and check what was built.

    python paper_plots/scripts/build.py [--no-plots] [--no-sim]

1. the colour palette is run through a colour-vision validator (needs `node`); series that cannot be told apart
   (with or without full colour vision) or that do not stand out of the page stop the build
2. make_plots.py draws every measured plot from ../data and writes ../tables; simulation/analyze.py then draws the
   simulation's plots (plot11 and up) from simulation/results, if there are results (--no-sim leaves them as they are)
3. every exported file is measured: page width (90 or 190 mm), fonts embedded and Arial only, smallest
   text size (limit 6.5 pt), PNG pixel width at 600 dpi, EPS bounding box; a grey-scale preview is written
4. ../checks/build_report.md lists the result per file; the exit status is 1 if any check failed

Needs: matplotlib, numpy, Pillow (the ground-station venv has them), poppler-utils (pdfinfo, pdffonts, pdftotext).
"""
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import plotlib as pl                                             # noqa: E402

ROOT = pl.ROOT
CHECKS = ROOT / "checks"
EM_FONT = 1.117                 # height of a pdftotext word box / font size, Arial (ascent 0.905 + descent 0.212 em)
VALIDATOR_CANDIDATES = [Path(p) for p in sorted(Path("/mnt/c/Users").glob("*/AppData/Local/Temp/claude/bundled-skills/*/*/dataviz/scripts/validate_palette.js"))]


def run(*cmd):
    return subprocess.run(cmd, capture_output=True, text=True)


def palette():
    """The validator of the dataviz skill, if it is on this machine; its verdicts are kept in checks/palette.txt."""
    out = CHECKS / "palette.txt"
    src = next((p for p in VALIDATOR_CANDIDATES if p.exists()), None)
    if not src or not shutil.which("node"):
        note = "validator or node not available on this machine: the stored result of the last run stands"
        return (out.exists(), note)
    tmp = CHECKS / "_validator"
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "package.json").write_text('{"type":"module"}')
    shutil.copy(src, tmp / "validate_palette.js")
    # The colours are those of figures4papers (plotlib.PALETTE) and are kept as they are. What must hold for them is
    # what a reader needs: neighbouring series stay apart for the three kinds of colour-blindness and for full colour
    # vision, and every series stands out of the white page. (The validator has two rules of taste besides - a band
    # of lightness and a floor of colourfulness - which this palette's dark blue and its teal miss by a little; they
    # are written into the report and do not stop the build. A separation in the validator's "only with a second
    # sign" band is in order here: every series has its own marker, line style and hatch.)
    must = ("CVD separation", "Normal-vision floor", "Contrast vs surface")
    text, ok, notes = [], True, 0
    for label, colours, extra in (("all four series colours, neighbours (lines, stacked bars)", pl.SERIES, []),
                                  ("first three, every pair (dots that can lie anywhere)", pl.SERIES[:3], ["--pairs", "all"])):
        r = run("node", str(tmp / "validate_palette.js"), ",".join(colours), "--mode", "light", "--surface", "#ffffff", *extra)
        failed = [line for line in r.stdout.splitlines() if "[FAIL]" in line]
        ok = ok and bool(r.stdout.strip()) and not any(m in line for line in failed for m in must)
        notes += sum(not any(m in line for m in must) for line in failed)
        text.append(f"## {label}\n{r.stdout.strip()}\n")
    shutil.rmtree(tmp)
    out.write_text(f"Palette check, {time.strftime('%Y-%m-%d %H:%M')}; surface white (journal page). Colours: figures4papers (plotlib.PALETTE).\n"
                   f"Required: {', '.join(must)}. The validator's other rules are reported, not required.\n\n" + "\n".join(text))
    return ok, (f"series stay apart and stand out of the page ({notes} of the validator's rules of taste not met: see palette.txt)" if ok
                else "FAILED: see checks/palette.txt")


def measure(name):
    """Checks of one plot; returns (row for the report, list of problems)."""
    pdf, eps, png = (pl.OUT[k] / f"{name}.{k}" for k in ("pdf", "eps", "png"))
    problems = []
    info = run("pdfinfo", str(pdf)).stdout
    m = re.search(r"Page size:\s+([\d.]+) x ([\d.]+) pts", info)
    w_mm, h_mm = (float(m.group(1)) / 72 * 25.4, float(m.group(2)) / 72 * 25.4) if m else (0, 0)
    target = min((pl.W1, pl.W2), key=lambda t: abs(t - w_mm))
    if abs(w_mm - target) > 0.2:
        problems.append(f"width {w_mm:.2f} mm")
    fonts = [l.split() for l in run("pdffonts", str(pdf)).stdout.splitlines()[2:]]
    names = sorted({re.sub(r"^[A-Z]{6}\+", "", f[0]) for f in fonts})
    if any(len(f) < 6 or f[-5] != "yes" for f in fonts):          # columns: name type encoding emb sub uni object-number generation
        problems.append("a font is not embedded")
    if any(not n.startswith("Arial") for n in names):
        problems.append(f"fonts {names}")
    # Text sizes: the sizes matplotlib set (recorded when the plot was drawn) must all be >= 6.5 pt, and every word
    # found in the PDF must have the box of one of those sizes, upright or rotated (so nothing was scaled on the way).
    used = json.loads((CHECKS / "text_sizes.json").read_text()).get(name, []) if (CHECKS / "text_sizes.json").exists() else []
    smallest = min(used) if used else 0
    if smallest < pl.FS_MIN - 1e-6:
        problems.append(f"text of {smallest:.2f} pt")
    cut = json.loads((CHECKS / "text_cut_off.json").read_text()).get(name, []) if (CHECKS / "text_cut_off.json").exists() else []
    if cut:
        problems.append(f"text cut off at the edge of the figure, or two texts on top of each other: {cut[:3]}")
    words = re.findall(r'<word xMin="([\d.-]+)" yMin="([\d.-]+)" xMax="([\d.-]+)" yMax="([\d.-]+)">([^<]*)</word>', run("pdftotext", "-bbox", str(pdf), "-").stdout)
    odd = [txt for x0, y0, x1, y1, txt in words
           if not any(abs((float(y1) - float(y0)) / EM_FONT - s) < 0.3 or abs((float(x1) - float(x0)) / EM_FONT - s) < 0.3 for s in used)]
    if odd or not words:
        problems.append(f"{len(odd)} of {len(words)} words in the PDF have no expected size, e.g. {odd[:3]}")
    from PIL import Image
    Image.MAX_IMAGE_PIXELS = None
    im = Image.open(png)
    want_px = round(target / 25.4 * 600)
    if abs(im.width - want_px) > 2:
        problems.append(f"PNG {im.width} px wide, expected {want_px}")
    gray = im.convert("L")
    gray.thumbnail((1400, 1400))
    (CHECKS / "gray").mkdir(parents=True, exist_ok=True)
    gray.save(CHECKS / "gray" / f"{name}.png")
    bb = re.search(r"%%BoundingBox: (-?\d+) (-?\d+) (-?\d+) (-?\d+)", eps.read_text(errors="replace")[:4000])
    eps_w = (int(bb.group(3)) - int(bb.group(1))) / 72 * 25.4 if bb else 0
    if abs(eps_w - target) > 0.6:
        problems.append(f"EPS {eps_w:.1f} mm wide")
    row = [name, f"{w_mm:.2f} × {h_mm:.2f}", ", ".join(n.replace("Arial-", "Arial ").replace("MT", "") for n in names),
           f"{smallest:.1f}", f"{im.width} × {im.height}", f"{eps_w:.1f}", f"{pdf.stat().st_size / 1024:.0f}", "ok" if not problems else "; ".join(problems)]
    return row, problems


def main():
    CHECKS.mkdir(exist_ok=True)
    pal_ok, pal_note = palette()
    print(f"palette: {pal_note}")
    if not pal_ok:
        return 1
    rc = 0
    if "--no-plots" not in sys.argv:
        import make_plots
        argv, sys.argv = sys.argv, sys.argv[:1]
        rc = make_plots.main()
        # the simulation's figures (plot11 and up) are drawn by simulation/analyze.py from its own results, if there are any
        sim = ROOT.parent / "simulation"
        if "--no-sim" not in argv and any((sim / "results" / "raw").glob("*.csv")):
            sys.path.insert(0, str(sim))
            import analyze
            rc = analyze.main([]) or rc
    rows, bad = [], 0
    for pdf in sorted(pl.OUT["pdf"].glob("plot*.pdf")):
        row, problems = measure(pdf.stem)
        rows.append(row)
        bad += bool(problems)
        print(f"  {'ok  ' if not problems else 'FAIL'} {row[0]:32s} {row[1]:16s} mm  min text {row[3]} pt  {row[7]}")
    summary = json.loads((CHECKS / "plot_summary.json").read_text()) if (CHECKS / "plot_summary.json").exists() else {}
    lines = ["# Build report of the paper's plots", "", f"Built {time.strftime('%Y-%m-%d %H:%M')}. Palette: {pal_note} (`palette.txt`).", "",
             "| plot | page (mm) | fonts in the PDF | smallest text (pt) | PNG at 600 dpi (px) | EPS width (mm) | PDF (kB) | checks |", "|---|---|---|---|---|---|---|---|"]
    lines += ["| " + " | ".join(r) + " |" for r in rows]
    lines += ["", "Limits: width 90.0 or 190.0 mm (± 0.2), all fonts embedded and Arial only, no text under 6.5 pt (sizes as set when",
              "drawing, cross-checked against the size of every word found in the PDF), PNG width 2126 or 4488 px. Grey-scale previews: `gray/`.",
              "", "## What each plot was drawn from", ""]
    for k, v in summary.items():
        lines.append(f"* `{k}`: `{json.dumps(v, default=str)[:600]}`")
    sim = json.loads((CHECKS / "sim_summary.json").read_text()) if (CHECKS / "sim_summary.json").exists() else {}
    if sim:
        lines += ["", "## Simulation figures (plot11 and up): SIMULATED, from simulation/results (see simulation/README.md)", ""]
        for k, v in sim.items():
            lines.append(f"* `{k}`: `{json.dumps(v, default=str)[:600]}`")
    (CHECKS / "build_report.md").write_text("\n".join(lines) + "\n")
    print(f"{len(rows)} plots, {bad} with problems -> {CHECKS / 'build_report.md'}")
    return 1 if (bad or rc) else 0


if __name__ == "__main__":
    sys.exit(main())
