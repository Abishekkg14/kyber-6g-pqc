"""Shared style of the paper's plots (matplotlib), matching the diagrams in paper_figures/.

One place for the things every plot has in common, so they cannot drift apart:

  size      90 mm (one column) or 190 mm (two columns) wide, exactly - the figure is created at that size and saved
            without any "tight" cropping, so the exported PDF/EPS/PNG have that width (checked by build.py)
  look      the house style of github.com/ChenLiu-1996/figures4papers (its scripts and its design notes), brought
            to the size of a journal column: Arial (its portable stand-in for Helvetica), black axes without the
            top and right spines, no grid, frameless legends, bars with a black outline, lines of 1.4 pt.
            Its figures are drawn large (labels of 28 pt on a 24 inch canvas) and scaled down by the journal; here
            the same proportions are set at the final size: 8 pt axis labels, 7 pt ticks / legend / notes, 8 pt bold
            panel titles, 1 pt axes - and nothing under 6.5 pt. Fonts are embedded as TrueType (PDF/EPS type 42).
  colour    PALETTE is that repository's: blue for the thing the paper is about, red for what it is compared
            with, green for gains, greys for context. SERIES are its four dark colours in a FIXED order (blue,
            red, teal, violet); checks/palette.txt holds the verdicts of a colour-vision validator on them
            (neighbours stay apart under protanopia / deuteranopia / tritanopia; contrast >= 3:1 on white).
            Colour follows the thing, not its rank: e.g. the Raspberry Pi is always SERIES[0]. Simulated results
            are drawn in the greys, never in a colour. Text is never drawn in a series colour.
  print     a journal page may be printed in grey: every series also has its own marker and line style, and bar
            fills carry a 45 / 135 degree hatch (never horizontal or vertical: those read as axis lines)
  marks     markers with a white ring, bars with square ends and a black outline, no chart junk, one y-axis per
            panel (never two scales); a legend sits where there is no data
  tables    every plot writes the numbers it shows to tables/<name>.csv (the table view of the figure)
"""
import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt                                  # noqa: E402
import matplotlib.legend                                         # noqa: E402
from matplotlib import font_manager                              # noqa: E402
from matplotlib.legend_handler import HandlerTuple               # noqa: E402
from matplotlib.patches import PathPatch                         # noqa: E402
from matplotlib.path import Path as MPath                        # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA, TABLES = ROOT / "data", ROOT / "tables"
OUT = {"pdf": ROOT / "exported_pdf", "eps": ROOT / "exported_eps", "png": ROOT / "exported_png"}

MM = 1 / 25.4
W1, W2 = 90.0, 190.0                                             # mm
# The palette of figures4papers (its design notes, section 9), by the names it gives them.
PALETTE = {
    "blue_main": "#0F4D92", "blue_secondary": "#3775BA",
    "green_1": "#DDF3DE", "green_2": "#AADCA9", "green_3": "#8BCF8B",
    "red_1": "#F6CFCB", "red_2": "#E9A6A1", "red_strong": "#B64342",
    "neutral": "#CFCECE", "grey_1": "#767676", "grey_2": "#4D4D4D", "grey_3": "#272727",
    "highlight": "#FFD700", "teal": "#42949E", "violet": "#9A4D8E",
}
INK, INK2, MUTED, GRID, AXIS = "#000000", "#272727", "#767676", "#CFCECE", "#000000"
SERIES = [PALETTE["blue_main"], PALETTE["red_strong"], PALETTE["teal"], PALETTE["violet"]]     # fixed order (checks/palette.txt)
SIMULATED = [PALETTE["grey_3"], PALETTE["grey_1"]]               # what was simulated: greys, never a colour
NEUTRAL = PALETTE["neutral"]                                     # "the rest" / context, never a series of its own
MARKERS = ["o", "s", "^", "D"]
DASHES = ["-", (0, (4.5, 1.6)), (0, (1.2, 1.3)), (0, (4.5, 1.4, 1.2, 1.4))]
HATCHES = [None, "/////", "\\\\\\\\\\", "xxxxx"]
FS_TITLE, FS_LABEL, FS_TICK, FS_NOTE, FS_MIN = 8.0, 8.0, 7.0, 7.0, 6.5
FONT = "Arial"


def setup():
    for d in ("/usr/local/share/fonts/windows-core", "/mnt/c/Windows/Fonts"):
        for f in ("arial.ttf", "arialbd.ttf", "ariali.ttf", "arialbi.ttf"):
            p = Path(d) / f
            if p.exists():
                font_manager.fontManager.addfont(str(p))
        if any(f.name == FONT for f in font_manager.fontManager.ttflist):
            break
    else:
        raise SystemExit("Arial not found (paper_figures/scripts/setup_tools.sh installs it)")
    # the two patches of a `swatch` are drawn on top of each other, not side by side
    matplotlib.legend.Legend.update_default_handler_map({tuple: HandlerTuple(ndivide=1, pad=0)})
    plt.rcParams.update({
        "font.family": FONT, "font.size": FS_TICK,
        "mathtext.fontset": "custom", "mathtext.rm": FONT, "mathtext.it": f"{FONT}:italic", "mathtext.bf": f"{FONT}:bold",
        "pdf.fonttype": 42, "ps.fonttype": 42, "svg.fonttype": "none",
        "axes.linewidth": 1.0, "axes.edgecolor": AXIS, "axes.labelcolor": INK, "axes.labelsize": FS_LABEL, "axes.labelpad": 3,
        "axes.titlesize": FS_TITLE, "axes.titleweight": "bold", "axes.titlecolor": INK, "axes.titlelocation": "left", "axes.titlepad": 5,
        "axes.spines.top": False, "axes.spines.right": False, "axes.axisbelow": True,
        "axes.grid": False, "grid.color": GRID, "grid.linewidth": 0.5, "grid.linestyle": "-",
        "xtick.color": AXIS, "ytick.color": AXIS, "xtick.labelcolor": INK, "ytick.labelcolor": INK,
        "xtick.labelsize": FS_TICK, "ytick.labelsize": FS_TICK, "xtick.major.size": 2.6, "ytick.major.size": 2.6,
        "xtick.major.width": 0.6, "ytick.major.width": 0.6, "xtick.minor.size": 1.5, "ytick.minor.size": 1.5,
        "xtick.minor.width": 0.45, "ytick.minor.width": 0.45, "xtick.major.pad": 2.5, "ytick.major.pad": 2.5,
        "lines.linewidth": 1.4, "lines.markersize": 4.4, "lines.markeredgecolor": "white", "lines.markeredgewidth": 0.6,
        "lines.solid_capstyle": "round", "lines.solid_joinstyle": "round", "lines.dash_capstyle": "round",
        # a legend has no frame; it is only ever put where there is no data
        "legend.frameon": False, "legend.facecolor": "white", "legend.edgecolor": "none", "legend.framealpha": 1.0,
        "legend.fancybox": False, "legend.borderpad": 0.2,
        "legend.fontsize": FS_NOTE, "legend.handlelength": 2.6, "legend.handletextpad": 0.5,
        "legend.borderaxespad": 0.2, "legend.labelspacing": 0.3, "legend.columnspacing": 1.2, "legend.labelcolor": INK,
        "hatch.linewidth": 0.5, "hatch.color": "white", "patch.linewidth": 0.6,
        "figure.dpi": 100, "savefig.dpi": 600, "figure.facecolor": "white", "savefig.facecolor": "white",
        "text.color": INK, "figure.constrained_layout.use": True,
        "figure.constrained_layout.h_pad": 0.03, "figure.constrained_layout.w_pad": 0.03,
        "figure.constrained_layout.hspace": 0.04, "figure.constrained_layout.wspace": 0.04,
    })


def swatch(color, hatch=None):
    """A legend key that looks like the bars: the fill with its hatch in white, and a black outline over it (two
    patches, because a patch draws its hatch in its edge colour)."""
    return (plt.Rectangle((0, 0), 1, 1, facecolor=color, hatch=hatch, edgecolor="white", linewidth=0),
            plt.Rectangle((0, 0), 1, 1, facecolor="none", edgecolor=INK, linewidth=0.6))


def figure(width_mm, height_mm, nrows=1, ncols=1, **kw):
    fig, ax = plt.subplots(nrows, ncols, figsize=(width_mm * MM, height_mm * MM), **kw)
    fig._k6g_bars = []
    return fig, ax


def tint(color, share):
    """The colour mixed with white (share = how much of the colour is left). Used instead of transparency: EPS has
    no transparency, and a figure must look the same in PDF, EPS and PNG."""
    r, g, b = matplotlib.colors.to_rgb(color)
    return (1 - share + share * r, 1 - share + share * g, 1 - share + share * b)


def series(i, **kw):
    """Line style of series i: its colour, marker and dash pattern together (so grey print still tells them apart)."""
    return {"color": SERIES[i], "marker": MARKERS[i], "linestyle": DASHES[i], **kw}


def panel(ax, letter, title):
    ax.set_title(f"({letter})  {title}", fontsize=FS_TITLE)


def note(ax, x, y, text, ha="left", va="center", size=FS_NOTE, color=INK2, **kw):
    """Text in ink beside a mark (never in the mark's colour)."""
    return ax.text(x, y, text, ha=ha, va=va, fontsize=size, color=color, **kw)


def bar(fig, ax, lo, hi, pos, thick, color, horizontal=True, hatch=None, round_end=True):
    """A bar from `lo` to `hi` (data units) at position `pos`, `thick` points thick: square at the baseline end,
    rounded at the data end, with a white outline that leaves a gap to a neighbouring fill. Drawn by `finish`,
    when the layout is final (the corner radius is in points, so it needs the final geometry)."""
    fig._k6g_bars.append((ax, lo, hi, pos, thick, color, horizontal, hatch, round_end))


def _bar_path(x0, y0, x1, y1, r, horizontal):
    """Rectangle x0..x1, y0..y1 (inches) with the far end (x1 if horizontal, y1 if vertical) rounded by r."""
    if r <= 0:
        return MPath([(x0, y0), (x1, y0), (x1, y1), (x0, y1), (x0, y0)], [MPath.MOVETO] + [MPath.LINETO] * 3 + [MPath.CLOSEPOLY])
    k = 0.5523 * r                                               # cubic Bezier approximation of a quarter circle
    C = MPath.CURVE4
    if horizontal:
        v = [(x0, y0), (x1 - r, y0), (x1 - r + k, y0), (x1, y0 + r - k), (x1, y0 + r), (x1, y1 - r),
             (x1, y1 - r + k), (x1 - r + k, y1), (x1 - r, y1), (x0, y1), (x0, y0)]
    else:
        v = [(x0, y0), (x1, y0), (x1, y1 - r), (x1, y1 - r + k), (x1 - r + k, y1), (x1 - r, y1), (x0 + r, y1),
             (x0 + r - k, y1), (x0, y1 - r + k), (x0, y1 - r), (x0, y0)]
        return MPath(v, [MPath.MOVETO, MPath.LINETO, MPath.LINETO, C, C, C, MPath.LINETO, C, C, C, MPath.CLOSEPOLY])
    return MPath(v, [MPath.MOVETO, MPath.LINETO, C, C, C, MPath.LINETO, C, C, C, MPath.LINETO, MPath.CLOSEPOLY])


def finish(fig):
    """Freeze the layout and draw the bars queued by `bar`."""
    fig.canvas.draw()
    fig.set_layout_engine("none")
    inv = fig.dpi_scale_trans.inverted()
    for ax, lo, hi, pos, thick, color, horizontal, hatch, round_end in fig._k6g_bars:
        t = thick / 72 / 2
        if horizontal:
            (x0, yc), (x1, _) = inv.transform(ax.transData.transform([(lo, pos), (hi, pos)]))
            y0, y1 = yc - t, yc + t
        else:
            (xc, y0), (_, y1) = inv.transform(ax.transData.transform([(pos, lo), (pos, hi)]))
            x0, x1 = xc - t, xc + t
        # square ends and a black outline (the look of figures4papers' bars). The fill is drawn first, with its hatch
        # in white, and the outline over it: a patch draws its hatch in its edge colour, which here must stay white.
        path = _bar_path(x0, y0, x1, y1, 0, horizontal)
        fig.add_artist(PathPatch(path, transform=fig.dpi_scale_trans, facecolor=color, edgecolor="white", linewidth=0, hatch=hatch, zorder=3))
        fig.add_artist(PathPatch(path, transform=fig.dpi_scale_trans, facecolor="none", edgecolor=INK, linewidth=0.6, zorder=3.1))
    fig._k6g_bars = []


def save(fig, name):
    finish(fig)
    # Any title, axis label, legend entry or note that reaches beyond the edge of the figure is cut off in the exported
    # file, and nothing else would notice: measured here, on the layout as drawn, before the files are written. (Tick
    # labels are left out: those outside the axis limits exist but are not drawn.)
    texts = [t for t in fig.findobj(matplotlib.text.Text) if t.get_visible() and t.get_text().strip()]
    ticks = set()
    for ax in fig.axes:
        ticks.update(id(t) for t in ax.get_xticklabels(which="both") + ax.get_yticklabels(which="both"))
        ticks.update((id(ax.xaxis.get_offset_text()), id(ax.yaxis.get_offset_text())))
    renderer = fig.canvas.get_renderer()
    W, H = fig.bbox.width, fig.bbox.height
    cut, boxes = [], []
    for t in texts:
        if id(t) in ticks:
            continue
        b = t.get_window_extent(renderer)
        boxes.append((" ".join(t.get_text().split())[:40], b))
        if b.x0 < -1 or b.y0 < -1 or b.x1 > W + 1 or b.y1 > H + 1:
            cut.append(" ".join(t.get_text().split())[:60])
    # ... and two of them on top of each other (a panel title running into the next panel's, a note over a label) is
    # just as unreadable: any two text boxes that share more than 2 x 2 pixels of the 100 dpi layout are reported
    for i, (ta, a) in enumerate(boxes):
        for tb, b in boxes[i + 1:]:
            if min(a.x1, b.x1) - max(a.x0, b.x0) > 2 and min(a.y1, b.y1) - max(a.y0, b.y0) > 2:
                cut.append(f"OVERLAP: {ta!r} and {tb!r}")
    for kind, d in OUT.items():
        d.mkdir(parents=True, exist_ok=True)
        fig.savefig(d / f"{name}.{kind}")
    sizes = sorted({round(float(t.get_fontsize()), 2) for t in texts})     # for build.py, which checks them against the PDF
    reg = ROOT / "checks" / "text_sizes.json"
    reg.parent.mkdir(exist_ok=True)
    known = json.loads(reg.read_text()) if reg.exists() else {}
    known[name] = sizes
    reg.write_text(json.dumps(known, indent=1, sort_keys=True))
    reg = ROOT / "checks" / "text_cut_off.json"
    known = json.loads(reg.read_text()) if reg.exists() else {}
    known[name] = cut
    reg.write_text(json.dumps(known, indent=1, sort_keys=True))
    if cut:
        print(f"       {name}: text reaches beyond the figure, or two texts overlap: {cut}")
    plt.close(fig)


def table(name, header, rows):
    TABLES.mkdir(parents=True, exist_ok=True)
    with open(TABLES / f"{name}.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


def pct(sorted_values, p):
    """Percentile p (0..100) of an already sorted list, linear interpolation."""
    if not sorted_values:
        return None
    k = (len(sorted_values) - 1) * p / 100
    lo = int(k)
    hi = min(lo + 1, len(sorted_values) - 1)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo)


def ecdf(values):
    v = sorted(values)
    n = len(v)
    return v, [(i + 1) / n * 100 for i in range(n)]
