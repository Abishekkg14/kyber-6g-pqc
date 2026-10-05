#!/usr/bin/env python3
"""figlib: describe a figure in Python, get an editable draw.io file and a list of layout problems.

Look (fourth version: the schematics of github.com/ChenLiu-1996/figures4papers, i.e. its ImmunoStruct, RNAGenScape,
VIGIL and Dispersion architecture figures, which were looked at one by one):
    white page; a component is a rounded box with a PASTEL fill and a thin DARK outline, its words in black;
    the pastel says what family it belongs to, and the bold title or pictogram beside it wears the strong colour
    of the same family:
        green   the UAV node                    cream   the ground station
        blue    public-key / post-quantum step  violet  symmetric step (AES-256-GCM, HKDF, SHA-256)
        red     the adversary                   grey    a neutral step, plain data
    thin black arrows carry data, short BLOCK ARROWS (pastel, dark outline) lead from one stage to the next,
    dashed blue lines are key material, dotted lines commands; groups stand in a dashed dark frame; parts of a
    figure are marked with a bold letter. Arial (that repository's portable stand-in for Helvetica). Pictures and
    pictograms still carry the meaning and words stay short. The plots (paper_plots/scripts/plotlib.py) use the
    same font and the same strong colours.

Units. Everything is in draw.io units ("px"). The build step scales the exported PDF so that one unit is exactly
0.75 pt, i.e. the design width W1 / W2 comes out as exactly 90 mm / 190 mm:
    12 px = 9 pt (labels)   10.67 px = 8 pt (secondary)   9.33 px = 7 pt (notes)   8.67 px = 6.5 pt (indices, minimum)
    1.33 px = 1 pt (box borders, connectors)   1.0 px = 0.75 pt (cells, block arrows)
"""
import base64
import html as _html
import re
from pathlib import Path

from PIL import ImageFont

ROOT = Path(__file__).resolve().parent.parent
MM = 96 / 25.4
W1, W2 = 90 * MM, 190 * MM                      # 340.16 and 718.11 units

FONT = "Arial"
INK, WHITE, GREY = "#1A1A1A", "#FFFFFF", "#767676"
LINE = "#272727"                                           # outlines of components, thin arrows (figures4papers' darkest grey)
# The families: a pastel fill and the strong colour that goes with it (titles, pictograms, key lines). The strong
# colours are figures4papers' blue_main, violet and red_strong, its green_1 and red_1 are two of the fills.
UAV_F, UAV_C = "#DDF3DE", "#2E7D4F"                        # green: the UAV node
GCS_F, GCS_C = "#FCEFC8", "#8A6A12"                        # cream: the ground station
KEY_F, ACC_KEY = "#D6E4F5", "#0F4D92"                      # blue: public-key / post-quantum step, key material
SYM_F, ACC_SYM = "#E9DDEF", "#9A4D8E"                      # violet: symmetric step
THR_F, THR_C = "#F6CFCB", "#B64342"                        # red: the adversary
PALE, NEUTRAL = "#EFEFEF", "#DDDDDD"                       # grey: a neutral step or plain data / a block arrow
MARK = "#FDFDFD"                                           # registration marks, see Fig.xml
TINT = {UAV_C: UAV_F, GCS_C: GCS_F, ACC_KEY: KEY_F, ACC_SYM: SYM_F, THR_C: THR_F, GREY: PALE, LINE: PALE, INK: PALE}
PALETTE = {INK, WHITE, GREY, LINE, UAV_F, UAV_C, GCS_F, GCS_C, KEY_F, ACC_KEY, SYM_F, ACC_SYM, THR_F, THR_C, PALE, NEUTRAL, MARK, "none"}
# the colour a pictogram wears unless the figure says otherwise
GLYPH_COLOUR = {"uav": UAV_C, "laptop": GCS_C, "monitor": GCS_C, "operator": GCS_C, "adversary": THR_C,
                "key": ACC_KEY, "keys": ACC_KEY, "file_key": ACC_KEY, "lock": ACC_SYM, "unlock": ACC_SYM}

FS_L, FS_M, FS_S, FS_MIN = 12.0, 10.67, 9.33, 8.67         # 9, 8, 7 and 6.5 pt
SW_BOX, SW_LINE, SW_CELL = 1.33, 1.33, 1.0                 # 1 pt, 1 pt and 0.75 pt
HEAD_L, HEAD_W, HEAD_OVERLAP = 5.33, 4.0, 0.6              # arrowhead: 4 pt long, 3 pt wide (a triangle shape, measured 3.97 x 3.00 pt)
FAT_H, FAT_MIN, FAT_MAX, FAT_GAP = 9.0, 12.0, 48.0, 1.0    # block arrow: thickness, shortest and longest straight run that
                                                           # becomes one by itself, gap it leaves at both ends
CORNER = 14                                                # rounding of connector corners (draw.io arcSize)
MARGIN = 2.0                                               # nothing may be drawn closer than this to the edge of the design
                                                           # (draw.io's cropped export cuts off the outermost unit on the left)

_FONT_DIRS = ["/usr/local/share/fonts/windows-core", "/mnt/c/Windows/Fonts", "/usr/share/fonts/truetype/liberation"]
_FONT_FILES = {(False, False): ["arial.ttf", "LiberationSans-Regular.ttf"], (True, False): ["arialbd.ttf", "LiberationSans-Bold.ttf"],
               (False, True): ["ariali.ttf", "LiberationSans-Italic.ttf"], (True, True): ["arialbi.ttf", "LiberationSans-BoldItalic.ttf"]}
_fonts = {}


def _font(bold, italic):
    key = (bool(bold), bool(italic))
    if key not in _fonts:
        for d in _FONT_DIRS:
            for f in _FONT_FILES[key]:
                if (Path(d) / f).exists():
                    _fonts[key] = ImageFont.truetype(str(Path(d) / f), 200)
                    return _fonts[key]
        raise RuntimeError("no Arial / Liberation Sans font found for text measurement")
    return _fonts[key]


_TAG = re.compile(r"<(/?)(b|i|sub|sup|br|span|font)\b([^>]*)>", re.I)


def text_lines(html, fs, bold=False, italic=False):
    """Split label HTML into lines of (text, size, bold, italic) runs. Only the tags figlib itself writes are known."""
    lines, stack, pos = [[]], [(fs, bold, italic)], 0
    for m in _TAG.finditer(html):
        if m.start() > pos:
            lines[-1].append((_html.unescape(html[pos:m.start()]), *stack[-1]))
        pos = m.end()
        close, tag, attrs = m.group(1), m.group(2).lower(), m.group(3)
        if tag == "br":
            lines.append([])
            continue
        if close:
            if len(stack) > 1:
                stack.pop()
            continue
        s, b, i = stack[-1]
        b, i = b or tag == "b", i or tag == "i"
        if tag in ("sub", "sup"):
            s = 0.83 * s
        size = re.search(r"font-size:\s*([\d.]+)px", attrs)
        if size:
            s = float(size.group(1))
        stack.append((s, b, i))
    if pos < len(html):
        lines[-1].append((_html.unescape(html[pos:]), *stack[-1]))
    return lines


def measure(html, fs, bold=False, italic=False):
    """(width, height, smallest font size) of a label as the browser lays it out (line height 1.2)."""
    lines = text_lines(html, fs, bold, italic)
    width = max((sum(_font(b, i).getlength(t) * s / 200 for t, s, b, i in line) for line in lines), default=0)
    sizes = [s for line in lines for t, s, b, i in line if t.strip()]
    return width, 1.2 * fs * len(lines), min(sizes, default=fs)


def var(name, sub=None, sup=None):
    """An italic variable with optional upright subscript / superscript (never below 6.5 pt)."""
    out = f"<i>{name}</i>"
    if sub is not None:
        out += f'<sub style="font-size:{FS_MIN}px;line-height:0">{sub}</sub>'
    if sup is not None:
        out += f'<sup style="font-size:{FS_MIN}px;line-height:0">{sup}</sup>'
    return out


def small(text, fs=FS_S):
    return f'<span style="font-size:{fs}px">{text}</span>'


def col(text, colour):
    return f'<span style="color:{colour}">{text}</span>'


def _plain(html):
    return re.sub(r"\s+", " ", _html.unescape(re.sub("<[^>]+>", " ", html))).strip()


def _esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _n(v):
    return f"{round(v, 2):g}"


class Fig:
    def __init__(self, name, width, height, caption=""):
        self.name, self.W, self.H, self.caption = name, width, height, caption
        self.shapes, self.ops, self.pics, self.texts, self.lines, self.heads = [], [], [], [], [], []
        self.blocks = []                 # block arrows (see _settle)
        self.labels = []                 # (x0, y0, x1, y1, owner id, text) of every piece of text
        self.issues = []
        self._n = 0
        self._settled = False

    def _id(self, prefix):
        self._n += 1
        return f"{prefix}{self._n}"

    def _font_ok(self, smallest, html):
        if smallest < FS_MIN - 0.01:
            self.issues.append(f"text below 6.5 pt ({smallest * 0.75:.1f} pt): {_plain(html)!r}")

    def _labelled(self, kind, x, y, w, h, value, style, fs, bold=False, italic=False, pad=4):
        sid = self._id(kind)
        self.shapes.append(dict(id=sid, x=x, y=y, w=w, h=h, value=value, style=style, shape="rect"))
        if value:
            tw, th, smallest = measure(value, fs, bold, italic)
            if tw > w - pad:
                self.issues.append(f"label wider than its {kind} by {tw - (w - pad):.1f} px: {_plain(value)!r}")
            if th > h + 1:
                self.issues.append(f"label taller than its {kind}: {_plain(value)!r}")
            self._font_ok(smallest, value)
            self.labels.append((x + w / 2 - tw / 2, y + h / 2 - th / 2, x + w / 2 + tw / 2, y + h / 2 + th / 2, sid, value))
        return sid

    # ------------------------------------------------------------------ shapes
    def box(self, x, y, w, h, label="", fs=FS_M, bold=False, italic=False, fill=None, stroke=LINE, dashed=False, arc=10, sw=SW_BOX):
        """A rounded box with a dark outline. With a label it is a component (a step): pastel fill, grey unless
        `fill` names a family's tint. Without one it is a frame around other things: white unless `fill` is given,
        dashed for a loose group."""
        if fill is None:
            fill = PALE if label else WHITE
        style = (f"rounded=1;arcSize={arc};absoluteArcSize=1;html=1;fillColor={fill};strokeColor={stroke};strokeWidth={sw};"
                 f"fontFamily={FONT};fontSize={fs};fontColor={INK};fontStyle={(1 if bold else 0) + (2 if italic else 0)};"
                 "align=center;verticalAlign=middle;spacing=0;" + ("dashed=1;dashPattern=4 3;" if dashed else ""))
        return self._labelled("box", x, y, w, h, label, style, fs, bold, italic)

    def pill(self, x, y, w, h, label, colour=ACC_KEY, fs=FS_M):
        """An algorithm: a well-rounded box in the pastel of its family, dark outline, bold black name.
        `colour` names the family by its strong colour: ACC_KEY = public-key / post-quantum, ACC_SYM = symmetric."""
        style = (f"rounded=1;arcSize=36;html=1;fillColor={TINT.get(colour, PALE)};strokeColor={LINE};strokeWidth={SW_BOX};"
                 f"fontFamily={FONT};fontSize={fs};fontColor={INK};fontStyle=1;align=center;verticalAlign=middle;spacing=0;")
        return self._labelled("pill", x, y, w, h, label, style, fs, bold=True, pad=8)

    def cell(self, x, y, w, h, label="", fs=FS_S, fill=WHITE, stroke=LINE, bold=False, italic=False, colour=INK, sw=SW_CELL):
        """A small square-cornered box: one field, one chunk, one bit."""
        style = (f"rounded=0;html=1;fillColor={fill};strokeColor={stroke};strokeWidth={sw};fontFamily={FONT};fontSize={fs};"
                 f"fontColor={colour};fontStyle={(1 if bold else 0) + (2 if italic else 0)};align=center;verticalAlign=middle;spacing=0;")
        return self._labelled("cell", x, y, w, h, label, style, fs, bold, italic, pad=2)

    def op(self, kind, cx, cy, d=15, colour=INK):
        """Circular operator: 'xor' (circle with a plus), 'slice' (circle with a bar: split into chunks),
        'concat' (circle with ||), 'dot' (a small junction)."""
        oid = self._id("op")
        base = f"html=1;fillColor={WHITE};strokeColor={colour};strokeWidth={SW_BOX};perimeter=ellipsePerimeter;"
        value = ""
        if kind == "xor":
            style = "shape=orEllipse;" + base
        elif kind == "slice":
            style = "shape=lineEllipse;line=vertical;" + base
        elif kind == "concat":
            style = "ellipse;" + base + f"fontFamily={FONT};fontSize={FS_MIN};fontColor={colour};fontStyle=1;spacing=0;spacingBottom=1;"
            value = "||"
        elif kind == "dot":
            style = f"ellipse;html=1;fillColor={colour};strokeColor=none;perimeter=ellipsePerimeter;"
        else:
            raise ValueError(kind)
        self.ops.append(dict(id=oid, x=cx - d / 2, y=cy - d / 2, w=d, h=d, value=value, style=style, shape="ellipse"))
        return oid

    def tag(self, n, cx, cy, d=13, colour=ACC_KEY):
        """A step number in a small pastel disc."""
        tid = self._id("tag")
        style = (f"ellipse;html=1;fillColor={TINT.get(colour, PALE)};strokeColor={LINE};strokeWidth={SW_CELL};fontFamily={FONT};fontSize={FS_MIN};"
                 f"fontColor={INK};fontStyle=1;spacing=0;")
        self.ops.append(dict(id=tid, x=cx - d / 2, y=cy - d / 2, w=d, h=d, value=str(n), style=style, shape="ellipse"))
        return tid

    # ---------------------------------------------------------------- pictures
    def _image(self, kind, path, x, y, w, h, extra=""):
        data = Path(path).read_bytes()
        mime = {".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg"}[Path(path).suffix]
        pid = self._id(kind)
        self.pics.append(dict(id=pid, x=x, y=y, w=w, h=h, value="", raster=mime != "image/svg+xml",
                              style=f"shape=image;html=1;imageAspect=0;image=data:{mime},{base64.b64encode(data).decode()};{extra}"))
        return pid

    def glyph(self, role, x, y, size=28, colour=None):
        """A solid pictogram from assets/pictograms (Material Design Icons), in the strong colour of its family
        (GLYPH_COLOUR) unless a colour is given."""
        colour = colour or GLYPH_COLOUR.get(role, INK)
        src = ROOT / "assets" / "pictograms" / f"{role}.svg"
        if colour != INK:
            tmp = src.read_text().replace('fill="#1A1A1A"', f'fill="{colour}"')
            pid = self._id("glyph")
            self.pics.append(dict(id=pid, x=x, y=y, w=size, h=size, value="", raster=False,
                                  style=f"shape=image;html=1;imageAspect=0;image=data:image/svg+xml,{base64.b64encode(tmp.encode()).decode()};"))
            return pid
        return self._image("glyph", src, x, y, size, size)

    def pic(self, name, x, y, w, h, border=GREY):
        """A picture from assets/illustrations (photo crop, ciphertext noise, lattice, curve)."""
        return self._image("pic", ROOT / "assets" / "illustrations" / name, x, y, w, h,
                           f"imageBorder={border};strokeWidth=0.8;" if border else "")

    # -------------------------------------------------------------------- text
    def text(self, x, y, w, h, html, fs=FS_M, align="center", valign="middle", colour=INK, bold=False, italic=False, rotate=False):
        tid = self._id("txt")
        style = (f"text;html=1;strokeColor=none;fillColor=none;align={align};verticalAlign={valign};spacing=0;"
                 f"fontFamily={FONT};fontSize={fs};fontColor={colour};fontStyle={(1 if bold else 0) + (2 if italic else 0)};"
                 + ("horizontal=0;" if rotate else ""))
        self.texts.append(dict(id=tid, x=x, y=y, w=w, h=h, value=html, style=style))
        tw, th, smallest = measure(html, fs, bold, italic)
        self._font_ok(smallest, html)
        if rotate:                                   # reads bottom to top, centred in the cell
            x0, y0, x1, y1 = x + w / 2 - th / 2, y + h / 2 - tw / 2, x + w / 2 + th / 2, y + h / 2 + tw / 2
        else:
            x0 = {"left": x, "center": x + w / 2 - tw / 2, "right": x + w - tw}[align]
            y0 = {"top": y, "middle": y + h / 2 - th / 2, "bottom": y + h - th}[valign]
            x1, y1 = x0 + tw, y0 + th
        self.labels.append((x0, y0, x1, y1, tid, html))
        if x0 < -0.5 or x1 > self.W + 0.5 or y0 < -0.5 or y1 > self.H + 0.5:
            self.issues.append(f"text outside the figure: {_plain(html)!r}")
        return tid

    # --------------------------------------------------------------- connectors
    def edge(self, pts, kind="flow", arrow="end", dashed=None, colour=None, width=SW_LINE, attach=True, jump=True, curved=True,
             fat=None, tone=None):
        """A connector through the given points (right angles, corners rounded).
        kind: flow (dark, solid) | key (blue, dashed: key material) | cmd (dark, dotted: commands) | threat (red, dashed) |
        plain (ink) | rule (grey, thin, no head). The line styles keep data, keys and commands apart in greyscale.
        fat: a straight data arrow from one stage to the next is drawn as a block arrow (True: always, False: never,
        None: if it is short and nothing stands in its way, decided in _settle once everything is placed);
        tone: the strong colour of the family whose pastel the block arrow wears (grey if none)."""
        pts = [(round(float(x), 2), round(float(y), 2)) for x, y in pts]
        for (x0, y0), (x1, y1) in zip(pts, pts[1:]):
            if abs(x0 - x1) > 0.005 and abs(y0 - y1) > 0.005:
                self.issues.append(f"connector segment is not orthogonal: {(x0, y0)} -> {(x1, y1)}")
        c = colour or {"flow": LINE, "key": ACC_KEY, "cmd": LINE, "threat": THR_C, "plain": INK, "rule": GREY}[kind]
        dashed = (kind in ("key", "cmd", "threat")) if dashed is None else dashed
        if kind == "rule":
            arrow, width = "none", (width if width != SW_LINE else 1.0)
        style = (f"edgeStyle=orthogonalEdgeStyle;rounded={1 if curved else 0};arcSize={CORNER};html=1;strokeColor={c};strokeWidth={width};"
                 "endArrow=none;startArrow=none;" + ("jumpStyle=arc;jumpSize=6;" if jump and kind != "rule" else "")
                 + (f"dashed=1;dashPattern={'1 2' if kind == 'cmd' else '4 3'};" if dashed else ""))
        src = self._terminal(pts[0]) if attach else None
        dst = self._terminal(pts[-1]) if attach else None
        draw = list(pts)                 # the line as drawn: it stops inside the base of each arrowhead
        n_heads = len(self.heads)
        if arrow in ("end", "both"):
            draw[-1] = self._head(pts[-1], pts[-2], c, dst)
        if arrow == "both":
            draw[0] = self._head(pts[0], pts[1], c, src)
        may_be_fat = fat is not False and kind == "flow" and arrow == "end" and len(pts) == 2 and colour is None and not dashed
        if fat and not may_be_fat:
            self.issues.append(f"connector {pts} cannot be a block arrow (a straight data arrow with one head only)")
        self.lines.append(dict(id=self._id("edge"), pts=pts, draw=draw, style=style, src=src, dst=dst, kind=kind, arrow=arrow, width=width,
                               fat=("force" if fat else "auto") if may_be_fat else None, tone=tone, heads=self.heads[n_heads:]))

    def _settle(self):
        """Decide, once everything is placed, which straight data arrows become block arrows: those asked for, and
        every short one that leads from one thing to the next with nothing in its way (a label on the line, another
        connector, a small operator circle at either end keep the thin arrow). A block arrow replaces the line and
        its head."""
        if self._settled:
            return
        self._settled = True
        for e in list(self.lines):
            if not e.get("fat"):
                continue
            (xa, ya), (xb, yb) = e["pts"]
            horizontal = abs(ya - yb) < 0.005
            length = abs(xb - xa) + abs(yb - ya)
            if horizontal:
                x, y, w, h = min(xa, xb) + FAT_GAP, ya - FAT_H / 2, length - 2 * FAT_GAP, FAT_H
                direction = "east" if xb > xa else "west"
            else:
                x, y, w, h = xa - FAT_H / 2, min(ya, yb) + FAT_GAP, FAT_H, length - 2 * FAT_GAP
                direction = "south" if yb > ya else "north"
            if e["fat"] == "auto":
                ends = [t for t in (e["src"], e["dst"]) if t]
                if not FAT_MIN <= length <= FAT_MAX or any(t in self.ops for t in ends):
                    continue
                solids = [s for s in self.shapes + self.ops + self.pics + self.blocks
                          if not any(s is t for t in ends) and not (s["id"].startswith("box") and not s["value"])]
                # (half a unit of room is asked for, not the whole gap: the arrow ends exactly one gap away from the
                # things it joins, and their coordinates carry rounding noise)
                if any(x < s["x"] + s["w"] + 0.5 and x + w > s["x"] - 0.5 and y < s["y"] + s["h"] + 0.5 and y + h > s["y"] - 0.5 for s in solids):
                    continue
                if any(x < lx1 + 0.5 and x + w > lx0 - 0.5 and y < ly1 and y + h > ly0 for (lx0, ly0, lx1, ly1, _, _) in self.labels):
                    continue
                crossed = False
                for o in self.lines:
                    if o is e:
                        continue
                    for (pa, qa), (pb, qb) in zip(o["pts"], o["pts"][1:]):
                        if x - 0.5 < max(pa, pb) and x + w + 0.5 > min(pa, pb) and y - 0.5 < max(qa, qb) and y + h + 0.5 > min(qa, qb):
                            crossed = True
                if crossed:
                    continue
            if w < 9:
                self.issues.append(f"block arrow {e['pts']} is too short")
            along = w if horizontal else h
            style = (f"shape=singleArrow;direction={direction};arrowWidth=0.46;arrowSize={min(0.55, 6.0 / along):.3f};html=1;"
                     f"fillColor={TINT.get(e['tone'], NEUTRAL) if e['tone'] else NEUTRAL};strokeColor={LINE};strokeWidth={SW_CELL};"
                     "perimeter=none;connectable=0;")
            self.blocks.append(dict(id=self._id("fat"), x=x, y=y, w=w, h=h, value="", style=style, shape="arrow"))
            self.lines.remove(e)
            for hd in e["heads"]:
                self.heads.remove(hd)

    def _head(self, tip, prev, c, owner):
        """A 4 pt x 3 pt triangle with its tip at `tip`, pointing away from `prev`. Returns where the line has to end.
        The head belongs to the shape it points at, so it moves with that shape in the editor."""
        dx, dy = tip[0] - prev[0], tip[1] - prev[1]
        if abs(dx) + abs(dy) < HEAD_L + 1.5:
            self.issues.append(f"connector end {prev} -> {tip} is too short for an arrowhead")
        ux, uy = (dx > 0.005) - (dx < -0.005), (dy > 0.005) - (dy < -0.005)
        if ux:
            x, y, w, h = (tip[0] - HEAD_L if ux > 0 else tip[0]), tip[1] - HEAD_W / 2, HEAD_L, HEAD_W
        else:
            x, y, w, h = tip[0] - HEAD_W / 2, (tip[1] - HEAD_L if uy > 0 else tip[1]), HEAD_W, HEAD_L
        d = {(1, 0): "east", (-1, 0): "west", (0, 1): "south", (0, -1): "north"}.get((ux, uy), "east")
        self.heads.append(dict(id=self._id("head"), x=x, y=y, w=w, h=h, value="", owner=owner,
                               style=f"shape=triangle;direction={d};html=1;fillColor={c};strokeColor=none;perimeter=none;connectable=0;"))
        back = HEAD_L - HEAD_OVERLAP
        return (round(tip[0] - ux * back, 2), round(tip[1] - uy * back, 2))

    def _terminal(self, p):
        for b in self.shapes + self.ops + [q for q in self.pics if q["id"].startswith("pic")]:
            x0, y0, x1, y1 = b["x"], b["y"], b["x"] + b["w"], b["y"] + b["h"]
            on_v = (abs(p[0] - x0) < 0.02 or abs(p[0] - x1) < 0.02) and y0 - 0.02 <= p[1] <= y1 + 0.02
            on_h = (abs(p[1] - y0) < 0.02 or abs(p[1] - y1) < 0.02) and x0 - 0.02 <= p[0] <= x1 + 0.02
            if on_v or on_h:
                return b
        return None

    def legend(self, x, y, items, gap=14, fs=FS_S):
        """A one-line legend: items are (kind, text)."""
        for kind, label in items:
            self.edge([(x, y), (x + 24, y)], kind=kind, attach=False, fat=False)
            w = measure(label, fs)[0]
            self.text(x + 29, y - 7, w + 2, 14, label, fs=fs, align="left")
            x += 29 + w + gap
        return x

    # -------------------------------------------------------------------- checks
    def panel(self, letter, x, y, title="", w=None):
        """The mark of one part of a figure: a bold letter, as in the schematics this look follows, and its title."""
        html = f'<b><span style="font-size:{FS_L}px">{letter}</span></b>' + (f"&nbsp;&nbsp;{title}" if title else "")
        return self.text(x, y, w or measure(html, FS_M)[0] + 2, 15, html, fs=FS_M, align="left")

    def check(self):
        self._settle()
        issues = list(self.issues)
        solids = self.shapes + self.ops + self.pics + self.blocks
        lo, hi = MARGIN + 0.6, self.W - MARGIN - 0.6               # the registration marks must stay the outermost ink
        for c in solids:
            if c["x"] < lo or c["y"] < MARGIN or c["x"] + c["w"] > hi or c["y"] + c["h"] > self.H:
                issues.append(f"{c['id']} ({_plain(c['value'])[:20]!r}) is closer than {MARGIN} to the edge of the figure")
        for (x0, y0, x1, y1, owner, what) in self.labels:
            if x0 < lo or x1 > hi or y0 < MARGIN - 1:
                issues.append(f"text {_plain(what)[:30]!r} is closer than {MARGIN} to the edge of the figure")
        for e in self.lines:
            ends = {id(t) for t in (e["src"], e["dst"]) if t}
            for (xa, ya), (xb, yb) in zip(e["pts"], e["pts"][1:]):
                sx0, sx1, sy0, sy1 = min(xa, xb), max(xa, xb), min(ya, yb), max(ya, yb)
                if not (lo <= sx0 - 1 and sx1 + 1 <= hi and MARGIN <= sy0 and sy1 <= self.H):
                    issues.append(f"connector {e['id']} is too close to the edge of the figure")
                for (lx0, ly0, lx1, ly1, owner, what) in self.labels:
                    if sx0 < lx1 + 0.8 and sx1 > lx0 - 0.8 and sy0 < ly1 - 1.0 and sy1 > ly0 + 1.0:
                        issues.append(f"connector {e['id']} runs over text {_plain(what)[:40]!r}")
                for b in solids:
                    if id(b) in ends or (b["id"].startswith("box") and not b["value"]):
                        continue                                # an empty box is a frame around other things
                    if sx0 < b["x"] + b["w"] - 0.5 and sx1 > b["x"] + 0.5 and sy0 < b["y"] + b["h"] - 0.5 and sy1 > b["y"] + 0.5:
                        issues.append(f"connector {e['id']} passes through {b['id']} ({_plain(b['value'])[:30]!r})")
        for i, (ax0, ay0, ax1, ay1, ao, aw) in enumerate(self.labels):
            for (bx0, by0, bx1, by1, bo, bw) in self.labels[i + 1:]:
                if ax0 < bx1 - 0.5 and ax1 > bx0 + 0.5 and ay0 < by1 - 1.5 and ay1 > by0 + 1.5:
                    issues.append(f"texts overlap: {_plain(aw)[:30]!r} and {_plain(bw)[:30]!r}")
            for p in self.pics + self.ops + self.blocks + [s for s in self.shapes if s["id"] != ao and not s["id"].startswith("box")]:
                if p["id"] == ao:
                    continue
                if ax0 < p["x"] + p["w"] - 0.5 and ax1 > p["x"] + 0.5 and ay0 < p["y"] + p["h"] - 1 and ay1 > p["y"] + 1:
                    issues.append(f"text {_plain(aw)[:30]!r} overlaps {p['id']}")
        # A piece of text is inside a box or outside it, never across its outline (with dark outlines this shows at once;
        # it went unnoticed for two lines of figure 12 while the outlines were pale).
        for (x0, y0, x1, y1, owner, what) in self.labels:
            for b in self.shapes:
                if b["id"] == owner or not b["id"].startswith("box"):
                    continue
                bx0, by0, bx1, by1 = b["x"], b["y"], b["x"] + b["w"], b["y"] + b["h"]
                touches = x0 < bx1 and x1 > bx0 and y0 + 1.5 < by1 and y1 - 1.5 > by0
                inside = x0 >= bx0 + 1.5 and x1 <= bx1 - 1.5 and y0 + 1.5 >= by0 and y1 - 1.5 <= by1
                if touches and not inside:
                    issues.append(f"text {_plain(what)[:40]!r} runs across the outline of {b['id']}")
        colours = set(re.findall(r"(?:fillColor|strokeColor|fontColor|imageBorder)=(#[0-9A-Fa-f]{6})",
                                 " ".join(c["style"] for c in self.shapes + self.ops + self.texts + self.lines + self.pics + self.heads + self.blocks)))
        for c in colours - PALETTE:
            issues.append(f"colour outside the palette: {c}")
        return issues

    # ------------------------------------------------------------------ emission
    def _parent(self, c):
        best = None
        for k in self.shapes:
            if k is c or not k["id"].startswith("box") or k["value"]:
                continue                                    # only empty boxes act as containers
            if k["x"] - 0.01 <= c["x"] and k["y"] - 0.01 <= c["y"] and c["x"] + c["w"] <= k["x"] + k["w"] + 0.01 and c["y"] + c["h"] <= k["y"] + k["h"] + 0.01:
                if best is None or k["w"] * k["h"] < best["w"] * best["h"]:
                    best = k
        return best

    def xml(self):
        self._settle()
        out = []
        # Registration marks: two near-white specks, MARGIN inside the left and right edge of the design width. They are
        # the outermost ink of every figure, a known distance apart, which is what lets the build scale the page to
        # exactly 90 / 190 mm although the drawing has no frame. At 0.4 pt and 99 % white they do not print.
        # draw.io's cropped export cuts off whatever lies on the leftmost unit of the diagram bounds, so an invisible
        # "canvas" a little larger than the figure keeps the bounds away from the marks and from the drawing.
        out.append('<mxCell id="canvas" value="" style="rounded=0;fillColor=none;strokeColor=none;connectable=0;pointerEvents=0;" vertex="1" parent="1">'
                   f'<mxGeometry x="-4" y="-4" width="{_n(self.W + 8)}" height="{_n(self.H + 8)}" as="geometry"/></mxCell>')
        marks = [dict(id="mark_l", x=MARGIN, y=self.H / 2, w=0.5, h=0.5), dict(id="mark_r", x=self.W - MARGIN - 0.5, y=self.H / 2, w=0.5, h=0.5)]
        for mk in marks:
            out.append(f'<mxCell id="{mk["id"]}" value="" style="rounded=0;fillColor={MARK};strokeColor=none;connectable=0;" vertex="1" parent="1">'
                       f'<mxGeometry x="{_n(mk["x"])}" y="{_n(mk["y"])}" width="0.5" height="0.5" as="geometry"/></mxCell>')
        for c in self.shapes:
            if c["id"].startswith("box") and not c["value"]:
                c["style"] += "container=1;collapsible=0;recursiveResize=0;"
        for c in self.shapes + self.blocks + self.ops + self.pics + self.texts:
            par = self._parent(c)
            px, py, pid = (par["x"], par["y"], par["id"]) if par else (0, 0, "1")
            out.append(f'<mxCell id="{c["id"]}" value="{_esc(c["value"])}" style="{c["style"]}" vertex="1" parent="{pid}">'
                       f'<mxGeometry x="{_n(c["x"] - px)}" y="{_n(c["y"] - py)}" width="{_n(c["w"])}" height="{_n(c["h"])}" as="geometry"/></mxCell>')
        for hd in self.heads:
            par = hd["owner"] or self._parent(hd)
            px, py, pid = (par["x"], par["y"], par["id"]) if par else (0, 0, "1")
            out.append(f'<mxCell id="{hd["id"]}" value="" style="{hd["style"]}" vertex="1" parent="{pid}">'
                       f'<mxGeometry x="{_n(hd["x"] - px)}" y="{_n(hd["y"] - py)}" width="{_n(hd["w"])}" height="{_n(hd["h"])}" as="geometry"/></mxCell>')
        for e in self.lines:
            pts, style, attrs, ends = e["draw"], e["style"], "", ""
            for which, term, p in (("exit", e["src"], pts[0]), ("entry", e["dst"], pts[-1])):
                role = "source" if which == "exit" else "target"
                if term:
                    attrs += f' {role}="{term["id"]}"'
                    style += f"{which}X=0;{which}Y=0;{which}Dx={_n(p[0] - term['x'])};{which}Dy={_n(p[1] - term['y'])};{which}Perimeter=0;"
                else:
                    ends += f'<mxPoint x="{_n(p[0])}" y="{_n(p[1])}" as="{role}Point"/>'
            way = "".join(f'<mxPoint x="{_n(x)}" y="{_n(y)}"/>' for x, y in pts[1:-1])
            out.append(f'<mxCell id="{e["id"]}" style="{style}" edge="1" parent="1"{attrs}><mxGeometry relative="1" as="geometry">'
                       f'{ends}{"<Array as=" + chr(34) + "points" + chr(34) + ">" + way + "</Array>" if way else ""}</mxGeometry></mxCell>')
        return ('<mxfile host="kyber6g-figlib" type="device"><diagram id="' + self.name + '" name="' + self.name + '">'
                f'<mxGraphModel dx="0" dy="0" grid="0" gridSize="1" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="0" '
                f'pageScale="1" pageWidth="{_n(self.W)}" pageHeight="{_n(self.H)}" math="0" shadow="0">'
                '<root><mxCell id="0"/><mxCell id="1" parent="0"/>' + "".join(out) + "</root></mxGraphModel></diagram></mxfile>\n")

    def save(self, directory=None):
        directory = Path(directory or ROOT / "raw_drawio")
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"{self.name}.drawio"
        path.write_text(self.xml())
        return path
