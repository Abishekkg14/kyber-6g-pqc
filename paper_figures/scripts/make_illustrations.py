#!/usr/bin/env python3
"""Draw the small pictures used inside the figures (all original, nothing third-party except the public-domain
photograph they are cropped from).

  frame.jpg      16:9 crop of the aerial photograph: stands in for one frame of the UAV camera
  cipher.png     that same frame encrypted with AES-256-GCM (a random key), the ciphertext bytes shown as pixels;
                 a real encryption, so the picture is what ciphertext looks like, not a drawing of noise
  lattice.svg    a lattice with a basis and a point close to a lattice point: the picture behind ML-KEM
  curve.svg      an elliptic curve with a chord through two points: the picture behind X25519
  wave.svg       a sound: a synthetic, speech-like signal (bursts of a few tones; made here, no recording)
  wave_cipher.svg  the 16-bit samples of that same signal encrypted with AES-256-GCM (a random key), drawn the same
                 way: a real encryption, so the picture is what sealed audio looks like, not a drawing of noise

and two pictograms that the icon family used elsewhere is not asked for (assets/pictograms/mic.svg, speaker.svg):
solid shapes on the same 24 x 24 grid, built here from circles, sectors and rectangles.

Usage:  python3 scripts/make_illustrations.py      (needs Pillow and the 'cryptography' package)
"""
import math
import os
import struct
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "assets" / "illustrations"
# The pictures' own colours: the blue of the public-key family (figlib.ACC_KEY) and two lighter blues for the lattice
# and the curve, greys for the rest. (ACC_SYM is the grey these pictures were drawn in, not figlib's violet.)
ACC_SYM, ACC_KEY, BLUE, LBLUE, GREY = "#4D4D4D", "#0F4D92", "#3775BA", "#9BBADD", "#767676"


def frame_and_cipher():
    src = Image.open(ROOT / "assets" / "photos" / "aerial_usda_naip.jpg").convert("RGB")
    w, h = src.size
    box = (int(0.234 * w), int(0.406 * h), int(0.953 * w), int(0.406 * h) + int((0.953 - 0.234) * w * 9 / 16))
    frame = src.crop(box).resize((640, 360), Image.LANCZOS)
    frame.save(OUT / "frame.jpg", quality=90)
    small = frame.resize((96, 54), Image.LANCZOS)
    plain = small.tobytes()
    ct = AESGCM(os.urandom(32)).encrypt(b"\x00" * 12, plain, b"illustration")[:len(plain)]      # ciphertext without the tag
    Image.frombytes("RGB", small.size, ct).resize((480, 270), Image.NEAREST).save(OUT / "cipher.png")
    return frame.size


def lattice():
    ox, oy, b1, b2 = 20.0, 66.0, (21.0, -3.0), (7.0, -17.0)
    pts = []
    for i in range(-3, 9):
        for j in range(-3, 7):
            x, y = ox + i * b1[0] + j * b2[0], oy + i * b1[1] + j * b2[1]
            if 5 <= x <= 115 and 5 <= y <= 79:
                pts.append((x, y))
    cell = [(ox, oy), (ox + b1[0], oy + b1[1]), (ox + b1[0] + b2[0], oy + b1[1] + b2[1]), (ox + b2[0], oy + b2[1])]
    tx, ty = ox + 3 * b1[0] + 2 * b2[0], oy + 3 * b1[1] + 2 * b2[1]                   # a lattice point ...
    ex, ey = tx + 6.0, ty + 5.0                                                        # ... and a point near it (the "error")

    def arrow(x0, y0, x1, y1, col):
        a = math.atan2(y1 - y0, x1 - x0)
        hx, hy = x1 - 5 * math.cos(a), y1 - 5 * math.sin(a)
        left = (hx + 2.2 * math.sin(a), hy - 2.2 * math.cos(a))
        right = (hx - 2.2 * math.sin(a), hy + 2.2 * math.cos(a))
        return (f'<line x1="{x0:.1f}" y1="{y0:.1f}" x2="{hx:.1f}" y2="{hy:.1f}" stroke="{col}" stroke-width="1.8"/>'
                f'<polygon points="{x1:.1f},{y1:.1f} {left[0]:.1f},{left[1]:.1f} {right[0]:.1f},{right[1]:.1f}" fill="{col}"/>')

    svg = ['<svg xmlns="http://www.w3.org/2000/svg" width="120" height="84" viewBox="0 0 120 84">',
           '<polygon points="' + " ".join(f"{x:.1f},{y:.1f}" for x, y in cell) + f'" fill="{LBLUE}" fill-opacity="0.45"/>']
    svg += [f'<circle cx="{x:.1f}" cy="{y:.1f}" r="1.7" fill="{ACC_SYM}"/>' for x, y in pts]
    svg += [arrow(ox, oy, ox + b1[0], oy + b1[1], ACC_KEY), arrow(ox, oy, ox + b2[0], oy + b2[1], ACC_KEY),
            f'<line x1="{tx:.1f}" y1="{ty:.1f}" x2="{ex:.1f}" y2="{ey:.1f}" stroke="{BLUE}" stroke-width="1" stroke-dasharray="2 1.5"/>',
            f'<circle cx="{ex:.1f}" cy="{ey:.1f}" r="2.6" fill="#FFFFFF" stroke="{BLUE}" stroke-width="1.4"/>', "</svg>"]
    (OUT / "lattice.svg").write_text("".join(svg) + "\n")


def curve():
    f = lambda x: x ** 3 - 2 * x + 2
    X = lambda x: 34 + (x + 1.8) * 19.0
    Y = lambda y: 42 - y * 11.0
    lo, hi = -1.7693, 2.25
    xs = [lo + (hi - lo) * (k / 120) ** 1.6 for k in range(121)]                        # denser near the left tip
    upper = [(X(x), Y(math.sqrt(max(f(x), 0)))) for x in xs]
    lower = [(X(x), Y(-math.sqrt(max(f(x), 0)))) for x in xs]
    path = "M " + " L ".join(f"{x:.1f} {y:.1f}" for x, y in reversed(upper)) + " L " + " L ".join(f"{x:.1f} {y:.1f}" for x, y in lower)
    P, Q = (-1.6, math.sqrt(f(-1.6))), (0.0, math.sqrt(f(0.0)))
    m = (Q[1] - P[1]) / (Q[0] - P[0])
    x3 = m * m - P[0] - Q[0]
    y3 = P[1] + m * (x3 - P[0])
    line = lambda x: P[1] + m * (x - P[0])
    svg = ['<svg xmlns="http://www.w3.org/2000/svg" width="120" height="84" viewBox="0 0 120 84">',
           f'<line x1="6" y1="{Y(0):.1f}" x2="114" y2="{Y(0):.1f}" stroke="{GREY}" stroke-width="0.7"/>',
           f'<line x1="{X(0):.1f}" y1="4" x2="{X(0):.1f}" y2="80" stroke="{GREY}" stroke-width="0.7"/>',
           f'<path d="{path}" fill="none" stroke="{ACC_SYM}" stroke-width="1.8" stroke-linejoin="round"/>',
           f'<line x1="{X(-1.75):.1f}" y1="{Y(line(-1.75)):.1f}" x2="{X(2.2):.1f}" y2="{Y(line(2.2)):.1f}" stroke="{ACC_KEY}" stroke-width="1.1"/>',
           f'<line x1="{X(x3):.1f}" y1="{Y(y3):.1f}" x2="{X(x3):.1f}" y2="{Y(-y3):.1f}" stroke="{ACC_KEY}" stroke-width="1" stroke-dasharray="2 1.5"/>']
    svg += [f'<circle cx="{X(x):.1f}" cy="{Y(y):.1f}" r="2.3" fill="{BLUE}"/>' for x, y in (P, Q)]
    svg += [f'<circle cx="{X(x3):.1f}" cy="{Y(y3):.1f}" r="1.9" fill="#FFFFFF" stroke="{BLUE}" stroke-width="1.2"/>',
            f'<circle cx="{X(x3):.1f}" cy="{Y(-y3):.1f}" r="2.6" fill="{ACC_KEY}"/>', "</svg>"]
    (OUT / "curve.svg").write_text("".join(svg) + "\n")


def waves():
    """A speech-like signal and its ciphertext, each as one column per unit of width (lowest to highest sample)."""
    n, cols, w, h = 6000, 120, 120.0, 40.0
    bursts = [(0.10, 0.045, 0.75, 31), (0.24, 0.03, 0.5, 47), (0.40, 0.06, 0.95, 23), (0.57, 0.025, 0.4, 59), (0.70, 0.05, 0.8, 37), (0.88, 0.04, 0.6, 29)]
    plain = []
    for k in range(n):
        t = k / n
        env = sum(a * math.exp(-((t - c) / s) ** 2) for c, s, a, _ in bursts)
        tone = sum(math.sin(2 * math.pi * f * t * (1 + 0.15 * j)) / (1 + j) for j, (_, _, _, f) in enumerate(bursts[:3]))
        plain.append(max(-32767, min(32767, int(15000 * env * tone))))
    raw = struct.pack(f"<{n}h", *plain)
    ct = AESGCM(os.urandom(32)).encrypt(b"\x00" * 12, raw, b"illustration")[:len(raw)]              # ciphertext without the tag
    cipher = struct.unpack(f"<{n}h", ct)
    for name, samples in (("wave.svg", plain), ("wave_cipher.svg", cipher)):
        per, d = n // cols, []
        for c in range(cols):
            part = samples[c * per:(c + 1) * per]
            lo, hi = min(part) / 32768, max(part) / 32768
            y0, y1 = h / 2 - hi * (h / 2 - 1), h / 2 - lo * (h / 2 - 1)
            if y1 - y0 < 0.5:
                y0, y1 = h / 2 - 0.25, h / 2 + 0.25
            d.append(f"M{c * w / cols + 0.5:.1f} {y0:.1f}V{y1:.1f}")
        (OUT / name).write_text(f'<svg xmlns="http://www.w3.org/2000/svg" width="{w:g}" height="{h:g}" viewBox="0 0 {w:g} {h:g}">'
                                f'<path d="{"".join(d)}" fill="none" stroke="{ACC_SYM}" stroke-width="0.7"/></svg>\n')


def pictograms():
    """mic.svg and speaker.svg: solid ink shapes on a 24 x 24 grid, from sectors and rectangles (drawn for this paper)."""
    INK = "#1A1A1A"

    def sector(cx, cy, r1, r2, a0, a1):
        """The part of a ring between two radii and two angles (degrees, clockwise from the positive x axis, y down)."""
        p = lambda r, a: (cx + r * math.cos(math.radians(a)), cy + r * math.sin(math.radians(a)))
        (ax, ay), (bx, by), (ex, ey), (fx, fy) = p(r1, a0), p(r1, a1), p(r2, a1), p(r2, a0)
        big = 1 if abs(a1 - a0) > 180 else 0
        return (f"M{ax:.2f} {ay:.2f}A{r1:g} {r1:g} 0 {big} 1 {bx:.2f} {by:.2f}L{ex:.2f} {ey:.2f}A{r2:g} {r2:g} 0 {big} 0 {fx:.2f} {fy:.2f}Z")

    def rect(x, y, w, h, r=0.0):
        if r <= 0:
            return f"M{x:g} {y:g}h{w:g}v{h:g}h{-w:g}Z"
        return (f"M{x + r:g} {y:g}h{w - 2 * r:g}a{r:g} {r:g} 0 0 1 {r:g} {r:g}v{h - 2 * r:g}a{r:g} {r:g} 0 0 1 {-r:g} {r:g}h{-(w - 2 * r):g}"
                f"a{r:g} {r:g} 0 0 1 {-r:g} {-r:g}v{-(h - 2 * r):g}a{r:g} {r:g} 0 0 1 {r:g} {-r:g}Z")

    def write(name, paths):
        (ROOT / "assets" / "pictograms" / name).write_text('<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">'
                                                           + "".join(f'<path fill="{INK}" d="{d}"/>' for d in paths) + "</svg>\n")
    # a microphone: capsule, the holder below it, stem and foot
    write("mic.svg", [rect(8.8, 2.2, 6.4, 11.6, 3.2), sector(12, 10.4, 5.6, 7.3, 0, 180), rect(11.15, 17.3, 1.7, 3.3), rect(7.8, 20.4, 8.4, 1.8, 0.9)])
    # a loudspeaker: the box and cone, two wave fronts
    cone = "M2.6 9.3h4.1l5-4.4v14.2l-5-4.4H2.6Z"
    write("speaker.svg", [cone, sector(11.7, 12, 3.6, 5.3, -42, 42), sector(11.7, 12, 7.1, 8.9, -42, 42)])
    # something that moves: a disc with three lines behind it
    disc = "M12.1 12a4.7 4.7 0 1 0 9.4 0a4.7 4.7 0 1 0 -9.4 0Z"
    write("motion.svg", [disc, rect(2.4, 7.0, 8.0, 1.7, 0.85), rect(1.2, 11.15, 8.6, 1.7, 0.85), rect(2.4, 15.3, 8.0, 1.7, 0.85)])


def motion():
    """Five pictures for the figure of the motion watch, COMPUTED by the watch itself (kyber6g/camera/motion.py) from
    the aerial photograph: a camera that shifts and turns a little from look to look, with one small bright target
    drawn in that moves over the ground.

      motion_prev.png, motion_now.png   two looks in a row (320 x 180, brightness only), the target marked by nothing
      motion_diff_raw.png               |now - previous| as it is: the edges of the whole scene (dark = difference)
      motion_diff_fit.png               |now - previous put onto now| with the movement the watch measured: the target
      motion_found.png                  the look with the region the watch reports

    The target is drawn, the camera movement is simulated, the photograph and everything computed from it are real."""
    import sys
    import numpy as np
    sys.path.insert(0, str(ROOT.parent))
    from kyber6g.camera import motion as mo
    src = Image.open(ROOT / "assets" / "photos" / "aerial_usda_naip.jpg").convert("L")
    w, h = src.size
    lw, lh, n = 320, 180, 12
    s = 0.52 * w / lw                                              # photo pixels per camera pixel
    rng = np.random.default_rng(7)
    step, turn = (4.6, 1.9), 0.35                                  # the scene's shift in the picture per look (pixels), degrees per look
    looks, boxes = [], []
    for i in range(n):
        t = math.radians(turn * (i - n / 2))
        cx, cy = 0.56 * w - step[0] * s * i, 0.60 * h - step[1] * s * i
        a, b = s / 2 * math.cos(t), -s / 2 * math.sin(t)           # output (2x oversampled) -> photo
        d, e = s / 2 * math.sin(t), s / 2 * math.cos(t)
        view = src.transform((2 * lw, 2 * lh), Image.AFFINE, (a, b, cx - a * lw - b * lh, d, e, cy - d * lw - e * lh), resample=Image.BICUBIC)
        img = np.asarray(view.resize((lw, lh), Image.LANCZOS), np.float32)
        x, y = 212.0 + (step[0] - 7.5) * i, 58.0 + (step[1] + 3.0) * i          # the target: 7.5 px a look against the ground's 4.6
        img[int(y):int(y) + 6, int(x):int(x) + 10] += 85
        boxes.append((x, y, 10, 6))
        looks.append(np.clip(np.rint(img + rng.normal(0, 1.2, img.shape)), 0, 255).astype(np.uint8))
    det, res = mo.MotionDetector(), None
    for i, f in enumerate(looks):
        res = det.step(f, i * 0.125)
    prev, now = looks[-2], looks[-1]
    L = det._L
    crop = lambda p: np.ascontiguousarray(p[L.y0:L.y0 + L.H, L.x0:L.x0 + L.W], dtype=np.float32)
    ego = {k: res["ego"][k] for k in ("dx", "dy", "a", "b")}
    fit, margin = det._align(mo._box3(crop(prev)), {**ego, "moving": True, "resid": 0.0})
    raw = np.abs(mo._box3(crop(now)) - mo._box3(crop(prev)))
    aligned = np.abs(mo._box3(crop(now)) - fit)
    aligned[:margin] = aligned[-margin:] = 0
    aligned[:, :margin] = aligned[:, -margin:] = 0
    show = lambda a: Image.fromarray(a.astype(np.uint8)).resize((2 * a.shape[1], 2 * a.shape[0]), Image.LANCZOS)
    dark = lambda diff: show(255 - np.clip(5.0 * diff, 0, 255))    # dark = different, on white (prints well)
    show(prev).save(OUT / "motion_prev.png")
    show(now).save(OUT / "motion_now.png")
    dark(raw).save(OUT / "motion_diff_raw.png")
    dark(aligned).save(OUT / "motion_diff_fit.png")
    found = show(now).convert("RGB")
    from PIL import ImageDraw
    pen = ImageDraw.Draw(found)
    for rx, ry, rw, rh, _ in res["regions"]:
        x0, y0, x1, y1 = (2 * rx * lw - 3, 2 * ry * lh - 3, 2 * (rx + rw) * lw + 3, 2 * (ry + rh) * lh + 3)
        pen.rectangle((x0 - 2, y0 - 2, x1 + 2, y1 + 2), outline="#FFFFFF", width=2)
        pen.rectangle((x0, y0, x1, y1), outline=ACC_SYM, width=4)
    found.save(OUT / "motion_found.png")
    hit = any(rx * lw < boxes[-1][0] + 26 and (rx + rw) * lw > boxes[-1][0] - 16 and ry * lh < boxes[-1][1] + 22 and (ry + rh) * lh > boxes[-1][1] - 16
              for rx, ry, rw, rh, _ in res["regions"])
    print(f"motion pictures: camera moved ({ego['dx']:+.2f}, {ego['dy']:+.2f}) px and turned {math.degrees(ego['b']):+.2f} deg in the last look "
          f"(simulated: {step[0]:+.2f}, {step[1]:+.2f}, {turn:+.2f}); regions {res['regions']}; the target is {'in' if hit else 'NOT in'} one of them; "
          f"scene flag {res['scene']}")
    return hit and not res["scene"] and len(res["regions"]) == 1


if __name__ == "__main__":
    OUT.mkdir(parents=True, exist_ok=True)
    size = frame_and_cipher()
    lattice()
    curve()
    waves()
    pictograms()
    motion()
    print("illustrations written to", OUT, "- frame", size)
