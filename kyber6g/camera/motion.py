"""Motion watch: things that move in the camera's picture, found on board.

The ISP makes a small second picture ("lores", 320 pixels wide) beside the video. Its brightness plane is analysed a
few times a second with NumPy/SciPy; what goes to the ground station is a few numbers (where, how strong, since
when) as text in the status stream. A moving thing is therefore reported even when no video is on the air, or when
the video is lost on the way: the report is a few hundred bytes in the link's authenticated records.

The camera of a UAV moves, and the difference of two pictures then lights up at every edge of the scene. So the
camera's own movement is estimated first and taken out. One look:

    1  Tiles of the half-size picture are phase-correlated with the previous look: one shift per tile, good to a
       fraction of a pixel, with a weight (how far the correlation peak stands out of its surroundings). The
       offsets a sensor at high gain adds to rows and columns are kept out of the correlation.
    2  A shift of the whole picture is fitted to the tile shifts - with rotation and zoom only where they explain
       the tiles clearly better. Tiles that disagree are left out (they show a moving thing, or nothing at all);
       if fewer than three agree, the movement counts as not measured.
    3  Where the tiles measured nothing (a dim scene at high gain gives them no peak), the question is put to
       pictures an eighth and a quarter of the size, in which the sensor's noise is averaged away. A shift found
       there is believed to be the camera's if edges in three parts of the picture show it, or if the places
       that changed strongly show it and the rest of the picture - flat, but many pixels - moves the same way (a
       test with a known error rate, whose evidence adds up over the looks of a pan). Otherwise one thing moved.
    4  The previous picture is put onto the current one, and the edges are asked whether it fits: a difference
       that is "gradient x a small shift" in most parts of the picture is a misfit. It is added to the movement
       and the fit is tried again.
    5  The pictures are subtracted with one gain per row (a change of exposure; lamp flicker under a rolling
       shutter). A pixel has changed if the difference exceeds   k x noise + tolerance x local gradient.   The
       noise is measured from the difference itself, in the flat half of the picture and per brightness band, so
       NIGHT mode sets its own threshold; the gradient term forgives the fraction of a pixel by which the two
       pictures may still disagree at an edge.
    6  "The picture as a whole changed" is said, and no single thing reported, if what is left has a pattern of
       its own, if it grows with the gradient, if the noise jumped, if edges changed in most parts of the
       picture, or if most cells are active. The same if the UAV is under way (its GNSS says so) and the
       camera's movement is not known: neither measured, nor is the picture one in which a misfit would show.
    7  A cell of 8 x 8 pixels with enough changed pixels is active. While the camera stands still the pictures of
       a second and of half a second ago are compared as well: a pixel counts if it differs from the older one
       and, in the same direction, from the newer one. That finds slow movers (less than a pixel from one look to
       the next) and does not report the place a thing has left.
    8  An active cell counts only if a cell near it was active at the previous look (noise does not repeat);
       connected cells make a region. Cells that are active most of the time (a screen, a fan, leaves) are muted
       until they calm down.

What this is not. It does not say WHAT moves (the detector on the ground station does). It cannot tell a moving
thing from a near, still thing passed by a moving camera (parallax), nor one bright thing in an otherwise empty
picture that is passed slowly from one that moves by itself: there the camera is taken to stand still, unless the
UAV is under way. It was tested with a camera that stands still and with imitated camera movement, not in flight
(`kyber6g.tools.motion_bench`, `tests/test_motion.py`).
"""
import collections
import math

import numpy as np

try:                                    # on the Pi (python3-scipy) and on the ground station
    from scipy import ndimage as ndi
except Exception:                       # without it: whole-pixel shifts only (no rotation, no zoom)
    ndi = None

CELL = 8                # lores pixels per side of a cell
TILE = 48               # half-size pixels per side of a correlation tile
NBINS = 8               # brightness bands of the noise table
MAX_REGIONS = 6
# sensitivity -> (k: threshold in units of the noise, changed pixels that make a cell active, cells that make a region)
LEVELS = {"low": (6.0, 12, 2), "medium": (4.5, 7, 1), "high": (3.6, 5, 1)}
PSR_MIN, PSR_FULL = 8.0, 16.0           # correlation peak over its surroundings: below = tile not used, above = full weight
STILL_PX = 0.25                         # the camera "stands still" below this shift (lores pixels) between two looks
Z_REST = 4.0                            # "the rest of the picture moves too": standard deviations (chance: 1 in 30,000 looks)
Z_KEEP = 0.8                            # of that evidence, the share kept from one look to the next (it adds up over a pan)
MUTE_AFTER_S = 20.0                     # a cell active for most of this long is muted (it is part of the scene)


def _box3(a):
    """3 x 3 mean: two pictures that disagree by a fraction of a pixel then differ less, and so does their noise."""
    s = a[:-2] + a[1:-1]
    s += a[2:]
    out = a.copy()                          # the outermost pixels stay as they are: they are never compared
    inner = out[1:-1, 1:-1]
    np.add(s[:, :-2], s[:, 1:-1], out=inner)
    inner += s[:, 2:]
    inner *= np.float32(1 / 9)
    return out


def _shifted(a, tx, ty):
    """a(x - t) for a shift t of any size, between whole pixels in proportion. What comes in over the edges is
    rubbish: the caller leaves a border of the size of the shift out."""
    ix, iy = math.floor(tx), math.floor(ty)
    fx, fy = np.float32(tx - ix), np.float32(ty - iy)
    r = np.roll(a, ix, axis=1)
    if fx > 1e-3:
        r = (1 - fx) * r + fx * np.roll(a, ix + 1, axis=1)
    out = np.roll(r, iy, axis=0)
    if fy > 1e-3:
        out = (1 - fy) * out + fy * np.roll(r, iy + 1, axis=0)
    return out


def _half(a):
    """The picture at half the size: means of 2 x 2 pixels (an odd last row or column is left out). The sensor's
    noise halves with every step; what the scene shows at that scale stays."""
    h, w = a.shape[0] // 2 * 2, a.shape[1] // 2 * 2
    return (a[0:h:2, 0:w:2] + a[1:h:2, 0:w:2] + a[0:h:2, 1:w:2] + a[1:h:2, 1:w:2]) * np.float32(0.25)


def _gradients(a):
    """Change of brightness per pixel to the right and downwards, and the larger of the two sizes."""
    gx, gy = np.zeros_like(a), np.zeros_like(a)
    np.subtract(a[:, 2:], a[:, :-2], out=gx[:, 1:-1])
    np.subtract(a[2:, :], a[:-2, :], out=gy[1:-1, :])
    gx *= 0.5
    gy *= 0.5
    return gx, gy, np.maximum(np.abs(gx), np.abs(gy))


def _dilate(m, r):
    """Cells within r cells of a set cell."""
    if ndi is not None:
        return ndi.maximum_filter(m.astype(np.uint8), size=2 * r + 1, mode="constant", cval=0) > 0
    out = m.copy()
    for dy in range(-r, r + 1):
        for dx in range(-r, r + 1):
            src = m[max(0, -dy):m.shape[0] - max(0, dy), max(0, -dx):m.shape[1] - max(0, dx)]
            out[max(0, dy):max(0, dy) + src.shape[0], max(0, dx):max(0, dx) + src.shape[1]] |= src
    return out


def _label(m):
    """Connected cells (8 neighbours): (labels, count)."""
    if ndi is not None:
        return ndi.label(m, structure=np.ones((3, 3), bool))
    lab, n = np.zeros(m.shape, np.int32), 0
    for y, x in zip(*np.nonzero(m)):
        if lab[y, x]:
            continue
        n += 1
        todo = [(y, x)]
        lab[y, x] = n
        while todo:
            cy, cx = todo.pop()
            for ny in range(max(0, cy - 1), min(m.shape[0], cy + 2)):
                for nx in range(max(0, cx - 1), min(m.shape[1], cx + 2)):
                    if m[ny, nx] and not lab[ny, nx]:
                        lab[ny, nx] = n
                        todo.append((ny, nx))
    return lab, n


class _Layout:
    """Sizes that follow from the size of the lores picture."""

    def __init__(self, shape):
        self.h, self.w = shape
        self.H, self.W = self.h - self.h % CELL, self.w - self.w % CELL
        if self.H < 4 * CELL or self.W < 4 * CELL:
            raise ValueError(f"picture of {self.w} x {self.h} is too small for the motion watch")
        self.y0, self.x0 = (self.h - self.H) // 2, (self.w - self.W) // 2
        hs, ws = self.H // 2, self.W // 2
        self.tile = n = TILE if min(hs, ws) >= TILE else (min(hs, ws) // 2) * 2
        # at least two tiles each way where the picture allows it (they may overlap): rotation and zoom show only
        # in how the shift differs from place to place
        nx, ny = max(2 if ws >= n + 8 else 1, round(ws / n)), max(2 if hs >= n + 8 else 1, round(hs / n))
        xs = np.linspace(0, ws - n, nx).round().astype(int)
        ys = np.linspace(0, hs - n, ny).round().astype(int)
        self.origins = [(int(x), int(y)) for y in ys for x in xs]
        # tile centres in the half-size picture, measured from its centre
        self.centres = np.array([(x + n / 2 - ws / 2, y + n / 2 - hs / 2) for x, y in self.origins], np.float64)
        self.win = np.outer(np.hanning(n), np.hanning(n)).astype(np.float32)
        # the fine half of a tile's spectrum (a real scene has little there: what is found is the sensor's noise)
        self.fine = np.hypot(np.fft.fftfreq(n)[:, None], np.fft.rfftfreq(n)[None, :]) > 0.3
        self.cells = (self.H // CELL, self.W // CELL)


class MotionDetector:
    """One look at a time: `step(luma, ts)` -> what moved since the previous look. No camera, no threads."""

    def __init__(self, sensitivity: str = "medium", long_baseline_s: float = 1.0):
        self.set_sensitivity(sensitivity)
        self.long_s = float(long_baseline_s)
        self._L = None
        self.reset()

    def set_sensitivity(self, level: str):
        if level not in LEVELS:
            raise ValueError(f"sensitivity must be one of {', '.join(LEVELS)}")
        self.sensitivity = level
        self.k, self.min_px, self.min_cells = LEVELS[level]

    def reset(self):
        self._prev = None                               # (ts, smoothed picture, tile spectra, tile texture)
        self._hist = collections.deque(maxlen=24)       # (ts, smoothed picture) of the looks since the camera stood still
        self._near_prev = None                          # cells near an active cell of the previous look
        self._rate = None                               # per cell: share of the recent time in which it was active
        self._muted = None
        self._lut = None                                # noise per brightness band
        self._level, self._misfit = None, 0             # noise of the whole picture, and for how many looks it was far above
        self._zsum, self._zseen = 0.0, False            # evidence that "the rest of the picture moves too", over the last looks
        self.last_tiles = self.last_psr = None
        self.looks = 0

    # ------------------------------------------------------- camera movement
    def _spectra(self, small):
        L = self._L
        n = L.tile
        t = np.stack([small[y:y + n, x:x + n] for x, y in L.origins])
        texture = t.std(axis=(1, 2))
        t = (t - t.mean(axis=(1, 2), keepdims=True)) * L.win
        return np.fft.rfft2(t), texture

    def _tile_shifts(self, fc, fp, texture):
        """Shift of the content of every tile from the previous look to this one (half-size pixels) and the weight
        it deserves. cur(x) = prev(x - d) puts the peak of the phase correlation at +d."""
        n = self._L.tile
        r = fc * np.conj(fp)
        # A sensor at high gain adds an offset to each row (and column) that changes from picture to picture. In the
        # spectrum that noise sits on the two axes; left in, it draws a random stripe through the correlation and the
        # "peak" lands anywhere on it (seen on the real camera at 13 lux: random shifts of up to 10 pixels).
        r[:, 0, :] = 0
        r[:, :, 0] = 0
        mag = np.abs(r)
        # Each frequency counts by how far it stands out of the noise, whose level is read from the fine half of
        # the spectrum: in a bright, detailed scene nearly all count alike (a sharp peak, good to a fraction of a
        # pixel); in a dim, flat one only the coarse structure counts (a broad peak, but the right one).
        floor = 6 * np.median(mag[:, self._L.fine], axis=1)[:, None, None]
        r /= mag + floor + 1e-6
        c = np.fft.irfft2(r, s=(n, n))
        flat = c.reshape(len(c), -1)
        ar = np.arange(len(c))
        kmax = flat.argmax(axis=1)
        peak = flat[ar, kmax]
        psr = (peak - flat.mean(axis=1)) / (flat.std(axis=1) + 1e-9)
        self.last_psr = psr
        py, px = np.divmod(kmax, n)

        def sub(lo, hi):
            """Fraction of a pixel by which the true peak lies beside the highest sample. The peak is close to a
            Gaussian, so a parabola is put through the LOGARITHMS of the sample and its two neighbours (measured on
            generated scenes: 0.04 pixel rms error, against 0.09 for a parabola through the values themselves, which
            pulls every shift towards a whole pixel); where a neighbour is not positive, the plain parabola."""
            ok = (lo > 0) & (hi > 0) & (peak > 0)
            ll, lc, lh = (np.log(np.where(ok, v, 1.0)) for v in (lo, peak, hi))
            den = ll - 2 * lc + lh
            gauss = 0.5 * (ll - lh) / np.where(np.abs(den) > 1e-9, den, 1.0)
            den2 = lo - 2 * peak + hi
            plain = 0.5 * (lo - hi) / np.where(np.abs(den2) > 1e-9, den2, 1.0)
            return np.clip(np.where(ok & (np.abs(den) > 1e-9), gauss, np.where(np.abs(den2) > 1e-9, plain, 0.0)), -0.5, 0.5)

        dx = px + sub(c[ar, py, (px - 1) % n], c[ar, py, (px + 1) % n])
        dy = py + sub(c[ar, (py - 1) % n, px], c[ar, (py + 1) % n, px])
        dx = np.where(dx > n / 2, dx - n, dx)
        dy = np.where(dy > n / 2, dy - n, dy)
        w = np.clip((psr - PSR_MIN) / (PSR_FULL - PSR_MIN), 0.0, 1.0) * (texture > 1.5)
        return np.stack([dx, dy], axis=1), w

    def _fit(self, d, w):
        """Movement of the whole picture from the tile shifts: d(c) = t + [[a, -b], [b, a]] c at a point c measured
        from the centre (a: zoom, b: rotation, both small). Returned in LORES pixels; None if no tile can be used."""
        c = self._L.centres
        use = w > 0
        if not use.any():
            return None
        self._tiles_needed = need = max(min(3, len(w)), math.ceil(0.45 * len(w)))

        def similarity(u):
            sw = np.sqrt(w[u])
            cx, cy = c[u, 0], c[u, 1]
            one, zero = np.ones_like(cx), np.zeros_like(cx)
            a_mat = np.concatenate([np.stack([one, zero, cx, -cy], 1) * sw[:, None],
                                    np.stack([zero, one, cy, cx], 1) * sw[:, None]])
            rhs = np.concatenate([d[u, 0] * sw, d[u, 1] * sw])
            return np.linalg.lstsq(a_mat, rhs, rcond=None)[0]

        def predict(p):
            return np.stack([p[0] + p[2] * c[:, 0] - p[3] * c[:, 1], p[1] + p[3] * c[:, 0] + p[2] * c[:, 1]], 1)

        p = None
        if use.sum() >= 3:
            for _ in range(3):
                p = similarity(use)
                res = np.linalg.norm(predict(p) - d, axis=1)
                bad = use & (res > max(0.6, 2.5 * float(np.median(res[use]))))
                if not bad.any() or (use & ~bad).sum() < 3:
                    break
                use = use & ~bad
            if abs(p[2]) > 0.06 or abs(p[3]) > 0.06:    # more than 3.4 degrees or 6 % between two looks: not believed
                p = None
        t = np.median(d[use], axis=0) if use.sum() >= 3 else (d[use] * w[use, None]).sum(0) / w[use].sum()
        shift_only = np.array([t[0], t[1], 0.0, 0.0])
        if p is not None:
            # rotation and zoom are believed only if they explain the tiles clearly better than a shift alone:
            # fitted to tiles that merely scatter, they would turn the scatter into a turn of the whole picture
            rms = lambda q: math.sqrt(float(np.mean(np.sum((predict(q) - d)[use] ** 2, axis=1))))
            if rms(shift_only) <= max(0.08, 1.5 * rms(p)):
                p = None
        if p is None:                                   # one or two tiles, or nothing gained by more: a shift only
            p = shift_only
        res = np.linalg.norm(predict(p) - d, axis=1)[use]
        tx, ty = 2 * p[0], 2 * p[1]                     # half-size -> lores pixels
        moving = math.hypot(tx, ty) > STILL_PX or abs(p[2]) > 8e-4 or abs(p[3]) > 8e-4
        if moving and int(use.sum()) < need:
            # Too small a part of the picture says so: it may be ONE thing that moves in front of a flat background
            # (seen: a target crossing an empty picture filled two tiles, was taken for a pan and vanished).
            return None
        return {"dx": float(tx), "dy": float(ty), "a": float(p[2]), "b": float(p[3]), "tiles": int(use.sum()),
                "resid": float(2 * math.sqrt(float(np.mean(res ** 2)))), "moving": bool(moving)}

    def _align(self, prev, ego):
        """The previous picture as the camera would see it now, and the border (pixels) in which that is not known."""
        L = self._L
        tx, ty, a, b = ego["dx"], ego["dy"], ego["a"], ego["b"]
        if abs(tx) < 0.02 and abs(ty) < 0.02 and a == 0 and b == 0:
            return prev, 1
        margin = int(math.ceil(max(abs(tx), abs(ty)) + (abs(a) + abs(b)) * max(L.H, L.W) / 2)) + 2
        if 3 * margin > min(L.H, L.W):
            return None, 0
        if ndi is None or (abs(a) < 3e-4 and abs(b) < 3e-4):     # a shift alone (or all that can be done without SciPy)
            return _shifted(prev, tx, ty), margin
        c0x, c0y = (L.W - 1) / 2, (L.H - 1) / 2
        ox, oy = a * c0x - b * c0y - tx, b * c0x + a * c0y - ty          # where in `prev` the pixel (0, 0) of now was
        ref = ndi.affine_transform(prev, [[1 - a, -b], [b, 1 - a]], offset=[oy, ox], order=1, mode="nearest", output=np.float32)
        return ref, margin

    # ----------------------------------------------------------- differences
    @staticmethod
    def _ego_out(ego, known):
        return {**{k: round(v, 4) if isinstance(v, float) else v for k, v in ego.items()}, "known": known}

    @staticmethod
    def _pattern(s) -> float:
        """How much the difference picture resembles itself four rows further down (-1..1). Sensor noise, smoothed
        over 3 x 3 pixels, does not at all (nor does an offset per row, which is new in every row). Two pictures that
        show different things do: what is left of them has the grain of the scene, not of the sensor. Values far
        from the rest are cut back first, so that one thing that really moved does not make a pattern of its own."""
        s = s[::2, ::2]
        lim = 3 * 1.4826 * float(np.median(np.abs(s[::2, ::2]))) + 0.3
        s = np.clip(s, -lim, lim)
        a, b = s[:-2].ravel(), s[2:].ravel()                 # 4 rows apart in the full picture
        den = math.sqrt(float(a @ a) * float(b @ b))
        return float(a @ b) / den if den > 0 else 0.0

    @staticmethod
    def _misfit_of(s, gx, gy, grad, every=2):
        """If the difference s = cur - ref is a misfit of the two pictures by a small shift e, then s = -(e . gradient)
        at every pixel. Returns the e that explains s best at the picture's strong edges (least squares, one round
        of leaving out the pixels that do not follow it: a thing that really moved does not), and the share of the
        difference at those edges that e explains (0..1). No strong edges in two directions: ((0, 0), 0).
        `every`: the step between the pixels that are used (2 for the full-size picture, 1 for the small ones)."""
        s2, gx2, gy2, grad = s[::every, ::every], gx[::every, ::every], gy[::every, ::every], grad[::every, ::every]
        # The steepest quarter of the pixels. (Taking only the few pixels that stand far out of the rest was tried for
        # dim, flat scenes: on the real camera it made a single moving thing - the only strong edges in the picture -
        # pass for a movement of the camera, and the thing was "taken out".)
        m2 = grad > np.percentile(grad, 75)
        s, gx, gy = s2[m2], gx2[m2], gy2[m2]
        if s.size < 60:
            return (0.0, 0.0), 0.0
        for again in (True, False):
            a11, a12, a22 = float(gx @ gx), float(gx @ gy), float(gy @ gy)
            b1, b2 = float(gx @ s), float(gy @ s)
            det = a11 * a22 - a12 * a12
            if det <= 1e-4 * (a11 + a22) ** 2 + 1e-9:            # edges in one direction only: the shift along them is open
                return (0.0, 0.0), 0.0
            e = (-(a22 * b1 - a12 * b2) / det, -(a11 * b2 - a12 * b1) / det)
            if not again:
                break
            r = np.abs(s + e[0] * gx + e[1] * gy)
            keep = r <= 2.5 * 1.4826 * float(np.median(r)) + 1e-3
            if keep.all() or keep.sum() < 60:
                break
            s, gx, gy = s[keep], gx[keep], gy[keep]
        total = float(s @ s)
        share = -(b1 * e[0] + b2 * e[1]) / total if total > 0 else 0.0
        if share < 0.2:
            return e, share
        # A camera's movement shows at the edges ALL OVER the picture; one thing that moves shows where it is. In a
        # flat scene a single mover is the only edge there is, and its movement fits "the camera moved" perfectly
        # (seen: a target crossing an empty picture was taken for a pan and vanished). So the shift must also
        # explain the difference in at least three of the picture's 3 x 2 parts, each judged on its own edges.
        h, w = s2.shape
        agree = 0
        few = min(30, max(12, int(m2.sum()) // 12))              # a part needs this many edge pixels to have a say
        for ys in (slice(0, h // 2), slice(h // 2, h)):
            for xs in (slice(0, w // 3), slice(w // 3, 2 * w // 3), slice(2 * w // 3, w)):
                mp = m2[ys, xs]
                if int(mp.sum()) < few:
                    continue
                sp, gxp, gyp = s2[ys, xs][mp], gx2[ys, xs][mp], gy2[ys, xs][mp]
                before = float(sp @ sp)
                r = sp + e[0] * gxp + e[1] * gyp
                agree += before > 0 and 1 - float(r @ r) / before >= 0.2
        return e, (share if agree >= 3 else 0.0)

    @staticmethod
    def _lk(s, gx, gy, least=12):
        """The shift e with s = -(e . gradient) that fits the given pixels best (least squares), found twice: the
        second time without the pixels that did not follow the first. None if their edges run in one direction only
        (the shift along an edge cannot be seen)."""
        e = None
        for again in (True, False):
            a11, a12, a22 = float(gx @ gx), float(gx @ gy), float(gy @ gy)
            b1, b2 = float(gx @ s), float(gy @ s)
            det = a11 * a22 - a12 * a12
            if det <= 1e-4 * (a11 + a22) ** 2 + 1e-9:
                return None
            e = (-(a22 * b1 - a12 * b2) / det, -(a11 * b2 - a12 * b1) / det)
            if not again:
                break
            r = np.abs(s + e[0] * gx + e[1] * gy)
            keep = r <= 2.5 * 1.4826 * float(np.median(r)) + 1e-3
            if keep.all() or keep.sum() < least:
                break
            s, gx, gy = s[keep], gx[keep], gy[keep]
        return e

    def _small_misfit(self, cur, ref, level, margin, shift=(0.0, 0.0), first=False):
        """Does `ref` lie beside `cur`, and by how much? Asked of pictures that are 2^level times smaller, where one
        pixel is the mean of many and the sensor's noise is averaged away. Returns ((ex, ey) in pixels of THAT size,
        believed) or None if the picture is too small. `shift`: `ref` is first moved by this much.

        A shift is believed - taken for a movement of the camera and not of one thing - on either of two grounds:

          (a) it explains a good part of the difference at the edges in at least three of the picture's six parts
              (`_misfit_of`): a scene with edges all over it;
          (b) the places that changed strongly give a shift, and THE REST OF THE PICTURE MOVES THE SAME WAY. The rest
              is flat and each of its pixels says next to nothing, but together they are a fair witness: under
              "the rest did not move" the sum over its pixels of  -(e . gradient) x difference  has mean zero and a
              spread that is known from the noise, so the number of spreads by which it stands out (z) can be
              read like a throw of dice. A lamp in a dark room that is passed by the camera, and a lamp that is
              carried through a dark room, differ in exactly this.

        (b) is asked only of the quarter- and eighth-size pictures: there the noise of neighbouring pixels is as
        good as independent, which the spread assumes. With `first` (the first question of a look) the z of this
        look is added to what the looks before left (`_zsum`, of which Z_KEEP is kept each time): a pan goes on
        for many looks and its evidence adds up, a thing's stays what dice give. So a slow pan over a nearly empty
        scene, too little to show in one look, is believed after a few."""
        m = 1 << level
        b = -(-margin // m) + 1
        if shift[0] or shift[1]:
            ref = _shifted(ref, shift[0], shift[1])
            b += int(math.ceil(max(abs(shift[0]), abs(shift[1]))))
        if min(cur.shape) - 2 * b < 12:
            return None
        sl = (slice(b, cur.shape[0] - b), slice(b, cur.shape[1] - b))
        gx, gy, _ = _gradients(cur)
        gx, gy = gx[sl], gy[sl]
        s = self._diff(cur[sl], ref[sl], rows=1, every=max(1, 4 >> level))
        # What a whole row has in common is no movement of the picture: at high gain every row gets an offset of its
        # own, new in each picture. It is taken out of the difference and of the gradient down the rows (left in,
        # the same offset stands in both and passes for a shift up or down, whole rows at a time).
        s -= np.median(s, axis=1, keepdims=True)
        gy = gy - np.median(gy, axis=1, keepdims=True)
        e, share = self._misfit_of(s, gx, gy, np.maximum(np.abs(gx), np.abs(gy)), every=1)
        if share >= 0.2:
            return e, True
        if level < 2:
            return e, False
        sig = 1.4826 * float(np.median(np.abs(s))) + 1e-3        # the noise of the difference; a thing or a lamp does not count
        strong = np.abs(s) > 3 * sig
        if strong.any():
            strong = _dilate(strong, 1)
        if int(strong.sum()) >= 12:
            rest = ~strong
            sr, gxr, gyr = s[rest], gx[rest], gy[rest]

            def witness(where, least):
                """The shift that the pixels `where` show, and by how many spreads the rest moves along it."""
                e = self._lk(s[where], gx[where], gy[where], least)
                if e is None:
                    return None
                along = e[0] * gxr + e[1] * gyr
                return -float(along @ sr) / (sig * math.sqrt(float(along @ along)) + 1e-9), e

            # The places that changed may be of two kinds at once: things of the scene that the camera passes
            # (they all show the camera's movement) and a thing that moves by itself (it shows its own). Each place
            # is asked on its own, and all together; the answer the rest of the picture agrees with most is the
            # camera's. (Seen: a lamp and a moving thing in a dark room, camera panning - taken together they gave
            # a shift between the two, which the rest still half agreed with, and the lamp was reported as moving.)
            whole = witness(strong, 12)
            tried = [whole] if whole is not None else []
            lab, n = _label(strong)
            if n > 1:
                sizes = np.bincount(lab.ravel())[1:]
                for i in np.argsort(-sizes)[:5] + 1:
                    if sizes[i - 1] >= 9:
                        one = witness(lab == i, 9)
                        if one is not None:
                            tried.append(one)
            if not tried:
                return (0.0, 0.0), False
            z, e = max(tried, key=lambda t: t[0])
            if whole is not None and whole[0] >= 0.95 * z:
                z, e = whole                                 # all places agree: together they measure best
            if not first:
                return e, z >= Z_REST
            self._zsum = Z_KEEP * self._zsum + z
            self._zseen = True
            # the sum of such z has a spread of 1 / sqrt(1 - Z_KEEP^2); this look must not speak against it
            return e, z >= Z_REST or (z >= 1.0 and self._zsum * math.sqrt(1 - Z_KEEP * Z_KEEP) >= Z_REST)
        # nothing stands out: does the picture as a whole lie beside the other? (chi-square with two degrees of
        # freedom under "it does not"; 20 is passed by chance once in 22,000 looks)
        sa, xa, ya = s.ravel(), gx.ravel(), gy.ravel()
        a11, a12, a22 = float(xa @ xa), float(xa @ ya), float(ya @ ya)
        b1, b2 = float(xa @ sa), float(ya @ sa)
        det = a11 * a22 - a12 * a12
        if det <= 1e-4 * (a11 + a22) ** 2 + 1e-9:
            return (0.0, 0.0), False
        e = (-(a22 * b1 - a12 * b2) / det, -(a11 * b2 - a12 * b1) / det)
        return e, -(b1 * e[0] + b2 * e[1]) / (sig * sig) >= 20.0

    def _coarse_misfit(self, small, ref, margin):
        """The shift (full-size pixels) by which `ref` still lies beside the current picture, measured on pictures an
        eighth and a quarter of the size, the smaller first, the other starting from what it found (and each asked
        again while it still finds something: in a flat scene one answer is only part of the way).
        Returns (ex, ey, found).

        Why: in a dim scene at high gain the full-size difference at the edges is mostly noise; a misfit explains a
        few per cent of it and is not believed, and the phase correlation of the tiles finds no peak either. (Seen
        on the real camera in NIGHT mode at 11 lux: a pan of 2 pixels per look was not measured, and the few strong
        edges of the room were reported as moving things in 95 of 102 looks.) One pixel of the eighth-size picture
        is the mean of 64: its noise is an eighth, while a misfit of the two pictures shows as it did."""
        refs = [ref]
        for _ in range(3):
            refs.append(_half(refs[-1]))
        ex = ey = 0.0
        found, first = False, True
        self._zseen = False
        for level in (3, 2):
            m = 1 << level
            for _ in range(3):
                r = self._small_misfit(small[level], refs[level], level, margin, (ex / m, ey / m), first)
                first = False
                if r is None or not r[1]:
                    break
                ex, ey, found = ex + r[0][0] * m, ey + r[0][1] * m, True
                if math.hypot(r[0][0], r[0][1]) * m < 0.15:
                    break
        if not self._zseen:                                      # this look had nothing to say about it
            self._zsum *= Z_KEEP
        return ex, ey, found

    def _would_show(self, small, ref, margin) -> bool:
        """True if a misfit of about one pixel WOULD be seen in these two pictures: `ref` is moved on purpose (0.2
        pixel each way at a quarter of the size, 0.8 full-size pixels) and the movement must be found again. If it
        is, a picture that shows no misfit is known to fit; if not, nothing is known (darkness, fog, a blank wall)."""
        r = self._small_misfit(small[2], _half(_half(ref)), 2, margin, (0.2, 0.2))
        # `ref` was moved by +0.2, so the current picture lies at -0.2 from it
        return r is not None and r[1] and abs(r[0][0] + 0.2) <= 0.1 and abs(r[0][1] + 0.2) <= 0.1

    @staticmethod
    def _diff(cur, ref, rows=9, every=4):
        """cur - gain x ref with one gain per row: the exposure may have changed between the two pictures, and
        under a rolling shutter a flickering lamp makes bright and dark bands along the rows that wander from one
        picture to the next. Both multiply the brightness. The gain of a row is the MEDIAN of the pixels' ratios
        cur / ref (every fourth pixel): a thing that moved changes the ratio of the pixels it covers and nothing
        else, so it cannot shift the median unless it covers half the row. (The ratio of the rows' medians, tried
        first, was shifted by a small target and lit up the whole row.) Dark pixels have no usable ratio: they are
        put alternately above and below everything, which leaves the median of the others where it is.
        `rows`, `every`: over how many rows the gains are smoothed, and the step between the pixels of a row that
        are asked (9 and 4 for the full-size picture; less for the small ones)."""
        c, r = cur[:, ::every], ref[:, ::every]
        ok = r > 16
        fill = np.where(np.arange(c.shape[1]) % 2, np.inf, -np.inf).astype(np.float32)
        with np.errstate(invalid="ignore"):                      # a row of dark pixels only: its median is "+inf and -inf"
            g = np.median(np.where(ok, c / np.maximum(r, 16), fill), axis=1)
        g = np.where(np.isfinite(g) & (ok.mean(axis=1) > 0.25), g, 1.0)
        # A band of flicker is many rows high and an exposure change is the same for all rows: one row alone has no
        # gain of its own. (A long horizontal edge that sits a fraction of a pixel off moves the ratios of its row
        # all one way; its "gain" then lit up the rest of that row. The median over nine rows does not follow it.)
        if rows > 1 and len(g) >= rows:
            g = np.median(np.lib.stride_tricks.sliding_window_view(np.pad(g, rows // 2, mode="edge"), rows), axis=1)
        s = np.clip(g, 0.7, 1.4).astype(np.float32)[:, None] * ref
        # At the sensor's limit the true brightness is not known: a brighter exposure cannot lift a pixel that is
        # already white, and the missing rest would count as a change. A pixel that is white in either picture
        # counts only if the two differ by far more than that could explain (a lamp that moved still does).
        white = (cur > 240) | (ref > 240)
        np.subtract(cur, s, out=s)
        s[white & (np.abs(s) < 30)] = 0
        return s

    def _noise(self, a, idx, grad, tol) -> bool:
        """Noise of the difference per brightness band (bright pixels are noisier): 1.4826 x median |difference|,
        robust against the part of the picture that really changed. The table changes slowly: every fourth look
        is enough for it.

        Only the FLAT half of the picture is asked (pixels whose brightness changes least towards their
        neighbours). Noise is the same everywhere, but if the two pictures do not fit on each other (the camera
        moved and that was not measured) the difference is  misfit x gradient: taken over the whole picture it
        would pass for noise, the threshold would rise with it and the few places still above it would be reported
        as moving things. In the flat half the misfit hardly shows, the noise stays what it is, and the edges then
        stand out as changed - all over the picture, which is what `_edges_changed_everywhere` looks for.

        Returns False if the noise so measured is still far above what it has been: a sensor's noise does not jump
        from one look to the next. If it stays high for a second it is the new level (the gain was changed)."""
        a, idx, g = a[::3, ::3].ravel(), idx[::3, ::3].ravel(), grad[::3, ::3].ravel()
        flat = g <= np.median(g)
        top = g >= np.percentile(g, 75)
        steep = a[top] - tol * g[top]                   # what the allowed misfit does not explain
        a, idx = a[flat], idx[flat]
        whole = 1.4826 * float(np.median(a))
        # Noise does not care where the edges are. If the difference at the steepest quarter of the pixels - beyond
        # what the allowed misfit explains - is well over twice that in the flat half, it grows with the gradient:
        # that is a misfit, however large, and it needs no memory of what the noise used to be (a camera that
        # moves from the very first look on).
        if steep.size >= 60 and 1.4826 * float(np.median(steep)) > 2.2 * whole + 0.5:
            return False
        if self._level is not None and whole > 2.5 * self._level + 0.5 and self._misfit < 8:
            self._misfit += 1
            return False
        fresh = self._misfit >= 8
        self._level = whole if self._level is None or fresh else 0.9 * self._level + 0.1 * whole
        self._misfit = 0
        if self._lut is not None and self.looks % 4 and not fresh:
            return True
        new = np.full(NBINS, whole, np.float32)
        for b in range(NBINS):
            sel = a[idx == b]
            if sel.size >= 60:
                new[b] = 1.4826 * float(np.median(sel))
        new = np.maximum(new, 0.35)
        self._lut = new if self._lut is None or fresh else 0.75 * self._lut + 0.25 * new
        return True

    def _edges_changed_everywhere(self, changed, grad, sigma) -> bool:
        """True if, in most parts of the picture, a good share of the EDGE pixels changed. A thing that moves changes
        the edges where it is; a camera that moved changes them wherever there are any. An edge pixel is one whose
        brightness differs from its neighbour's by more than twice the threshold on noise, so that half a pixel of
        misfit shows. The picture is looked at in 3 x 2 parts; parts with hardly any edges do not vote."""
        edge = grad > 2 * self.k * sigma
        h, w = edge.shape
        votes = parts = 0
        for ys in (slice(0, h // 2), slice(h // 2, h)):
            for xs in (slice(0, w // 3), slice(w // 3, 2 * w // 3), slice(2 * w // 3, w)):
                n = int(edge[ys, xs].sum())
                if n >= 40:
                    parts += 1
                    votes += int((changed[ys, xs] & edge[ys, xs]).sum()) > 0.25 * n
        return parts >= 3 and votes >= max(3, math.ceil(0.6 * parts))

    def _active(self, mask, sl):
        L = self._L
        full = np.zeros((L.H, L.W), bool)
        full[sl] = mask
        return full.reshape(L.cells[0], CELL, L.cells[1], CELL).sum(axis=(1, 3))

    # ------------------------------------------------------------------ look
    def step(self, luma, ts: float, platform_moving: bool = False) -> dict:
        """`luma`: 2-D uint8 picture, `ts`: its capture time (seconds); `platform_moving`: something other than the
        picture says the camera is being carried along (the UAV's GNSS speed). Returns
        {"ts", "regions": [[x, y, w, h, strength], ...] (fractions of the picture, strongest first), "scene": bool
        (the picture as a whole changed, or it could not be told how the camera moved: nothing can be said about
        single things), "ego": {...} or None (camera movement since the previous look; None: first look),
        "noise", "pattern", "active", "muted"}."""
        luma = np.asarray(luma)
        if luma.ndim != 2:
            raise ValueError("the motion watch needs a 2-D brightness picture")
        if self._L is None or (self._L.h, self._L.w) != luma.shape:
            self._L = _Layout(luma.shape)
            self.reset()
        L = self._L
        cur = np.ascontiguousarray(luma[L.y0:L.y0 + L.H, L.x0:L.x0 + L.W], dtype=np.float32)
        small = (cur[0::2, 0::2] + cur[1::2, 0::2] + cur[0::2, 1::2] + cur[1::2, 1::2]) * np.float32(0.25)
        blur = _box3(cur)
        spec, texture = self._spectra(small)
        self.looks += 1
        out = {"ts": ts, "regions": [], "scene": False, "ego": None, "noise": None, "active": 0, "muted": 0}
        prev, self._prev = self._prev, (ts, blur, spec, texture)
        if prev is None or not 0 < ts - prev[0] <= 1.5:          # the first look, or a gap: nothing to compare with
            self._hist.clear()
            self._near_prev = None
            return out
        dt = ts - prev[0]

        d, w = self._tile_shifts(spec, prev[2], np.minimum(texture, prev[3]))
        self.last_tiles = (d, w, texture)                        # for diagnosis (the UAV's `motion` command, "trace")
        ego = self._fit(d, w)
        known = ego is not None
        if known:
            self._zsum = 0.0                                     # a scene the tiles can hold on to: the other evidence starts anew
        if not known or not ego["moving"]:
            # nothing to hold on to (dark, or a blank wall), or a shift too small to be told from the tiles' scatter:
            # start from "no movement" and let the edges say more (below)
            ego = {"dx": 0.0, "dy": 0.0, "a": 0.0, "b": 0.0, "tiles": ego["tiles"] if known else 0, "resid": 0.0, "moving": False}
        gx, gy, grad = _gradients(blur)
        idx = np.minimum((blur * (NBINS / 256.0)).astype(np.intp), NBINS - 1)

        # Put the previous picture onto this one, then ask the edges whether it fits: if the difference looks like
        # "gradient x a small shift" all over the picture, that shift is still in it (the tiles measured the
        # movement a little wrongly, or not at all). It is added and the fit is asked again; a misfit that does not
        # go away means the camera moved in a way that cannot be taken out here. Where the tiles found nothing, the
        # small pictures are asked first: they see a misfit of several pixels, and one that the full-size
        # picture's noise hides.
        left = 0.0
        coarse, small = False, None
        for attempt in range(5):
            ref, margin = self._align(prev[1], ego)
            if ref is None:                                      # the camera turned too far between two looks
                out["ego"] = self._ego_out(ego, known)
                return self._scene(out)
            sl = (slice(margin, L.H - margin), slice(margin, L.W - margin))
            if attempt == 0 and not known:
                small = [blur]                                   # the picture at half, a quarter and an eighth of its size
                for _ in range(3):
                    small.append(_half(small[-1]))
                ex, ey, found = self._coarse_misfit(small, ref, margin)
                if found and math.hypot(ex, ey) >= 0.15:
                    ego = {**ego, "dx": ego["dx"] + ex, "dy": ego["dy"] + ey, "refined": True}
                    ego["moving"] = math.hypot(ego["dx"], ego["dy"]) > STILL_PX or abs(ego["a"]) > 8e-4 or abs(ego["b"]) > 8e-4
                    coarse = True
                    continue                                     # put it on again; the full-size picture has the last word
            s = self._diff(blur[sl], ref[sl])
            (ex, ey), share = self._misfit_of(s, gx[sl], gy[sl], grad[sl])
            if share < 0.2 and coarse and self._level is not None:
                # The camera's movement is established (the small pictures showed it), but only to a pixel or so,
                # and the full-size picture as a whole is too noisy to say more. Its few real edges are not: those
                # that stand far out of the noise (four times the noise of a gradient) say by how much the two
                # pictures still disagree. Only a correction is taken from them, never a movement: they may be
                # few, and one of them may be a thing that moves on its own.
                edge = grad[sl] > 1.64 * self._level + 0.5
                if int(edge.sum()) >= 40:
                    fine = self._lk(s[edge], gx[sl][edge], gy[sl][edge], least=40)
                    if fine is not None and math.hypot(fine[0], fine[1]) <= 1.5:
                        (ex, ey), share = fine, 1.0
            left = math.hypot(ex, ey) if share >= 0.2 else 0.0
            if left < (0.1 if attempt == 0 else 0.2):
                break
            if attempt == 4 or left > 2.5:
                out["ego"] = self._ego_out(ego, known)
                return self._scene(out)
            ego = {**ego, "dx": ego["dx"] + ex, "dy": ego["dy"] + ey, "refined": True}
            ego["moving"] = math.hypot(ego["dx"], ego["dy"]) > STILL_PX or abs(ego["a"]) > 8e-4 or abs(ego["b"]) > 8e-4
        # The camera's movement is KNOWN if the tiles measured it, if the edges corrected it, or if the picture has
        # enough in it that a misfit would have shown (and none did).
        known = known or bool(ego.get("refined")) or (small is not None and self._would_show(small, ref, margin))
        out["ego"] = self._ego_out(ego, known)
        if platform_moving and not known:
            # The UAV is under way (its GNSS says so) and the picture gave no way to measure how the camera moved:
            # whatever differs now may be the ground going by. Nothing is reported for this look.
            return self._scene(out)
        out["pattern"] = round(self._pattern(s), 2)
        if out["pattern"] > 0.35:
            # What is left after subtraction has a pattern: it is not noise. The two pictures show different things
            # (the camera moved further than could be measured, or the scene was replaced).
            return self._scene(out)
        a1 = np.abs(s, out=s)
        # how far (pixels) the two pictures may still disagree at an edge: what the edges still showed, and what
        # the fit of rotation and zoom left over
        # (a resampled picture is also a little softer than a fresh one: 0.35 pixel is allowed then, 0.15 otherwise)
        tol = min(2.0, (0.35 if ref is not prev[1] else 0.15) + 1.2 * left + 1.5 * ego["resid"])
        if not self._noise(a1, idx[sl], grad[sl], tol):          # the two pictures do not fit on each other
            return self._scene(out)
        sigma = self._lut[idx]
        changed = a1 > self.k * sigma[sl] + tol * grad[sl]
        if self._edges_changed_everywhere(changed, grad[sl], sigma[sl]):
            # The two pictures do not fit on each other: the camera moved and its movement was not measured (a dim,
            # flat scene gives the correlation nothing to hold on to) or was measured wrongly. Edges all over the
            # picture then "change". Nothing can be said about single things in this look.
            return self._scene(out)
        counts = self._active(changed, sl)
        active = counts >= self.min_px

        # The pictures of a second and of half a second ago, while the camera stands still: slow movers.
        if ego["moving"]:
            self._hist.clear()
        else:
            self._hist.append((ts, blur))
        if self._hist and ts - self._hist[0][0] >= 0.7 * self.long_s:
            old = min(self._hist, key=lambda e: abs(ts - self.long_s - e[0]))[1]
            mid = min(self._hist, key=lambda e: abs(ts - 0.5 * self.long_s - e[0]))[1]
            one = (slice(1, L.H - 1), slice(1, L.W - 1))
            thr = self.k * sigma[one] + max(tol, 0.2) * grad[one]
            d2 = self._diff(blur[one], old[one])
            far = np.abs(d2) > 1.25 * thr
            counts2 = self._active(far, one)
            if mid is not old and mid is not blur and counts2.max() >= self.min_px:
                # A thing that moved on shows twice in the difference to the picture of a second ago: where it is
                # now and where it was then. Only the first is something that moves NOW, and the picture of half a
                # second ago tells the two apart: where the thing is, this picture differs from both older ones in
                # the same direction (by half as much or more, if it moves steadily); the place it has left looks
                # now as it did half a second ago.
                # (Tried before: not asking the older picture near anything the comparison of neighbouring looks
                # had just seen. A target of medium contrast, strong enough to light that comparison now and then
                # but too weak to hold it, then closed the slow comparison on itself and was found LESS often
                # than a fainter one. Here the two comparisons know nothing of each other.)
                d3 = self._diff(blur[one], mid[one])
                far &= d2 * d3 > 0.4 * d2 * d2
                counts2 = self._active(far, one)
            slow = counts2 >= self.min_px
            counts = np.where(slow & ~active, counts2, counts)
            out["slow"] = int((slow & ~active).sum())            # cells that only the older pictures show
            active = active | slow

        if active.mean() > 0.6 or (active.mean() > 0.3 and not known):
            return self._scene(out)

        # cells that are active most of the time belong to the scene (only while the camera stands still)
        if self._rate is None:
            self._rate, self._muted = np.zeros(L.cells), np.zeros(L.cells, bool)
        if ego["moving"]:
            self._rate *= 0.9
        else:
            self._rate += (active - self._rate) * min(1.0, dt / MUTE_AFTER_S)
        self._muted = np.where(self._muted, self._rate > 0.25, self._rate > 0.5)
        if self._muted.any():
            active = active & ~_dilate(self._muted, 1)           # and its fringe, which is active only now and then

        confirmed = active & self._near_prev if self._near_prev is not None else np.zeros_like(active)
        self._near_prev = _dilate(active, 2)
        out.update(noise=round(float(self._lut.mean()), 2), active=int(active.sum()), muted=int(self._muted.sum()))
        out["regions"] = self._regions(confirmed, counts)
        return out

    def _scene(self, out):
        out["scene"] = True
        self._hist.clear()
        self._near_prev = None
        return out

    def _regions(self, confirmed, counts):
        L = self._L
        if not confirmed.any():
            return []
        lab, n = _label(_dilate(confirmed, 1))                   # parts one cell apart are one thing
        lab = np.where(confirmed, lab, 0)
        found = []
        for i in range(1, n + 1):
            ys, xs = np.nonzero(lab == i)
            if len(ys) < self.min_cells:
                continue
            strength = min(1.0, float(counts[ys, xs].mean()) / (CELL * CELL))
            x, y = float(L.x0 + xs.min() * CELL) / L.w, float(L.y0 + ys.min() * CELL) / L.h
            bw, bh = float(xs.max() - xs.min() + 1) * CELL / L.w, float(ys.max() - ys.min() + 1) * CELL / L.h
            found.append((len(ys) * strength, [round(x, 3), round(y, 3), round(bw, 3), round(bh, 3), round(strength, 2)]))
        found.sort(key=lambda f: -f[0])
        return [r for _, r in found[:MAX_REGIONS]]


class MotionState:
    """Looks -> events. Movement begins with the first look that shows a region and ends when no look has shown one
    for `hold` seconds (a walker who stops for a moment is one event, not ten)."""

    def __init__(self, hold: float = 2.5):
        self.hold = hold
        self.on, self.since, self.last_seen = False, None, None
        self.events = self.looks = self.looks_with_motion = self.scene_changes = 0
        self.last = None                                         # the last event that ended: {"since", "until", "looks"}
        self._n = 0

    def update(self, res: dict):
        """Returns "start", "end" or None."""
        ts = res["ts"]
        self.looks += 1
        self.scene_changes += bool(res.get("scene"))
        if res.get("regions"):
            self.looks_with_motion += 1
            self.last_seen = ts
            self._n += 1
            if not self.on:
                self.on, self.since, self._n = True, ts, 1
                self.events += 1
                return "start"
        elif self.on and ts - self.last_seen > self.hold:
            self.on = False
            self.last = {"since": self.since, "until": self.last_seen, "looks": self._n}
            return "end"
        return None

    def summary(self) -> dict:
        return {"on": self.on, "since": self.since if self.on else None, "last_seen": self.last_seen, "events": self.events,
                "looks": self.looks, "looks_with_motion": self.looks_with_motion, "scene_changes": self.scene_changes,
                "last": self.last}
