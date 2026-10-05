"""Evaluation of the motion watch with targets whose position is known.

Two kinds of pictures are used, and every result says which:

  synthetic   a generated scene (structure at every scale plus hard edges), seen by a simulated camera that can
              shift by fractions of a pixel, rotate and zoom, with sensor-like noise. Everything is known exactly.
  real        pictures taken by the UAV's camera (kept in memory only), into which a target is drawn. The noise,
              the optics and the scene are real; the target and - if asked for - the camera movement (a window
              sliding over the pictures by whole pixels) are not.

A look counts as a hit if a reported region touches the target's box grown by `TOL` pixels (a difference picture
also shows where the target has just been). Every other region is a false one.
"""
import math

import numpy as np

from .motion import CELL, MotionDetector, ndi

F = 4                   # the synthetic scene has F x F scene pixels per camera pixel
TOL = 2 * CELL          # pixels around the target's box in which a region still belongs to it
DAY, NIGHT = (1.0, 0.01), (9.0, 0.08)          # noise variance = a + b x brightness (NIGHT: high sensor gain)


def make_scene(rng, h, w, border=48):
    """A background of (h + 2 border) x (w + 2 border) camera pixels at F times that resolution, values 20..235."""
    hh, ww = (h + 2 * border) * F, (w + 2 * border) * F
    fy, fx = np.fft.fftfreq(hh)[:, None], np.fft.rfftfreq(ww)[None, :]
    amp = 1.0 / np.maximum(np.hypot(fy, fx), 1.0 / max(hh, ww)) ** 1.1
    spec = amp * np.exp(2j * np.pi * rng.random((hh, ww // 2 + 1)))
    img = np.fft.irfft2(spec, s=(hh, ww))
    img = (img - img.mean()) / img.std()
    for _ in range(14):                                    # roofs, roads, fields: flat patches with hard edges
        y, x = int(rng.integers(0, hh - 40)), int(rng.integers(0, ww - 40))
        sy, sx = int(rng.integers(30, hh // 4)), int(rng.integers(30, ww // 4))
        img[y:y + sy, x:x + sx] = 0.35 * img[y:y + sy, x:x + sx] + rng.normal(0, 1.2)
    lo, hi = np.percentile(img, [1, 99])
    return np.clip(20 + 215 * (img - lo) / (hi - lo), 20, 235).astype(np.float32)


def render(scene, h, w, dx=0.0, dy=0.0, rot_deg=0.0, zoom=1.0):
    """What a camera of h x w pixels sees of the scene after the SCENE'S CONTENT has moved by (dx, dy) camera pixels
    in the picture, turned by rot_deg about the picture's centre and grown by `zoom` (each camera pixel averages
    F x F scene pixels)."""
    hh, ww = scene.shape
    cy, cx = (hh - 1) / 2, (ww - 1) / 2
    if rot_deg == 0 and zoom == 1 and float(dx * F).is_integer() and float(dy * F).is_integer():
        y0, x0 = int(round(cy - h * F / 2 + 0.5 - dy * F)), int(round(cx - w * F / 2 + 0.5 - dx * F))
        crop = scene[y0:y0 + h * F, x0:x0 + w * F]
    else:
        if ndi is None:
            raise RuntimeError("rotation, zoom and other fractions of a pixel need SciPy")
        t = math.radians(rot_deg)
        m = np.array([[math.cos(t), math.sin(t)], [-math.sin(t), math.cos(t)]]) / zoom      # output (row, col) -> scene
        out_c = np.array([(h * F - 1) / 2, (w * F - 1) / 2])
        off = np.array([cy - dy * F, cx - dx * F]) - m @ out_c
        crop = ndi.affine_transform(scene, m, offset=off, output_shape=(h * F, w * F), order=1, mode="nearest")
    if crop.shape != (h * F, w * F):
        raise ValueError("the camera has left the scene: make the border larger")
    return crop.reshape(h, F, w, F).mean(axis=(1, 3))


def add_target(frame, box, contrast):
    """Draws a target into `frame` (float, in place): box = (x, y, w, h) in pixels, not necessarily whole ones; the
    brightness inside changes by `contrast` grey levels, edges are covered in proportion (no hard staircase)."""
    x, y, bw, bh = box
    h, w = frame.shape
    xs, ys = np.arange(w), np.arange(h)
    cov_x = np.clip(np.minimum(xs + 1, x + bw) - np.maximum(xs, x), 0, 1)
    cov_y = np.clip(np.minimum(ys + 1, y + bh) - np.maximum(ys, y), 0, 1)
    frame += np.float32(contrast) * np.outer(cov_y, cov_x).astype(np.float32)
    return frame


def add_noise(rng, frame, noise=DAY):
    a, b = noise
    f = np.clip(frame, 0, 255)
    return np.clip(np.rint(f + rng.normal(0, 1, f.shape) * np.sqrt(a + b * f)), 0, 255).astype(np.uint8)


def judge(regions, box, shape):
    """(hit, false regions) for one look. `box` None: no target in the picture, every region is a false one."""
    h, w = shape
    hit, false = False, 0
    for rx, ry, rw, rh, _ in regions:
        x0, y0, x1, y1 = rx * w, ry * h, (rx + rw) * w, (ry + rh) * h
        if box is not None and x0 < box[0] + box[2] + TOL and x1 > box[0] - TOL and y0 < box[1] + box[3] + TOL and y1 > box[1] - TOL:
            hit = True
        else:
            false += 1
    return hit, false


def run(det: MotionDetector, frames, boxes, dt: float, warmup: int = 10, under_way: bool = False) -> dict:
    """Feeds the pictures to the detector and scores the looks after the first `warmup` (the detector has nothing to
    compare the first look with, and the picture of a second ago - the one that shows slow movers - exists only
    after a second; ten looks at 8 per second are 1.25 s). `under_way`: the detector is told that the UAV moves
    (as its GNSS would). Besides the hits and the false regions, the result says in how many looks the camera's
    movement was known and what it was measured to be (the sum of the measured shifts, pixels: for a camera that
    was moved by a known amount per look this can be compared with the truth)."""
    looks = hits = with_target = false_regions = false_looks = scene = moving = known = 0
    shift = 0.0
    for i, (f, box) in enumerate(zip(frames, boxes)):
        res = det.step(f, i * dt, under_way)
        if i < warmup:
            continue
        looks += 1
        scene += res["scene"]
        ego = res["ego"] or {}
        moving += bool(ego.get("moving"))
        known += bool(ego.get("known"))
        shift += math.hypot(ego.get("dx", 0.0), ego.get("dy", 0.0))
        hit, false = judge(res["regions"], box, f.shape)
        if box is not None:
            with_target += 1
            hits += hit
        false_regions += false
        false_looks += false > 0
    return {"looks": looks, "looks_with_target": with_target, "hits": hits, "false_regions": false_regions,
            "looks_with_false_region": false_looks, "scene_changes": scene, "looks_camera_moving": moving,
            "looks_camera_known": known, "camera_shift_sum": round(shift, 2)}


def path(rng, n, pan=0.0, jitter=0.0, rot=0.0, zoom=0.0):
    """Camera movement per look: a steady pan (pixels per look, direction fixed per run), a random walk of `jitter`
    pixels, `rot` degrees and `zoom` (fraction) per look. Returns n poses (dx, dy, rot_deg, zoom factor)."""
    ang = rng.uniform(0, 2 * math.pi)
    step = np.array([math.cos(ang), math.sin(ang)]) * pan
    pos, r, z, out = np.zeros(2), 0.0, 1.0, []
    for _ in range(n):
        # without rotation and zoom the camera stands on the scene's own grid (quarters of a camera pixel): such a
        # picture is cut out and averaged exactly, with no resampling in between
        p = pos if rot or zoom else np.round(pos * F) / F
        out.append((float(p[0]), float(p[1]), r, z))
        pos = pos + step + (rng.normal(0, jitter, 2) if jitter else 0)
        r += rot * (1 if rng.random() < 0.5 else -1) if rot else 0.0
        z *= 1 + zoom
    return out


def target_path(rng, n, shape, size, speed, margin=24):
    """A target of size x size pixels (taller than wide by a third) crossing the picture at `speed` pixels per look."""
    h, w = shape
    bw, bh = size, size * 4 / 3
    ang = rng.uniform(-0.5, 0.5) + (math.pi if rng.random() < 0.5 else 0.0)
    v = np.array([math.cos(ang), math.sin(ang)]) * speed
    span = v * (n - 1)
    lo = np.array([margin, margin]) - np.minimum(span, 0)
    hi = np.array([w - margin - bw, h - margin - bh]) - np.maximum(span, 0)
    start = np.array([rng.uniform(lo[0], max(lo[0], hi[0])), rng.uniform(lo[1], max(lo[1], hi[1]))])
    return [(float(start[0] + v[0] * i), float(start[1] + v[1] * i), bw, bh) for i in range(n)]


_SCENES = {}


def _scene(seed, h, w, border):
    """(random generator, scene) for a seed: the scene of a seed is made once and kept (it takes longer to make than
    a whole run does), and the generator continues from where the making of the scene left it, so a run is the same
    whether its scene was kept or not."""
    key = (seed, h, w, border)
    if key not in _SCENES:
        rng = np.random.default_rng(seed)
        scene = make_scene(rng, h, w, border)
        if scene.nbytes > 40e6:                              # a long pan needs a large scene: not kept
            return rng, scene
        if len(_SCENES) >= 16:
            _SCENES.clear()
        _SCENES[key] = (scene, rng.bit_generator.state)
    scene, state = _SCENES[key]
    rng = np.random.default_rng()
    rng.bit_generator.state = state
    return rng, scene


def dim(frame, flat=0.12, level=66.0):
    """The scene as a dim room shows it: little contrast around a low brightness (what the real camera gave at
    13 lux: mean 67, a few grey levels of structure)."""
    return (level + flat * (frame - frame.mean())).astype(np.float32)


def synthetic(seed, shape=(180, 320), looks=42, dt=0.125, size=8.0, contrast=25.0, speed=2.0, pan=0.0, jitter=0.0,
              rot=0.0, zoom=0.0, noise=DAY, sensitivity="medium", target=True, flicker=0.0, exposure=0.0,
              flat=0.0, row_noise=0.0, lamps=0, under_way=False) -> dict:
    """One run with a generated scene. `flicker`: brightness bands along the rows that wander from look to look
    (fraction of the brightness); `exposure`: random change of the whole picture's brightness per look (fraction);
    `flat` > 0: a dim scene with that fraction of the contrast (see `dim`); `row_noise`: an offset per row, new in
    every picture (grey levels, standard deviation), as a sensor at high gain adds; `lamps`: that many bright,
    sharp-edged things that belong to the scene (they stand still in it and move with it when the camera pans),
    all in one third of the picture: a dark room with a few lit things, the hard case for a camera that moves;
    `under_way`: the detector is told that the UAV moves."""
    h, w = shape
    reach = int(math.ceil((pan + 3 * jitter) * looks + (rot * looks / 57.3 + zoom * looks) * max(h, w) / 2)) + 8
    rng, scene = _scene(seed, h, w, max(16, reach))
    poses = path(rng, looks, pan, jitter, rot, zoom)
    boxes = target_path(rng, looks, shape, size, speed) if target else [None] * looks
    if lamps:                                                # their own generator: the scene and the paths stay as they are
        lr = np.random.default_rng(seed + 9)
        x0 = lr.uniform(0.1, 0.55) * w
        lit = [(x0 + lr.uniform(0, 0.3) * w, lr.uniform(0.15, 0.75) * h, lr.uniform(5, 14), lr.uniform(5, 14), lr.uniform(35, 90))
               for _ in range(lamps)]
    rows = np.arange(h)[:, None]
    frames, gain = [], 1.0
    for i, (pose, box) in enumerate(zip(poses, boxes)):
        f = render(scene, h, w, *pose)
        if flat:
            f = dim(f, flat)
        if lamps:
            for lx, ly, lw, lh, lc in lit:
                add_target(f, (lx + pose[0], ly + pose[1], lw, lh), lc)
        if box is not None:
            add_target(f, box, contrast)
        if row_noise:
            f = f + rng.normal(0, row_noise, (h, 1)).astype(np.float32)
        if flicker:
            f = f * (1 + flicker * np.sin(2 * math.pi * (rows / 37.0 + 0.31 * i))).astype(np.float32)
        if exposure:
            gain *= 1 + rng.normal(0, exposure)
            f = f * np.float32(gain)
        frames.append(add_noise(rng, f, noise))
    return run(MotionDetector(sensitivity), frames, boxes, dt, under_way=under_way)


def real(frames, seed, dt=0.125, size=8.0, contrast=25.0, speed=2.0, pan=0, sensitivity="medium", target=True,
         under_way=False) -> dict:
    """One run on real pictures (uint8, equal sizes, taken by a camera that stood still). `pan` > 0: the camera's
    movement is imitated by a window that slides over the pictures by that many whole pixels per look.
    `under_way`: the detector is told that the UAV moves."""
    rng = np.random.default_rng(seed)
    h, w = frames[0].shape
    n = len(frames)
    if pan:
        reach = int(pan) * (n - 1)
        ww = w - reach
        if ww < 128:
            raise ValueError(f"{n} pictures of {w} pixels are too narrow for a pan of {pan} pixels per look")
        forward = rng.random() < 0.5
        xs = [int(pan) * i if forward else reach - int(pan) * i for i in range(n)]
        views = [f[:, x:x + ww] for f, x in zip(frames, xs)]
    else:
        views = list(frames)
    shape = views[0].shape
    boxes = target_path(rng, n, shape, size, speed) if target else [None] * n
    out = []
    for v, box in zip(views, boxes):
        if box is None:
            out.append(np.ascontiguousarray(v))
            continue
        f = add_target(v.astype(np.float32), box, contrast)
        out.append(np.clip(np.rint(f), 0, 255).astype(np.uint8))
    return run(MotionDetector(sensitivity), out, boxes, dt, under_way=under_way)
