"""Measurements of the motion watch (camera/motion.py) for the paper.

    python -m kyber6g.tools.motion_bench synthetic --out FILE [--seeds 8]      generated scenes, everything known
    python -m kyber6g.tools.motion_bench camera    --out FILE [--captures 3]   the UAV's own camera, targets drawn in
    python -m kyber6g.tools.motion_bench cost      --out FILE [--rounds 4]     what the watch costs the UAV (on / off)
    python -m kyber6g.tools.motion_bench quiet     --out FILE [--minutes 5]    the real scene as it is: what is reported

`synthetic` runs here (no hardware). The other three talk to the running ground station (which talks to the UAV):
the pictures of `camera` are taken and judged ON the UAV, in memory, and only counts come back (see
CameraService.motion_selftest); `cost` switches the watch off and on in turns and reads the UAV's own status.

What each number is: a HIT is a look in which a reported region touches the target's box (grown by 16 pixels); a
FALSE REGION is any other region. Looks are scored from the eleventh on (the watch needs a second of history).
In a generated scene a false region is a false alarm, because nothing else moves there. In front of the real camera
it is "a region without a drawn target": something that really moved, or a false alarm. Every capture is used.
"""
import argparse
import json
import platform
import statistics
import sys
import time
import urllib.request
from pathlib import Path

API = "http://127.0.0.1:8600"


def provenance(kind):
    return {"what": f"motion watch: {kind}", "when": time.strftime("%Y-%m-%d %H:%M:%S %Z"), "host": platform.node(), "tool": "kyber6g.tools.motion_bench"}


def total(runs):
    out = {}
    for r in runs:
        for k, v in r.items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                out[k] = out.get(k, 0) + v
    return out


# ------------------------------------------------------------------ synthetic
def synthetic(a):
    from ..camera import motion_eval as me
    seeds = range(a.seeds)
    rows = []

    def case(series, x, label, **kw):
        t0 = time.perf_counter()
        # the same seeds for every case: along a curve only the one quantity changes, the scenes and the paths stay
        runs = [me.synthetic(7000 + 131 * s, **kw) for s in seeds]
        t = total(runs)
        rows.append({"series": series, "x": x, "label": label, "runs": len(runs),
                     "settings": {k: (list(v) if isinstance(v, tuple) else v) for k, v in kw.items()}, **t})
        pd = t["hits"] / t["looks_with_target"] if t.get("looks_with_target") else None
        print(f"{series:22s} {label:34s} hit {'-' if pd is None else format(pd, '.2f'):>5s}   false regions {t['false_regions']:3d} in {t['looks']:4d} looks"
              f"   scene {t['scene_changes']:3d}   ({time.perf_counter() - t0:.0f} s)", flush=True)

    for noise, name in ((me.DAY, "day"), (me.NIGHT, "night")):
        for c in (3, 4, 6, 8, 12, 16, 25, 40):
            case(f"contrast, {name} noise", c, f"contrast {c}, 8 px, 2 px/look", contrast=c, noise=noise)
        for s in (3, 4, 6, 8, 12, 16):
            case(f"size, {name} noise", s, f"{s} px, contrast 25, 2 px/look", size=s, noise=noise)
    for level in ("low", "high"):
        for c in (3, 4, 6, 8, 12, 16, 25, 40):
            case(f"contrast, day noise, {level}", c, f"contrast {c}, sensitivity {level}", contrast=c, sensitivity=level)
    for v in (0.1, 0.2, 0.4, 0.8, 1.5, 3, 6, 10):
        case("speed", v, f"{v} px/look, 8 px, contrast 25", speed=v, looks=50)
    for pan in (0, 0.5, 1, 2, 4, 8, 12):
        case("pan", pan, f"camera {pan} px/look, target +4", pan=pan, jitter=0.2 if pan else 0, contrast=30, speed=pan + 4)
        case("pan + turn", pan, f"camera {pan} px/look and 0.3 deg", pan=pan, rot=0.3, contrast=30, speed=pan + 4)
        case("pan, no target", pan, f"camera {pan} px/look, nothing moves", pan=pan, jitter=0.2 if pan else 0, target=False)
    for label, kw in (("still, day noise", {}), ("still, night noise", {"noise": me.NIGHT}),
                      ("lamp flicker 5 %", {"flicker": 0.05}), ("exposure wanders 2 % a look", {"exposure": 0.02}),
                      ("pan 2.3 px/look", {"pan": 2.3}), ("pan 6.5 px + shake 0.5 px", {"pan": 6.5, "jitter": 0.5}),
                      ("pan + turn 0.3 deg/look", {"pan": 2.3, "rot": 0.3}), ("pan + zoom 0.5 %/look", {"pan": 1.0, "zoom": 0.005}),
                      ("dim flat scene, night, row noise", {"flat": 0.12, "noise": me.NIGHT, "row_noise": 1.5}),
                      ("dim flat scene, pan 2.3", {"flat": 0.12, "noise": me.NIGHT, "row_noise": 1.5, "pan": 2.3})):
        for level in ("medium", "high"):
            case(f"nothing moves, {level}", label, label, target=False, sensitivity=level, **kw)
    return {**provenance("generated scenes"), "seeds": a.seeds, "looks_per_run_scored": "looks - 10", "picture": [320, 180], "looks_per_second": 8,
            "noise_models": {"day": list(me.DAY), "night": list(me.NIGHT), "meaning": "variance = a + b x brightness, grey levels squared"},
            "rows": rows}


# --------------------------------------------------------------------- hardware
def post(cmd, args=None, timeout=30):
    body = json.dumps({"cmd": cmd, "args": args or {}, "timeout": min(120, max(1, timeout))}).encode()
    req = urllib.request.Request(API + "/api/cmd", body, {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=timeout + 10))


def state():
    return json.load(urllib.request.urlopen(API + "/api/state", timeout=6))


def cam_motion(s=None):
    return (((s or state()).get("uav") or {}).get("camera") or {}).get("motion") or {}


def camera(a):
    grid = [{"target": False}, {"target": False, "sensitivity": "high"}, {"target": False, "sensitivity": "low"}]
    for c in (4, 6, 8, 12, 16, 25, 40):
        grid.append({"size": 8, "contrast": c, "speed": 2})
    for c in (4, 6, 8, 12):
        grid.append({"size": 8, "contrast": c, "speed": 2, "sensitivity": "high"})
    for s in (3, 4, 6, 12, 16):
        grid.append({"size": s, "contrast": 25, "speed": 2})
    for v in (0.2, 0.4, 0.8, 4, 8):
        grid.append({"size": 8, "contrast": 25, "speed": v})
    grid += [{"size": 8, "contrast": -25, "speed": 2}, {"target": False, "pan": 2}, {"size": 8, "contrast": 25, "speed": 6, "pan": 2},
             {"target": False, "pan": 1}, {"target": False, "pan": 3}, {"target": False, "pan": 2, "under_way": True}]
    # EVERY capture is used. The scene in front of the camera is real and nobody is asked to keep still: a region that
    # touches no drawn target may be something that really moved, or a false alarm, and the pictures (which never
    # leave the UAV) are the only thing that could tell which. So such regions are counted and reported as what they
    # are, "regions without a drawn target". (A first version threw away the captures in which the no-target cases
    # showed a region: that hides false alarms by construction, and in a room with people in it it left nothing.)
    captures = []
    for n in range(a.captures):
        r = post("motion", {"selftest": {"looks": 44, "seed": 100 + 17 * n, "cases": grid}}, timeout=110)
        if not r.get("ok"):
            sys.exit(f"self-test refused: {r.get('error')}")
        res = r["result"]
        res["scene_was_still"] = res["results"][0]["false_regions"] == 0 and res["results"][1]["false_regions"] == 0
        captures.append(res)
        print(f"capture {n + 1}: {res['mode']}, {res['lux']} lux, gain {res['gain']}, mean {res['mean']}; regions with no target drawn in: "
              f"{res['results'][0]['false_regions']} (medium), {res['results'][1]['false_regions']} (high), {res['results'][2]['false_regions']} (low)", flush=True)
    used = captures
    rows = []
    keys = ("looks", "looks_with_target", "hits", "false_regions", "looks_with_false_region", "scene_changes", "looks_camera_moving",
            "looks_camera_known", "camera_shift_sum")
    for i, g in enumerate(grid):
        t = total([c["results"][i] for c in used])
        rows.append({"case": g, **{k: t.get(k) for k in keys}})
        print(f"  {str(g):78s} hits {t['hits']:3d}/{t['looks_with_target']:3d}  other regions {t['false_regions']:3d} in {t['looks']} looks"
              f"  camera known {t.get('looks_camera_known', 0)}", flush=True)
    s = state()
    return {**provenance("the UAV's camera, targets drawn into its pictures on the UAV"), "captures": len(captures), "captures_used": len(used),
            "captures_with_a_still_scene": sum(c["scene_was_still"] for c in captures),
            "other_regions": "regions that touch no drawn target: real movement in the scene or a false alarm (the scene was not controlled)",
            "looks_per_capture": 44,
            "conditions": [{k: c.get(k) for k in ("mode", "lux", "gain", "exposure_us", "mean", "dt", "size", "scene_was_still")} for c in captures],
            # capture by capture as well: one capture during which somebody walks through the picture says little about
            # the watch, and must be seen as what it is (the plot shows the median of the captures and their range)
            "per_capture": [[{k: c["results"][i].get(k) for k in keys} for i in range(len(grid))] for c in captures],
            "camera": {k: ((s.get("uav") or {}).get("camera") or {}).get(k) for k in ("sensor", "mode", "width", "height", "fps", "tuning")},
            "rows": rows}


def sample(seconds, every=1.0):
    """The UAV's and the ground station's own numbers over a stretch of time."""
    s0 = state()
    cpu, fps, ms, seal, temp, mhz = [], [], [], [], [], []
    t_end = time.time() + seconds
    while time.time() < t_end:
        time.sleep(every)
        s = state()
        u = s.get("uav") or {}
        cam, system = u.get("camera") or {}, u.get("system") or {}
        cpu.append(system.get("cpu_percent", system.get("cpu")))
        temp.append(system.get("temp_c"))
        mhz.append(system.get("cpu_mhz"))
        fps.append(cam.get("fps"))
        seal.append((u.get("video_tx") or {}).get("seal_us_avg"))
        m = cam.get("motion") or {}
        ms.append(m.get("ms") if m.get("watching") else None)   # while the watch is off its last value stays in the status
    s1 = state()
    v0, v1 = s0["video"], s1["video"]
    med = lambda xs: round(statistics.median([x for x in xs if x is not None]), 2) if any(x is not None for x in xs) else None
    return {"seconds": seconds, "pi_cpu_percent": med(cpu), "pi_temp_c": med(temp), "pi_cpu_mhz": med(mhz), "camera_fps": med(fps),
            "seal_us_per_chunk": med(seal), "motion_ms_per_look": med(ms), "frames": v1["frames_complete"] - v0["frames_complete"],
            "frames_lost": v1["frames_lost"] - v0["frames_lost"], "cpu_samples": [c for c in cpu if c is not None]}


def timed_ops(n):
    """Handshake, cached rekey and ratchet, timed on the UAV (as in the link measurements)."""
    out = {}
    for cmd in ("full_handshake", "cached_rekey", "pq_ratchet"):
        ms = []
        for _ in range(n):
            r = post(cmd, {"wait": True, "tag": "motion-cost"}, timeout=20)
            v = (r.get("result") or {}) if r.get("ok") else {}
            if isinstance(v.get("ms"), (int, float)):
                ms.append(v["ms"])
            # as far apart as in the link measurements: a PQ ratchet asked for within half a second of the one before
            # is answered only when the UAV repeats its request (seen: 450 ms instead of 14, for every one but the first)
            time.sleep(1.2)
        out[cmd] = {"runs": len(ms), "median_ms": round(statistics.median(ms), 2) if ms else None, "ms": ms}
    return out


def cost(a):
    was = cam_motion()
    if not was.get("available"):
        sys.exit("the UAV reports no motion watch")
    rounds = []
    try:
        for i in range(a.rounds):
            for on in (False, True) if i % 2 == 0 else (True, False):        # alternate the order: drift does not favour one
                post("motion", {"enabled": on})
                time.sleep(6)
                row = {"watch": on, **sample(a.seconds), **({"ops": timed_ops(a.ops)} if a.ops else {})}
                rounds.append(row)
                print(f"watch {'ON ' if on else 'OFF'}: Pi CPU {row['pi_cpu_percent']} % at {row['pi_cpu_mhz']} MHz, camera {row['camera_fps']} fps, "
                      f"{row['frames_lost']} of {row['frames']} frames lost, sealing {row['seal_us_per_chunk']} us/chunk, look {row['motion_ms_per_look']} ms"
                      + (f", handshake {row['ops']['full_handshake']['median_ms']} ms" if a.ops else ""), flush=True)
    finally:
        post("motion", {"enabled": bool(was.get("enabled"))})
    s = state()
    cam = (s.get("uav") or {}).get("camera") or {}
    return {**provenance("cost of the watch on the UAV, switched off and on in turns"), "camera": {k: cam.get(k) for k in ("mode", "width", "height", "fps", "bitrate_target", "live")},
            "watch": {k: cam_motion(s).get(k) for k in ("hz", "sensitivity", "lores")}, "cpu_note": "share of all four cores, as the UAV reports it", "rounds": rounds}


def quiet(a):
    for _ in range(20):                                      # the UAV's status is a second or two behind a change of settings
        m0 = cam_motion()
        if m0.get("watching"):
            break
        time.sleep(1)
    else:
        sys.exit("the watch is not watching (start the live video or sentry)")
    g0, t0 = state().get("motion") or {}, time.time()
    time.sleep(a.minutes * 60)
    s = state()
    m1, g1 = cam_motion(s), s.get("motion") or {}
    d = lambda k: (m1.get(k) or 0) - (m0.get(k) or 0)
    out = {**provenance("the real scene as it was (nobody was asked to keep still or to move)"), "minutes": round((time.time() - t0) / 60, 2),
           "looks": d("looks"), "looks_with_motion": d("looks_with_motion"), "movements": d("events"), "scene_changes": d("scene_changes"),
           "reports_received": (g1.get("reports") or 0) - (g0.get("reports") or 0), "errors": d("errors"),
           "camera": {k: ((s.get("uav") or {}).get("camera") or {}).get(k) for k in ("mode", "lux", "gain", "exposure_us", "fps")},
           "watch": {k: m1.get(k) for k in ("hz", "hz_measured", "sensitivity", "ms", "ms_max")}}
    print(json.dumps({k: v for k, v in out.items() if k not in ("what", "tool")}))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("synthetic", synthetic), ("camera", camera), ("cost", cost), ("quiet", quiet)):
        p = sub.add_parser(name)
        p.set_defaults(fn=fn)
        p.add_argument("--out", required=True)
    sub.choices["synthetic"].add_argument("--seeds", type=int, default=8)
    sub.choices["camera"].add_argument("--captures", type=int, default=3)
    sub.choices["cost"].add_argument("--rounds", type=int, default=4)
    sub.choices["cost"].add_argument("--seconds", type=int, default=30)
    sub.choices["cost"].add_argument("--ops", type=int, default=0, help="also time this many handshakes / rekeys / ratchets in each stretch")
    sub.choices["quiet"].add_argument("--minutes", type=float, default=5)
    a = ap.parse_args()
    out = a.fn(a)
    Path(a.out).write_text(json.dumps(out, indent=1) + "\n")
    print(f"written: {a.out}")


if __name__ == "__main__":
    main()
