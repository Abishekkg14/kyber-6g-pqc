"""Plots 21 and 22: the motion watch, and what is proved under which attacker.

    motion_synthetic.json                         generated scenes (kyber6g.tools.motion_bench synthetic): SIMULATED
    motion_camera_normal.json, _night.json        the UAV's camera, targets drawn into its pictures on the UAV: MEASURED
    motion_cost.json, motion_quiet.json           what the watch costs the UAV; the real scene as it was: MEASURED
    ../../formal/results.json                     every ProVerif run (formal/run.py)
    pq_conformance_pi.json, _laptop.json          NIST's known-answer vectors on both machines

As everywhere in these plots: measured in colour, simulated in black and grey, and no number is typed in here.
"""
import json
import statistics

from matplotlib.gridspec import GridSpec
from matplotlib.ticker import FixedLocator, FuncFormatter, NullFormatter

import plotlib as pl
from plotlib import INK, INK2, MUTED, NEUTRAL, SERIES, W2, plt

SIM = pl.SIMULATED                          # generated scenes: the greys


def load(name):
    p = pl.DATA / f"{name}.json"
    return json.loads(p.read_text()) if p.exists() else None


def share(r):
    return 100.0 * r["hits"] / r["looks_with_target"] if r.get("looks_with_target") else None


def sim_series(d, name):
    rows = [r for r in d["rows"] if r["series"] == name]
    return [r["x"] for r in rows], [share(r) for r in rows], rows


def cam_points(d, key, fixed, sensitivity="medium"):
    """Rows of a camera file that vary `key` and hold the other settings at `fixed`:
    (x, median share over the captures, row of the totals, lowest share, highest share)."""
    out = []
    for i, r in enumerate((d or {}).get("rows", [])):
        c = r["case"]
        if c.get("target") is False or c.get("pan") or c.get("sensitivity", "medium") != sensitivity or not r.get("looks_with_target"):
            continue
        if all(c.get(k) == v for k, v in fixed.items()) and key in c:
            each = [share(pc[i]) for pc in d.get("per_capture", []) if pc[i].get("looks_with_target")] or [share(r)]
            out.append((c[key], statistics.median(each), r, min(each), max(each)))
    return sorted(out, key=lambda t: t[0])


def motion_watch():
    syn, cost, quiet = load("motion_synthetic"), load("motion_cost"), load("motion_quiet")
    cams = [(m, load(f"motion_camera_{m}")) for m in ("normal", "night")]
    cams = [(m, d) for m, d in cams if d and d.get("captures_used")]
    if not syn:
        return {"skipped": "no motion_synthetic.json (bash run/kyber6g.sh measure motion)"}
    fig = plt.figure(figsize=(W2 * pl.MM, 124 * pl.MM))
    fig._k6g_bars = []
    gs = GridSpec(2, 3, figure=fig, width_ratios=[1, 1, 1.18])
    table = []

    def curves(ax, letter, title, xlabel, names, cam_key, cam_fixed, log=True, ticks=None):
        for i, (name, label) in enumerate(names):
            x, y, rows = sim_series(syn, name)
            ax.plot(x, y, color=SIM[i], marker=pl.MARKERS[i], linestyle=pl.DASHES[i], markeredgecolor="white", label=label)
            table.extend([letter, "generated scene: " + label, r["x"], r["looks_with_target"], r["hits"], round(share(r), 1), r["false_regions"]] for r in rows)
        for j, (mode, d) in enumerate(cams):
            pts = cam_points(d, cam_key, cam_fixed)
            if pts:
                lux = statistics.median([c.get("lux") or 0 for c in d["conditions"]])
                lab = f"UAV camera, {mode.upper()} ({lux:.0f} lux)"
                # the median of the captures, and a thin line over their range: the scene is real and not controlled
                off = (-0.018, 0.018)[j] if log else (-0.05, 0.05)[j]          # the two modes side by side, not on top of each other
                xs = [p[0] * (10 ** off) if log else p[0] + off for p in pts]
                ax.vlines(xs, [p[3] for p in pts], [p[4] for p in pts], color=pl.tint(SERIES[j], 0.55), linewidth=1.0, zorder=2.5)
                ax.plot(xs, [p[1] for p in pts], color=SERIES[j], marker=pl.MARKERS[j + 2], linestyle="none", markersize=5.2, label=lab, zorder=3)
                table.extend([letter, lab, p[0], p[2]["looks_with_target"], p[2]["hits"], round(share(p[2]), 1), p[2]["false_regions"], round(p[1], 1), round(p[3], 1), round(p[4], 1)] for p in pts)
        if log:
            ax.set_xscale("log")
            ax.xaxis.set_major_locator(FixedLocator(ticks))
            ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
            ax.xaxis.set_minor_formatter(NullFormatter())
        ax.set_ylim(-4, 104)
        ax.yaxis.set_major_locator(FixedLocator([0, 25, 50, 75, 100]))
        ax.set_xlabel(xlabel)
        ax.set_ylabel("Looks in which it is found (%)")
        pl.panel(ax, letter, title)

    a = fig.add_subplot(gs[0, 0])
    curves(a, "a", "By contrast", "Contrast of the target (grey levels of 255)",
           [("contrast, day noise", "day noise"), ("contrast, night noise", "night noise")], "contrast", {"size": 8, "speed": 2}, ticks=[3, 6, 12, 25, 40])
    b = fig.add_subplot(gs[0, 1])
    curves(b, "b", "By size", "Width of the target (pixels of 320)",
           [("size, day noise", "day noise"), ("size, night noise", "night noise")], "size", {"contrast": 25, "speed": 2}, ticks=[3, 4, 6, 8, 12, 16])
    b.legend(loc="lower right", handlelength=1.8)                # the one legend of (a) to (c): this corner is the only free one
    c = fig.add_subplot(gs[1, 0])
    curves(c, "c", "By speed", "Speed of the target (pixels per look)", [("speed", "day noise")], "speed", {"size": 8, "contrast": 25}, ticks=[0.1, 0.4, 1.5, 6])
    d = fig.add_subplot(gs[1, 1])
    for i, (name, label) in enumerate((("pan", "camera pans"), ("pan + turn", "pans and turns 0.3°"))):
        x, y, rows = sim_series(syn, name)
        d.plot(x, y, color=SIM[i], marker=pl.MARKERS[i], linestyle=pl.DASHES[i], markeredgecolor="white", label=label)
        table.extend(["d", "generated scene: " + label, r["x"], r["looks_with_target"], r["hits"], round(share(r), 1), r["false_regions"]] for r in rows)
    quiet_pan = [r for r in syn["rows"] if r["series"] == "pan, no target"]
    d.set_ylim(-4, 104)
    d.yaxis.set_major_locator(FixedLocator([0, 25, 50, 75, 100]))
    d.xaxis.set_major_locator(FixedLocator([0, 1, 2, 4, 8, 12]))
    d.set_xlabel("Movement of the camera (pixels per look)")
    d.set_ylabel("Looks in which it is found (%)")
    d.legend(loc="lower left", handlelength=2.2)
    pl.panel(d, "d", "While the camera moves")
    fr, lk = sum(r["false_regions"] for r in quiet_pan), sum(r["looks"] for r in quiet_pan)
    table.extend(["d", "generated scene: camera pans, nothing moves", r["x"], 0, 0, "", r["false_regions"]] for r in quiet_pan)

    # the two text panels: what is reported when nothing moves, and what the watch costs
    e = fig.add_subplot(gs[0, 2])
    e.axis("off")
    pl.panel(e, "e", "Nothing moves: regions reported")
    still = [r for r in syn["rows"] if r["series"].startswith("nothing moves")]
    labels = list(dict.fromkeys(r["label"] for r in still))
    y = 0.955
    pl.note(e, 0.0, y, "Generated scene", color=INK, transform=e.transAxes, weight="bold")
    pl.note(e, 0.80, y, "medium", ha="right", color=INK, transform=e.transAxes, weight="bold")
    pl.note(e, 1.0, y, "high", ha="right", color=INK, transform=e.transAxes, weight="bold")
    for lab in labels:
        y -= 0.066
        cells = {r["series"].split(", ")[1]: r for r in still if r["label"] == lab}
        pl.note(e, 0.0, y, lab, color=INK2, transform=e.transAxes, size=pl.FS_MIN)
        for xpos, lev in ((0.80, "medium"), (1.0, "high")):
            r = cells.get(lev)
            pl.note(e, xpos, y, f"{r['false_regions']} in {r['looks']}" if r else "", ha="right", color=INK, transform=e.transAxes, size=pl.FS_MIN)
            if r:
                table.append(["e", f"generated scene, nothing moves, sensitivity {lev}: {lab}", "", 0, 0, "", r["false_regions"]])
    y -= 0.085
    lines = [f"Camera pans (d), nothing moves: {fr} in {lk} looks."]
    for mode, dd in cams:
        r = dd["rows"][0]
        lines.append(f"UAV camera, {mode.upper()}, nothing drawn in: {r['false_regions']} in {r['looks']} looks*")
        table.append(["e", f"UAV camera, {mode.upper()} mode, no target drawn in (real scene, not controlled)", "", 0, 0, "", r["false_regions"]])
    if quiet:
        lines.append(f"The scene left to itself for {quiet['minutes']:.0f} min: {quiet['movements']} movements,\n{quiet['looks_with_motion']:,} of {quiet['looks']:,} looks with a region*")
    if cams or quiet:
        lines.append("* a lit room with people in it: what moved there,\nor a false alarm; the pictures cannot be kept to tell.")
    pl.note(e, 0.0, y, "\n".join(lines), va="top", color=INK2, transform=e.transAxes, size=pl.FS_MIN, linespacing=1.3)

    f = fig.add_subplot(gs[1, 2])
    f.axis("off")
    pl.panel(f, "f", "What the watch costs the UAV")
    rows_cost = []
    if cost:
        med = lambda on, key: statistics.median([r[key] for r in cost["rounds"] if r["watch"] is on and r.get(key) is not None] or [float("nan")])
        tot = lambda on, key: sum(r[key] for r in cost["rounds"] if r["watch"] is on)
        ops = lambda on, op: statistics.median([v for r in cost["rounds"] if r["watch"] is on for v in (r.get("ops") or {}).get(op, {}).get("ms", [])] or [float("nan")])
        rows_cost = [("Median of the stretches", "off", "on"),
                     ("Pi CPU, all four cores (%)", f"{med(False, 'pi_cpu_percent'):.1f}", f"{med(True, 'pi_cpu_percent'):.1f}"),
                     ("Processor clock (MHz)**", f"{med(False, 'pi_cpu_mhz'):.0f}", f"{med(True, 'pi_cpu_mhz'):.0f}"),
                     ("Camera frames per second", f"{med(False, 'camera_fps'):.1f}", f"{med(True, 'camera_fps'):.1f}"),
                     ("Video frames lost", f"{tot(False, 'frames_lost')} of {tot(False, 'frames'):,}", f"{tot(True, 'frames_lost')} of {tot(True, 'frames'):,}"),
                     ("AES-GCM per video chunk (µs)", f"{med(False, 'seal_us_per_chunk'):.0f}", f"{med(True, 'seal_us_per_chunk'):.0f}")]
        if any(r.get("ops") for r in cost["rounds"]):
            rows_cost += [("Full handshake at the UAV (ms)", f"{ops(False, 'full_handshake'):.1f}", f"{ops(True, 'full_handshake'):.1f}"),
                          ("1-RTT Cached RapidRekey (ms)", f"{ops(False, 'cached_rekey'):.1f}", f"{ops(True, 'cached_rekey'):.1f}"),
                          ("PQ ratchet (ms)", f"{ops(False, 'pq_ratchet'):.1f}", f"{ops(True, 'pq_ratchet'):.1f}")]
        y = 0.955
        for i, row in enumerate(rows_cost):
            w = "bold" if i == 0 else "normal"
            pl.note(f, 0.0, y, row[0], color=INK, transform=f.transAxes, weight=w, size=pl.FS_MIN if i else pl.FS_NOTE)
            pl.note(f, 0.76, y, row[1], ha="right", color=INK, transform=f.transAxes, weight=w, size=pl.FS_MIN if i else pl.FS_NOTE)
            pl.note(f, 1.0, y, row[2], ha="right", color=INK, transform=f.transAxes, weight=w, size=pl.FS_MIN if i else pl.FS_NOTE)
            y -= 0.066
        w = cost["watch"]
        cam = cost["camera"]
        n_on = sum(r["watch"] for r in cost["rounds"])
        n_cap = max((len(dd.get("per_capture", [])) for _, dd in cams), default=0)
        pl.note(f, 0.0, y - 0.012,
                f"One look: {med(True, 'motion_ms_per_look'):.0f} ms, {w['hz']:g} a second, {w['lores'][0]} × {w['lores'][1]} pixels, beside\nvideo of "
                f"{cam['width']} × {cam['height']}. Off and on in turns, {n_on} stretches of {cost['rounds'][0]['seconds']} s each.\n"
                "** with the watch on, the Pi's governor raises the clock:\nthat is why the other work gets quicker, not slower.\n"
                "(a) to (c): target 8 pixels wide, contrast 25, 2 pixels per look\nunless varied. Grey: generated scenes. Colour: the UAV's\n"
                f"camera, targets drawn in on the UAV; median of {n_cap} captures,\nthin line: their range.",
                va="top", color=INK2, transform=f.transAxes, size=pl.FS_MIN, linespacing=1.25)
    else:
        pl.note(f, 0.0, 0.9, "not measured (measure motion)", color=INK2, transform=f.transAxes)
    pl.save(fig, "plot21_motion_watch")
    pl.table("plot21_motion_watch", ["panel", "series", "x", "looks_with_target", "hits", "found_pct", "false_regions", "found_pct_median_of_captures",
                                     "found_pct_lowest_capture", "found_pct_highest_capture"], [r + [""] * (10 - len(r)) for r in table])
    if rows_cost:
        pl.table("plot21_motion_cost", ["quantity", "watch_off", "watch_on"], [list(r) for r in rows_cost[1:]])
    return {"cases": len(table), "camera_modes": [m for m, _ in cams], "false_regions_camera_pans": fr}


# what the rows of the matrix are: (group, label, model, leak library, indexes of the queries that make up the claim)
CLAIMS = [
    ("Full handshake", "Session data secret (also after both signing keys leak)", "handshake", None, [0, 1]),
    ("Full handshake", "Ground station knows it talks to the UAV", "handshake", None, [2]),
    ("Full handshake", "UAV knows it talks to the ground station", "handshake", None, [3]),
    ("1-RTT Cached RapidRekey", "New keys secret and agreed", "cached_rekey", "leak_none", [0, 1, 2, 3]),
    ("1-RTT Cached RapidRekey", "... also if the next secret leaks afterwards", "cached_rekey", "leak_next", [0, 1, 2, 3]),
    ("1-RTT Cached RapidRekey", "... if the old secret had leaked before", "cached_rekey", "leak_before", [0, 1, 2, 3]),
    ("PQ ratchet", "New keys secret and agreed", "pq_ratchet", "leak_none", [0, 1, 2]),
    ("PQ ratchet", "... also if the old master secret leaks afterwards", "pq_ratchet", "leak_next", [0, 1, 2]),
    ("PQ ratchet", "Old secret leaked before, attacker listens: heals", "pq_ratchet_passive", None, [0, 1]),
    ("PQ ratchet", "Old secret leaked before, attacker active", "pq_ratchet_active", None, [0, 1]),
    ("Stored photo, recording, audio", "Content secret", "sealed_file", "file_leak_none", [0]),
    ("Stored photo, recording, audio", "... also if the UAV is captured afterwards", "sealed_file", "file_leak_uav", [0]),
    ("Stored photo, recording, audio", "... also if the ML-KEM recording key is stolen", "sealed_file", "file_leak_kem", [0]),
    ("Stored photo, recording, audio", "... also if the X25519 recording key is stolen", "sealed_file", "file_leak_x", [0]),
    ("Stored photo, recording, audio", "... if both recording keys are stolen", "sealed_file", "file_leak_both", [0]),
    ("Stored photo, recording, audio", "What is opened was sealed by the pinned UAV", "sealed_file", "file_leak_none", [1]),
]
ATTACKERS = [("classical", "breaks\nnothing"), ("shor", "X25519\nbroken"), ("mlkem", "ML-KEM\nbroken"), ("both", "both\nbroken")]
STEP = 1.3                                  # distance between the attackers' columns, in the units the claims are written in


def proof_matrix():
    p = pl.ROOT.parent / "formal" / "results.json"
    if not p.exists():
        return {"skipped": "no formal/results.json (bash run/kyber6g.sh formal)"}
    res = json.loads(p.read_text())
    runs = {(r["model"], r["leak"], r["attacker"]): r for r in res["runs"]}
    conf = [(n, load(f"pq_conformance_{n}")) for n in ("pi", "laptop")]
    fig = plt.figure(figsize=(W2 * pl.MM, 117 * pl.MM))
    fig._k6g_bars = []
    gs = GridSpec(1, 2, figure=fig, width_ratios=[1.62, 1])
    ax = fig.add_subplot(gs[0, 0])
    ax.grid(False)
    for s in ("left", "bottom"):
        ax.spines[s].set_visible(False)
    n = len(CLAIMS)
    table, proved, attacks, ypos, y, last = [], 0, 0, [], 0.0, None
    for group, label, model, leak, idx in CLAIMS:
        if group != last:
            y += 0.75 if last else 0.0
            pl.note(ax, -0.5, y, group, color=INK, weight="bold", ha="right")
            y += 1.0
            last = group
        ypos.append(y)
        pl.note(ax, -0.5, y, label, color=INK2, ha="right", size=pl.FS_MIN)
        for j, (att, _) in enumerate(ATTACKERS):
            r = runs.get((model, leak, att))
            if r is None:
                table.append([group, label, att, "not run (the attack exists with nothing broken)"])
                continue
            ok = all(r["queries"][i]["result"] is True for i in idx)
            fail = any(r["queries"][i]["result"] is False for i in idx)
            if ok:
                ax.plot([j * STEP], [y], marker="o", markersize=6.0, color=SERIES[0], markeredgecolor="white", linestyle="none")
                proved += 1
            elif fail:
                ax.plot([j * STEP], [y], marker="X", markersize=6.2, color=SERIES[1], markeredgecolor="white", linestyle="none")
                attacks += 1
            table.append([group, label, att, "proved" if ok else "attack found" if fail else "not decided"])
        y += 1.0
    ax.set_xlim(-9.4, (len(ATTACKERS) - 1) * STEP + 0.6)     # the claims are written inside the axes, left of the columns
    ax.set_ylim(y + 1.9, -0.7)
    ax.set_xticks([j * STEP for j in range(len(ATTACKERS))])
    ax.set_xticklabels([lab for _, lab in ATTACKERS])
    ax.xaxis.tick_top()
    ax.tick_params(axis="x", length=0, pad=1)
    ax.set_yticks([])
    for j in range(len(ATTACKERS)):
        ax.plot([j * STEP, j * STEP], [min(ypos) - 0.5, max(ypos) + 0.5], color=pl.GRID, lw=0.45, zorder=0)
    pl.panel(ax, "a", "What ProVerif proves, attacker by attacker")
    ax.plot([], [], marker="o", markersize=6.0, color=SERIES[0], markeredgecolor="white", linestyle="none", label="proved")
    ax.plot([], [], marker="X", markersize=6.2, color=SERIES[1], markeredgecolor="white", linestyle="none", label="attack found, as it must be")
    ax.legend(loc="lower left", ncol=2, handlelength=1.2, columnspacing=1.8)

    b = fig.add_subplot(gs[0, 1])
    b.axis("off")
    pl.panel(b, "b", "The libraries against NIST's vectors")
    s = res["summary"]
    yy = 0.955
    have = [(nm, d) for nm, d in conf if d]
    if have:
        groups = have[0][1]["groups"]
        pl.note(b, 0.0, yy, "Known-answer test", color=INK, transform=b.transAxes, weight="bold")
        for k, (nm, _) in enumerate(have):
            pl.note(b, 1.0 - 0.17 * (len(have) - 1 - k), yy, "Pi" if nm == "pi" else "laptop", ha="right", color=INK, transform=b.transAxes, weight="bold")
        ctab = []
        for gi, g in enumerate(groups):
            yy -= 0.052
            pl.note(b, 0.0, yy, g["name"].replace(" (crypto/keyschedule.py)", ""), color=INK2, transform=b.transAxes, size=pl.FS_MIN)
            row = [g["name"], g["what"], g["vectors"]]
            for k, (nm, dd) in enumerate(have):
                gg = dd["groups"][gi]
                pl.note(b, 1.0 - 0.17 * (len(have) - 1 - k), yy, f"{gg['passed']}/{gg['vectors']}", ha="right", color=INK, transform=b.transAxes, size=pl.FS_MIN)
                row.append(gg["passed"])
            ctab.append(row)
        pl.table("plot22_known_answers", ["test", "what", "vectors"] + [f"passed_{nm}" for nm, _ in have], ctab)
        d0 = have[0][1]
        yy -= 0.075
        tail = (f"All {d0['vectors']} pass on both: {d0['passed'] == d0['vectors'] and all(dd['all_passed'] for _, dd in have)}.\n".replace("True", "yes").replace("False", "NO")
                + f"liboqs {d0['liboqs']}: ML-KEM-1024 as \"{d0['algorithms']['ML-KEM-1024']['version']}\",\nML-DSA-87 as \"{d0['algorithms']['ML-DSA-87']['version']}\"; "
                + f"{d0['openssl'].split()[0]} {d0['openssl'].split()[1]}.\n")
    else:
        tail = "Known-answer tests: not measured (measure pq).\n"
    tail += (f"(a): {s['runs']} ProVerif runs, {s['queries']} queries in {s['seconds']:.0f} s. A dot is a\nclaim that holds for any number of sessions; a cross is\n"
             "the same claim with the decisive scheme broken or key\nleaked, where the attack must be, and is, found.\n"
             "No mark: not run, because the attack found with nothing\nbroken exists all the more with something broken.\n"
             "Symbolic model: ideal primitives, no timing, no sizes.")
    pl.note(b, 0.0, yy, tail, va="top", color=INK2, transform=b.transAxes, size=pl.FS_MIN, linespacing=1.3)
    pl.save(fig, "plot22_proof_matrix")
    pl.table("plot22_proof_matrix", ["protocol", "claim", "attacker", "result"], table)
    return {"proved": proved, "attacks_found": attacks, "runs": s["runs"], "queries": s["queries"]}


PLOTS = {"motion_watch": motion_watch, "proof_matrix": proof_matrix}
