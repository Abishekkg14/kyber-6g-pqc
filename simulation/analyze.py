#!/usr/bin/env python3
"""Tables and plots of the simulation studies (results/raw, written by run_sweep.py).

    python simulation/analyze.py [name ...]        (no name: everything there is data for)

Reads every run of results/raw (one process' output each: operations `O`, video per UAV `V`, the run `M`), groups the
runs by what their own `M` line says they were, and writes
    paper_plots/exported_{pdf,eps,png}/plot11..16_*   the figures, in the style of the measured plots (plotlib.py)
    paper_plots/tables/plot11..16_*.csv               the numbers every figure shows
    simulation/results/summary.json                   headline numbers and the checks below
Nothing here contains a result: a number in a figure is computed from the raw files, a measured number from
paper_plots/data.

Checks made on the results before anything is drawn (summary.json, "checks"; a failed one is printed):
  * every run of the manifest finished and its file is complete;
  * the results were all made with one calibration and one simulator source;
  * no UAV's uplink went silent during a run (the fault the retxBSR patch removes, see README.md);
  * every UAV got its first session.

Simulated values are SIMULATED: every figure title says so, and the NR cell is a model, not a measurement.
"""
import collections
import json
import math
import re
import statistics as st
import sys
from pathlib import Path

SIM = Path(__file__).resolve().parent
REPO = SIM.parent
RAW = SIM / "results" / "raw"
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "paper_plots" / "scripts"))

import numpy as np                                               # noqa: E402
from matplotlib.gridspec import GridSpec                         # noqa: E402
from matplotlib.ticker import FixedLocator, FuncFormatter, MultipleLocator, NullLocator   # noqa: E402

import plotlib as pl                                             # noqa: E402
from plotlib import INK, INK2, MUTED, NEUTRAL, SERIES, W1, W2, plt  # noqa: E402

Op = collections.namedtuple("Op", "uav kind initial t0 ok total build wait proc fin gcs tx why")
Vid = collections.namedtuple("Vid", "uav sent complete decoded lost chunks keyreq dist chunks_sent last_rx cell_changes")
KINDS = [("full", "Full handshake"), ("cached", "Cached rekey"), ("ratchet", "PQ ratchet")]
MEASURED_OP = {"full": "full_handshake", "cached": "cached_rekey", "ratchet": "pq_ratchet"}
PROFILES = [("classical", "X25519,\nEd25519"), ("hybrid1", "ML-KEM-512\n+ X25519,\nML-DSA-44"), ("hybrid3", "ML-KEM-768\n+ X25519,\nML-DSA-65"),
            ("pq5", "ML-KEM-1024\nalone,\nML-DSA-87"), ("hybrid5", "ML-KEM-1024\n+ X25519,\nML-DSA-87")]
SIMNOTE = "simulated"


# ------------------------------------------------------------------------------------------------------- data
def read_run(path):
    ops, vid, meta = [], [], None
    with open(path) as fh:
        for line in fh:
            c = line[:2]
            if c == "O,":
                f = line.rstrip("\n").split(",")
                if len(f) >= 15:
                    ops.append(Op(int(f[1]), f[3], int(f[4]), float(f[5]), f[6] == "1", float(f[7]), float(f[8]), float(f[9]), float(f[10]),
                                  float(f[11]), float(f[12]), int(f[13]), f[14]))
            elif c == "V,":
                f = line.rstrip("\n").split(",")
                if len(f) >= 12:
                    vid.append(Vid(int(f[1]), int(f[2]), int(f[3]), int(f[4]), int(f[5]), int(f[6]), int(f[7]), float(f[8]), int(f[9]), float(f[10]), int(f[11])))
            elif c == "M,":
                meta = {}
                for kv in line.rstrip("\n").split(",")[1:]:
                    k, _, v = kv.partition("=")
                    try:
                        meta[k] = float(v) if re.fullmatch(r"-?[\d.]+(e[+-]?\d+)?", v) else v
                    except ValueError:
                        meta[k] = v
    return {"ops": ops, "vid": vid, "meta": meta}


_RUNS = {}


def runs(prefix):
    """All complete runs whose name starts with `prefix`: list of (name, run)."""
    if not _RUNS:
        for p in sorted(RAW.glob("*.csv")):
            _RUNS[p.stem] = None
    out = []
    for name in _RUNS:
        if name.startswith(prefix):
            if _RUNS[name] is None:
                _RUNS[name] = read_run(RAW / f"{name}.csv")
                _RUNS[name]["name"] = name
            if _RUNS[name]["meta"]:
                out.append((name, _RUNS[name]))
    return out


_MANIFEST = {}


def arg(r, key, default=None):
    """An argument the run was started with (the manifest of run_sweep.py), for what its own `M` line does not repeat."""
    if not _MANIFEST:
        mp = SIM / "results" / "manifest.json"
        _MANIFEST.update(json.loads(mp.read_text()) if mp.exists() else {"_": {}})
    return ((_MANIFEST.get(r.get("name")) or {}).get("args") or {}).get(key, default)


def group(rs, key):
    g = collections.defaultdict(list)
    for name, r in rs:
        g[key(name, r)].append(r)
    return dict(sorted(g.items()))


def q(v, p):
    v = sorted(v)
    return pl.pct(v, p) if v else float("nan")


def planned(rs, kind, initial=0):
    return [o for r in rs for o in r["ops"] if o.kind == kind and o.initial == initial]


def frames(rs):
    """(complete %, decoded %) of the frames judged, per run."""
    out = []
    for r in rs:
        c, l, d = sum(v.complete for v in r["vid"]), sum(v.lost for v in r["vid"]), sum(v.decoded for v in r["vid"])
        if c + l:
            out.append((100 * c / (c + l), 100 * d / (c + l)))
    return out


def delivered(rs, tail=6):
    """(complete %, given to the decoder %) of the frames SENT, per run. In a cell that carries its load this equals
    frames(); in an overloaded one most frames never reach the ground station at all (they wait in the UAV's queue or are
    dropped from it) and are in neither of the receiver's counts, so frames() would call the little that arrives
    "nearly all". A frame sent and never accounted for counts as not delivered here, except the last `tail` frames of
    each UAV (200 ms at 30 frames a second): those are still on their way, or inside the receiver's waiting window,
    when the run ends."""
    out = []
    for r in rs:
        c, d = sum(v.complete for v in r["vid"]), sum(v.decoded for v in r["vid"])
        den = sum(v.complete + v.lost + max(0, v.sent - v.complete - v.lost - tail) for v in r["vid"])
        if den:
            out.append((100 * c / den, 100 * d / den))
    return out


def stalled(r):
    """UAVs whose video stopped arriving more than a second before the end of the run."""
    sim = r["meta"].get("simTime", 0)
    return sum(1 for v in r["vid"] if v.sent > 60 and v.last_rx < sim - 1.0)


def measured(name):
    p = REPO / "paper_plots" / "data" / f"{name}.json"
    return json.loads(p.read_text()) if p.exists() else None


def rate(d):
    return (d.get("clock") or {}).get("local_per_reference_second") or 1.0


def stat_row(v):
    v = sorted(v)
    if not v:
        return ["", "", "", ""]
    return [round(pl.pct(v, 5), 2), round(st.median(v), 2), round(pl.pct(v, 95), 2), round(v[-1], 2)]


def band(ax, xs, groups, i, label, dodge=0.0, value=lambda o: o.total, log=False, line=True):
    """Median with a marker and a 5th-95th percentile range at every x, in the style of series i; the medians are
    joined by a line where x is a quantity (line=False where x is a list of separate things)."""
    px, med, lo, hi = [], [], [], []
    for x, sample in zip(xs, groups):
        v = sorted(value(o) for o in sample)
        if v:
            px.append(x * (1 + dodge) if log else x + dodge); med.append(st.median(v)); lo.append(pl.pct(v, 5)); hi.append(pl.pct(v, 95))
    ax.vlines(px, lo, hi, color=pl.tint(SERIES[i], 0.45), lw=1.0, zorder=2)
    style = pl.series(i) if line else {**pl.series(i), "linestyle": "none"}
    ax.plot(px, med, **style, label=label, zorder=3)
    return max(hi) if hi else 0


def ms_axis(ax, lo, hi):
    ax.set_yscale("log")
    ax.set_ylim(lo, hi)
    ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}" if v >= 1 else f"{v:g}"))
    ax.yaxis.set_minor_formatter(FuncFormatter(lambda v, _: ""))


# ------------------------------------------------------------------------------------------------- 11 validation
def validation():
    noloss = [r for _, r in runs("val_noloss")]
    lossy = group(runs("val_loss"), lambda n, r: r["meta"]["loss"])
    ops, loss = measured("link_ops"), measured("loss")
    if not noloss or not ops:
        return None
    fig = plt.figure(figsize=(W2 * pl.MM, 126 * pl.MM))
    fig._k6g_bars = []
    gs = GridSpec(2, 6, figure=fig, height_ratios=[1.05, 1])
    a, b = fig.add_subplot(gs[0, :3]), fig.add_subplot(gs[0, 3:])
    low = [fig.add_subplot(gs[1, 0:2]), fig.add_subplot(gs[1, 2:4]), fig.add_subplot(gs[1, 4:6])]
    tab, out = [], {"operations_without_loss": {}}

    # (a) the three operations without loss: measured (150 each) against simulated
    xmax, medians = 0, ["Medians, measured / simulated:"]
    for i, (kind, label) in enumerate(KINDS):
        m = sorted(r["uav_ms"] for r in ops["rows"] if r["op"] == MEASURED_OP[kind] and r["ok"])
        s = sorted(o.total for o in planned(noloss, kind) if o.ok)
        x, y = pl.ecdf(m)
        a.plot(x, y, drawstyle="steps-post", color=SERIES[i], linestyle=pl.DASHES[i], marker="none", lw=1.6, label=f"{label}, measured")
        x, y = pl.ecdf(s)
        a.plot(x, y, drawstyle="steps-post", color=INK, linestyle="-", marker="none", lw=0.6, zorder=4, label="Simulated (thin line beside each)" if i == 2 else None)
        medians.append(f"{label if label.startswith('PQ') else label[0].lower() + label[1:]} {st.median(m):.1f} / {st.median(s):.1f} ms")
        xmax = max(xmax, pl.pct(m, 98), pl.pct(s, 98))
        # largest vertical distance between the two distribution functions (Kolmogorov-Smirnov)
        grid = sorted(set(m) | set(s))
        ks = max(abs(np.searchsorted(m, g, side="right") / len(m) - np.searchsorted(s, g, side="right") / len(s)) for g in grid)
        tab.append(["no loss", label, "", len(m), *stat_row(m), len(s), *stat_row(s), round(100 * (st.median(s) / st.median(m) - 1), 1), round(ks, 3)])
        out["operations_without_loss"][kind] = {"measured_median_ms": round(st.median(m), 2), "simulated_median_ms": round(st.median(s), 2),
                                                "measured_p95_ms": round(pl.pct(m, 95), 2), "simulated_p95_ms": round(pl.pct(s, 95), 2), "ks_distance": round(ks, 3)}
    xr = np.ceil(xmax / 10) * 10 + 20                             # the curves end by xmax: the legend and the medians go to their right
    a.set_xlim(0, xr)
    a.set_ylim(0, 101)
    a.yaxis.set_major_locator(MultipleLocator(25))
    a.set_xlabel("Time to a new session (ms)")
    a.set_ylabel("Share of operations (%)")
    a.legend(loc="lower right", handlelength=2.2)
    pl.note(a, xr * 0.985, 72, "\n".join(medians), ha="right", va="top", linespacing=1.15)
    pl.panel(a, "a", "Session operations, no loss: measured and simulated")

    # (b) video under injected loss
    if loss and lossy:
        k = rate(loss)
        mx, mc, md = [], [], []
        for L in loss["levels"]:
            c0, c1, s0, s1 = L["counters_before"], L["counters_after"], L["before"], L["after"]
            p = 100 * (c1["drop-out"] - c0["drop-out"]) / max(c1["seen-out"] - c0["seen-out"], 1)
            fc, fl = s1["frames_complete"] - s0["frames_complete"], s1["frames_lost"] - s0["frames_lost"]
            skipped = (s1.get("frames_skipped_wait_key") or 0) - (s0.get("frames_skipped_wait_key") or 0)
            mx.append(p); mc.append(100 * fc / max(fc + fl, 1)); md.append(100 * (fc - skipped) / max(fc + fl, 1))
        sx = [100 * p for p in lossy]
        sc = [[f[0] for f in frames(rs)] for rs in lossy.values()]
        sd = [[f[1] for f in frames(rs)] for rs in lossy.values()]
        for vals, ls, lab in ((sc, "-", "Simulated: frames complete"), (sd, (0, (4.5, 1.6)), "Simulated: frames given to the decoder")):
            b.fill_between(sx, [min(v) for v in vals], [max(v) for v in vals], color=pl.tint(NEUTRAL, 0.45), lw=0, zorder=1)
            b.plot(sx, [st.fmean(v) for v in vals], color=INK, linestyle=ls, marker="none", lw=0.9, zorder=3, label=lab)
        b.plot(mx, mc, linestyle="none", marker=pl.MARKERS[0], color=SERIES[0], ms=5, zorder=5, label="Measured: frames complete")
        b.plot(mx, md, linestyle="none", marker=pl.MARKERS[1], color=SERIES[1], ms=4.6, zorder=5, label="Measured: frames given to the decoder")
        b.set_ylim(0, 104)
        b.set_xlim(-0.5, max(mx) * 1.05)
        b.xaxis.set_major_locator(MultipleLocator(5))
        b.yaxis.set_major_locator(MultipleLocator(25))
        b.set_xlabel("Datagrams dropped in each direction (%)")
        b.set_ylabel("Share of the frames (%)")
        b.legend(loc="upper right")
        pl.panel(b, "b", "Live video under loss: measured and simulated")
        out["video_under_loss"] = []
        for p, c, d in zip(mx, mc, md):
            j = min(range(len(sx)), key=lambda i: abs(sx[i] - p)) if sx else None
            if j is not None and abs(sx[j] - p) < 0.01 + 0.02 * p:
                tab.append([f"loss {p:.2f} %", "video frames complete (%)", "", "", "", round(c, 2), "", "", len(sc[j]), round(min(sc[j]), 2), round(st.fmean(sc[j]), 2),
                            round(max(sc[j]), 2), "", round(st.fmean(sc[j]) - c, 2), ""])
                tab.append([f"loss {p:.2f} %", "video frames given to the decoder (%)", "", "", "", round(d, 2), "", "", len(sd[j]), round(min(sd[j]), 2),
                            round(st.fmean(sd[j]), 2), round(max(sd[j]), 2), "", round(st.fmean(sd[j]) - d, 2), ""])
                out["video_under_loss"].append({"loss_pct": round(p, 2), "complete_measured": round(c, 1), "complete_simulated": round(st.fmean(sc[j]), 1),
                                                "decoder_measured": round(d, 1), "decoder_simulated": round(st.fmean(sd[j]), 1)})

        # (c)-(e) every operation of the measured loss experiment (dots) on the simulated distribution
        log = loss["uav_oplog"]
        out["operations_under_loss"] = []
        for i, ((kind, label), ax) in enumerate(zip(KINDS, low)):
            bx, lo, med, hi = [], [], [], []
            for p, rs in lossy.items():
                v = sorted(o.total for o in planned(rs, kind) if o.ok)
                if v:
                    bx.append(100 * p); lo.append(pl.pct(v, 5)); med.append(st.median(v)); hi.append(pl.pct(v, 95))
            ax.fill_between(bx, lo, hi, color=pl.tint(NEUTRAL, 0.45), lw=0, zorder=1, label="Simulated: 5th to 95th percentile")
            ax.plot(bx, med, color=INK, marker="none", lw=0.9, zorder=3, label="Simulated: median")
            first = True
            for L, p in zip(loss["levels"], mx):
                es = [e for e in log if e["tag"] == L["tag"] and e["kind"] == kind]
                okv = [e["ms"] for e in es if e["ok"]]
                if not p:
                    continue
                ax.plot([p] * len(okv), okv, linestyle="none", marker=pl.MARKERS[i], color=SERIES[i], ms=3.4, zorder=5, label="Measured: one operation" if first else None)
                first = False
                rs = min(lossy.items(), key=lambda kv: abs(100 * kv[0] - p))[1]
                so = planned(rs, kind)
                sv = sorted(o.total for o in so if o.ok)
                inside = sum(1 for v in okv if pl.pct(sv, 5) <= v <= pl.pct(sv, 95)) if sv else 0      # the band that is drawn
                tab.append([f"loss {p:.2f} %", label, "", len(es), *stat_row(okv), len(so), *stat_row(sv), "", ""])
                out["operations_under_loss"].append({"loss_pct": round(p, 2), "kind": kind, "measured_completed": f"{len(okv)}/{len(es)}",
                                                     "simulated_completed_pct": round(100 * len(sv) / max(len(so), 1), 1),
                                                     "measured_inside_the_simulated_5_to_95_band": f"{inside}/{len(okv)}"})
            ms_axis(ax, 3, 40000)                                 # room above the data for the legend of (c)
            ax.set_xlim(-0.8, max(mx) * 1.06)
            ax.xaxis.set_major_locator(MultipleLocator(5))
            ax.set_xlabel("Datagrams dropped (%)")
            if i == 0:
                ax.set_ylabel("Time to a new session (ms)")
                ax.legend(loc="upper left", handlelength=1.6)           # the same three things in (d) and (e)
            pl.panel(ax, "cde"[i], f"{label} under loss")
    pl.save(fig, "plot11_sim_validation")
    pl.table("plot11_sim_validation", ["condition", "quantity", "", "measured_n", "measured_p5", "measured_median", "measured_p95", "measured_max", "simulated_n",
                                       "simulated_p5", "simulated_median", "simulated_p95", "simulated_max", "median_difference_pct_or_points", "ks_distance"], tab)
    return out


# ------------------------------------------------------------------------------------------------------ 12 swarm
def swarm():
    by = group(runs("swarm_"), lambda n, r: (n.split("_")[1], int(r["meta"]["nUav"])))
    if not by:
        return None
    ns = sorted({n for _, n in by})
    fig, (a, b, c) = pl.figure(W2, 70, 1, 3, gridspec_kw={"width_ratios": [1, 1, 0.92]})
    tab, out = [], {}
    names = {"ul": "uplink-heavy cell (6 of 10 slots)", "dl": "downlink-heavy cell (3 of 10 slots)"}
    # a cell is beyond its uplink capacity where it does not carry what the UAVs offer (datagrams received / sent)
    carried = {k: 100 * sum(r["meta"]["upRecv"] for r in rs) / max(sum(r["meta"]["upSent"] for r in rs), 1) for k, rs in by.items()}
    xlim = (ns[0] * 0.8, ns[-1] * 1.25)
    top = 0
    for ax, t, letter in ((a, "ul", "a"), (b, "dl", "b")):
        xs = [n for n in ns if (t, n) in by]
        for i, (kind, label) in enumerate(KINDS):
            top = max(top, band(ax, xs, [[o for o in planned(by[(t, n)], kind) if o.ok] for n in xs], i, label, dodge=(i - 1) * 0.035, log=True))
        ax.set_xscale("log", base=2)
        ax.xaxis.set_major_locator(FixedLocator(ns))
        ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
        ax.xaxis.set_minor_locator(NullLocator())
        ax.set_xlabel("UAVs in the cell, each streaming video")
        pl.panel(ax, letter, names[t][0].upper() + names[t][1:])
    for ax, t in ((a, "ul"), (b, "dl")):
        ms_axis(ax, 5, max(100, top * 1.6))
        ax.set_xlim(*xlim)
        xs = [n for n in ns if (t, n) in by]
        over = [n for n in xs if carried[(t, n)] < 98]
        if over:                                                  # from half-way (in the logarithm) between the last cell that carries its load and the first that does not
            last_ok = max([n for n in xs if n < over[0]], default=over[0] / 2)
            ax.axvspan(math.sqrt(last_ok * over[0]), xlim[1], color=pl.tint(NEUTRAL, 0.22), lw=0, zorder=0)
            pl.note(ax, xlim[1] / 1.04, 5.6, "more video than\nthe uplink carries", ha="right", va="bottom", linespacing=1.05)
    a.set_ylabel("Time to a new session (ms)")
    a.legend(loc="upper left")
    pl.note(a, xlim[0] * 1.06, 5.6, "marker: median; bar: 5th to 95th percentile", ha="left", va="bottom")
    for j, t in enumerate(("ul", "dl")):
        xs = [n for n in ns if (t, n) in by]
        fr = [delivered(by[(t, n)]) for n in xs]
        c.vlines(xs, [min(f[1] for f in v) for v in fr], [max(f[1] for f in v) for v in fr], color=pl.tint(SERIES[j], 0.45), lw=1.0, zorder=2)
        c.plot(xs, [st.fmean(f[1] for f in v) for v in fr], **pl.series(j), label=names[t][0].upper() + names[t][1:].split(" cell")[0])
    c.set_xscale("log", base=2)
    c.xaxis.set_major_locator(FixedLocator(ns))
    c.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    c.xaxis.set_minor_locator(NullLocator())
    c.set_xlim(*xlim)
    c.set_ylim(0, 104)
    c.yaxis.set_major_locator(MultipleLocator(25))
    c.set_xlabel("UAVs in the cell")
    c.set_ylabel("Frames given to the decoder (% of those sent)")
    c.legend(loc="center left", bbox_to_anchor=(0.0, 0.42))
    pl.panel(c, "c", "Usable video")
    pl.save(fig, "plot12_sim_swarm")
    for (t, n), rs in by.items():
        fr = delivered(rs)
        m = [r["meta"] for r in rs]
        row = [names[t], n, len(rs)]
        for kind, _ in KINDS:
            o = planned(rs, kind)
            ok = [x.total for x in o if x.ok]
            row += [len(o), len(ok), round(100 * sum(x.tx == 1 for x in o) / max(len(o), 1), 1), *stat_row(ok)[:3]]
        # the plan of every UAV: opsPerUav rounds of (full handshake, cached rekey, PQ ratchet); in an overloaded cell an
        # operation takes so long that the run ends before the plan does
        expected = sum(len(r["vid"]) * int(arg(r, "opsPerUav", 4)) * len(KINDS) for r in rs)
        row += [round(100 * sum(len(planned(rs, kind)) for kind, _ in KINDS) / max(expected, 1), 1),
                round(st.fmean(f[0] for f in fr), 2) if fr else "", round(st.fmean(f[1] for f in fr), 2) if fr else "",
                round(100 * sum(x["upRecv"] for x in m) / max(sum(x["upSent"] for x in m), 1), 3),
                round(100 * sum(x["ulTbErr"] for x in m) / max(sum(x["ulTb"] for x in m), 1), 3), int(sum(x["ulTbLost"] for x in m)),
                round(st.fmean(x["ulSinrMeanDb"] for x in m), 1), round(st.fmean(x["ulMcsMean"] for x in m), 1),
                round(st.fmean(x["gcsBusyMs"] / 10 / x["simTime"] for x in m), 2), round(max(x["gcsMaxQueueMs"] for x in m), 1),
                round(st.fmean(x["upBytes"] * 8 / (x["simTime"] - 3.0) / 1e6 for x in m), 1), sum(stalled(r) for r in rs)]
        tab.append(row)
        out[f"{t}_{n}"] = {"full_median_ms": row[7], "full_p95_ms": row[8], "cached_median_ms": row[13], "ratchet_median_ms": row[19],
                           "planned_operations_run_pct": row[21], "frames_complete_pct_of_sent": row[22], "frames_to_decoder_pct_of_sent": row[23],
                           "datagrams_delivered_pct": row[24], "offered_mbit_s": row[-2]}
    hdr = ["cell", "uavs", "runs"]
    for kind, _ in KINDS:
        hdr += [f"{kind}_ran", f"{kind}_completed", f"{kind}_first_transmission_pct", f"{kind}_p5_ms", f"{kind}_median_ms", f"{kind}_p95_ms"]
    hdr += ["planned_operations_run_pct", "frames_complete_pct_of_sent", "frames_given_to_decoder_pct_of_sent", "datagrams_delivered_pct", "uplink_blocks_not_decoded_pct",
            "uplink_blocks_given_up", "uplink_sinr_db", "uplink_mcs", "ground_station_receive_thread_busy_pct", "ground_station_longest_queue_ms",
            "uplink_offered_mbit_s", "uavs_gone_silent"]
    pl.table("plot12_sim_swarm", hdr, tab)
    return out


# ------------------------------------------------------------------------------------------------------ 13 storm
def storm():
    by = group(runs("storm_w"), lambda n, r: (int(r["meta"]["gcsWorkers"]), int(r["meta"]["nUav"])))
    if not by:
        return None
    ns = sorted({n for _, n in by})
    fig, (a, b) = pl.figure(W2, 64, 1, 2, gridspec_kw={"width_ratios": [1, 1.1]})
    tab, out = [], {}
    labels = {1: "One thread answers (as implemented)", 4: "Four threads answer (design study)"}

    def ready(r):                                                 # seconds from the common start to each UAV's session
        t = {}
        for o in r["ops"]:
            if o.initial == 1 and o.ok:
                t[o.uav] = o.t0 + o.total / 1000 - 2.0
        return t
    top = 0
    for i, w in enumerate(sorted({w for w, _ in by})):
        xs = [n for n in ns if (w, n) in by]
        last = [[max(ready(r).values()) * 1000 for r in by[(w, n)] if ready(r)] for n in xs]
        top = max([top] + [max(v) for v in last])
        a.vlines(xs, [min(v) for v in last], [max(v) for v in last], color=pl.tint(SERIES[i], 0.45), lw=1.0, zorder=2)
        a.plot(xs, [st.median(v) for v in last], **pl.series(i), label=labels.get(w, f"{w} threads"))
        for n, v in zip(xs, last):
            rs = by[(w, n)]
            per = sorted(x * 1000 for r in rs for x in ready(r).values())
            first = [o for r in rs for o in r["ops"] if o.initial == 1]
            tab.append([w, n, len(rs), round(min(v), 1), round(st.median(v), 1), round(max(v), 1), round(st.median(per), 1), round(pl.pct(per, 95), 1),
                        round(100 * sum(o.tx == 1 and o.ok for o in first) / max(len(first), 1), 1), sum(not o.ok for o in first),
                        round(max(r["meta"]["gcsMaxQueueMs"] for r in rs), 1), int(st.fmean(r["meta"]["gcsCacheAnswers"] for r in rs))])
            out[f"workers{w}_n{n}"] = {"all_up_median_ms": round(st.median(v), 1), "all_up_max_ms": round(max(v), 1)}
    a.set_xscale("log", base=2)
    a.xaxis.set_major_locator(FixedLocator(ns))
    a.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    a.xaxis.set_minor_locator(NullLocator())
    a.set_xlim(ns[0] * 0.8, ns[-1] * 1.25)
    a.set_ylim(0, top * 1.12)
    a.set_xlabel("UAVs that start a handshake at the same instant")
    a.set_ylabel("Time until every UAV has its session (ms)")
    a.legend(loc="upper left")
    pl.panel(a, "a", "All sessions up (median, range of the runs)")
    nmax = ns[-1]
    for i, w in enumerate(sorted({w for w, _ in by})):
        if (w, nmax) in by:
            x, y = pl.ecdf([v * 1000 for r in by[(w, nmax)] for v in ready(r).values()])
            b.plot(x, y, drawstyle="steps-post", color=SERIES[i], linestyle=pl.DASHES[i], marker="none", label=labels.get(w, f"{w} threads"))
    b.set_ylim(0, 101)
    b.set_xlim(0, None)
    b.yaxis.set_major_locator(MultipleLocator(25))
    b.set_xlabel("Time from the common start to the UAV's session (ms)")
    b.set_ylabel(f"Share of the {nmax} UAVs (%)")
    b.legend(loc="lower right")
    pl.panel(b, "b", f"When each of {nmax} UAVs gets its session")
    pl.save(fig, "plot13_sim_storm")
    pl.table("plot13_sim_storm", ["answering_threads", "uavs", "runs", "all_up_min_ms", "all_up_median_ms", "all_up_max_ms", "per_uav_median_ms", "per_uav_p95_ms",
                                  "first_transmission_enough_pct", "uavs_without_session", "ground_station_longest_queue_ms", "answers_repeated_from_cache"], tab)
    return out


# --------------------------------------------------------------------------------------------- 14 mobility, range
def mobility():
    mob = group(runs("mob_v"), lambda n, r: r["meta"]["speed"])
    rng = group(runs("range_d"), lambda n, r: round((r["meta"]["rMin"] + r["meta"]["radius"]) / 2))
    if not mob and not rng:
        return None
    cal = json.loads((SIM / "calibration" / "k6g_calibration.json").read_text())
    cell = cal["scalars"]["cell_m"]
    fig, (a, b, c) = pl.figure(W2, 66, 1, 3, gridspec_kw={"width_ratios": [1, 1, 1]})
    tab, out = [], {}
    if mob:
        speeds = sorted(mob)
        per_min = []
        for v in speeds:
            rs = mob[v]
            per_min.append([60 * sum(1 for o in r["ops"] if o.initial == 2) / len(r["vid"]) / (r["meta"]["simTime"] - 2.5) for r in rs])
        xs = np.linspace(0, max(speeds) * 1.05, 50)
        a.plot(xs, 60 * xs / cell, color=NEUTRAL, lw=1.0, marker="none", label=f"One per cell side flown ({cell:.0f} m)")
        a.vlines(speeds, [min(v) for v in per_min], [max(v) for v in per_min], color=pl.tint(SERIES[0], 0.45), lw=1.0, zorder=2)
        a.plot(speeds, [st.fmean(v) for v in per_min], **pl.series(0), label="Simulated (mean and range of the runs)")
        a.set_xlim(-1, max(speeds) * 1.07)
        a.set_ylim(0, None)
        a.set_xlabel("Speed of the UAVs (m/s)")
        a.set_ylabel("Full handshakes per UAV and minute")
        a.legend(loc="upper left")
        pl.panel(a, "a", "Handshakes after a change of cell")
        moving = [v for v in speeds if v > 0]
        top = band(b, moving, [[o for o in planned(mob[v], "full", initial=2) if o.ok] for v in moving], 0, "Handshake after a change of cell")
        b.set_xlim(-1, max(speeds) * 1.07)
        b.set_ylim(0, max(40, top * 1.25))
        b.set_xlabel("Speed of the UAVs (m/s)")
        b.set_ylabel("Time to the new session (ms)")
        pl.note(b, max(speeds) * 1.05, 1.2, "median; bar: 5th to 95th percentile", ha="right", va="bottom")
        pl.panel(b, "b", "Their duration")
        full = cal["profiles"]["hybrid5"]
        up_bytes = full["ch_bytes"] + cal["scalars"]["cf_bytes"]
        for v, pm in zip(speeds, per_min):
            rs = mob[v]
            o = planned(rs, "full", initial=2)
            ok = [x.total for x in o if x.ok]
            fr = delivered(rs)
            video = st.fmean(r["meta"]["upBytes"] / (r["meta"]["simTime"] - 3.0) / len(r["vid"]) for r in rs)
            tab.append(["speed", v, len(rs), len(o), len(ok), round(st.fmean(pm), 3), *stat_row(ok)[:3], round(100 * sum(x.tx == 1 for x in o) / max(len(o), 1), 1),
                        round(st.fmean(f[0] for f in fr), 2), round(st.fmean(f[1] for f in fr), 2), round(st.fmean(pm) / 60 * up_bytes, 1),
                        round(100 * st.fmean(pm) / 60 * up_bytes / video, 3), round(st.fmean(r["meta"]["ulSinrMeanDb"] for r in rs), 1),
                        round(st.fmean(r["meta"]["ulMcsMean"] for r in rs), 1), round(100 * sum(r["meta"]["ulTbErr"] for r in rs) / sum(r["meta"]["ulTb"] for r in rs), 3),
                        sum(stalled(r) for r in rs)])
            out[f"speed_{v:g}"] = {"handshakes_per_uav_minute": round(st.fmean(pm), 2), "median_ms": tab[-1][7], "p95_ms": tab[-1][8], "completed": f"{len(ok)}/{len(o)}",
                                   "frames_complete_pct_of_sent": tab[-1][10], "frames_to_decoder_pct_of_sent": tab[-1][11],
                                   "handshake_share_of_uplink_bytes_pct": tab[-1][13]}
    if rng:
        ds = sorted(rng)
        top = 0
        for i, (kind, label) in enumerate(KINDS):
            top = max(top, band(c, [d / 1000 for d in ds], [[o for o in planned(rng[d], kind) if o.ok] for d in ds], i, label, dodge=(i - 1) * 0.04))
        c.set_xlim(0, max(ds) / 1000 * 1.06)
        c.set_ylim(0, max(40, top * 1.45))
        c.set_xlabel("Distance of the UAVs from the mast (km)")
        c.set_ylabel("Time to a new session (ms)")
        c.legend(loc="upper left", ncol=1)
        # why the times do not move: the radio adapts its rate (the index falls with distance) and repeats what fails
        for d in ds:
            mcs = st.fmean(r["meta"]["ulMcsMean"] for r in rng[d])
            pl.note(c, d / 1000, 2.0, f"{mcs:.0f}", ha="center", va="bottom", size=pl.FS_MIN)
        pl.note(c, max(ds) / 1000 * 0.53, 5.4, "uplink modulation and coding index (28: fastest):", ha="center", va="bottom", size=pl.FS_MIN)
        pl.panel(c, "c", "Session operations against range")
        for d in ds:
            rs = rng[d]
            fr = delivered(rs)
            row = ["range_m", d, len(rs)]
            o = planned(rs, "full")
            ok = [x.total for x in o if x.ok]
            row += [len(o), len(ok), "", *stat_row(ok)[:3], round(100 * sum(x.tx == 1 for x in o) / max(len(o), 1), 1), round(st.fmean(f[0] for f in fr), 2),
                    round(st.fmean(f[1] for f in fr), 2), "", "", round(st.fmean(r["meta"]["ulSinrMeanDb"] for r in rs), 1), round(st.fmean(r["meta"]["ulMcsMean"] for r in rs), 1),
                    round(100 * sum(r["meta"]["ulTbErr"] for r in rs) / sum(r["meta"]["ulTb"] for r in rs), 3), sum(stalled(r) for r in rs)]
            tab.append(row)
            out[f"range_{d}"] = {"full_median_ms": row[7], "full_p95_ms": row[8], "uplink_sinr_db": row[14], "uplink_mcs": row[15],
                                 "frames_complete_pct_of_sent": row[10], "frames_to_decoder_pct_of_sent": row[11]}
    else:
        c.set_axis_off()                                          # the range study is not there (yet)
    pl.save(fig, "plot14_sim_mobility_range")
    pl.table("plot14_sim_mobility_range", ["study", "speed_m_s_or_distance_m", "runs", "full_handshakes", "completed", "handshakes_per_uav_minute", "p5_ms", "median_ms", "p95_ms",
                                           "first_transmission_enough_pct", "frames_complete_pct_of_sent", "frames_given_to_decoder_pct_of_sent", "handshake_uplink_bytes_per_s",
                                           "share_of_the_uavs_uplink_traffic_pct", "uplink_sinr_db", "uplink_mcs", "uplink_blocks_not_decoded_pct", "uavs_gone_silent"], tab)
    return out


# ------------------------------------------------------------------------------- 15 ablation: cryptographic configuration
def ablation_crypto():
    tb = group(runs("crypto_tb_"), lambda n, r: (r["meta"]["profile"], r["meta"]["loss"]))
    nr = group(runs("crypto_nr_"), lambda n, r: r["meta"]["profile"])
    stm = group(runs("crypto_storm_"), lambda n, r: r["meta"]["profile"])
    if not tb:
        return None
    cal = json.loads((SIM / "calibration" / "k6g_calibration.json").read_text())
    sc, prof, steps = cal["scalars"], cal["profiles"], cal["notes"]["in_process_step_us"]
    names = [p for p, _ in PROFILES if p in prof]
    ticks = [lab for p, lab in PROFILES if p in prof]
    x = list(range(len(names)))
    fig, axes = pl.figure(W2, 132, 2, 2, gridspec_kw={"height_ratios": [1, 1.08]})
    (a, b), (c, d) = axes
    tab, out = [], {}

    def wire(p):                                                  # bytes on the wire of one full handshake, both directions
        fp, hdr, ip = sc["frag_payload"], sc["hs_hdr"], sc["udp_ip"]
        n = lambda body: math.ceil(body / fp)
        ch, sh, cf = prof[p]["ch_bytes"], prof[p]["sh_bytes"], sc["cf_bytes"]
        dg = n(ch) + n(sh) + 1
        return ch + sh + cf + dg * (hdr + ip), dg
    for i, p in enumerate(names):
        total, dg = wire(p)
        pl.bar(fig, a, 0, total / 1000, i, 13, SERIES[0] if p != "hybrid5" else SERIES[1], horizontal=False, hatch=None if p != "hybrid5" else "/////")
        pl.note(a, i, total / 1000 + 0.35, f"{total / 1000:.1f} kB\n{dg} datagrams" if total >= 1000 else f"{total} B\n{dg} datagrams", ha="center", va="bottom",
                size=pl.FS_MIN, linespacing=1.0, color=INK)
        out[p] = {"wire_bytes": int(total), "datagrams": dg}
    a.set_ylim(0, wire("hybrid5")[0] / 1000 * 1.3)
    a.set_ylabel("Full handshake on the wire (kB)")
    pl.panel(a, "a", "Bytes of a full handshake (computed from the message layouts)")
    # (b) computing per side: the measured step with this configuration's measured primitives put in
    uav = [(steps["full_build"] * prof[p]["scale_full_build"] + steps["full_process"] * prof[p]["scale_full_process"]) / 1000 for p in names]
    gcs = [steps["full_answer"] * prof[p]["scale_full_answer"] / 1000 for p in names]
    for i, p in enumerate(names):
        pl.bar(fig, b, 0, uav[i], i - 0.19, 9, SERIES[0], horizontal=False)
        pl.bar(fig, b, 0, gcs[i], i + 0.19, 9, SERIES[1], horizontal=False, hatch="/////")
        pl.note(b, i - 0.19, uav[i] + 0.12, f"{uav[i]:.1f}", ha="center", va="bottom", size=pl.FS_MIN, color=INK)
        pl.note(b, i + 0.19, gcs[i] + 0.12, f"{gcs[i]:.1f}", ha="center", va="bottom", size=pl.FS_MIN, color=INK)
        out[p].update(uav_compute_ms=round(uav[i], 2), gcs_compute_ms=round(gcs[i], 2))
    b.set_ylim(0, max(uav + gcs) * 1.28)
    b.set_ylabel("Computing per full handshake (ms)")
    b.legend(handles=[pl.swatch(SERIES[0]),
                      pl.swatch(SERIES[1], "/////")],
             labels=["UAV (Raspberry Pi 4B)", "Ground station (laptop)"], loc="upper left", handlelength=1.6, handleheight=0.9)
    pl.panel(b, "b", "Computing (measured, in-process, no video)")
    # (c) over the test-bed link, with loss
    losses = sorted({l for _, l in tb})
    top = 0
    for j, l in enumerate(losses):
        top = max(top, band(c, x, [[o for o in planned(tb.get((p, l), []), "full") if o.ok] for p in names], j,
                            "No loss" if l == 0 else f"{100 * l:g} % of datagrams lost", dodge=(j - (len(losses) - 1) / 2) * 0.16, line=False))
    ms_axis(c, 3, max(3000, top * 2.2))
    c.set_ylabel("Time to a new session (ms)")
    c.legend(loc="upper left", ncol=len(losses), columnspacing=1.0, handlelength=2.0)
    pl.panel(c, "c", f"Full handshake over the Wi-Fi test-bed link ({SIMNOTE})")
    # (d) in the NR cell, and when 64 UAVs start at once
    top = band(d, x, [[o for o in planned(nr.get(p, []), "full") if o.ok] for p in names], 0, "One of 8 UAVs in the cell, each streaming video", dodge=-0.1,
               line=False)
    if stm:
        allup = [[max(o.t0 + o.total / 1000 - 2.0 for o in r["ops"] if o.initial == 1 and o.ok) * 1000 for r in stm.get(p, []) if r["ops"]] for p in names]
        px = [i + 0.1 for i, v in enumerate(allup) if v]
        vv = [v for v in allup if v]
        d.vlines(px, [min(v) for v in vv], [max(v) for v in vv], color=pl.tint(SERIES[1], 0.45), lw=1.0, zorder=2)
        d.plot(px, [st.median(v) for v in vv], **{**pl.series(1), "linestyle": "none"}, label="64 UAVs start at once: until all have a session")
        top = max(top, max(max(v) for v in vv))
    d.set_ylim(0, top * 1.35)
    d.set_ylabel("Time (ms)")
    d.legend(loc="upper left")
    pl.panel(d, "d", f"In the NR cell ({SIMNOTE})")
    for ax in (a, b, c, d):
        ax.set_xticks(x)
        ax.set_xticklabels(ticks, fontsize=pl.FS_MIN, linespacing=1.0)
        ax.set_xlim(-0.6, len(names) - 0.4)
        ax.grid(axis="x", visible=False)
        ax.tick_params(axis="x", length=0)
    pl.save(fig, "plot15_ablation_crypto")
    for i, p in enumerate(names):
        row = [p, prof[p]["text"], out[p]["wire_bytes"], out[p]["datagrams"], prof[p]["ch_bytes"], prof[p]["sh_bytes"], round(uav[i], 3), round(gcs[i], 3)]
        for l in losses:
            o = planned(tb.get((p, l), []), "full")
            ok = [v.total for v in o if v.ok]
            row += [len(o), round(100 * len(ok) / max(len(o), 1), 2), *stat_row(ok)[:3]]
            out[p][f"testbed_loss{100 * l:g}_median_ms"] = stat_row(ok)[1]
        o = planned(nr.get(p, []), "full")
        ok = [v.total for v in o if v.ok]
        row += [len(o), *stat_row(ok)[:3]]
        out[p]["nr_median_ms"] = stat_row(ok)[1]
        o = planned(nr.get(p, []), "ratchet")
        row += [stat_row([v.total for v in o if v.ok])[1]]
        if stm.get(p):
            v = allup[i]
            row += [round(st.median(v), 1), round(max(v), 1)]
            out[p]["storm64_all_up_median_ms"] = round(st.median(v), 1)
        tab.append(row)
    hdr = ["configuration", "algorithms", "wire_bytes", "datagrams", "client_hello_bytes", "server_hello_bytes", "uav_compute_ms", "ground_station_compute_ms"]
    for l in losses:
        hdr += [f"testbed_loss{100 * l:g}_ran", f"testbed_loss{100 * l:g}_completed_pct", f"testbed_loss{100 * l:g}_p5_ms", f"testbed_loss{100 * l:g}_median_ms", f"testbed_loss{100 * l:g}_p95_ms"]
    hdr += ["nr_ran", "nr_p5_ms", "nr_median_ms", "nr_p95_ms", "nr_ratchet_median_ms", "storm64_all_up_median_ms", "storm64_all_up_max_ms"]
    pl.table("plot15_ablation_crypto", hdr, tab)
    return out


# ----------------------------------------------------------------------------------------- 16 ablation: protocol design
def ablation_design():
    frag = group(runs("design_frag"), lambda n, r: (int(r["meta"]["fragPayload"]), r["meta"]["loss"]))
    nocomb = group(runs("design_nocombine"), lambda n, r: r["meta"]["loss"])
    retx = group(runs("design_retx"), lambda n, r: (int(r["meta"]["adaptiveRetx"]), r["meta"]["loss"]))
    video = group(runs("design_video"), lambda n, r: (int(r["meta"]["fecParity"]), int(r["meta"]["kfRequest"]), r["meta"]["loss"]))
    if not frag and not retx and not video:
        return None
    fig, axes = pl.figure(W2, 128, 2, 2)
    (a, b), (c, d) = axes
    tab, out = [], {}
    full = lambda rs: planned(rs, "full")

    def done_within(ops, ms):
        return 100 * sum(1 for o in ops if o.ok and o.total <= ms) / max(len(ops), 1)

    def completed(ops):
        return 100 * sum(1 for o in ops if o.ok) / max(len(ops), 1)
    pc = lambda l: round(100 * l, 3)
    cal = json.loads((SIM / "calibration" / "k6g_calibration.json").read_text())
    ch, sh = cal["profiles"]["hybrid5"]["ch_bytes"], cal["profiles"]["hybrid5"]["sh_bytes"]
    as_built = int(cal["scalars"]["frag_payload"])
    # (a) combining the fragments of repeated transmissions: it cannot change how many handshakes get through at the
    # first attempt, so what is shown is how many get through at all (the UAV tries five times)
    if frag:
        ref = as_built if any(p == as_built for p, _ in frag) else sorted({p for p, _ in frag})[0]
        losses = sorted({l for p, l in frag if p == ref})
        xs = [100 * l for l in losses]
        series_ = [("Fragments of repeats combine (as implemented)", [full(frag[(ref, l)]) for l in losses], 0)]
        if nocomb:
            series_.append(("Every repeat on its own", [full(nocomb[l]) for l in losses if l in nocomb], 1))
        for label, groups, i in series_:
            a.plot(xs[:len(groups)], [completed(g) for g in groups], **pl.series(i), label=label)
            for l, g in zip(losses, groups):
                ok = [o.total for o in g if o.ok]
                tab.append(["combining", label, pc(l), len(g), round(completed(g), 2), round(done_within(g, 1000), 2), *stat_row(ok)[:3],
                            round(st.fmean(o.tx for o in g), 2)])
                out[f"combine{1 - i}_loss{100 * l:g}"] = {"completed_pct": tab[-1][4], "within_1s_pct": tab[-1][5], "median_ms": tab[-1][7], "p95_ms": tab[-1][8],
                                                           "mean_transmissions": tab[-1][9]}
        a.set_ylim(0, 104)
        a.yaxis.set_major_locator(MultipleLocator(25))
        a.xaxis.set_major_locator(MultipleLocator(5))
        a.set_xlim(-0.8, max(xs) * 1.06)
        a.set_xlabel("Datagrams dropped in each direction (%)")
        a.set_ylabel("Full handshakes completed in five attempts (%)")
        a.legend(loc="lower left")
        pl.panel(a, "a", "Combining the fragments of repeated messages")
        # (b) fragment size: how many handshakes need no repeat at all (a repeat costs 1.2 s)
        sizes = sorted({p for p, _ in frag})
        for i, s in enumerate(sizes):
            groups = [full(frag[(s, l)]) for l in losses if (s, l) in frag]
            b.plot(xs[:len(groups)], [done_within(g, 1000) for g in groups], **pl.series(i % 4),
                   label=f"{s} B: {math.ceil(ch / s)} + {math.ceil(sh / s)} datagrams" + (" (as implemented)" if s == as_built else ""))
            for l, g in zip(losses, groups):
                ok = [o.total for o in g if o.ok]
                tab.append(["fragment size", f"{s} B", pc(l), len(g), round(completed(g), 2), round(done_within(g, 1000), 2), *stat_row(ok)[:3],
                            round(st.fmean(o.tx for o in g), 2)])
                out[f"frag{s}_loss{100 * l:g}"] = {"completed_pct": tab[-1][4], "no_repeat_pct": tab[-1][5]}
        b.set_ylim(0, 104)
        b.yaxis.set_major_locator(MultipleLocator(25))
        b.xaxis.set_major_locator(MultipleLocator(5))
        b.set_xlim(-0.8, max(xs) * 1.06)
        b.set_xlabel("Datagrams dropped in each direction (%)")
        b.set_ylabel("Full handshakes that need no repeat (%)")
        b.legend(loc="upper right", title="Bytes per fragment")
        b.get_legend().get_title().set_fontsize(pl.FS_TICK)
        pl.panel(b, "b", "Size of a handshake fragment")
    # (c) repeat timers
    if retx:
        from matplotlib.lines import Line2D
        losses = sorted({l for _, l in retx})
        xs = [100 * l for l in losses]
        top = 0
        styles = ((0, "-", "fixed timers (as implemented)"), (1, (0, (1.2, 1.3)), "three round trips, at most the fixed timer (design study)"))
        for ad, ls, tag in styles:
            for i, (kind, label) in enumerate(KINDS):
                groups = [planned(retx[(ad, l)], kind) for l in losses if (ad, l) in retx]
                v = [q([o.total for o in g if o.ok], 95) for g in groups]
                c.plot(xs[:len(v)], v, color=SERIES[i], marker=pl.MARKERS[i] if ad == 0 else "none", linestyle=ls)
                top = max(top, max(v))
                for l, g in zip(losses, groups):
                    ok = [o.total for o in g if o.ok]
                    tab.append(["repeat timer", f"{label}, {tag}", pc(l), len(g), round(completed(g), 2), round(done_within(g, 1000), 2),
                                *stat_row(ok)[:3], round(st.fmean(o.tx for o in g), 2)])
                    out[f"retx{ad}_{kind}_loss{100 * l:g}"] = {"p95_ms": stat_row(ok)[2], "median_ms": stat_row(ok)[1], "completed_pct": tab[-1][4], "ran": len(g)}
        ms_axis(c, 5, top * 60)                                   # room above the curves for the legend
        c.xaxis.set_major_locator(MultipleLocator(5))
        c.set_xlim(-0.8, max(xs) * 1.06)
        c.set_xlabel("Datagrams dropped in each direction (%)")
        c.set_ylabel("95 % of the operations are done within (ms)")
        handles = [Line2D([], [], color=SERIES[i], marker=pl.MARKERS[i], linestyle="-") for i in range(len(KINDS))] \
            + [Line2D([], [], color=INK, marker="none", linestyle=ls) for _, ls, _ in styles]
        c.legend(handles, [label for _, label in KINDS] + ["solid: " + styles[0][2], "dotted: " + styles[1][2]], loc="upper left", handlelength=2.4)
        pl.panel(c, "c", "When to repeat an unanswered message")
    # (d) what would help the live video (not implemented)
    if video:
        losses = sorted({l for *_, l in video})
        xs = [100 * l for l in losses]
        variants = [((0, 0), "As implemented"), ((0, 1), "Keyframe on request"), ((1, 0), "One parity datagram per frame"), ((1, 1), "Both")]
        for i, ((fec, kf), label) in enumerate(variants):
            groups = [frames(video[(fec, kf, l)]) for l in losses if (fec, kf, l) in video]
            if not groups:
                continue
            d.plot(xs[:len(groups)], [st.fmean(f[1] for f in g) for g in groups], **pl.series(i), label=label)
        for (fec, kf, l), rs in video.items():
            fr = frames(rs)
            tab.append(["video", f"parity {fec}, keyframe request {kf}", pc(l), len(rs), round(st.fmean(f[0] for f in fr), 2), round(st.fmean(f[1] for f in fr), 2),
                        "", "", "", round(st.fmean(sum(v.keyreq for v in r["vid"]) for r in rs), 1)])
            out[f"video_fec{fec}_kf{kf}_loss{100 * l:g}"] = {"complete_pct": tab[-1][4], "decoder_pct": tab[-1][5]}
        d.set_ylim(0, 104)
        d.yaxis.set_major_locator(MultipleLocator(25))
        d.xaxis.set_major_locator(MultipleLocator(5))
        d.set_xlim(-0.8, max(xs) * 1.06)
        d.set_xlabel("Datagrams dropped in each direction (%)")
        d.set_ylabel("Frames given to the decoder (%)")
        d.legend(loc="upper right")
        pl.panel(d, "d", "Live video: two additions that are not implemented")
    pl.save(fig, "plot16_ablation_design")
    pl.table("plot16_ablation_design", ["study", "variant", "loss_pct", "n", "completed_pct_or_frames_complete_pct", "within_1s_pct_or_decoder_pct", "p5_ms", "median_ms",
                                        "p95_ms", "mean_transmissions_or_keyframe_requests"], tab)
    return out


# ---------------------------------------------------------------------------------------- rekey schedule (measured)
def rekey_schedule():
    """What the implemented key-refresh schedule costs per hour of flight, against doing the same refreshes with full
    handshakes. From measured values only (link_ops.json, crypto_pi.json): no simulation in this table."""
    ops, pi = measured("link_ops"), measured("crypto_pi")
    if not ops or not pi:
        return None
    from kyber6g.config import LinkConfig
    cfg = LinkConfig()
    w = pi["wire"]
    ip = w["record"]["udp_ip_headers"]
    wire = lambda msgs: sum(sum(m["datagrams"]) + len(m["datagrams"]) * ip for m in msgs.values())
    med = lambda op, f: st.median(f(r) for r in ops["rows"] if r["op"] == op and r["ok"])
    total = {k: med(MEASURED_OP[k], lambda r: r["uav_ms"]) for k, _ in KINDS}
    P = lambda n: pi["results"][n]["median_us"] / 1000
    cpu = {"full": P("full: UAV builds ClientHello") + P("full: UAV verifies, derives, Finished"),
           "cached": P("cached: UAV builds request") + P("cached: UAV verifies, Finished"),
           "ratchet": P("ratchet: UAV builds request") + P("ratchet: UAV finishes")}
    # The UAV's computing as timed inside the operations themselves, with video streaming: what the schedule costs in
    # operation, not in a benchmark loop. Same split as plot 2 (handshake and cached rekey: building the request,
    # working on the answer, installing the session; the wait for the answer contains the second of these), and for
    # the ratchet also the key generation, which happens before its timed stretch begins.
    def uav_compute(r, kind):
        p = r["parts"]
        if kind == "ratchet":
            return p.get("build_ms", 0.0) + p["finish_ms"] + p["install_ms"] if "finish_ms" in p else None
        return p["build_ms"] + p["process_ms"] + max(0.0, r["uav_ms"] - p["build_ms"] - p["wait_ms"])
    situ = {}
    for k, _ in KINDS:
        v = [uav_compute(r, k) for r in ops["rows"] if r["op"] == MEASURED_OP[k] and r["ok"] and isinstance(r.get("parts"), dict)]
        v = [x for x in v if x is not None]
        situ[k] = st.median(v) if v else float("nan")
    size = {"full": wire(w["full handshake"]), "cached": wire(w["cached rekey"]), "ratchet": wire(w["pq ratchet"])}
    per_h = {"cached": 3600 / cfg.cached_rekey_interval_s, "ratchet": 3600 / cfg.pq_ratchet_interval_s}
    rows = []
    for name, mix in (("as implemented: cached rekey every %g s, PQ ratchet every %g s" % (cfg.cached_rekey_interval_s, cfg.pq_ratchet_interval_s),
                       {"cached": per_h["cached"] - per_h["ratchet"], "ratchet": per_h["ratchet"]}),
                      ("a full handshake at every one of those instants", {"full": per_h["cached"]}),
                      ("a PQ ratchet at every one of those instants", {"ratchet": per_h["cached"]})):
        rows.append([name, round(sum(mix.values()), 1), round(sum(n * size[k] for k, n in mix.items()) / 1000, 1), round(sum(n * cpu[k] for k, n in mix.items()), 1),
                     round(sum(n * situ[k] for k, n in mix.items()), 1), round(sum(n * total[k] for k, n in mix.items()), 1)])
    base = rows[1]
    for r in rows:
        r += [round(100 * (1 - r[2] / base[2]), 1), round(100 * (1 - r[4] / base[4]), 1), round(100 * (1 - r[5] / base[5]), 1)]
    pl.table("table_rekey_schedule", ["schedule", "operations_per_hour", "kilobytes_per_hour_on_the_wire", "uav_computing_ms_per_hour_in_a_benchmark_loop",
                                      "uav_computing_ms_per_hour_in_the_running_system", "time_in_operations_ms_per_hour",
                                      "bytes_saved_against_full_handshakes_pct", "uav_computing_saved_pct", "time_in_operations_saved_pct"], rows)
    pl.table("table_operation_costs", ["operation", "bytes_on_the_wire", "uav_computing_ms_in_a_benchmark_loop", "uav_computing_ms_in_the_running_system",
                                       "time_over_the_link_median_ms"],
             [[lab, size[k], round(cpu[k], 3), round(situ[k], 2), round(total[k], 2)] for k, lab in KINDS])
    return {"per_hour": {r[0]: {"kB": r[2], "uav_ms_in_the_running_system": r[4], "time_in_operations_ms": r[5]} for r in rows},
            "saved_against_full_handshakes_pct": {"bytes": rows[0][6], "uav_computing": rows[0][7], "time_in_operations": rows[0][8]}}


# ------------------------------------------------------------------------------------------------------- checks
def checks():
    out, bad = {}, []
    mp = SIM / "results" / "manifest.json"
    man = json.loads(mp.read_text()) if mp.exists() else {}
    made = man.get("_made_with") or {}
    entries = {k: v for k, v in man.items() if not k.startswith("_")}
    failed = [k for k, v in entries.items() if not v.get("ok")]
    files = sorted(p.stem for p in RAW.glob("*.csv"))
    incomplete = [n for n in files if not read_meta_only(RAW / f"{n}.csv")]
    out["runs"] = {"in_manifest": len(entries), "result_files": len(files), "failed": failed[:10], "incomplete_files": incomplete[:10]}
    if failed or incomplete:
        bad.append(f"{len(failed)} failed runs, {len(incomplete)} incomplete files")
    cal = SIM / "calibration" / "k6g_calibration.txt"
    import hashlib
    now = hashlib.sha256(cal.read_bytes()).hexdigest()[:16] if cal.exists() else None
    out["made_with"] = made
    out["calibration_now"] = now
    if made and now != made.get("calibration_sha256"):
        bad.append("the calibration file has changed since the runs were made (run the sweep again with --fresh)")
    silent, no_session, uavs, nr_runs = 0, 0, 0, 0
    for name, r in runs(""):
        if r["meta"].get("link") != "nr":
            continue
        nr_runs += 1
        uavs += len(r["vid"])
        silent += stalled(r)
        got = {o.uav for o in r["ops"] if o.initial == 1 and o.ok}
        no_session += int(r["meta"]["nUav"]) - len(got)
    out["nr"] = {"runs": nr_runs, "uavs": uavs, "uavs_gone_silent": silent, "uavs_without_first_session": no_session}
    if silent:
        bad.append(f"{silent} UAV uplinks went silent")
    out["wall_time_s"] = made.get("wall_s")
    out["cpu_time_s"] = round(sum(v.get("wall_s", 0) for v in entries.values()))
    out["problems"] = bad
    return out


def read_meta_only(path):
    try:
        with open(path, "rb") as f:
            f.seek(max(0, path.stat().st_size - 4096))
            return b"\nM," in f.read()
    except OSError:
        return False


PLOTS = {"validation": validation, "swarm": swarm, "storm": storm, "mobility": mobility, "ablation_crypto": ablation_crypto,
         "ablation_design": ablation_design, "rekey_schedule": rekey_schedule}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    pl.setup()
    want = argv or list(PLOTS)
    summary = {"checks": checks()}
    for p in summary["checks"]["problems"]:
        print(f"[CHECK] {p}")
    rc = 0
    for name in want:
        try:
            res = PLOTS[name]()
            summary[name] = res
            print(f"[{'ok' if res is not None else 'no data'}] {name}" + (f": {json.dumps(res, default=str)[:300]}" if res else ""))
        except Exception as e:
            import traceback
            traceback.print_exc()
            summary[name] = {"error": f"{type(e).__name__}: {e}"}
            print(f"[FAIL] {name}: {type(e).__name__}: {e}")
            rc = 1
    out = SIM / "results" / "summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    prev = json.loads(out.read_text()) if out.exists() and argv else {}
    prev.update(summary)
    out.write_text(json.dumps(prev, indent=1, default=str))
    (pl.ROOT / "checks").mkdir(exist_ok=True)
    (pl.ROOT / "checks" / "sim_summary.json").write_text(json.dumps({k: v for k, v in prev.items() if k != "checks"}, indent=1, default=str))
    print(f"-> {out}")
    return 1 if (rc or summary["checks"]["problems"]) else 0


if __name__ == "__main__":
    sys.exit(main())
