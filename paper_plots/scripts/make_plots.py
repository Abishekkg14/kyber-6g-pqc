"""Draw the paper's plots from the measurement files in ../data (nothing here contains a measured number).

    python paper_plots/scripts/make_plots.py [name ...]          (no name: all plots)

Data files are written by kyber6g.tools.bench_crypto and kyber6g.tools.bench_link on the real hardware; this script
only reads them. Values timed on the ground station (suffix _raw in the files) are divided by the clock rate that
the same file records (the laptop's WSL clock runs slow; see ../README.md). Each plot also writes the numbers it
shows to ../tables/<name>.csv.
"""
import json
import statistics
import sys

import numpy as np
from matplotlib.ticker import FixedLocator, FuncFormatter, MultipleLocator, NullFormatter, NullLocator

import plotlib as pl
from plotlib import INK, INK2, MUTED, NEUTRAL, SERIES, W1, W2, plt

PI, LAPTOP = "Raspberry Pi 4B (UAV)", "Laptop (ground station)"
OPS = [("full_handshake", "full", "Full handshake (1.5-RTT)"), ("cached_rekey", "cached", "1-RTT Cached RapidRekey"),
       ("pq_ratchet", "ratchet", "PQ ratchet")]


def load(name):
    p = pl.DATA / f"{name}.json"
    if not p.exists():
        return None
    return json.loads(p.read_text())


def rate(d):
    return (d.get("clock") or {}).get("local_per_reference_second") or 1.0


def us(d, name):
    """Sorted samples of one operation in microseconds, corrected for the measuring machine's clock rate."""
    r = d["results"][name]
    k = rate(d)
    return sorted(s / 1e3 / k for s in r["samples_ns"])


def fmt_time_us(v):
    return f"{v:.0f} µs" if v < 1000 else f"{v / 1000:.2f} ms" if v < 10000 else f"{v / 1000:.1f} ms"


# ------------------------------------------------------------------------------------------------ 1 primitives
def crypto_primitives():
    pi, lap = load("crypto_pi"), load("crypto_laptop")
    rows = [("ML-KEM-1024 keygen", "ML-KEM-1024 key generation"), ("ML-KEM-1024 encapsulate", "ML-KEM-1024 encapsulation"),
            ("ML-KEM-1024 decapsulate", "ML-KEM-1024 decapsulation"), ("X25519 keygen", "X25519 key generation"),
            ("X25519 exchange", "X25519 key agreement"), ("ML-DSA-87 keygen", "ML-DSA-87 key generation"),
            ("ML-DSA-87 sign", "ML-DSA-87 signing"), ("ML-DSA-87 verify", "ML-DSA-87 verification"),
            ("HKDF key schedule (session secrets)", "HKDF-SHA256 key schedule"), ("record keys for 6 streams x 2 directions", "Record keys, 12 streams"),
            ("epoch rotation (chain step + new AEAD key)", "Epoch-key rotation"), ("HMAC-SHA256 (Finished)", "HMAC-SHA256 (Finished)")]
    fig, ax = pl.figure(W2, 78)
    ax.set_xscale("log")
    tab, lo, hi = [], 1e9, 0
    for i, (key, label) in enumerate(rows):
        y = len(rows) - 1 - i
        a, b = us(pi, key), us(lap, key)
        ma, mb = statistics.median(a), statistics.median(b)
        lo, hi = min(lo, pl.pct(b, 5), pl.pct(a, 5)), max(hi, pl.pct(a, 95), pl.pct(b, 95))
        ax.plot([mb, ma], [y, y], color=NEUTRAL, lw=0.9, zorder=2, solid_capstyle="butt")            # the gap between the machines
        for vals, k in ((a, 0), (b, 1)):
            ax.plot([pl.pct(vals, 5), pl.pct(vals, 95)], [y, y], color=pl.tint(SERIES[k], 0.35), lw=2.6, zorder=2.5 + 0.1 * k, solid_capstyle="butt")
        ax.plot(ma, y, linestyle="none", marker="o", color=SERIES[0], ms=5.0, zorder=4, label=PI if i == 0 else None)
        ax.plot(mb, y, linestyle="none", marker="s", color=SERIES[1], ms=4.6, zorder=4, label=LAPTOP if i == 0 else None)
        pl.note(ax, max(pl.pct(a, 95), ma) * 1.22, y, fmt_time_us(ma))                                # the Pi's value: the constrained node
        tab.append([label, len(a), round(ma, 2), round(pl.pct(a, 5), 2), round(pl.pct(a, 95), 2), len(b), round(mb, 2),
                    round(pl.pct(b, 5), 2), round(pl.pct(b, 95), 2), round(ma / mb, 2)])
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([r[1] for r in reversed(rows)], fontsize=pl.FS_LABEL, color=INK)
    ax.set_ylim(-0.7, len(rows) - 0.3)
    ax.set_xlim(10 ** np.floor(np.log10(lo * 0.8)), hi * 4.5)                 # room on the right for the values
    ax.xaxis.set_major_locator(FixedLocator([0.1, 1, 10, 100, 1000, 10000]))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: {0.1: "0.1 µs", 1: "1 µs", 10: "10 µs", 100: "100 µs", 1000: "1 ms", 10000: "10 ms"}.get(round(v, 1), "")))
    ax.xaxis.set_minor_formatter(NullFormatter())
    ax.grid(axis="y", visible=False)
    ax.tick_params(axis="y", length=0)
    ax.set_xlabel("Time per operation (median; bar: 5th to 95th percentile)")
    ax.legend(loc="lower right", ncol=1, handlelength=1.0)
    pl.save(fig, "plot01_crypto_primitives")
    pl.table("plot01_crypto_primitives", ["operation", "pi_n", "pi_median_us", "pi_p5_us", "pi_p95_us", "laptop_n", "laptop_median_us",
                                         "laptop_p5_us", "laptop_p95_us", "pi_over_laptop"], tab)
    return {"n": pi["samples_per_operation"], "laptop_clock_rate": rate(lap)}


# ------------------------------------------------------------------------------------------------- 2 handshake
def handshake_latency():
    d, pi = load("link_ops"), load("crypto_pi")
    k = rate(d)
    lap = load("crypto_laptop")
    fig, (a, b) = pl.figure(W2, 70, 1, 2, gridspec_kw={"width_ratios": [1.15, 1]})
    tab, med, xmax = [], {}, 0
    for i, (op, kind, label) in enumerate(OPS):
        ms = sorted(r["uav_ms"] for r in d["rows"] if r["op"] == op and r["ok"])
        n_all = sum(1 for r in d["rows"] if r["op"] == op)
        x, y = pl.ecdf(ms)
        med[op] = statistics.median(ms)
        xmax = max(xmax, pl.pct(ms, 99))
        # the legend carries the medians: beside the curves the labels would run into the neighbouring curve
        a.plot(x, y, drawstyle="steps-post", color=SERIES[i], linestyle=pl.DASHES[i], marker="none")
        a.plot(med[op], 50, linestyle="none", marker=pl.MARKERS[i], color=SERIES[i], ms=5.2, zorder=5)
        a.plot([], [], color=SERIES[i], linestyle=pl.DASHES[i], marker=pl.MARKERS[i],
               label=f"{label}: median {med[op]:.1f} ms, 95 % within {pl.pct(ms, 95):.1f} ms (n = {len(ms)})")
        tab.append([label, n_all, len(ms), round(min(ms), 2), round(pl.pct(ms, 5), 2), round(med[op], 2), round(statistics.fmean(ms), 2),
                    round(pl.pct(ms, 95), 2), round(pl.pct(ms, 99), 2), round(max(ms), 2)])
    xmax = max(pl.pct(sorted(r["uav_ms"] for r in d["rows"] if r["op"] == op and r["ok"]), 98) for op, _, _ in OPS)
    a.set_xlim(0, np.ceil(xmax / 10) * 10)
    a.set_ylim(0, 101)
    a.yaxis.set_major_locator(MultipleLocator(25))
    a.set_xlabel("Time to a new session, measured at the UAV (ms)")
    a.set_ylabel("Share of operations (%)")
    beyond = sum(1 for r in d["rows"] if r["ok"] and r["uav_ms"] > a.get_xlim()[1])
    if beyond:
        pl.note(a, a.get_xlim()[1], 3, f"{beyond} slower operation{'s' if beyond > 1 else ''} beyond the axis ", ha="right", va="bottom", size=pl.FS_MIN)
    a.legend(loc="upper center", bbox_to_anchor=(0.5, -0.215), ncol=1)
    pl.panel(a, "a", "Session establishment over the Wi-Fi link")

    # (b) where the time goes. The total is the median measured over the link (panel a). The two computing shares are
    # the medians of the same code run in one process on each machine (bench_crypto: no network, nothing else running),
    # the laptop's corrected for its clock rate. What is left is the radio link in both directions plus everything
    # that is not computation: the operating systems, the Python interpreters' scheduling, the video stream going on.
    step = lambda dd, *names_: sum(statistics.median(us(dd, n_)) for n_ in names_) / 1000
    compute = {"full": (step(pi, "full: UAV builds ClientHello", "full: UAV verifies, derives, Finished"),
                        step(lap, "full: GCS answers (ServerHello)", "full: GCS checks Finished")),
               "cached": (step(pi, "cached: UAV builds request", "cached: UAV verifies, Finished"),
                          step(lap, "cached: GCS answers", "cached: GCS checks Finished")),
               "ratchet": (step(pi, "ratchet: UAV builds request", "ratchet: UAV finishes"), step(lap, "ratchet: GCS answers"))}
    # The split is the one timed inside the measured operations themselves (the UAV times its own sections, the ground
    # station reports how long it took over each request). The UAV's sections take about 2.8 times as long there as
    # the same code run alone in a loop (bench_crypto): the processor is shared with the video stream and has left its
    # idle frequency only just before. The in-process figures go into the table as a reference.
    def uav_ms(r, kind):
        p = r["parts"]
        if kind == "ratchet":                                    # its clock starts after the key pairs are made
            return p["finish_ms"] + p["install_ms"] if "finish_ms" in p else None
        return p["build_ms"] + p["process_ms"] + max(0.0, r["uav_ms"] - p["build_ms"] - p["wait_ms"])
    parts = []
    for op, kind, label in OPS:
        rows = [r for r in d["rows"] if r["op"] == op and r["ok"] and isinstance(r.get("parts"), dict)]
        total = statistics.median(r["uav_ms"] for r in rows)
        ref_uav, ref_gcs = compute[kind]
        timed = [uav_ms(r, kind) for r in rows]
        if all(v is not None for v in timed) and timed:
            uav = statistics.median(timed)
            gcs = statistics.median(r["gcs_ms_raw"] for r in rows if r.get("gcs_ms_raw")) / k
            src = f"timed in the operations themselves (video streaming); the same steps alone in a loop: UAV {ref_uav:.2f} ms, ground station {ref_gcs:.2f} ms"
        else:                                                    # a campaign made before the ratchet timed its sections
            uav, gcs, src = ref_uav, ref_gcs, "computing shares from the in-process benchmark (this operation did not time its sections)"
        parts.append((label, uav, gcs, max(total - uav - gcs, 0), total, src))
    names = ["Computation on the UAV (Raspberry Pi 4B)", "Computation on the ground station (laptop)", "Radio link both ways, scheduling, waiting"]
    cols, hat = [SERIES[0], SERIES[1], NEUTRAL], [None, "/////", None]
    for j, (label, uav, gcs, rest, total, src) in enumerate(parts):
        y, x0 = len(parts) - 1 - j, 0.0
        for s, v in enumerate((uav, gcs, rest)):
            pl.bar(fig, b, x0, x0 + v, y, 9, cols[s], hatch=hat[s], round_end=(s == 2))
            x0 += v
        pl.note(b, total + 0.5, y, f"{total:.1f} ms", size=pl.FS_NOTE, color=INK)
        pl.note(b, 0, y + 0.36, f"UAV {uav:.2f} ms · ground station {gcs:.2f} ms · link and waiting {rest:.1f} ms", va="bottom", size=pl.FS_MIN)
        tab.append([f"breakdown: {label}", "", "", "", "", round(total, 3), "", f"uav_ms={uav:.3f}", f"gcs_ms={gcs:.3f}", f"link_and_wait_ms={rest:.3f} ({src})"])
    b.set_yticks(range(len(parts)))
    b.set_yticklabels([p[0].replace(" (1.5-RTT)", "").replace("1-RTT Cached RapidRekey", "Cached rekey") for p in reversed(parts)], fontsize=pl.FS_LABEL, color=INK)
    b.set_ylim(-0.6, len(parts) - 0.25)
    b.set_xlim(0, max(p[4] for p in parts) * 1.22)
    b.grid(axis="y", visible=False)
    b.tick_params(axis="y", length=0)
    b.set_xlabel("Median time (ms)")
    b.legend(handles=[pl.swatch(cols[s], hat[s]) for s in range(3)],
             labels=names, loc="upper center", bbox_to_anchor=(0.46, -0.215), ncol=1, handlelength=1.6, handleheight=0.9)
    pl.panel(b, "b", "Where the time goes (medians)")
    pl.save(fig, "plot02_handshake_latency")
    pl.table("plot02_handshake_latency", ["operation", "attempted", "succeeded", "min_ms", "p5_ms", "median_ms", "mean_ms", "p95_ms", "p99_ms", "max_ms"], tab)
    v0, v1 = d["before"], d["after"]
    return {"ops": len(d["rows"]), "ok": sum(r["ok"] for r in d["rows"]), "frames": v1["frames_complete"] - v0["frames_complete"],
            "frames_lost": v1["frames_lost"] - v0["frames_lost"], "gaps": v1["stream_gaps"] - v0["stream_gaps"], "clock_rate": k}


# ------------------------------------------------------------------------------------------------------ 3 wire
def wire_bytes():
    w = load("crypto_pi")["wire"]
    P = w["parts"]
    sig, ek, ct = P["ML-DSA-87 signature"], P["ML-KEM-1024 encapsulation key"], P["ML-KEM-1024 ciphertext"]
    ip, fh, rh = w["record"]["udp_ip_headers"], P["handshake fragment header"], w["record"]["header"] + w["record"]["tag"]
    full, cached, rat = w["full handshake"], w["cached rekey"], w["pq ratchet"]

    def split(msgs, n_sig, kem, per_dgram, framed):
        """(signatures, KEM, other fields, packet headers, total on the wire, datagrams)"""
        body = sum(m["bytes"] for m in msgs.values())
        dg = sum(len(m["datagrams"]) for m in msgs.values())
        wire = sum(sum(m["datagrams"]) for m in msgs.values()) + dg * ip
        hdr = wire - body if framed else dg * per_dgram
        return n_sig * sig, kem, wire - hdr - n_sig * sig - kem, hdr, wire, dg
    rows = [("Full handshake", split(full, 2, ek + ct, fh + ip, True)),
            ("PQ ratchet", split(rat, 0, ek + ct, rh + ip, True)),
            ("Cached rekey", split(cached, 0, 0, fh + ip, True))]
    names = ["ML-DSA-87 signatures", "ML-KEM-1024 key and ciphertext", "Other fields and encoding", "Framing, tags, UDP/IP headers"]
    cols, hat = [SERIES[0], SERIES[1], SERIES[2], NEUTRAL], [None, "/////", "\\\\\\\\\\", None]
    fig, ax = pl.figure(W1, 52)
    tab = []
    for j, (label, (s, kem, other, hdr, total, dg)) in enumerate(rows):
        y, x0 = len(rows) - 1 - j, 0.0
        vals = [v for v in (s, kem, other, hdr)]
        last = max(i for i, v in enumerate(vals) if v > 0)
        for i, v in enumerate(vals):
            if v > 0:
                pl.bar(fig, ax, x0, x0 + v, y, 10, cols[i], hatch=hat[i], round_end=(i == last))
                x0 += v
        pl.note(ax, total + 250, y, f"{total / 1000:.1f} kB" if total >= 1000 else f"{total} B", color=INK)
        pl.note(ax, total + 250, y - 0.30, f"{dg} datagrams", size=pl.FS_MIN)
        tab.append([label, s, kem, other, hdr, total, dg])
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([r[0] for r in reversed(rows)], fontsize=pl.FS_LABEL, color=INK)
    ax.set_ylim(-0.75, len(rows) - 0.35)
    ax.set_xlim(0, rows[0][1][4] * 1.24)
    ax.xaxis.set_major_locator(MultipleLocator(4000))
    ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v / 1000:.0f}"))
    ax.grid(axis="y", visible=False)
    ax.tick_params(axis="y", length=0)
    ax.set_xlabel("Bytes on the wire per operation, both directions (kB)")
    ax.legend(handles=[pl.swatch(cols[i], hat[i]) for i in range(4)],
              labels=names, loc="upper center", bbox_to_anchor=(0.36, -0.30), ncol=2, handlelength=1.6, handleheight=0.9, columnspacing=1.0)
    pl.save(fig, "plot03_wire_bytes")
    pl.table("plot03_wire_bytes", ["operation", "signature_bytes", "kem_bytes", "other_bytes", "header_bytes", "total_bytes_on_wire", "datagrams"], tab)
    msg = [[op, name, m["bytes"], len(m["datagrams"])] for op, ms in (("full handshake", full), ("cached rekey", cached), ("pq ratchet", rat)) for name, m in ms.items()]
    pl.table("plot03_wire_messages", ["operation", "message", "body_bytes", "datagrams"], msg)
    return {r[0]: r[1][4] for r in rows}


# ------------------------------------------------------------------------------------------------------ 4 aead
def aead_throughput():
    pi, lap = load("crypto_pi"), load("crypto_laptop")
    sizes = [64, 256, 1100, 4096, 16384, 65536]
    algs = [("AES-256-GCM", 0), ("ChaCha20-Poly1305", 1)]
    fig, axes = pl.figure(W2, 62, 1, 2)
    tab = []
    for ax, (d, name, unit, div) in zip(axes, ((pi, PI, "Mbit/s", 1.0), (lap, LAPTOP, "Gbit/s", 1000.0))):
        ymax = 0
        for alg, i in algs:
            thr = []
            for s in sizes:
                m = statistics.median(us(d, f"{alg} seal {s} B"))
                thr.append(s * 8 / m / div)                       # bits per microsecond = Mbit/s
                tab.append([name, alg, s, round(m, 3), round(s * 8 / m, 1)])
            ax.plot(sizes, thr, **pl.series(i), label=alg)
            ymax = max(ymax, max(thr))
            pl.note(ax, sizes[-1] * 1.25, thr[-1], f"{thr[-1]:.0f}" if div == 1 else f"{thr[-1]:.1f}", color=INK)
        ax.set_xscale("log", base=2)
        ax.set_xlim(45, 65536 * 2.6)
        ax.xaxis.set_major_locator(FixedLocator(sizes))
        ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: {64: "64 B", 256: "256 B", 1100: "1.1 kB", 4096: "4 kB", 16384: "16 kB", 65536: "64 kB"}.get(int(v), "")))
        ax.xaxis.set_minor_locator(NullLocator())
        ax.set_ylim(0, ymax * 1.12)
        ax.axvline(1100, color=MUTED, lw=0.6, zorder=1)
        pl.note(ax, 1100 * 1.12, ymax * 1.07, "one video record", size=pl.FS_MIN, va="center")
        ax.set_xlabel("Payload per record")
        ax.set_ylabel(f"Sealing throughput ({unit})")
        ax.legend(loc="upper left" if div == 1 else "center left", bbox_to_anchor=(0.0, 0.93) if div == 1 else (0.0, 0.62))
    hw = lambda d: "AES in hardware" if d["environment"]["cpu_has_aes"] else "AES in software"
    pl.panel(axes[0], "a", f"Raspberry Pi 4B: {hw(pi)}")
    pl.panel(axes[1], "b", f"Laptop: {hw(lap)}")
    rec = []
    for d, name in ((pi, PI), (lap, LAPTOP)):
        for alg in ("AES-256-GCM", "ChaCha20-Poly1305"):
            for what in ("seal", "open"):
                m = statistics.median(us(d, f"record {what} 1100 B ({alg})"))
                rec.append([name, alg, f"record {what} (whole record layer)", 1100, round(m, 3), round(1100 * 8 / m, 1)])
    pl.save(fig, "plot04_aead_throughput")
    pl.table("plot04_aead_throughput", ["machine", "algorithm", "payload_bytes", "median_us", "mbit_per_s"], tab)
    pl.table("plot04_record_layer", ["machine", "algorithm", "operation", "payload_bytes", "median_us", "mbit_per_s"], rec)
    return {"pi_has_aes": pi["environment"]["cpu_has_aes"], "laptop_has_aes": lap["environment"]["cpu_has_aes"]}


# -------------------------------------------------------------------------------------------------- 5 timeline
def timeline():
    d = load("timeline")
    k = rate(d)
    rows = [r for r in d["rows"] if "error" not in r and r.get("uav_ts")]
    # time axis: the UAV's clock (its status time stamp) plus the age of that status on arrival
    t_first = rows[0]["uav_ts"]
    m0 = rows[0]["mono"]
    t = np.array([(r["mono"] - m0) / k for r in rows])                          # seconds of real time since the first sample
    uts = np.array([r["uav_ts"] - t_first for r in rows])
    fig, axes = pl.figure(W2, 104, 4, 1, sharex=True, gridspec_kw={"height_ratios": [1.15, 1, 1, 1]})
    # the measured quantities are drawn in ink; colour is kept for the session operations, each in the colour and
    # line style it has in the other plots
    line = {"color": INK2, "lw": 0.9, "marker": "none"}
    fps = np.array([r["fps"] or 0 for r in rows])
    axes[0].plot(t, fps, **line)
    axes[0].set_ylim(0, 37)
    axes[0].yaxis.set_major_locator(MultipleLocator(10))
    axes[0].set_ylabel("Frames/s")
    lost = np.array([r["frames_lost"] for r in rows]) - rows[0]["frames_lost"]
    complete = rows[-1]["frames_complete"] - rows[0]["frames_complete"]
    pl.panel(axes[0], "a", "Video received and decrypted at the ground station (1280 × 720, H.264, 3 Mbit/s)")
    rtt = np.array([(r["rtt_ms_raw"] or np.nan) / k for r in rows])
    # the ground station pings every 2 s and the samples are 0.5 s apart: keep each ping once (when its value appears)
    new = np.array([not np.isnan(v) and (i == 0 or v != rtt[i - 1]) for i, v in enumerate(rtt)])
    pt, pv = t[new], rtt[new]
    top = 40.0
    axes[1].plot(pt[pv <= top], pv[pv <= top], linestyle="none", marker="o", ms=2.0, markeredgewidth=0, color=INK2)
    extra = ""
    if (pv > top).any():                                          # the few slow pings: a triangle at the top edge, their values in the title
        axes[1].plot(pt[pv > top], [top * 0.93] * int((pv > top).sum()), linestyle="none", marker="^", ms=3.0, markeredgewidth=0, color=INK2, clip_on=False)
        extra = f"; triangles: {int((pv > top).sum())} pings of {pv[pv > top].min():.0f} to {pv[pv > top].max():.0f} ms"
    axes[1].set_ylim(0, top)
    axes[1].yaxis.set_major_locator(MultipleLocator(10))
    axes[1].set_ylabel("ms")
    pl.panel(axes[1], "b", f"Round trip of a control message (one ping every 2 s, {len(pv)} pings{extra})")
    # UAV values change once a second (status message): plot them at the UAV's own time
    cpu = np.array([r["uav_cpu"] if r["uav_cpu"] is not None else np.nan for r in rows])
    axes[2].plot(uts, cpu, **line)
    axes[2].set_ylim(0, max(30, np.ceil(np.nanmax(cpu[4:]) / 10) * 10 + 10))
    axes[2].yaxis.set_major_locator(MultipleLocator(10))
    axes[2].set_ylabel("%")
    pl.panel(axes[2], "c", "Processor load of the Raspberry Pi (all four cores busy = 100 %)")
    temp = np.array([r["uav_temp_c"] or np.nan for r in rows])
    axes[3].plot(uts, temp, **line)
    axes[3].set_ylim(np.floor(np.nanmin(temp) - 2), np.ceil(np.nanmax(temp) + 2))
    axes[3].set_ylabel("°C")
    pl.panel(axes[3], "d", "Temperature of the Raspberry Pi's processor")
    axes[3].set_xlabel("Time (s)")
    axes[3].set_xlim(0, np.round(t[-1] / 60) * 60)
    axes[3].xaxis.set_major_locator(MultipleLocator(60))
    # events from the UAV's own operation log, on its clock
    ev = [(e["t"] - t_first, e["kind"], e.get("ms")) for e in d["uav_oplog"] if e["ok"]]
    # each operation keeps the colour it has in the other plots. A PQ ratchet (and a full handshake) is drawn as a wide
    # light band with the cached rekeys as dashed lines on top, so two operations in the same second both stay visible
    style = {"full": (pl.tint(SERIES[0], 0.55), "-", 2.4, 1.4, OPS[0][2]), "cached": (SERIES[1], pl.DASHES[1], 1.0, 1.6, OPS[1][2]),
             "ratchet": (pl.tint(SERIES[2], 0.60), "-", 2.4, 1.4, OPS[2][2])}
    seen = {}
    for ax in axes:
        for te, kind, ms in ev:
            c, ls, lw, z, lab = style[kind]
            h = ax.axvline(te, color=c, lw=lw, linestyle=ls, zorder=z)
            seen.setdefault(lab, h)
    rec = [c for c in d.get("commands") or [] if c["cmd"] in ("start_rec", "stop_rec") and c["ok"]]
    if len(rec) == 2:
        for ax in axes:
            ax.axvspan(rec[0]["at_s"], rec[1]["at_s"], color=pl.tint(NEUTRAL, 0.30), lw=0, zorder=0.5)
        pl.note(axes[0], rec[0]["at_s"] + 4, 17, "also recording,\nencrypted, to\nthe SD card", ha="left", size=pl.FS_MIN, linespacing=1.0)
    # epoch-key rotations: the video stream's epoch counter as seen in the UAV's status
    ep = [((r["uav_epochs"] or {}).get("video"), u) for r, u in zip(rows, uts)]
    rot = [u for (e0, _), (e1, u) in zip(ep, ep[1:]) if e0 is not None and e1 is not None and e1 > e0]
    hr, = axes[0].plot(rot, [34.5] * len(rot), linestyle="none", marker="|", ms=4, markeredgewidth=0.8, markeredgecolor=INK2, color=INK2)
    handles = list(seen.values()) + [hr]
    labels = [f"{lab} ({sum(1 for e in ev if style[e[1]][4] == lab)})" for lab in seen] + [f"Epoch-key rotation between rekeys ({len(rot)})"]
    fig.legend(handles=handles, labels=labels, loc="outside lower center", ncol=len(handles), handlelength=2.2)
    pl.note(axes[0], 757, 6.0, f"{int(lost[-1])} of {complete:,} frames lost", ha="right", color=INK)
    pl.save(fig, "plot05_timeline")
    pl.table("plot05_timeline", ["t_s", "uav_t_s", "fps_gcs", "frames_lost_cum", "rtt_ms", "uav_cpu_pct", "uav_temp_c", "uav_mem_pct", "wifi_dbm", "cam_fps", "kbps"],
             [[round(a, 2), round(b, 2), r["fps"], int(l), None if np.isnan(x) else round(float(x), 2), r["uav_cpu"], r["uav_temp_c"], r["uav_mem_pct"], r["wifi_dbm"], r["cam_fps"], r["kbps"]]
              for a, b, r, l, x in zip(t, uts, rows, lost, rtt)])
    pl.table("plot05_timeline_events", ["uav_t_s", "kind", "ms", "tag"], [[round(e["t"] - t_first, 2), e["kind"], e.get("ms"), e["tag"]] for e in d["uav_oplog"]])
    return {"seconds": float(t[-1]), "frames": complete, "lost": int(lost[-1]), "events": {lab: sum(1 for e in ev if style[e[1]][4] == lab) for lab in seen},
            "rotations": len(rot), "clock_rate": k}


# ------------------------------------------------------------------------------------------------------ 6 loss
def loss():
    d = load("loss")
    k = rate(d)
    lv = d["levels"]
    x, complete, decoded, tab = [], [], [], []
    for L in lv:
        c0, c1, s0, s1 = L["counters_before"], L["counters_after"], L["before"], L["after"]
        seen, dropped = c1["seen-out"] - c0["seen-out"], c1["drop-out"] - c0["drop-out"]
        p = 100 * dropped / max(seen, 1)
        sent = (s1["frames_sent"] or 0) - (s0["frames_sent"] or 0)
        fc, fl = s1["frames_complete"] - s0["frames_complete"], s1["frames_lost"] - s0["frames_lost"]
        dec = s1["frames_decoded"] - s0["frames_decoded"]
        chunks = ((s1["chunks_sent"] or 0) - (s0["chunks_sent"] or 0)) / max(sent, 1)
        base = max(fc + fl, 1)                                    # frames the ground station accounted for in the window
        x.append(p); complete.append(100 * fc / base); decoded.append(100 * dec / base)
        tab.append([L["nominal_pct"], seen, dropped, round(p, 3), c1["seen-in"] - c0["seen-in"], c1["drop-in"] - c0["drop-in"], fc, fl, dec,
                    round(100 * fc / base, 2), round(100 * dec / base, 2), round(chunks, 2), round(L["window_s_raw"] / k, 2), s1["tm_rx"] - s0["tm_rx"]])
    kmean = statistics.fmean(r[11] for r in tab if r[11] > 0)
    fig, (a, b, c) = pl.figure(W2, 66, 1, 3, gridspec_kw={"width_ratios": [1.2, 1, 0.9]})
    xs = np.linspace(0, max(x) * 1.03, 200)
    # the model: a frame arrives if every one of its datagrams does, independently. With the sizes of the frames of a
    # recording made in the same campaign (a keyframe is about five times a frame between keyframes); without such a
    # recording, with the mean number of datagrams per frame
    fr = ((load("transfer") or {}).get("recording_frames") or {}).get("frames") or []
    if fr:
        n_dg = np.array([-(-(f[2] + 8) // 1100) for f in fr], dtype=float)
        model = [100 * float(np.mean((1 - p / 100) ** n_dg)) for p in xs]
        label = "Model: every datagram of a frame arrives"
    else:
        model, label = 100 * (1 - xs / 100) ** kmean, f"Model: all {kmean:.1f} datagrams of a frame arrive"
    a.plot(xs, model, color=NEUTRAL, lw=1.0, marker="none", label=label)
    a.plot(x, complete, **pl.series(0), label="Frames received complete")
    a.plot(x, decoded, **pl.series(1), label="Frames decoded and shown")
    a.set_ylim(0, 104)
    a.set_xlim(-0.5, max(x) * 1.05)
    a.yaxis.set_major_locator(MultipleLocator(25))
    a.set_xlabel("Datagrams dropped on the uplink (%, counted)")
    a.set_ylabel("Share of the frames sent (%)")
    a.legend(loc="upper right")
    pl.note(a, max(x) * 0.16, 17.5, "after a lost frame\nthe receiver waits for\nthe next keyframe\n(one per second)", size=pl.FS_MIN, linespacing=1.05)
    pl.panel(a, "a", "Live video (no retransmission)")

    # (b) session operations under loss, from the UAV's own log
    log = d["uav_oplog"]
    ymax, opt, ran, failed = 0, [], 0, 0
    for i, (op, kind, label) in enumerate(OPS):
        px, med, lo, hi = [], [], [], []
        for L, p in zip(lv, x):
            ms = sorted(e["ms"] for e in log if e["tag"] == L["tag"] and e["kind"] == kind and e["ok"])
            fail = sum(1 for e in log if e["tag"] == L["tag"] and e["kind"] == kind and not e["ok"])
            sent = [e.get("hello_sent") or e.get("request_sent") or e.get("requests_sent") or 1 for e in log if e["tag"] == L["tag"] and e["kind"] == kind and e["ok"]]
            ran, failed = ran + len(ms) + fail, failed + fail
            opt.append([label, L["nominal_pct"], round(p, 3), len(ms) + fail, len(ms), fail, round(statistics.median(ms), 2) if ms else None,
                        round(ms[0], 2) if ms else None, round(ms[-1], 2) if ms else None, round(statistics.fmean(sent), 2) if sent else None, max(sent) if sent else None])
            if ms:
                px.append(p); med.append(statistics.median(ms)); lo.append(ms[0]); hi.append(ms[-1])
        dodge = (i - 1) * max(x) * 0.012                         # the three ranges side by side instead of on top of each other
        b.vlines([v + dodge for v in px], lo, hi, color=pl.tint(SERIES[i], 0.45), lw=1.0, zorder=2)
        b.plot([v + dodge for v in px], med, **pl.series(i), label=label.replace(" (1.5-RTT)", "").replace("1-RTT Cached RapidRekey", "Cached rekey"))
        ymax = max(ymax, max(hi) if hi else 0)
    b.set_yscale("log")
    # the ranges reach from the fastest to the slowest operation at every level, so no place between them is free:
    # the axis goes on below the fastest one (for the legend) and above the slowest one (for the note)
    top = max(ymax * 2.6, 100)
    b.set_ylim(0.55, top)
    b.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    b.set_xlim(-0.8, max(x) * 1.06)
    b.set_xlabel("Datagrams dropped, each direction (%)")
    b.set_ylabel("Time to a new session (ms)")
    b.legend(loc="lower center", ncol=2, handlelength=2.3, columnspacing=1.6)
    pl.note(b, -0.3, top * 0.74, f"{ran - failed} of {ran} operations completed; the {failed} that\ntimed out were all at {max(x):.0f} % loss" if failed else
            f"all {ran} operations completed", size=pl.FS_MIN, linespacing=1.05, bbox={"facecolor": "white", "edgecolor": "none", "pad": 0.8})
    pl.panel(b, "b", "Session operations (median, range)")

    # (c) a photo sent with retransmission: every one arrived intact; how long it took
    px, pm, n_ok, n_all, pt = [], [], 0, 0, []
    for L, p in zip(lv, x):
        ok = [ph for ph in L["photos"] if ph["received"] and ph["integrity"] == "PASS" and ph["transfer_s_raw"]]
        n_ok += len(ok); n_all += len(L["photos"])
        for ph in ok:
            pt.append([L["nominal_pct"], round(p, 3), ph["bytes"], ph["chunks"], round(ph["transfer_s_raw"] / k, 3), ph["integrity"]])
        if ok:
            px.append(p); pm.append(statistics.median(ph["transfer_s_raw"] / k for ph in ok))
            c.plot([p] * len(ok), [ph["transfer_s_raw"] / k for ph in ok], linestyle="none", marker="o", ms=2.8, color=pl.tint(SERIES[0], 0.45), markeredgewidth=0, zorder=2)
    c.plot(px, pm, **pl.series(0))
    top = max(ph[4] for ph in pt) * 1.12 if pt else 1
    c.set_ylim(0, top)
    c.set_xlim(-0.8, max(x) * 1.06)
    c.set_xlabel("Datagrams dropped (%)")
    c.set_ylabel("Transfer time of a 0.2 MB photo (s)")
    none = n_all - n_ok
    pl.note(c, max(x) * 1.03, top * 0.04, f"all {n_ok} photos that arrived are intact\n(SHA-256); {none} request{'s' if none != 1 else ''} got no answer" if none else
            f"all {n_ok} photos arrived intact (SHA-256)", ha="right", va="bottom", size=pl.FS_MIN, linespacing=1.05)
    pl.panel(c, "c", "Photo, with retransmission")
    pl.save(fig, "plot06_loss")
    pl.table("plot06_loss_video", ["nominal_loss_pct", "uplink_datagrams", "uplink_dropped", "uplink_loss_pct", "downlink_datagrams", "downlink_dropped",
                                   "frames_complete", "frames_lost", "frames_decoded", "complete_pct", "decoded_pct", "datagrams_per_frame", "window_s", "telemetry_rows"], tab)
    pl.table("plot06_loss_operations", ["operation", "nominal_loss_pct", "uplink_loss_pct", "ran_on_the_uav", "succeeded", "timed_out", "median_ms", "min_ms", "max_ms",
                                        "mean_transmissions_of_the_request", "max_transmissions"], opt)
    pl.table("plot06_loss_photos", ["nominal_loss_pct", "uplink_loss_pct", "bytes", "chunks", "transfer_s", "integrity"], pt)
    return {"levels": [round(p, 2) for p in x], "complete": [round(v, 1) for v in complete], "decoded": [round(v, 1) for v in decoded], "k": round(kmean, 2),
            "photos": f"{n_ok}/{n_all}", "clock_rate": k}


# --------------------------------------------------------------------------------------------------- 7 latency
def latency():
    r, tl = load("link_rtt"), load("timeline")
    k = rate(tl)
    ctl = sorted(x for p in r["probes"] for x in (p["rtt_ms"] or []))
    icmp = sorted(r["icmp"]["rtt_ms"])
    # the same control message when the UAV sends it at once after a command from the ground station (as a session
    # operation asked for from the dashboard or by a measurement starts): one probe per command
    trig = sorted(x for name in ("link_rtt", "link_rtt_after") for s in ((load(name) or {}).get("sized_triggered") or [])
                  if s["datagrams_each_way"] == 1 for x in s["rtt_ms"])
    curves = [(icmp, "ICMP echo (the radio path alone)"), (ctl, "Control message through the secure link")]
    if trig:
        curves.append((trig, "The same message, sent right after a command arrived"))
    fig, (a, b) = pl.figure(W2, 68 if trig else 62, 1, 2, gridspec_kw={"width_ratios": [1, 1.25]})
    for i, (vals, label) in enumerate(curves):
        xs, ys = pl.ecdf(vals)
        a.plot(xs, ys, drawstyle="steps-post", color=SERIES[i], linestyle=pl.DASHES[i], marker="none")
        a.plot(statistics.median(vals), 50, linestyle="none", marker=pl.MARKERS[i], color=SERIES[i], ms=5.2, zorder=5)
        a.plot([], [], color=SERIES[i], linestyle=pl.DASHES[i], marker=pl.MARKERS[i],
               label=f"{label}:\nmedian {statistics.median(vals):.1f} ms, 95 % within {pl.pct(vals, 95):.1f} ms (n = {len(vals)})")
    xmax = np.ceil(max(pl.pct(ctl, 98), pl.pct(icmp, 98)) / 5) * 5
    a.set_xlim(0, xmax)
    a.set_ylim(0, 101)
    a.yaxis.set_major_locator(MultipleLocator(25))
    a.set_xlabel("Round-trip time measured at the UAV (ms)")
    a.set_ylabel("Share of probes (%)")
    a.legend(loc="upper center", bbox_to_anchor=(0.5, -0.25), ncol=1)
    pl.panel(a, "a", "Round trip over the Wi-Fi link")

    # (b) what one video frame spends where, capture to decoded picture: medians over a run of live video. The run
    # "latency" was made after the decoder stopped holding every frame until the next one arrived; in the timeline run,
    # which is older, the decoder's time was paired with the wrong frame (README, "What the latency budget is made of").
    lat = load("latency") or tl
    k = rate(lat)
    rows = [x for x in lat["rows"] if "error" not in x and x.get("cam_live") and not x.get("cam_recording")]
    med = lambda key, f=1.0: statistics.median(x[key] for x in rows if x.get(key) is not None) * f
    chunks = (rows[-1]["chunks_sent"] - rows[0]["chunks_sent"]) / max(rows[-1]["frames_sent"] - rows[0]["frames_sent"], 1)
    encode = med("encode_latency_ms")
    seal = med("seal_us_avg") * chunks / 1000                      # per datagram: record sealing and the send call
    radio = statistics.median(icmp) / 2
    decode = med("decode_ms_raw", 1 / k)
    est = med("display_latency_ms_est")
    parts = [("Camera and H.264 encoder (Pi)", encode, SERIES[0], None), (f"Sealing and sending {chunks:.0f} records (Pi)", seal, SERIES[1], "/////"),
             ("Radio, one way (half the ICMP round trip)", radio, SERIES[2], "\\\\\\\\\\"),
             ("Decoder at the ground station (H.264 to picture)", decode, SERIES[3], "xxxxx")]
    x0 = 0.0
    for i, (label, v, col, hat) in enumerate(parts):
        pl.bar(fig, b, x0, x0 + v, 0, 11, col, hatch=hat, round_end=(i == len(parts) - 1))
        if v > 6:
            pl.note(b, x0 + v / 2, 0.42, f"{v:.1f} ms", ha="center", va="bottom", color=INK)
        x0 += v
    total = x0
    pl.note(b, total + 1.5, 0, f"sum {total:.0f} ms", color=INK)
    b.plot([est], [-0.55], linestyle="none", marker="v", color=INK2, ms=5)
    pl.note(b, est + 2.5, -0.55, f"{est:.0f} ms", color=INK)
    pl.note(b, est - 2.5, -0.55, "the ground station's own estimate, from both clocks", ha="right", size=pl.FS_MIN)
    b.set_ylim(-1.1, 1.0)
    b.set_xlim(0, max(total, est) * 1.20)
    b.set_yticks([])
    b.grid(axis="y", visible=False)
    b.spines["left"].set_visible(False)
    b.set_xlabel("Time from the sensor to the decoded picture (ms, medians)")
    b.legend(handles=[pl.swatch(p[2], p[3]) for p in parts],
             labels=[f"{p[0]}: {p[1]:.1f} ms" for p in parts], loc="upper center", bbox_to_anchor=(0.5, -0.25), ncol=1, handlelength=1.6, handleheight=0.9)
    pl.panel(b, "b", "Latency budget of one video frame")
    pl.save(fig, "plot07_latency")
    q = lambda v: [len(v), round(min(v), 3), round(pl.pct(v, 5), 3), round(statistics.median(v), 3), round(statistics.fmean(v), 3), round(pl.pct(v, 95), 3), round(pl.pct(v, 99), 3), round(max(v), 3)]
    sized = []
    for name in ("link_rtt", "link_rtt_after"):
        dd = load(name) or {}
        for kind, key in (("probes on the UAV's timer", "sized"), ("one probe per command", "sized_triggered")):
            for s in dd.get(key) or []:
                if s["rtt_ms"]:
                    sized.append([f"{name}: {kind}, {s['datagrams_each_way']} datagram(s) each way"] + q(sorted(s["rtt_ms"])))
    pl.table("plot07_round_trip", ["probe", "n", "min_ms", "p5_ms", "median_ms", "mean_ms", "p95_ms", "p99_ms", "max_ms"],
             [["ICMP echo from the Pi"] + q(icmp), ["secure control message"] + q(ctl)]
             + ([["secure control message, one probe per command"] + q(trig)] if trig else []) + sized)
    pl.table("plot07_latency_budget", ["component", "ms", "source"],
             [[parts[0][0], round(encode, 2), f"camera status on the Pi (sensor time stamp to encoded frame), median over {len(rows)} samples of live video"],
              [parts[1][0], round(seal, 3), "Pi: mean seal+send time per record x records per frame"],
              [parts[2][0], round(radio, 3), "half the median ICMP round trip measured on the Pi (assumes a symmetric path)"],
              [parts[3][0], round(decode, 2), "ground station, corrected for its clock rate"],
              ["sum", round(total, 2), ""], ["ground station's estimate (capture to decoded)", round(est, 1), "needs both clocks: an estimate while the laptop clock is unsteady"]])
    lost = sum(p["lost"] or 0 for p in r["probes"])
    return {"control_n": len(ctl), "control_lost": lost, "icmp_n": len(icmp), "chunks_per_frame": round(chunks, 2), "budget_ms": round(total, 1), "estimate_ms": round(est, 1)}


# ------------------------------------------------------------------------------------- 8 photos and video: the cost
PHOTO_SIZES = [("50 kB", 50), ("200 kB", 200), ("1 MB", 1000), ("3 MB", 3000)]
F1, F2 = "format 1 (ML-KEM-1024, AES-256-GCM)", "format 2 (ML-KEM-1024 + X25519, AES-256-GCM, ML-DSA-87 signature{})"


def media_protection():
    pi, lap, tl, tr = load("crypto_pi"), load("crypto_laptop"), load("timeline"), load("transfer")
    fig, axes = pl.figure(W2, 122, 2, 2, gridspec_kw={"height_ratios": [1.1, 1]})
    (a, b), (c, d) = axes
    tab = []
    kb = [s for _, s in PHOTO_SIZES]
    for ax, dd, what, name, col, mk, letter, title in ((a, pi, "seal", PI, SERIES[0], "o", "a", "Storing a photo on the UAV (Raspberry Pi 4B)"),
                                                       (b, lap, "open", LAPTOP, SERIES[1], "s", "b", "Opening it at the ground station (laptop)")):
        med = {}
        for fmt, tag in ((F1, 1), (F2.format(" verified" if what == "open" else ""), 2)):
            v = [us(dd, f"photo {what} {lab}, {fmt}") for lab, _ in PHOTO_SIZES]
            med[tag] = [statistics.median(x) / 1000 for x in v]
            for (lab, s), x in zip(PHOTO_SIZES, v):
                tab.append([name, what, f"format {tag}", s, len(x), round(statistics.median(x) / 1000, 3), round(pl.pct(x, 5) / 1000, 3), round(pl.pct(x, 95) / 1000, 3),
                            round(s / (statistics.median(x) / 1000), 1)])
        ax.plot(kb, med[1], color=pl.tint(col, 0.55), linestyle=pl.DASHES[2], marker=mk, ms=3.6, label="Format 1: ML-KEM-1024 alone, unsigned (before)")
        ax.plot(kb, med[2], color=col, linestyle="-", marker=mk, label="Format 2: ML-KEM-1024 + X25519, ML-DSA-87 signature")
        for s, v2, v1 in zip(kb, med[2], med[1]):
            pl.note(ax, s, v2 * 1.28, fmt_time_us(v2 * 1000), ha="center", va="bottom", color=INK)
        ax.set_xscale("log"); ax.set_yscale("log")
        ax.set_xlim(32, 4700)
        ax.set_ylim(min(med[1]) * 0.22, max(med[2]) * 2.6)          # room below the curves for the legend, above them for the values
        ax.xaxis.set_major_locator(FixedLocator(kb))
        ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: {50: "50 kB", 200: "200 kB", 1000: "1 MB", 3000: "3 MB"}.get(int(round(v)), "")))
        ax.xaxis.set_minor_locator(NullLocator())
        ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
        ax.yaxis.set_minor_formatter(NullFormatter())
        ax.set_xlabel("Size of the photo (JPEG)")
        ax.set_ylabel(f"Time to {what} it (ms, median)")
        ax.legend(loc="lower right")
        pl.panel(ax, letter, title)

    # (c) what a stored file carries besides its content
    P = pi["wire"]["parts"]
    note2 = pi["results"]["photo seal 200 kB, format 2 (ML-KEM-1024 + X25519, AES-256-GCM, ML-DSA-87 signature)"].get("note", "")
    import re
    m = re.match(r"file: (\d+) B for (\d+) B of JPEG \(format 1: (\d+) B\)", note2)
    f2, plain, f1 = (int(x) for x in m.groups())
    sig, ct, tag, wrapped, xk = P["ML-DSA-87 signature"] + 10, P["ML-KEM-1024 ciphertext"], 16, 48, P["X25519 public key"]
    rows = [("Format 2", [("ML-DSA-87 signature of the UAV", sig), ("ML-KEM-1024 ciphertext", ct), ("X25519 key, wrapped key, tag", xk + wrapped + tag),
                          ("Header (time, size, position, signer)", f2 - plain - sig - ct - xk - wrapped - tag)], f2 - plain),
            ("Format 1", [("ML-DSA-87 signature of the UAV", 0), ("ML-KEM-1024 ciphertext", ct), ("X25519 key, wrapped key, tag", wrapped + tag),
                          ("Header (time, size, position, signer)", f1 - plain - ct - wrapped - tag)], f1 - plain)]
    cols, hat = [SERIES[0], SERIES[1], SERIES[2], NEUTRAL], [None, "/////", "\\\\\\\\\\", None]
    for j, (label, parts, total) in enumerate(rows):
        y, x0 = len(rows) - 1 - j, 0.0
        last = max(i for i, (_, v) in enumerate(parts) if v > 0)
        for i, (_, v) in enumerate(parts):
            if v > 0:
                pl.bar(fig, c, x0, x0 + v, y, 11, cols[i], hatch=hat[i], round_end=(i == last))
                x0 += v
        pl.note(c, total + 150, y, f"{total / 1000:.1f} kB" if total >= 1000 else f"{total} B", color=INK)
        pl.note(c, total + 150, y - 0.31, f"{100 * total / plain:.1f} % of a 200 kB photo", size=pl.FS_MIN)
        tab.append(["file", "bytes added", label.lower(), plain // 1000, "", total, *[v for _, v in parts]])
    c.set_yticks(range(len(rows)))
    c.set_yticklabels([r[0] for r in reversed(rows)], fontsize=pl.FS_LABEL, color=INK)
    c.set_ylim(-0.8, len(rows) - 0.35)
    c.set_xlim(0, rows[0][2] * 1.42)
    c.xaxis.set_major_locator(MultipleLocator(2000))
    c.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v / 1000:.0f}"))
    c.grid(axis="y", visible=False)
    c.tick_params(axis="y", length=0)
    c.set_xlabel("Bytes a stored photo or recording carries besides its content (kB)")
    c.legend(handles=[pl.swatch(cols[i], hat[i]) for i in range(4)],
             labels=[p[0] for p in rows[0][1]], loc="upper center", bbox_to_anchor=(0.45, -0.30), ncol=2, handlelength=1.6, handleheight=0.9, columnspacing=1.0)
    pl.panel(c, "c", "What the hybrid key wrap and the signature add to a file")

    # (d) live video: bytes of one second on the air, and the Pi's time to seal and send them
    rec = pi["wire"]["record"]
    live = [x for x in tl["rows"] if "error" not in x and x.get("cam_live") and not x.get("cam_recording")]
    frames = live[-1]["frames_sent"] - live[0]["frames_sent"]
    chunks = live[-1]["chunks_sent"] - live[0]["chunks_sent"]
    secs = live[-1]["uav_ts"] - live[0]["uav_ts"]
    kbps = statistics.median(x["cam_kbps"] for x in live if x.get("cam_kbps"))
    seal_us = statistics.median(x["seal_us_avg"] for x in live if x.get("seal_us_avg"))
    rps, fps = chunks / secs, frames / secs
    payload = kbps * 1000 / 8 + fps * 8                                     # H.264 and the 8-byte capture time of every frame
    parts = [("H.264 video and capture times", payload), ("Record header, frame position, AES-GCM tag", rps * (rec["header"] + rec["video extension"] + rec["tag"])),
             ("UDP and IP headers", rps * rec["udp_ip_headers"])]
    x0, total = 0.0, sum(v for _, v in parts)
    for i, (label, v) in enumerate(parts):
        pl.bar(fig, d, x0, x0 + v / 1000, 0.35, 11, [NEUTRAL, SERIES[0], SERIES[2]][i], hatch=[None, None, "\\\\\\\\\\"][i], round_end=(i == 2))
        x0 += v / 1000
    pl.note(d, total / 1000 * 1.02, 0.35, f"{total / 1000:.0f} kB per second", color=INK)
    cpu = rps * seal_us / 1e6 * 100
    pl.note(d, 0, -0.32, f"{rps:.0f} records per second ({rps / fps:.1f} per frame), each sealed and sent\n"
                         f"by the Pi in {seal_us:.0f} µs: {cpu:.1f} % of one of its four cores. The record layer\n"
                         f"adds {100 * parts[1][1] / payload:.1f} % to the video's bytes, UDP/IP another {100 * parts[2][1] / payload:.1f} %.",
            va="top", size=pl.FS_NOTE, color=INK2, linespacing=1.25)
    d.set_ylim(-1.25, 0.9)
    d.set_xlim(0, total / 1000 * 1.32)
    d.set_yticks([])
    d.grid(axis="y", visible=False)
    d.spines["left"].set_visible(False)
    d.set_xlabel("Bytes of one second of live video on the air (kB)")
    d.legend(handles=[pl.swatch([NEUTRAL, SERIES[0], SERIES[2]][i], [None, None, "\\\\\\\\\\"][i]) for i in range(3)],
             labels=[f"{p[0]}: {p[1] / 1000:.1f} kB" for p in parts], loc="upper center", bbox_to_anchor=(0.45, -0.30), ncol=1, handlelength=1.6, handleheight=0.9)
    pl.panel(d, "d", "Live video: what the AES-256-GCM record layer adds")
    pl.save(fig, "plot08_media_protection")
    pl.table("plot08_media_protection", ["machine_or_file", "operation", "format", "photo_kB", "n", "median_ms_or_bytes_added", "p5_ms", "p95_ms", "kB_per_ms"], tab)
    live_tab = [["records per second", round(rps, 1)], ["frames per second", round(fps, 2)], ["records per frame", round(rps / fps, 2)], ["video bit rate (kbit/s)", round(kbps, 1)],
                ["seal and send per record on the Pi (us)", round(seal_us, 1)], ["share of one core (%)", round(cpu, 2)]] + [[f"bytes per second: {k}", round(v)] for k, v in parts]
    fr = (tr or {}).get("recording_frames", {}).get("frames") or []
    if fr:
        key, oth = sorted(f[2] for f in fr if f[1]), sorted(f[2] for f in fr if not f[1])
        live_tab += [["recording: frames", len(fr)], ["keyframes: median bytes", statistics.median(key)], ["keyframes: records each (median)", -(-(statistics.median(key) + 8) // 1100)],
                     ["other frames: median bytes", statistics.median(oth)], ["other frames: records each (median)", -(-(statistics.median(oth) + 8) // 1100)]]
    pl.table("plot08_live_video", ["quantity", "value"], live_tab)
    return {"format2_added_bytes": f2 - plain, "format1_added_bytes": f1 - plain, "records_per_s": round(rps, 1), "seal_us": round(seal_us, 1), "core_pct": round(cpu, 2)}


# --------------------------------------------------------------------------------------- 9 a picture, encrypted
def cipher_statistics():
    d = load("media_stats")
    if not d:
        return {"skipped": "no media_stats.json (python -m kyber6g.tools.media_stats)"}
    from matplotlib.gridspec import GridSpec
    from PIL import Image
    im = d["image"]
    fig = plt.figure(figsize=(W2 * pl.MM, 104 * pl.MM))
    fig._k6g_bars = []
    gs = GridSpec(2, 4, figure=fig, width_ratios=[1.12, 1.2, 0.86, 1.42])
    media = pl.DATA / "media"
    ideal = d["ideal"]
    tab = []
    for r, (kind, png, title) in enumerate((("plain", "plain.png", "The picture"), ("cipher", "cipher.png", "The same pixels, as stored"))):
        s = im[kind]
        ax = fig.add_subplot(gs[r, 0])
        pic = Image.open(media / png)
        pic.thumbnail((420, 420), Image.LANCZOS if kind == "plain" else Image.NEAREST)
        ax.imshow(pic, interpolation="nearest", aspect="equal")
        ax.set_xticks([]); ax.set_yticks([])
        ax.grid(False)
        for sp in ax.spines.values():
            sp.set_visible(True); sp.set_linewidth(0.4); sp.set_color(pl.AXIS)
        pl.panel(ax, "ad"[r], title)
        ax = fig.add_subplot(gs[r, 1])
        h = np.sum(np.array(s["histogram"]), axis=0)
        ax.fill_between(np.arange(256), h / 1000, step="mid", color=SERIES[0], lw=0)
        ax.set_xlim(0, 255)
        ax.set_ylim(0, None)
        ax.xaxis.set_major_locator(FixedLocator([0, 64, 128, 192, 255]))
        ax.set_xlabel("Pixel value")
        ax.set_ylabel("Thousand pixel values")
        pl.panel(ax, "be"[r], "Histogram")
        ax = fig.add_subplot(gs[r, 2])
        pts = np.array(im[f"scatter_{kind}"])
        ax.plot(pts[:, 0], pts[:, 1], linestyle="none", marker="o", ms=1.1, markeredgewidth=0, color=SERIES[0])
        ax.set_xlim(0, 255); ax.set_ylim(0, 255)
        ax.set_aspect("equal")
        ax.set_anchor("N")                                            # top edge (and the panel title) level with the histogram beside it
        ax.xaxis.set_major_locator(FixedLocator([0, 128, 255])); ax.yaxis.set_major_locator(FixedLocator([0, 128, 255]))
        ax.set_xlabel("A pixel")
        ax.set_ylabel("Its right neighbour")
        pl.panel(ax, "cf"[r], "Neighbours")
        for ch, name in enumerate(("red", "green", "blue")):
            tab.append([kind, name, s["entropy_bits"][ch], s["chi_square"][ch], s["correlation"]["horizontal"][ch], s["correlation"]["vertical"][ch], s["correlation"]["diagonal"][ch]])
    # the numbers, as a table in the figure
    ax = fig.add_subplot(gs[:, 3])
    ax.axis("off")
    mean = lambda v: sum(v) / len(v)
    pc, cc = im["plain"], im["cipher"]
    diff = d["differences"]
    lines = [("Measure", "picture", "as stored", None),
             ("Entropy (bits of 8)", f"{mean(pc['entropy_bits']):.3f}", f"{mean(cc['entropy_bits']):.4f}", None),
             ("Correlation, right", f"{mean(pc['correlation']['horizontal']):.3f}", f"{mean(cc['correlation']['horizontal']):+.4f}", None),
             ("Correlation, below", f"{mean(pc['correlation']['vertical']):.3f}", f"{mean(cc['correlation']['vertical']):+.4f}", None),
             ("Correlation, diagonal", f"{mean(pc['correlation']['diagonal']):.3f}", f"{mean(cc['correlation']['diagonal']):+.4f}", None),
             ("χ² against flat*", f"{mean(pc['chi_square']):.3g}", f"{mean(cc['chi_square']):.0f}", None),
             (None, None, None, None),
             ("Two stored copies", "NPCR", "UACI", None),
             ("Sealed twice", f"{diff[0]['npcr_pct']:.2f} %", f"{diff[0]['uaci_pct']:.2f} %", None),
             ("One pixel changed", f"{diff[1]['npcr_pct']:.2f} %", f"{diff[1]['uaci_pct']:.2f} %", None),
             ("Random (ideal)", f"{ideal['npcr_pct']:.2f} %", f"{ideal['uaci_pct']:.2f} %", None)]
    y = 0.965
    for i, (k, v1, v2, _) in enumerate(lines):
        if k is None:
            y -= 0.035
            continue
        head = i in (0, 7)
        pl.note(ax, 0.0, y, k, size=pl.FS_NOTE, color=INK, transform=ax.transAxes, weight="bold" if head else "normal")
        pl.note(ax, 0.74, y, v1, ha="right", size=pl.FS_NOTE, color=INK, transform=ax.transAxes, weight="bold" if head else "normal")
        pl.note(ax, 1.0, y, v2, ha="right", size=pl.FS_NOTE, color=INK, transform=ax.transAxes, weight="bold" if head else "normal")
        y -= 0.062
    w = d["wrong_key"]
    pl.note(ax, 0.0, y - 0.03, f"Mean of the three colour channels; {im['width']} × {im['height']} pixels,\nsealed uncompressed for this figure (the system\nstores JPEG). "
                              f"* a flat histogram stays under {ideal['chi_square_5pct_limit']:.0f}\nin 95 % of cases.\n"
                              f"Opening gives back every byte: {'yes' if im['round_trip_identical'] else 'NO'}.\n"
                              f"One bit of the file changed: {d['tamper']['refused']} of {d['tamper']['files_with_one_bit_changed']} refused.\n"
                              f"Key wrong in one bit: {'refused (tag)' if w['implementation_refuses'] else 'NOT refused'}.",
            va="top", size=pl.FS_MIN, color=INK2, transform=ax.transAxes, linespacing=1.3)
    pl.save(fig, "plot09_cipher_statistics")
    pl.table("plot09_cipher_statistics", ["picture", "channel", "entropy_bits", "chi_square", "correlation_right", "correlation_below", "correlation_diagonal"], tab)
    pl.table("plot09_npcr_uaci", ["compared", "npcr_pct", "uaci_pct", "values_that_differ", "values"],
             [[x["what"], x["npcr_pct"], x["uaci_pct"], x["values_that_differ"], x["values"]] for x in diff]
             + [["a key wrong in one bit, tag not checked, against the picture", w["without_the_tag_check"]["npcr_pct"], w["without_the_tag_check"]["uaci_pct"], "", ""],
                ["ideal: two unrelated uniform byte strings", round(ideal["npcr_pct"], 4), round(ideal["uaci_pct"], 4), "", ""]])
    return {"image": im["file"], "source": im["source"], "pixels": f"{im['width']}x{im['height']}", "entropy_cipher": cc["entropy_bits"], "chi_square_cipher": cc["chi_square"],
            "npcr": diff[0]["npcr_pct"], "uaci": diff[0]["uaci_pct"], "seal_ms": im["seal_ms_median"], "open_ms": im["open_ms_median"]}


# --------------------------------------------------------------------------------------------------- 10 attacks
def attacks():
    A = [(n, load(f)) for n, f in ((PI, "attacks_pi"), (LAPTOP, "attacks_laptop"))]
    A = [(n, d) for n, d in A if d]
    if not A:
        return {"skipped": "no attacks_*.json (bash run/kyber6g.sh measure attacks)"}
    from matplotlib.gridspec import GridSpec
    # The nonce experiment is a stress test of the sender (records sealed by racing threads), not an attacker's input:
    # it is counted on its own, in a note, and not among the attack attempts.
    RACE = "record: nonce reuse"
    names = [e["attack"] for e in A[-1][1]["experiments"] if e["expect"] == "refused" and e["attack"] != RACE]
    fig = plt.figure(figsize=(W2 * pl.MM, 112 * pl.MM))
    fig._k6g_bars = []
    gs = GridSpec(2, 2, figure=fig, width_ratios=[1.0, 1.02], height_ratios=[1.25, 1])
    a, b, c = fig.add_subplot(gs[:, 0]), fig.add_subplot(gs[0, 1]), fig.add_subplot(gs[1, 1])
    tab, total, accepted = [], 0, 0
    race = [(mach, e) for mach, d in A for e in d["experiments"] if e["attack"] == RACE]
    race_n, race_reused = sum(e["attempts"] for _, e in race), sum(e["accepted"] for _, e in race)
    a.set_xscale("log")
    counts = []
    for i, name in enumerate(names):
        y = len(names) - 1 - i
        n = 0
        for k, (mach, d) in enumerate(A):
            e = next((x for x in d["experiments"] if x["attack"] == name), None)
            if not e:
                continue
            n += e["attempts"]; total += e["attempts"]; accepted += e["accepted"]
            tab.append([name, mach, e["attempts"], e["accepted"], e["verdict"], "; ".join(f"{kk}: {vv}" for kk, vv in list(e["outcomes"].items())[:4])])
        counts.append(n)
        a.plot([1, n], [y, y], color=pl.tint(SERIES[0], 0.40), lw=2.6, solid_capstyle="butt", zorder=2)
        a.plot(n, y, linestyle="none", marker="o", color=SERIES[0], ms=4.4, zorder=4)
        pl.note(a, n * 1.6, y, f"{n:,}", color=INK)
    a.set_yticks(range(len(names)))
    a.set_yticklabels([n[0].upper() + n[1:] for n in reversed(names)], fontsize=pl.FS_TICK, color=INK)
    a.set_ylim(-0.7, len(names) - 0.3)
    a.set_xlim(1, 4e6)
    a.xaxis.set_major_locator(FixedLocator([1, 10, 100, 1000, 10000, 100000]))
    a.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{int(v):,}" if v < 10000 else f"{int(v) // 1000}k"))   # "10,000" and "100,000" would touch
    a.xaxis.set_minor_formatter(NullFormatter())
    a.grid(axis="y", visible=False)
    a.tick_params(axis="y", length=0)
    a.set_xlabel("Attack attempts made, both machines together")
    pl.panel(a, "a", f"{total:,} attack attempts, {accepted} accepted")
    if race:
        # beside the five neighbouring rows with the shortest bars: the right half of the panel is empty there
        w = 5
        i0 = min(range(len(counts) - w + 1), key=lambda i: max(counts[i:i + w])) if len(counts) >= w else 0
        pl.note(a, 3.2e6, len(names) - 1 - (i0 + (w - 1) / 2), f"Stress test of the\nsender: {race_n:,}\nrecords sealed by\neight racing threads,\n"
                                                              + ("no nonce used twice" if not race_reused else f"{race_reused} NONCES USED TWICE"),
                ha="right", va="center", linespacing=1.1)
        for mach, e in race:
            tab.append([RACE + " (stress test of the sender: records sealed, pairs used twice)", mach, e["attempts"], e["accepted"], e["verdict"],
                        "; ".join(f"{kk}: {vv}" for kk, vv in list(e["outcomes"].items())[:4])])

    # (b) the flood: time for a genuine UAV to connect against the rate of forged hellos
    ymax, fl = 0, []
    for k, (mach, d) in enumerate(A):
        e = next((x for x in d["experiments"] if x["attack"].startswith("flood")), None)
        if not e or "levels" not in e:
            continue
        lv = [l for l in e["levels"] if l["median_ms"] is not None]
        xs = [max(l["forged_per_s"], 30) for l in lv]                # no flood: drawn at the left edge of the log axis
        b.vlines(xs, [min(v for v in l["connect_ms"] if v) for l in lv], [l["max_ms"] for l in lv], color=pl.tint(SERIES[k], 0.45), lw=1.0, zorder=2)
        b.plot(xs, [l["median_ms"] for l in lv], **pl.series(k), label=f"Ground station on the {mach.split(' (')[0].replace('Laptop', 'laptop')}")
        ymax = max(ymax, max(l["max_ms"] for l in lv))
        for l in e["levels"]:
            fl.append([mach, l["target_per_s"], l["forged_per_s"], l["mbit_per_s"], l["connections"], l["connected"], l["median_ms"], l["max_ms"],
                       l["refused_after_signature_check"], l["dropped_unverified_by_the_ration"], e["outcomes"].get("ration of failed signature checks per second")])
    b.set_xscale("log"); b.set_yscale("log")
    b.set_ylim(2.5, max(1000, ymax * 12))                        # the legend sits above the slowest connection
    b.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}"))
    b.xaxis.set_major_formatter(FuncFormatter(lambda v, _: "none" if v < 50 else f"{int(v):,}"))
    b.xaxis.set_major_locator(FixedLocator([30, 100, 1000, 10000]))
    b.xaxis.set_minor_formatter(NullFormatter())
    b.set_xlim(22, 22000)
    b.set_xlabel("Forged ClientHellos per second")
    b.set_ylabel("Genuine UAV connects in (ms)")
    b.legend(loc="upper left")
    pl.panel(b, "b", "Flood of forged handshakes")

    # (c) the timing test
    rows = []
    for k, (mach, d) in enumerate(A):
        for t in d.get("timing") or []:
            rows.append((t["test"], mach, sorted(abs(v) for v in t.get("t_rounds", [t["t"]])), k, t))
    tests = list(dict.fromkeys(r[0] for r in rows))
    short = {0: "Record: tag wrong in its\nfirst or its last byte", 1: "Handshake MAC wrong in\nits first or last byte", 2: "Control: a comparison that\nstops at the first wrong byte"}
    for test, mach, tv, k, t in rows:
        y = len(tests) - 1 - tests.index(test) + (0.16 if k == 0 else -0.16)
        lo, hi = max(tv[0], 0.06), max(tv[-1], 0.06)
        c.plot([lo, hi], [y, y], color=pl.tint(SERIES[k], 0.40), lw=2.6, solid_capstyle="butt", zorder=2)       # the rounds, smallest to largest
        c.plot(hi, y, linestyle="none", marker=pl.MARKERS[k], color=SERIES[k], ms=4.4, zorder=4, label=mach if tests.index(test) == 0 else None)
        pl.note(c, hi * 1.45, y, f"{tv[-1]:.1f}" if tv[-1] < 100 else f"{tv[-1]:.0f}", color=INK, zorder=5,
                bbox={"facecolor": "white", "edgecolor": "none", "pad": 0.5})
        tab.append([f"timing: {test}", mach, sum(t["samples_per_class"]), "", f"|t| per round: {tv}", f"mean ns {t['mean_ns']}, difference {t['difference_ns']} ns"])
    c.axvline(4.5, color=MUTED, lw=0.6, zorder=1)
    pl.note(c, 5.3, len(tests) - 0.42, "over 4.5: a difference", size=pl.FS_MIN)
    c.set_xscale("log")
    c.set_xlim(0.05, 9000)
    c.set_yticks(range(len(tests)))
    c.set_yticklabels([short.get(i, tests[i][:30]) for i in reversed(range(len(tests)))], fontsize=pl.FS_TICK, color=INK, linespacing=1.0)
    c.set_ylim(-0.6, len(tests) - 0.1)
    c.xaxis.set_major_locator(FixedLocator([0.1, 1, 10, 100, 1000]))
    c.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    c.xaxis.set_minor_formatter(NullFormatter())
    c.grid(axis="y", visible=False)
    c.tick_params(axis="y", length=0)
    c.set_xlabel("|t| in five rounds (largest marked)")
    c.legend(loc="center right", bbox_to_anchor=(1.0, 0.62), handlelength=1.0)
    pl.panel(c, "c", "Timing of a refusal")
    pl.save(fig, "plot10_attacks")
    pl.table("plot10_attacks", ["experiment", "machine", "attempts", "accepted", "verdict", "reasons_given_or_result"], tab)
    pl.table("plot10_flood", ["ground_station_on", "forged_per_s_asked", "forged_per_s_sent", "mbit_per_s", "genuine_connections_tried", "connected", "median_ms", "slowest_ms",
                              "refused_after_signature_check", "dropped_unverified_by_the_ration", "ration_per_s"], fl)
    return {"attack_attempts": total, "accepted": accepted, "kinds_of_attack": len(names), "records_sealed_in_the_nonce_race": race_n,
            "nonce_pairs_used_twice": race_reused, "machines": [m for m, _ in A]}


# ------------------------------------------------------------------------------------------------------ tables
def tables():
    """Numbers the paper quotes that are not a plot: resources of the Pi by state, transfers, at-rest encryption."""
    out = {}
    idle, tl, tr, pi, lap = load("idle"), load("timeline"), load("transfer"), load("crypto_pi"), load("crypto_laptop")
    res = []
    if idle and tl:
        groups = [("idle (link up, camera off)", [r for r in idle["rows"] if "error" not in r and not r.get("cam_live")]),
                  ("live video", [r for r in tl["rows"] if "error" not in r and r.get("cam_live") and not r.get("cam_recording")]),
                  ("live video + encrypted recording", [r for r in tl["rows"] if "error" not in r and r.get("cam_recording")])]
        for name, rows in groups:
            f = lambda key: [r[key] for r in rows if r.get(key) is not None]
            if rows and f("uav_cpu"):
                res.append([name, len(rows), round(statistics.median(f("uav_cpu")), 1), round(pl.pct(sorted(f("uav_cpu")), 95), 1),
                            round(statistics.median(f("uav_mem_pct")), 1), round(statistics.median(f("uav_temp_c")), 1), round(max(f("uav_temp_c")), 1),
                            set(f("uav_throttled")).pop() if len(set(f("uav_throttled"))) == 1 else "varied"])
        pl.table("table_pi_resources", ["state", "samples", "cpu_median_pct", "cpu_p95_pct", "memory_pct", "temp_median_c", "temp_max_c", "throttled_flags"], res)
        out["resources"] = res
    if tr:
        k = rate(tr)
        rows = [["recording fetch", f["bytes"], round(f["transfer_s_raw"] / k, 3), round(f["bytes"] * 8 / (f["transfer_s_raw"] / k) / 1e6, 2), f["integrity"], f["decrypt"],
                 round(f["decrypt_ms_raw"] / k, 1) if f.get("decrypt_ms_raw") else None] for f in tr["fetches"] if f.get("transfer_s_raw")]
        rows += [["photo", p["bytes"], round(p["transfer_s_raw"] / k, 3), round(p["bytes"] * 8 / (p["transfer_s_raw"] / k) / 1e6, 2), p["integrity"], "", None]
                 for p in tr["photos"] if p.get("transfer_s_raw")]
        pl.table("table_transfers", ["what", "bytes", "transfer_s", "mbit_per_s", "sha256_check", "decrypt", "decrypt_ms"], rows)
        out["transfers"] = rows
        out["recording"] = tr["recording"]
    rest = []
    for d, name in ((pi, PI), (lap, LAPTOP)):
        for key, r in d["results"].items():
            if r["group"] == "at_rest":
                v = us(d, key)
                m = statistics.median(v)
                rest.append([name, key, len(v), round(m / 1000, 3), round(r["bytes_per_call"] / m, 1) if r.get("bytes_per_call") else "", r.get("note") or ""])
    pl.table("table_at_rest", ["machine", "operation", "n", "median_ms", "megabytes_per_s", "note"], rest)
    alt = []
    for d, name in ((pi, PI), (lap, LAPTOP)):
        for key, r in d["results"].items():
            if r["group"] in ("variants", "primitives") and any(a_ in key for a_ in ("ML-KEM", "ML-DSA", "X25519", "Ed25519")):
                v = us(d, key)
                alt.append([name, key, len(v), round(statistics.median(v), 2), round(pl.pct(v, 5), 2), round(pl.pct(v, 95), 2)])
    pl.table("table_algorithm_variants", ["machine", "operation", "n", "median_us", "p5_us", "p95_us"], alt)
    out["variant_sizes"] = pi.get("variant_sizes")
    steps = []
    for d, name in ((pi, PI), (lap, LAPTOP)):
        for key, r in d["results"].items():
            if r["group"] == "handshake":
                v = us(d, key)
                steps.append([name, key, len(v), round(statistics.median(v), 2), round(pl.pct(v, 5), 2), round(pl.pct(v, 95), 2)])
    pl.table("table_protocol_steps", ["machine", "step", "n", "median_us", "p5_us", "p95_us"], steps)
    env = [[name, e["cpu_model"], e["machine"], e["platform"], e["python"], e["liboqs"], e["cryptography"], e["openssl"], e["cpu_has_aes"], e["governor"], e["temp_c"],
            d["clock"]["local_per_reference_second"]] for d, name in ((pi, PI), (lap, LAPTOP)) for e in [d["environment"]]]
    pl.table("table_environment", ["machine", "cpu", "arch", "platform", "python", "liboqs", "cryptography", "openssl", "cpu_has_aes", "governor", "temp_c", "clock_rate"], env)
    out["at_rest"] = rest
    return out


PLOTS = {"crypto_primitives": crypto_primitives, "handshake_latency": handshake_latency, "wire_bytes": wire_bytes, "aead_throughput": aead_throughput,
         "timeline": timeline, "loss": loss, "latency": latency, "media_protection": media_protection, "cipher_statistics": cipher_statistics,
         "attacks": attacks, "tables": tables}
import audio_plots                                               # noqa: E402 - the plots about sealed audio (plot17 to plot20)
PLOTS.update(audio_plots.PLOTS)
import assurance_plots                                           # noqa: E402 - plot21 (motion watch), plot22 (what is proved)
PLOTS.update(assurance_plots.PLOTS)


def main():
    pl.setup()
    want = sys.argv[1:] or list(PLOTS)
    summary = {}
    for name in want:
        try:
            summary[name] = PLOTS[name]()
            print(f"[ok]   {name}: {json.dumps(summary[name], default=str)[:700]}")
        except Exception as e:
            import traceback
            print(f"[FAIL] {name}: {type(e).__name__}: {e}")
            traceback.print_exc()
            summary[name] = {"error": f"{type(e).__name__}: {e}"}
    (pl.ROOT / "checks").mkdir(exist_ok=True)
    (pl.ROOT / "checks" / "plot_summary.json").write_text(json.dumps(summary, indent=1, default=str))
    return 1 if any("error" in (v or {}) for v in summary.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
