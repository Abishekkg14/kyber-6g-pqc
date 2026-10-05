"""The plots about sealed audio (plot17 to plot20), drawn from the files kyber6g.tools.audio_bench wrote to ../data.

    audio_stats.json                              the sample decoded to PCM, sealed; a variable-bit-rate encoding of it
    audio_attacks_pi.json, audio_attacks_laptop.json    attack experiments on the sealed format, on both machines
    audio_cost_pi.json, audio_cost_laptop.json          time and bytes against the length of a clip, excerpts
    audio_loss.json                               a clip sent while it is sealed, with datagrams dropped on the Pi

Nothing here contains a measured number. The one thing computed here that is not read from a file is the rule by
which the number of blocks is rounded up (quaver.padme): it is part of the format, not a measurement.
"""
import statistics
import sys

import numpy as np
from matplotlib.colors import LinearSegmentedColormap
from matplotlib.gridspec import GridSpec
from matplotlib.ticker import FixedLocator, FuncFormatter, NullFormatter

import plotlib as pl
from plotlib import INK, INK2, MUTED, NEUTRAL, SERIES, W2, plt

sys.path.insert(0, str(pl.ROOT.parent))
PI, LAPTOP = "Raspberry Pi 4B (UAV)", "Laptop (ground station)"


def load(name):
    import json
    p = pl.DATA / f"{name}.json"
    return json.loads(p.read_text()) if p.exists() else None


def rate(d):
    return (d.get("clock") or {}).get("local_per_reference_second") or 1.0


def new_fig(height_mm):
    fig = plt.figure(figsize=(W2 * pl.MM, height_mm * pl.MM))
    fig._k6g_bars = []
    return fig


# ------------------------------------------------------------------------------------------- 17 a sound, sealed
def audio_statistics():
    d = load("audio_stats")
    if not d:
        return {"skipped": "no audio_stats.json (bash run/kyber6g.sh measure audio)"}
    p, ideal = d["pcm"], d["ideal"]
    secs = p["seconds"]
    fig = new_fig(104)
    gs = GridSpec(2, 4, figure=fig, width_ratios=[1.2, 1.2, 0.95, 1.5])
    shade = LinearSegmentedColormap.from_list("k6g_blue", ["#FFFFFF", pl.tint(SERIES[0], 0.45), SERIES[0], "#14254A"])     # one hue, light to dark
    spec = {k: np.array(p["spectrogram_db"][k]) for k in ("plain", "cipher")}
    top = max(float(v.max()) for v in spec.values())
    for r, kind in enumerate(("plain", "cipher")):
        ax = fig.add_subplot(gs[r, 0])
        lo, hi = (np.array(v) / 32768 for v in p["envelope"][kind])
        ax.fill_between(np.linspace(0, secs, len(lo)), lo, hi, color=SERIES[0], lw=0)
        ax.set_xlim(0, secs); ax.set_ylim(-1.08, 1.08)
        ax.yaxis.set_major_locator(FixedLocator([-1, 0, 1]))
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Sample value (full scale 1)")
        pl.panel(ax, "ad"[r], "The sound" if r == 0 else "As stored")
        ax = fig.add_subplot(gs[r, 1])
        ax.imshow(spec[kind], origin="lower", aspect="auto", extent=(0, secs, 0, p["spectrogram_db"]["frequency_max_hz"] / 1000),
                  cmap=shade, vmin=top - 80, vmax=top, interpolation="nearest")
        ax.grid(False)
        ax.set_xlabel("Time (s)")
        ax.set_ylabel("Frequency (kHz)")
        pl.panel(ax, "be"[r], "Spectrogram")
        ax = fig.add_subplot(gs[r, 2])
        h = np.array(p[kind]["histogram_128_bins"])
        ax.fill_between((np.arange(128) + 0.5) / 64 - 1, h / 1000, step="mid", color=SERIES[0], lw=0)
        ax.set_xlim(-1, 1); ax.set_ylim(0, None)
        ax.xaxis.set_major_locator(FixedLocator([-1, 0, 1]))
        ax.set_xlabel("Sample value")
        ax.set_ylabel("Thousand samples")
        pl.panel(ax, "cf"[r], "Histogram")
    ax = fig.add_subplot(gs[:, 3])
    ax.axis("off")
    pc, cc, wk, diff = p["plain"], p["cipher"], p["wrong_key"], d["differences"]
    lines = [("Measure", "sound", "as stored"),
             ("Entropy (bits of 8)", f"{pc['bytes']['entropy_bits_per_byte']:.3f}", f"{cc['bytes']['entropy_bits_per_byte']:.4f}"),
             ("Correlation, lag 1", f"{pc['correlation_with_next_sample']:.3f}", f"{cc['correlation_with_next_sample']:+.4f}"),
             ("Correlation, lag 2", f"{pc['correlation_at_lag_2']:.3f}", f"{cc['correlation_at_lag_2']:+.4f}"),
             ("Spectral flatness†", f"{pc['spectral_flatness']:.3f}", f"{cc['spectral_flatness']:.3f}"),
             ("χ² against flat*", f"{pc['bytes']['chi_square']:.3g}", f"{cc['bytes']['chi_square']:.0f}"),
             None,
             ("Two stored copies", "NSCR", "UACI"),
             ("Sealed twice", f"{diff[0]['bytes']['nscr_pct']:.2f} %", f"{diff[0]['bytes']['uaci_pct']:.2f} %"),
             ("1 sample changed", f"{diff[1]['bytes']['nscr_pct']:.2f} %", f"{diff[1]['bytes']['uaci_pct']:.2f} %"),
             ("Random (ideal)", f"{ideal['nscr_bytes_pct']:.2f} %", f"{ideal['uaci_bytes_pct']:.2f} %")]
    y = 0.965
    for i, row in enumerate(lines):
        if row is None:
            y -= 0.035
            continue
        w = "bold" if i in (0, 7) else "normal"
        pl.note(ax, 0.0, y, row[0], color=INK, transform=ax.transAxes, weight=w)
        pl.note(ax, 0.74, y, row[1], ha="right", color=INK, transform=ax.transAxes, weight=w)
        pl.note(ax, 1.0, y, row[2], ha="right", color=INK, transform=ax.transAxes, weight=w)
        y -= 0.062
    rep = p["repeated_16_byte_blocks"]
    pl.note(ax, 0.0, y - 0.03,
            f"{secs:.1f} s of 16-bit samples at {p['sample_rate'] / 1000:g} kHz, sealed uncompressed\nfor this figure (the system seals the encoder's frames).\n"
            f"* a flat histogram stays under {ideal['chi_square_5pct_limit']:.0f} in 95 % of cases.\n† white noise: {ideal['spectral_flatness_white_noise']:.2f}. "
            f"Shading: 80 dB, darker is stronger.\n"
            f"Stored against the sound: correlation {cc['correlation_with_the_plain_signal']:+.4f}.\n"
            f"Repeated 16-byte pieces: {rep['plain']:,} in the sound, {rep['cipher']} as stored.\n"
            f"Opening gives back every byte: {'yes' if p['opened']['identical_to_the_source'] else 'NO'}.\n"
            f"Key wrong in one bit: refused; without the checks it\ngives noise (correlation {wk['correlation_with_the_plain_signal']:+.4f}).",
            va="top", size=pl.FS_MIN, color=INK2, transform=ax.transAxes, linespacing=1.3)
    pl.save(fig, "plot17_audio_statistics")
    pl.table("plot17_audio_statistics", ["signal", "samples", "entropy_bits_per_byte", "chi_square_bytes", "correlation_next_sample", "correlation_lag_2",
                                         "spectral_flatness", "correlation_with_the_sound", "snr_db", "psnr_db"],
             [["the sound (PCM)", pc["samples"], pc["bytes"]["entropy_bits_per_byte"], pc["bytes"]["chi_square"], pc["correlation_with_next_sample"],
               pc["correlation_at_lag_2"], pc["spectral_flatness"], "", "", ""]]
             + [[name, s["samples"], s.get("bytes", {}).get("entropy_bits_per_byte", ""), s.get("bytes", {}).get("chi_square", ""), s["correlation_with_next_sample"],
                 s["correlation_at_lag_2"], s["spectral_flatness"], s["correlation_with_the_plain_signal"], s["snr_db"], s["psnr_db"]]
                for name, s in (("as stored (ciphertext at the place of every sample)", cc), ("key wrong in one bit, checks removed", wk))])
    pl.table("plot17_nscr_uaci", ["compared", "nscr_bytes_pct", "uaci_bytes_pct", "nscr_16_bit_pct", "uaci_16_bit_pct", "values_that_differ", "values"],
             [[x["what"], x["bytes"]["nscr_pct"], x["bytes"]["uaci_pct"], x["samples_16_bit"]["nscr_pct"], x["samples_16_bit"]["uaci_pct"], x["values_that_differ"], x["values"]]
              for x in diff]
             + [["ideal: two unrelated uniform byte strings", round(ideal["nscr_bytes_pct"], 4), round(ideal["uaci_bytes_pct"], 4),
                 round(ideal["nscr_16_bit_pct"], 5), round(ideal["uaci_16_bit_pct"], 4), "", ""]])
    comp = d["compressed"]
    pl.table("plot17_compressed_file", ["what", "bytes", "entropy_bits_per_byte", "chi_square"],
             [["the source file (compressed audio)", comp["plain"]["bytes"], comp["plain"]["entropy_bits_per_byte"], comp["plain"]["chi_square"]],
              ["its sealed blocks", comp["sealed_blocks"]["bytes"], comp["sealed_blocks"]["entropy_bits_per_byte"], comp["sealed_blocks"]["chi_square"]]])
    return {"source": d["source"]["file"], "seconds": secs, "entropy_cipher": cc["bytes"]["entropy_bits_per_byte"], "chi_square_cipher": cc["bytes"]["chi_square"],
            "correlation_plain": pc["correlation_with_next_sample"], "correlation_cipher": cc["correlation_with_next_sample"],
            "nscr": diff[0]["bytes"]["nscr_pct"], "uaci": diff[0]["bytes"]["uaci_pct"], "identical": p["opened"]["identical_to_the_source"]}


# ---------------------------------------------------------------------------------- 18 what the sizes give away
def audio_shape():
    st = load("audio_stats")
    cost = load("audio_cost_pi") or load("audio_cost_laptop")
    att = load("audio_attacks_laptop") or load("audio_attacks_pi")
    if not st or not cost:
        return {"skipped": "no audio_stats.json / audio_cost_*.json (bash run/kyber6g.sh measure audio)"}
    from kyber6g.audio.quaver import padme
    s = st["shape"]
    fig = new_fig(98)
    gs = GridSpec(2, 2, figure=fig, width_ratios=[1.25, 1.0])
    a, b, c, e = fig.add_subplot(gs[0, 0]), fig.add_subplot(gs[1, 0]), fig.add_subplot(gs[0, 1]), fig.add_subplot(gs[1, 1])
    sizes = np.array(s["frame_bytes"])
    t = np.arange(len(sizes)) * s["frame_ms"] / 1000
    span = min(float(t[-1]), 30.0)
    a.step(t, sizes, where="post", color=SERIES[1], lw=0.55)
    a.set_xlim(0, span); a.set_ylim(0, s["frame_bytes_max"] * 1.3)
    a.set_ylabel("Bytes in a frame")
    a.set_xlabel("Time (s)")
    pl.note(a, span * 0.985, s["frame_bytes_max"] * 1.2, f"{s['distinct_frame_sizes']} sizes, {s['frame_bytes_min']} to {s['frame_bytes_max']} bytes; "
            f"the size changes {s['frame_size_changes']:,} times in {s['frames']:,} frames", ha="right")
    pl.panel(a, "a", "Encrypted frame by frame: each frame shows its size")
    nb = int(span * 1000 / s["block_ms"])
    b.step(np.arange(nb + 1) * s["block_ms"] / 1000, [s["sealed_block_bytes"]] * (nb + 1), where="post", color=SERIES[0], lw=1.2)
    b.set_xlim(0, span); b.set_ylim(0, s["sealed_block_bytes"] * 1.3)
    b.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,.0f}"))
    b.set_ylabel("Bytes in a block")
    b.set_xlabel("Time (s)")
    pl.note(b, span * 0.985, s["sealed_block_bytes"] * 1.15, f"1 size: {s['sealed_block_bytes']:,} bytes, one block every {s['block_ms']:.0f} ms, whatever is said",
            ha="right")
    pl.panel(b, "b", "Sealed: every block has the same size")
    # (c) the length of a clip is rounded up
    need = np.arange(3, 603)
    c.plot(need, need, color=NEUTRAL, lw=0.9, linestyle=(0, (4.5, 1.6)), marker="None", label="Blocks needed")
    c.step(need, [padme(int(n)) for n in need], where="post", color=SERIES[0], lw=1.2, label="Blocks stored")
    c.set_xlim(0, 600); c.set_ylim(0, 680)
    c.set_xlabel("Blocks the clip needs")
    c.set_ylabel("Blocks")
    c.legend(loc="upper left")
    rows = (att or {}).get("shape", {}).get("padded_length") or []
    if rows:
        r = rows[-2] if len(rows) > 1 else rows[-1]
        pl.note(c, 590, 70, f"clips of {r['clips_of']}: {r['different_lengths']:,} lengths\nshow as {r['different_padded_lengths']} ({r['padding_pct_mean']:.1f} % padding on average)",
                ha="right", linespacing=1.15)
    pl.panel(c, "c", "The length is rounded up")
    # (d) what the uniform shape costs
    xs = [r["seconds"] for r in cost["by_length"]]
    # three marks, each named beside it: a legend would have to sit on one of them
    e.plot(xs, [r["added_pct"] for r in cost["by_length"]], **pl.series(0))
    comp, at = st["compressed"], st["pcm"]["seconds"]
    e.plot([at], [comp["added_pct"]], linestyle="none", marker=pl.MARKERS[2], color=SERIES[2], ms=5)
    e.plot([at], [s["added_pct"]], linestyle="none", marker=pl.MARKERS[1], color=SERIES[1], ms=5)
    pl.note(e, cost["by_length"][1]["seconds"] * 1.25, cost["by_length"][1]["added_pct"] * 1.45, "constant bit rate, 128 kbit/s", ha="left", va="bottom")
    pl.note(e, at * 0.82, comp["added_pct"] * 0.86, "the sample as it is\n(256 kbit/s, constant)", ha="right", va="top", linespacing=1.1)
    pl.note(e, at * 1.3, s["added_pct"], "the sample at a variable bit rate", ha="left")
    e.set_xscale("log"); e.set_yscale("log")
    e.set_xlim(0.7, 1300); e.set_ylim(2, 600)
    e.xaxis.set_major_locator(FixedLocator(xs))
    e.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    e.xaxis.set_minor_formatter(NullFormatter())
    e.yaxis.set_major_locator(FixedLocator([3, 10, 30, 100, 300]))
    e.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    e.yaxis.set_minor_formatter(NullFormatter())
    e.set_xlabel("Length of the clip (s)")
    e.set_ylabel("Bytes added (% of the audio)")
    pl.panel(e, "d", "What it costs")
    pl.save(fig, "plot18_audio_shape")
    pl.table("plot18_audio_shape", ["quantity", "value"],
             [["frames of the variable-bit-rate encoding", s["frames"]], ["different frame sizes", s["distinct_frame_sizes"]],
              ["smallest frame (bytes)", s["frame_bytes_min"]], ["largest frame (bytes)", s["frame_bytes_max"]],
              ["entropy of the frame size (bits per frame)", s["frame_size_entropy_bits"]], ["frame size changes", s["frame_size_changes"]],
              ["correlation of frame size with loudness", s["correlation_frame_size_with_loudness"]],
              ["sealed block (bytes)", s["sealed_block_bytes"]], ["sealed blocks", s["sealed_blocks"]], ["different block sizes", s["distinct_block_sizes"]],
              ["variable-rate source (bytes)", s["source_bytes"]], ["sealed (bytes)", s["sealed_bytes"]], ["added (%)", s["added_pct"]],
              ["per-frame encryption would take (bytes)", s["per_frame_encryption_bytes"]],
              ["with the frame cap of 320 kbit/s: block (bytes)", s["with_cap_320_kbit"]["block_bytes"]], ["with that cap: added (%)", s["with_cap_320_kbit"]["added_pct"]],
              ["the sample as it is (constant 256 kbit/s): added (%)", comp["added_pct"]]])
    pl.table("plot18_padded_length", ["clips_of", "audio_blocks_from", "to", "different_lengths", "different_padded_lengths", "lengths_per_padded_length",
                                      "padding_pct_worst", "padding_pct_mean"],
             [[r[k] for k in ("clips_of", "audio_blocks_from", "to", "different_lengths", "different_padded_lengths", "lengths_per_padded_length",
                              "padding_pct_worst", "padding_pct_mean")] for r in rows])
    if att:
        pl.table("plot18_three_recordings", ["recording", "source_bytes", "frame_sizes", "frame_bytes_min", "frame_bytes_max", "sealed_bytes_with_cap",
                                             "block_bytes_with_cap", "blocks_with_cap", "block_bytes_without_cap", "per_frame_encryption_bytes"],
                 [[r[k] for k in ("recording", "source_bytes", "frame_sizes_distinct", "frame_bytes_min", "frame_bytes_max", "sealed_bytes_with_cap",
                                  "block_bytes_with_cap", "blocks_with_cap", "block_bytes_without_cap", "per_frame_encryption_bytes")] for r in att["shape"]["recordings"]])
    return {"frame_sizes": s["distinct_frame_sizes"], "block_sizes": s["distinct_block_sizes"], "vbr_added_pct": s["added_pct"], "cbr_sample_added_pct": comp["added_pct"],
            "added_pct_by_length": {r["seconds"]: r["added_pct"] for r in cost["by_length"]}}


# ------------------------------------------------------------------------------------------------- 19 the cost
def audio_cost():
    pi, lap = load("audio_cost_pi"), load("audio_cost_laptop")
    if not pi and not lap:
        return {"skipped": "no audio_cost_*.json (bash run/kyber6g.sh measure audio)"}
    M = [(n, d, k) for k, (n, d) in enumerate(((PI, pi), (LAPTOP, lap))) if d]
    fig = new_fig(66)
    gs = GridSpec(1, 3, figure=fig, width_ratios=[1, 1, 1.05])
    a, b, c = (fig.add_subplot(gs[0, i]) for i in range(3))
    tab = []
    for ax, key, title in ((a, "seal_ms", "Sealing a clip"), (b, "open_ms", "Verifying and opening it")):
        for name, d, k in M:
            rows = d["by_length"]
            ax.plot([r["seconds"] for r in rows], [r[key] for r in rows], **pl.series(k), label=name)
            if ax is a:
                tab += [[name, r["seconds"], r["frames"], r["source_bytes"], r["sealed_bytes"], r["blocks"], r["block_bytes"], r["added_pct"], r["seal_ms"],
                         r["seal_blocks_only_ms"], r["seal_us_per_block"], r["open_ms"], r["verify_without_keys_ms"], r["seal_realtime_factor"], r["seal_mb_per_s"],
                         r["open_mb_per_s"]] for r in rows]
        ax.set_xscale("log"); ax.set_yscale("log")
        xs = [r["seconds"] for r in M[0][1]["by_length"]]
        ax.set_xlim(0.7, 1300)
        ax.xaxis.set_major_locator(FixedLocator(xs))
        ax.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
        ax.xaxis.set_minor_formatter(NullFormatter())
        ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:,g}"))
        ax.set_xlabel("Length of the clip (s)")
        ax.set_ylabel("Time (ms)")
        ax.legend(loc="upper left")
        pl.panel(ax, "a" if ax is a else "b", title)
    # the slowest machine at the longest clip: how far from real time
    name, d, k = M[0]
    last = d["by_length"][-1]
    lowest = min(r["seal_ms"] for _, d_, _ in M for r in d_["by_length"])
    pl.note(a, 1200, lowest * 1.05, f"{name.split(' (')[0]}: {last['seconds'] // 60} min of audio\nin {last['seal_ms'] / 1000:.2f} s ({last['seal_realtime_factor']:,.0f} × real time)",
            ha="right", va="bottom", linespacing=1.15)
    ex = (lap or pi)["excerpts"]
    xs = [r["seconds"] for r in ex["rows"]]
    c.plot(xs, [r["share_of_clip_pct"] for r in ex["rows"]], **pl.series(1 if lap else 0))
    for r in ex["rows"]:
        pl.note(c, r["seconds"] * 1.25, r["share_of_clip_pct"] * 0.8, f"at most {r['keys_released_max']} keys", ha="left", va="top")
    c.set_xscale("log"); c.set_yscale("log")
    c.set_xlim(0.7, 1400); c.set_ylim(0.05, 200)
    c.xaxis.set_major_locator(FixedLocator(xs))
    c.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    c.xaxis.set_minor_formatter(NullFormatter())
    c.yaxis.set_major_locator(FixedLocator([0.1, 1, 10, 100]))
    c.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
    c.yaxis.set_minor_formatter(NullFormatter())
    c.set_xlabel("Length of the excerpt (s)")
    c.set_ylabel("Size of the excerpt (% of the clip)")
    pl.note(c, 0.85, 120, f"a 10-minute clip: {ex['clip_blocks']:,} blocks,\none key each", va="top", linespacing=1.15)
    pl.panel(c, "c", "An excerpt for someone else")
    pl.save(fig, "plot19_audio_cost")
    pl.table("plot19_audio_cost", ["machine", "clip_s", "frames", "source_bytes", "sealed_bytes", "blocks", "block_bytes", "added_pct", "seal_ms", "seal_blocks_only_ms",
                                   "seal_us_per_block", "open_ms", "verify_without_keys_ms", "seal_times_real_time", "seal_mb_per_s", "open_mb_per_s"], tab)
    pl.table("plot19_audio_pieces", ["machine", "piece", "median_ms"], [[name, k_, v] for name, d, _ in M for k_, v in d["pieces_ms"].items()])
    pl.table("plot19_audio_excerpts", ["machine", "excerpt_s", "blocks", "bundle_bytes", "share_of_clip_pct", "keys_released_median", "keys_released_max",
                                       "proof_nodes_median", "bytes_besides_the_blocks", "make_ms", "verify_ms"],
             [[name, r["seconds"], r["blocks"], r["bundle_bytes"], r["share_of_clip_pct"], r["keys_released_median"], r["keys_released_max"], r["proof_nodes_median"],
               r["bytes_besides_the_blocks"], r["make_ms"], r["verify_ms"]] for name, d, _ in M for r in d["excerpts"]["rows"]])
    pl.table("plot19_frames_per_block", ["machine", "frames_per_block", "block_ms", "block_bytes", "blocks", "datagrams_per_block", "added_pct", "seal_ms"],
             [[name, r["frames_per_block"], r["block_ms"], r["block_bytes"], r["blocks"], r["datagrams_per_block"], r["added_pct"], r["seal_ms"]]
              for name, d, _ in M for r in d["frames_per_block"]["rows"]])
    pl.table("plot19_bit_rate", ["machine", "kbit_s", "source_bytes", "sealed_bytes", "block_bytes", "added_pct"],
             [[name, r["kbit_s"], r["source_bytes"], r["sealed_bytes"], r["block_bytes"], r["added_pct"]] for name, d, _ in M for r in d["bit_rate"]["rows"]]
             + [[name, "PCM 16 kHz mono", d["pcm"]["source_bytes"], d["pcm"]["sealed_bytes"], d["pcm"]["block_bytes"], d["pcm"]["added_pct"]] for name, d, _ in M])
    return {"machines": [n for n, _, _ in M], "seal_ms_60s": {n: next(r["seal_ms"] for r in d["by_length"] if r["seconds"] == 60) for n, d, _ in M},
            "open_ms_60s": {n: next(r["open_ms"] for r in d["by_length"] if r["seconds"] == 60) for n, d, _ in M}, "pieces_ms": {n: d["pieces_ms"] for n, d, _ in M}}


# ---------------------------------------------------------------------------- 20 attacks, and loss on the link
MERGE = [("one bit changed", "One bit changed in the clip"), ("two blocks exchanged", "Blocks moved, repeated, removed or added"),
         ("a block repeated", "Blocks moved, repeated, removed or added"), ("a block removed", "Blocks moved, repeated, removed or added"),
         ("a block added", "Blocks moved, repeated, removed or added"), ("the clip cut short", "Clip cut short"),
         ("a block borrowed", "Parts of another clip put in"), ("root record and signature of another clip", "Parts of another clip put in"),
         ("signed again", "Signed or made by another key"), ("a clip made by the attacker", "Signed or made by another key"),
         ("opened with other recipient keys", "Opened with other recipient keys"), ("header rewritten", "Header rewritten (downgrade)"),
         ("a cut-off clip passed", "Cut-off clip passed as complete"),
         ("the excerpt said to be other blocks", "Excerpt said to be other blocks"), ("a block exchanged inside", "Block exchanged in an excerpt"),
         ("another key passed off", "Another key passed off for a block"), ("the proof of one clip", "Proof of one clip, blocks of another"),
         ("an excerpt cut short", "Excerpt cut short or extended"), ("an excerpt of a recording", "Excerpt of a recording never made"),
         ("the released keys tried", "Released keys tried on other blocks"),
         ("blocks changed on the air", "Live blocks changed on the air"), ("the repair itself is wrong", "Live clip: wrong repair or signature"),
         ("the signature of another clip after", "Live clip: wrong repair or signature"),
         ("a clip deleted", "Clip deleted, replaced or misplaced"), ("a clip replaced", "Clip deleted, replaced or misplaced"),
         ("a clip from another chain", "Clip deleted, replaced or misplaced"), ("a key used twice", "A key used twice"),
         ("three different recordings", "Recordings told apart by their sizes")]


def row_of(e):
    name = e["attack"]
    if e["group"] == "excerpt" and name.startswith("one bit changed"):
        return "One bit changed in an excerpt"
    return next((label for key, label in MERGE if name.startswith(key)), name[0].upper() + name[1:])


def audio_attacks():
    A = [(n, load(f)) for n, f in ((PI, "audio_attacks_pi"), (LAPTOP, "audio_attacks_laptop"))]
    A = [(n, d) for n, d in A if d]
    L = load("audio_loss")
    if not A:
        return {"skipped": "no audio_attacks_*.json (bash run/kyber6g.sh measure audio)"}
    fig = new_fig(112)
    gs = GridSpec(2, 2, figure=fig, width_ratios=[1.0, 0.9])
    a, b, c = fig.add_subplot(gs[:, 0]), fig.add_subplot(gs[0, 1]), fig.add_subplot(gs[1, 1])
    counts, order, tab, total, accepted, crashes = {}, [], [], 0, 0, 0
    for mach, d in A:
        for e in d["experiments"]:
            tab.append([e["group"], e["attack"], mach, e["expect"], e["attempts"], e["accepted"], e["crashes"], e["verdict"],
                        "; ".join(f"{k}: {v}" for k, v in list(e["outcomes"].items())[:4])])
            if e["expect"] != "refused":
                continue
            r = row_of(e)
            if r not in counts:
                order.append(r)
            counts[r] = counts.get(r, 0) + e["attempts"]
            total += e["attempts"]; accepted += e["accepted"]; crashes += e["crashes"]
    a.set_xscale("log")
    for i, r in enumerate(order):
        y = len(order) - 1 - i
        a.plot([1, counts[r]], [y, y], color=pl.tint(SERIES[0], 0.40), lw=2.6, solid_capstyle="butt", zorder=2)
        a.plot(counts[r], y, linestyle="none", marker="o", color=SERIES[0], ms=4.4, zorder=4)
        pl.note(a, counts[r] * 1.6, y, f"{counts[r]:,}", color=INK)
    a.set_yticks(range(len(order)))
    a.set_yticklabels(list(reversed(order)), fontsize=pl.FS_TICK, color=INK)
    a.set_ylim(-0.7, len(order) - 0.3)
    a.set_xlim(1, 2e5)
    a.xaxis.set_major_locator(FixedLocator([1, 10, 100, 1000, 10000]))
    a.xaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{int(v):,}"))
    a.xaxis.set_minor_formatter(NullFormatter())
    a.grid(axis="y", visible=False)
    a.tick_params(axis="y", length=0)
    a.set_xlabel("Attack attempts made, both machines together")
    pl.panel(a, "a", f"{total:,} attack attempts, {accepted} accepted")
    out = {"attack_attempts": total, "accepted": accepted, "crashes": crashes, "rows": len(order), "machines": [m for m, _ in A]}
    lt = []
    if L:
        k = rate(L)
        fs = sorted({r["frames_per_block"] for r in L["runs"]}, reverse=True)
        for i, F in enumerate(fs):
            runs = [r for r in L["runs"] if r["frames_per_block"] == F and r.get("blocks")]
            if not runs:
                continue
            up = lambda r: 100 * (r["counters_after"].get("drop-out", 0) - r["counters_before"].get("drop-out", 0)) / max(
                r["counters_after"].get("seen-out", 0) - r["counters_before"].get("seen-out", 0), 1)
            dg = -(-runs[0]["block_bytes"] // 1100)
            x = [up(r) for r in runs]
            b.plot(x, [100 * r["on_air"] / r["blocks"] for r in runs], **pl.series(i),
                   label=f"{F} frame{'s' if F > 1 else ''} a block ({dg} datagram{'s' if dg > 1 else ''})")
            px = np.linspace(0, 24, 100)
            b.plot(px, 100 * (1 - px / 100) ** dg, color=NEUTRAL, lw=0.7, marker="None", zorder=1)
            c.plot(x, [100 * r["heard_share"] for r in runs], **pl.series(i), label=f"{F} frame{'s' if F > 1 else ''} a block")
            for r in runs:
                lt.append([F, r["nominal_pct"], round(up(r), 3), r["blocks"], r["block_bytes"], dg, r["on_air"], r["repaired"], r.get("requests_for_blocks"), r["refused"],
                           round(100 * r["heard_share"], 2), r["completed"], r["verified"], r["identical_to_the_source"],
                           round(r["seconds_until_stored_raw"] / k, 2) if r.get("seconds_until_stored_raw") else "", r.get("duration_s")])
        for ax in (b, c):
            ax.set_xlim(-0.8, 24); ax.set_ylim(0, 108)
            ax.xaxis.set_major_locator(FixedLocator([0, 5, 10, 15, 20]))
            ax.yaxis.set_major_locator(FixedLocator([0, 25, 50, 75, 100]))
            ax.set_xlabel("Datagrams dropped on the way down (%)")
        b.set_ylabel("Blocks that arrived on the air (%)")
        c.set_ylabel("Audio a listener heard live (%)")
        b.legend(loc="lower left")
        c.legend(loc="lower left")
        done = [r for r in L["runs"] if r.get("blocks")]
        good = sum(1 for r in done if r["verified"] and r["identical_to_the_source"])
        pl.panel(b, "b", "A clip sent while it is sealed, under loss")
        pl.panel(c, "c", f"Stored whole and verified: {good} of {len(L['runs'])} clips")
        pl.note(b, 23.6, 101, "grey: (1 − loss) to the power of\nthe datagrams in a block", ha="right", va="top", size=pl.FS_MIN, linespacing=1.1)
        out.update(live_clips=len(L["runs"]), stored_and_verified=good, blocks_fetched_again=sum(r["repaired"] or 0 for r in done))
    else:
        for ax, letter in ((b, "b"), (c, "c")):
            ax.axis("off")
            pl.note(ax, 0.5, 0.5, "not measured", ha="center", transform=ax.transAxes)
    pl.save(fig, "plot20_audio_attacks")
    pl.table("plot20_audio_attacks", ["group", "experiment", "machine", "expected", "attempts", "accepted", "crashes", "verdict", "reasons_given_or_result"], tab)
    pl.table("plot20_audio_live_loss", ["frames_per_block", "nominal_loss_pct", "uplink_loss_pct", "blocks", "block_bytes", "datagrams_per_block", "arrived_on_the_air",
                                        "fetched_again_from_the_card", "requests_for_blocks", "refused", "heard_live_pct", "completed", "verified", "identical_to_the_source",
                                        "seconds_until_stored", "clip_s"], lt)
    t = [(m, d["timing"]) for m, d in A]
    pl.table("plot20_audio_timing", ["machine", "clip_blocks", "runs_each", "place", "median_ms", "spread_between_places_ms", "spread_of_the_control_ms", "verdict"],
             [[m, x["clip_blocks"], x["runs_each"], place, ms, x["spread_between_places_ms"], x["spread_of_the_control_ms"], x["verdict"]]
              for m, x in t for place, ms in x["median_ms"].items()])
    out["timing"] = {m: x["verdict"] for m, x in t}
    return out


PLOTS = {"audio_statistics": audio_statistics, "audio_shape": audio_shape, "audio_cost": audio_cost, "audio_attacks": audio_attacks}
