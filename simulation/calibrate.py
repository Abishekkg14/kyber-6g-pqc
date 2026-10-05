#!/usr/bin/env python3
"""Calibration of the simulation from the measurements (paper_plots/data) and from the implementation itself.

    python simulation/calibrate.py            ->  simulation/calibration/k6g_calibration.txt   (read by the ns-3 program)
                                                  simulation/calibration/k6g_calibration.json  (the same, with provenance)

Nothing in the simulation's model of the protocol is a free parameter:

  from the code     message layouts and sizes, fragment size, every retransmission timer and attempt limit. They are
                    read from the running implementation (constants, and the source text of the functions that hold
                    the timers), so the model cannot drift away from the code unnoticed.
  from the Pi       how long each computing phase of a session operation takes on the UAV while it streams video
                    (150 operations of each kind, timed on the Pi itself: `link_ops.json`).
  from the laptop   how long the ground station works on each request (the same operations, corrected for its clock).
  from the link     the round trip of a message of 1..6 datagrams over the test bed (`link_rtt_sizes.json`), the ICMP
                    round trip of the same path, the size of every video frame of a recording (`transfer.json`).

What is NOT used for calibration and is therefore left to validate the model against: the duration of the three
session operations as a whole and their waiting part (`link_ops.json`), and everything measured under injected
packet loss (`loss.json`).

Design alternatives (other algorithms) are not measured as whole handshakes - the link does not implement them. Their
message sizes follow from the algorithms' key and signature sizes, and their computing time is the measured time of
the real step with the measured times of the primitives exchanged (bench_crypto, group "variants").
"""
import inspect
import json
import re
import statistics as st
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
DATA, OUT = REPO / "paper_plots" / "data", REPO / "simulation" / "calibration"

from kyber6g import config as cfgmod                             # noqa: E402
from kyber6g.crypto import handshake as hs                       # noqa: E402
from kyber6g.crypto.record import HDR_LEN                        # noqa: E402
from kyber6g.ground import video_sink                            # noqa: E402
from kyber6g.transport import framing                            # noqa: E402
from kyber6g.transport import link as linkmod                    # noqa: E402

M_PER_DEG = 111_195.0        # metres per degree of latitude (mean Earth radius 6371.0 km)


def load(name):
    return json.loads((DATA / f"{name}.json").read_text())


def med(v):
    return st.median(v)


def source_number(fn, pattern, what):
    """A number taken from the source text of a function of the implementation (a timer that is not a constant)."""
    m = re.search(pattern, inspect.getsource(fn))
    if not m:
        raise SystemExit(f"calibration: cannot find {what} in {fn.__qualname__}: the implementation changed, update calibrate.py")
    return float(m.group(1))


def b64len(n):
    return 4 * ((n + 2) // 3)


def main():
    pi, lap, ops = load("crypto_pi"), load("crypto_laptop"), load("link_ops")
    k_lap = lap["clock"]["local_per_reference_second"] or 1.0
    k_ops = ops["clock"]["local_per_reference_second"] or 1.0
    P = lambda name: pi["results"][name]["median_us"]                       # Pi, microseconds
    L = lambda name: lap["results"][name]["median_us"] / k_lap              # laptop, microseconds, clock-corrected
    scalars, samples, notes = {}, {}, {}

    # ------------------------------------------------------------------------------- from the implementation
    U, G = linkmod.UavLink, linkmod.GcsLink
    link_cfg, cam_cfg = cfgmod.LinkConfig(), cfgmod.CameraConfig()
    uav_main = (REPO / "kyber6g" / "uav" / "main.py").read_text()    # not imported: it needs the camera stack of the Pi

    def text_number(text, pattern, what):
        m = re.search(pattern, text)
        if not m:
            raise SystemExit(f"calibration: cannot find {what}: the implementation changed, update calibrate.py")
        return float(m.group(1))

    ctrl_ext = len(linkmod.control_records(b"x" * (linkmod.CONTROL_CHUNK + 1))[0][0])     # what a part of a split control message adds
    scalars.update({
        "hs_retx_s": source_number(U._do_full_handshake, r"_hs_event\.wait\(([0-9.]+)\)", "the ClientHello repeat interval"),
        "hs_max_tx": source_number(U._do_full_handshake, r"for attempt in range\((\d+)\)", "the ClientHello attempt limit"),
        "rekey_retx_s": source_number(U._do_cached_rekey, r"_hs_event\.wait\(([0-9.]+)\)", "the rekey repeat interval"),
        "rekey_max_tx": source_number(U._do_cached_rekey, r"for attempt in range\((\d+)\)", "the rekey attempt limit"),
        "ratchet_retx_s": source_number(U._ratchet_tick, r"age > ([0-9.]+) \* self\._ratchet_tx", "the ratchet repeat interval"),
        "ratchet_max_tx": source_number(U._ratchet_tick, r"self\._ratchet_tx < (\d+)", "the ratchet attempt limit"),
        "ratchet_timeout_s": U.RATCHET_TIMEOUT,
        "manager_tick_s": source_number(U._manage, r"self\._ratchet_tick\(now\)\s+time\.sleep\(([0-9.]+)\)", "the manager's tick"),
        "manager_backoff_s": source_number(U._manage, r"backoff = ([0-9.]+)\n", "the first wait after a failed handshake"),
        "manager_backoff_max_s": source_number(U._manage, r"backoff = min\(backoff \* 2, ([0-9.]+)\)", "the longest wait after a failed handshake"),
        "hello_cache_s": source_number(G, r"self\.hello_cache\[key\] = \[time\.monotonic\(\) \+ ([0-9.]+),", "how long an answered ClientHello is remembered"),
        "rekey_cache_s": source_number(G, r"self\.rekey_cache\[key\] = \(now \+ ([0-9.]+),", "how long an answered rekey request is remembered"),
        "frag_payload": framing.MAX_FRAG_PAYLOAD, "hs_hdr": framing.HS_HDR.size, "reassembly_timeout_s": framing.REASSEMBLY_TIMEOUT,
        "ctrl_chunk": linkmod.CONTROL_CHUNK, "ctrl_part_ext": ctrl_ext, "rec_hdr": HDR_LEN, "rec_tag": 16, "udp_ip": 28,
        "video_ext": video_sink.VIDEO_EXT.size, "video_chunk": text_number(uav_main, r"\nVIDEO_CHUNK = (\d+)", "the size of a video chunk"),
        "video_frame_hdr": 8 if 'struct.pack("!Q", ts_us) + data' in uav_main else 0,          # the capture time in front of every frame
        "jitter_ms": inspect.signature(video_sink.VideoSink.__init__).parameters["jitter_ms"].default,
        "video_fps": cam_cfg.fps, "video_gop": cam_cfg.iperiod,
        "cell_m": round(link_cfg.mobility_cell_deg * M_PER_DEG, 2),
        "cell_margin": inspect.signature(hs.MobilityTracker.__init__).parameters["margin"].default,
        "ch_fixed": hs.CH_FIXED.size, "sh_fixed": hs.SH_FIXED.size, "fin_len": hs.FIN_LEN, "x25519_len": hs.X25519_LEN,
    })
    if not scalars["video_frame_hdr"]:
        raise SystemExit("calibration: the video frame header in kyber6g/uav/main.py changed, update calibrate.py")
    wire = pi["wire"]
    scalars.update({"rekey_req_bytes": wire["cached rekey"]["RekeyRequest"]["bytes"], "rekey_resp_bytes": wire["cached rekey"]["RekeyResponse"]["bytes"],
                    "cf_bytes": wire["full handshake"]["ClientFinished"]["bytes"]})

    # ------------------------------------------------------------------- computing phases, as measured in the running system
    rows = {op: [r for r in ops["rows"] if r["op"] == op and r["ok"]] for op in ("full_handshake", "cached_rekey", "pq_ratchet")}
    full, cached, ratchet = rows["full_handshake"], rows["cached_rekey"], rows["pq_ratchet"]
    samples["uav_full_build_ms"] = [r["parts"]["build_ms"] for r in full]
    samples["uav_full_process_ms"] = [r["parts"]["process_ms"] for r in full]
    samples["uav_cached_build_ms"] = [r["parts"]["build_ms"] for r in cached]
    samples["uav_cached_process_ms"] = [r["parts"]["process_ms"] for r in cached]
    samples["gcs_full_ms"] = [r["gcs_ms_raw"] / k_ops for r in full if r.get("gcs_ms_raw")]
    samples["gcs_cached_ms"] = [r["gcs_ms_raw"] / k_ops for r in cached if r.get("gcs_ms_raw")]
    samples["gcs_ratchet_ms"] = [r["gcs_ms_raw"] / k_ops for r in ratchet if r.get("gcs_ms_raw")]
    # what remains of a full handshake on the UAV after the answer is processed: installing the session (record keys
    # for 12 streams) and sending the Finished message. Measured as total - build - wait.
    samples["uav_full_finish_ms"] = [max(0.0, r["uav_ms"] - r["parts"]["build_ms"] - r["parts"]["wait_ms"]) for r in full]
    samples["uav_cached_finish_ms"] = [max(0.0, r["uav_ms"] - r["parts"]["build_ms"] - r["parts"]["wait_ms"]) for r in cached]
    # The PQ ratchet: its phases as the UAV timed them (making the key pairs, which happens before the ratchet's own
    # clock starts; deriving the new secrets from the answer and installing the session, which end it).
    inproc_full = P("full: UAV builds ClientHello") + P("full: UAV verifies, derives, Finished")
    factor = [(r["parts"]["build_ms"] + r["parts"]["process_ms"]) * 1000 / inproc_full for r in full]
    notes["uav_slower_in_the_running_system_than_in_process"] = round(med(factor), 3)
    timed = [r for r in ratchet if isinstance(r.get("parts"), dict) and "finish_ms" in r["parts"]]
    if timed:
        samples["uav_ratchet_build_ms"] = [r["parts"]["build_ms"] for r in timed]
        samples["uav_ratchet_finish_ms"] = [r["parts"]["finish_ms"] for r in timed]
        samples["uav_ratchet_install_ms"] = [r["parts"]["install_ms"] for r in timed]
        notes["ratchet_phases"] = f"timed on the UAV in {len(timed)} ratchets"
    else:       # a campaign made before the ratchet timed its phases: the in-process times, slowed as the handshake's steps were
        samples["uav_ratchet_build_ms"] = [P("ratchet: UAV builds request") / 1000 * f for f in factor]
        samples["uav_ratchet_finish_ms"] = [P("ratchet: UAV finishes") / 1000 * f for f in factor]
        samples["uav_ratchet_install_ms"] = [P("record keys for 6 streams x 2 directions") / 1000 * f for f in factor]
        notes["ratchet_phases"] = "not timed in this campaign: in-process times scaled by the slow-down of the handshake's steps"

    # ----------------------------------------------------------------------------------------------- the test-bed link
    # round trips of messages of 1..6 datagrams, measured right before (link_rtt) and right after (link_rtt_after)
    # the session operations and pooled: the model is checked against those operations
    # Which probes: those sent one per command from the ground station (`sized_triggered`), if the campaign has them.
    # A session operation of the measurement starts when the UAV has just received the command asking for it, and so
    # do these probes; probes the UAV sends on its own timer start at any moment between two bursts of video and were
    # measured to take longer (both kinds are in the files, the difference is noted below).
    # A probe's round trip contains the time the ground station takes to turn it round. The ground station reports
    # that time for every probe (as it does for every session operation), and it is taken out here: what remains is
    # the path, and the simulation adds the ground station's own time for the operation it simulates. Without this the
    # ground station would be counted twice.
    icmp, used, free, turn = [], [], {}, {}
    for name in ("link_rtt", "link_rtt_after"):
        try:
            d = load(name)
        except OSError:
            continue
        if not d.get("sized"):
            continue
        which = "sized_triggered" if d.get("sized_triggered") else "sized"
        k_file = (d.get("clock") or {}).get("local_per_reference_second") or 1.0
        used.append(f"{name}.json ({'one probe per command' if which == 'sized_triggered' else 'probes on the UAV timer'})")
        icmp += d["icmp"]["rtt_ms"]
        for s in d[which]:
            r, g = s["rtt_ms"] or [], s.get("gcs_ms_raw") or []
            if g and len(g) == len(r):
                turn.setdefault(s["datagrams_each_way"], []).extend(y / k_file for y in g)
                r = [max(0.2, x - y / k_file) for x, y in zip(r, g)]
            samples.setdefault(f"rtt_k{s['datagrams_each_way']}_ms", []).extend(r)
        for s in d["sized"]:
            free.setdefault(s["datagrams_each_way"], []).extend(s["rtt_ms"] or [])
    if turn:
        notes["ground_station_time_over_a_probe_median_ms"] = {str(kk): round(med(v), 3) for kk, v in sorted(turn.items())}
        notes["round_trips"] = "path only: the ground station's time over each probe is taken out"
    if free and any(n.endswith("command)") for n in used):
        notes["round_trip_median_ms_by_datagrams"] = {str(kk): {"one_probe_per_command" + ("_path_only" if turn else ""): round(med(samples[f"rtt_k{kk}_ms"]), 3),
                                                              "probes_on_the_uav_timer": round(med(v), 3)} for kk, v in sorted(free.items())}
    if not used:                                   # a campaign made before messages of several datagrams were probed
        try:
            d = load("link_rtt_sizes")
            used.append("link_rtt_sizes.json (measured at another time than the operations)")
            icmp = d["icmp"]["rtt_ms"]
            for s in d["sized"]:
                samples[f"rtt_k{s['datagrams_each_way']}_ms"] = s["rtt_ms"]
        except OSError:
            d = load("link_rtt")
            used.append("link_rtt.json (single-datagram probes only)")
            icmp = d["icmp"]["rtt_ms"]
            samples["rtt_k1_ms"] = [x for p in d["probes"] for x in (p["rtt_ms"] or [])]
    notes["link_rtt_source"] = used
    samples["icmp_rtt_ms"] = icmp
    # what the two hosts add to a one-way message over the bare path (seal, open, JSON, thread wake-ups): half of
    # (secure control round trip - ICMP round trip), both started at moments of the UAV's own choosing. Used when the
    # radio path is simulated (NR), not for the test bed.
    scalars["host_msg_ms"] = round(max(0.05, (med(free.get(1) or samples["rtt_k1_ms"]) - med(icmp)) / 2), 4)

    # ----------------------------------------------------------------------------------------------------- video
    tr = load("transfer")
    frames = (tr.get("recording_frames") or {}).get("frames") or []
    if frames:
        samples["video_i_bytes"] = [f[2] for f in frames if f[1]]
        samples["video_p_bytes"] = [f[2] for f in frames if not f[1]]
        notes["video_source"] = f"{len(frames)} frames of the recording in transfer.json"
    else:
        samples["video_i_bytes"], samples["video_p_bytes"] = [12500.0], [12500.0]
        notes["video_source"] = "no frame index measured yet: constant frames of bitrate / fps"
    if frames:
        # the stream as it was recorded, in place of the configured defaults: frames per second from the capture times,
        # keyframe distance from the keyframes
        ts = [f[0] for f in frames]
        keys = [i for i, f in enumerate(frames) if f[1]]
        if len(ts) > 30 and ts[-1] > ts[0]:
            scalars["video_fps"] = round((len(ts) - 1) / ((ts[-1] - ts[0]) / 1e6))
        if len(keys) > 2:
            scalars["video_gop"] = round(med([b - a for a, b in zip(keys, keys[1:])]))
        notes["video_bitrate_kbps"] = round(sum(f[2] for f in frames) * 8 / max(1e-9, (ts[-1] - ts[0]) / 1e6) / 1000, 1)
    tl = load("timeline")
    seal = [r["seal_us_avg"] for r in tl["rows"] if r.get("seal_us_avg")]
    scalars["uav_tx_us"] = round(med(seal), 1) if seal else 150.0             # sealing and sending one video record on the Pi
    name = "receive path per video record (session lookup, replay window, open, frame reassembly)"
    scalars["gcs_rx_us"] = round(L(name), 2) if name in lap["results"] else 0.0

    # ---------------------------------------------------------------- cryptographic configurations (design alternatives)
    vs_pi, vs_lap = pi.get("variant_sizes") or {}, lap.get("variant_sizes") or {}
    have_variants = bool(vs_pi) and "ML-KEM-768 keygen" in pi["results"] and "ML-KEM-768 keygen" in lap["results"]
    KEM = {"ML-KEM-1024": (1568, 1568)}
    SIG = {"ML-DSA-87": 4627}
    if have_variants:
        KEM.update({k: (v["encapsulation_key"], v["ciphertext"]) for k, v in vs_pi.items() if "encapsulation_key" in v})
        SIG.update({k: v["signature"] for k, v in vs_pi.items() if "signature" in v})

    def prim(M, kem, x, sig):
        """Measured primitive times on one machine (M = P for the Pi or L for the laptop), microseconds."""
        g = lambda n: M(n)
        return {"kem_keygen": g(f"{kem} keygen") if kem else 0, "kem_encaps": g(f"{kem} encapsulate") if kem else 0,
                "kem_decaps": g(f"{kem} decapsulate") if kem else 0, "x_keygen": g("X25519 keygen") if x else 0,
                "x_exchange": g("X25519 exchange") if x else 0, "sign": g(f"{sig} sign"), "verify": g(f"{sig} verify")}

    def steps(M, kem, x, sig):
        """Primitive content of each protocol step (who computes what), microseconds on machine M."""
        p = prim(M, kem, x, sig)
        return {"full_build": p["x_keygen"] + p["kem_keygen"] + p["sign"],
                "full_answer": p["verify"] + p["x_keygen"] + p["x_exchange"] + p["kem_encaps"] + p["sign"],
                "full_process": p["verify"] + p["x_exchange"] + p["kem_decaps"],
                "ratchet_build": p["x_keygen"] + p["kem_keygen"], "ratchet_answer": p["x_keygen"] + p["x_exchange"] + p["kem_encaps"],
                "ratchet_finish": p["x_exchange"] + p["kem_decaps"]}

    measured = {"full_build": P("full: UAV builds ClientHello"), "full_process": P("full: UAV verifies, derives, Finished"),
                "ratchet_build": P("ratchet: UAV builds request"), "ratchet_finish": P("ratchet: UAV finishes"),
                "full_answer": L("full: GCS answers (ServerHello)"), "ratchet_answer": L("ratchet: GCS answers")}
    base_pi, base_lap = steps(P, "ML-KEM-1024", True, "ML-DSA-87"), steps(L, "ML-KEM-1024", True, "ML-DSA-87")
    configs = [("hybrid5", "ML-KEM-1024", True, "ML-DSA-87", "ML-KEM-1024 + X25519, ML-DSA-87 (the implemented suite)")]
    if have_variants:
        configs += [("pq5", "ML-KEM-1024", False, "ML-DSA-87", "ML-KEM-1024 alone, ML-DSA-87 (no classical half)"),
                    ("hybrid3", "ML-KEM-768", True, "ML-DSA-65", "ML-KEM-768 + X25519, ML-DSA-65"),
                    ("hybrid1", "ML-KEM-512", True, "ML-DSA-44", "ML-KEM-512 + X25519, ML-DSA-44"),
                    ("classical", None, True, "Ed25519", "X25519 alone, Ed25519 (no post-quantum part)")]
    profiles = {}
    for name, kem, x, sig, text in configs:
        ek, ct = KEM[kem] if kem else (0, 0)
        xl = hs.X25519_LEN if x else 0
        s = SIG[sig]
        vp, vl = steps(P, kem, x, sig), steps(L, kem, x, sig)
        # the step as measured, with the primitives of this configuration put in place of those of the implemented one
        t = {k: measured[k] - (base_lap if k.endswith("answer") else base_pi)[k] + (vl if k.endswith("answer") else vp)[k] for k in measured}
        # the ratchet request / answer as they travel: JSON with base64 fields ({"t":..,"rid":..,"x":..,"ek"|"ct":..[,"sid":..]})
        rq = 27 + (7 + b64len(xl) if x else 0) + (8 + b64len(ek) if kem else 0)
        rs = 53 + (7 + b64len(xl) if x else 0) + (8 + b64len(ct) if kem else 0)
        profiles[name] = {
            "text": text, "kem": kem or "-", "sig": sig, "x25519": int(x),
            "ch_bytes": hs.CH_FIXED.size + xl + ek + 2 + s, "sh_bytes": hs.SH_FIXED.size + xl + ct + 2 + s + hs.FIN_LEN,
            "ratchet_req_bytes": rq, "ratchet_resp_bytes": rs,
            # computing time relative to the implemented suite, per step (applied to the times measured in the running system)
            "scale_full_build": round(t["full_build"] / measured["full_build"], 4),
            "scale_full_process": round(t["full_process"] / measured["full_process"], 4),
            "scale_full_answer": round(t["full_answer"] / measured["full_answer"], 4),
            "scale_ratchet_build": round(t["ratchet_build"] / measured["ratchet_build"], 4),
            "scale_ratchet_finish": round(t["ratchet_finish"] / measured["ratchet_finish"], 4),
            "scale_ratchet_answer": round(t["ratchet_answer"] / measured["ratchet_answer"], 4),
        }
    b = profiles["hybrid5"]
    if (b["ch_bytes"], b["sh_bytes"]) != (wire["full handshake"]["ClientHello"]["bytes"], wire["full handshake"]["ServerHello"]["bytes"]):
        raise SystemExit(f"calibration: computed handshake sizes {b['ch_bytes']}/{b['sh_bytes']} differ from the measured wire sizes")
    if (b["ratchet_req_bytes"], b["ratchet_resp_bytes"]) != (wire["pq ratchet"]["request"]["bytes"], wire["pq ratchet"]["response"]["bytes"]):
        raise SystemExit(f"calibration: computed ratchet sizes {b['ratchet_req_bytes']}/{b['ratchet_resp_bytes']} differ from the measured ones")
    notes["in_process_step_us"] = {k: round(v, 1) for k, v in measured.items()}
    notes["primitive_share_of_step"] = {k: round((base_lap if k.endswith("answer") else base_pi)[k] / measured[k], 3) for k in measured}

    # ------------------------------------------------------------------------------------------------------- write
    OUT.mkdir(parents=True, exist_ok=True)
    lines = ["# Calibration of simulation/ns3/k6g-swarm-sim.cc. Generated by simulation/calibrate.py - do not edit.",
             f"# From the measurements in paper_plots/data ({ops['provenance']['started_utc']}) and from the implementation in kyber6g/.",
             "# scalar <name> <value> | samples <name> <n> <values...> | profile <name> <key> <value> ..."]
    for k, v in sorted(scalars.items()):
        lines.append(f"scalar {k} {v:g}")
    for k, v in sorted(samples.items()):
        v = [float(x) for x in v if x is not None]
        lines.append(f"samples {k} {len(v)} " + " ".join(f"{x:.4f}" for x in v))
    for name, p in profiles.items():
        lines.append(f"profile {name} " + " ".join(f"{k} {v:g}" for k, v in p.items() if isinstance(v, (int, float))))
    (OUT / "k6g_calibration.txt").write_text("\n".join(lines) + "\n")
    summary = {"generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "measurements": {n: (load(n).get("provenance") or {}).get("started_utc") or load(n).get("started_utc")
                                for n in ("crypto_pi", "crypto_laptop", "link_ops", "transfer", "timeline")},
               "laptop_clock_rate": {"crypto_laptop": k_lap, "link_ops": k_ops},
               "scalars": scalars, "profiles": profiles, "notes": notes,
               "samples": {k: {"n": len(v), "median": round(med(v), 4), "min": round(min(v), 4), "max": round(max(v), 4)} for k, v in samples.items()}}
    (OUT / "k6g_calibration.json").write_text(json.dumps(summary, indent=1))
    print(f"calibration written: {len(scalars)} scalars, {len(samples)} sample sets, {len(profiles)} configurations -> {OUT}")
    for k, v in summary["samples"].items():
        print(f"  {k:26s} n={v['n']:4d}  median {v['median']:10.3f}")
    for n, p in profiles.items():
        print(f"  {n:10s} ClientHello {p['ch_bytes']:5d} B  ServerHello {p['sh_bytes']:5d} B  build x{p['scale_full_build']:.3f}  "
              f"process x{p['scale_full_process']:.3f}  answer x{p['scale_full_answer']:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
