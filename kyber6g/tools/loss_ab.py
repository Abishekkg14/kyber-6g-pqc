"""The two fixes of the manuscript review (14 October 2026) measured in one pass over the loss rates.

At each loss rate injected on the Pi, two threads run at the same time:
  * video: slices of live video in which the ground station's keyframe request is on and off in turns
    (the order alternates from one loss rate to the next);
  * session operations: full handshake, cached rekey and PQ ratchet, each with the fixed repeat timers and with the
    timer from the measured round trip in turns. The timer travels inside the operation's own command, so a lost
    command can only mean "not started", never "started with an unknown timer"; the UAV writes the timer it used
    into its operation log, and that record is what counts.
Interleaving the two settings at every loss rate exposes both to the same radio conditions, which two runs one after
the other would not. Photo transfers are left out: neither setting changes them.

    python -m kyber6g.tools.loss_ab [--levels 0,1,2,5,10,20] [--rounds 5] [--slices 4] [--slice 10]

Writes paper_plots/data/loss_ab.json; paper_plots/scripts/review_ab.py evaluates it."""
import argparse
import threading
import time

from .bench_link import NFT, OPS, REPO, Api, finish, need_live, nft_clear, nft_counters, nft_set, oplog, provenance, ref_clock, snap, ssh


def run_op(api, op, tag, retx, wait_s=8):
    r = api.cmd(op, wait_s=wait_s, wait=True, tag=tag, retx=retx)
    res = r.get("result") if isinstance(r.get("result"), dict) else {}
    return {"op": op, "retx_asked": retx, "acked": bool(r.get("ok")), "ok": bool(r.get("ok") and res.get("ok")), "uav_ms": res.get("ms"),
            "error": r.get("error") or res.get("error")}


def video_slices(api, n, seconds, first_on, rate, out):
    for k in range(n):
        on = (k % 2 == 0) == first_on
        api.cmd("video_tuning", keyframe_request=on)
        time.sleep(1.0)                                   # the switch settles; the slice starts after it
        s0, m0 = snap(api), time.monotonic()
        time.sleep(seconds * rate)                        # `seconds` on the Pi's clock
        s1 = snap(api)
        out.append({"keyframe_request": on, "before": s0, "after": s1, "seconds_raw": round(time.monotonic() - m0, 3)})


def op_rounds(api, rounds, tag, pace, out):
    # The timer changes after a whole set of the three operations, not between two of the same kind: the ground
    # station accepts at most one ratchet in 0.5 s, and two ratchets back to back would measure that limit instead.
    for r in range(rounds):
        order = ("fixed", "rtt") if r % 2 == 0 else ("rtt", "fixed")
        for retx in order:
            for op in OPS:
                out.append(run_op(api, op, tag, retx))
                time.sleep(pace)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--api", default="http://127.0.0.1:8600")
    ap.add_argument("--pi", default="kyber-pi")
    ap.add_argument("-o", "--out", default=str(REPO / "paper_plots" / "data"))
    ap.add_argument("--levels", default="0,1,2,5,10,20")
    ap.add_argument("--rounds", type=int, default=5, help="rounds of the three operations with each timer per loss rate")
    ap.add_argument("--slices", type=int, default=4, help="video slices per loss rate (keyframe request on and off in turns)")
    ap.add_argument("--slice", type=float, default=10.0, help="length of one video slice (s)")
    ap.add_argument("--pace", type=float, default=0.4, help="pause after each operation (s)")
    a = ap.parse_args()
    api = Api(a.api)
    need_live(api)
    levels = [float(x) for x in a.levels.split(",")]
    ref = ref_clock(a)
    out = {"what": "repeat timer (fixed | rtt) and keyframe request (on | off), interleaved at each loss rate injected on the Pi "
                   "(nftables, UDP 14600, both directions); video and session operations measured at the same time",
           "provenance": provenance(api, a, ref),
           "design": {"levels": levels, "rounds": a.rounds, "slices": a.slices, "slice_s": a.slice, "pace_s": a.pace}, "levels": []}
    for op in OPS:                                        # round trips without loss for the rtt timer (Karn: unrepeated only)
        run_op(api, op, "warmup", "rtt")
        time.sleep(0.5)
    first = oplog(api)
    since = first[-1]["n"] if first else 0
    budget = int(len(levels) * (a.slices * (a.slice + 2) + a.rounds * 6 * 8) + 300)
    rc, _, err = ssh(a.pi, "sudo -n systemctl stop k6g-loss-cleanup.timer k6g-loss-cleanup.service 2>/dev/null; "
                           "sudo -n systemctl reset-failed k6g-loss-cleanup.service 2>/dev/null; "
                           f"sudo -n systemd-run --quiet --collect --on-active={budget} --unit k6g-loss-cleanup {NFT} delete table inet k6gloss", 30)
    if rc != 0:
        raise SystemExit(f"could not arm the clean-up timer on the Pi, not injecting loss: {err.strip()[:200]}")
    t_start = time.monotonic()
    try:
        for i, pct in enumerate(levels):
            tag = f"ab{pct:g}"
            nft_set(a.pi, pct)
            time.sleep(3)
            lv = {"nominal_pct": pct, "tag": tag, "slices": [], "ops": []}
            c0 = nft_counters(a.pi)
            rate = ref.rate() or 1.0
            tv = threading.Thread(target=video_slices, args=(api, a.slices, a.slice, i % 2 == 0, rate, lv["slices"]), daemon=True)
            to = threading.Thread(target=op_rounds, args=(api, a.rounds, tag, a.pace, lv["ops"]), daemon=True)
            tv.start(); to.start()
            tv.join(); to.join()
            lv["counters_before"], lv["counters_after"] = c0, nft_counters(a.pi)
            out["levels"].append(lv)
            c1 = lv["counters_after"]
            seen, dropped = c1.get("seen-out", 0) - c0.get("seen-out", 0), c1.get("drop-out", 0) - c0.get("drop-out", 0)
            dec = {on: sum(s["after"]["frames_decoded"] - s["before"]["frames_decoded"] for s in lv["slices"] if s["keyframe_request"] is on) for on in (True, False)}
            print(f"  {pct:5.1f} %: uplink dropped {dropped}/{seen} ({100 * dropped / max(seen, 1):.2f} %)  frames to the decoder: requests on {dec[True]}, "
                  f"off {dec[False]}  ops ok {sum(o['ok'] for o in lv['ops'])}/{len(lv['ops'])}  ({time.monotonic() - t_start:.0f} s)", flush=True)
            ref.sample()
    finally:
        nft_clear(a.pi)
        api.cmd("video_tuning", keyframe_request=True)
    time.sleep(6)
    out["uav_oplog"] = [e for e in oplog(api, since) if str(e.get("tag", "")).startswith("ab")]
    api.cmd("link_tuning", retx_timer="rtt")             # the default again
    return finish(out, ref, a, "loss_ab")


if __name__ == "__main__":
    main()
