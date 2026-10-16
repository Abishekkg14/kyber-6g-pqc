"""The two fixes that the manuscript review of 14 October 2026 asked for, measured on the test bed in one pass
(kyber6g/tools/loss_ab.py -> paper_plots/data/loss_ab.json): at each loss rate the keyframe request alternates
between slices of video, and the repeat timer alternates between session operations.

Evaluated as make_plots.loss() evaluates loss.json: loss counted by the Pi's packet filter; frames as the ground
station accounted for them in each slice; session operations from the UAV's own log (timed on the Pi), grouped by
the repeat timer that the UAV recorded for each operation.

    python3 paper_plots/scripts/review_ab.py   -> paper_plots/tables/review_ab_video.csv, review_ab_operations.csv"""
import csv, json, pathlib, statistics, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA, TABLES = ROOT / "data", ROOT / "tables"
KINDS = (("full", "Full handshake"), ("cached", "Cached rekey"), ("ratchet", "PQ ratchet"))


def pct(v, q):
    v = sorted(v)
    if not v:
        return None
    k = (len(v) - 1) * q / 100
    i = int(k)
    return v[i] if i + 1 >= len(v) else v[i] + (v[i + 1] - v[i]) * (k - i)


def rnd(x, d=1):
    return None if x is None else round(x, d)


def main():
    d = json.loads((DATA / "loss_ab.json").read_text())
    rate = (d.get("clock") or {}).get("local_per_reference_second") or 1.0
    log = d["uav_oplog"]
    video, ops = [], []
    for L in d["levels"]:
        c0, c1 = L["counters_before"], L["counters_after"]
        seen, dropped = c1["seen-out"] - c0["seen-out"], c1["drop-out"] - c0["drop-out"]
        p = 100 * dropped / max(seen, 1)
        for on in (False, True):
            sl = [s for s in L["slices"] if s["keyframe_request"] is on]
            dk = lambda k: sum((s["after"].get(k) or 0) - (s["before"].get(k) or 0) for s in sl)
            fc, fl, dec = dk("frames_complete"), dk("frames_lost"), dk("frames_decoded")
            base = max(fc + fl, 1)
            secs = sum(s["seconds_raw"] for s in sl) / rate
            video.append({"keyframe_request": "on" if on else "off", "nominal_loss_pct": L["nominal_pct"], "uplink_loss_pct": round(p, 3),
                          "frames_accounted": fc + fl, "frames_complete_pct": round(100 * fc / base, 2),
                          "frames_to_decoder_pct": round(100 * dec / base, 2), "keyframes_per_s": round(dk("cam_keyframes") / secs, 2),
                          "keyframe_requests_per_s": round(dk("keyframe_requests_gcs") / secs, 2),
                          "requests_carried_out": dk("keyframe_requests_uav"), "requests_failed": dk("keyframe_requests_failed_uav"),
                          "video_kbps_mean": rnd(statistics.fmean([s["after"]["kbps"] for s in sl if s["after"].get("kbps")] or [0])),
                          "seconds": round(secs, 1)})
        for kind, kl in KINDS:
            for retx in ("fixed", "rtt"):
                es = [e for e in log if e["tag"] == L["tag"] and e["kind"] == kind and e.get("retx") == retx]
                ok = [e["ms"] for e in es if e["ok"]]
                sent = [e.get("hello_sent") or e.get("request_sent") or e.get("requests_sent") or 1 for e in es if e["ok"]]
                ops.append({"retx_timer": retx, "operation": kl, "nominal_loss_pct": L["nominal_pct"], "uplink_loss_pct": round(p, 3),
                            "started": len(es), "completed": len(ok), "median_ms": rnd(statistics.median(ok)) if ok else None,
                            "p95_ms": rnd(pct(ok, 95)), "max_ms": rnd(max(ok)) if ok else None,
                            "within_100ms_pct": round(100 * sum(v <= 100 for v in ok) / len(ok), 1) if ok else None,
                            "mean_transmissions": round(statistics.fmean(sent), 2) if sent else None,
                            "first_wait_ms_median": rnd(statistics.median([e["first_wait_ms"] for e in es if e.get("first_wait_ms") is not None] or [0]))})
    TABLES.mkdir(exist_ok=True)
    for rows, fname in ((video, "review_ab_video.csv"), (ops, "review_ab_operations.csv")):
        with open(TABLES / fname, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
    unknown = sum(1 for e in log if e.get("retx") not in ("fixed", "rtt"))
    print(f"operations in the log: {len(log)} (without a recorded timer: {unknown}); clock rate {rate}")
    print("VIDEO")
    for r in video:
        print(f"  kf {r['keyframe_request']:3s} {r['uplink_loss_pct']:6.2f} %  frames {r['frames_accounted']:4d}  complete {r['frames_complete_pct']:6.2f}  "
              f"to decoder {r['frames_to_decoder_pct']:6.2f}  keyframes {r['keyframes_per_s']:4.2f}/s  requests {r['keyframe_requests_per_s']:4.2f}/s "
              f"(failed {r['requests_failed']})  {r['video_kbps_mean']} kbit/s  {r['seconds']} s")
    print("OPERATIONS")
    for r in ops:
        print(f"  {r['retx_timer']:5s} {r['operation']:15s} {r['uplink_loss_pct']:6.2f} %  {r['completed']}/{r['started']}  median {r['median_ms']}  "
              f"p95 {r['p95_ms']}  max {r['max_ms']}  <=100 ms {r['within_100ms_pct']}%  tx {r['mean_transmissions']}  first wait {r['first_wait_ms_median']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
