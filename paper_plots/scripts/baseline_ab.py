"""The Kyber-6G link against DTLS 1.3 on the same test bed (kyber6g/tools/baseline_ab.py -> paper_plots/data/baseline_ab.json).

Per loss rate (counted by the Pi's packet filter, apart for the link's port and the DTLS ports): the link's session
operations from the UAV's own log, grouped by the repeat timer the UAV recorded; the DTLS 1.3 handshakes as the client on
the Pi timed them. Sizes (bytes and datagrams of one operation) come from the rate without loss.

    python3 paper_plots/scripts/baseline_ab.py   -> paper_plots/tables/baseline_ab_{operations,sizes}.csv"""
import csv, json, pathlib, statistics, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
DATA, TABLES = ROOT / "data", ROOT / "tables"
LINK = (("full", "Kyber-6G full handshake"), ("cached", "Kyber-6G cached rekey"), ("ratchet", "Kyber-6G PQ ratchet"))
DTLS = (("full", "DTLS 1.3 full handshake, cookie"), ("full_nc", "DTLS 1.3 full handshake"),
        ("psk_ke", "DTLS 1.3 resumption, PSK only"), ("psk_dhe_ke", "DTLS 1.3 resumption, new key exchange"))


def pct(v, q):
    v = sorted(v)
    if not v:
        return None
    k = (len(v) - 1) * q / 100
    i = int(k)
    return v[i] if i + 1 >= len(v) else v[i] + (v[i + 1] - v[i]) * (k - i)


def rnd(x, d=1):
    return None if x is None else round(x, d)


def stats(label, setting, loss, started, ms):
    return {"operation": label, "setting": setting, "nominal_loss_pct": loss[0], "loss_pct": round(loss[1], 3), "started": started,
            "completed": len(ms), "median_ms": rnd(statistics.median(ms)) if ms else None, "p95_ms": rnd(pct(ms, 95)),
            "max_ms": rnd(max(ms)) if ms else None, "over_1s": sum(1 for x in ms if x > 1000)}


def main():
    d = json.loads((DATA / "baseline_ab.json").read_text())
    log = d["uav_oplog"]
    rows, sizes = [], []
    for L in d["levels"]:
        c0, c1 = L["counters_before"], L["counters_after"]
        loss = lambda tag: 100 * (c1.get(f"drop-{tag}", 0) - c0.get(f"drop-{tag}", 0)) / max(c1.get(f"seen-{tag}", 0) - c0.get(f"seen-{tag}", 0), 1)
        pl, pd = loss("out"), loss("out-dtls")
        for kind, label in LINK:
            for retx in ("rtt", "fixed"):
                es = [e for e in log if e["tag"] == L["tag"] and e["kind"] == kind and e.get("retx") == retx]
                rows.append(stats(label, f"{retx} timer", (L["nominal_pct"], pl), len(es), [e["ms"] for e in es if e["ok"]]))
        for kind, label in DTLS:
            ds = [x for x in L["dtls"] if x.get("kind") == kind]
            ok = [x["ms"] for x in ds if x.get("ok") and (kind.startswith("full") or x.get("resumed"))]
            rows.append(stats(label, "wolfSSL 5.9.4", (L["nominal_pct"], pd), len(ds), ok))
            if L["nominal_pct"] == 0 and ds:
                okd = [x for x in ds if x.get("ok") and (kind.startswith("full") or x.get("resumed"))]
                sizes.append({"operation": label, "bytes": int(statistics.median(x["sent_bytes"] + x["received_bytes"] for x in okd)),
                              "datagrams": int(statistics.median(x["sent_datagrams"] + x["received_datagrams"] for x in okd)),
                              "flow": okd[0]["flow"] if okd else ""})
        if L["nominal_pct"] == 0:
            sizes += [{"operation": "Kyber-6G full handshake", "bytes": 13106, "datagrams": 13, "flow": "Table 6 (counted in the implementation)"},
                      {"operation": "Kyber-6G cached rekey", "bytes": 324, "datagrams": 3, "flow": "Table 6"},
                      {"operation": "Kyber-6G PQ ratchet", "bytes": 4757, "datagrams": 5, "flow": "Table 6"}]
    # pooled over the loss rates above zero
    pooled = []
    for label, setting in sorted({(r["operation"], r["setting"]) for r in rows}):
        sel = [r for r in rows if r["operation"] == label and r["setting"] == setting and r["nominal_loss_pct"] > 0]
        pooled.append({"operation": label, "setting": setting, "started": sum(r["started"] for r in sel), "completed": sum(r["completed"] for r in sel),
                       "over_1s": sum(r["over_1s"] for r in sel)})
    TABLES.mkdir(exist_ok=True)
    for data, name in ((rows, "baseline_ab_operations.csv"), (sizes, "baseline_ab_sizes.csv"), (pooled, "baseline_ab_pooled.csv")):
        with open(TABLES / name, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(data[0]))
            w.writeheader()
            w.writerows(data)
    print("wolfSSL", d.get("dtls"), "| video during the run:", d["design"].get("video"))
    print("SIZES")
    for s in sizes:
        print(f"  {s['operation']:42s} {s['bytes']:6d} B {s['datagrams']:3d} datagrams")
    print("OPERATIONS (median / 95th / max ms, completed of started)")
    for r in rows:
        print(f"  {r['loss_pct']:6.2f} %  {r['operation']:42s} {r['setting']:14s} {r['median_ms']} / {r['p95_ms']} / {r['max_ms']}  {r['completed']}/{r['started']}  >1 s: {r['over_1s']}")
    print("POOLED over the loss rates above zero")
    for r in pooled:
        print(f"  {r['operation']:42s} {r['setting']:14s} completed {r['completed']}/{r['started']}  over 1 s {r['over_1s']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
