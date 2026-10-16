"""The Kyber-6G link against DTLS 1.3, and its two repairs, in one pass over the loss rates (manuscript review of
14 October 2026). At each loss rate injected on the Pi, three threads run at the same time:

  * video: slices of live video in which the ground station's keyframe request is on and off in turns;
  * the link's session operations (full handshake, cached rekey, PQ ratchet) with the fixed and with the round-trip
    repeat timer in turns, the timer carried in each operation's command and logged by the UAV (loss_ab.py);
  * DTLS 1.3 handshakes between the same two machines (wolfSSL 5.9.4, dtls_baseline/dtls_bench.c): full handshake with
    and without a cookie, resumption with PSK only, resumption with a new hybrid key exchange. Group SecP384r1MLKEM1024,
    ML-DSA-87 certificates pinned at both ends, client on the Pi (timed there), server on the laptop.
Handshakes of the link and of DTLS never overlap: they take turns through one lock, so neither slows the other down.
The same random loss applies to the link's port (14600) and to the two DTLS ports (14700, 14701), counted apart.

    python -m kyber6g.tools.baseline_ab [--levels 0,1,2,5,10,20] [--rounds 5]

Needs: dtls_bench built on both machines (dtls_baseline/build.sh), the certificates in ~/dtls_certs on the Pi and in
/root/dtls_certs on the laptop. Writes paper_plots/data/baseline_ab.json; paper_plots/scripts/baseline_ab.py evaluates it."""
import argparse
import json
import subprocess
import threading
import time

from . import sshopts
from .bench_link import NFT, OPS, REPO, Api, finish, need_live, nft_clear, nft_counters, oplog, provenance, ref_clock, snap, ssh
from .loss_ab import run_op, video_slices

GCS_IP = "10.88.242.139"
PORTS_DTLS = "{ 14700, 14701 }"
DTLS_KINDS = ("full", "full_nc", "psk_ke", "psk_dhe_ke")


def nft_set_all(pi, pct):
    """Loss rules on the Pi for the link (UDP 14600) and for DTLS (UDP 14700/14701), both directions, counted apart."""
    n = int(round(pct * 100))
    def rule(d, ports, tag):
        return (f"udp {d} {ports} counter comment \"seen-{tag}\"\n    " +
                (f"udp {d} {ports} numgen random mod 10000 < {n} counter drop comment \"drop-{tag}\"" if n > 0
                 else f"udp {d} 0 counter comment \"drop-{tag}\""))
    script = f"""set -e
sudo -n {NFT} delete table inet k6gloss 2>/dev/null || true
sudo -n {NFT} -f - <<'EOF'
table inet k6gloss {{
  chain k6g_out {{ type filter hook output priority 0; policy accept;
    {rule("dport", "14600", "out")}
    {rule("dport", PORTS_DTLS, "out-dtls")}
  }}
  chain k6g_in {{ type filter hook input priority 0; policy accept;
    {rule("sport", "14600", "in")}
    {rule("sport", PORTS_DTLS, "in-dtls")}
  }}
}}
EOF
"""
    rc, _, err = ssh(pi, script, 30)
    if rc != 0:
        raise RuntimeError(f"nft on the Pi failed: {err.strip()[:300]}")


class DtlsClient:
    """dtls_bench client on the Pi, one process for the whole run: a command in, one JSON line out."""

    def __init__(self, pi):
        cmd = (f"~/dtls/dtls_bench client {GCS_IP} 14700 14701 ~/dtls_certs/uav-cert.pem ~/dtls_certs/uav-key.pem "
               f"~/dtls_certs/gcs-cert.pem")
        self.p = subprocess.Popen(sshopts.ssh_base(pi) + [cmd], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)
        self.hello = json.loads(self.p.stdout.readline())

    def run(self, kind):
        self.p.stdin.write(kind + "\n")
        self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())

    def close(self):
        try:
            self.p.stdin.write("quit\n")
            self.p.stdin.flush()
            self.p.wait(10)
        except Exception:
            self.p.kill()


def link_rounds(api, rounds, tag, pace, lock, out):
    for r in range(rounds):
        order = ("fixed", "rtt") if r % 2 == 0 else ("rtt", "fixed")
        for retx in order:                                # a whole set per timer: one ratchet in 0.5 s at most (GCS)
            for op in OPS:
                with lock:
                    out.append(run_op(api, op, tag, retx))
                time.sleep(pace)


def dtls_rounds(client, rounds, pace, lock, out):
    for r in range(rounds):
        for kind in DTLS_KINDS:                           # psk_* resume the ticket of the full_nc just before
            with lock:
                res = client.run(kind)
            res["t"] = time.time()
            out.append(res)
            time.sleep(pace)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--api", default="http://127.0.0.1:8600")
    ap.add_argument("--pi", default="kyber-pi")
    ap.add_argument("-o", "--out", default=str(REPO / "paper_plots" / "data"))
    ap.add_argument("--levels", default="0,1,2,5,10,20")
    ap.add_argument("--rounds", type=int, default=5)
    ap.add_argument("--slices", type=int, default=4)
    ap.add_argument("--slice", type=float, default=10.0)
    ap.add_argument("--pace", type=float, default=0.4)
    ap.add_argument("--no-video", action="store_true",
                    help="camera off, no video slices: handshakes of the link and of DTLS only (14 October 2026: with the GNSS "
                         "receiver attached the camera stopped within seconds whenever the radio sent video)")
    a = ap.parse_args()
    api = Api(a.api)
    if a.no_video:
        if api.get("/api/state")["link"]["state"] != "UP":
            raise SystemExit("the secure link is not up")
        api.cmd("stop_live")
    else:
        need_live(api)
    levels = [float(x) for x in a.levels.split(",")]
    certs = "/root/dtls_certs"
    servers = [subprocess.Popen(["/root/dtls/dtls_bench", "server", str(port), str(cookie), f"{certs}/gcs-cert.pem",
                                 f"{certs}/gcs-key.pem", f"{certs}/uav-cert.pem"], stderr=subprocess.DEVNULL)
               for port, cookie in ((14700, 1), (14701, 0))]
    time.sleep(0.5)
    client = DtlsClient(a.pi)
    ref = ref_clock(a)
    out = {"what": "the Kyber-6G link (fixed | rtt repeat timer, keyframe request on | off) and DTLS 1.3 (wolfSSL, "
                   "SecP384r1MLKEM1024, ML-DSA-87 pinned certificates) at the same loss rates, interleaved; loss injected on "
                   "the Pi (nftables, UDP 14600 and 14700/14701, both directions)",
           "provenance": provenance(api, a, ref), "dtls": client.hello,
           "design": {"levels": levels, "rounds": a.rounds, "slices": 0 if a.no_video else a.slices, "slice_s": a.slice, "pace_s": a.pace,
                      "dtls_kinds": DTLS_KINDS, "video": not a.no_video}, "levels": []}
    for op in OPS:
        run_op(api, op, "warmup", "rtt")
        time.sleep(0.5)
    for k in DTLS_KINDS:
        client.run(k)
    first = oplog(api)
    since = first[-1]["n"] if first else 0
    budget = int(len(levels) * (a.slices * (a.slice + 2) + a.rounds * 10 * 8) + 300)
    rc, _, err = ssh(a.pi, "sudo -n systemctl stop k6g-loss-cleanup.timer k6g-loss-cleanup.service 2>/dev/null; "
                           "sudo -n systemctl reset-failed k6g-loss-cleanup.service 2>/dev/null; "
                           f"sudo -n systemd-run --quiet --collect --on-active={budget} --unit k6g-loss-cleanup {NFT} delete table inet k6gloss", 30)
    if rc != 0:
        raise SystemExit(f"could not arm the clean-up timer on the Pi, not injecting loss: {err.strip()[:200]}")
    t_start = time.monotonic()
    lock = threading.Lock()
    try:
        for i, pct in enumerate(levels):
            tag = f"bl{pct:g}"
            nft_set_all(a.pi, pct)
            time.sleep(3)
            lv = {"nominal_pct": pct, "tag": tag, "slices": [], "ops": [], "dtls": []}
            c0 = nft_counters(a.pi)
            rate = ref.rate() or 1.0
            th = [threading.Thread(target=link_rounds, args=(api, a.rounds, tag, a.pace, lock, lv["ops"]), daemon=True),
                  threading.Thread(target=dtls_rounds, args=(client, a.rounds, a.pace, lock, lv["dtls"]), daemon=True)]
            if not a.no_video:
                th.append(threading.Thread(target=video_slices, args=(api, a.slices, a.slice, i % 2 == 0, rate, lv["slices"]), daemon=True))
            for t in th:
                t.start()
            for t in th:
                t.join()
            c1 = nft_counters(a.pi)
            lv["counters_before"], lv["counters_after"] = c0, c1
            out["levels"].append(lv)
            p = lambda tag: 100 * (c1.get(f"drop-{tag}", 0) - c0.get(f"drop-{tag}", 0)) / max(c1.get(f"seen-{tag}", 0) - c0.get(f"seen-{tag}", 0), 1)
            ok = {k: sum(1 for d in lv["dtls"] if d.get("kind") == k and d.get("ok")) for k in DTLS_KINDS}
            print(f"  {pct:5.1f} %: link uplink {p('out'):.2f} %, DTLS uplink {p('out-dtls'):.2f} %  link ops ok {sum(o['ok'] for o in lv['ops'])}/{len(lv['ops'])}"
                  f"  DTLS ok {ok}  ({time.monotonic() - t_start:.0f} s)", flush=True)
            ref.sample()
    finally:
        nft_clear(a.pi)
        api.cmd("video_tuning", keyframe_request=True)
        client.close()
        for s in servers:
            s.terminate()
    time.sleep(6)
    out["uav_oplog"] = [e for e in oplog(api, since) if str(e.get("tag", "")).startswith("bl")]
    api.cmd("link_tuning", retx_timer="rtt")
    return finish(out, ref, a, "baseline_ab")


if __name__ == "__main__":
    main()
