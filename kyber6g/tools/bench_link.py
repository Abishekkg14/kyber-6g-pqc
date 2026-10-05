"""Measurements on the LIVE system (Raspberry Pi 4B <-> ground station over Wi-Fi), driven from the ground station.

    python -m kyber6g.tools.bench_link ops       [-n 150]                     session establishment over the real link
    python -m kyber6g.tools.bench_link rtt       [-n 600]                     round trip of a control message
    python -m kyber6g.tools.bench_link timeline  [--seconds 780]              the running system, sampled twice a second
    python -m kyber6g.tools.bench_link loss      [--levels 0,0.5,1,2,5,10,20] packet loss injected on the Pi (nftables)
    python -m kyber6g.tools.bench_link transfer  [-n 5]                       reliable transfer of a recording and of photos
  common:  [--api http://127.0.0.1:8600] [--pi kyber-pi] [-o paper_plots/data]

Each run writes one JSON file with every sample and a `provenance` block (when, which software, which hardware,
camera settings, clock check). Nothing is simulated.

Which clock a number comes from (it matters: the clock of the laptop's WSL virtual machine was measured to run
8-11 % slow, the Pi's clock is disciplined by NTP):
  * every duration of a handshake, rekey, ratchet or round trip is timed ON THE PI and only fetched from it
    (`uav_ms`, the operation log, `rtt_probe`);
  * values timed on the ground station keep the suffix `_raw`; the file's `clock.local_per_reference_second` is the
    measured rate of this machine's clock against the Pi's during the run, and true = raw / rate;
  * frame and bit rates are computed by the ground station from the camera's own time stamps.
Packet loss is injected with nftables on the Pi, for UDP port 14600 in both directions, and the file records the
rule's own packet counters (how many datagrams it saw and how many it dropped), not the nominal percentage.
"""
import argparse
import json
import platform
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import sshopts
from .bench_crypto import RefClock

REPO = Path(__file__).resolve().parents[2]
OPS = ("full_handshake", "cached_rekey", "pq_ratchet")
GCS_MS = {"full_handshake": "last_handshake_ms", "cached_rekey": "last_cached_rekey_ms", "pq_ratchet": "last_pq_ratchet_ms"}
NFT = "/usr/sbin/nft"


class Api:
    def __init__(self, url):
        self.url = url.rstrip("/")

    def get(self, path, timeout=20):
        with urllib.request.urlopen(self.url + path, timeout=timeout) as r:
            return json.loads(r.read())

    def cmd(self, c, wait_s=None, **args):
        body = {"cmd": c, "args": args, **({"timeout": wait_s} if wait_s else {})}
        req = urllib.request.Request(self.url + "/api/cmd", json.dumps(body).encode(), {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=(wait_s or 60) + 30) as r:
                return json.loads(r.read())
        except (urllib.error.URLError, OSError, ValueError) as e:
            return {"ok": False, "error": f"{type(e).__name__}: {e}"}


def ssh(host, script, timeout=60):
    r = subprocess.run(sshopts.ssh_base(host) + ["bash -s"], input=script, capture_output=True, text=True, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def snap(api):
    """The numbers of one moment that the plots need, from /api/state."""
    s = api.get("/api/state")
    L, v, u, d = s["link"], s["video"], s.get("uav") or {}, s.get("detector") or {}
    cam, sysm, tx, ul = u.get("camera") or {}, u.get("system") or {}, u.get("video_tx") or {}, u.get("link") or {}
    rec = L.get("record") or {}
    return {"gcs_now": s["now"], "mono": time.monotonic(), "uav_ts": u.get("ts"), "uav_rx_at": u.get("rx_at"),
            "state": L["state"], "session": L.get("session_id"), "rtt_ms_raw": L.get("rtt_ms"), "clock_rate_pct": L.get("clock_rate_pct"),
            "gcs_handshakes_ok": L.get("handshakes_ok"), "gcs_cached_ok": L.get("cached_rekeys_ok"), "gcs_ratchets": L.get("pq_ratchets"),
            "rx_records": L.get("rx_records"), "rx_bytes": L.get("rx_bytes"), "drops": L.get("drops"), "rejected": rec.get("rejected"),
            "udp_rcvbuf_errors": (L.get("udp") or {}).get("RcvbufErrors"),
            "fps": v.get("fps"), "kbps": v.get("kbps"), "frames_complete": v.get("frames_complete"), "frames_lost": v.get("frames_lost"),
            "frames_decoded": v.get("frames_decoded"), "frames_skipped_wait_key": v.get("frames_skipped_wait_key"),
            "chunks_rx": v.get("chunks_rx"), "expected_chunks": v.get("expected_chunks"), "late_chunks": v.get("late_chunks"),
            "stream_gaps": v.get("stream_gaps"), "decoder_restarts": v.get("decoder_restarts"), "decode_ms_raw": v.get("decode_ms"),
            "decoder_behind": v.get("decoder_behind"), "frames_given_up_decoder_behind": v.get("frames_dropped_decoder_behind"),
            "frames_without_picture": v.get("frames_without_picture"), "det_eased": (d.get("ease") or {}).get("factor"),
            "network_latency_ms_est": v.get("network_latency_ms"), "display_latency_ms_est": v.get("display_latency_ms"),
            "uav_cpu": sysm.get("cpu_percent"), "uav_per_cpu": sysm.get("per_cpu"), "uav_temp_c": sysm.get("temp_c"), "uav_mem_pct": sysm.get("mem_percent"),
            "uav_throttled": sysm.get("throttled"), "wifi_dbm": (sysm.get("wifi") or {}).get("signal_dbm"),
            "cam_fps": cam.get("fps"), "cam_kbps": cam.get("kbps"), "encode_latency_ms": cam.get("encode_latency_ms"), "cam_live": cam.get("live"),
            "cam_recording": cam.get("recording"), "frames_sent": tx.get("frames_sent"), "chunks_sent": tx.get("chunks_sent"),
            "send_failures": tx.get("send_failures"), "seal_us_avg": tx.get("seal_us_avg"),
            "uav_state": ul.get("state"), "uav_handshakes_ok": ul.get("handshakes_ok"), "uav_handshakes_fail": ul.get("handshakes_fail"),
            "uav_cached_ok": ul.get("cached_rekeys_ok"), "uav_cached_rej": ul.get("cached_rekey_rejects"), "uav_ratchets": ul.get("pq_ratchets"),
            "uav_epochs": (ul.get("record") or {}).get("epochs"), "uav_rotations": (ul.get("record") or {}).get("rotations"),
            "uav_tx_records": ul.get("tx_records"), "uav_drops": ul.get("drops"),
            "tm_rx": s["telemetry_stats"].get("rx"), "tm_gaps": s["telemetry_stats"].get("gaps"), "tm_backfill": s["telemetry_stats"].get("backfill"),
            "det_fps": d.get("fps"), "det_infer_ms_raw": d.get("infer_ms"), "det_profile": d.get("profile")}


def oplog(api, since=0):
    """The UAV's own record of every handshake / rekey / ratchet after entry number `since`."""
    out = []
    for _ in range(60):
        r = api.cmd("oplog", since=since)
        res = r.get("result") or {}
        out += res.get("entries") or []
        if not r.get("ok") or not res.get("more"):
            break
        since = out[-1]["n"]
    return out


def provenance(api, a, ref):
    def git(*args):
        try:
            return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True, timeout=10).stdout.strip()
        except Exception:
            return None
    s = api.get("/api/state")
    u = s.get("uav") or {}
    cam = u.get("camera") or {}
    rc, pi, _ = ssh(a.pi, "cat /proc/device-tree/model 2>/dev/null | tr -d '\\0'; echo; uname -srm; ~/kyber6g_venv/bin/python -V; "
                          "~/kyber6g_venv/bin/python -c 'import oqs,cryptography;print(oqs.oqs_version(),cryptography.__version__)' 2>/dev/null | tail -1; "
                          "iw dev wlan0 link 2>/dev/null | grep -E 'freq|signal|bitrate' | tr -s ' \\t\\n' ' '; echo; timedatectl show -p NTPSynchronized --value", 30)
    return {"tool": "kyber6g.tools.bench_link " + " ".join(sys.argv[1:]), "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "repository": {"commit": git("rev-parse", "HEAD"), "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
                           "uncommitted_files": len((git("status", "--porcelain") or "").splitlines())},
            "ground_station": {"host": platform.node(), "platform": platform.platform(), "python": platform.python_version(),
                               "note": "WSL2 virtual machine on the laptop; its clock rate is measured below"},
            "uav": {"ssh": a.pi, "ssh_key_exchange": sshopts.negotiated_kex(a.pi), "lines": [l.strip() for l in pi.splitlines() if l.strip()]},
            "link": {"suite": s["link"].get("suite"), "uav_addr": s["link"].get("uav_addr"), "transport": "UDP over IEEE 802.11 (Wi-Fi), same access point"},
            "camera": {k: cam.get(k) for k in ("sensor", "mode", "width", "height", "fps_target", "bitrate_target", "codec", "lux", "exposure_us", "gain", "live")},
            "detector": {"profile": (s.get("detector") or {}).get("profile"), "enabled": (s.get("detector") or {}).get("enabled"),
                         "finder": ((s.get("detector") or {}).get("finder") or {}).get("enabled")},
            "clock_start": ref.points[-1] if ref else None}


def finish(out, ref, a, name):
    if ref:
        ref.sample()
        out["clock"] = {"reference": a.pi, "local_per_reference_second": round(ref.rate(), 6),
                        "points_local_reference_rtt_s": [[round(x, 6) for x in p] for p in ref.points],
                        "note": "values ending in _raw were timed on the ground station: true = raw / local_per_reference_second"}
        ref.close()
    out["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    d = Path(a.out)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{name}.json"
    path.write_text(json.dumps(out))
    print(f"-> {path}  ({path.stat().st_size / 1024:.0f} kB)")
    return path


def wait_entry(api, key, since, name=None, timeout=60, poll=0.25):
    """The entry of a received image / recording (state["images"] or ["recordings"]) that arrived after ground-station
    time `since` (and has this `name`): a transfer counts as received when its file was verified and stored, which
    is a moment later than the last chunk."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        for e in api.get("/api/state").get(key) or []:
            if (e.get("received_at") or 0) > since and (name is None or e.get("name") == name):
                return e
        time.sleep(poll)
    return None


def need_live(api):
    s = api.get("/api/state")
    if s["link"]["state"] != "UP":
        raise SystemExit("the secure link is not up")
    cam = (s.get("uav") or {}).get("camera") or {}
    if not cam.get("live"):
        r = api.cmd("start_live")
        if not r.get("ok"):
            raise SystemExit(f"cannot start the live stream: {r}")
        time.sleep(6)


def ref_clock(a):
    """The Pi's clock as the reference, with a first rate estimate (two readings 5 s apart) before the run starts."""
    ref = RefClock(a.pi)
    time.sleep(5)
    ref.sample()
    return ref


# ----------------------------------------------------------------------------------------------------------- ops
def run_op(api, op, tag, wait_s=None):
    r = api.cmd(op, wait_s=wait_s, wait=True, tag=tag)
    res = r.get("result") if isinstance(r.get("result"), dict) else {}
    return {"op": op, "acked": bool(r.get("ok")), "ok": bool(r.get("ok") and res.get("ok")), "uav_ms": res.get("ms"), "parts": res.get("parts"),
            "requests_sent": res.get("requests_sent"), "error": (r.get("error") or res.get("error")), "session": res.get("session")}


def ops(a, api):
    need_live(api)
    ref = ref_clock(a)
    out = {"what": "time to a new session at the UAV, over the live link, video streaming meanwhile", "provenance": provenance(api, a, ref)}
    first = oplog(api)
    since = first[-1]["n"] if first else 0
    s0, rows = snap(api), []
    for i in range(a.n):
        for op in OPS:                                   # round-robin, so slow drifts (Wi-Fi, temperature) hit all three alike
            t0 = time.monotonic()
            row = run_op(api, op, "ops")
            row["http_s_raw"] = round(time.monotonic() - t0, 4)
            L = api.get("/api/state")["link"]
            row.update(i=i, gcs_ms_raw=L.get(GCS_MS[op]), gcs_rtt_ms_raw=L.get("rtt_ms"))
            rows.append(row)
            time.sleep(a.pace)
        if (i + 1) % 25 == 0:
            ref.sample()
            done = [r for r in rows if r["ok"]]
            print(f"  {i + 1}/{a.n}: {len(done)}/{len(rows)} ok", flush=True)
    time.sleep(2)
    out.update(rows=rows, before=s0, after=snap(api), uav_oplog=[e for e in oplog(api, since) if e["tag"] == "ops"])
    for op in OPS:
        ms = sorted(r["uav_ms"] for r in rows if r["op"] == op and r["ok"])
        if ms:
            print(f"  {op:15s} n={len(ms):4d}  median {ms[len(ms) // 2]:8.2f} ms   p95 {ms[int(len(ms) * 0.95)]:8.2f} ms   min {ms[0]:.2f}  max {ms[-1]:.2f}")
    d = {k: out["after"][k] - s0[k] for k in ("frames_complete", "frames_lost", "stream_gaps")}
    print(f"  video during the {len(rows)} operations: {d}")
    return finish(out, ref, a, "link_ops")


# ----------------------------------------------------------------------------------------------------------- rtt
def rtt(a, api):
    need_live(api)
    ref = ref_clock(a)
    out = {"what": "round trip of a control message through the secure path, timed on the UAV, video streaming meanwhile",
           "provenance": provenance(api, a, ref), "probes": []}
    left = a.n
    while left > 0:
        k = min(left, 200)
        r = api.cmd("rtt_probe", n=k, interval=0.05)
        res = r.get("result") or {}
        out["probes"].append({"ok": bool(r.get("ok")), "sent": res.get("sent"), "lost": res.get("lost"), "rtt_ms": res.get("rtt_ms"),
                              "gcs_rtt_ms_raw": api.get("/api/state")["link"].get("rtt_ms")})
        left -= k
    # the path alone: ICMP echo from the Pi to the ground station's address (also timed by the Pi)
    import re
    rc, txt, _ = ssh(a.pi, f"ping -c 150 -i 0.2 {a.gcs_ip} 2>&1", 90)
    out["icmp"] = {"target": a.gcs_ip, "summary": [l for l in txt.strip().splitlines()[-2:]],
                   "rtt_ms": [float(x) for x in re.findall(r"time=([0-9.]+) ms", txt)]}
    allr = sorted(x for p in out["probes"] for x in (p["rtt_ms"] or []))
    if allr:
        print(f"  secure control round trip: n={len(allr)} median {allr[len(allr) // 2]:.2f} ms  p95 {allr[int(len(allr) * 0.95)]:.2f} ms  "
              f"lost {sum(p['lost'] or 0 for p in out['probes'])}")
    print(f"  ICMP: {out['icmp']['summary'][-1] if out['icmp']['summary'] else 'no answer'}")
    # round trip of a LARGE message: the probe carries padding that the ground station sends back, so the message is
    # several datagrams in each direction, as a handshake message is. The sizes take turns (blocks of 50 probes), so
    # that a change of the radio conditions during the run does not look like an effect of the size.
    sizes = [int(x) for x in (a.pad_sizes or "").split(",") if x.strip()]
    if sizes:
        def datagrams(pad):
            padding = ["p" * 1000] * (pad // 1000) + (["p" * (pad % 1000)] if pad % 1000 else [])
            msg = {"t": "hb", "echo": 1000000, "pad": padding} if padding else {"t": "hb", "echo": 1000000}
            return -(-len(json.dumps(msg, separators=(",", ":"))) // 1100)
        sized = {pad: {"pad_bytes": pad, "datagrams_each_way": datagrams(pad), "sent": 0, "lost": 0, "rtt_ms": []} for pad in sizes}
        for _ in range(max(1, a.pad_n // 50)):
            for pad in sizes:
                res = api.cmd("rtt_probe", n=50, interval=0.04, pad=pad).get("result") or {}
                sized[pad]["sent"] += res.get("sent") or 0
                sized[pad]["lost"] += res.get("lost") or 0
                sized[pad]["rtt_ms"] += res.get("rtt_ms") or []
        out["sized"] = list(sized.values())
        for s in out["sized"]:
            v = sorted(s["rtt_ms"])
            if v:
                print(f"  message of {s['datagrams_each_way']} datagram(s) each way: n={len(v)} median {v[len(v) // 2]:.2f} ms  "
                      f"p95 {v[int(len(v) * 0.95)]:.2f} ms  lost {s['lost']}")
        # The same probes, but ONE per command from the ground station, paced like the session operations of `ops`.
        # A session operation in `ops` starts when the UAV has just received the command that asks for it; the probes
        # above start whenever the UAV's own timer says so. The two are not the same moment on a radio that is busy
        # with a burst of video datagrams every 33 ms, and the operations are to be compared with the former.
        # `gcs_ms_raw`: how long the ground station took over that probe (complete request to answer sent, its own
        # clock), read back after every probe as it is after every session operation. A round trip minus this is the
        # path alone; the model of the simulation puts the ground station's time for the operation in its place.
        trig = {pad: {"pad_bytes": pad, "datagrams_each_way": datagrams(pad), "sent": 0, "lost": 0, "rtt_ms": [], "gcs_ms_raw": []} for pad in sizes}
        seen = None
        for _ in range(max(1, a.trig_n // 25)):
            for pad in sizes:
                for _ in range(25):
                    res = api.cmd("rtt_probe", n=1, interval=0.005, pad=pad).get("result") or {}
                    L = api.get("/api/state")["link"]
                    trig[pad]["sent"] += res.get("sent") or 0
                    trig[pad]["lost"] += res.get("lost") or 0
                    if len(res.get("rtt_ms") or []) == 1 and L.get("last_echo_ms") is not None and L.get("last_echo_n") != seen:
                        trig[pad]["rtt_ms"].append(res["rtt_ms"][0])
                        trig[pad]["gcs_ms_raw"].append(L["last_echo_ms"])
                    seen = L.get("last_echo_n")
                    time.sleep(min(a.pace, 0.1))
        out["sized_triggered"] = list(trig.values())
        for s in out["sized_triggered"]:
            v = sorted(s["rtt_ms"])
            if v:
                g = sorted(s["gcs_ms_raw"])
                print(f"  the same, one probe per command: {s['datagrams_each_way']} datagram(s) each way: n={len(v)} median {v[len(v) // 2]:.2f} ms  "
                      f"p95 {v[int(len(v) * 0.95)]:.2f} ms  lost {s['lost']}  (of it at the ground station: median {g[len(g) // 2]:.2f} ms raw)")
    return finish(out, ref, a, a.name or "link_rtt")


# ------------------------------------------------------------------------------------------------------ timeline
def timeline(a, api):
    if not a.idle:
        need_live(api)
    ref = ref_clock(a)
    out = {"what": "the running system sampled every 0.5 s: periodic key rotation, cached rekeys and PQ ratchet with live video",
           "provenance": provenance(api, a, ref), "interval_s": 0.5}
    first = oplog(api)
    since = first[-1]["n"] if first else 0
    cfg = {"rotate_seconds": 30, "cached_rekey_interval_s": 120, "pq_ratchet_interval_s": 600}
    out["link_config"] = cfg
    rows = []
    phases = []
    if a.record_at and a.record_for:
        phases = [(a.record_at, "start_rec"), (a.record_at + a.record_for, "stop_rec")]
    # Steps of 0.5 s of REAL time: this machine's clock is slow by the measured rate, so a step is 0.5 * rate of its
    # own seconds. The rate is the one measured just before the run; the samples carry the UAV's time stamps anyway.
    step, t0 = 0.5 * (ref.rate() or 1.0), time.monotonic()
    for k in range(1, int(a.seconds / 0.5) + 1):
        try:
            rows.append(snap(api))
        except Exception as e:                           # one failed poll is a missing sample, not the end of the run
            rows.append({"mono": time.monotonic(), "error": f"{type(e).__name__}: {e}"})
        while phases and k * 0.5 >= phases[0][0]:
            _, c = phases.pop(0)
            r = api.cmd(c)
            out.setdefault("commands", []).append({"mono": time.monotonic(), "at_s": k * 0.5, "cmd": c, "ok": r.get("ok"),
                                                   "uav_ts": rows[-1].get("uav_ts"), "result": r.get("result")})
        if k % 120 == 0:
            ref.sample()
            print(f"  {k // 2} s of {int(a.seconds)}", flush=True)
        time.sleep(max(0.0, t0 + k * step - time.monotonic()))
    out.update(rows=rows, uav_oplog=oplog(api, since))
    ok = [r for r in rows if "error" not in r]
    kinds = {}
    for e in out["uav_oplog"]:
        kinds[e["kind"]] = kinds.get(e["kind"], 0) + 1
    print(f"  {len(ok)} samples; operations logged by the UAV: {kinds}; frames lost {ok[-1]['frames_lost'] - ok[0]['frames_lost']} of "
          f"{ok[-1]['frames_complete'] - ok[0]['frames_complete']}")
    return finish(out, ref, a, a.name or "timeline")


# ----------------------------------------------------------------------------------------------------------- loss
def nft_set(pi, pct):
    """(Re)create the loss rules on the Pi: UDP port 14600, both directions. 0 = rules that only count."""
    n = int(round(pct * 100))                            # numgen random mod 10000 < n  ->  pct %
    # 0 %: the same two rules per direction, the second one matching nothing (port 0), so its counter stays 0
    out_rule = f"udp dport 14600 numgen random mod 10000 < {n} counter drop" if n > 0 else "udp dport 0 counter"
    in_rule = f"udp sport 14600 numgen random mod 10000 < {n} counter drop" if n > 0 else "udp sport 0 counter"
    script = f"""set -e
sudo -n {NFT} delete table inet k6gloss 2>/dev/null || true
sudo -n {NFT} -f - <<'EOF'
table inet k6gloss {{
  chain k6g_out {{ type filter hook output priority 0; policy accept;
    udp dport 14600 counter comment "seen-out"
    {out_rule} comment "drop-out"
  }}
  chain k6g_in {{ type filter hook input priority 0; policy accept;
    udp sport 14600 counter comment "seen-in"
    {in_rule} comment "drop-in"
  }}
}}
EOF
"""
    rc, out, err = ssh(pi, script, 30)
    if rc != 0:
        raise RuntimeError(f"nft on the Pi failed: {err.strip()[:300]}")


def nft_counters(pi):
    rc, out, err = ssh(pi, f"sudo -n {NFT} -j list table inet k6gloss", 30)
    c = {}
    for item in json.loads(out).get("nftables", []) if rc == 0 and out.strip() else []:
        rule = item.get("rule")
        if rule and rule.get("comment"):
            for e in rule.get("expr", []):
                if "counter" in e:
                    c[rule["comment"]] = e["counter"]["packets"]
    return c


def nft_clear(pi):
    ssh(pi, f"sudo -n {NFT} delete table inet k6gloss 2>/dev/null; sudo -n systemctl stop k6g-loss-cleanup.timer 2>/dev/null; "
            f"sudo -n {NFT} list table inet k6gloss 2>&1 | head -1", 30)


def loss(a, api):
    need_live(api)
    levels = [float(x) for x in a.levels.split(",")]
    ref = ref_clock(a)
    out = {"what": "packet loss injected on the Pi (nftables, UDP 14600, both directions); video, telemetry, rekeying and transfers under it",
           "provenance": provenance(api, a, ref), "window_s": a.seconds, "levels": []}
    first = oplog(api)
    since = first[-1]["n"] if first else 0
    # dead-man switch: whatever happens to this program, the Pi removes the rules by itself
    rc, _, err = ssh(a.pi, "sudo -n systemctl stop k6g-loss-cleanup.timer k6g-loss-cleanup.service 2>/dev/null; "
                           "sudo -n systemctl reset-failed k6g-loss-cleanup.service 2>/dev/null; "
                           f"sudo -n systemd-run --quiet --collect --on-active={int(len(levels) * (a.seconds + 300) + 600)} "
                           f"--unit k6g-loss-cleanup {NFT} delete table inet k6gloss", 30)
    if rc != 0:
        raise SystemExit(f"could not arm the clean-up timer on the Pi, not injecting loss: {err.strip()[:200]}")
    try:
        for pct in levels:
            tag = f"loss{pct:g}"
            nft_set(a.pi, pct)
            time.sleep(4)
            lv = {"nominal_pct": pct, "tag": tag}
            c0, s0, m0 = nft_counters(a.pi), snap(api), time.monotonic()
            samples = []
            while time.monotonic() - m0 < a.seconds * (ref.rate() or 1.0):
                time.sleep(1.0)
                try:
                    samples.append(snap(api))
                except Exception:
                    pass
            c1, s1 = nft_counters(a.pi), snap(api)
            lv.update(counters_before=c0, counters_after=c1, before=s0, after=s1, samples=samples, window_s_raw=round(time.monotonic() - m0, 3))
            # session operations under the same loss; a command or its answer can be lost too, so the UAV's own log
            # (fetched once the loss is removed) is what counts, and the wait for an answer is kept short
            lv["ops"] = []
            for i in range(a.ops):
                for op in OPS:
                    lv["ops"].append(run_op(api, op, tag, wait_s=8))
                    time.sleep(0.6)
            # one photo: captured, stored encrypted on the Pi, transferred with retransmission, verified by SHA-256
            lv["photos"] = []
            for i in range(a.photos):
                now0, m = api.get("/api/state")["now"], time.monotonic()
                r = api.cmd("capture_image", wait_s=12)
                # with the answer lost the name is not known: then the next image that arrives is the one
                got = wait_entry(api, "images", now0, (r.get("result") or {}).get("name") if r.get("ok") else None, timeout=45)
                lv["photos"].append({"acked": bool(r.get("ok")), "received": got is not None, "bytes": (got or {}).get("size"),
                                     "integrity": (got or {}).get("integrity"), "transfer_s_raw": (got or {}).get("seconds"),
                                     "chunks": (got or {}).get("chunks"), "wall_s_raw": round(time.monotonic() - m, 3)})
            lv["counters_end"] = nft_counters(a.pi)
            out["levels"].append(lv)
            seen, dropped = c1.get("seen-out", 0) - c0.get("seen-out", 0), c1.get("drop-out", 0) - c0.get("drop-out", 0)
            fc, fl = s1["frames_complete"] - s0["frames_complete"], s1["frames_lost"] - s0["frames_lost"]
            print(f"  {pct:5.1f} %: uplink dropped {dropped}/{seen} ({100 * dropped / max(seen, 1):.2f} %)  frames complete {fc} lost {fl}  "
                  f"ops ok {sum(o['ok'] for o in lv['ops'])}/{len(lv['ops'])}  photos {sum(p['received'] for p in lv['photos'])}/{len(lv['photos'])}", flush=True)
            ref.sample()
    finally:
        nft_clear(a.pi)
    time.sleep(6)                                        # the link settles; then the UAV's log of what really happened
    out["uav_oplog"] = [e for e in oplog(api, since) if str(e.get("tag", "")).startswith("loss")]
    out["after_recovery"] = snap(api)
    return finish(out, ref, a, "loss")


# ------------------------------------------------------------------------------------------------------ transfer
def transfer(a, api):
    need_live(api)
    ref = ref_clock(a)
    out = {"what": "reliable transfer over the secure link: a recording made for this test (fetched n times) and photos",
           "provenance": provenance(api, a, ref), "recording": None, "fetches": [], "photos": []}
    r = api.cmd("start_rec")
    if not r.get("ok"):
        raise SystemExit(f"start_rec: {r}")
    time.sleep(a.record_s * (ref.rate() or 1.0))
    r = api.cmd("stop_rec")
    summ = r.get("result") or {}
    out["recording"] = summ
    name = summ.get("name")
    print(f"  recorded {name}: {summ.get('frames')} frames, {summ.get('file_bytes')} B, at-rest encryption {summ.get('throughput_MBps')} MB/s on the Pi")
    for i in range(a.n):
        now0 = api.get("/api/state")["now"]
        r = api.cmd("fetch_recording", name=name)
        got = wait_entry(api, "recordings", now0, name, timeout=240)
        out["fetches"].append({"acked": bool(r.get("ok")), "bytes": (got or {}).get("size"), "integrity": (got or {}).get("integrity"),
                               "decrypt": (got or {}).get("decrypt"), "transfer_s_raw": (got or {}).get("seconds"),
                               "decrypt_ms_raw": (got or {}).get("decrypt_ms"), "frames": (got or {}).get("frames"), "chunks": (got or {}).get("chunks")})
        f = out["fetches"][-1]
        if f["transfer_s_raw"]:
            print(f"  fetch {i + 1}: {f['bytes']} B in {f['transfer_s_raw']} s (raw) = {f['bytes'] * 8 / f['transfer_s_raw'] / 1e6:.1f} Mbit/s raw, "
                  f"{f['integrity']}/{f['decrypt']}", flush=True)
        time.sleep(1)
    # the size of every frame of that recording and which of them are keyframes (the ground station keeps the
    # encrypted file it fetched): what the video stream is made of, for the loss model in simulation/
    try:
        from ..crypto import identity as idm
        from ..recording.recorder import decrypt_recording
        enc = Path.home() / "kyber6g_ground" / "recordings" / name
        _, _, rep = decrypt_recording(enc, idm.load_recording_dk(idm.DEFAULT_DIR), x25519_sk=idm.load_recording_xsk(idm.DEFAULT_DIR),
                                      signer_pk=idm.load_pinned_peer(idm.DEFAULT_DIR, "uav"), index=True)
        out["recording_frames"] = {"signature": rep.get("signature"), "format": rep.get("format"),
                                   "columns": ["ts_us", "keyframe", "bytes"], "frames": rep["frame_index"]}
        sizes = sorted(f[2] for f in rep["frame_index"])
        keys = sorted(f[2] for f in rep["frame_index"] if f[1])
        print(f"  frames: {len(sizes)}, median {sizes[len(sizes) // 2]} B; keyframes: {len(keys)}, median {keys[len(keys) // 2] if keys else None} B; "
              f"signature {rep.get('signature')}")
    except Exception as e:
        out["recording_frames"] = {"error": f"{type(e).__name__}: {e}"}
        print(f"  frame sizes not read: {e}")
    for i in range(a.photos):
        now0 = api.get("/api/state")["now"]
        r = api.cmd("capture_image")
        info = (r.get("result") or {}).get("info") or {}
        got = wait_entry(api, "images", now0, (r.get("result") or {}).get("name"), timeout=30, poll=0.2)
        out["photos"].append({"bytes": (got or {}).get("size"), "integrity": (got or {}).get("integrity"), "transfer_s_raw": (got or {}).get("seconds"),
                              "capture_ms": info.get("capture_ms"), "seal_ms": info.get("seal_ms"), "stored_bytes": info.get("stored_bytes")})
        time.sleep(0.5)
    return finish(out, ref, a, "transfer")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("what", choices=["ops", "rtt", "timeline", "loss", "transfer"])
    ap.add_argument("--api", default="http://127.0.0.1:8600")
    ap.add_argument("--pi", default="kyber-pi", help="ssh alias of the Raspberry Pi (reference clock, loss injection)")
    ap.add_argument("--gcs-ip", default="10.88.242.139", help="address the Pi reaches the ground station under (for ICMP)")
    ap.add_argument("-o", "--out", default=str(REPO / "paper_plots" / "data"))
    ap.add_argument("-n", type=int, default=None)
    ap.add_argument("--pace", type=float, default=0.25, help="ops: pause after each operation (s)")
    ap.add_argument("--seconds", type=float, default=None)
    ap.add_argument("--idle", action="store_true", help="timeline: do not start the live stream (the UAV at rest)")
    ap.add_argument("--name", help="timeline / rtt: name of the output file (default 'timeline' / 'link_rtt')")
    ap.add_argument("--pad-sizes", default="", help="rtt: also probe with messages padded to these sizes in bytes, "
                                                    "e.g. 0,1500,2600,3700,4800,6000 (1 to 6 datagrams each way)")
    ap.add_argument("--pad-n", type=int, default=300, help="rtt: probes per padded size")
    ap.add_argument("--trig-n", type=int, default=150, help="rtt: probes per padded size sent one per command")
    ap.add_argument("--record-at", type=float, default=0, help="timeline: start a recording after this many seconds (0 = none)")
    ap.add_argument("--record-for", type=float, default=0, help="timeline: ... and stop it after this many more")
    ap.add_argument("--levels", default="0,0.5,1,2,5,10,20")
    ap.add_argument("--ops", type=int, default=8, help="loss: rounds of the three session operations per level")
    ap.add_argument("--photos", type=int, default=3, help="loss / transfer: photos per level / in total")
    ap.add_argument("--record-s", type=float, default=20, help="transfer: length of the test recording (s)")
    a = ap.parse_args()
    api = Api(a.api)
    if a.what == "ops":
        a.n = a.n or 150
        return ops(a, api) and 0
    if a.what == "rtt":
        a.n = a.n or 600
        return rtt(a, api) and 0
    if a.what == "timeline":
        a.seconds = a.seconds or 780
        return timeline(a, api) and 0
    if a.what == "loss":
        a.seconds = a.seconds or 40
        return loss(a, api) and 0
    a.n = a.n or 5
    return transfer(a, api) and 0


if __name__ == "__main__":
    sys.exit(main())
