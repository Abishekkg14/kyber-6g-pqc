"""End-to-end pipeline test against the RUNNING system (GCS + UAV), via the GCS API.

    python -m kyber6g.tools.pipeline_test [--api http://127.0.0.1:8600] [--keep-live]

Every check reports PASS / FAIL / INFO with the measured value; nothing is
assumed. A JSON report is written to ~/kyber6g_ground/exports/.
"""
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

API = "http://127.0.0.1:8600"
RESULTS = []


def get(path, raw=False, timeout=30):
    with urllib.request.urlopen(API + path, timeout=timeout) as r:
        data = r.read()
        return data if raw else json.loads(data)


def cmd(c, **args):
    req = urllib.request.Request(API + "/api/cmd", data=json.dumps({"cmd": c, "args": args}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=90) as r:
        return json.loads(r.read())


def check(name, ok, value, info=False):
    status = "INFO" if info else ("PASS" if ok else "FAIL")
    RESULTS.append({"check": name, "status": status, "value": value})
    print(f"[{status:4s}] {name}: {value}")
    return ok


def drops(s):
    L = s["link"]
    d, rj = L.get("drops") or {}, (L.get("record") or {}).get("rejected") or {}
    return {k: d.get(k, 0) + rj.get(k, 0) for k in ("auth-fail", "duplicate", "stale", "stale-epoch", "wrong-session", "malformed")}


def wait(pred, timeout, step=0.5):
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = pred()
        if v:
            return v
        time.sleep(step)
    return None


def audio_checks(source: str = ""):
    """Sealed audio, both ways. No microphone is attached to the Pi, so a file stands in for one: `source`, or a six
    second tone made here as a real MP3. It is copied to the Pi's inbox, sealed there, fetched, verified and opened;
    then the same once more, sent while it is sealed."""
    repo = Path(__file__).resolve().parents[2]
    src = Path(source) if source else Path(tempfile.gettempdir()) / "k6g_pipeline_tone.mp3"
    if not source:
        r = subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", "sine=frequency=440:duration=6",
                            "-c:a", "libmp3lame", "-b:a", "64k", "-ar", "44100", "-ac", "1", str(src)], capture_output=True)
        if r.returncode != 0 or not src.is_file():
            return check("sealed audio", True, "this ffmpeg cannot make an MP3 test tone: audio checks skipped", info=True)
    data = src.read_bytes()
    want = hashlib.sha256(data).hexdigest()
    name = "".join(c if c.isalnum() or c in "._-" else "_" for c in src.name)

    def put():
        r = subprocess.run(["bash", str(repo / "run" / "kyber6g.sh"), "audio-put", str(src)], capture_output=True, text=True, timeout=90)
        return r.returncode == 0, (r.stdout.strip().splitlines() or [r.stderr.strip()[:120]])[-1]

    def clips():
        return (get("/api/state").get("audio") or {}).get("clips") or []

    ok, said = put()
    if not check("audio source copied to the Pi's inbox (SSH, post-quantum hybrid key exchange)", ok, said):
        return
    r = cmd("record_audio", source=name)
    res = r.get("result") or {}
    check("audio sealed on the UAV: hybrid wrap, signed, plain source removed", r.get("ok") and res.get("frames", 0) > 0 and res.get("source_kept") is False,
          f"{res.get('name')}: {res.get('frames')} frames in {res.get('blocks')} blocks of {res.get('block_bytes')} B, sealed in {res.get('seal_ms')} ms"
          if r.get("ok") else r.get("error"))
    clip = res.get("name", "")
    la = cmd("list_audio").get("result") or {}
    check("UAV lists the clip, its inbox is empty again", any(c.get("name") == clip for c in la.get("clips", [])) and not any(x.get("name") == name for x in la.get("sources", [])),
          f"{la.get('count')} clips, {la.get('bytes')} B on the UAV, {la.get('sources') and len(la['sources'])} waiting")
    ck = cmd("check_audio", name=clip)
    check("the UAV checks its stored clip against its own signature (it holds no key that opens it)",
          ck.get("ok") and (ck.get("result") or {}).get("blocks") == res.get("blocks"), ck.get("result") or ck.get("error"))
    cmd("fetch_audio", name=clip)
    got = wait(lambda: next((c for c in clips()[:4] if c.get("name") == clip), None), 40)
    check("clip fetched: signature, chain, opened on the GCS, the audio byte for byte the source",
          got and got.get("signature") == "PASS" and got.get("decrypt") == "PASS" and got.get("sha256") == want,
          f"transfer {got.get('integrity')} in {got.get('seconds')} s, signature {got.get('signature')}, open {got.get('decrypt')} in {got.get('open_ms')} ms, "
          f"chain: {got.get('chain')}, {got.get('duration_s'):.1f} s of {got.get('codec')}" if got and got.get("duration_s") is not None else (got or "timeout"))
    if got and got.get("url"):
        check("opened audio served", hashlib.sha256(get(got["url"], raw=True)).hexdigest() == want, got["url"])
        ex = cmd("audio_excerpt", name=clip, t0=1.0, t1=3.0)
        x = ex.get("result") or {}
        check("an excerpt (seconds 1 to 3) verifies with the UAV's public key alone", ex.get("ok") and x.get("verified_with_public_key_only") == "PASS"
              and 0 < x.get("bundle_bytes", 0) < x.get("clip_bytes", 0),
              f"blocks {x.get('blocks')} of {x.get('blocks_in_clip')}, {x.get('keys_released')} keys released, bundle {x.get('bundle_bytes')} B of a {x.get('clip_bytes')} B clip"
              if ex.get("ok") else ex.get("error"))
    # the same source once more, sent while it is sealed
    ok, said = put()
    if not ok:
        return check("audio source copied again for the live run", False, said)
    t_live = time.time()
    r = cmd("record_audio", source=name, live=True)
    tag = (r.get("result") or {}).get("tag")
    if not check("live audio started", r.get("ok") and tag, r.get("result") or r.get("error")):
        return
    heard = []

    def listen():
        try:
            heard.append(get(f"/audio_live?tag={tag}", raw=True, timeout=120))
        except Exception as e:                       # noqa: BLE001 - reported below as "nothing heard"
            heard.append(b"")
    th = threading.Thread(target=listen, daemon=True)
    th.start()
    dur = (got or {}).get("duration_s") or 6.0
    live = wait(lambda: next((c for c in clips()[:4] if c.get("how") == "live" and (c.get("received_at") or 0) >= t_live), None), dur + 45)
    check("live clip: every block sent as it is sealed, completed and verified against the signed root",
          live and live.get("decrypt") == "PASS" and live.get("signature") == "PASS" and live.get("sha256") == want,
          f"{live.get('live_blocks_on_air')} of {live.get('blocks')} blocks arrived on the air, {live.get('live_blocks_repaired')} fetched again from the card; "
          f"chain: {live.get('chain')}" if live else "timeout")
    th.join(timeout=30)
    h = heard[0] if heard else b""
    check("live audio can be listened to while it comes in", len(h) >= 0.5 * len(data),
          f"{len(h)} of {len(data)} bytes opened for the listener" + (" (the whole clip, identical)" if h == data else ""))


def crypto_checks(s):
    """Both nodes checked their cryptography against published values when they started (crypto/selftest.py)."""
    for who, c in (("ground station", s.get("crypto")), ("UAV", (s.get("uav") or {}).get("crypto"))):
        c = c or {}
        check(f"cryptographic self-test passed when the {who} started (known answers, its own key pairs)",
              c.get("ok") is True and (c.get("checks") or 0) >= 16 and not c.get("failed"),
              f"{c.get('checks')} checks in {c.get('ms')} ms, liboqs {c.get('liboqs')}" if c else "no report")
    check("suite: ML-KEM-1024 + X25519 for the keys, ML-DSA-87 for the identities", "MLKEM1024-X25519-MLDSA87" in str(s["link"].get("suite")), s["link"].get("suite"))


def motion_checks(s):
    """The UAV's motion watch: it watches, refuses a wrong setting, finds a target drawn into its own camera's pictures
    (on the UAV, in memory), and its reports arrive as text in the status stream."""
    m = ((s.get("uav") or {}).get("camera") or {}).get("motion") or {}
    if not check("motion watch watching on the UAV (the camera's small second picture)", m.get("available") and m.get("watching") and not m.get("error"),
                 f"{m.get('hz_measured')} looks/s, {m.get('ms')} ms each, picture {m.get('lores')}, sensitivity {m.get('sensitivity')}" if m else "no report"):
        return
    r = cmd("motion", sensitivity="extreme")
    check("a wrong setting of the watch is refused", not r.get("ok") and "sensitivity" in str(r.get("error")), r.get("error"))
    r = cmd("motion", selftest={"looks": 36, "seed": 9, "cases": [{"target": False}, {"size": 10, "contrast": 40, "speed": 3},
                                                                  {"size": 6, "contrast": 20, "speed": 1}]})
    res = r.get("result") or {}
    rows = res.get("results") or [{}, {}, {}]
    quiet, big, small = rows[0], rows[1], rows[2]
    check("self-test on the UAV's own camera: a target drawn into its pictures is found where it is",
          r.get("ok") and (big.get("hits") or 0) >= 0.8 * (big.get("looks_with_target") or 1e9) and (small.get("hits") or 0) >= 0.6 * (small.get("looks_with_target") or 1e9),
          f"{big.get('hits')} of {big.get('looks_with_target')} looks (40 grey levels, 10 px), {small.get('hits')} of {small.get('looks_with_target')} (20 levels, 6 px); "
          f"{res.get('mode')}, {res.get('lux')} lux" if r.get("ok") else r.get("error"))
    check("the same pictures without a target", True, f"{quiet.get('false_regions')} region(s) in {quiet.get('looks')} looks "
          "(0 = the real scene stood still during the capture; more = something in it moved)", info=True)
    g = get("/api/state").get("motion") or {}
    check("motion reports are taken only when well-formed", (g.get("malformed") or 0) == 0, f"{g.get('reports')} reports, {g.get('events')} movement(s) so far")
    feed = get("/api/detections/latest")
    check("overlay feed carries the watch's regions", "motion" in feed, "moving now" if feed.get("motion") else "nothing moving now")


def main():
    global API
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default=API)
    ap.add_argument("--audio", default="", help="audio file that stands in for a microphone (default: a 6 s tone made with ffmpeg)")
    ap.add_argument("--no-audio", action="store_true")
    ap.add_argument("--keep-live", action="store_true")
    ap.add_argument("--pi", default="kyber-pi", help="ssh alias of the UAV for the stored-data audit ('' to skip)")
    a = ap.parse_args()
    API = a.api
    t_start = time.time()

    # 1. health
    s = get("/api/state")
    up = check("secure link up", s["link"]["state"] == "UP", f"{s['link']['state']} session {s['link']['session_id']} suite {s['link']['suite']}")
    if not up:
        print("UAV not connected - aborting"); return 2
    u = s["uav"] or {}
    check("UAV status fresh", u.get("rx_at") and s["now"] - u["rx_at"] < 5, f"age {round(s['now'] - (u.get('rx_at') or 0), 1)} s")
    check("camera available", (u.get("camera") or {}).get("available"), (u.get("camera") or {}).get("sensor"))
    check("LCD updating", (u.get("lcd") or {}).get("ok"), u.get("lcd"))
    check("Pi not throttled", (u.get("system") or {}).get("throttled") == "0x0", (u.get("system") or {}).get("throttled"))
    base_drops = drops(s)
    # the camera is put back at the end the way the operator had it (live or not, NORMAL or NIGHT)
    live0, mode0 = bool((u.get("camera") or {}).get("live")), (u.get("camera") or {}).get("mode") or "NORMAL"
    if mode0 != "NORMAL":
        cmd("set_mode", mode="NORMAL")                  # the rate checks below are for the normal mode (NIGHT exposes up to 100 ms)
    # The detector and the finder are tested running. An operator who has paused them (the AI button, FINDER off) has
    # not broken anything: they are switched on for the test and put back as they were at the end. (Before, a paused
    # detector was reported as three failed checks.)
    det0 = bool((s.get("detector") or {}).get("enabled"))
    fin0 = bool(((s.get("detector") or {}).get("finder") or {}).get("enabled"))
    if not det0:
        cmd("detector", enabled=True)
    if not fin0:
        cmd("finder", enabled=True)
    if not (det0 and fin0):
        check("detector and finder as the operator left them", True,
              f"detector {'on' if det0 else 'PAUSED'}, finder {'on' if fin0 else 'OFF'}: switched on for this test, put back afterwards", info=True)

    # 2. telemetry rate + storage
    n0 = get("/api/db")["telemetry"]
    time.sleep(10)
    s = get("/api/state")
    n1 = get("/api/db")["telemetry"]                    # fresh count, same source as n0 (the cached /api/state value can be seconds old)
    rate = (n1 - n0) / 10
    check("telemetry stored in SQLite (~1 Hz)", 0.7 <= rate <= 1.6, f"{n1 - n0} rows in 10 s")
    # Every latency compares the UAV's clock with this machine's. The clock of a WSL VM can run at the wrong rate
    # (measured: 8.3 % slow, stepped by 2.9 s every 35 s); latencies are then estimates, and are reported as such.
    L0 = s["link"]
    rate_pct = L0.get("clock_rate_pct") or 0
    clock_ok = check("ground-station clock steady against the UAV clock", abs(rate_pct) <= 0.5,
                     f"drift {rate_pct} % ({'this machine runs SLOW' if rate_pct > 0.5 else 'this machine runs FAST' if rate_pct < -0.5 else 'ok'}), "
                     f"{L0.get('clock_steps')} jump(s) seen, offset {L0.get('clock_offset_ms')} ms"
                     + ("" if abs(rate_pct) <= 0.5 else "  -> a fault of this machine's clock (WSL VM), not of the link; latencies below are estimates"))
    tl = s["telemetry_stats"]["latency_ms"]
    check("telemetry latency (median)", tl is not None and -5 < tl < 1000, f"{tl} ms" + ("" if clock_ok else "  [estimate only: clock unsteady]"),
          info=not clock_ok)
    t = s["telemetry"] or {}
    check("GNSS fix", (t.get("mode") or 0) >= 2, f"{t.get('fix')} · sats {t.get('sats_used')}/{t.get('sats_seen')} · "
          f"satellites {[(x[0], x[1], x[4]) for x in t.get('satellites') or []]}", info=(t.get("mode") or 0) < 2)

    # 3. live video (loss is counted over THIS test, not since the ground station started)
    v_before = get("/api/state")["video"]
    r = cmd("start_live")
    check("start live acknowledged", r.get("ok"), r.get("error") or "ok")
    time.sleep(12)
    s = get("/api/state")
    v = s["video"]
    d_lost = v.get("frames_lost", 0) - v_before.get("frames_lost", 0)
    d_done = v.get("frames_complete", 0) - v_before.get("frames_complete", 0)
    check("video frame rate 25-31 fps (measured on the camera's clock)", 25 <= (v.get("fps") or 0) <= 31, f"{v.get('fps')} fps, {v.get('kbps')} kbit/s")
    check("video frames lost in the first 12 s <= 1 %", d_lost <= max(1, d_done // 100), f"{d_lost} lost of {d_done}")
    # frames that arrived but were given up because the decoder was behind (a busy or throttled ground-station machine):
    # not a loss on the link, and the picture stays live, but worth knowing
    behind = v.get("decoder_behind", 0) - v_before.get("decoder_behind", 0)
    given_up = v.get("frames_dropped_decoder_behind", 0) - v_before.get("frames_dropped_decoder_behind", 0)
    check("decoder kept up with the stream", behind == 0, f"{behind} time(s) behind, {given_up} frames given up for it (the machine was busy)", info=behind > 0)
    lat = v.get("display_latency_ms")
    # A latency must be positive; with an unsteady clock it is reported as an estimate, not judged. The clock is looked
    # at again here: on this laptop it went from steady to 8 % slow between two checks of one run (latency read -61 ms).
    L1 = s["link"]
    clock_ok = clock_ok and abs(L1.get("clock_rate_pct") or 0) <= 0.5 and L1.get("clock_steps") == L0.get("clock_steps")
    check("capture->decoded latency (median)", lat is not None and 0 < lat < 400, f"{lat} ms "
          f"(network+crypto {v.get('network_latency_ms')} ms, decode {v.get('decode_ms')} ms)"
          + ("" if clock_ok else f"  [estimate only: clock unsteady, drift {L1.get('clock_rate_pct')} %]"), info=not clock_ok)

    # 4. detector + dashboard stability (a detector that was only just switched on may still be loading its model)
    det = wait(lambda: (lambda d: d if (d.get("fps") or 0) > 0 or d.get("error") else None)(get("/api/state")["detector"]), 5 if det0 else 90) \
        or get("/api/state")["detector"]
    check("object detector running", det.get("available") and (det.get("fps") or 0) > 0,
          f"{det.get('profile')} {det.get('fps')} fps, {det.get('infer_ms')} ms/frame, {det.get('vocab_size')} classes, objects now {det.get('counts_now')}")
    check("unique tracked objects so far", True, det.get("by_class_unique"), info=True)
    fd = wait(lambda: (lambda f: f if f.get("error") or (f.get("passes") or 0) > 0 else None)(get("/api/state")["detector"].get("finder") or {}), 30) or {}
    check("finder (OWLv2) running", fd.get("enabled") and not fd.get("error") and (fd.get("passes") or 0) > 0,
          f"{fd.get('backend')} words {fd.get('words')} · {fd.get('passes')} passes · {fd.get('infer_ms')} ms each · threshold {fd.get('threshold')} · "
          f"error {fd.get('error')}")
    seen, labels, boxes_ok, frames = {}, {}, True, set()
    t_end = time.time() + 12
    while time.time() < t_end:                      # sample the overlay feed the dashboard uses
        L = get("/api/detections/latest")
        if L.get("seq") in frames:
            time.sleep(0.05); continue
        frames.add(L.get("seq"))
        for d in L.get("dets", []):
            labels.setdefault(d["id"], set()).add(d["cls"])
            boxes_ok &= all(0 <= v <= 1 for v in d["box"]) and d["box"][2] > d["box"][0] and d["box"][3] > d["box"][1]
        time.sleep(0.05)
    flips = {k: sorted(v) for k, v in labels.items() if len(v) > 1}
    # age of the analysed frame = capture time of the picture on screen minus capture time of that frame (both camera clock)
    age = round(L["view_ts"] - L["frame_ts"], 2) if L.get("frame_ts") and L.get("view_ts") else None
    check("detection feed: boxes valid, frame timestamps on the camera clock", boxes_ok and age is not None and -0.05 <= age < 6,
          f"{len(frames)} frames sampled, analysed frame is {age} s older than the picture on screen")
    check("labels stable per tracked object (no flicker)", len(flips) <= max(1, len(labels) // 5),
          f"{len(flips)} of {len(labels)} tracks changed label in 12 s {dict(list(flips.items())[:3])}")
    st = get("/api/state")
    check("dashboard build id served (auto-reload on update)", bool(st.get("build")), st.get("build"))
    for f_ in ("/", "/static/app.js", "/static/boxtracker.js", "/static/index.html"):
        try:
            ok_ = len(get(f_, raw=True)) > 1000
        except Exception as e:
            ok_ = False
        check(f"dashboard file served: {f_}", ok_, "ok" if ok_ else "missing")

    # 4b. the cryptography's self-test at start-up, and the motion watch (the live video is on: its camera runs)
    crypto_checks(st)
    motion_checks(st)

    # 5. image
    r = cmd("capture_image")
    shot = (r.get("result") or {}).get("name")
    check("capture image acknowledged", r.get("ok"), shot or r.get("error"))
    # found by its name: the gallery lists a fixed number of images, so its length says nothing once it is full
    img = wait(lambda: next((i for i in get("/api/state")["images"][:4] if i.get("name") == shot and i.get("kind") != "photo_enc"), None), 30)
    check("image received, SHA-256 verified", img and img.get("integrity") == "PASS",
          f"{img.get('name')} {img.get('size')} B in {img.get('seconds')} s" if img else "not received")
    if img and img.get("url"):
        check("image file served", len(get(img["url"], raw=True)) == img["size"], f"{img['url']}")
    stored = ((r.get("result") or {}).get("info") or {}).get("stored_as")
    check("photo also stored on the UAV, encrypted at rest (.k6gimg)", bool(stored), stored or "not stored")
    if stored:
        lp = (cmd("list_photos").get("result") or {})
        check("UAV lists the stored photo", any(p["name"] == stored for p in lp.get("photos", [])), f"{lp.get('count')} photos, {lp.get('bytes')} B on the UAV")
        cmd("fetch_photo", name=stored)
        back = wait(lambda: next((i for i in get("/api/state")["images"][:3] if i.get("kind") == "photo_enc" and i.get("name") == stored), None), 30)
        check("stored photo fetched from the UAV and decrypted on the GCS",
              back and back.get("integrity") == "PASS" and back.get("decrypt") == "PASS" and back.get("meta", {}).get("sha256") == (img or {}).get("sha256"),
              f"transfer {back.get('integrity')}, decrypt {back.get('decrypt')} in {back.get('decrypt_ms')} ms, same SHA-256 as the live copy" if back else "timeout")

    # 6. recording while live
    r = cmd("start_rec")
    check("start recording", r.get("ok"), (r.get("result") or {}).get("name") or r.get("error"))
    time.sleep(5)
    c1 = get("/api/state")["uav"]["camera"]
    time.sleep(3)
    c2 = get("/api/state")["uav"]["camera"]
    check("REC indicator data (elapsed time, size, frames) advances while recording",
          c1.get("recording") and (c2.get("recording_elapsed_s") or 0) > (c1.get("recording_elapsed_s") or 0) >= 3 and (c2.get("recording_bytes") or 0) > (c1.get("recording_bytes") or 0) > 0,
          f"elapsed {c1.get('recording_elapsed_s')} -> {c2.get('recording_elapsed_s')} s, {c2.get('recording_bytes')} B, {c2.get('recording_frames')} frames")
    r2 = cmd("start_rec")
    check("second start_rec is refused cleanly (no orphan file)", not r2.get("ok") and "already recording" in (r2.get("error") or ""), r2.get("error"))
    r = cmd("stop_rec")
    rec = r.get("result") or {}
    check("stop recording (encrypted at rest)", r.get("ok") and rec.get("frames", 0) > 0,
          f"{rec.get('frames')} frames, {rec.get('segments')} segments, {rec.get('throughput_MBps')} MB/s AES-GCM")
    r = cmd("fetch_recording", name=rec.get("name", ""))
    t_fetch = time.time()
    got = wait(lambda: next((x for x in get("/api/state")["recordings"][:3]
                             if x.get("name") == rec.get("name") and (x.get("received_at") or 0) >= t_fetch - 5), None), 60)
    check("recording fetched + decrypted on GCS", got and got.get("decrypt") == "PASS" and got.get("frames") == rec.get("frames"),
          f"transfer {got.get('integrity')}, decrypt {got.get('decrypt')}, {got.get('frames')} frames, {got.get('decrypt_ms')} ms" if got else "timeout")
    if got and got.get("mp4"):
        mp4 = Path.home() / "kyber6g_ground" / "recordings" / Path(got["mp4"]).name
        try:
            nb = subprocess.run(["ffprobe", "-v", "error", "-count_frames", "-select_streams", "v:0", "-show_entries",
                                 "stream=nb_read_frames", "-of", "csv=p=0", str(mp4)], capture_output=True, text=True).stdout.strip()
            check("every recorded frame decodes", nb == str(got["frames"]), f"{nb}/{got['frames']} frames decodable")
        except FileNotFoundError:
            check("every recorded frame decodes", True, "ffprobe not installed", info=True)

    # 6b. sealed audio: stored on the UAV and fetched, and sent while it is sealed
    if not a.no_audio:
        try:
            audio_checks(a.audio)
        except Exception as e:                           # noqa: BLE001 - a failed audio check must not end the pipeline test
            check("sealed audio", False, f"{type(e).__name__}: {e}")

    # 7. night vision
    r1, r2 = cmd("set_mode", mode="NIGHT"), None
    time.sleep(4)
    cam_n = get("/api/state")["uav"]["camera"]
    r2 = cmd("set_mode", mode="NORMAL")
    check("night mode switch + restore", r1.get("ok") and r2.get("ok") and cam_n.get("mode") == "NIGHT",
          f"night exposure {cam_n.get('exposure_us')} us, fps {cam_n.get('fps')}")

    # 8. rekeying under live video
    # Three rounds of (cached rekey, PQ ratchet). UDP over Wi-Fi has no retransmission, so a lost frame now and then is
    # normal with or without a rekey (measured: 12 of 5809 frames over 32 rekeys, no drop counter moved); one 6 s window
    # is too short to tell that from a rekey problem, three rounds are judged together.
    s0 = get("/api/state")
    v0 = s0["video"]
    sid, switched, rk_ms, pq_ms, per_round = s0["link"]["session_id"], 0, [], [], []
    for _ in range(3):
        before = get("/api/state")["video"].get("frames_lost", 0)
        cmd("cached_rekey")
        time.sleep(2)
        s1 = get("/api/state")
        switched += s1["link"]["session_id"] != sid
        rk_ms.append((s1["uav"]["link"] or {}).get("last_cached_rekey_ms"))
        cmd("pq_ratchet")
        time.sleep(2)
        s2 = get("/api/state")
        switched += s2["link"]["session_id"] != s1["link"]["session_id"]
        pq_ms.append((s2["uav"]["link"] or {}).get("last_pq_ratchet_ms"))
        sid = s2["link"]["session_id"]
        per_round.append(s2["video"].get("frames_lost", 0) - before)
    check("1-RTT Cached RapidRekey (3 times, a new session each time)", switched >= 3 and all(m is not None for m in rk_ms),
          f"{rk_ms} ms (UAV side, includes the round trip)")
    check("PQ ratchet, fresh ML-KEM-1024 + X25519 (3 times, a new session each time)", switched == 6,
          f"{pq_ms} ms (UAV side), {switched} of 6 session switches, now {sid}")
    v2 = get("/api/state")["video"]
    lost, frames = sum(per_round), v2.get("frames_complete", 0) - v0.get("frames_complete", 0)
    check("video loss during 6 rekeys <= 1.5 %", frames > 200 and lost <= frames * 0.015,
          f"{lost} frames lost of {frames} ({100 * lost / max(frames, 1):.2f} %), per round {per_round}")

    # 9. exports
    csv_ = get("/api/export/telemetry.csv?minutes=30", raw=True)
    check("CSV export", csv_.startswith(b"id,run_id,ts"), f"{len(csv_)} bytes")
    gj = json.loads(get("/api/export/telemetry.geojson?minutes=30", raw=True))
    check("GeoJSON export", gj.get("type") == "FeatureCollection", f"{len(gj['features'])} features")
    kml = get("/api/export/telemetry.kml?minutes=30", raw=True)
    check("KML export", b"<kml" in kml, f"{len(kml)} bytes")
    db = get("/api/export/db", raw=True)
    check("database snapshot export", db.startswith(b"SQLite format 3"), f"{len(db) / 1e6:.2f} MB")
    check("database contents", True, get("/api/db"), info=True)

    # 10. security counters over the whole run
    end = drops(get("/api/state"))
    delta = {k: end[k] - base_drops[k] for k in end}
    check("no authentication failures / replays on the real link", all(v == 0 for v in delta.values()), delta)

    # 11. everything that was stored (ground station + UAV)
    pi = ["--pi", a.pi] if a.pi else []
    r = subprocess.run([sys.executable, "-m", "kyber6g.tools.data_audit", *pi], capture_output=True, text=True, timeout=300)
    last = (r.stdout.strip().splitlines() or [""])[-1]
    bad = [l for l in r.stdout.splitlines() if l.startswith("[FAIL]")]
    check("stored-data audit (SQLite, images, recordings, UAV files, no secrets)", r.returncode == 0, f"{last} {bad[:3]}")

    if mode0 != "NORMAL":
        cmd("set_mode", mode=mode0)
    if not (a.keep_live or live0):
        cmd("stop_live")
    if not det0:
        cmd("detector", enabled=False)
    if not fin0:
        cmd("finder", enabled=False)
    passed = sum(r["status"] == "PASS" for r in RESULTS)
    failed = [r["check"] for r in RESULTS if r["status"] == "FAIL"]
    summary = {"started": t_start, "duration_s": round(time.time() - t_start, 1), "pass": passed, "fail": len(failed),
               "failed_checks": failed, "results": RESULTS}
    out = Path.home() / "kyber6g_ground" / "exports" / time.strftime("pipeline_%Y%m%d_%H%M%S.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=1, default=str))
    print(f"\n{passed} PASS, {len(failed)} FAIL in {summary['duration_s']} s -> {out}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
