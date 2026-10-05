"""Real-browser test of the dashboard (headless Chromium driven by Playwright).

    python -m kyber6g.tools.ui_test [--url http://127.0.0.1:8600] [--dwell 10] [--quick] [--no-controls]
    bash run/kyber6g.sh ui-test

Needs the ground station running and, for the control checks, the UAV connected.
Test tooling only (pip install playwright && python -m playwright install --with-deps chromium).

What it measures, per tab and at three scroll positions, with live video running:
  * layout shifts reported by the browser itself (the Layout Instability API: any element that moves without
    user input) - this is the objective form of "the page scrolls / jumps like a glitch";
  * the position and size of every panel, sampled 4x per second - names the panel that moved;
  * document height and scroll position;
  * JavaScript errors, unhandled promise rejections, console errors, failed requests;
  * that animation frames run and the detection overlay is drawn.
Then it presses every control the way an operator would and checks what the page shows afterwards.
"""
import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

INSTRUMENT = r"""
(() => {
  const ui = window.__ui = {errors: [], shifts: [], moves: [], heights: [], raf: 0, t0: performance.now()};
  window.addEventListener('error', (e) => ui.errors.push('error: ' + String(e.message) + ' @' + String(e.filename || '').split('/').pop() + ':' + e.lineno));
  window.addEventListener('unhandledrejection', (e) => ui.errors.push('unhandled rejection: ' + String(e.reason)));
  const ce = console.error.bind(console);
  console.error = (...a) => { ui.errors.push('console.error: ' + a.map(String).join(' ').slice(0, 300)); ce(...a); };
  const name = (n) => { if (!n) return '?'; const el = n.nodeType === 1 ? n : n.parentElement; if (!el) return '?';
    const p = el.closest('.panel'), h = p && p.querySelector('h2');
    return (el.id ? '#' + el.id : el.nodeName.toLowerCase() + (el.className && typeof el.className === 'string' ? '.' + el.className.split(' ')[0] : '')) +
      (h ? ' in [' + h.firstChild.textContent.trim().slice(0, 28) + ']' : ''); };
  try {
    new PerformanceObserver((list) => { for (const e of list.getEntries()) if (!e.hadRecentInput)
      ui.shifts.push({v: +e.value.toFixed(5), t: Math.round(e.startTime), src: (e.sources || []).slice(0, 5).map((s) => name(s.node))}); })
      .observe({type: 'layout-shift', buffered: false});
  } catch (e) { ui.errors.push('layout-shift observer unavailable: ' + e); }
  let prev = new Map();
  setInterval(() => {
    const now = Math.round(performance.now());
    ui.heights.push([now, document.documentElement.scrollHeight, Math.round(scrollY)]);
    if (ui.heights.length > 4000) ui.heights.splice(0, 1000);
    const cur = new Map();
    document.querySelectorAll('.view.active .panel, header, nav, .banner.show').forEach((p, i) => {
      const r = p.getBoundingClientRect(), h = p.querySelector('h2');
      const key = (h ? h.firstChild.textContent.trim() : p.nodeName) + '#' + i;
      cur.set(key, [Math.round(r.top + scrollY), Math.round(r.height)]);
    });
    if (!ui.muted) for (const [k, v] of cur) { const o = prev.get(k); if (o && (o[0] !== v[0] || o[1] !== v[1])) ui.moves.push({t: now, panel: k, dTop: v[0] - o[0], dH: v[1] - o[1]}); }
    prev = cur;
  }, 250);
  const tick = () => { ui.raf++; requestAnimationFrame(tick); }; requestAnimationFrame(tick);
  ui.report = (since) => {
    const sh = ui.shifts.filter((s) => s.t >= since), mv = ui.moves.filter((m) => m.t >= since), hs = ui.heights.filter((h) => h[0] >= since);
    const by = {}; sh.forEach((s) => s.src.forEach((x) => (by[x] = +(((by[x] || 0) + s.v).toFixed(4)))));
    const pm = {}; mv.forEach((m) => { const e = pm[m.panel] || (pm[m.panel] = {n: 0, dTop: 0, dH: 0}); e.n++; e.dTop = Math.max(e.dTop, Math.abs(m.dTop)); e.dH = Math.max(e.dH, Math.abs(m.dH)); });
    return {shifts: sh.length, cls: +sh.reduce((a, s) => a + s.v, 0).toFixed(4), sources: by, moved: pm,
            heights: [...new Set(hs.map((h) => h[1]))], scroll: [...new Set(hs.map((h) => h[2]))].slice(0, 6), errors: ui.errors.slice()};
  };
})();
"""

TABS = ["mission", "telemetry", "security", "media", "data"]
# third-party hosts: a failed map tile or font is the network's business, not a dashboard defect
EXTERNAL = ("arcgisonline.com", "openstreetmap.org", "googleapis.com", "gstatic.com", "unpkg.com", "jsdelivr.net")


class Run:
    def __init__(self):
        self.results = []

    def check(self, name, ok, detail=""):
        self.results.append({"name": name, "ok": bool(ok), "detail": str(detail)[:600]})
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {str(detail)[:400]}", flush=True)
        return bool(ok)

    def info(self, name, detail):
        self.results.append({"name": name, "ok": None, "detail": str(detail)[:1500]})
        print(f"[INFO] {name}: {str(detail)[:600]}", flush=True)


def wait_js(page, expr, arg=None, timeout=20000, poll=100):
    """Wait until a JavaScript expression (or a function of `arg`) is true in the page.

    Playwright's own wait_for_function polls with eval() INSIDE the page, and the dashboard's Content-Security-Policy
    forbids eval there (as it should: the test runs against the page as it is served, policy included). Each check
    here is one evaluate() through the DevTools protocol, which a page policy does not apply to."""
    deadline = time.monotonic() + timeout / 1000
    while True:
        ok = page.evaluate(expr, arg) if arg is not None else page.evaluate(expr)
        if ok:
            return ok
        if time.monotonic() > deadline:
            raise TimeoutError(f"timeout after {timeout} ms waiting for: {expr[:90]}")
        page.wait_for_timeout(poll)


def api(url, path, cmd=None, args=None, timeout=60):
    if cmd:
        req = urllib.request.Request(url + "/api/cmd", json.dumps({"cmd": cmd, "args": args or {}}).encode(), {"Content-Type": "application/json"})
        return json.load(urllib.request.urlopen(req, timeout=timeout))
    return json.load(urllib.request.urlopen(url + path, timeout=timeout))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8600")
    ap.add_argument("--dwell", type=float, default=10.0, help="seconds observed per tab and scroll position")
    ap.add_argument("--quick", action="store_true", help="one viewport, shorter observation")
    ap.add_argument("--no-controls", action="store_true", help="layout/error sweep only (sends no commands to the UAV)")
    ap.add_argument("--no-teach", action="store_true", help="skip the TEACH flow (it loads the ACCURATE model)")
    ap.add_argument("--shots", default="~/kyber6g_ground/exports/ui")
    a = ap.parse_args()
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright is not installed: pip install playwright && python -m playwright install --with-deps chromium")
        return 2
    shots = Path(a.shots).expanduser()
    shots.mkdir(parents=True, exist_ok=True)
    R = Run()
    url = a.url.rstrip("/")
    st = api(url, "/api/state")
    link_up = st["link"]["state"] == "UP"
    R.check("ground station reachable, secure link up", link_up, f"link {st['link']['state']}")
    controls = link_up and not a.no_controls
    viewports = [(1366, 768)] if a.quick else [(1366, 768), (1920, 1080)]
    dwell = 5.0 if a.quick else a.dwell

    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=["--autoplay-policy=no-user-gesture-required"])
        failed_req, http_err = [], []

        def new_page(w, h):
            ctx = browser.new_context(viewport={"width": w, "height": h}, accept_downloads=True)
            page = ctx.new_page()
            page.add_init_script(INSTRUMENT)
            # not failures: a closed MJPEG stream, and a video player that stops reading an .mp4 once it has the index
            page.on("requestfailed", lambda r: failed_req.append(f"{r.url} {r.failure}") if not any(x in r.url for x in EXTERNAL)
                    and ".mjpg" not in r.url and "/audio_live" not in r.url
                    and not (r.url.endswith((".mp4", ".mp3", ".wav")) and "ERR_ABORTED" in str(r.failure)) else None)
            page.on("response", lambda r: http_err.append(f"{r.status} {r.url}") if r.status >= 400 and url in r.url else None)
            page.goto(url + "/", wait_until="domcontentloaded")
            wait_js(page,"window.K6G_STATE && window.K6G_STATE.link", timeout=20000)
            return ctx, page

        def tab(page, name):
            page.click(f'nav button[data-tab="{name}"]')
            page.wait_for_timeout(300)

        def observe(page, seconds):
            t0 = page.evaluate("performance.now()")
            page.wait_for_timeout(int(seconds * 1000))
            return page.evaluate("(t) => __ui.report(t)", t0)

        def msg_after(page, action, expect, timeout=30000):
            """Run `action`, wait until the command line shows a result for it, return the text."""
            page.evaluate("document.getElementById('msg').textContent = ''; document.getElementById('msg')._t = ''")
            action()
            try:
                wait_js(page,"(e) => { const t = document.getElementById('msg').textContent; return t.includes(e) && !t.trim().endsWith('…'); }",
                                       arg=expect, timeout=timeout)
            except Exception:
                pass
            return page.evaluate("document.getElementById('msg').textContent")

        # ------------------------------------------------------------------ live video on
        if controls:
            # the checks below are written for the standard picture (NORMAL mode, 1280 x 720 at 30 frames/s); whatever
            # the operator had set is put back at the end
            cam_now = (st.get("uav") or {}).get("camera") or {}
            if cam_now.get("mode") not in (None, "NORMAL"):
                api(url, "", "set_mode", {"mode": "NORMAL"})
            if cam_now.get("width") and (cam_now.get("width"), cam_now.get("height"), cam_now.get("fps_target")) != (1280, 720, 30):
                api(url, "", "set_video", {"width": 1280, "height": 720, "fps": 30, "bitrate": 3000000})
            if not cam_now.get("live"):
                api(url, "", "start_live")
            time.sleep(4)

        # ------------------------------------------------------------------ layout sweep
        for (w, h) in viewports:
            ctx, page = new_page(w, h)
            page.wait_for_timeout(4000)
            raf0 = page.evaluate("__ui.raf")
            page.wait_for_timeout(1000)
            fps = page.evaluate("__ui.raf") - raf0
            # headless Chromium draws in software, so the rate itself says little; what matters is that frames are produced
            R.check(f"{w}x{h}: page renders (animation frames running)", fps >= 5, f"{fps} frames in 1 s (software rendering)")
            for name in TABS:
                page.evaluate("__ui.muted = true")
                tab(page, name)
                page.wait_for_timeout(5000)                       # charts created, first data in
                total = {"shifts": 0, "cls": 0.0, "sources": {}, "moved": {}, "heights": set()}
                for frac in (0.0, 0.5, 1.0):
                    page.evaluate("(f) => window.scrollTo(0, Math.round((document.documentElement.scrollHeight - innerHeight) * f))", frac)
                    page.wait_for_timeout(800)
                    page.evaluate("__ui.muted = false")
                    rep = observe(page, dwell)
                    page.evaluate("__ui.muted = true")
                    total["shifts"] += rep["shifts"]; total["cls"] += rep["cls"]
                    total["heights"].update(rep["heights"])
                    for k, v in rep["sources"].items():
                        total["sources"][k] = round(total["sources"].get(k, 0) + v, 4)
                    for k, v in rep["moved"].items():
                        total["moved"][k] = v
                    if len(rep["scroll"]) > 1:
                        total["moved"]["<scroll position changed by itself>"] = rep["scroll"]
                ok = total["shifts"] == 0 and not total["moved"] and len(total["heights"]) == 1
                R.check(f"{w}x{h} {name.upper()}: nothing moves by itself ({dwell * 3:.0f} s, top/middle/bottom)", ok,
                        f"layout shifts {total['shifts']} (score {total['cls']:.4f}) · page height {sorted(total['heights'])} px"
                        + (f" · shifted: {total['sources']}" if total["sources"] else "")
                        + (f" · panels that moved: {total['moved']}" if total["moved"] else ""))
                # Worst case for the live text: every status line / heading note / pill gets a very long text at once.
                # No panel may change position or size (the lines have fixed heights, the rest is cut with an ellipsis).
                torture = page.evaluate("""() => {
                  const snap = () => [...document.querySelectorAll('.view.active .panel, header, nav')].map((p) => { const r = p.getBoundingClientRect();
                    return Math.round(r.top + scrollY) + ':' + Math.round(r.height) + ':' + Math.round(r.width); }).join('|');
                  const before = snap(), text = 'W'.repeat(30) + ' a very long status text'.repeat(40), saved = [];
                  document.querySelectorAll('.l1, .l2, .l3, .panel>h2 .r, .tile .n, .tile .s, .kv td.v').forEach((e) => {
                    if (e.offsetParent !== null) { saved.push([e, e.innerHTML]); e.textContent = text; } });
                  const during = snap();
                  saved.forEach(([e, h]) => (e.innerHTML = h));
                  return {same: before === during && document.documentElement.scrollWidth - innerWidth <= 1, n: saved.length, after: snap() === before};
                }""")
                R.check(f"{w}x{h} {name.upper()}: long status texts cannot move anything", torture["same"] and torture["after"],
                        f"{torture['n']} live text fields filled with 990-character texts")
                page.evaluate("window.scrollTo(0, 0)")
                page.wait_for_timeout(300)
                try:
                    page.screenshot(path=str(shots / f"{name}_{w}x{h}.png"), full_page=True, timeout=60000)
                except Exception as e:                   # the picture is a by-product: a machine too busy to render one in
                    R.info(f"{w}x{h} {name.upper()}: screenshot", f"not taken ({type(e).__name__}); the checks go on")   # a minute must not end the test
            # overflow: nothing may be wider than the window (a horizontal scrollbar is a layout bug)
            for name in TABS:
                tab(page, name)
                over = page.evaluate("document.documentElement.scrollWidth - innerWidth")
                R.check(f"{w}x{h} {name.upper()}: no horizontal overflow", over <= 1, f"{over} px")
            errs = page.evaluate("__ui.errors")
            R.check(f"{w}x{h}: no JavaScript errors during the sweep", not errs, errs[:6])
            ctx.close()

        # ------------------------------------------------------------------ controls
        if controls:
            ctx, page = new_page(1600, 900)
            S = lambda expr: page.evaluate(f"(() => {{ const S = window.K6G_STATE || {{}}; return {expr}; }})()")
            wait_state = lambda expr, timeout=20000: wait_js(page,f"(() => {{ const S = window.K6G_STATE || {{}}; return {expr}; }})()", timeout=timeout)
            hot = lambda c, extra="": page.click(f'.hotbar button[data-cmd="{c}"]{extra}')

            def safe(name, fn):
                try:
                    fn()
                except Exception as e:
                    R.check(name, False, f"{type(e).__name__}: {str(e)[:300]}")

            # The steps below change the detector profile and threshold, the finder, the camera mode and the video
            # size. What the operator had set is put back at the end (see `restore`): a test must leave the station
            # as it found it. An interrupted run once left the AI switched off, and a complete one left the
            # confidence threshold at 0.25.
            det0 = st.get("detector") or {}
            cam0 = (st.get("uav") or {}).get("camera") or {}
            fin0 = det0.get("finder") or {}
            # The detector steps toggle the AI button and expect it to have been ON. With the AI paused by the operator
            # the first click switched it on and the second off, and everything after that waited for a detector that
            # was not running (three failed checks that said nothing about the dashboard). It is switched on here and
            # `restore` puts it back as it was.
            if not det0.get("enabled"):
                api(url, "", "detector", {"enabled": True})
                R.info("detector", "was paused by the operator: switched on for this test, put back at the end")

            def restore():
                args = {"enabled": bool(det0.get("enabled")), "enhance": bool(det0.get("enhance"))}
                args.update({k: det0[k] for k in ("conf", "imgsz") if det0.get(k) is not None})
                if det0.get("custom_vocab"):                  # the operator's own word list, whichever profile is on:
                    args["vocab"] = ", ".join(det0["custom_vocab"])   # the FIND step below replaces it
                if det0.get("profile"):                       # (given together with a word list, the profile decides)
                    args["profile"] = det0["profile"]
                r = api(url, "", "detector", args)
                f = api(url, "", "finder", {k: fin0[k] for k in ("enabled", "words", "threshold", "period") if fin0.get(k) is not None})
                c = []
                if cam0.get("width"):
                    c.append(api(url, "", "set_video", {"width": cam0["width"], "height": cam0["height"], "fps": cam0.get("fps_target"),
                                                        "bitrate": cam0.get("bitrate_target")}))
                if cam0.get("mode"):
                    c.append(api(url, "", "set_mode", {"mode": cam0["mode"]}))
                c.append(api(url, "", "start_live" if cam0.get("live") else "stop_live"))
                R.check("operator's settings put back (detector, finder, camera)", r.get("ok") and f.get("ok") and all(x.get("ok") for x in c),
                        f"detector {args} · finder on={fin0.get('enabled')} · camera {cam0.get('mode')} {cam0.get('width')}x{cam0.get('height')} live={cam0.get('live')}")

            # ---- live video
            def t_live():
                t = msg_after(page, lambda: hot("start_live"), "start_live:")
                R.check("▶ LIVE: command acknowledged", "OK" in t, t)
                wait_js(page,"document.getElementById('video').naturalWidth > 0 && document.getElementById('nosig').style.display === 'none'", timeout=20000)
                dims = page.evaluate("[document.getElementById('video').naturalWidth, document.getElementById('video').naturalHeight]")
                R.check("live video is displayed, NO SIGNAL hidden, LIVE badge shown",
                        page.evaluate("document.getElementById('liveOsd').classList.contains('show')"), f"{dims[0]}x{dims[1]}")
                grab = """() => { const i = document.getElementById('video'), c = document.createElement('canvas'); c.width = 160; c.height = 90;
                    const g = c.getContext('2d'); g.drawImage(i, 0, 0, 160, 90); const d = g.getImageData(0, 0, 160, 90).data; let s = 0;
                    for (let k = 0; k < d.length; k += 16) s = (s * 31 + d[k]) >>> 0; return s; }"""
                hashes = set()
                for _ in range(6):
                    hashes.add(page.evaluate(grab)); page.wait_for_timeout(400)
                R.check("the picture is moving (frames change in the browser)", len(hashes) >= 3, f"{len(hashes)} different frames in 6 samples")
                wait_state("S.video && S.video.fps > 20", 15000)
                v = S("S.video")
                R.check("video rate shown is plausible (20-31 fps)", 20 <= v["fps"] <= 31.0, f"{v['fps']} fps, {v['kbps']} kbit/s")
            safe("▶ LIVE", t_live)

            # ---- detection overlay
            def t_overlay():
                wait_js(page,"typeof boxes !== 'undefined' && serverOffset != null", timeout=15000)
                seen = 0
                for _ in range(40):
                    n = page.evaluate("boxes.tracks.size")
                    if n:
                        seen = n; break
                    page.wait_for_timeout(500)
                det = S("({fps: S.detector.fps, now: S.detector.objects_now, profile: S.detector.profile, analysing: S.detector.analysing})")
                if not seen:
                    R.info("detection overlay", f"no object in view during the test, nothing to draw (detector {det})")
                    return
                painted = page.evaluate("""() => { const c = document.getElementById('overlay'), d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data;
                    let n = 0; for (let k = 3; k < d.length; k += 4) if (d[k]) n++; return n; }""")
                R.check("detection boxes are drawn on the live picture", painted > 200, f"{seen} tracked object(s), {painted} overlay pixels painted · detector {det}")
                inside = page.evaluate("""() => { const o = []; for (const t of boxes.tracks.values()) o.push(t.disp.every((v) => v > -0.05 && v < 1.05) && t.disp[2] > t.disp[0] && t.disp[3] > t.disp[1]); return o; }""")
                R.check("every box lies inside the picture and is well-formed", all(inside), inside)
            safe("overlay", t_overlay)

            # ---- motion watch (it runs on the UAV; the page switches it and draws what it reports)
            def t_motion():
                wait_state("S.uav && S.uav.camera && S.uav.camera.motion && S.uav.camera.motion.available", 10000)
                m0 = S("S.uav.camera.motion")
                R.check("motion watch: the UAV reports it watching", bool(m0.get("watching")) and not m0.get("error"),
                        f"{m0.get('hz_measured')} looks/s, {m0.get('ms')} ms each, sensitivity {m0.get('sensitivity')}")
                text = lambda i: page.evaluate(f"document.getElementById('{i}').textContent")
                on0 = bool(m0.get("enabled"))
                t = msg_after(page, lambda: page.click("#btnMotion"), "motion watch:")
                wait_state(f"S.uav.camera.motion.enabled === {json.dumps(not on0)}", 10000); page.wait_for_timeout(400)
                R.check("MOTION button switches the watch on the UAV and shows it", "OK" in t and text("btnMotion") == f"MOTION: {'OFF' if on0 else 'ON'}",
                        f"{text('btnMotion')} · {t[:70]}")
                msg_after(page, lambda: page.click("#btnMotion"), "motion watch:")
                wait_state(f"S.uav.camera.motion.enabled === {json.dumps(on0)}", 10000)
                other = "high" if m0.get("sensitivity") != "high" else "low"
                t = msg_after(page, lambda: page.select_option("#motionSens", other), "motion sensitivity:")
                wait_state(f"S.uav.camera.motion.sensitivity === '{other}'", 10000)
                R.check("sensitivity chosen on the page reaches the UAV", "OK" in t, t[:90])
                msg_after(page, lambda: page.select_option("#motionSens", m0.get("sensitivity") or "medium"), "motion sensitivity:")
                for button, key, label in (("btnSentry", "sentry", "sentry:"), ("btnMotionPhoto", "photo", "photo on motion:")):
                    was = bool(m0.get(key))
                    t = msg_after(page, lambda: page.click("#" + button), label)
                    wait_state(f"S.uav.camera.motion.{key} === {json.dumps(not was)}", 10000); page.wait_for_timeout(400)
                    shown = page.evaluate(f"document.getElementById('{button}').classList.contains('on')")
                    R.check(f"{text(button).split(':')[0]} button arms and disarms on the UAV", "OK" in t and shown == (not was), f"{text(button)} · {t[:70]}")
                    msg_after(page, lambda: page.click("#" + button), label)
                    wait_state(f"S.uav.camera.motion.{key} === {json.dumps(was)}", 10000)
                # the page's own drawing code, given a region (nothing may be moving in front of the camera right now);
                # the feed is polled ten times a second and replaces it, so it is given again until a frame was drawn
                painted = page.evaluate("""async () => { let n = 0;
                    for (let i = 0; i < 12 && n < 100; i++) {
                      motionNow = {regions: [[0.3, 0.3, 0.2, 0.2, 0.8]], at: performance.now()};
                      await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
                      const c = document.getElementById('overlay'), d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data;
                      n = 0; for (let k = 0; k < d.length; k += 4) if (d[k] === 255 && d[k + 1] === 170 && d[k + 2] === 0 && d[k + 3] === 255) n++; }
                    return n; }""")
                R.check("a region the watch reports is drawn on the live picture (dashed, amber, tagged MOVING)", painted > 100, f"{painted} amber pixels")
                R.check("status line of the watch says what it is doing", len(text("motionStatus")) > 12, text("motionStatus")[:110])
            safe("motion watch", t_motion)

            # ---- photo
            def t_photo():
                n0 = S("(S.images || []).length ? S.images[0].name : null")
                t = msg_after(page, lambda: hot("capture_image"), "capture_image:", 40000)
                R.check("◘ PHOTO: command acknowledged", "OK" in t, t[:160])
                wait_state(f"(S.images || []).length && S.images[0].name !== {json.dumps(n0)}", 30000)
                img = S("S.images[0]")
                R.check("photo arrives, SHA-256 verified", img.get("integrity") == "PASS" and img.get("url"), f"{img.get('name')} {img.get('size')} B in {img.get('seconds')} s")
                tab(page, "media"); page.wait_for_timeout(1500)
                ok = page.evaluate("""async (u) => { const i = [...document.querySelectorAll('#imgSlots img')].find((x) => x.getAttribute('src') === u); if (!i) return 'no <img> for ' + u;
                    if (!i.complete) await new Promise((r) => { i.onload = i.onerror = r; setTimeout(r, 5000); }); return i.naturalWidth; }""", img.get("url"))
                R.check("the photo is shown in the MEDIA tab", isinstance(ok, int) and ok > 0, ok)
                tab(page, "mission")
            safe("◘ PHOTO", t_photo)

            # ---- recording
            def t_rec():
                t = msg_after(page, lambda: hot("start_rec"), "start_rec:")
                R.check("● REC: command acknowledged", "OK" in t, t[:160])
                wait_js(page,"document.getElementById('recOsd').classList.contains('show')", timeout=10000)
                t1 = page.evaluate("document.getElementById('recTime').textContent"); page.wait_for_timeout(3200)
                t2 = page.evaluate("document.getElementById('recTime').textContent")
                sub = page.evaluate("document.getElementById('recSub').textContent")
                R.check("camcorder REC indicator shown and its timer advances", t1 != t2 and page.evaluate("document.getElementById('pRec').classList.contains('show')"),
                        f"{t1} -> {t2} · {sub}")
                t = msg_after(page, lambda: hot("start_rec"), "start_rec:")
                R.check("second ● REC is refused with a clear message", "FAILED" in t and "already recording" in t, t[:160])
                page.wait_for_timeout(2500)
                t = msg_after(page, lambda: hot("stop_rec"), "stop_rec:")
                R.check("◼ SAVE: recording closed", "OK" in t and "frames" in t, t[:200])
                wait_js(page,"!document.getElementById('recOsd').classList.contains('show')", timeout=10000)
                t = msg_after(page, lambda: hot("stop_rec"), "stop_rec:")
                R.check("◼ SAVE with nothing recording answers cleanly", "stop_rec:" in t, t[:160])
            safe("● REC", t_rec)

            # ---- camera modes
            def t_modes():
                t = msg_after(page, lambda: page.click('.hotbar button[data-args*="NIGHT"]'), "set_mode:")
                wait_state("S.uav && S.uav.camera && S.uav.camera.mode === 'NIGHT'", 10000)
                R.check("☾ NIGHT mode", "OK" in t and "NIGHT" in page.evaluate("document.getElementById('vInfo').textContent"), t[:120])
                t = msg_after(page, lambda: page.click('.hotbar button[data-args*="NORMAL"]'), "set_mode:")
                wait_state("S.uav.camera.mode === 'NORMAL'", 10000)
                R.check("☼ DAY mode", "OK" in t, t[:120])
                t = msg_after(page, lambda: hot("focus"), "focus:", 30000)
                R.check("◎ FOCUS: sharpness measured", "OK" in t and "sharpness" in t, t[:160])
            safe("camera modes", t_modes)

            # ---- resolution change (the decoder must follow the new stream)
            def t_res():
                page.select_option("#res", "640x480")
                t = msg_after(page, lambda: page.click("#apply"), "set_video:", 30000)
                R.check("APPLY 640×480: acknowledged", "OK" in t, t[:140])
                try:
                    wait_js(page,"document.getElementById('video').naturalWidth === 640", timeout=20000)
                except Exception:
                    pass
                d = page.evaluate("[document.getElementById('video').naturalWidth, document.getElementById('video').naturalHeight]")
                R.check("the picture really is 640×480 after the change", d == [640, 480], f"{d[0]}x{d[1]}")
                page.select_option("#res", "1280x720")
                t = msg_after(page, lambda: page.click("#apply"), "set_video:", 30000)
                try:
                    wait_js(page,"document.getElementById('video').naturalWidth === 1280", timeout=20000)
                except Exception:
                    pass
                d = page.evaluate("[document.getElementById('video').naturalWidth, document.getElementById('video').naturalHeight]")
                R.check("back to 1280×720", "OK" in t and d == [1280, 720], f"{d[0]}x{d[1]} · {t[:100]}")
                wait_state("S.video && S.video.fps > 20", 20000)
            safe("resolution", t_res)

            # ---- detector controls
            def t_detector():
                t = msg_after(page, lambda: page.click("#hbDet"), "detector:")
                wait_state("S.detector && S.detector.enabled === false", 8000)
                R.check("◈ AI off: detector paused", "PAUSED" in page.evaluate("document.getElementById('pDet').textContent"), page.evaluate("document.getElementById('pDet').textContent"))
                msg_after(page, lambda: page.click("#hbDet"), "detector:")
                wait_state("S.detector.enabled === true", 8000)
                msg_after(page, lambda: page.click("#btnOverlay"), "")
                R.check("BOXES toggle", "OFF" in page.evaluate("document.getElementById('btnOverlay').textContent"), "")
                page.click("#btnOverlay")
                page.click("#btnAnn"); page.wait_for_timeout(6000)
                ann = page.evaluate("[document.getElementById('video').getAttribute('src'), document.getElementById('video').naturalWidth]")
                R.check("SERVER-DRAWN stream plays", "annotated" in ann[0] and ann[1] > 0, ann)
                page.click("#btnAnn"); page.wait_for_timeout(2500)
                back = page.evaluate("[document.getElementById('video').getAttribute('src'), document.getElementById('video').naturalWidth]")
                R.check("back to the normal stream", "annotated" not in back[0] and back[1] > 0, back)
                t = msg_after(page, lambda: page.select_option("#detProfile", "fast"), "detector:")
                wait_state("S.detector.profile === 'fast' && !S.detector.loading", 90000)
                wait_state("S.detector.fps > 0", 20000)
                R.check("profile FAST (YOLOv8n) loads and runs", True, S("({fps: S.detector.fps, ms: S.detector.infer_ms, classes: S.detector.vocab_size})"))
                page.fill("#vocab", "cup, bottle, person")
                t = msg_after(page, lambda: page.click("#vocabGo"), "detector:")
                wait_state("S.detector.profile === 'custom' && !S.detector.loading", 120000)
                R.check("FIND your own words (CUSTOM profile) loads", S("S.detector.vocab_size") == 3, S("({profile: S.detector.profile, classes: S.detector.vocab_size, error: S.detector.error})"))
                page.fill("#vocab", "")
                msg_after(page, lambda: page.select_option("#detProfile", "general"), "detector:")
                wait_state("S.detector.profile === 'general' && !S.detector.loading", 120000)
                wait_state("S.detector.fps > 0", 30000)
                R.check("back to GENERAL (120 everyday classes)", S("S.detector.vocab_size") >= 100, S("({fps: S.detector.fps, classes: S.detector.vocab_size, error: S.detector.error})"))
                page.fill("#conf", "0.3"); page.dispatch_event("#conf", "change"); page.wait_for_timeout(1500)
                R.check("confidence threshold applied", abs(S("S.detector.conf") - 0.3) < 1e-6, S("S.detector.conf"))
                page.fill("#conf", "0.25"); page.dispatch_event("#conf", "change")
            safe("detector controls", t_detector)

            # ---- finder
            def t_finder():
                on = S("S.detector.finder.enabled")
                if not on:
                    msg_after(page, lambda: page.click("#btnFinder"), "finder:"); wait_state("S.detector.finder.enabled", 8000)
                msg_after(page, lambda: page.click("#btnFinder"), "finder:")
                wait_state("!S.detector.finder.enabled", 8000)
                R.check("FINDER off", "off" in page.evaluate("document.getElementById('finderStatus').textContent"), page.evaluate("document.getElementById('finderStatus').textContent")[:120])
                page.fill("#finderWords", "pencil, screwdriver"); page.fill("#finderThr", "0.35"); page.select_option("#finderSpeed", "4")
                t = msg_after(page, lambda: page.click("#finderSet"), "finder:")
                wait_state("S.detector.finder.enabled && S.detector.finder.words.length === 2", 8000)
                p0 = S("S.detector.finder.passes")
                wait_state(f"S.detector.finder.passes > {p0} && !S.detector.finder.error", 60000)
                f = S("S.detector.finder")
                R.check("FINDER on, words set, passes running without error", f["enabled"] and not f["error"],
                        f"{f['backend']} words {f['words']} pass {f['passes']} {f['infer_ms']} ms best {f.get('best')}")
            safe("finder", t_finder)

            # ---- teach by example (visual prompt), then forget it again
            def t_teach():
                page.fill("#teachName", "uitest object")
                page.click("#btnTeach")
                wait_js(page,"document.getElementById('overlay').classList.contains('teaching')", timeout=5000)
                box = page.evaluate("(() => { const r = document.getElementById('overlay').getBoundingClientRect(); return [r.left, r.top, r.width, r.height]; })()")
                x0, y0 = box[0] + box[2] * 0.40, box[1] + box[3] * 0.35
                x1, y1 = box[0] + box[2] * 0.62, box[1] + box[3] * 0.70
                page.mouse.move(x0, y0); page.mouse.down(); page.mouse.move((x0 + x1) / 2, (y0 + y1) / 2, steps=5); page.mouse.move(x1, y1, steps=5)
                page.evaluate("document.getElementById('msg').textContent = ''; document.getElementById('msg')._t = ''")
                page.mouse.up()
                wait_js(page,"document.getElementById('msg').textContent.includes('teach uitest object:')", timeout=120000)
                t = page.evaluate("document.getElementById('msg').textContent")
                R.check("TEACH: one box on the frozen picture is learned", "OK" in t, t[:200])
                wait_state("S.detector.profile === 'accurate' && !S.detector.loading && (S.detector.taught || []).some((x) => x.name === 'uitest object')", 180000)
                wait_state("S.detector.fps > 0", 60000)
                d = S("({profile: S.detector.profile, taught: S.detector.taught, loaded: S.detector.taught_loaded, fps: S.detector.fps, classes: S.detector.vocab_size})")
                R.check("ACCURATE profile runs with the taught object as a class", "uitest object" in (d.get("loaded") or []), d)
                chip = page.evaluate("document.getElementById('taughtList').textContent")
                R.check("taught object listed as a chip", "uitest object" in chip, chip[:120])
                msg_after(page, lambda: page.click('#taughtList button[data-forget="uitest object"]'), "forget:", 60000)
                wait_state("!(S.detector.taught || []).some((x) => x.name === 'uitest object')", 60000)
                R.check("FORGET removes it again", True, S("S.detector.taught"))
                msg_after(page, lambda: page.select_option("#detProfile", "general"), "detector:")
                wait_state("S.detector.profile === 'general' && !S.detector.loading", 180000)
            if not a.no_teach:
                safe("teach", t_teach)

            # ---- security tab
            def t_security():
                tab(page, "security"); page.wait_for_timeout(1500)
                sid = S("S.link.session_id")
                t = msg_after(page, lambda: page.click("#btnCached"), "cached_rekey:")
                wait_state(f"S.link.session_id !== {json.dumps(sid)} && S.link.state === 'UP'", 15000)
                sid2 = S("S.link.session_id")
                R.check("1-RTT Cached RapidRekey button: new session, link stays up", "OK" in t and sid2 != sid, f"{sid} -> {sid2}")
                t = msg_after(page, lambda: page.click("#btnPq"), "pq_ratchet:")
                wait_state(f"S.link.session_id !== {json.dumps(sid2)} && S.link.state === 'UP'", 15000)
                R.check("PQ RATCHET button: new session, link stays up", "OK" in t, f"{sid2} -> {S('S.link.session_id')}")
                kv = page.evaluate("document.getElementById('secKv').innerText")
                R.check("SECURITY panel shows the session", "UP (SECURE)" in kv and "ML-KEM" in kv.upper().replace("MLKEM", "ML-KEM"), kv[:160].replace("\n", " | "))
                L = S("({hs: S.link.handshakes_ok, cached: S.link.cached_rekeys_ok, pq: S.link.pq_ratchets, rej: (S.link.record || {}).rejected})")
                R.info("link counters", L)
                tab(page, "mission")
            safe("security", t_security)

            # ---- telemetry tab
            def t_telemetry():
                tab(page, "telemetry"); page.wait_for_timeout(6500)
                rows = page.evaluate("document.querySelectorAll('#tbl tr').length")
                R.check("telemetry table filled", rows > 10, f"{rows} rows")
                page.click('#tbl th[data-k="sats_used"]'); page.wait_for_timeout(400)      # the pointer is now ON the table
                hdr = page.evaluate("document.querySelector('#tbl th[data-k=\"sats_used\"]').textContent")
                col = page.evaluate("[...document.querySelectorAll('#tbl tr')].slice(1, 40).map((r) => +r.children[7].textContent)")
                R.check("table sorts when a column header is clicked (also while the pointer is on it)",
                        ("▼" in hdr or "▲" in hdr) and col == sorted(col, reverse=True), f"header '{hdr}', first values {col[:6]}")
                page.click('#tbl th[data-k="ts"]')
                rng = page.evaluate("""async () => { const r = await fetch('/static/app.js', {headers: {Range: 'bytes=10-29'}}); return [r.status, r.headers.get('Content-Range'), (await r.text()).length]; }""")
                R.check("the server answers byte-range requests (needed to scrub recordings)", rng[0] == 206 and rng[2] == 20, rng)
                charts_ok = page.evaluate("['cAlt','cSats','cSnr','cCons'].map((id) => { const c = document.getElementById(id); return c.width > 50 && c.height > 50 && c.height < 700; })")
                R.check("the four telemetry charts are drawn at a fixed size", all(charts_ok), charts_ok)
                has_map = page.evaluate("!!document.querySelector('#map .leaflet-pane')")
                R.check("GIS map created", has_map, "")
                fix = S("S.telemetry && S.telemetry.lat != null")
                t = msg_after(page, lambda: page.click("#btnHome"), "set_home:")
                R.check("SET HOME = UAV FIX answers", ("OK" in t) if fix else ("FAILED" in t and "no GNSS fix" in t), t[:140])
                page.click("#btnFit"); page.wait_for_timeout(500)
                sky = page.evaluate("""() => { const c = document.getElementById('sky'), d = c.getContext('2d').getImageData(0, 0, c.width, c.height).data; let n = 0;
                    for (let k = 0; k < d.length; k += 400) if (d[k] > 60 || d[k + 1] > 60) n++; return n; }""")
                R.check("sky plot drawn", sky > 20, f"{sky} sampled bright pixels · {S('(S.telemetry && S.telemetry.satellites || []).length')} satellites")
                vox = page.evaluate("document.getElementById('voxel').width")
                vox_note = page.evaluate("document.getElementById('voxNote').textContent")
                R.check("3D density map canvas active", vox > 100, f"{vox} px wide · {vox_note[:80]}")
                tab(page, "mission")
            safe("telemetry", t_telemetry)

            # ---- media tab: files stored on the Pi
            def t_media():
                tab(page, "media"); page.wait_for_timeout(800)
                t = msg_after(page, lambda: page.click("#btnPhotos"), "list_photos:", 30000)
                n = page.evaluate("document.querySelectorAll('#photoList button').length")
                R.check("LIST photos stored on the Pi", "OK" in t and n > 0, f"{n} photos listed")
                if n:
                    n_img = S("(S.images || []).filter((i) => i.kind === 'photo_enc').length")
                    msg_after(page, lambda: page.click("#photoList button >> nth=0"), "fetch_photo:", 30000)
                    wait_state(f"(S.images || []).filter((i) => i.kind === 'photo_enc').length > {n_img} || (S.images[0] && S.images[0].kind === 'photo_enc')", 40000)
                    p = S("S.images.find((i) => i.kind === 'photo_enc')")
                    R.check("stored photo fetched from the Pi and decrypted on the ground station", p and p.get("decrypt") == "PASS" and p.get("integrity") == "PASS",
                            f"{p.get('name')} decrypt {p.get('decrypt')} in {p.get('decrypt_ms')} ms")
                t = msg_after(page, lambda: page.click("#btnList"), "list_recordings:", 30000)
                rows = page.evaluate("[...document.querySelectorAll('#recList tr')].map((r) => r.innerText.replace(/\\s+/g, ' ').trim())")
                R.check("LIST recordings stored on the Pi", "OK" in t and len(rows) > 0, f"{len(rows)} recordings")
                big = [r for r in rows if "TOO LARGE" in r.upper()]
                R.info("recordings too large for one transfer", big or "none")
                name = page.evaluate("""() => { const rows = [...document.querySelectorAll('#recList tr')].map((r) => ({b: r.querySelector('button'), mb: parseFloat((r.children[1] || {}).textContent)}))
                    .filter((x) => x.b && x.mb > 0.5).sort((p, q) => p.mb - q.mb); if (!rows.length) return null; rows[0].b.id = 'uitestFetch'; return rows[0].b.dataset.n; }""")
                if name:
                    n_rec = S("(S.recordings || []).length")
                    t = msg_after(page, lambda: page.click("#uitestFetch"), "fetch_recording:", 60000)
                    wait_state(f"(S.recordings || []).some((r) => r.name === {json.dumps(name)})", 90000)
                    r = S(f"S.recordings.find((r) => r.name === {json.dumps(name)})")
                    R.check("recording fetched, decrypted and playable (MP4)", r.get("decrypt") == "PASS" and r.get("mp4"), f"{name} {r.get('frames')} frames, decrypt {r.get('decrypt_ms')} ms")
                    page.wait_for_timeout(1500)
                    vid = page.evaluate("""async () => { const v = document.querySelector('#recRx video'); if (!v) return 'no <video>';
                        if (v.readyState < 1) await new Promise((r) => { v.onloadedmetadata = v.onerror = r; setTimeout(r, 8000); }); return [v.videoWidth, v.videoHeight, +v.duration.toFixed(1), v.error ? v.error.code : null]; }""")
                    R.check("the decrypted recording loads in the page's video player", isinstance(vid, list) and vid[0] > 0, vid)
                tab(page, "mission")
            safe("media", t_media)

            # ---- media tab: sealed audio. The Pi has no microphone: a file in its inbox stands in for one (a tone made
            # here as a real MP3). It is sealed on the Pi, fetched, verified, opened, an excerpt is cut, and the same
            # once more sent live while it is sealed.
            def t_audio():
                src = Path(tempfile.gettempdir()) / "k6g_uitest_tone.mp3"
                r = subprocess.run(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "lavfi", "-i", "sine=frequency=523:duration=5",
                                    "-c:a", "libmp3lame", "-b:a", "64k", "-ar", "44100", "-ac", "1", str(src)], capture_output=True)
                if r.returncode != 0 or not src.is_file():
                    R.info("sealed audio", "this ffmpeg cannot make an MP3 test tone: the audio controls were not pressed")
                    return
                want = hashlib.sha256(src.read_bytes()).hexdigest()
                kyber = str(Path(__file__).resolve().parents[2] / "run" / "kyber6g.sh")

                def put():
                    p = subprocess.run(["bash", kyber, "audio-put", str(src)], capture_output=True, text=True, timeout=90)
                    return p.returncode == 0, (p.stdout.strip().splitlines() or [p.stderr.strip()[:160]])[-1]
                ok, said = put()
                if not R.check("audio source copied to the Pi's inbox", ok, said):
                    return
                tab(page, "media"); page.wait_for_timeout(800)
                t = msg_after(page, lambda: page.click("#btnAudRec"), "record_audio (seal the source):", 60000)
                R.check("● SEAL SOURCE: the file in the inbox is sealed on the Pi, the plain file removed", "OK" in t and ".k6gaud" in t, t[:220])
                t = msg_after(page, lambda: page.click("#btnAudList"), "list_audio:", 30000)
                n = page.evaluate("document.querySelectorAll('#audList button').length")
                R.check("LIST sealed audio stored on the Pi", "OK" in t and n > 0, f"{n} clips listed")
                name = page.evaluate("(document.querySelector('#audList button') || {dataset: {}}).dataset.n || null")     # newest first
                if not name:
                    return
                msg_after(page, lambda: page.click("#audList button >> nth=0"), "fetch_audio:", 60000)
                clip = f"((S.audio || {{}}).clips || []).find((c) => c.name === {json.dumps(name)} && c.decrypt)"
                wait_state(clip, 60000)
                c = S(clip)
                R.check("clip fetched: the UAV's signature checked, opened on the ground station, byte for byte the source",
                        c.get("signature") == "PASS" and c.get("decrypt") == "PASS" and c.get("sha256") == want,
                        f"{name} signature {c.get('signature')} open {c.get('decrypt')} in {c.get('open_ms')} ms, {c.get('blocks')} blocks of {c.get('block_bytes')} B, chain: {c.get('chain')}")
                page.wait_for_timeout(1500)
                aud = page.evaluate("""async (u) => { const a = [...document.querySelectorAll('#audRx audio')].find((x) => x.getAttribute('src') === u); if (!a) return 'no <audio> for ' + u;
                    a.preload = 'metadata'; a.load(); if (a.readyState < 1) await new Promise((r) => { a.onloadedmetadata = a.onerror = r; setTimeout(r, 8000); });
                    return [+(a.duration || 0).toFixed(1), a.error ? a.error.code : null]; }""", c.get("url"))
                R.check("the opened clip loads in the page's audio player", isinstance(aud, list) and aud[0] > 0 and aud[1] is None, aud)
                set_range = page.evaluate("""(n) => { const b = [...document.querySelectorAll('#audRx button[data-ex]')].find((x) => x.dataset.ex === n); if (!b) return false;
                    const s = b.closest('.slot'); s.querySelector('input.t0').value = 1; s.querySelector('input.t1').value = 3; b.id = 'uitestExcerpt'; return true; }""", name)
                if set_range:
                    t = msg_after(page, lambda: page.click("#uitestExcerpt"), "audio_excerpt:", 30000)
                    ex = page.evaluate("document.getElementById('audEx').textContent").replace("\n", " ")
                    R.check("EXCERPT (seconds 1 to 3): a bundle that is checked with the UAV's public key only", "OK" in t and "PASS" in ex and "keys released" in ex,
                            " ".join(ex.split())[:240])
                else:
                    R.check("EXCERPT button of the fetched clip", False, "not found")
                # the same source once more, sent while it is sealed
                ok, said = put()
                if not R.check("audio source copied again for the live run", ok, said):
                    return
                t_live = time.time() - 1.0
                t = msg_after(page, lambda: page.click("#btnAudLive"), "record_audio (seal and send live):", 30000)
                R.check("● SEAL + SEND LIVE: started", "OK" in t and "tag" in t, t[:200])
                live = f"((S.audio || {{}}).clips || []).find((c) => c.how === 'live' && c.received_at >= {t_live} && c.decrypt)"
                wait_state(live, 60000)
                lv = S(live)
                R.check("live clip: completed and verified against the root the UAV signed", lv.get("signature") == "PASS" and lv.get("decrypt") == "PASS" and lv.get("sha256") == want,
                        f"{lv.get('name')}: {lv.get('live_blocks_on_air')} of {lv.get('blocks')} blocks from the air, {lv.get('live_blocks_repaired')} fetched again from the card; chain: {lv.get('chain')}")
                note = page.evaluate("document.getElementById('audLive').textContent")
                R.check("live status line reports the clip complete", "complete" in note, note[:200])
                page.wait_for_timeout(1500)
                pl = page.evaluate("""(() => { const p = document.getElementById('audLivePlayer');
                    return {src: p.getAttribute('src') || '', ready: p.readyState, t: +p.currentTime.toFixed(2), err: p.error ? p.error.code : null}; })()""")
                R.check("the live stream was opened by the page's player as it came in", "/audio_live?tag=" in pl["src"] and pl["err"] is None and (pl["ready"] >= 1 or pl["t"] > 0), pl)
                tab(page, "mission")
            safe("sealed audio", t_audio)

            # ---- data tab + exports
            def t_data():
                tab(page, "data"); page.wait_for_timeout(6500)
                kv = page.evaluate("document.getElementById('dbKv').innerText")
                R.check("DATABASE panel filled", "telemetry" in kv and "MB" in kv, kv[:120].replace("\n", " | "))
                ev = page.evaluate("document.querySelectorAll('#dbEvents div').length")
                R.check("stored events listed", ev > 5, f"{ev} events")
                sysk = page.evaluate("document.getElementById('sysKv').innerText")
                R.check("RASPBERRY PI panel filled", "CPU" in sysk and "°C" in sysk, sysk[:160].replace("\n", " | "))
                ex = page.evaluate("""async () => { const out = {}; for (const p of ['/api/export/telemetry.csv?minutes=5', '/api/export/telemetry.geojson?minutes=5', '/api/export/telemetry.kml?minutes=5',
                    '/api/export/satellites.csv?minutes=5', '/api/export/detections.csv?minutes=5', '/api/export/db']) { const r = await fetch(p); out[p.split('/').pop().split('?')[0]] = [r.status, (await r.arrayBuffer()).byteLength]; } return out; }""")
                R.check("all six exports download", all(v[0] == 200 and v[1] > 0 for v in ex.values()), ex)
                tab(page, "mission")
            safe("data", t_data)

            # ---- stop
            def t_stop():
                t = msg_after(page, lambda: hot("stop_live"), "stop_live:")
                R.check("■ STOP: command acknowledged", "OK" in t, t[:120])
                wait_js(page,"document.getElementById('nosig').style.display !== 'none'", timeout=10000)
                page.wait_for_timeout(4000)
                v = S("({fps: S.video.fps, kbps: S.video.kbps, ai: S.detector.fps, now: S.detector.objects_now})")
                R.check("after STOP: NO SIGNAL shown, rates read 0 (no stale '30 fps')", v["fps"] == 0 and v["ai"] == 0 and not v["now"], v)
                page.screenshot(path=str(shots / "mission_stopped.png"))
            safe("■ STOP", t_stop)
            safe("operator's settings put back (detector, finder, camera)", restore)

            errs = page.evaluate("__ui.errors")
            R.check("no JavaScript errors while every control was used", not errs, errs[:8])
            ctx.close()

        R.check("no failed requests to the ground station", not failed_req, failed_req[:6])
        http_err = [e for e in http_err if "/api/cmd" not in e]
        R.check("no HTTP errors from the ground station", not http_err, http_err[:6])
        browser.close()

    n_fail = sum(1 for r in R.results if r["ok"] is False)
    n_pass = sum(1 for r in R.results if r["ok"] is True)
    out = shots.parent / time.strftime("ui_test_%Y%m%d_%H%M%S.json")
    out.write_text(json.dumps({"ts": time.time(), "pass": n_pass, "fail": n_fail, "results": R.results}, indent=1))
    print(f"\n{n_pass} PASS, {n_fail} FAIL -> {out}   (screenshots: {shots})")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
