// Simulates the live overlay: a detector delivering noisy boxes at ~5 fps, 0.4 s after the frame they describe,
// while the browser shows a frame captured `lag` seconds before "now". Compares the BoxTracker against drawing
// the last detection as-is. Prints JSON; exit code 1 if the tracker does not clearly beat the naive overlay.
const {BoxTracker} = require("../../kyber6g/ground/static/boxtracker.js");

let seed = 12345;
const rnd = () => ((seed = (seed * 1664525 + 1013904223) >>> 0) / 4294967296);
const gauss = () => Math.sqrt(-2 * Math.log(rnd() + 1e-12)) * Math.cos(2 * Math.PI * rnd());

// sigma: detector box noise per coordinate (normalised); YOLO boxes on a live camera wobble by about 1% of the frame
function run(truth, {fps = 5, latency = 0.4, lag = 0.19, sigma = 0.012, dur = 24, tracker = {}} = {}) {
  seed = 12345;                                        // same noise for every variant
  const tr = new BoxTracker(tracker), dtD = 1 / 60;
  const pending = [];                                  // detections in flight: {arrive, frameTs, box}
  let nextDet = 0, naive = null, errT = [], errN = [], jitT = [], jitN = [], prevT = null, prevN = null;
  for (let t = 0; t < dur; t += dtD) {
    while (nextDet <= t) {                             // detector finishes a frame captured at nextDet
      const b = truth(nextDet).map((v) => v + sigma * gauss());
      pending.push({arrive: nextDet + latency, frameTs: nextDet, box: b});
      nextDet += 1 / fps + (rnd() - 0.5) * 0.06;
    }
    while (pending.length && pending[0].arrive <= t) {
      const d = pending.shift();
      tr.ingest([{id: 1, cls: "x", conf: 0.8, box: d.box}], d.frameTs, t);
      naive = d.box;
    }
    const out = tr.step(t - lag, t, dtD);
    if (t < 3 || !out.length || !naive) continue;
    const want = truth(t - lag), cx = (b) => (b[0] + b[2]) / 2;
    errT.push(Math.abs(cx(out[0].box) - cx(want)) * 1280); errN.push(Math.abs(cx(naive) - cx(want)) * 1280);
    if (prevT) { jitT.push(Math.abs(cx(out[0].box) - prevT) * 1280); jitN.push(Math.abs(cx(naive) - prevN) * 1280); }
    prevT = cx(out[0].box); prevN = cx(naive);
  }
  const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;
  return {errorPx: {tracker: +mean(errT).toFixed(1), naive: +mean(errN).toFixed(1)},
          frameToFrameMovePx: {tracker: +mean(jitT).toFixed(3), naive: +mean(jitN).toFixed(3)}};
}

// continuous trajectories (no teleporting): a hand-held object swaying, and one swung fast across the frame
const moving = (t) => { const x = 0.45 + 0.2 * Math.sin(0.6 * t) + 0.03 * Math.sin(1.3 * t); return [x, 0.3, x + 0.12, 0.6]; };
const still = () => [0.4, 0.3, 0.52, 0.6];
const fast = (t) => { const x = 0.45 + 0.33 * Math.sin(1.5 * t); return [x, 0.3, x + 0.1, 0.55]; };      // peak ~0.5 widths/s
if (process.argv[2] === "grid") {                    // parameter search, prints a table
  const rows = [];
  for (const alpha of [0.4, 0.5, 0.7]) for (const beta of [0.2, 0.35, 0.5, 0.8]) for (const v0 of [0.03, 0.06, 0.09]) for (const tau of [0.04, 0.08]) {
    const o = {tracker: {alpha, beta, v0, tau}};
    const m = run(moving, o), s = run(still, o), f = run(fast, o), sl = run(moving, {...o, fps: 2, latency: 0.7});
    rows.push({alpha, beta, v0, tau, mov: m.errorPx.tracker, fast: f.errorPx.tracker, slow: sl.errorPx.tracker, stillErr: s.errorPx.tracker,
               stillJit: s.frameToFrameMovePx.tracker, score: m.errorPx.tracker + f.errorPx.tracker * 0.5 + sl.errorPx.tracker * 0.5 + s.errorPx.tracker * 3 + s.frameToFrameMovePx.tracker * 40});
  }
  rows.sort((a, b) => a.score - b.score);
  console.table(rows.slice(0, 8));
  process.exit(0);
}
const res = {moving: run(moving), stationary: run(still), fastCrossing: run(fast), slowDetector2fps: run(moving, {fps: 2, latency: 0.7})};
console.log(JSON.stringify(res));
const ok = res.moving.errorPx.tracker < 0.8 * res.moving.errorPx.naive &&               // sticks to a moving object
  res.fastCrossing.errorPx.tracker < 0.8 * res.fastCrossing.errorPx.naive &&            // ... and to a fast one
  res.slowDetector2fps.errorPx.tracker < 1.05 * res.slowDetector2fps.errorPx.naive &&   // never clearly worse with a slow detector
  res.stationary.errorPx.tracker <= res.stationary.errorPx.naive &&                     // a still object stays put
  res.stationary.frameToFrameMovePx.tracker < 0.7 * res.stationary.frameToFrameMovePx.naive;   // ... and does not jitter
process.exit(ok ? 0 : 1);
