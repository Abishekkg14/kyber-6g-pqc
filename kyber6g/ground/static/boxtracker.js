/* Box smoothing + extrapolation for the live detection overlay (pure logic, no DOM; unit-tested under node).
 *
 * Detections describe the frame captured at `frameTs`; the browser is showing a newer frame (capture time
 * `viewT`). Each tracked object runs an alpha-beta filter on its four box coordinates (position + velocity),
 * the box is moved to where the object should be at `viewT`, and the drawn box eases toward that target.
 * So boxes stay attached to moving objects instead of trailing them, and a stationary object neither jitters
 * with detector noise nor drifts (velocities below `v0` are treated as zero). A track that stops being
 * detected is held briefly, faded, then dropped.
 * Coordinates are normalised (0..1) [x1, y1, x2, y2]; times are seconds.
 */
(function (root) {
  "use strict";
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const soft = (v, t) => (Math.abs(v) <= t ? 0 : v - Math.sign(v) * t);   // soft threshold: no velocity from noise

  class BoxTracker {
    constructor(o = {}) {
      // defaults tuned in tests/js/boxtracker_sim.js (`node boxtracker_sim.js grid`) against ~1 %-of-frame detector noise
      this.alpha = o.alpha ?? 0.5;            // position gain of the alpha-beta filter
      this.beta = o.beta ?? 0.5;              // velocity gain
      this.v0 = o.v0 ?? 0.06;                 // velocities below this (normalised units / s) are noise
      this.maxV = o.maxV ?? 1.0;              // velocity clamp
      this.tau = o.tau ?? 0.04;               // easing time constant of the drawn box (s)
      this.hold = o.hold ?? 1.2;              // drop a track this long after its last detection
      this.fade = o.fade ?? 0.6;              // ... fading over the last `fade` seconds
      this.freezeAfter = o.freezeAfter ?? 0.8; // stop extrapolating when the detections have gone quiet
      this.maxExtrap = o.maxExtrap ?? 0.6;    // never extrapolate further than this (s)
      this.tracks = new Map();
    }

    clear() { this.tracks.clear(); }

    /* dets: [{id, cls, conf, box, ts?}], frameTs: capture time of the analysed frame (a detection may carry its
     * own `ts` when it came from a slower model that analysed an older frame), now: wall time of arrival */
    ingest(dets, frameTs, now) {
      for (const det of dets) {
        const fts = det.ts ?? frameTs;
        let tr = this.tracks.get(det.id);
        if (!tr) {
          tr = {box: det.box.slice(), disp: det.box.slice(), vel: [0, 0, 0, 0], ts: fts, conf: det.conf};
          this.tracks.set(det.id, tr);
        } else {
          const dt = fts - tr.ts;
          if (dt === 0 && det.static) continue;       // the same slow pass delivered again: no new sighting, do not refresh it
          if (det.static) {                           // slow detector (seconds between passes): smooth, never extrapolate
            for (let k = 0; k < 4; k++) tr.box[k] += this.alpha * (det.box[k] - tr.box[k]);
          } else if (dt > 0.02 && dt < 1.5) {
            for (let k = 0; k < 4; k++) {
              const pred = tr.box[k] + tr.vel[k] * dt, r = det.box[k] - pred;
              tr.box[k] = pred + this.alpha * r;
              tr.vel[k] = clamp(tr.vel[k] + this.beta * r / dt, -this.maxV, this.maxV);
            }
          } else if (dt < -0.02) { tr.seenAt = now; continue; }                       // an older frame than the one we have: ignore
          else { tr.box = det.box.slice(); tr.vel = [0, 0, 0, 0]; }
          tr.ts = fts; tr.conf = 0.6 * tr.conf + 0.4 * det.conf;
        }
        tr.cls = det.cls; tr.id = det.id; tr.seenAt = now;
        tr.hold = det.hold ?? this.hold;              // a slow detector keeps its boxes alive for longer than the real-time one
      }
    }

    /* advance the drawn boxes; viewT: capture time of the frame being displayed (same clock as frameTs) */
    step(viewT, now, dt) {
      const out = [], a = 1 - Math.exp(-Math.min(dt, 0.1) / this.tau);
      for (const [key, tr] of this.tracks) {
        const age = now - tr.seenAt, hold = tr.hold ?? this.hold;
        if (age > hold) { this.tracks.delete(key); continue; }
        const ex = age > this.freezeAfter ? 0 : clamp(viewT - tr.ts, 0, this.maxExtrap);
        for (let k = 0; k < 4; k++) tr.disp[k] += (tr.box[k] + soft(tr.vel[k], this.v0) * ex - tr.disp[k]) * a;
        out.push({id: tr.id, cls: tr.cls, conf: tr.conf, box: tr.disp.slice(),
                  alpha: age < hold - this.fade ? 1 : (hold - age) / this.fade});
      }
      return out;
    }
  }

  if (typeof module !== "undefined" && module.exports) module.exports = {BoxTracker}; else root.BoxTracker = BoxTracker;
})(typeof window !== "undefined" ? window : globalThis);
