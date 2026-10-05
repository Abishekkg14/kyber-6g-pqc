/* Kyber-6G ground station dashboard (Minecraft-style GUI). All server text is escaped before insertion.
 *
 * Layout stability rules (the dashboard used to "scroll like a glitch"):
 *   - DOM is only rewritten when the generated HTML actually changed (setHTML), so images are not re-created
 *     every second (a re-created <img> has height 0 until decoded, which shifted the whole page);
 *   - every thumbnail has a fixed aspect ratio and every list a fixed height, so content can never push the page;
 *   - logs auto-scroll only while the reader is at the bottom;
 *   - the data table is frozen while the mouse is over it or it is scrolled away from the newest row.
 */
"use strict";
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "—").replace(/[&<>"']/g, (c) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}[c]));
/* a number with d decimals; anything that is not a number is escaped like every other text from the server */
const f = (v, d = 1, u = "") => (v == null || Number.isNaN(v) ? "—" : (typeof v === "number" ? v.toFixed(d) : esc(v)) + u);
const tstr = (t) => (t ? new Date(t * 1000).toLocaleTimeString() : "—");
const hms = (s) => { s = Math.max(0, Math.floor(s || 0)); return [s / 3600, (s % 3600) / 60, s % 60].map((x) => String(Math.floor(x)).padStart(2, "0")).join(":"); };
function setHTML(id, html) { const el = $(id); if (el && el._h !== html) { el._h = html; el.innerHTML = html; } }
function setText(id, text) { const el = $(id); if (el && el._t !== text) { el._t = text; el.textContent = text; } }
/* a status line with a fixed height (CSS .l1/.l2/.l3): the full text is always available as the tooltip */
function setNote(id, text) { const el = $(id); if (el && el._t !== text) { el._t = text; el.textContent = text; el.title = text; } }
/* fetch that gives up: a ground station that accepts the connection but never answers (suspended laptop, stuck
 * process) would otherwise leave the polling loops waiting forever, and the page would look alive but be frozen */
async function fetchJSON(url, ms, opts = {}) {
  const c = new AbortController(), timer = setTimeout(() => c.abort(), ms);
  try {
    const r = await fetch(url, {...opts, signal: c.signal});
    if (r.status >= 500) throw new Error("HTTP " + r.status);
    return await r.json();                          // the timeout also covers reading the body
  } finally { clearTimeout(timer); }
}
/* one failing section must not blank the rest of the page */
function safe(name, fn) { try { fn(); } catch (e) { if (safe.last !== name + e) { safe.last = name + e; console.error("render " + name, e); } } }
function setLog(id, html) {
  const el = $(id); if (!el) return;
  const atBottom = el._seen === undefined || el.scrollHeight - el.scrollTop - el.clientHeight < 40;
  if (el._h !== html) { el._h = html; el.innerHTML = html; if (atBottom) el.scrollTop = el.scrollHeight; }
  el._seen = true;
}
let S = null, tab = "mission";

/* ---------- procedural pixel textures (16x16 blocks, no downloads) ---------- */
function tex(palette, seed, topRows) {
  const c = document.createElement("canvas"); c.width = c.height = 16;
  const g = c.getContext("2d"); let s = seed;
  const rnd = () => ((s = (s * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff);
  for (let y = 0; y < 16; y++) for (let x = 0; x < 16; x++) {
    const pal = topRows && y < topRows.rows + Math.floor(rnd() * 2) ? topRows.palette : palette;
    g.fillStyle = pal[Math.floor(rnd() * pal.length)]; g.fillRect(x, y, 1, 1);
  }
  return `url(${c.toDataURL()})`;
}
const root = document.documentElement.style;
root.setProperty("--dirt", tex(["#79553a", "#6b4a31", "#8c6142", "#5e4029", "#966c4a"], 7));
root.setProperty("--stone", tex(["#7a7a7a", "#6f6f6f", "#858585", "#686868", "#8f8f8f"], 3));
root.setProperty("--grass", tex(["#79553a", "#6b4a31", "#8c6142"], 11, {rows: 4, palette: ["#5d9a2f", "#6aad35", "#4f8a27", "#77b83f"]}));
root.setProperty("--deep", tex(["#2a2a2e", "#26262a", "#303035", "#232327", "#2d2d31"], 5));

/* ---------- tabs ---------- */
document.querySelectorAll("nav button").forEach((b) => (b.onclick = () => {
  document.querySelectorAll("nav button").forEach((x) => x.classList.toggle("active", x === b));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === "v-" + b.dataset.tab));
  tab = b.dataset.tab;
  if (tab !== "mission") cancelTeach();
  // only a VISIBLE map may be re-measured: on a hidden (0 x 0) one the heat layer throws ("source width is 0")
  setTimeout(() => {
    if (map && $("map").offsetParent !== null) map.invalidateSize();
    if (mini && $("minimap").offsetParent !== null) mini.invalidateSize();
    refreshSlow(); window.dispatchEvent(new Event("k6g-tab"));
  }, 50);
}));

/* ---------- commands ---------- */
async function cmd(c, args = {}, label = c) {
  setNote("msg", `> ${label} …`);
  try {
    const r = await fetchJSON("/api/cmd", 150000, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({cmd: c, args})});
    setNote("msg", `> ${label}: ${r.ok ? "OK" : "FAILED"} ${r.error || ""} ${r.result ? JSON.stringify(r.result).slice(0, 220) : ""}`);
    $("msg").className = "l2 " + (r.ok ? "" : "bad");
    return r;
  } catch (e) { setNote("msg", `> ${label}: ground station not reachable (${e})`); $("msg").className = "l2 bad"; }
}
/* a button stays disabled until its command is answered: a double click must not send the command twice */
async function press(b, c, args, label) {
  if (b.disabled) return;
  b.disabled = true;
  try { return await cmd(c, args, label); } finally { b.disabled = false; }
}
document.querySelectorAll("button[data-cmd]").forEach((b) => (b.onclick = () => press(b, b.dataset.cmd, b.dataset.args ? JSON.parse(b.dataset.args) : {})));
$("apply").onclick = () => { const [w, h] = $("res").value.split("x").map(Number); press($("apply"), "set_video", {width: w, height: h, fps: +$("fps").value, bitrate: +$("br").value}); };
$("btnCached").onclick = () => press($("btnCached"), "cached_rekey");
$("btnPq").onclick = () => press($("btnPq"), "pq_ratchet");
$("btnHome").onclick = () => press($("btnHome"), "set_home");
let picking = false;
$("btnPick").onclick = () => { picking = !picking; $("btnPick").classList.toggle("on", picking);
  $("btnPick").textContent = picking ? "CLICK THE MAP…" : "PICK REFERENCE ON MAP"; };
$("conf").onchange = () => cmd("detector", {conf: +$("conf").value});
$("hbDet").onclick = () => cmd("detector", {enabled: !(S && S.detector && S.detector.enabled)});
/* ---------- media library ----------
 * The page's state carries the newest 16 photos and 10 recordings. Two things were missing (an operator's recordings
 * "were not displayed": they were on the Pi's card, and nothing on the page said so until LIST ON UAV was pressed):
 *   - the list of what is on the Pi's card is now asked for by the page itself: when MEDIA is opened, when a recording
 *     has been saved, and every half minute while MEDIA is open. Newest first, with what is already here marked;
 *   - SHOW ALL: every photo and every decrypted recording the ground station holds (/api/media), newest first. */
const media = {uavRecs: null, recsAt: 0, all: null, allAt: 0, allImg: false, allRec: false, wasRecording: false, newest: null};
const REC_ROWS = 8;                                          // rows of the card's list until SHOW ALL is pressed
async function ask(c, args = {}) {                           // a command that leaves the message line alone
  try { return await fetchJSON("/api/cmd", 60000, {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({cmd: c, args})}); }
  catch (e) { return null; }
}
function drawRecList() {
  if (!media.uavRecs) return;
  const active = ((S && S.uav && S.uav.camera) || {}).recording_name;
  const limit = Number((((S && S.uav) || {}).storage || {}).transfer_limit_mb) || 256;
  const here = new Set([...((S && S.recordings) || []), ...((media.all && media.all.recordings) || [])].filter((r) => r.mp4).map((r) => r.name));
  const all = media.uavRecs.slice().sort((p, q) => q.mtime - p.mtime), rows = media.allRec ? all : all.slice(0, REC_ROWS);
  // a file over the limit of one transfer cannot be fetched over the link (the Pi would have to hold it in RAM)
  setHTML("recList", `<tr><th>file on the Pi</th><th>size</th><th>saved</th><th></th></tr>` + (rows.map((x) => `<tr><td>${esc(x.name)}</td><td>${(x.bytes / 1e6).toFixed(2)} MB</td><td>${tstr(x.mtime)}</td>
    <td>${x.name === active ? `<span class="bad">● RECORDING</span>` : x.fetchable === false || x.bytes > limit * 1048576 ?
      `<span class="toolarge" title="Over the ${limit} MB limit of one transfer. Copy and decrypt it with:  bash run/kyber6g.sh pull ${esc(x.name)}">TOO LARGE — run: kyber6g.sh pull</span>` :
      `<button data-n="${esc(x.name)}">${here.has(x.name) ? "FETCH AGAIN" : "FETCH &amp; DECRYPT"}</button>${here.has(x.name) ? ` <span class="ok">here ✔</span>` : ` <span class="dim">on the Pi only</span>`}`}</td></tr>`).join("")
    || `<tr><td colspan="4" class="dim">no recordings on the Pi yet — press ● REC</td></tr>`)
    + (all.length > rows.length ? `<tr><td colspan="4" class="dim">… and ${all.length - rows.length} older on the Pi — SHOW ALL</td></tr>` : ""));
  $("recList").querySelectorAll("button").forEach((b) => (b.onclick = () => press(b, "fetch_recording", {name: b.dataset.n})));
  const notHere = all.filter((x) => !here.has(x.name)).length;
  setText("recInfo", `${all.length} on the Pi · ${notHere} not fetched`);
}
async function loadAllMedia() {
  try { media.all = await fetchJSON("/api/media", 15000); media.allAt = performance.now(); } catch (e) { /* the latest stay on show */ }
  if (S) render(S);
  drawRecList();
}
/* what is on the Pi's card, and (to mark what of it is here already) everything the ground station holds */
async function listRecordings(quiet) {
  const [r] = await Promise.all([quiet ? ask("list_recordings") : press($("btnList"), "list_recordings"),
    !media.all || performance.now() - media.allAt > 20000 ? loadAllMedia() : null]);
  if (!r || !r.ok) return;
  media.uavRecs = r.result || []; media.recsAt = performance.now();
  drawRecList();
}
$("btnList").onclick = () => listRecordings(false);
function toggleAll(which, btn) {
  media[which] = !media[which];
  btn.textContent = media[which] ? "SHOW LATEST" : "SHOW ALL";
  btn.classList.toggle("on", media[which]);
  if (media[which]) loadAllMedia(); else { if (S) render(S); drawRecList(); }
}
$("btnImgAll").onclick = () => toggleAll("allImg", $("btnImgAll"));
$("btnRecAll").onclick = () => toggleAll("allRec", $("btnRecAll"));
/* called with every state: keeps the two lists current without a button */
function mediaTick(s) {
  const cam = (s.uav && s.uav.camera) || {}, up = s.link && s.link.state === "UP";
  const saved = media.wasRecording && !cam.recording;        // a recording has just been saved on the Pi
  media.wasRecording = !!cam.recording;
  const newest = ((s.recordings || [])[0] || {}).name + "|" + ((s.images || [])[0] || {}).name;
  const arrived = media.newest !== null && newest !== media.newest;      // something new was received here
  media.newest = newest;
  if (up && (saved || (tab === "media" && performance.now() - media.recsAt > 30000))) { media.recsAt = performance.now(); listRecordings(true); }
  // something arrived: the library is read again (it marks the rows of the card's list, and SHOW ALL shows it)
  if (media.all && (arrived || ((media.allImg || media.allRec) && tab === "media" && performance.now() - media.allAt > 60000))) { media.allAt = performance.now(); loadAllMedia(); }
}
window.addEventListener("k6g-tab", () => { if (tab === "media" && S && S.link && S.link.state === "UP") listRecordings(true); });
$("btnPhotos").onclick = async () => {
  const r = await press($("btnPhotos"), "list_photos"); if (!r || !r.ok) return;
  const res = r.result || {};
  $("photoList").innerHTML = `<tr><th>file on the Pi</th><th>size</th><th>captured</th><th>image</th><th></th></tr>` +
    ((res.photos || []).slice().reverse().map((x) => `<tr><td>${esc(x.name)}</td><td>${(x.bytes / 1024).toFixed(0)} KB</td><td>${tstr(x.mtime)}</td>
    <td>${esc(x.width)}×${esc(x.height)} ${esc(x.mode)}</td><td><button data-n="${esc(x.name)}">FETCH &amp; DECRYPT</button></td></tr>`).join("") ||
    `<tr><td colspan="5" class="dim">no photos stored yet — press ◘ PHOTO</td></tr>`);
  $("photoList").querySelectorAll("button").forEach((b) => (b.onclick = () => press(b, "fetch_photo", {name: b.dataset.n})));
};
/* ---------- sealed audio ---------- */
$("btnAudList").onclick = async () => {
  const r = await press($("btnAudList"), "list_audio"); if (!r || !r.ok) return;
  const res = r.result || {};
  $("audList").innerHTML = `<tr><th>clip on the Pi</th><th>size</th><th>sealed</th><th>block</th><th></th></tr>` +
    ((res.clips || []).slice().reverse().map((x) => `<tr><td>${esc(x.name)}</td><td>${f((x.bytes || 0) / 1024, 0, " KB")}</td><td>${tstr(x.mtime)}</td>
    <td>${esc(x.block_bytes)} B</td><td><button data-n="${esc(x.name)}">FETCH, VERIFY &amp; OPEN</button></td></tr>`).join("") ||
    `<tr><td colspan="5" class="dim">no clips on the Pi yet — press ● SEAL SOURCE</td></tr>`) +
    (res.sources || []).map((x) => `<tr><td class="dim">waiting in the inbox: ${esc(x.name)}</td><td>${f((x.bytes || 0) / 1024, 0, " KB")}</td><td colspan="3" class="dim">not sealed yet</td></tr>`).join("");
  $("audList").querySelectorAll("button").forEach((b) => (b.onclick = () => press(b, "fetch_audio", {name: b.dataset.n})));
};
$("btnAudRec").onclick = () => press($("btnAudRec"), "record_audio", {}, "record_audio (seal the source)");
$("btnAudLive").onclick = async () => {
  const r = await press($("btnAudLive"), "record_audio", {live: true}, "record_audio (seal and send live)");
  if (r && r.ok && r.result && r.result.tag) {            // listen to the blocks as they are opened
    const p = $("audLivePlayer"); p.src = "/audio_live?tag=" + encodeURIComponent(r.result.tag) + "&t=" + Date.now(); p.play().catch(() => {});
  }
};
$("audRx").addEventListener("click", async (ev) => {
  const b = ev.target.closest("button[data-ex]"); if (!b) return;
  const box = b.closest(".slot"), t0 = +box.querySelector("input.t0").value, t1 = +box.querySelector("input.t1").value;
  const r = await press(b, "audio_excerpt", {name: b.dataset.ex, t0, t1}, "audio_excerpt");
  if (r && r.ok) {
    const x = r.result;
    setHTML("audEx", `excerpt of ${esc(x.clip)}: blocks ${esc(x.blocks[0])}–${esc(x.blocks[1])} of ${esc(x.blocks_in_clip)} · ${f(x.duration_s, 1, " s")} · ${esc(x.keys_released)} keys released ·
      checked with the UAV's public key only: <b class="${x.verified_with_public_key_only === "PASS" ? "ok" : "bad"}">${esc(x.verified_with_public_key_only)}</b> ·
      <a href="${esc(x.bundle)}">bundle (${f(x.bundle_bytes / 1024, 0, " KB")})</a> · <a href="${esc(x.audio)}" target="_blank">listen</a>`);
  }
});

/* ---------- motion watch (runs on the UAV; its reports arrive as text in the status stream) ---------- */
const motionSet = () => (((S && S.uav && S.uav.camera) || {}).motion || {});
$("btnMotion").onclick = () => press($("btnMotion"), "motion", {enabled: !motionSet().enabled}, "motion watch");
$("btnMotionPhoto").onclick = () => press($("btnMotionPhoto"), "motion", {photo: !motionSet().photo}, "photo on motion");
$("btnSentry").onclick = () => press($("btnSentry"), "motion", {sentry: !motionSet().sentry}, "sentry");
$("motionSens").onchange = () => cmd("motion", {sensitivity: $("motionSens").value}, "motion sensitivity");
function renderMotion(m, g) {
  const now = (g || {}).now, off = m.available === false || m.available == null;
  for (const [id, label, on] of [["btnMotion", "MOTION", m.enabled], ["btnMotionPhoto", "PHOTO ON MOTION", m.photo], ["btnSentry", "SENTRY", m.sentry]]) {
    setText(id, `${label}: ${off ? "—" : on ? "ON" : "OFF"}`); $(id).classList.toggle("on", !off && !!on);
  }
  if (document.activeElement !== $("motionSens") && m.sensitivity) $("motionSens").value = m.sensitivity;
  const moving = !!(now && now.on && now.regions && now.regions.length);
  $("motionOsd").classList.toggle("show", moving && !noSignal);
  setNote("motionStatus", m.available == null ? "motion watch: no status from the UAV yet" :
    m.available === false ? `motion watch not available: ${m.error || "switched off in the UAV's settings"}` :
    !m.enabled ? "motion watch off" :
    !m.watching ? "motion watch waits for the camera — press ▶ LIVE, or SENTRY to watch without sending video" :
    m.error ? `motion watch ERROR: ${m.error}` :
    now && now.scene ? "the whole picture changed (light, or the camera was moved)" :
    moving ? `MOVEMENT in ${now.regions.length} place${now.regions.length > 1 ? "s" : ""}${now.cam ? " · the camera is moving" : ""}${now.since ? " · since " + tstr(now.since) : ""}` :
    `watching${m.sentry && !m.live ? " (sentry)" : ""} · ${m.events ?? 0} movement${m.events === 1 ? "" : "s"} seen · ${f(m.hz_measured ?? m.hz, 1)} looks/s · ${f(m.ms, 1)} ms each on the Pi`);
  $("motionStatus").className = "note l1 " + (m.available === false || m.error ? "bad" : moving ? "warn" : "");
}

/* ---------- detector controls ---------- */
$("detProfile").onchange = () => cmd("detector", {profile: $("detProfile").value});
$("detSize").onchange = () => cmd("detector", {imgsz: +$("detSize").value});
$("detEnh").onclick = () => cmd("detector", {enhance: !(S && S.detector && S.detector.enhance)});
$("vocabGo").onclick = () => { const v = $("vocab").value.trim(); if (v) cmd("detector", {vocab: v}); };
$("vocab").onkeydown = (e) => { if (e.key === "Enter") $("vocabGo").onclick(); };
$("taughtList").onclick = (e) => {
  const b = e.target.closest("button[data-forget]"); if (!b) return;
  cmd("detector", {forget: b.dataset.forget === "*" ? "" : b.dataset.forget}, "forget");
};
$("btnFinder").onclick = () => cmd("finder", {enabled: !(S && S.detector && S.detector.finder && S.detector.finder.enabled)}, "finder");
$("finderSet").onclick = async () => {
  const v = $("finderWords").value.trim(), thr = parseFloat($("finderThr").value);
  if (v) { await cmd("finder", {words: v, enabled: true, period: +$("finderSpeed").value, ...(thr >= 0.12 ? {threshold: thr} : {})}, "finder"); $("finderWords")._edited = false; $("finderThr")._edited = false; }
};
$("finderSpeed").onchange = () => cmd("finder", {period: +$("finderSpeed").value}, "finder speed");
$("finderThr").oninput = () => ($("finderThr")._edited = true);
$("finderWords").onkeydown = (e) => { if (e.key === "Enter") $("finderSet").onclick(); };
function renderFinder(f) {
  if (!f) return;
  setText("btnFinder", `FINDER: ${f.enabled ? "ON" : "OFF"}`); $("btnFinder").classList.toggle("on", !!f.enabled);
  if (document.activeElement !== $("finderWords") && !$("finderWords")._edited) $("finderWords").value = (f.words || []).join(", ");
  if (document.activeElement !== $("finderThr") && !$("finderThr")._edited && f.threshold != null) $("finderThr").value = f.threshold.toFixed(2);
  if (document.activeElement !== $("finderSpeed") && f.period != null) {
    const v = [10, 4, 0].reduce((a, b) => (Math.abs(b - f.period) < Math.abs(a - f.period) ? b : a)); $("finderSpeed").value = String(v);
  }
  const shown = (f.shown || []).map((x) => `${x.cls} ${(x.conf * 100).toFixed(0)}%`).join(", ");
  const weak = (f.weak || []).slice(0, 3).map((x) => `${x.cls} ${(x.conf * 100).toFixed(0)}%`).join(", ");
  const words = (f.words || []).join(", ") || "—";
  setNote("finderStatus", !f.enabled ? "finder off — only the real-time detector is running" :
    f.loading ? `finder loading ${f.model}… (first start downloads/loads the model)` :
    f.error ? `finder ERROR: ${f.error}` :
    f.looking === false ? `${f.backend} · ready to look for ${words} · waiting for live video (press ▶ LIVE)` :
    `${f.backend} · looking for ${words} · pass ${f.passes} · ${f.infer_ms != null ? (f.infer_ms / 1000).toFixed(1) + " s" : "—"} each` +
    (shown ? ` · FOUND ${shown}` : weak ? ` · weak signal: ${weak} (below ${(f.threshold * 100).toFixed(0)}%)` : " · nothing yet"));
  $("finderStatus").className = "note l2 " + (f.error ? "bad" : shown ? "ok" : weak ? "warn" : "");
}
$("finderWords").oninput = () => ($("finderWords")._edited = true);
function renderDetControls(det) {
  renderFinder(det.finder);
  const sel = $("detProfile");
  if (det.profiles && sel.options.length !== Object.keys(det.profiles).length)
    sel.innerHTML = Object.entries(det.profiles).map(([k, l]) => `<option value="${esc(k)}">${esc(l)}</option>`).join("");
  if (document.activeElement !== sel && det.profile) sel.value = det.loading || det.profile;
  if (det.imgsz && ![...$("detSize").options].some((o) => o.value === String(det.imgsz))) {      // e.g. ACCURATE runs at 512
    $("detSize").add(new Option(`${det.imgsz} px`, String(det.imgsz)));
    [...$("detSize").options].sort((a, b) => a.value - b.value).forEach((o) => $("detSize").add(o));
  }
  if (document.activeElement !== $("detSize") && det.imgsz) $("detSize").value = String(det.imgsz);
  if (document.activeElement !== $("conf") && det.conf != null) $("conf").value = det.conf;
  setText("detEnh", `LOW-LIGHT: ${det.enhance ? "ON" : "OFF"}`); $("detEnh").classList.toggle("on", !!det.enhance);
  if (document.activeElement !== $("vocab") && !$("vocab").value && det.custom_vocab) $("vocab").placeholder = `find anything: ${det.custom_vocab.join(", ")}`;
  const tg = det.taught || [];
  setHTML("taughtList", tg.length ? tg.map((x) => `<span class="chip">${esc(x.name)} ×${x.examples}<button data-forget="${esc(x.name)}" title="forget">✕</button></span>`).join("") +
    (tg.length > 1 ? `<span class="chip"><button data-forget="*">FORGET ALL</button></span>` : "") : `<span class="dim note" style="margin:0">nothing taught yet</span>`);
  const lt = det.last_teach;
  const st = det.loading ? `loading ${det.loading}…` : det.notice ? det.notice : det.error ? `ERROR: ${det.error}` :
    det.worker_alive === false ? "ERROR: the detector worker has stopped — restart the ground station" :
    lt && Date.now() / 1000 - lt.ts < 20 ? (lt.error ? `teach failed: ${lt.error}` : `${lt.kind === "teach" ? "learned" : "forgot"} ${lt.name || "all"}`) : "";
  setNote("detStatus", st); $("detStatus").className = "note l1 " + (det.error || det.worker_alive === false || (lt && lt.error) ? "bad" : "");
}

/* ---------- camcorder REC indicator (ticks locally between 1 s status updates) ---------- */
function recTick() {
  const u = (S && S.uav) || {}, cam = u.camera || {};
  const on = !!cam.recording && S && S.link && S.link.state === "UP";
  const el = on ? (cam.recording_elapsed_s || 0) + Math.max(0, S.now - (u.rx_at || S.now)) + (Date.now() / 1000 - (S.fetched || Date.now() / 1000)) : 0;
  $("recOsd").classList.toggle("show", on);
  $("pRec").classList.toggle("show", on);
  if (on) {
    setText("recTime", hms(el));
    setHTML("pRec", `<i>●</i> REC ${hms(el)}`);
    setText("recSub", `${((cam.recording_bytes || 0) / 1e6).toFixed(1)} MB · ${cam.recording_frames ?? 0} frames · encrypted on SD` +
      ((cam.recording_part || 1) > 1 ? ` · part ${cam.recording_part}` : ""));
  }
  const hb = document.querySelector(".hotbar button.rec");
  hb.classList.toggle("recording", on);
  setHTML_el(hb, on ? `<b>●</b>${hms(el)}` : `<b>●</b>REC`);
  hb.style.fontSize = on ? "6px" : "";
  $("liveOsd").classList.toggle("show", !!cam.live && !noSignal);
}
function setHTML_el(el, html) { if (el._h !== html) { el._h = html; el.innerHTML = html; } }
setInterval(recTick, 250);

/* ---------- live video + detection overlay ---------- */
let overlayOn = true, annotated = false, noSignal = true, lastDecoded = -1, lastDecodedAt = 0;
const img = $("video");
function setStream() { setStream.at = performance.now(); img.src = (annotated ? "/video_annotated.mjpg" : "/video.mjpg") + "?t=" + Date.now(); }
setStream();
img.onerror = () => { if (!document.hidden) setTimeout(setStream, 2000); };
// a background tab must not keep pulling 3 MB/s of MJPEG from the ground station (the GIL is shared with the receive thread)
document.addEventListener("visibilitychange", () => { if (document.hidden) img.removeAttribute("src"); else setStream(); });
/* Stream watchdog (last resort). An MJPEG <img> gives no event when its connection dies quietly: the picture just
 * stays frozen. A restart of the ground station and an unreachable period are handled in poll(); this covers what
 * is left. Every 2 s five small patches of the picture are compared, pixel for pixel and unscaled (so sensor noise
 * shows: a live picture of a motionless scene still changes with every keyframe), with the previous sample. If the
 * ground station is decoding new frames but nothing changed for 15 s, the stream is reopened, then with a growing
 * pause (a picture that really is constant, e.g. a covered lens, must not be reopened over and over). */
const wd = {canvas: document.createElement("canvas"), sig: null, changed: performance.now(), wait: 15000, reconnects: 0};
wd.canvas.width = 80; wd.canvas.height = 16;
function frameSignature() {
  const w = img.naturalWidth, h = img.naturalHeight;
  if (!w || !h) return null;
  const g = wd.canvas.getContext("2d", {willReadFrequently: true});
  [[0.5, 0.5], [0.2, 0.25], [0.8, 0.25], [0.2, 0.75], [0.8, 0.75]].forEach(([fx, fy], i) =>
    g.drawImage(img, Math.round(w * fx) - 8, Math.round(h * fy) - 8, 16, 16, i * 16, 0, 16, 16));     // 1:1, no scaling
  const d = g.getImageData(0, 0, 80, 16).data;
  let s = 0;
  for (let k = 0; k < d.length; k++) s = (s * 31 + d[k]) >>> 0;
  return s;
}
setInterval(() => {
  if (document.hidden || tab !== "mission" || annotated || !img.getAttribute("src")) { wd.changed = performance.now(); return; }
  let sig = null;
  try { sig = frameSignature(); } catch (e) { return; }
  const now = performance.now(), serverLive = S && S.video && S.video.streaming !== false && S.video.decoder === "running" && now - lastDecodedAt < 2500;
  if (sig !== wd.sig || !serverLive) { wd.sig = sig; wd.changed = now; wd.wait = 15000; return; }
  if (now - wd.changed > wd.wait && now - (setStream.at || 0) > 10000) { wd.reconnects++; wd.changed = now; wd.wait = Math.min(wd.wait * 2, 120000); setStream(); }
}, 2000);
$("btnOverlay").onclick = (e) => { overlayOn = !overlayOn; e.target.textContent = `BOXES: ${overlayOn ? "ON" : "OFF"}`; e.target.classList.toggle("on", overlayOn); };
$("btnAnn").onclick = (e) => { annotated = !annotated; e.target.classList.toggle("on", annotated); setStream(); };
const COLORS = ["#55ff55", "#55ffff", "#ffff55", "#ff55ff", "#ffaa00", "#ff7777", "#7a7aff", "#ffffff"];
const clsColor = (c) => COLORS[[...c].reduce((a, ch) => a + ch.charCodeAt(0), 0) % COLORS.length];

/* Boxes come from the detector a little after the frame they describe was captured, while the browser shows a
 * newer frame. Each track keeps its last box, capture time and a smoothed velocity; every animation frame the
 * box is moved to where the object should be in the frame being displayed, then eased toward it. Result: boxes
 * stay attached to moving objects instead of trailing them, and do not jitter between detections. */
const boxes = new BoxTracker();                               // static/boxtracker.js (unit-tested under node)
let serverOffset = null, lastSeq = null, dims = {w: 1280, h: 720};
let motionNow = null;                                         // newest report of the UAV's motion watch + when it came
const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
function ingest(d) {
  if (d) motionNow = d.motion && Array.isArray(d.motion.regions) ? {regions: d.motion.regions.filter(Array.isArray), at: performance.now()} : null;
  if (!d || d.seq == null || d.seq === lastSeq) return;
  lastSeq = d.seq; dims = {w: d.w || dims.w, h: d.h || dims.h};
  if (d.profile !== ingest.profile) { boxes.clear(); ingest.profile = d.profile; }         // new model = new track ids
  boxes.ingest(d.dets || [], d.frame_ts, performance.now() / 1000);
}
async function pollDet() {
  if (tab === "mission" && !annotated) {
    try {
      const t0 = Date.now(), d = await fetchJSON("/api/detections/latest", 4000), t1 = Date.now();
      // serverOffset maps this browser's clock to the CAMERA's capture clock (view_ts = capture time of the picture
      // being shown at the moment of the reply). Boxes carry capture times of the same clock, so the ground
      // station's own clock plays no part. A jump (new stream, camera clock corrected) is taken over at once.
      if (d.view_ts != null) {
        const o = d.view_ts - (t0 + t1) / 2000;
        serverOffset = serverOffset == null || Math.abs(o - serverOffset) > 0.5 ? o : 0.9 * serverOffset + 0.1 * o;
      }
      ingest(d);
    } catch (e) { /* server restarting */ }
  }
  setTimeout(pollDet, 100);
}
pollDet();

/* teach by example: freeze the frame, drag a box around the object, name it */
let teach = null;                                             // {frame, drag:{x0,y0,x1,y1}|null}
function cancelTeach() { teach = null; $("btnTeach").classList.remove("on"); $("btnTeach").textContent = "TEACH"; $("overlay").classList.remove("teaching"); $("teachHint").classList.remove("show"); }
$("btnTeach").onclick = () => {
  if (teach) return cancelTeach();
  const name = $("teachName").value.trim();
  if (!name) { setNote("msg", "> type a name first (e.g. pencil), then press TEACH and drag a box around the object"); $("teachName").focus(); return; }
  if (!img.naturalWidth || noSignal) { setNote("msg", "> no live video: press ▶ LIVE first, then TEACH"); return; }
  const c = document.createElement("canvas"); c.width = img.naturalWidth; c.height = img.naturalHeight;
  try { c.getContext("2d").drawImage(img, 0, 0); } catch (e) { setNote("msg", "> could not freeze the picture - try again"); return; }
  teach = {frame: c, drag: null, name};
  $("btnTeach").classList.add("on"); $("btnTeach").textContent = "CANCEL";
  $("overlay").classList.add("teaching"); $("teachHint").classList.add("show");
  setText("teachHint", `drag a tight box around the "${name}" — the picture is frozen`);
};
window.addEventListener("keydown", (e) => { if (e.key === "Escape") cancelTeach(); });
function videoRect() {
  const r = $("overlay").getBoundingClientRect(), fw = teach ? teach.frame.width : dims.w, fh = teach ? teach.frame.height : dims.h;
  const ar = fw / fh, boxAr = r.width / r.height;
  const W = ar > boxAr ? r.width : r.height * ar, H = ar > boxAr ? r.width / ar : r.height;
  return {r, W, H, ox: (r.width - W) / 2, oy: (r.height - H) / 2};
}
(() => {
  const cv = $("overlay");
  const pos = (e) => { const {r, W, H, ox, oy} = videoRect(); return [clamp((e.clientX - r.left - ox) / W, 0, 1), clamp((e.clientY - r.top - oy) / H, 0, 1)]; };
  cv.addEventListener("pointerdown", (e) => { if (!teach) return; cv.setPointerCapture(e.pointerId); const [x, y] = pos(e); teach.drag = {x0: x, y0: y, x1: x, y1: y}; });
  cv.addEventListener("pointermove", (e) => { if (teach && teach.drag) { const [x, y] = pos(e); teach.drag.x1 = x; teach.drag.y1 = y; } });
  cv.addEventListener("pointercancel", () => { if (teach) teach.drag = null; });
  cv.addEventListener("pointerup", async (e) => {
    if (!teach || !teach.drag) return;
    const d = teach.drag, box = [Math.min(d.x0, d.x1), Math.min(d.y0, d.y1), Math.max(d.x0, d.x1), Math.max(d.y0, d.y1)];
    if ((box[2] - box[0]) * teach.frame.width < 8 || (box[3] - box[1]) * teach.frame.height < 8) { teach.drag = null; return; }
    const {name, frame} = teach;
    cancelTeach();
    setNote("detStatus", `learning "${name}" … (a few seconds, the model reloads)`);
    let image;
    try { image = frame.toDataURL("image/jpeg", 0.92).split(",")[1]; } catch (err) { setNote("msg", "> could not read the frozen picture - try again"); return; }
    const r = await cmd("detector", {teach: {name, box, image}}, `teach ${name}`);
    if (r && r.ok) $("teachName").value = "";
  });
})();

const labelFont = "bold 21px VT323, monospace";
function overlayFrame() {
  requestAnimationFrame(overlayFrame);
  if (tab !== "mission") return;
  const cv = $("overlay"), {r, W, H, ox, oy} = videoRect(), dpr = window.devicePixelRatio || 1;
  const pw = Math.round(r.width * dpr), ph = Math.round(r.height * dpr);
  if (cv.width !== pw || cv.height !== ph) { cv.width = pw; cv.height = ph; }
  const g = cv.getContext("2d"); g.setTransform(dpr, 0, 0, dpr, 0, 0); g.clearRect(0, 0, r.width, r.height);
  const now = performance.now() / 1000;
  if (teach) {
    g.drawImage(teach.frame, ox, oy, W, H);
    if (teach.drag) {
      const d = teach.drag, x = ox + Math.min(d.x0, d.x1) * W, y = oy + Math.min(d.y0, d.y1) * H, w = Math.abs(d.x1 - d.x0) * W, h = Math.abs(d.y1 - d.y0) * H;
      g.lineWidth = 4; g.strokeStyle = "#000"; g.strokeRect(x, y, w, h); g.lineWidth = 2; g.strokeStyle = "#ffff55"; g.strokeRect(x, y, w, h);
    }
    return;
  }
  if (!overlayOn || annotated || serverOffset == null) return;
  // capture time of the frame on screen: the newest decoded frame, less the ~60 ms the MJPEG stream needs to reach the <img>
  const viewT = Date.now() / 1000 + serverOffset - 0.06, dtF = now - (overlayFrame.last || now); overlayFrame.last = now;
  const items = boxes.step(viewT, now, dtF);
  g.font = labelFont; g.textBaseline = "alphabetic";
  const used = [];
  items.sort((p, q) => p.box[1] - q.box[1]);
  for (const {box, cls, conf, alpha} of items) {
    const tr = {cls, conf}, [x1, y1, x2, y2] = box, col = clsColor(cls || "?");
    const bx = ox + clamp(x1, 0, 1) * W, by = oy + clamp(y1, 0, 1) * H, bw = (clamp(x2, 0, 1) - clamp(x1, 0, 1)) * W, bh = (clamp(y2, 0, 1) - clamp(y1, 0, 1)) * H;
    if (bw < 2 || bh < 2) continue;
    g.globalAlpha = alpha;
    g.lineWidth = 5; g.strokeStyle = "#000"; g.strokeRect(bx, by, bw, bh);
    g.lineWidth = 3; g.strokeStyle = col; g.strokeRect(bx, by, bw, bh);
    const label = `${tr.cls} ${(tr.conf * 100).toFixed(0)}%`, tw = g.measureText(label).width + 12, th = 24;
    let lx = clamp(bx - 1, 0, r.width - tw), ly = by - th - 1 >= 0 ? by - th - 1 : by + 1;     // above the box, inside it at the top edge
    for (let tries = 0; tries < 8 && used.some((u) => lx < u[0] + u[2] && lx + tw > u[0] && ly < u[1] + u[3] && ly + th > u[1]); tries++) ly += th + 2;
    ly = clamp(ly, 0, r.height - th); used.push([lx, ly, tw, th]);
    g.fillStyle = col; g.fillRect(lx, ly, tw, th); g.lineWidth = 2; g.strokeStyle = "#000"; g.strokeRect(lx, ly, tw, th);
    g.fillStyle = "#000"; g.fillText(label, lx + 6, ly + th - 6);
  }
  g.globalAlpha = 1;
  // what the UAV's motion watch reports: dashed amber boxes, the tag below the box (object labels sit above theirs)
  if (motionNow && now * 1000 - motionNow.at < 1500) {
    for (const [x, y, w, h] of motionNow.regions) {
      const bx = ox + clamp(x, 0, 1) * W, by = oy + clamp(y, 0, 1) * H, bw = clamp(w, 0, 1 - clamp(x, 0, 1)) * W, bh = clamp(h, 0, 1 - clamp(y, 0, 1)) * H;
      if (!(bw >= 2 && bh >= 2)) continue;
      g.setLineDash([]); g.lineWidth = 5; g.strokeStyle = "#000"; g.strokeRect(bx, by, bw, bh);
      g.setLineDash([10, 6]); g.lineWidth = 3; g.strokeStyle = "#ffaa00"; g.strokeRect(bx, by, bw, bh);
      g.setLineDash([]);
      const tw = g.measureText("MOVING").width + 12, th = 24, lx = clamp(bx - 1, 0, r.width - tw);
      let ly = by + bh + 1 + th <= r.height ? by + bh + 1 : by + bh - th - 1;
      for (let tries = 0; tries < 6 && used.some((u) => lx < u[0] + u[2] && lx + tw > u[0] && ly < u[1] + u[3] && ly + th > u[1]); tries++) ly -= th + 2;
      ly = clamp(ly, 0, r.height - th); used.push([lx, ly, tw, th]);
      g.fillStyle = "#ffaa00"; g.fillRect(lx, ly, tw, th); g.lineWidth = 2; g.strokeStyle = "#000"; g.strokeRect(lx, ly, tw, th);
      g.fillStyle = "#000"; g.fillText("MOVING", lx + 6, ly + th - 6);
    }
  }
}
requestAnimationFrame(overlayFrame);

/* ---------- maps ---------- */
let map, mini, layers = {}, miniMarker, ctrl;
const SAT = () => L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}",
  {maxZoom: 19, attribution: "Imagery © Esri, Maxar, Earthstar Geographics"});
const OSM = () => L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {maxZoom: 19, attribution: "© OpenStreetMap contributors"});
function initMaps() {
  if (!window.L) { $("map").textContent = "Map library unavailable"; return; }
  // leaflet.heat redraws on an animation frame; if the tab was switched meanwhile its canvas is 0 x 0 and
  // getImageData throws (an uncaught error on every tab change). Skip the frame instead; it redraws when shown.
  if (L.HeatLayer && !L.HeatLayer.prototype._k6g) {
    const redraw = L.HeatLayer.prototype._redraw;
    L.HeatLayer.prototype._redraw = function () {
      if (!this._map || !this._canvas || !this._canvas.width || !this._canvas.height || $("map").offsetParent === null) { this._frame = null; return; }
      try { return redraw.call(this); } catch (e) { this._frame = null; }
    };
    L.HeatLayer.prototype._k6g = true;
  }
  const sat = SAT(), osm = OSM();
  map = L.map("map", {layers: [sat]}).setView([12.97, 79.16], 15);
  layers.track = L.layerGroup().addTo(map);
  layers.rings = L.layerGroup().addTo(map);
  layers.det = L.layerGroup().addTo(map);
  layers.cur = L.layerGroup().addTo(map);
  // added to the map lazily (see updateMapsInner): leaflet.heat draws on add and fails on a hidden 0-size map
  layers.heat = L.heatLayer ? L.heatLayer([], {radius: 18, blur: 14, maxZoom: 19}) : L.layerGroup();
  ctrl = L.control.layers({"Satellite (Esri)": sat, "Street (OSM)": osm},
    {"Track (by speed)": layers.track, "Heatmap": layers.heat, "Range rings": layers.rings, "Detections": layers.det, "Position": layers.cur}).addTo(map);
  L.control.scale().addTo(map);
  mini = L.map("minimap", {layers: [SAT()], zoomControl: false, attributionControl: false}).setView([12.97, 79.16], 16);
  // the big map's height follows the layout (it fills its column): tell Leaflet whenever its box really changes
  if (window.ResizeObserver) new ResizeObserver(() => { if ($("map").offsetParent !== null) map.invalidateSize({animate: false}); }).observe($("map"));
  $("btnFit").onclick = () => { const b = layers.track.getLayers().flatMap((l) => (l.getLatLngs ? l.getLatLngs() : [])); if (b.length) map.fitBounds(L.latLngBounds(b).pad(0.2)); };
  map.on("click", (e) => {
    if (!picking) return;
    picking = false; $("btnPick").classList.remove("on"); $("btnPick").textContent = "PICK REFERENCE ON MAP";
    cmd("set_home", {lat: +e.latlng.lat.toFixed(7), lon: +e.latlng.lng.toFixed(7), source: "operator (map click)"});
  });
}
initMaps();
const speedColor = (v) => (v == null ? "#aaaaaa" : v < 0.5 ? "#55ffff" : v < 2 ? "#55ff55" : v < 5 ? "#ffff55" : v < 10 ? "#ffaa00" : "#ff5555");
$("speedLegend").innerHTML = [["<0.5", "#55ffff"], ["0.5–2", "#55ff55"], ["2–5", "#ffff55"], ["5–10", "#ffaa00"], [">10 m/s", "#ff5555"]]
  .map(([t, c]) => `<span><i class="sw" style="background:${c}"></i>${t}</span>`).join("");
let mapCentered = false;
function updateMaps(s) {
  try { updateMapsInner(s); } catch (e) { console.warn("map update", e); }
}
function updateMapsInner(s) {
  if (!map) return;
  const t = s.telemetry, trk = s.track || [];
  const miniPos = t && t.lat != null ? [t.lat, t.lon] : s.home;
  if (miniPos && mini && $("minimap").offsetParent !== null) {
    if (!miniMarker) miniMarker = L.circleMarker(miniPos, {radius: 7, color: "#000", weight: 3, fillColor: "#ff5555", fillOpacity: 1}).addTo(mini);
    miniMarker.setLatLng(miniPos); mini.setView(miniPos, mini.getZoom());
    miniMarker.setStyle({fillColor: t && t.lat != null ? "#ff5555" : "#ffffff"});
  }
  if ($("map").offsetParent === null) return;            // hidden tab: canvas layers have zero size
  if (!layers.heatAdded) { map.invalidateSize(); layers.heat.addTo(map); layers.heatAdded = true; }
  // rebuild a layer only when its data changed (clearing and re-adding hundreds of polylines every second flickers)
  const sig = (k, v) => { const j = JSON.stringify(v); if (layers["sig_" + k] === j) return false; layers["sig_" + k] = j; return true; };
  if (sig("track", [trk.length, trk[trk.length - 1]])) {
    layers.track.clearLayers();
    for (let i = 1; i < trk.length; i++) L.polyline([[trk[i - 1][0], trk[i - 1][1]], [trk[i][0], trk[i][1]]], {color: speedColor(trk[i][2]), weight: 4}).addTo(layers.track);
    if (layers.heat.setLatLngs) layers.heat.setLatLngs(trk.map((p) => [p[0], p[1], 0.6]));
  }
  if (sig("rings", s.home)) layers.rings.clearLayers();
  if (s.home && !layers.rings.getLayers().length) {
    [100, 250, 500, 1000].forEach((r, i) => L.circle(s.home, {radius: r, color: ["#55ff55", "#ffff55", "#ffaa00", "#ff5555"][i], weight: 2, fillOpacity: 0.04})
      .bindTooltip(`${r} m`).addTo(layers.rings));
    L.circleMarker(s.home, {radius: 6, color: "#000", fillColor: "#ffffff", fillOpacity: 1})
      .bindTooltip(`HOME / REFERENCE · ${esc(s.home_source || "")}`).addTo(layers.rings);
    if (!(t && t.lat != null) && !mapCentered) { map.setView(s.home, 17); mapCentered = "home"; }
  }
  setNote("mapNote", t && t.lat != null ? "" :
    s.home ? `No GNSS fix: the white marker is the reference point (${s.home_source || "operator"}), not a measured UAV position.` :
    "No GNSS fix yet: no UAV position is drawn (nothing is guessed). Use PICK REFERENCE ON MAP to mark where the UAV is.");
  if (sig("cur", t && t.lat != null ? [t.lat, t.lon, t.eph_m] : null)) {
    layers.cur.clearLayers();
    if (t && t.lat != null) {
      const p = [t.lat, t.lon];
      if (t.eph_m) L.circle(p, {radius: t.eph_m, color: "#55ffff", weight: 1, fillOpacity: 0.1}).addTo(layers.cur);
      L.circleMarker(p, {radius: 8, color: "#000", weight: 3, fillColor: "#ff5555", fillOpacity: 1}).bindTooltip("UAV").addTo(layers.cur);
      if (mapCentered !== "fix") { map.setView(p, 18); mapCentered = "fix"; }
    }
  }
}
async function updateDetMarkers() {
  if (!map) return;
  try {
    const tr = await fetchJSON("/api/tracks", 15000);
    layers.det.clearLayers();
    tr.filter((x) => x.lat != null).forEach((x) => L.circleMarker([x.lat, x.lon], {radius: 6, color: "#000", fillColor: clsColor(x.cls), fillOpacity: 1})
      .bindTooltip(`${esc(x.cls)} · ${tstr(x.first_ts)}`).addTo(layers.det));
  } catch (e) { /* offline */ }
}

/* ---------- charts ---------- */
const charts = {};
if (window.Chart) {
  Chart.defaults.font.family = "VT323, monospace"; Chart.defaults.font.size = 16; Chart.defaults.color = "#dddddd";
  Chart.defaults.borderColor = "#ffffff22"; Chart.defaults.animation = false;
}
function chart(id, type, datasets, opts = {}) {
  if (!window.Chart) return null;
  if (charts[id]) return charts[id];
  charts[id] = new Chart($(id), {type, data: {labels: [], datasets}, options: {responsive: true, maintainAspectRatio: false,
    plugins: {legend: {labels: {boxWidth: 12}}}, elements: {point: {radius: 0}, line: {borderWidth: 2, stepped: false}}, ...opts}});
  return charts[id];
}
const ds = (label, color, axis = "y", extra = {}) => ({label, data: [], borderColor: color, backgroundColor: color, yAxisID: axis, ...extra});
function setSeries(c, labels, arrays) {
  if (!c) return;
  const sig = labels.length + "|" + labels[labels.length - 1] + "|" + JSON.stringify(arrays.map((a) => [a.length, a[a.length - 1]]));
  if (c._sig === sig) return;                      // nothing new: do not repaint
  c._sig = sig; c.data.labels = labels; arrays.forEach((a, i) => (c.data.datasets[i].data = a)); c.update("none");
}
const tl = (rows) => rows.map((r) => new Date(r.ts * 1000).toLocaleTimeString());

async function refreshSlow() {
  if (!["telemetry", "security", "data"].includes(tab)) return;
  let s;
  try { s = await fetchJSON("/api/series?minutes=30", 15000); } catch (e) { return; }
  const tm = s.telemetry;
  if (tab === "telemetry") {
    setSeries(chart("cAlt", "line", [ds("altitude m (MSL)", "#55ffff"), ds("speed m/s", "#ffaa00", "y2")],
      {scales: {y: {position: "left"}, y2: {position: "right", grid: {display: false}}}}), tl(tm), [tm.map((r) => r.alt_m), tm.map((r) => r.speed_mps)]);
    setSeries(chart("cSats", "line", [ds("sats used", "#55ff55"), ds("sats seen", "#aaaaaa"), ds("HDOP", "#ffff55", "y2"), ds("PDOP", "#ff55ff", "y2")],
      {scales: {y: {position: "left", beginAtZero: true}, y2: {position: "right", grid: {display: false}, beginAtZero: true}}}),
      tl(tm), [tm.map((r) => r.sats_used), tm.map((r) => r.sats_seen), tm.map((r) => r.hdop), tm.map((r) => r.pdop)]);
    await loadTable();
    updateDetMarkers();
  }
  if (tab === "security") setSeries(chart("cRtt", "line", [ds("RTT ms", "#55ffff")], {scales: {y: {beginAtZero: true}}}), tl(s.link), [s.link.map((r) => r.rtt_ms)]);
  if (tab === "data") {
    setSeries(chart("cVid", "line", [ds("video fps", "#55ff55"), ds("detector fps", "#ffff55"), ds("display latency ms", "#ff5555", "y2"), ds("inference ms", "#ffaa00", "y2")],
      {scales: {y: {beginAtZero: true}, y2: {position: "right", beginAtZero: true, grid: {display: false}}}}),
      tl(s.video), [s.video.map((r) => r.fps), s.video.map((r) => r.det_fps), s.video.map((r) => r.display_latency_ms), s.video.map((r) => r.det_ms)]);
    setSeries(chart("cSys", "line", [ds("CPU %", "#55ff55"), ds("temp °C", "#ff5555"), ds("Wi-Fi dBm", "#55ffff", "y2")],
      {scales: {y: {beginAtZero: true}, y2: {position: "right", grid: {display: false}}}}),
      tl(s.system), [s.system.map((r) => r.cpu), s.system.map((r) => r.temp_c), s.system.map((r) => r.wifi_dbm)]);
    const dc = chart("cDet", "bar", [ds("detections", "#55ff55")], {indexAxis: "y", plugins: {legend: {display: false}}});
    const dSig = JSON.stringify(s.detections_by_class);
    if (dc && dc._sig !== dSig) { dc._sig = dSig; dc.data.labels = s.detections_by_class.map((r) => r.cls); dc.data.datasets[0].data = s.detections_by_class.map((r) => r.n); dc.update("none"); }
    try {
      const ev = await fetchJSON("/api/events?limit=150", 15000);
      setHTML("dbEvents", ev.map((e) => `<div><span class="dim">${tstr(e.ts)}</span> <span class="yel">${esc(e.kind)}</span> ${esc(e.msg)}</div>`).join(""));
    } catch (e) { /* ignore */ }
  }
}
setInterval(refreshSlow, 5000);

/* ---------- data table (frozen while being read) ---------- */
let tblRows = [], sortKey = "ts", sortDir = -1, tblHover = false;
const COLS = [["ts", "time"], ["fix", "fix"], ["lat", "lat"], ["lon", "lon"], ["alt_m", "alt MSL m"], ["speed_mps", "m/s"], ["track_deg", "course"],
  ["sats_used", "used"], ["sats_seen", "seen"], ["hdop", "HDOP"], ["vdop", "VDOP"], ["pdop", "PDOP"], ["cn0_max", "best C/N0"], ["latency_ms", "lat. ms"], ["backfill", "late"], ["epoch", "key epoch"]];
$("tblWrap").onmouseenter = () => (tblHover = true);
$("tblWrap").onmouseleave = () => { tblHover = false; renderTable(); };
async function loadTable() {
  try { tblRows = await fetchJSON("/api/telemetry?latest=400", 15000); } catch (e) { return; }
  setText("tblInfo", `${tblRows.length} newest rows · stored in SQLite${tblHover || $("tblWrap").scrollTop > 30 ? " · paused while you read" : ""}`);
  renderTable();
}
function renderTable(force) {
  // frozen while it is being read - except when the reader asks for a new sort order (the pointer is on the table then)
  if (!force && (tblHover || $("tblWrap").scrollTop > 30)) return;
  const rows = [...tblRows].sort((a, b) => ((a[sortKey] ?? -1e18) > (b[sortKey] ?? -1e18) ? 1 : -1) * sortDir).slice(0, 300);
  const fmt = (k, v) => (k === "ts" ? tstr(v) : k === "lat" || k === "lon" ? f(v, 6) : typeof v === "number" ? (Number.isInteger(v) ? v : v.toFixed(2)) : v);
  setHTML("tbl", `<tr>${COLS.map(([k, n]) => `<th data-k="${k}">${n}${sortKey === k ? (sortDir > 0 ? " ▲" : " ▼") : ""}</th>`).join("")}</tr>` +
    rows.map((r) => `<tr>${COLS.map(([k]) => `<td>${esc(fmt(k, r[k]))}</td>`).join("")}</tr>`).join(""));
  $("tbl").querySelectorAll("th").forEach((th) => (th.onclick = () => { sortDir = sortKey === th.dataset.k ? -sortDir : -1; sortKey = th.dataset.k; $("tblWrap").scrollTop = 0; renderTable(true); }));
}

/* ---------- sky plot ---------- */
const CONS_COL = {GPS: "#55ff55", Galileo: "#55ffff", GLONASS: "#ff5555", BeiDou: "#ffff55", NavIC: "#ff55ff", QZSS: "#ffaa00", SBAS: "#aaaaaa"};
function drawSky(sats) {
  const cv = $("sky"), g = cv.getContext("2d"), W = cv.width, c = W / 2, R = W / 2 - 40;
  g.clearRect(0, 0, W, W); g.fillStyle = "#0b1a10"; g.fillRect(0, 0, W, W);
  g.strokeStyle = "#55ff5555"; g.lineWidth = 2; g.font = "26px VT323"; g.fillStyle = "#aaaaaa";
  [0, 30, 60].forEach((el) => { g.beginPath(); g.arc(c, c, R * (90 - el) / 90, 0, 2 * Math.PI); g.stroke(); g.fillText(`${el}°`, c + 4, c - R * (90 - el) / 90 + 22); });
  g.beginPath(); g.moveTo(c - R, c); g.lineTo(c + R, c); g.moveTo(c, c - R); g.lineTo(c, c + R); g.stroke();
  g.fillStyle = "#ffff55"; g.font = "30px VT323"; g.fillText("N", c - 7, 30); g.fillText("S", c - 7, W - 8); g.fillText("E", W - 26, c + 8); g.fillText("W", 8, c + 8);
  const noPos = [];
  for (const [con, prn, az, el, snr, used] of sats) {
    if (az == null || el == null) { noPos.push(`${con} ${prn}${snr ? " (" + snr + " dB-Hz)" : ""}`); continue; }
    const r = R * (90 - el) / 90, a = (az - 90) * Math.PI / 180, x = c + r * Math.cos(a), y = c + r * Math.sin(a), sz = 8 + (snr || 0) / 4;
    g.fillStyle = CONS_COL[con] || "#fff"; g.strokeStyle = "#000"; g.lineWidth = 3;
    if (used) g.fillRect(x - sz / 2, y - sz / 2, sz, sz); else { g.strokeStyle = CONS_COL[con] || "#fff"; g.strokeRect(x - sz / 2, y - sz / 2, sz, sz); }
    g.fillStyle = "#fff"; g.font = "22px VT323"; g.fillText(String(prn), x + sz / 2 + 2, y - sz / 2);
  }
  setNote("skyNoPos", noPos.length ? `Tracked, no azimuth/elevation yet (almanac still downloading): ${noPos.join(", ")}` : "");
}
$("skyLegend").innerHTML = Object.entries(CONS_COL).map(([k, c]) => `<span><i class="sw" style="background:${c}"></i>${k}</span>`).join("") + "<span>■ used · □ tracked</span>";

/* ---------- main poll ---------- */
function tile(l, n, s = "", cls = "") { return `<div class="tile" title="${esc(l)}: ${esc(n)} ${esc(s)}"><div class="l">${esc(l)}</div><div class="n ${cls}">${esc(n)}</div><div class="s">${esc(s)}</div></div>`; }
function kv(rows) { return rows.map(([k, v, c]) => `<tr><td class="k">${esc(k)}</td><td class="v ${c || ""}" title="${esc(v)}">${esc(v)}</td></tr>`).join(""); }

function renderReceiver(t, sats, cn0, listening) {
  const best = cn0.length ? Math.max(...cn0) : null, withPos = sats.filter((x) => x[2] != null && x[3] != null).length;
  const cons = [...new Set(sats.map((x) => x[0]))];
  setText("rxInfo", t.connected ? `${t.device || "gpsd"} · ${t.driver || ""}` : "gpsd not connected");
  setHTML("rxKv", kv([["gpsd / device", `${t.connected ? "connected" : "DISCONNECTED"} · ${t.device || "—"}`, t.connected ? "ok" : "bad"],
    ["receiver UTC (RMC)", t.receiver_utc || "—", t.utc_valid ? "ok" : "warn"],
    ["receiver − Pi clock", t.receiver_minus_system_s != null ? `${t.receiver_minus_system_s} s` : "—"],
    ["RMC status / mode", `${t.rmc_status || "—"} · ${t.nav_mode || "—"}`, t.rmc_status === "VALID" ? "ok" : "warn"],
    ["GGA quality", `${t.gga_quality ?? "—"} ${t.gga_quality_name || ""} · ${t.gga_sats ?? "—"} sats`],
    ["satellites tracked", `${sats.length} (${withPos} with az/el) · ${cons.join(", ") || "none"}`],
    ["NMEA", `${f(t.nmea_rate_hz, 1)} sentences/s · ${t.nmea_sentences ?? 0} total`],
    ["talkers", Object.entries(t.talkers || {}).map(([k, v]) => `${k}:${v}`).join(" ") || "—"],
    ["antenna (PQTM raw)", t.antenna_status_raw || "not reported"],
    ["receiver messages", (t.receiver_text || []).slice(-3).join(" | ") || "—"],
    ["searching for", listening != null ? hms(listening) : "—"]]));
  let d = "";
  if ((t.mode || 0) >= 2) d = "Fix OK.";
  else if (!t.connected) d = "gpsd is not connected to the receiver (USB?).";
  else if (sats.length < 4) d = `Only ${sats.length} satellite(s) tracked — a fix needs ≥4 with ephemeris. Put the antenna under open sky (ceramic patch facing up, away from walls, metal and the Pi/Wi-Fi); a window sill or under a roof usually is not enough.`;
  else if (best != null && best < 30) d = `Signals are weak (best ${best} dB-Hz; ≥35 needed to decode quickly). Improve the sky view.`;
  else if (withPos < 4) d = "Satellites are tracked but orbit data is still downloading (a cold start needs ~30 s – 15 min of uninterrupted strong signal).";
  else d = "Enough satellites with orbits — a fix should follow shortly.";
  setNote("rxDiag", "Diagnosis: " + d);
}

const thumb = (src, link) => `<a href="${esc(link || src)}" target="_blank" class="thumb"><img src="${esc(src)}" alt=""></a>`;

function render(s) {
  const L_ = s.link || {}, t = s.telemetry || {}, v = s.video || {}, u = s.uav || {}, cam = u.camera || {}, det = s.detector || {}, a = (s.analytics || {}).summary || {};
  const up = L_.state === "UP", fixOk = (t.mode || 0) >= 2;
  const clockBad = up && Math.abs(L_.clock_rate_pct || 0) > 0.5;     // more than 5 ms per second: not NTP noise
  const sats = Array.isArray(t.satellites) ? t.satellites.filter(Array.isArray) : [], cn0 = sats.map((x) => x[4]).filter((x) => x != null);
  const listening = t.receiver_start ? (t.ts || s.now) - t.receiver_start : null;
  // each block is independent: an unexpected value in one of them must not stop the others from updating
  safe("header", () => {
  $("bUav").classList.toggle("show", !up);
  setHTML("pLink", `LINK <span class="${up ? "ok" : "bad"}">${up ? "SECURE" : esc(L_.state)}</span>`);
  setHTML("pGnss", `GNSS <span class="${fixOk ? "ok" : "warn"}">${esc(t.fix || "NO DATA")}</span> ${esc(t.sats_used ?? 0)}/${esc(t.sats_seen ?? 0)}`);
  // IDLE: the detector is ready but there is no live picture to analyse (a rate would be a leftover of the last stream)
  const ai = det.loading ? "LOADING" : !det.available ? "OFF" : !det.enabled ? "PAUSED" : det.analysing === false ? "IDLE" : f(det.fps, 1) + " FPS";
  setHTML("pDet", `AI <span class="${det.available ? (det.enabled && det.analysing !== false ? "ok" : "warn") : "bad"}">${ai}</span>`);
  setHTML("pDb", `DB <span class="aqua">${esc((s.db || {}).telemetry ?? 0)}</span> rows`);
  $("hbDet").classList.toggle("on", !!det.enabled);
  });
  safe("video", () => {
  if (v.frames_decoded !== lastDecoded) { lastDecoded = v.frames_decoded; lastDecodedAt = performance.now(); }
  noSignal = !(v.decoder === "running" && performance.now() - lastDecodedAt < 2500);        // no flicker on a single slow second
  $("nosig").style.display = noSignal ? "flex" : "none";
  setHTML("nosig", !up ? "NO SIGNAL<br>UAV not connected" : cam.available === false ? `NO SIGNAL<br>camera: ${esc(cam.error || "not available")}` :
    cam.live ? "NO SIGNAL<br>waiting for the first keyframe…" : "NO SIGNAL<br>press ▶ LIVE on the hotbar");
  setText("vInfo", cam.live ? `${cam.width}×${cam.height} · ${cam.mode}${cam.recording ? " · ● REC" : ""}` : "camera idle");
  // with an unsteady ground-station clock the two latency tiles are estimates: say so instead of showing nonsense as fact
  setHTML("vTiles", tile("FPS (GCS)", f(v.fps, 1), `UAV ${f(cam.fps, 1)}`) + tile("BITRATE", f(v.kbps, 0), "kbit/s") +
    tile("CAPTURE→DECODED", f(v.display_latency_ms, 0), clockBad ? "ms · APPROX: PC clock unsteady" : "ms median (excl. browser)", clockBad ? "warn" : "") +
    tile("NETWORK+CRYPTO", f(v.network_latency_ms, 0), clockBad ? "ms · APPROX: PC clock unsteady" : "capture→decrypted ms", clockBad ? "warn" : "") +
    tile("FRAMES LOST", `${v.frames_lost ?? 0}`, `of ${v.frames_complete ?? 0} · ${f(v.frame_loss_pct, 2, "%")}`, (v.frames_lost || 0) ? "warn" : "") +
    tile("AES-GCM / CHUNK", f((u.video_tx || {}).seal_us_avg, 0), "µs on the Pi"));
  });
  safe("motion", () => renderMotion({...(cam.motion || {}), live: cam.live}, s.motion));
  safe("detector", () => {
  renderDetControls(det);
  setText("detInfo", det.loading ? `loading ${det.loading}…` : det.available ? `${f(det.infer_ms, 0)} ms / frame` : (det.error || ""));
  setHTML("detTiles", tile("OBJECTS NOW", det.objects_now ?? 0) + tile("UNIQUE TRACKS", det.unique_tracks ?? 0) + tile("AI FPS", f(det.fps, 1)) +
    tile("VOCABULARY", det.vocab_size ?? "—", (det.profile || "").toUpperCase()));
  const now_ = det.counts_now || {}, uniq = det.by_class_unique || {};
  const names = [...new Set([...Object.keys(now_), ...Object.keys(uniq)])]
    .sort((x, y) => ((now_[y] || 0) - (now_[x] || 0)) || ((uniq[y] || 0) - (uniq[x] || 0)) || x.localeCompare(y)).slice(0, 40);
  setHTML("detNow", `<tr><th>class</th><th>now</th><th>seen (unique)</th></tr>` + (names.length ?
    names.map((c) => `<tr><td style="color:${clsColor(c)}">${esc(c)}</td><td>${esc(now_[c] || 0)}</td><td>${esc(uniq[c] || 0)}</td></tr>`).join("") :
    `<tr><td colspan="3" class="dim">nothing detected yet</td></tr>`));
  const rt = (det.recent_tracks || []);
  setHTML("trackSlots", rt.map((x) => `<div class="slot">${thumb(x.snapshot)}<div class="cap" style="color:${clsColor(String(x.cls))}">${esc(x.cls)} #${esc(x.id)}</div>
    <div class="cap">${tstr(x.first)} · ${((x.conf || 0) * 100).toFixed(0)}%</div></div>`).join("") || `<p class="note">Detected objects appear here with a snapshot.</p>`);
  });
  safe("position", () => {
  setText("posInfo", t.time ? `UTC ${t.time}` : t.receiver_utc ? `RX UTC ${t.receiver_utc}` : "");
  setHTML("posKv", kv([["fix / satellites", `${t.fix || "—"} · ${t.sats_used ?? 0} used / ${t.sats_seen ?? 0} tracked`, fixOk ? "ok" : "warn"],
    ["lat, lon", t.lat != null ? `${f(t.lat, 6)}, ${f(t.lon, 6)}` : s.home ? `no fix · reference ${f(s.home[0], 6)}, ${f(s.home[1], 6)} (${s.home_source || "operator"})` : "no fix"],
    ["alt / speed / course", `${f(t.alt_m, 1, " m MSL")} · ${f(t.speed_mps, 2, " m/s")} · ${f(t.track_deg, 0, "°")}`],
    ["ellipsoid height", t.alt_hae_m != null ? `${f(t.alt_hae_m, 1, " m")} (geoid ${f(t.geoid_sep_m, 1, " m")})` : "—"],
    ["error est. H / V", `${f(t.eph_m, 1, " m")} / ${f(t.epv_m, 1, " m")}`],
    ["HDOP / VDOP / PDOP", `${f(t.hdop, 2)} / ${f(t.vdop, 2)} / ${f(t.pdop, 2)}`],
    ["receiver UTC", t.receiver_utc ? `${t.receiver_utc}${t.utc_valid ? "" : " (unverified)"}` : "—"],
    ["C/N0 best / mean", cn0.length ? `${Math.max(...cn0)} / ${(cn0.reduce((x, y) => x + y, 0) / cn0.length).toFixed(1)} dB-Hz` : "no signal"],
    ["time to first fix", t.ttff_s != null ? `${t.ttff_s} s${t.ttff_s < 2 ? " (already fixed at start)" : " after app start"}` : `searching ${listening != null ? hms(listening) : "—"}`]]));
  });
  safe("log", () => {
  const logs = [...(s.log || []), ...((u.events || []).map((e) => ({...e, kind: "UAV:" + e.kind})))].sort((x, y) => x.t - y.t).slice(-80);
  const kc = (k) => (k.includes("DETECT") || k.includes("FOUND") ? "ok" : /REJECT|FAIL|ERROR/.test(k) ? "bad" : k.startsWith("UAV") ? "aqua" : "yel");
  setLog("chat", logs.map((e) => `<div><span class="dim">[${tstr(e.t)}]</span> <span class="${kc(String(e.kind))}">&lt;${esc(e.kind)}&gt;</span> ${esc(e.msg)}</div>`).join(""));
  });
  safe("telemetry", () => {
  const acc = a.accuracy_m || {};
  setHTML("fixTiles", tile("FIX", t.fix || "—", t.source || "", fixOk ? "ok" : "warn") + tile("SATS USED/SEEN", `${t.sats_used ?? 0}/${t.sats_seen ?? 0}`) +
    tile("TTFF", t.ttff_s != null ? `${t.ttff_s}s` : "—", "since UAV app start") + tile("POSITION", t.lat != null ? `${f(t.lat, 5)}` : "NO FIX", t.lat != null ? `${f(t.lon, 5)} · ±${f(t.eph_m, 0)} m` : "", fixOk ? "ok" : "warn") +
    tile("ALT (MSL)", f(t.alt_m, 1, " m"), t.alt_hae_m != null ? `ellipsoid ${f(t.alt_hae_m, 1)} m` : "") + tile("FIX AVAILABILITY", f(a.fix_availability_pct, 1, "%"), "last 60 min") +
    tile("CEP50 / CEP95", acc.cep50 != null ? `${acc.cep50}/${acc.cep95}` : "—", "metres (stationary)") + tile("2DRMS", f(acc.drms2, 2, " m")) +
    tile("DISTANCE", f(a.distance_m, 1, " m")) + tile("MAX SPEED", f((a.speed_mps || {}).max, 2, " m/s")) +
    tile("ALT MIN/MAX", (a.alt_m || {}).n ? `${f(a.alt_m.min, 0)}/${f(a.alt_m.max, 0)}` : "—", "m") + tile("HDOP MEAN", f((a.hdop || {}).mean, 2)) +
    tile("FROM HOME", f((a.from_home_m || {}).current, 1, " m"), `max ${f((a.from_home_m || {}).max, 1, " m")}`) + tile("TELEMETRY LATENCY", f((s.telemetry_stats || {}).latency_ms, 1, " ms")) +
    tile("BEST C/N0", cn0.length ? Math.max(...cn0) : "—", "dB-Hz (≥35 good)", cn0.length && Math.max(...cn0) >= 35 ? "ok" : "warn") +
    tile("NMEA RATE", f(t.nmea_rate_hz, 1), "sentences / s") + tile("SEARCHING", listening != null ? hms(listening) : "—", t.ttff_s != null ? "fixed" : "since receiver opened"));
  renderReceiver(t, sats, cn0, listening);
  });
  safe("sky", () => {
  if (tab === "telemetry") {
    // redraw only when the data changed: repainting identical charts every second is what made the page flicker
    const skySig = JSON.stringify(sats);
    if ($("sky")._sig !== skySig) { $("sky")._sig = skySig; drawSky(sats); }
    setText("skyInfo", `${sats.length} tracked`);
    const snr = chart("cSnr", "bar", [{label: "C/N0", data: [], backgroundColor: []}], {plugins: {legend: {display: false}}, scales: {y: {beginAtZero: true, max: 55}}});
    const snrSig = JSON.stringify(sats.map((x) => [x[0], x[1], x[4]]));
    if (snr && snr._sig !== snrSig) { snr._sig = snrSig; snr.data.labels = sats.map((x) => `${x[0][0]}${x[1]}`); snr.data.datasets[0].data = sats.map((x) => x[4] || 0);
      snr.data.datasets[0].backgroundColor = sats.map((x) => CONS_COL[x[0]] || "#fff"); snr.update("none"); }
    const by = (s.analytics || {}).sky || {};
    const cons = chart("cCons", "doughnut", [{data: [], backgroundColor: []}], {plugins: {legend: {position: "right"}}});
    const consSig = JSON.stringify(by);
    if (cons && cons._sig !== consSig) { cons._sig = consSig; cons.data.labels = Object.keys(by).map((k) => `${k} (${by[k].used}/${by[k].seen})`); cons.data.datasets[0].data = Object.values(by).map((x) => x.seen);
      cons.data.datasets[0].backgroundColor = Object.keys(by).map((k) => CONS_COL[k] || "#fff"); cons.update("none"); }
  }
  });
  updateMaps(s);
  safe("security", () => {
  const rec = L_.record || {}, rej = rec.rejected || {}, dr = L_.drops || {};
  setHTML("secKv", kv([["state", up ? "UP (SECURE)" : L_.state, up ? "ok" : "bad"], ["suite", L_.suite], ["session id", L_.session_id], ["session age", f(L_.session_age_s, 0, " s")],
    // labels are short on purpose: a label cut with "…" says nothing (the tooltip of each value has the long form)
    ["UAV", `${L_.uav_id || "—"} @ ${L_.uav_addr || "—"}`], ["PQC handshakes", `${L_.handshakes_ok} ok · ${L_.handshakes_fail} failed`],
    ["handshake time", `GCS ${f(L_.last_handshake_ms, 1, " ms")} · UAV ${f((u.link || {}).last_handshake_ms, 1, " ms")} (with Wi-Fi)`],
    ["cached rekeys", `${L_.cached_rekeys_ok} ok · ${L_.cached_rekey_rejects} rejected · last ${f((u.link || {}).last_cached_rekey_ms, 1, " ms")}`],
    ["PQ ratchets", `${L_.pq_ratchets} · last ${f((u.link || {}).last_pq_ratchet_ms, 2, " ms")}`], ["records rx / tx", `${L_.rx_records} / ${L_.tx_records}`],
    // each node checks its cryptography against published values when it starts, and does not start if a check fails
    ...[["crypto self-test GCS", s.crypto], ["crypto self-test UAV", u.crypto]].map(([k, c]) => [k, !c ? "—" :
      `${c.ok ? "PASS" : "FAILED: " + (c.failed || []).join("; ")} · ${c.checks} checks · ${f(c.ms, 0, " ms")} · liboqs ${c.liboqs} · ${tstr(c.at)}`, !c ? "" : c.ok ? "ok" : "bad"]),
    ["round trip", f(L_.rtt_ms, 2, " ms")], ["clock offset", f(L_.clock_offset_ms, 1, " ms")],
    // two healthy clocks stay together; the clock of a WSL VM can run at the wrong rate (measured on this laptop: 8.3 % slow)
    ["PC clock", clockBad ? `${Math.abs(L_.clock_rate_pct).toFixed(1)} % ${L_.clock_rate_pct > 0 ? "SLOW" : "FAST"} · see note` :
      `steady${L_.clock_steps ? ` · ${L_.clock_steps} jump(s)` : ""}`, clockBad ? "bad" : L_.clock_steps ? "warn" : "ok"],
    ["UDP buffer / drops", `${L_.rcvbuf_bytes ? Math.round(L_.rcvbuf_bytes / 1024) + " KB" : "—"} / ${(L_.udp || {}).RcvbufErrors ?? "—"}`,
      ((L_.udp || {}).RcvbufErrors || 0) > 0 && (L_.rcvbuf_bytes || 0) < 2e6 ? "warn" : ""],
    ["last error", L_.last_error || "none"]]));
  // no "fix" is offered: a WSL restart was measured to help for about two minutes only, and the cause is not known
  setNote("clockNote", clockBad ? `This computer's clock runs ${Math.abs(L_.clock_rate_pct).toFixed(1)} % ${L_.clock_rate_pct > 0 ? "slow" : "fast"} against the UAV's ` +
    `(the clock of the WSL virtual machine, not the UAV or the link). Video, boxes and frame rate are timed on the camera's clock and are not affected; ` +
    `latency figures are estimates, and times stamped by this computer can be up to 3 s off.` : "");
  const R = (k) => (rej[k] || 0) + (dr[k] || 0);
  setHTML("rejTiles", tile("AUTH FAIL", R("auth-fail"), "bad tag / tampered", R("auth-fail") ? "bad" : "ok") + tile("REPLAY (DUP)", R("duplicate"), "", R("duplicate") ? "warn" : "ok") +
    tile("STALE", R("stale") + R("stale-epoch"), "outside window / old epoch") + tile("WRONG SESSION", R("wrong-session")) + tile("UNKNOWN SESSION", R("unknown-session")) +
    tile("MALFORMED", R("malformed")) + tile("HANDSHAKE REJECTS", L_.handshakes_fail ?? 0) +
    // work refused because too much of it was asked for by senders that did not authenticate (flood protection)
    tile("FLOOD LIMITED", (dr["hello-flood"] || 0) + (dr["reject-not-sent"] || 0) + (dr["ratchet-rate"] || 0)) +
    // web requests the dashboard's own server refused: another site, or another host name, reaching for this page
    tile("WEB REFUSED", Object.values(s.http_refused || {}).reduce((x, y) => x + y, 0), "cross-site / foreign host", Object.keys(s.http_refused || {}).length ? "warn" : ""));
  setHTML("epochKv", kv(Object.entries(rec.epochs || {}).map(([k, e]) => [k, `epoch ${e}`])));
  setLog("linkEv", ((u.events || []).filter((e) => !["IMAGE", "VIDEO", "REC", "CAMERA"].includes(e.kind))).slice(-40)
    .map((e) => `<div><span class="dim">[${tstr(e.t)}]</span> <span class="aqua">${esc(e.kind)}</span> ${esc(e.msg)}</div>`).join(""));
  });
  safe("media", () => {
  const pu = u.photos_on_uav;
  setText("photoInfo", pu ? `${pu.count} on the Pi · ${(pu.bytes / 1e6).toFixed(1)} MB` : "");
  // the newest 16 photos and 10 recordings from the state, or with SHOW ALL everything the ground station holds; newest first
  const mc = s.media_counts || {}, lib = media.all || {};
  const imgs = media.allImg && lib.images ? lib.images : (s.images || []);
  const recs = media.allRec && lib.recordings ? lib.recordings : (s.recordings || []);
  setText("imgInfo", mc.images != null ? `${imgs.length} of ${Math.max(mc.images, imgs.length)} shown · newest first` : "");
  setText("imgAllNote", media.allImg && !lib.images ? "loading…" : "");
  setText("recAllNote", media.allRec && !lib.recordings ? "loading…" : mc.recordings != null ? `${recs.length} of ${Math.max(mc.recordings, recs.length)} decrypted recordings shown · newest first` : "");
  // (pictures beyond the first rows are fetched when they are scrolled to: SHOW ALL may be some hundred photos)
  setHTML("imgSlots", imgs.map((i, k) => `<div class="slot">${i.url ? (k < 16 ? thumb(i.url) : thumb(i.url).replace("<img ", `<img loading="lazy" `)) : `<div class="thumb"></div>`}
    <div class="cap">${esc(i.name)}</div><div class="cap">${esc((i.meta || {}).width)}×${esc((i.meta || {}).height)} ${esc((i.meta || {}).mode)} · ${(((i.size_plain || i.size) || 0) / 1024).toFixed(0)} KB</div>
    <div class="cap">SHA-256 <b class="${i.integrity === "PASS" ? "ok" : "bad"}">${esc(i.integrity)}</b> · ${esc(i.seconds)} s</div>
    <div class="cap">${i.kind === "photo_enc" ? `from Pi storage · decrypt <b class="${i.decrypt === "PASS" ? "ok" : "bad"}">${esc(i.decrypt)}</b>`
      : (i.meta || {}).stored_as ? `on Pi: ${esc(i.meta.stored_as)}` : ""}</div>
    <div class="cap">${i.received_at ? `received ${new Date(i.received_at * 1000).toLocaleString()}` : ""}</div></div>`).join("") || `<p class="note">Press ◘ PHOTO on the hotbar.</p>`);
  setHTML("detSlots", $("trackSlots")._h || "");
  // preload="metadata": with byte-range support the player reads only the index of the file until PLAY is pressed
  // (the first ten; of the rest nothing is read before PLAY)
  setHTML("recRx", recs.map((r, k) => `<div class="slot" style="grid-column:span 2">${r.mp4 ? `<video controls preload="${k < 10 ? "metadata" : "none"}" src="${esc(r.mp4)}" style="width:100%;aspect-ratio:16/9;background:#000"></video>` : `<div class="thumb"></div>`}
    <div class="cap">${esc(r.name)}</div><div class="cap">transfer ${esc(r.integrity)} · decrypt <b class="${r.decrypt === "PASS" ? "ok" : "bad"}">${esc(r.decrypt)}</b> · ${esc(r.frames)} frames · ${esc(r.decrypt_ms)} ms</div>
    <div class="cap">${r.received_at ? `received ${new Date(r.received_at * 1000).toLocaleString()}` : ""}</div></div>`).join(""));
  const au = s.audio || {}, aou = u.audio_on_uav, lv = au.live;
  setText("audInfo", aou ? `${aou.count} on the Pi · ${(aou.bytes / 1e6).toFixed(1)} MB · ${aou.sources} waiting in the inbox` : "");
  setNote("audLive", lv ? `live clip ${lv.tag}: ${lv.blocks} blocks here, ${lv.on_air} of them from the air${lv.expected ? ` (of ${lv.expected})` : ""}${lv.done ? " — complete, root and signature checked" : lv.has_head ? " — receiving" : " — waiting for its head"}` : "");
  const ok = (v) => `<b class="${v === "PASS" ? "ok" : "bad"}">${esc(v)}</b>`;
  setHTML("audRx", (au.clips || []).map((c) => `<div class="slot">${c.url ? `<audio controls preload="none" src="${esc(c.url)}" style="width:100%;height:32px"></audio>` : `<div style="height:32px"></div>`}
    <div class="cap">${esc(c.name)}</div>
    <div class="cap">signature ${ok(c.signature)} · open ${ok(c.decrypt)} · ${esc(c.how)}</div>
    <div class="cap">${c.url ? `${esc(c.codec)} · ${f(c.duration_s, 1, " s")} · ${esc(c.blocks)} blocks × ${esc(c.block_bytes)} B` : ""}</div>
    <div class="cap">${c.url ? `clip no. ${esc(c.clip_no)} · chain: ${esc(c.chain)}` : ""}</div>
    <div class="cap">${c.captured_ms ? `captured ${new Date(c.captured_ms).toLocaleString()}${c.lat != null ? ` at ${f(c.lat, 5)}, ${f(c.lon, 5)}` : " (no fix)"}` : ""}</div>
    <div class="cap">${c.how === "live" ? `on the air ${esc(c.live_blocks_on_air)} blocks · fetched again ${esc(c.live_blocks_repaired)}` : c.url ? `transfer ${esc(c.integrity)} · ${f(c.seconds, 2, " s")}` : ""}</div>
    <div class="cap">${c.url ? `seconds <input class="t0" type="number" min="0" step="0.5" value="0" style="width:58px"> to <input class="t1" type="number" min="0" step="0.5" value="5" style="width:58px"> <button data-ex="${esc(c.name)}">EXCERPT</button>` : ""}</div></div>`).join("") ||
    `<p class="note">No clip received yet. LIST ON UAV, then FETCH — or SEAL + SEND LIVE.</p>`);
  });
  safe("data", () => {
  const db = s.db || {};
  setHTML("dbKv", kv(Object.entries(db).map(([k, val]) => [k, k === "db_bytes" ? `${(val / 1e6).toFixed(2)} MB` : val, k === "last_error" || (k === "dropped" && val) ? "warn" : ""])));
  const sy = u.system || {}, w = sy.wifi || {}, lcd = u.lcd || {}, sto = u.storage || {};
  setHTML("sysKv", kv([["status age", u.rx_at ? f(s.now - u.rx_at, 1, " s") : "no status"], ["CPU", f(sy.cpu_percent, 1, "%")], ["per core", (sy.per_cpu || []).join(" / ")],
    ["memory", `${f(sy.mem_percent, 1, "%")} (${sy.mem_used_mb ?? "—"} MB)`], ["temperature", f(sy.temp_c, 1, " °C"), sy.temp_c > 70 ? "warn" : ""],
    ["throttled", sy.throttled, sy.throttled && sy.throttled !== "0x0" ? "warn" : "ok"], ["Wi-Fi", w.signal_dbm != null ? `${w.signal_dbm} dBm` : "—"],
    ["SD card free", sto.free_mb != null ? `${(sto.free_mb / 1000).toFixed(1)} GB` : "—", sto.free_mb != null && sto.free_mb < 1000 ? "warn" : ""],
    ["LCD", lcd.ok ? `OK · ${lcd.updates} updates` : `ERROR ${lcd.error || ""}`, lcd.ok ? "ok" : "bad"], ["camera", `${cam.sensor || "—"} · ${cam.available ? "ready" : cam.error || "n/a"}`],
    ["unsent telemetry", u.telemetry_backlog ?? 0]]));
  });
}

async function poll() {
  try {
    const st = await fetchJSON("/api/state", 8000);
    if (!st || !st.link) throw new Error("not a state object");
    S = st;
    S.fetched = Date.now() / 1000;
    $("bServer").classList.remove("show");
    window.K6G_STATE = S;
    // the dashboard files changed on the server (new version deployed): reload so no stale page keeps running
    if (S.build) { if (poll.build && poll.build !== S.build) { location.reload(); return; } poll.build = S.build; }
    // the ground station was restarted, or was unreachable for a while: the old video connection is dead and the
    // browser gives no event for that, so open it again; detection tracks belong to the old process too
    if (poll.down || (poll.started && S.started && poll.started !== S.started)) {
      boxes.clear(); lastSeq = null; serverOffset = null;
      if (!document.hidden) setStream();
    }
    poll.started = S.started || poll.started; poll.down = false;
  } catch (e) {
    poll.down = true;
    $("bServer").classList.add("show");
    $("bUav").classList.remove("show");            // what we last knew about the UAV says nothing while the server is away
    $("nosig").style.display = "flex"; noSignal = true;
    setTimeout(poll, 1500);
    return;
  }
  try { render(S); } catch (e) { console.error("render", e); }
  try { mediaTick(S); } catch (e) { console.error("media", e); }
  setTimeout(poll, 1000);
}
poll();
