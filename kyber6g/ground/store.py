"""Ground-station persistence (SQLite, WAL) with a single writer thread.

Everything the GCS receives or measures is stored: telemetry (incl. late
store-and-forward backfill), satellite snapshots, object detections and
tracks, images, recordings, link/security counters, video and system stats,
sessions and events. Writes are queued so the network receive thread never
blocks on disk.
"""
import json
import queue
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS runs (id INTEGER PRIMARY KEY, started REAL, host TEXT, note TEXT);
CREATE TABLE IF NOT EXISTS telemetry (
  id INTEGER PRIMARY KEY, run_id INTEGER, ts REAL, rx_ts REAL, n INTEGER, backfill INTEGER,
  source TEXT, mode INTEGER, fix TEXT, lat REAL, lon REAL, alt_m REAL, alt_msl_m REAL,
  speed_mps REAL, track_deg REAL, climb_mps REAL, eph_m REAL, epv_m REAL,
  hdop REAL, vdop REAL, pdop REAL, sats_used INTEGER, sats_seen INTEGER, gnss_time TEXT,
  latency_ms REAL, epoch INTEGER, session_id TEXT);
CREATE INDEX IF NOT EXISTS i_tm_ts ON telemetry(ts);
CREATE TABLE IF NOT EXISTS satellites (
  id INTEGER PRIMARY KEY, ts REAL, constellation TEXT, prn INTEGER, az REAL, el REAL, snr REAL, used INTEGER);
CREATE INDEX IF NOT EXISTS i_sat_ts ON satellites(ts);
CREATE TABLE IF NOT EXISTS detections (
  id INTEGER PRIMARY KEY, ts REAL, frame_seq INTEGER, track_id INTEGER, cls TEXT, conf REAL,
  x1 REAL, y1 REAL, x2 REAL, y2 REAL, lat REAL, lon REAL);
CREATE INDEX IF NOT EXISTS i_det_ts ON detections(ts);
CREATE TABLE IF NOT EXISTS tracks (
  track_id INTEGER, cls TEXT, first_ts REAL, last_ts REAL, hits INTEGER, best_conf REAL,
  snapshot TEXT, lat REAL, lon REAL, PRIMARY KEY (track_id, cls));
CREATE TABLE IF NOT EXISTS images (
  id INTEGER PRIMARY KEY, ts REAL, name TEXT, bytes INTEGER, sha256 TEXT, integrity TEXT,
  transfer_s REAL, width INTEGER, height INTEGER, mode TEXT, lat REAL, lon REAL, meta TEXT);
CREATE TABLE IF NOT EXISTS recordings (
  id INTEGER PRIMARY KEY, ts REAL, name TEXT, bytes INTEGER, integrity TEXT, decrypt TEXT,
  frames INTEGER, segments INTEGER, mp4 TEXT, meta TEXT);
CREATE TABLE IF NOT EXISTS link_stats (
  id INTEGER PRIMARY KEY, ts REAL, state TEXT, session_id TEXT, rtt_ms REAL, rx_records INTEGER,
  tx_records INTEGER, auth_fail INTEGER, duplicate INTEGER, stale INTEGER, handshakes INTEGER,
  cached_rekeys INTEGER, pq_ratchets INTEGER, raw TEXT);
CREATE TABLE IF NOT EXISTS video_stats (
  id INTEGER PRIMARY KEY, ts REAL, fps REAL, kbps REAL, display_latency_ms REAL, network_latency_ms REAL,
  decode_ms REAL, frames_complete INTEGER, frames_lost INTEGER, chunk_loss_pct REAL, det_fps REAL, det_ms REAL);
CREATE TABLE IF NOT EXISTS system_stats (
  id INTEGER PRIMARY KEY, ts REAL, cpu REAL, mem REAL, temp_c REAL, throttled TEXT, wifi_dbm REAL, cam_fps REAL);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, ts REAL, kind TEXT, msg TEXT);
CREATE TABLE IF NOT EXISTS finder_passes (
  id INTEGER PRIMARY KEY, ts REAL, frame_ts REAL, infer_ms REAL, threshold REAL, best TEXT, shown TEXT);
CREATE INDEX IF NOT EXISTS i_fp_ts ON finder_passes(ts);
"""


# Columns added after the first release; applied to existing databases on open.
MIGRATIONS = {
    "telemetry": {"alt_hae_m": "REAL", "geoid_sep_m": "REAL", "receiver_utc": "TEXT", "gga_quality": "INTEGER",
                  "cn0_max": "REAL", "cn0_mean": "REAL", "sats_tracked": "INTEGER", "uav_boot": "REAL"},
}


class Store:
    def __init__(self, path):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.q = queue.Queue(maxsize=20000)
        self.lock = threading.Lock()
        self.dropped = 0
        self.written = 0
        self.last_error = None
        con = sqlite3.connect(self.path)
        con.executescript(SCHEMA)
        for table, cols in MIGRATIONS.items():
            have = {r[1] for r in con.execute(f"PRAGMA table_info({table})")}
            for col, typ in cols.items():
                if col not in have:
                    con.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typ}")
        self.run_id = con.execute("INSERT INTO runs(started, host) VALUES (?, ?)", (time.time(), "gcs")).lastrowid
        con.commit()
        con.close()
        threading.Thread(target=self._writer, name="db-writer", daemon=True).start()

    # ------------------------------------------------------------ writes
    def _put(self, sql, args):
        try:
            self.q.put_nowait((sql, args))
        except queue.Full:
            self.dropped += 1

    def _writer(self):
        con = sqlite3.connect(self.path, check_same_thread=False, timeout=30)
        while True:
            items = [self.q.get()]
            t_end = time.time() + 0.2
            while time.time() < t_end and len(items) < 2000:
                try:
                    items.append(self.q.get(timeout=0.05))
                except queue.Empty:
                    break
            with self.lock:
                try:
                    for sql, args in items:
                        con.execute(sql, args)
                    con.commit()
                    self.written += len(items)
                    continue
                except Exception as e:                   # sqlite3.Error, or a value SQLite cannot bind (OverflowError ...)
                    self.last_error = f"{type(e).__name__}: {e}"
                try:
                    con.rollback()
                except sqlite3.Error:
                    pass
                # One bad row must cost one row, not the whole batch (and never the writer thread): retry one by one.
                for sql, args in items:
                    try:
                        con.execute(sql, args)
                        con.commit()
                        self.written += 1
                    except Exception as e:
                        self.last_error = f"{type(e).__name__}: {e}"
                        self.dropped += 1
                        try:
                            con.rollback()
                        except sqlite3.Error:
                            pass

    def telemetry(self, tm: dict, latency_ms, epoch, session_id):
        sats = tm.get("satellites")
        cn0 = [s[4] for s in sats if isinstance(s, list) and len(s) > 4 and s[4] is not None] if isinstance(sats, list) else []
        self._put("""INSERT INTO telemetry(run_id, ts, rx_ts, n, backfill, source, mode, fix, lat, lon, alt_m,
                     alt_msl_m, speed_mps, track_deg, climb_mps, eph_m, epv_m, hdop, vdop, pdop, sats_used,
                     sats_seen, gnss_time, latency_ms, epoch, session_id,
                     alt_hae_m, geoid_sep_m, receiver_utc, gga_quality, cn0_max, cn0_mean, sats_tracked, uav_boot)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (self.run_id, tm.get("ts"), time.time(), tm.get("n"), 1 if tm.get("backfill") else 0,
                   tm.get("source"), tm.get("mode"), tm.get("fix"), tm.get("lat"), tm.get("lon"), tm.get("alt_m"),
                   tm.get("alt_msl_m"), tm.get("speed_mps"), tm.get("track_deg"), tm.get("climb_mps"),
                   tm.get("eph_m"), tm.get("epv_m"), tm.get("hdop"), tm.get("vdop"), tm.get("pdop"),
                   tm.get("sats_used"), tm.get("sats_seen"), tm.get("time"), latency_ms, epoch, session_id,
                   tm.get("alt_hae_m"), tm.get("geoid_sep_m"), tm.get("receiver_utc"), tm.get("gga_quality"),
                   max(cn0) if cn0 else None, round(sum(cn0) / len(cn0), 1) if cn0 else None,
                   tm.get("sats_seen"), tm.get("boot")))

    def satellites(self, ts, sats):
        for s in sats:
            if isinstance(s, (list, tuple)) and len(s) >= 6:        # a malformed row is skipped, the rest is kept
                self._put("INSERT INTO satellites(ts, constellation, prn, az, el, snr, used) VALUES (?,?,?,?,?,?,?)",
                          (ts, *s[:6]))

    def detection(self, ts, seq, det, lat, lon):
        self._put("INSERT INTO detections(ts, frame_seq, track_id, cls, conf, x1, y1, x2, y2, lat, lon) "
                  "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                  (ts, seq, det.get("uid", det.get("id")), det["cls"], det["conf"], *det["box"], lat, lon))

    def track(self, tid, cls, first, last, hits, conf, snapshot, lat, lon):
        self._put("""INSERT INTO tracks(track_id, cls, first_ts, last_ts, hits, best_conf, snapshot, lat, lon)
                     VALUES (?,?,?,?,?,?,?,?,?) ON CONFLICT(track_id, cls) DO UPDATE SET
                     last_ts=excluded.last_ts, hits=excluded.hits, best_conf=max(best_conf, excluded.best_conf),
                     snapshot=coalesce(excluded.snapshot, snapshot)""",
                  (tid, cls, first, last, hits, conf, snapshot, lat, lon))

    def image(self, info, lat, lon):
        m = info.get("meta") or {}
        self._put("INSERT INTO images(ts, name, bytes, sha256, integrity, transfer_s, width, height, mode, lat, lon, meta) "
                  "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                  (time.time(), info.get("name"), info.get("size"), info.get("sha256"), info.get("integrity"),
                   info.get("seconds"), m.get("width"), m.get("height"), m.get("mode"), lat, lon, json.dumps(info, default=str)))

    def recording(self, e):
        self._put("INSERT INTO recordings(ts, name, bytes, integrity, decrypt, frames, segments, mp4, meta) VALUES (?,?,?,?,?,?,?,?,?)",
                  (time.time(), e.get("name"), e.get("size"), e.get("integrity"), e.get("decrypt"), e.get("frames"),
                   e.get("segments"), e.get("mp4"), json.dumps(e, default=str)))

    def link_stats(self, L):
        d, rec = L.get("drops") or {}, (L.get("record") or {}).get("rejected") or {}
        self._put("""INSERT INTO link_stats(ts, state, session_id, rtt_ms, rx_records, tx_records, auth_fail, duplicate,
                     stale, handshakes, cached_rekeys, pq_ratchets, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                  (time.time(), L.get("state"), L.get("session_id"), L.get("rtt_ms"), L.get("rx_records"),
                   L.get("tx_records"), d.get("auth-fail", 0) + rec.get("auth-fail", 0),
                   d.get("duplicate", 0) + rec.get("duplicate", 0),
                   d.get("stale", 0) + rec.get("stale", 0) + rec.get("stale-epoch", 0),
                   L.get("handshakes_ok"), L.get("cached_rekeys_ok"), L.get("pq_ratchets"), json.dumps(L, default=str)))

    def video_stats(self, v, det):
        self._put("""INSERT INTO video_stats(ts, fps, kbps, display_latency_ms, network_latency_ms, decode_ms,
                     frames_complete, frames_lost, chunk_loss_pct, det_fps, det_ms) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                  (time.time(), v.get("fps"), v.get("kbps"), v.get("display_latency_ms"), v.get("network_latency_ms"),
                   v.get("decode_ms"), v.get("frames_complete"), v.get("frames_lost"), v.get("chunk_loss_pct"),
                   det.get("fps"), det.get("infer_ms")))

    def system_stats(self, u):
        sy, cam = u.get("system") or {}, u.get("camera") or {}
        self._put("INSERT INTO system_stats(ts, cpu, mem, temp_c, throttled, wifi_dbm, cam_fps) VALUES (?,?,?,?,?,?,?)",
                  (time.time(), sy.get("cpu_percent"), sy.get("mem_percent"), sy.get("temp_c"), sy.get("throttled"),
                   (sy.get("wifi") or {}).get("signal_dbm"), cam.get("fps")))

    def finder_pass(self, ts, frame_ts, infer_ms, threshold, best, shown):
        """One finder pass: the strongest score per word (even below the threshold) and what was shown."""
        self._put("INSERT INTO finder_passes(ts, frame_ts, infer_ms, threshold, best, shown) VALUES (?,?,?,?,?,?)",
                  (ts, frame_ts, infer_ms, threshold, json.dumps(best), json.dumps([[d["cls"], d["conf"]] for d in shown])))

    def event(self, kind, msg):
        self._put("INSERT INTO events(ts, kind, msg) VALUES (?,?,?)", (time.time(), kind, str(msg)[:2000]))

    # ------------------------------------------------------------- reads
    def query(self, sql, args=()):
        con = sqlite3.connect(f"file:{self.path}?mode=ro", uri=True)
        con.row_factory = sqlite3.Row
        try:
            return [dict(r) for r in con.execute(sql, args)]
        finally:
            con.close()

    def columns(self, table):
        """Column names of a table, for an export that has no rows (its header line is still written)."""
        if not table.isidentifier():
            raise ValueError("not a table name")
        return [r["name"] for r in self.query(f"PRAGMA table_info({table})")]

    def counts(self):
        tables = ("telemetry", "satellites", "detections", "tracks", "images", "recordings", "link_stats",
                  "video_stats", "system_stats", "events", "runs", "finder_passes")
        out = {}
        for t in tables:
            out[t] = self.query(f"SELECT count(*) AS n FROM {t}")[0]["n"]
        out["db_bytes"] = self.path.stat().st_size + sum(
            p.stat().st_size for p in self.path.parent.glob(self.path.name + "-*") if p.exists())
        out["queued"] = self.q.qsize()
        out["written"] = self.written
        out["dropped"] = self.dropped
        if self.last_error:
            out["last_error"] = self.last_error
        return out
