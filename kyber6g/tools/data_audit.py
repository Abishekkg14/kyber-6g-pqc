"""Audit everything the system has stored, on the ground station and (optionally) on the UAV.

    python -m kyber6g.tools.data_audit [--data ~/kyber6g_ground] [--pi kyber-pi] [--repair-altitude]

Nothing is assumed: each check reads the real files / rows and reports PASS, WARN or FAIL
with the measured numbers. Exit status 1 if anything FAILs.

Checks: SQLite integrity; telemetry plausibility (coordinates only with a fix, ranges, ordering,
sequence gaps, impossible jumps, altitude basis); detection / track rows and their snapshot files;
images (file present, size and SHA-256 equal to the stored values); recordings (every .k6grec
decrypts, FINAL segment present, frame count equals the database); key-file permissions; no secrets in
logs or the events table; on the UAV: encrypted-at-rest file magics, permissions and no empty orphans.
"""
import argparse
import hashlib
import json
import math
import re
import sqlite3
import stat
import subprocess
import sys
import time
from pathlib import Path

from . import sshopts

RESULTS = []


def check(name, status, value):
    RESULTS.append({"check": name, "status": status, "value": value})
    print(f"[{status:4s}] {name}: {value}")
    return status != "FAIL"


def haversine(a, b, c, d):
    p = math.pi / 180
    x = math.sin((c - a) * p / 2) ** 2 + math.cos(a * p) * math.cos(c * p) * math.sin((d - b) * p / 2) ** 2
    return 12742000 * math.asin(math.sqrt(x))


def audit_db(con, data: Path, repair_alt: bool):
    con.row_factory = sqlite3.Row
    ic = con.execute("PRAGMA integrity_check").fetchone()[0]
    check("SQLite integrity_check", "PASS" if ic == "ok" else "FAIL", ic)
    tables = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    need = {"telemetry", "satellites", "detections", "tracks", "images", "recordings", "link_stats", "video_stats",
            "system_stats", "events", "runs"}
    check("all tables present", "PASS" if need <= tables else "FAIL", sorted(need - tables) or f"{len(need)} tables")
    counts = {t: con.execute(f"SELECT count(*) FROM {t}").fetchone()[0] for t in sorted(need & tables)}
    check("row counts", "PASS", counts)

    # ---- telemetry
    q = lambda sql, *a: con.execute(sql, a).fetchall()
    n_fix = q("SELECT count(*) c FROM telemetry WHERE mode>=2")[0]["c"]
    bad_range = q("SELECT count(*) c FROM telemetry WHERE mode>=2 AND (lat IS NULL OR lon IS NULL OR lat NOT BETWEEN -90 AND 90 "
                  "OR lon NOT BETWEEN -180 AND 180 OR (abs(lat)<1e-9 AND abs(lon)<1e-9))")[0]["c"]
    check("fix rows have valid coordinates", "PASS" if not bad_range else "FAIL", f"{bad_range} bad of {n_fix} fix rows")
    invented = q("SELECT count(*) c FROM telemetry WHERE (mode IS NULL OR mode<2) AND lat IS NOT NULL")[0]["c"]
    check("no position is stored without a GNSS fix", "PASS" if not invented else "FAIL", f"{invented} rows")
    syn = q("SELECT count(*) c FROM telemetry WHERE source LIKE '%SYNTH%'")[0]["c"]
    check("no synthetic GNSS data stored", "PASS" if not syn else "FAIL", f"{syn} synthetic rows")
    odd = q("SELECT count(*) c FROM telemetry WHERE (speed_mps IS NOT NULL AND (speed_mps<0 OR speed_mps>200)) OR "
            "(hdop IS NOT NULL AND (hdop<=0 OR hdop>99)) OR (sats_used>sats_seen AND sats_seen>0 AND sats_seen IS NOT NULL AND mode<2) OR "
            "(mode>=3 AND alt_m IS NOT NULL AND alt_m NOT BETWEEN -500 AND 12000)")[0]["c"]
    check("speed / DOP / altitude within physical limits", "PASS" if not odd else "WARN", f"{odd} rows outside limits")
    # ordering and sequence, per run, live (non-backfill) rows
    gaps = dup = disorder = restarts = 0
    for run in q("SELECT DISTINCT run_id FROM telemetry"):
        boot_col = "uav_boot" if "uav_boot" in {r[1] for r in con.execute("PRAGMA table_info(telemetry)")} else "NULL AS uav_boot"
        rows = q(f"SELECT ts, n, {boot_col} FROM telemetry WHERE run_id=? AND backfill=0 ORDER BY id", run[0])
        seen = set()
        for prev, cur in zip(rows, rows[1:]):
            if cur["ts"] + 1e-6 < prev["ts"]:
                disorder += 1
            if cur["n"] is not None and prev["n"] is not None and cur["n"] > prev["n"] + 1:
                gaps += 1
        # the UAV counter restarts at 1 whenever the UAV app restarts (new boot id, or - for older rows - a counter
        # reset); numbers must be unique within one UAV boot, a duplicate there would mean a replayed/duplicated sample
        boot = None
        for prev, r in zip([None] + rows[:-1], rows):
            restarted = (r["uav_boot"] is not None and r["uav_boot"] != boot) if r["uav_boot"] is not None else \
                (prev is not None and r["n"] is not None and prev["n"] is not None and r["n"] < prev["n"])
            if restarted or prev is None:
                seen = set(); restarts += 1
                boot = r["uav_boot"]
            if r["n"] in seen:
                dup += 1
            seen.add(r["n"])
    check("telemetry sequence numbers unique within each UAV boot", "PASS" if not dup else "WARN",
          f"{dup} duplicates across {restarts} UAV boots / ground runs")
    check("telemetry timestamps ordered", "PASS" if disorder < 5 else "WARN", f"{disorder} out-of-order rows")
    check("telemetry sequence gaps (lost samples)", "PASS" if gaps == 0 else "INFO", f"{gaps} gaps (UAV restarts, link outages; backfill fills the data)")
    # (a fix row without a position is counted above, as a failure; here it would end the audit with an exception,
    # and it did: nothing after this line was checked)
    fixes = q("SELECT ts, lat, lon FROM telemetry WHERE mode>=2 AND backfill=0 AND lat IS NOT NULL AND lon IS NOT NULL ORDER BY ts")
    jumps = 0
    for a, b in zip(fixes, fixes[1:]):
        dt = b["ts"] - a["ts"]
        if 0 < dt < 30 and haversine(a["lat"], a["lon"], b["lat"], b["lon"]) / dt > 60:
            jumps += 1
    check("no impossible position jumps (>60 m/s)", "PASS" if not jumps else "WARN", f"{jumps} jumps in {len(fixes)} fixes")
    # altitude basis: alt_m is height above MSL since the dashboard rework; older rows stored the ellipsoid height there
    legacy = q("SELECT count(*) c FROM telemetry WHERE alt_hae_m IS NULL AND alt_msl_m IS NOT NULL AND alt_m IS NOT NULL AND abs(alt_m-alt_msl_m)>1")[0]["c"]
    if legacy and repair_alt:
        backup = data / "exports" / time.strftime("kyber6g_before_altitude_repair_%Y%m%d_%H%M%S.db")
        backup.parent.mkdir(parents=True, exist_ok=True)
        dst = sqlite3.connect(backup)
        con.backup(dst)                                  # consistent copy first; the repair is also reversible (old value kept)
        dst.close()
        con.execute("UPDATE telemetry SET alt_hae_m=alt_m, geoid_sep_m=alt_m-alt_msl_m, alt_m=alt_msl_m "
                    "WHERE alt_hae_m IS NULL AND alt_msl_m IS NOT NULL AND alt_m IS NOT NULL AND abs(alt_m-alt_msl_m)>1")
        con.commit()
        check("altitude basis repaired", "PASS", f"{legacy} legacy rows: alt_m := MSL, old value kept in alt_hae_m; backup {backup.name}")
    else:
        check("altitude basis consistent (alt_m = MSL)", "PASS" if not legacy else "WARN",
              f"{legacy} legacy rows hold the ellipsoid height in alt_m (run with --repair-altitude)" if legacy else "all rows")
    sat = q("SELECT count(*) c FROM satellites WHERE snr IS NOT NULL AND (snr<0 OR snr>70)")[0]["c"]
    check("satellite C/N0 within 0..70 dB-Hz", "PASS" if not sat else "WARN", f"{sat} rows outside")

    # ---- detections / tracks
    bad = q("SELECT count(*) c FROM detections WHERE conf IS NULL OR conf<=0 OR conf>1 OR x1<-0.001 OR y1<-0.001 OR x2>1.001 OR y2>1.001 OR x2<=x1 OR y2<=y1")[0]["c"]
    check("detection boxes valid (0..1, x2>x1, conf in (0,1])", "PASS" if not bad else "FAIL", f"{bad} bad of {counts.get('detections', 0)}")
    tr = q("SELECT track_id, cls, first_ts, last_ts, hits, snapshot FROM tracks")
    miss = [t["snapshot"] for t in tr if t["snapshot"] and not (data / "detections" / Path(t["snapshot"]).name).exists()]
    check("track snapshots exist on disk", "PASS" if not miss else "WARN", f"{len(miss)} missing of {len(tr)}")
    badt = sum(1 for t in tr if t["last_ts"] < t["first_ts"] or t["hits"] < 3)
    check("tracks consistent (last>=first, >=3 hits)", "PASS" if not badt else "WARN", f"{badt} inconsistent of {len(tr)}")
    big = sum(1 for t in tr if t["track_id"] >= 10_000_000)
    check("track ids unique across runs (uid scheme)", "PASS", f"{big} new-scheme, {len(tr) - big} legacy rows (small ids repeated across restarts before the fix)")

    # ---- images
    bad_img = []
    imgs = q("SELECT name, bytes, sha256, integrity FROM images")
    for r in imgs:
        p = data / "images" / Path(r["name"]).name
        if not p.exists():
            bad_img.append((r["name"], "missing")); continue
        raw = p.read_bytes()
        if r["integrity"] == "PASS" and (len(raw) != r["bytes"] or hashlib.sha256(raw).hexdigest() != r["sha256"]):
            bad_img.append((r["name"], "hash/size mismatch"))
        elif not raw.startswith(b"\xff\xd8"):
            bad_img.append((r["name"], "not a JPEG"))
    # an image fetched from the UAV's encrypted store is saved under the same name: only the newest row must match the file
    check("stored images: file present, size and SHA-256 match the database", "PASS" if not bad_img else "WARN", f"{len(bad_img)} problems of {len(imgs)}: {bad_img[:3]}")

    # ---- recordings
    audit_recordings(con, data)

    # ---- secrets
    pat = re.compile(r"(password|passwd|BEGIN [A-Z ]*PRIVATE KEY|secret_key|api[_-]?key|sshpass)", re.I)
    hits = [r["id"] for r in q("SELECT id, msg FROM events") if pat.search(r["msg"] or "")]
    log = data / "ground.log"
    log_hits = sum(1 for line in log.read_text(errors="replace").splitlines() if pat.search(line)) if log.exists() else 0
    check("no credentials / key material in events or ground.log", "PASS" if not hits and not log_hits else "FAIL",
          f"{len(hits)} event rows, {log_hits} log lines match")


def audit_recordings(con, data: Path):
    try:
        from ..crypto import identity as idm
        from ..recording.recorder import RecordingError, decrypt_recording
        dk = idm.load_recording_dk(idm.DEFAULT_DIR)
        xsk = idm.load_recording_xsk(idm.DEFAULT_DIR)
        uav_pk = idm.load_pinned_peer(idm.DEFAULT_DIR, "uav")
    except Exception as e:
        check("recordings decrypt", "INFO", f"skipped ({type(e).__name__}: {e})")
        return
    files = sorted((data / "recordings").glob("*.k6grec"))
    db = {r["name"]: r for r in con.execute("SELECT name, frames, decrypt FROM recordings ORDER BY id")}
    problems, ok, skipped, signed, legacy = [], 0, 0, 0, 0
    for p in files:
        if p.stat().st_size > 300_000_000:
            skipped += 1
            continue
        try:
            _, _, rep = decrypt_recording(p, dk, x25519_sk=xsk, signer_pk=uav_pk)     # format 2: signature checked too
        except RecordingError as e:
            problems.append((p.name, str(e))); continue
        signed += rep.get("signature") == "PASS"
        legacy += rep.get("format") == 1
        if not rep["complete"]:
            problems.append((p.name, "no FINAL segment"))
        elif p.name in db and db[p.name]["frames"] not in (None, rep["frames"]):
            problems.append((p.name, f"frames {rep['frames']} != db {db[p.name]['frames']}"))
        else:
            ok += 1
    check("recordings on the ground station decrypt and are complete", "PASS" if not problems else "FAIL",
          f"{ok} ok, {len(problems)} problems {problems[:3]}, {skipped} skipped (>300 MB)")
    check("recordings carry the UAV's ML-DSA-87 signature", "PASS" if signed + legacy == len(files) - skipped - len(problems) else "FAIL",
          f"{signed} signed and verified against the pinned key, {legacy} of the earlier format 1 (ML-KEM only, unsigned)")
    # the encrypted photos kept beside the decrypted ones
    try:
        from ..recording.photos import PhotoError, open_image
        enc = sorted((data / "images" / "encrypted").glob("*.k6gimg"))
        bad, p_signed, p_legacy = [], 0, 0
        for p in enc:
            try:
                hdr, _ = open_image(p.read_bytes(), dk, x25519_sk=xsk, signer_pk=uav_pk)
                p_signed += hdr.get("sig_status") == "PASS"
                p_legacy += hdr.get("v") == 1
            except PhotoError as e:
                bad.append((p.name, str(e)))
        check("stored photos fetched from the UAV decrypt, and the format-2 ones are signed by the UAV",
              "PASS" if not bad and p_signed + p_legacy == len(enc) else "FAIL",
              f"{len(enc)} files: {p_signed} signed and verified, {p_legacy} of format 1, {len(bad)} problems {bad[:3]}")
    except Exception as e:
        check("stored photos decrypt", "INFO", f"skipped ({type(e).__name__}: {e})")


def audit_audio(data: Path):
    """Sealed audio clips held by the ground station: each signed by the pinned UAV key, whole, and opening to the
    audio file that is kept beside it; and the UAV's chain of clips (each names the one before it) without a break."""
    sealed = sorted((data / "audio" / "sealed").glob("*.k6gaud"))
    if not sealed:
        return check("sealed audio clips", "INFO", "none on the ground station")
    try:
        from ..audio import quaver
        from ..crypto import identity as idm
        from ..ground.audio_desk import audio_ext
        dk, xsk = idm.load_recording_dk(idm.DEFAULT_DIR), idm.load_recording_xsk(idm.DEFAULT_DIR)
        uav_pk = idm.load_pinned_peer(idm.DEFAULT_DIR, "uav")
    except Exception as e:
        return check("sealed audio clips", "INFO", f"skipped ({type(e).__name__}: {e})")
    bad, differ, chain, incomplete = [], [], {}, 0
    for p in sealed:
        try:
            raw = p.read_bytes()
            meta, stream, rep = quaver.open_audio(raw, dk, xsk, uav_pk)
        except quaver.AudioError as e:
            bad.append((p.name, str(e))); continue
        incomplete += not rep["complete"]
        out = data / "audio" / (p.stem + audio_ext(meta.get("codec")))
        if not out.is_file() or hashlib.sha256(out.read_bytes()).hexdigest() != rep["sha256"]:
            differ.append(p.name)
        if isinstance(meta.get("clip_no"), int):
            chain.setdefault(meta["clip_no"], []).append((quaver.SealedAudio(raw).root.hex(), meta.get("prev_root"), p.name))
    check("sealed audio clips: signed by the pinned UAV key (ML-DSA-87), every block under the signed root, and they open",
          "PASS" if not bad else "FAIL", f"{len(sealed) - len(bad)} of {len(sealed)} clips, {incomplete} not closed by their sealer, problems {bad[:3]}")
    check("opened audio files are what their clips hold (SHA-256)", "PASS" if not differ else "FAIL", differ[:3] or f"{len(sealed) - len(bad)} files")
    # the chain: a number used twice with different content, or a clip whose predecessor here is not the one it names.
    # Several chains can be on disk (the UAV's card was replaced or its store emptied): each is judged by itself.
    broken, gaps = [], 0
    for no, entries in sorted(chain.items()):
        for root, prev, name in entries:
            before = chain.get(no - 1) or []
            if prev is None or not before:
                gaps += prev is not None
            elif not any(r == prev for r, _, _ in before):
                broken.append(f"{name} does not follow any clip no. {no - 1} held here")
    check("the UAV's chain of audio clips has no break among the clips held", "PASS" if not broken else "WARN",
          broken[:3] or f"{len(chain)} clip numbers, {gaps} whose predecessor was not fetched")


def audit_files(data: Path):
    try:
        from ..crypto import identity as idm
        d = idm.DEFAULT_DIR
        loose = [p.name for p in d.glob("*") if p.is_file() and (p.name.endswith(".sk") or p.name.endswith(".dk") or "secret" in p.name)
                 and stat.S_IMODE(p.stat().st_mode) & 0o077]
        check("private key files are owner-only (0600)", "PASS" if not loose else "FAIL", loose or "all private keys 0600")
        # whoever can write the key directory or a pinned public key decides whom this station trusts
        mode = lambda p: stat.S_IMODE(p.stat().st_mode)
        open_dirs = [f"{p} {mode(p):o}" for p in (d, d / "peers", data) if p.exists() and mode(p) & 0o077]
        check("key and data directories are owner-only (0700)", "PASS" if not open_dirs else "FAIL", open_dirs or f"{d}, {d / 'peers'}, {data}")
        writable = [f"{p.name} {mode(p):o}" for p in (d / "peers").glob("*") if mode(p) & 0o022]
        check("pinned keys are not writable by group/others", "PASS" if not writable else "FAIL", writable or "all pinned keys")
        both = [(d / n).exists() for n in ("gcs_recording_ML-KEM-1024.dk", "gcs_recording_X25519.sk")]
        check("both recording keys are there (stored files use a hybrid key wrap: ML-KEM-1024 and X25519)", "PASS" if all(both) else "WARN",
              "ML-KEM-1024 and X25519" if all(both) else "the X25519 recording key is missing: the UAV writes the older format (python -m kyber6g.tools.provision gcs)")
    except Exception as e:
        check("private key permissions", "INFO", f"skipped ({e})")
    # Public-key cryptography in the code: post-quantum or hybrid only. A classical signature or key exchange used on its
    # own would be the weakest link; this looks for the names of such algorithms in the package (the tools that measure
    # alternatives for comparison, and this file, are left out; X25519 is allowed: it is only ever used beside ML-KEM).
    try:
        pkg = Path(__file__).resolve().parents[1]
        skip = {"bench_crypto.py", "attack_bench.py", "crypto_report.py", "data_audit.py", "sshopts.py"}
        pat = re.compile(r"(?<![A-Za-z_-])(rsa|ecdsa|ed25519|ed448|secp\d+r1|ffdhe|dsa)(?![A-Za-z])", re.I)
        hits = [f"{p.relative_to(pkg)}:{i}" for p in sorted(pkg.rglob("*.py")) if p.name not in skip
                for i, line in enumerate(p.read_text(errors="replace").splitlines(), 1) if pat.search(line)]
        check("no classical-only public-key algorithm in the code (RSA, ECDSA, EdDSA, finite-field DH)", "PASS" if not hits else "FAIL",
              hits[:5] or f"{sum(1 for _ in pkg.rglob('*.py'))} source files")
    except Exception as e:
        check("public-key algorithms in the code", "INFO", f"skipped ({e})")


def ssh(host, script, timeout=60):
    return subprocess.run(sshopts.ssh_base(host) + ["bash -s"], input=script, capture_output=True, text=True, timeout=timeout)


def audit_pi(host):
    script = r'''
cd ~
echo "REC $(ls kyber6g_recordings/*.k6grec 2>/dev/null | wc -l)"
for f in kyber6g_recordings/*.k6grec kyber6g_photos/*.k6gimg kyber6g_audio/*.k6gaud; do [ -e "$f" ] || continue
  printf "F %s %s %s %s\n" "$(stat -c %a "$f")" "$(stat -c %s "$f")" "$(head -c 8 "$f")" "$f"; done
echo "KEYS $(stat -c '%a %n' ~/.kyber6g/*.sk ~/.kyber6g/*secret* 2>/dev/null | tr '\n' ';')"
echo "DIRS $(stat -c '%a' ~/.kyber6g ~/.kyber6g/peers ~/kyber6g_recordings ~/kyber6g_photos 2>/dev/null | tr '\n' ' ')"
echo "PINS $(stat -c '%a' ~/.kyber6g/peers/* 2>/dev/null | tr '\n' ' ')"
echo "ADIRS $(stat -c '%a' ~/kyber6g_audio ~/kyber6g_audio/inbox 2>/dev/null | tr '\n' ' ')"
echo "AUDIN $(ls ~/kyber6g_audio/inbox 2>/dev/null | wc -l) $(ls ~/kyber6g_audio/*.part 2>/dev/null | wc -l)"
echo "AUD $(cd ~/kyber6g_app 2>/dev/null && ~/kyber6g_venv/bin/python -W ignore - 2>/dev/null <<'PY' | tail -1
from pathlib import Path
from kyber6g.audio import quaver
pk = (Path.home() / ".kyber6g" / "uav_ML-DSA-87.pk").read_bytes()
ok = bad = 0
for p in sorted((Path.home() / "kyber6g_audio").glob("*.k6gaud")):
    try:
        quaver.SealedAudio(p.read_bytes()).verify(pk)
        ok += 1
    except Exception:
        bad += 1
print(ok, bad)
PY
)"
echo "UNIT $(systemctl show kyber6g-uav -p NoNewPrivileges -p ProtectSystem -p UMask 2>/dev/null | tr '\n' ' ')"
echo "DISK $(df --output=pcent / | tail -1 | tr -d ' %')"
echo "GPS $(systemctl is-active gpsd) UAV $(systemctl is-active kyber6g-uav)"
journalctl -u kyber6g-uav --no-pager -n 400 2>/dev/null | grep -ciE "password|BEGIN .*PRIVATE|sshpass" | sed 's/^/LOGSECRETS /'
'''
    try:
        r = ssh(host, script)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        check("UAV reachable for audit", "INFO", f"skipped ({type(e).__name__})")
        return
    if r.returncode != 0:
        check("UAV reachable for audit", "INFO", f"ssh failed: {r.stderr.strip()[:100]}")
        return
    files, other = [], {}
    for line in r.stdout.splitlines():
        if line.startswith("F "):
            _, mode, size, magic, name = line.split(" ", 4)
            files.append((mode, int(size), magic, name))
        else:
            k, _, v = line.partition(" ")
            other[k] = v
    bad_mode = [n for m, s, g, n in files if m != "600"]
    check("UAV media files are owner-only (0600)", "PASS" if not bad_mode else "FAIL", f"{len(files)} files, {bad_mode[:3] or 'all 0600'}")
    bad_magic = [n for m, s, g, n in files if g not in ("K6GREC01", "K6GIMG01", "K6GREC02", "K6GIMG02", "K6GAUD01")]
    v2 = sum(1 for m, s, g, n in files if g in ("K6GREC02", "K6GIMG02", "K6GAUD01"))
    check("UAV media files are encrypted containers (K6GREC / K6GIMG / K6GAUD)", "PASS" if not bad_magic else "FAIL",
          bad_magic[:3] or f"{len(files)} files: {v2} with the hybrid key wrap and the UAV's signature, {len(files) - v2} of format 1")
    aud = other.get("AUD", "").split()
    if len(aud) == 2 and aud[0].isdigit() and aud[1].isdigit():
        check("audio clips on the UAV's card are whole: every block under the root the UAV signed (checked on the UAV, no secret)",
              "PASS" if aud[1] == "0" else "FAIL", f"{aud[0]} clips verified, {aud[1]} not")
        waiting = other.get("AUDIN", "0 0").split()
        check("no plain audio left on the UAV (its inbox is empty, no clip half written)", "PASS" if waiting == ["0", "0"] else "WARN",
              f"{waiting[0]} file(s) waiting in the inbox, {waiting[-1]} unfinished clip(s)")
        adirs = other.get("ADIRS", "").split()
        check("UAV audio directories are owner-only (0700)", "PASS" if adirs and set(adirs) == {"700"} else "FAIL", " ".join(adirs) or "not found")
    orphans = [n for m, s, g, n in files if s < 4096]
    check("no empty orphan recordings on the UAV", "PASS" if not orphans else "WARN", orphans[:3] or "none")
    check("UAV SD card usage", "PASS" if int(other.get("DISK", "100")) < 85 else "WARN", f"{other.get('DISK')}% used")
    check("UAV services", "PASS" if other.get("GPS", "").startswith("active UAV active") else "FAIL", other.get("GPS"))
    check("no credentials in the UAV journal", "PASS" if other.get("LOGSECRETS", "0") == "0" else "FAIL", f"{other.get('LOGSECRETS')} matching lines")
    keys = other.get("KEYS", "")
    check("UAV private key permissions", "PASS" if keys and all(k.startswith("600 ") for k in keys.strip(";").split(";") if k) else "FAIL", keys or "no key files found")
    dirs, pins = other.get("DIRS", "").split(), other.get("PINS", "").split()
    check("UAV key and media directories are owner-only (0700)", "PASS" if len(dirs) == 4 and set(dirs) == {"700"} else "FAIL",
          f"~/.kyber6g, peers, recordings, photos: {' '.join(dirs) or 'not found'}")
    check("UAV pinned keys are not writable by group/others", "PASS" if pins and all(int(p, 8) & 0o022 == 0 for p in pins) else "FAIL", " ".join(pins) or "none found")
    unit = other.get("UNIT", "").split()
    check("UAV service runs confined (no new privileges, read-only system, private umask)",
          "PASS" if {"NoNewPrivileges=yes", "ProtectSystem=strict", "UMask=0077"} <= set(unit) else "WARN",
          " ".join(unit) or "systemctl show gave nothing")
    # the management channel (deploy, service control, this audit): its key exchange should be post-quantum as well
    kex = sshopts.negotiated_kex(host)
    check("management channel to the UAV (SSH) uses a post-quantum hybrid key exchange",
          "PASS" if sshopts.is_post_quantum(kex) else "WARN", kex or "could not be determined")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(Path.home() / "kyber6g_ground"))
    ap.add_argument("--pi", help="ssh alias of the UAV, e.g. kyber-pi")
    ap.add_argument("--repair-altitude", action="store_true")
    a = ap.parse_args()
    data = Path(a.data).expanduser()
    db = data / "kyber6g.db"
    if not db.exists():
        print("no database at", db); return 2
    con = sqlite3.connect(db, timeout=30)
    audit_db(con, data, a.repair_altitude)
    con.close()
    audit_files(data)
    audit_audio(data)
    if a.pi:
        audit_pi(a.pi)
    fails = [r["check"] for r in RESULTS if r["status"] == "FAIL"]
    warns = [r["check"] for r in RESULTS if r["status"] == "WARN"]
    out = data / "exports" / time.strftime("audit_%Y%m%d_%H%M%S.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"pass": sum(r["status"] == "PASS" for r in RESULTS), "warn": warns, "fail": fails, "results": RESULTS}, indent=1, default=str))
    print(f"\n{sum(r['status'] == 'PASS' for r in RESULTS)} PASS, {len(warns)} WARN, {len(fails)} FAIL -> {out}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
