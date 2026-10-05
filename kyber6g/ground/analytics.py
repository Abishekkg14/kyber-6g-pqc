"""Telemetry analytics (pure functions, unit-tested).

Accuracy metrics follow the usual GNSS definitions on a local east/north
plane around the mean position: CEP50/CEP95 = 50th/95th percentile of
horizontal radial error, 2DRMS = 2 * sqrt(mean(e^2 + n^2)).
"""
import math

R_EARTH = 6371008.8


def haversine_m(lat1, lon1, lat2, lon2):
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = p2 - p1, math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * R_EARTH * math.asin(math.sqrt(a))


def enu(lat, lon, lat0, lon0):
    """Local tangent-plane east/north metres (small-area approximation)."""
    e = math.radians(lon - lon0) * R_EARTH * math.cos(math.radians(lat0))
    n = math.radians(lat - lat0) * R_EARTH
    return e, n


def percentile(xs, p):
    if not xs:
        return None
    s = sorted(xs)
    k = (len(s) - 1) * p / 100
    f, c = math.floor(k), math.ceil(k)
    return s[f] if f == c else s[f] + (s[c] - s[f]) * (k - f)


def _stats(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return {"n": 0, "min": None, "max": None, "mean": None, "p50": None, "p95": None}
    return {"n": len(xs), "min": round(min(xs), 3), "max": round(max(xs), 3), "mean": round(sum(xs) / len(xs), 3),
            "p50": round(percentile(xs, 50), 3), "p95": round(percentile(xs, 95), 3)}


def summarize(rows, home=None):
    """rows: telemetry dicts ordered by ts (ts, lat, lon, alt_m, speed_mps, mode, hdop, ...)."""
    out = {"samples": len(rows)}
    if not rows:
        return out
    fixes = [r for r in rows if r.get("mode", 0) and r["mode"] >= 2 and r.get("lat") is not None]
    out["duration_s"] = round(rows[-1]["ts"] - rows[0]["ts"], 1)
    out["fix_availability_pct"] = round(100 * len(fixes) / len(rows), 1)
    out["fix_3d_pct"] = round(100 * sum(1 for r in rows if (r.get("mode") or 0) >= 3) / len(rows), 1)
    out["sats_used"] = _stats([r.get("sats_used") for r in rows])
    out["sats_seen"] = _stats([r.get("sats_seen") for r in rows])
    out["hdop"] = _stats([r.get("hdop") for r in rows])
    out["pdop"] = _stats([r.get("pdop") for r in rows])
    out["latency_ms"] = _stats([r.get("latency_ms") for r in rows])
    if not fixes:
        return out
    dist = 0.0
    for a, b in zip(fixes, fixes[1:]):
        d = haversine_m(a["lat"], a["lon"], b["lat"], b["lon"])
        # ignore jitter below the reported horizontal error when stationary
        if d > max(1.0, (b.get("eph_m") or 0)):
            dist += d
    out["distance_m"] = round(dist, 1)
    out["speed_mps"] = _stats([r.get("speed_mps") for r in fixes])
    out["alt_m"] = _stats([r.get("alt_m") for r in fixes])
    lat0 = sum(r["lat"] for r in fixes) / len(fixes)
    lon0 = sum(r["lon"] for r in fixes) / len(fixes)
    alts = [r["alt_m"] for r in fixes if r.get("alt_m") is not None]
    out["mean_position"] = {"lat": round(lat0, 7), "lon": round(lon0, 7),
                            "alt_m": round(sum(alts) / len(alts), 2) if alts else None}
    radial = []
    sq = 0.0
    for r in fixes:
        e, n = enu(r["lat"], r["lon"], lat0, lon0)
        radial.append(math.hypot(e, n))
        sq += e * e + n * n
    out["accuracy_m"] = {"cep50": round(percentile(radial, 50), 2), "cep95": round(percentile(radial, 95), 2),
                         "drms2": round(2 * math.sqrt(sq / len(fixes)), 2), "max": round(max(radial), 2),
                         "note": "scatter about the mean position; meaningful when the receiver is stationary"}
    if home:
        dh = [haversine_m(home[0], home[1], r["lat"], r["lon"]) for r in fixes]
        out["from_home_m"] = {"current": round(dh[-1], 1), "max": round(max(dh), 1)}
    return out


def density_grid(points, cells=24):
    """Bin (lat, lon) points into a cells x cells grid -> counts, for heat/3D views."""
    pts = [(la, lo) for la, lo in points if la is not None and lo is not None]
    if not pts:
        return {"cells": cells, "bounds": None, "grid": []}
    la0, la1 = min(p[0] for p in pts), max(p[0] for p in pts)
    lo0, lo1 = min(p[1] for p in pts), max(p[1] for p in pts)
    pad_la, pad_lo = max((la1 - la0) * 0.05, 1e-5), max((lo1 - lo0) * 0.05, 1e-5)
    la0, la1, lo0, lo1 = la0 - pad_la, la1 + pad_la, lo0 - pad_lo, lo1 + pad_lo
    grid = [[0] * cells for _ in range(cells)]
    for la, lo in pts:
        i = min(cells - 1, int((la - la0) / (la1 - la0) * cells))
        j = min(cells - 1, int((lo - lo0) / (lo1 - lo0) * cells))
        grid[i][j] += 1
    return {"cells": cells, "bounds": [la0, lo0, la1, lo1], "grid": grid}


def sky_summary(sats):
    """sats: [constellation, prn, az, el, snr, used] rows -> per-constellation summary."""
    by = {}
    for c, prn, az, el, snr, used in sats:
        d = by.setdefault(c, {"seen": 0, "used": 0, "snr": []})
        d["seen"] += 1
        d["used"] += used
        if snr:
            d["snr"].append(snr)
    return {c: {"seen": d["seen"], "used": d["used"],
                "snr_mean": round(sum(d["snr"]) / len(d["snr"]), 1) if d["snr"] else None,
                "snr_max": max(d["snr"]) if d["snr"] else None} for c, d in by.items()}
