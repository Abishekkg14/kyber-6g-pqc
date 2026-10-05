#!/usr/bin/env python3
"""Everything the website shows that is a number or a picture, taken from the repository's own results.

    python3 kyber6g-website/scripts/build_data.py

  public/data/results.json   the headline table of the README, the tables behind the paper's plots
                             (paper_plots/tables/*.csv), the ProVerif results (formal/results.json), the known-answer
                             tests (paper_plots/data/pq_conformance_*.json) and where each came from
  public/img/*.png           the paper's figures and plots, made smaller for a web page

No number is typed into the website's source: a section that shows one reads it from results.json. Run this again
after a measurement campaign, `plots`, `formal` or a change of the README's results table, then `npm run build`.
"""
import csv
import json
import re
import subprocess
import time
from pathlib import Path

from PIL import Image

SITE = Path(__file__).resolve().parents[1]
REPO = SITE.parent
TABLES = REPO / "paper_plots" / "tables"
Image.MAX_IMAGE_PIXELS = None

FIGURES = ["fig01_system_overview", "fig02_threat_model", "fig03_handshake", "fig04_key_schedule", "fig08_perception_hitl",
           "fig11_media_protection", "fig12_simulation_setup", "fig13_rekey_flows", "fig15_audio_sealing", "fig17_audio_excerpt",
           "fig18_architecture", "fig19_motion_watch"]
PLOTS = ["plot10_attacks", "plot12_sim_swarm", "plot17_audio_statistics", "plot20_audio_attacks", "plot21_motion_watch",
         "plot22_proof_matrix"]
CSVS = ["plot01_crypto_primitives", "plot02_handshake_latency", "plot03_wire_bytes", "plot06_loss_video", "plot07_latency_budget",
        "plot12_sim_swarm", "plot15_ablation_crypto", "plot19_audio_cost", "plot19_audio_excerpts", "plot20_audio_live_loss",
        "plot21_motion_watch", "plot21_motion_cost", "plot22_proof_matrix", "plot22_known_answers", "table_environment",
        "table_rekey_schedule"]


def number(v):
    try:
        f = float(v)
        return int(f) if f.is_integer() and "." not in v and "e" not in v.lower() else f
    except (TypeError, ValueError):
        return v


def table(name):
    p = TABLES / f"{name}.csv"
    if not p.exists():
        return None
    with p.open(newline="", encoding="utf-8") as f:
        return [{k: number(v) for k, v in row.items() if k} for row in csv.DictReader(f)]


def session_operations():
    """plot02_handshake_latency.csv holds two things: the three operations, and where each one's time goes."""
    ops, parts = [], []
    for r in table("plot02_handshake_latency") or []:
        if not str(r["operation"]).startswith("breakdown:"):
            ops.append(r)
            continue
        found = dict(re.findall(r"(\w+_ms)=([\d.]+)", " ".join(str(r[k]) for k in ("p95_ms", "p99_ms", "max_ms"))))
        parts.append({"operation": r["operation"].split(":", 1)[1].strip(), "median_ms": r["median_ms"],
                      "uav_ms": float(found["uav_ms"]), "gcs_ms": float(found["gcs_ms"]), "link_and_wait_ms": float(found["link_and_wait_ms"])})
    return ops, parts


def headline():
    """The rows of "Results at a glance" in the README: [measurement, value]."""
    text = (REPO / "README.md").read_text(encoding="utf-8")
    part = text.split("## Results at a glance", 1)[1].split("\n## ", 1)[0]
    rows = []
    for line in part.splitlines():
        m = re.match(r"^\|\s*(.+?)\s*\|\s*(.+?)\s*\|\s*$", line)
        if m and not set(m.group(1)) <= set("-: ") and m.group(1) != "Measurement":
            rows.append([re.sub(r"[*`]", "", m.group(1)), re.sub(r"[*`]", "", m.group(2))])
    return rows


def grouped(rows, key):
    out = {}
    for r in rows:
        g = out.setdefault(key(r), {"group": key(r), "experiments": set(), "attempts": 0, "accepted": 0})
        g["experiments"].add(r["experiment"])
        g["attempts"] += r["attempts"]
        g["accepted"] += r["accepted"]
    return [g | {"experiments": len(g["experiments"])} for g in out.values()]


def link_attacks():
    """Attempts to get something false accepted by the link or as a stored photo or recording (both machines).

    Left out of the count, as in the README: the stress test of the sender (it forges nothing) and the timing
    rows (they have no accept or refuse)."""
    rows = [r for r in table("plot10_attacks") or [] if isinstance(r.get("accepted"), int)]
    stress = [r for r in rows if "nonce reuse" in r["experiment"]]
    rows = [r for r in rows if r not in stress]
    return {"attempts": sum(r["attempts"] for r in rows), "accepted": sum(r["accepted"] for r in rows),
            "groups": grouped(rows, lambda r: r["experiment"].split(":")[0]),
            "sender_stress": {"records_sealed": sum(r["attempts"] for r in stress), "nonces_used_twice": sum(r["accepted"] for r in stress)}}


def audio_attacks():
    """The same for sealed audio; the rows that expect "accepted" are the controls (genuine input must open)."""
    rows = table("plot20_audio_attacks") or []
    bad = [r for r in rows if r["expected"] == "refused"]
    good = [r for r in rows if r["expected"] != "refused"]
    return {"attempts": sum(r["attempts"] for r in bad), "accepted": sum(r["accepted"] for r in bad),
            "crashes": sum(r["crashes"] for r in rows), "groups": grouped(bad, lambda r: r["group"]),
            "controls": {"offered": sum(r["attempts"] for r in good), "accepted": sum(r["accepted"] for r in good)}}


def cbom():
    p = REPO / "docs" / "CBOM.json"
    if not p.exists():
        return None
    d = json.loads(p.read_text(encoding="utf-8"))
    kinds = {}
    for c in d["components"]:
        k = c.get("cryptoProperties", {}).get("assetType", c["type"])
        kinds[k] = kinds.get(k, 0) + 1
    return {"spec": f'{d["bomFormat"]} {d["specVersion"]}', "components": len(d["components"]), "by_kind": kinds,
            "cryptographic_assets": sum(c["type"] == "cryptographic-asset" for c in d["components"]),
            "libraries": sum(c["type"] == "library" for c in d["components"])}


def pictures():
    out = SITE / "public" / "img"
    out.mkdir(parents=True, exist_ok=True)
    done = []
    for name in FIGURES + PLOTS:
        src = next((d / f"{name}.png" for d in (REPO / "paper_figures" / "exported_png", REPO / "paper_plots" / "exported_png") if (d / f"{name}.png").exists()), None)
        if src is None:
            continue
        im = Image.open(src).convert("RGB")
        w = min(1800, im.width)
        im = im.resize((w, round(im.height * w / im.width)), Image.LANCZOS)
        im.save(out / f"{name}.png", optimize=True)
        done.append({"name": name, "width": im.width, "height": im.height})
    return done


def main():
    formal = REPO / "formal" / "results.json"
    conf = {n: json.loads(p.read_text()) for n in ("pi", "laptop") if (p := REPO / "paper_plots" / "data" / f"pq_conformance_{n}.json").exists()}
    head = subprocess.run(["git", "-C", str(REPO), "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    tables = {n: t for n in CSVS if (t := table(n)) is not None}
    tables["plot02_handshake_latency"], tables["handshake_breakdown"] = session_operations()
    data = {
        "generated": time.strftime("%Y-%m-%d %H:%M %Z"), "repository_head": head,
        "sources": "README.md (results at a glance), paper_plots/tables/*.csv, formal/results.json, paper_plots/data/pq_conformance_*.json, docs/CBOM.json",
        "headline": headline(),
        "tables": tables,
        "attacks": {"link_and_files": link_attacks(), "audio": audio_attacks()},
        "formal": json.loads(formal.read_text())["summary"] if formal.exists() else None,
        "cbom": cbom(),
        "known_answers": {n: {k: c[k] for k in ("vectors", "passed", "all_passed", "liboqs", "openssl", "when")} | {"machine": c["machine"]["node"], "arch": c["machine"]["arch"]}
                          for n, c in conf.items()},
        "pictures": pictures(),
    }
    out = SITE / "public" / "data" / "results.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"{out}: {out.stat().st_size // 1024} kB; {len(data['headline'])} headline rows, {len(data['tables'])} tables, {len(data['pictures'])} pictures; "
          f"missing tables: {[n for n in CSVS if n not in data['tables']]}")


if __name__ == "__main__":
    main()
