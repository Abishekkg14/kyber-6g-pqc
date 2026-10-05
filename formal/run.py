#!/usr/bin/env python3
"""Runs every ProVerif model of this directory under every attacker and compares each result with what is claimed.

    python3 formal/run.py [--proverif PATH] [--only handshake]

Each run is   proverif -lib primitives.pvl -lib attacker_<A>.pvl [-lib <what leaks>.pvl] <model>.pv
A claim is a query that must come out TRUE. Next to the claims stand queries that must come out FALSE: the same
secrecy question with both key-establishment schemes broken or with the decisive key stolen, and a reachability
question per model ("can the protocol finish at all?" - asked as "it never finishes", which must be false). They show
that a model is able to fail and is not empty. A result that differs from the table below, or one ProVerif cannot
decide, makes this script exit with an error.

Writes results.json (every run, every query, ProVerif's own wording) and RESULTS.md (the table for people).
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
T, F = True, False
ALL = ("classical", "shor", "mlkem", "both")
ATTACKERS = {"classical": "breaks nothing", "shor": "X25519 broken", "mlkem": "ML-KEM broken", "both": "X25519 and ML-KEM broken"}

# (model, what-leaks library or None, what this run is about, {attacker: expected outcome of each query, in the file's order})
RUNS = [
    ("handshake", None,
     "full handshake; both signing keys are given to the attacker afterwards (phase 1); a second pinned UAV is the attacker's",
     # secret sent by the UAV | by the GCS | GCS completes => UAV completed, once | UAV completes => GCS running, once | never finishes
     {"classical": [T, T, T, T, F], "shor": [T, T, T, T, F], "mlkem": [T, T, T, T, F],
      # both broken: the session key is computable, so nothing is secret and the attacker can finish a session the UAV
      # began (the ClientFinished is a MAC under that key); the ground station's signature still binds ITS side
      "both": [F, F, F, T, F]}),
    ("cached_rekey", "leak_none", "1-RTT Cached RapidRekey from a secret resumption secret",
     # secret by UAV | by GCS | GCS completes => UAV completed, once | UAV completes => GCS running | never finishes
     {a: [T, T, T, T, F] for a in ALL}),          # no public-key operation in it: which scheme is broken does not matter
    ("cached_rekey", "leak_next", "... and the next resumption secret leaks afterwards (the chain is one-way)",
     {a: [T, T, T, T, F] for a in ALL}),
    ("cached_rekey", "leak_before", "... but the resumption secret had leaked BEFORE: a cached rekey does not heal (expected to fail)",
     {a: [F, F, F, F, F] for a in ALL}),
    ("pq_ratchet", "leak_none", "PQ ratchet inside a healthy session",
     # secret by UAV | by GCS | UAV arrives => GCS arrived at the same keys | never finishes
     {a: [T, T, T, F] for a in ALL}),             # the old master secret is mixed in: even both schemes broken changes nothing
    ("pq_ratchet", "leak_next", "... and the OLD master secret leaks afterwards",
     {"classical": [T, T, T, F], "shor": [T, T, T, F], "mlkem": [T, T, T, F], "both": [F, F, T, F]}),
    ("pq_ratchet_active", None, "... the old master secret leaked before and the attacker is ACTIVE during the ratchet (expected to fail)",
     # secret by UAV | UAV arrives => GCS arrived at the same keys
     {"classical": [F, F]}),
    ("pq_ratchet_passive", None, "PQ ratchet after the old master secret leaked, attacker only LISTENS: the session heals",
     # secret by UAV | by GCS | never finishes
     {"classical": [T, T, F], "shor": [T, T, F], "mlkem": [T, T, F], "both": [F, F, F]}),
    ("sealed_file", "file_leak_none", "stored photo / recording / audio clip",
     # content secret | what the GCS opens was sealed by the UAV | never opens
     {"classical": [T, T, F], "shor": [T, T, F], "mlkem": [T, T, F], "both": [F, T, F]}),
    ("sealed_file", "file_leak_uav", "... the UAV is captured afterwards (all it holds: its signing key)",
     {"classical": [T, T, F], "shor": [T, T, F], "mlkem": [T, T, F], "both": [F, T, F]}),
    ("sealed_file", "file_leak_kem", "... the ground station's ML-KEM recording key alone is stolen",
     {"classical": [T, T, F], "shor": [F, T, F], "mlkem": [T, T, F], "both": [F, T, F]}),
    ("sealed_file", "file_leak_x", "... the ground station's X25519 recording key alone is stolen",
     {"classical": [T, T, F], "shor": [T, T, F], "mlkem": [F, T, F], "both": [F, T, F]}),
    ("sealed_file", "file_leak_both", "... both recording keys are stolen (expected to fail: nothing at rest is forward secret)",
     {"classical": [F, T, F]}),
]

RESULT = re.compile(r"^RESULT (?!\()(.*?) (is true|is false|cannot be proved)\.\s*$")
LIMIT_S = 180                   # per run; the runs that end take seconds


def find_proverif(given):
    for p in (given, shutil.which("proverif"), "/root/tools/proverif/proverif", str(Path.home() / "tools/proverif/proverif")):
        if p and Path(p).is_file():
            return p
    sys.exit("ProVerif not found (https://bblanche.gitlabpages.inria.fr/proverif/): give --proverif PATH")


def run(pv, model, leak, attacker):
    cmd = [pv, "-lib", "primitives.pvl", "-lib", f"attacker_{attacker}.pvl"] + (["-lib", f"{leak}.pvl"] if leak else []) + [f"{model}.pv"]
    t0 = time.perf_counter()
    try:
        p = subprocess.run(cmd, cwd=HERE, capture_output=True, text=True, timeout=LIMIT_S)
    except subprocess.TimeoutExpired:
        return [], float(LIMIT_S), -1, f"ProVerif did not come to an end within {LIMIT_S} s"
    found = []
    for line in p.stdout.splitlines():
        m = RESULT.match(line)
        if m:
            found.append((m.group(1), {"is true": True, "is false": False}.get(m.group(2))))
    return found, round(time.perf_counter() - t0, 2), p.returncode, (p.stdout + p.stderr)[-600:]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--proverif")
    ap.add_argument("--only", help="run only the models whose name contains this")
    a = ap.parse_args()
    pv = find_proverif(a.proverif)
    version = subprocess.run([pv, "--help"], capture_output=True, text=True).stdout.splitlines()[0].strip()
    rows, bad = [], 0
    for model, leak, about, expected in RUNS:
        if a.only and a.only not in model:
            continue
        for attacker, want in expected.items():
            found, secs, rc, tail = run(pv, model, leak, attacker)
            ok = rc == 0 and len(found) == len(want) and all(got is exp for (_, got), exp in zip(found, want))
            bad += not ok
            rows.append({"model": model, "leak": leak, "about": about, "attacker": attacker, "seconds": secs, "ok": ok,
                         "queries": [{"query": q, "result": got, "expected": exp} for (q, got), exp in zip(found, want)],
                         **({} if ok else {"exit_code": rc, "results_found": len(found), "results_expected": len(want), "output_tail": tail})})
            marks = " ".join(("T" if got else "F" if got is False else "?") + ("" if got is exp else "(!)") for (_, got), exp in zip(found, want))
            print(f"{'ok ' if ok else 'BAD'} {model:19s} {leak or '-':15s} {attacker:9s} {secs:6.2f} s  {marks}", flush=True)
    claims = sum(q["expected"] for r in rows for q in r["queries"])
    summary = {"proverif": version, "runs": len(rows), "runs_as_expected": len(rows) - bad, "queries": sum(len(r["queries"]) for r in rows),
               "claims_proved": sum(q["expected"] and q["result"] is True for r in rows for q in r["queries"]), "claims": claims,
               "attacks_found_where_expected": sum(q["expected"] is False and q["result"] is False for r in rows for q in r["queries"]),
               "attacks_expected": sum(q["expected"] is False for r in rows for q in r["queries"]),
               "seconds": round(sum(r["seconds"] for r in rows), 1), "when": time.strftime("%Y-%m-%d %H:%M:%S %Z")}
    if not a.only:
        (HERE / "results.json").write_text(json.dumps({"summary": summary, "attackers": ATTACKERS, "runs": rows}, indent=1) + "\n")
        write_md(summary, rows)
    print(json.dumps(summary))
    sys.exit(1 if bad else 0)


def write_md(summary, rows):
    out = ["# Machine-checked protocol models: results", "",
           f"Written by `formal/run.py` on {summary['when']} with {summary['proverif']}.", "",
           f"**{summary['claims_proved']} of {summary['claims']} claims proved; "
           f"{summary['attacks_found_where_expected']} of {summary['attacks_expected']} attacks found where one must exist** "
           f"({summary['runs']} runs, {summary['queries']} queries, {summary['seconds']} s).", "",
           "A claim is a query that must hold (`true`). The other queries must NOT hold (`false`): they ask the same thing "
           "with the decisive scheme broken or the decisive key stolen, or whether the protocol can finish at all. They show "
           "that each model can fail. Attackers: " + "; ".join(f"`{k}` = {v}" for k, v in ATTACKERS.items()) + ".", ""]
    last = None
    for r in rows:
        key = (r["model"], r["leak"])
        if key != last:
            last = key
            out += ["", f"## `{r['model']}.pv`" + (f" with `{r['leak']}.pvl`" if r["leak"] else ""), "", r["about"] + ".", "",
                    "| attacker | query (ProVerif's wording) | result | expected |", "|---|---|---|---|"]
        for q in r["queries"]:
            res = {True: "true", False: "false", None: "cannot be proved"}[q["result"]]
            exp = "true" if q["expected"] else "false"
            out.append(f"| {r['attacker']} | `{q['query']}` | {res} | {exp}{'' if res == exp else ' **MISMATCH**'} |")
    (HERE / "RESULTS.md").write_text("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
