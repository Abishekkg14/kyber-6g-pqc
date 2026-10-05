#!/usr/bin/env python3
"""Run the simulation studies, many runs at a time.

    python simulation/run_sweep.py [study ...] [--jobs N] [--seeds K] [--list] [--force] [--fresh] [--rebuild]

Studies (default: all):
  validation   the replica of the test bed, without loss and at the loss rates that were measured: the model against
               the measurements that were not used to calibrate it
  swarm        an NR cell with 1..64 UAVs, each streaming video: session operations and video delivery against swarm size
  storm        every UAV of an NR cell starts its first handshake at the same instant (a restarted ground station)
  mobility     an NR cell with 8 UAVs moving at 0..30 m/s: the handshakes a change of position cell triggers
  range        an NR cell with 8 UAVs at 0.25..4 km from the mast
  crypto       ablation, cryptographic configuration: other choices of algorithms (classical, ML-KEM alone, smaller
               parameter sets) on both links and in the storm
  design       ablation, protocol design on the test-bed link: repeat timers, fragment size, video parity and
               keyframe request

What it does: writes the calibration file from the measurements (calibrate.py), applies the patches the NR library
needs (ns3/patches), builds the simulator inside the ns-3 tree, and runs the binary once per (study, parameters,
seed), `--jobs` processes side by side (one process is one core). Every run writes results/raw/<name>.csv; a run whose
file is complete is not repeated, so an interrupted sweep continues where it stopped. results/manifest.json records
every run (parameters, wall time, outcome) and what the results were made with (calibration, simulator source,
patches); results made with something else are not mixed in: the sweep stops and asks for --fresh, which removes them.
analyze.py turns the raw files into tables and plots.
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

SIM = Path(__file__).resolve().parent
REPO = SIM.parent
NS3 = REPO / "ns-3-dev"
RAW, LOGS = SIM / "results" / "raw", SIM / "results" / "logs"
BIN = NS3 / "build" / "scratch" / "ns3.42-k6g-swarm-sim-default"
TDD = {"dl": "DL|DL|DL|S|UL|DL|DL|S|UL|UL|",       # 3 of 10 slots uplink: the pattern of public networks
       "ul": "DL|S|UL|UL|UL|DL|S|UL|UL|UL|"}       # 6 of 10 slots uplink: a cell set up for uplink video
PROFILES = ["classical", "hybrid1", "hybrid3", "pq5", "hybrid5"]
SWARM_N = (1, 2, 4, 8, 16, 24, 32, 48, 64)
STORM_N = (4, 8, 16, 32, 64)
SPEEDS = (0, 5, 10, 20, 30)
RANGES_M = (250, 500, 1000, 2000, 3000, 4000)       # the path-loss model is given for up to 4 km


def sh(cmd, cwd=None, **kw):
    return subprocess.run(cmd, cwd=cwd, text=True, capture_output=True, **kw)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


def prepare(rebuild=False):
    """Calibration file, library patches, simulator binary. Returns what the results will have been made with."""
    r = sh([sys.executable, "-W", "ignore", str(SIM / "calibrate.py")])
    line = [l for l in r.stdout.splitlines() if l.startswith("calibration written")]
    print(line[0] if line else r.stderr.strip()[-400:])
    if r.returncode != 0:
        sys.exit(r.stdout[-800:] + r.stderr[-800:])
    patches = sorted((SIM / "ns3" / "patches").glob("*.patch"))
    for patch in patches:
        nr = NS3 / "contrib" / "nr"
        if sh(["git", "-C", str(nr), "apply", "--reverse", "--check", str(patch)]).returncode == 0:
            continue                                                    # already applied
        r = sh(["git", "-C", str(nr), "apply", str(patch)])
        if r.returncode != 0:
            sys.exit(f"patch {patch.name} does not apply to ns-3-dev/contrib/nr: {r.stderr.strip()[:300]}")
        print(f"applied {patch.name} to ns-3-dev/contrib/nr")
        rebuild = True
    src, dst = SIM / "ns3" / "k6g-swarm-sim.cc", NS3 / "scratch" / "k6g-swarm-sim.cc"
    if not dst.exists() or dst.read_bytes() != src.read_bytes():
        shutil.copyfile(src, dst)
        rebuild = True
    if rebuild or not BIN.exists():
        t0 = time.time()
        if "k6g-swarm-sim" not in (NS3 / "cmake-cache" / "build.ninja").read_text(errors="replace"):
            sh(["./ns3", "configure"], cwd=NS3)
        r = sh(["./ns3", "build", "k6g-swarm-sim"], cwd=NS3)
        if r.returncode != 0 or not BIN.exists():
            sys.exit("build failed:\n" + (r.stdout + r.stderr)[-3000:])
        print(f"simulator built in {time.time() - t0:.0f} s")
    return {"calibration_sha256": sha(SIM / "calibration" / "k6g_calibration.txt"), "simulator_sha256": sha(src),
            "nr_patches": [p.name for p in patches],
            "ns3": "ns-3.42, 5G-LENA (nr) v3.3, build profile default (assertions on)"}


def measured_loss_rates():
    """The datagram loss rates of the measured loss experiment, as counted by the rule on the Pi (uplink)."""
    d = json.loads((REPO / "paper_plots" / "data" / "loss.json").read_text())
    out = []
    for lv in d["levels"]:
        c0, c1 = lv["counters_before"], lv["counters_after"]
        seen, drop = c1["seen-out"] - c0["seen-out"], c1["drop-out"] - c0["drop-out"]
        if drop:
            out.append(round(drop / seen, 5))
    return out


def studies(seeds=10, loss_rates=None):
    """name -> list of (run name, arguments). Every run is one process on one core (0.3 GB at 64 UAVs)."""
    S = {}
    sx = lambda n: range(1, n + 1)
    loss_rates = measured_loss_rates() if loss_rates is None else loss_rates

    v = [(f"val_noloss_s{s}", dict(link="testbed", opsPerUav=150, opGap=0.25, simTime=400, run=s)) for s in sx(max(seeds, 20))]
    for p in loss_rates:
        v += [(f"val_loss{p:.5f}_s{s}", dict(link="testbed", loss=p, opsPerUav=10, opGap=0.25, simTime=300, run=s)) for s in sx(max(seeds, 40))]
    S["validation"] = v

    # small cells: more runs (a run of one UAV holds 4 operations of each kind); large cells: fewer (a run of 64 UAVs
    # holds 256 of each kind and 64 video streams, and takes a core for half an hour)
    n_seeds = lambda n: 2 * seeds if n <= 4 else (seeds if n <= 16 else max(3, seeds // 2))
    S["swarm"] = [(f"swarm_{t}_n{n}_s{s}", dict(link="nr", nUav=n, tdd=TDD[t], opsPerUav=4, opGap=0.4, simTime=14, run=s))
                  for t in ("ul", "dl") for n in SWARM_N for s in sx(n_seeds(n))]

    S["storm"] = [(f"storm_w{w}_n{n}_s{s}", dict(link="nr", nUav=n, tdd=TDD["ul"], storm=1, video=0, opsPerUav=0, gcsWorkers=w, simTime=16, run=s))
                  for w in (1, 4) for n in STORM_N for s in sx(seeds)]

    # no planned operations: the handshakes are those a change of position cell triggers
    S["mobility"] = [(f"mob_v{v_}_s{s}", dict(link="nr", nUav=8, tdd=TDD["ul"], speed=v_, chUpdateMs=20, opsPerUav=0, simTime=45, run=s))
                     for v_ in SPEEDS for s in sx(seeds)]

    S["range"] = [(f"range_d{d}_s{s}", dict(link="nr", nUav=8, tdd=TDD["ul"], rMin=round(d * 0.98), radius=round(d * 1.02), opsPerUav=4, opGap=0.4,
                                           simTime=14, run=s)) for d in RANGES_M for s in sx(max(3, seeds // 2))]

    c = []
    for prof in PROFILES:
        for loss in (0.0, 0.02, 0.05):
            c += [(f"crypto_tb_{prof}_l{loss}_s{s}", dict(link="testbed", profile=prof, loss=loss, ops="full,ratchet", opsPerUav=100, opGap=0.25,
                                                         video=0, simTime=900, run=s)) for s in sx(seeds)]
        c += [(f"crypto_nr_{prof}_s{s}", dict(link="nr", profile=prof, nUav=8, tdd=TDD["ul"], ops="full,ratchet", opsPerUav=6, opGap=0.4, simTime=14, run=s))
              for s in sx(seeds)]
        c += [(f"crypto_storm_{prof}_s{s}", dict(link="nr", profile=prof, nUav=64, tdd=TDD["ul"], storm=1, video=0, opsPerUav=0, simTime=16, run=s))
              for s in sx(seeds)]
    S["crypto"] = c

    d = []
    for loss in (0.01, 0.02, 0.05, 0.10, 0.20):
        for ad in (0, 1):
            d += [(f"design_retx{ad}_l{loss}_s{s}", dict(link="testbed", loss=loss, adaptiveRetx=ad, opsPerUav=30, opGap=0.25, video=0, simTime=900, run=s))
                  for s in sx(max(seeds, 20))]
        for fp in (400, 600, 1180, 1400):                 # 1180 is the implemented size: the reference of this group
            d += [(f"design_frag{fp}_l{loss}_s{s}", dict(link="testbed", loss=loss, fragPayload=fp, ops="full", opsPerUav=60, opGap=0.25, video=0,
                                                         simTime=900, run=s)) for s in sx(max(seeds, 20))]
        # without combining the fragments of repeated transmissions (the implementation combines them)
        d += [(f"design_nocombine_l{loss}_s{s}", dict(link="testbed", loss=loss, combine=0, ops="full", opsPerUav=60, opGap=0.25, video=0,
                                                      simTime=900, run=s)) for s in sx(max(seeds, 20))]
    for loss in (0.0045, 0.01, 0.02, 0.05, 0.10, 0.20):
        for fec in (0, 1, 2, 3):
            for kf in (0, 1):
                d += [(f"design_video_fec{fec}_kf{kf}_l{loss}_s{s}", dict(link="testbed", loss=loss, fecParity=fec, kfRequest=kf, opsPerUav=0,
                                                                          simTime=125, run=s)) for s in sx(max(3, seeds // 2))]
    S["design"] = d
    return S


def complete(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            f.seek(max(0, path.stat().st_size - 4096))
            return b"\nM," in f.read()
    except OSError:
        return False


def run_one(name, args):
    out, log = RAW / f"{name}.csv", LOGS / f"{name}.log"
    # run at low priority: a sweep takes every core for an hour, and the machine is also the ground station
    cmd = ["nice", "-n", "12", str(BIN), "--calib=calibration/k6g_calibration.txt", f"--out=results/raw/{name}.csv", f"--tag={name}"] \
        + [f"--{k}={v}" for k, v in args.items()]
    env = {**os.environ, "LD_LIBRARY_PATH": str(NS3 / "build" / "lib")}
    t0 = time.time()
    try:
        r = subprocess.run(cmd, cwd=SIM, env=env, capture_output=True, text=True, timeout=6 * 3600)
        rc, tail = r.returncode, (r.stdout + r.stderr)[-600:]
    except subprocess.TimeoutExpired:
        rc, tail = -9, "timeout"
    ok = rc == 0 and complete(out)
    if not ok:
        log.write_text(f"{' '.join(cmd)}\nrc={rc}\n{tail}\n")
        out.unlink(missing_ok=True)
    return {"name": name, "args": args, "ok": ok, "rc": rc, "wall_s": round(time.time() - t0, 1), **({"error": tail.strip().splitlines()[-3:]} if not ok else {})}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("study", nargs="*", help="validation swarm storm mobility range crypto design (default: all)")
    ap.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 4) - 2))
    ap.add_argument("--mem-mb", type=int, default=3500, help="memory the runs may take together (default 3500 MB)")
    ap.add_argument("--seeds", type=int, default=10, help="independent runs per point (default 10; small cells get twice, large cells half)")
    ap.add_argument("--list", action="store_true", help="show what would run and stop")
    ap.add_argument("--force", action="store_true", help="run again even if the result file is there")
    ap.add_argument("--fresh", action="store_true", help="remove all earlier results first")
    ap.add_argument("--rebuild", action="store_true")
    a = ap.parse_args()
    S = studies(a.seeds)
    chosen = a.study or list(S)
    unknown = [s for s in chosen if s not in S]
    if unknown:
        sys.exit(f"unknown study {unknown}; there are: {', '.join(S)}")
    if a.fresh and not a.list:
        shutil.rmtree(SIM / "results", ignore_errors=True)
    RAW.mkdir(parents=True, exist_ok=True); LOGS.mkdir(parents=True, exist_ok=True)
    todo = [(n, args) for s in chosen for n, args in S[s] if a.force or not complete(RAW / f"{n}.csv")]
    total = sum(len(S[s]) for s in chosen)
    print(f"studies: {', '.join(chosen)} | runs: {total}, to do: {len(todo)} | {a.jobs} at a time")
    if a.list:
        for n, args in todo[:2000]:
            print(f"  {n}  {args}")
        return 0
    if not todo:
        return 0
    made_with = prepare(a.rebuild)
    manifest_path = SIM / "results" / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    before = manifest.get("_made_with")
    same = lambda x, y: all(x.get(k) == y.get(k) for k in ("calibration_sha256", "simulator_sha256", "nr_patches"))
    if any(RAW.glob("*.csv")) and not a.force and (before is None or not same(before, made_with)):
        sys.exit("results/raw holds runs made with another calibration or another simulator. Results of two kinds are not mixed:\n"
                 "  run again with --fresh (removes simulation/results and runs everything chosen), or move the old results away.")
    manifest["_made_with"] = {**made_with, "started_utc": (before or {}).get("started_utc") or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    manifest_path.write_text(json.dumps(manifest, indent=0))
    # The longest runs first (the largest cells), so the last minutes are not one core finishing a 64-UAV run. A run
    # takes one core; the large cells also take memory (measured: 100 MB at 24 UAVs, 115 MB at 32; budgeted with room
    # for full buffers), and the machine is the ground station as well, so no more of them are started than fit into
    # --mem-mb. Smaller runs fill the cores.
    todo.sort(key=lambda t: -(t[1].get("nUav", 1) * t[1].get("simTime", 1) * (1 if t[1].get("video", 1) else 0.05) * (t[1]["link"] == "nr")))
    mem_mb = lambda args: 60 if args["link"] != "nr" else 120 + (5 if args.get("video", 1) else 3) * args.get("nUav", 1)
    cv = threading.Condition()
    state = {"free": a.jobs, "mem": a.mem_mb, "done": 0, "failed": 0, "running": 0}
    t_start = time.time()

    def worker(name, args):
        res = run_one(name, args)
        with cv:
            state["free"] += 1
            state["mem"] += mem_mb(args)
            state["running"] -= 1
            state["done"] += 1
            state["failed"] += not res["ok"]
            manifest[name] = res
            if state["done"] % 25 == 0 or not res["ok"] or state["done"] == len(todo):
                manifest_path.write_text(json.dumps(manifest, indent=0))
                print(f"  {state['done']}/{len(todo)} done, {state['failed']} failed, {time.time() - t_start:.0f} s"
                      + ("" if res["ok"] else f"   FAILED {name}: {res.get('error')}"), flush=True)
            cv.notify_all()

    threads, pending = [], list(todo)
    with cv:
        while pending:
            pick = None
            if state["free"] >= 1:
                pick = next((i for i, (_, args) in enumerate(pending) if mem_mb(args) <= state["mem"] or state["running"] == 0), None)
            if pick is None:
                cv.wait()
                continue
            name, args = pending.pop(pick)
            state["free"] -= 1
            state["mem"] -= mem_mb(args)
            state["running"] += 1
            t = threading.Thread(target=worker, args=(name, args), daemon=True)
            t.start()
            threads.append(t)
    for t in threads:
        t.join()
    manifest["_made_with"]["finished_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    manifest["_made_with"]["wall_s"] = round(time.time() - t_start)
    manifest["_made_with"]["jobs"] = a.jobs
    manifest_path.write_text(json.dumps(manifest, indent=0))
    print(f"finished: {state['done']} runs, {state['failed']} failed, {time.time() - t_start:.0f} s -> {RAW}")
    return 1 if state["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
