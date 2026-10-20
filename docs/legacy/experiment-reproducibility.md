> **SUPERSEDED: earlier study, kept for the record only, not used in the paper.**
> This document belongs to the first phase of the project, whose simulation results were withdrawn. Its radio
> and simulator settings (for example 5G-LENA v3.1, a 3.5 GHz n78 carrier with 20 MHz, carriers at 28 GHz or
> 140 GHz, FDD, 120 m/s) do not describe the current work. The current simulation uses ns-3.42 with 5G-LENA
> NR-v3.3 and one TDD carrier at 3.5 GHz with 100 MHz and 30 kHz subcarrier spacing (simulation/README.md);
> the prototype runs over Wi-Fi only. See docs/README.md, section legacy/.

# Experiment Reproducibility

## Artifact layout

```
ns-3-dev/results/              Per-run CSV summaries
ns-3-dev/results/metadata/     Run metadata (.meta, .json)
ns-3-dev/results_data/         Intermediate time-series logs
simulation_results.json        Aggregated JSON with 95% CI
updated_access_plots_2026/     PNG + SVG + PDF figures
experiments/config.yaml        Experiment matrix definition
```

## Full reproduction

```bash
# 1. Build
cd ns-3-dev && ./ns3 configure --enable-tests && ./ns3 build

# 2. Tests
./build/utils/ns3.42-test-runner-default --suite=pqc-security

# 3. Experiments (30-run Monte Carlo)
cd .. && chmod +x run_experiments.sh
NUM_RUNS=30 SEED=42 ./run_experiments.sh

# 4. Aggregate + plot
python3 aggregate_results.py
python3 build_results_and_plots.py
```

## Smoke validation (fast)

```bash
SMOKE=1 ./run_experiments.sh
# or
cd ns-3-dev && ./ns3 run "drone-swarm-pqc-sim --cryptoMode=hybrid --nDrones=10 --numRuns=3 --seed=1"
```

## Config reference

See `experiments/config.yaml` for swarm sizes (10–200), modes, and scenario list.

## Seeds

- Base seed: `--seed=42` (default)
- Run *i* uses `seed + i` via `RngSeedManager`

## Plot captions

Modeled quantities are labeled in plot titles and `docs/simulation-methodology.md`.
