#!/usr/bin/env bash
# Kyber-6G Paper Experiment Runner
# Targeted experiment matrix for publication (~170 runs)
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS3_DIR="${SCRIPT_DIR}/../ns-3-dev"
RESULTS_DIR="${NS3_DIR}/results"
SEED="${SEED:-42}"
SEEDS=10  # per configuration

echo "╔════════════════════════════════════════════════════════╗"
echo "║    Kyber-6G Paper Experiment Matrix                   ║"
echo "╚════════════════════════════════════════════════════════╝"

mkdir -p "$RESULTS_DIR" "$RESULTS_DIR/metadata"
cd "$NS3_DIR"
echo "Building ns-3..."
./ns3 build >/dev/null

RUN_SIM() {
    local desc="$1"; shift
    echo "  → $desc"
    ./ns3 run "drone-swarm-pqc-sim $*" 2>&1 | tail -1 || echo "    WARNING: run failed"
}

# ══════════════════════════════════════════════════════════════
# Experiment 1: Full KEM comparison (4 modes × 10 seeds = 40 runs)
# ══════════════════════════════════════════════════════════════
echo ""
echo "═══ Experiment 1: Full KEM Comparison ═══"
for mode in ecc kyber kyber_cached hybrid; do
    RUN_SIM "KEM $mode (N=10, 10 seeds)" \
        "--cryptoMode=$mode --nDrones=10 --numRuns=$SEEDS --seed=$SEED --simTime=10"
done

# ══════════════════════════════════════════════════════════════
# Experiment 2: Mobility sweep (4 speeds × 10 seeds = 40 runs)
# ══════════════════════════════════════════════════════════════
echo ""
echo "═══ Experiment 2: Mobility Sweep ═══"
for speed in 0 5 20 50; do
    RUN_SIM "Speed ${speed}m/s" \
        "--cryptoMode=hybrid --nDrones=10 --numRuns=$SEEDS --seed=$SEED --speed=$speed --simTime=10"
done

# ══════════════════════════════════════════════════════════════
# Experiment 3: Loss sweep (3 rates × 10 seeds = 30 runs)
# ══════════════════════════════════════════════════════════════
echo ""
echo "═══ Experiment 3: Loss Rate Sweep ═══"
for loss in 0.0 0.01 0.05; do
    RUN_SIM "Loss ${loss}" \
        "--cryptoMode=hybrid --nDrones=10 --numRuns=$SEEDS --seed=$SEED --lossRate=$loss --simTime=10"
done

# ══════════════════════════════════════════════════════════════
# Experiment 4: 5G vs 6G band (2 bands × 3 KEMs × 10 seeds = 60 runs)
# ══════════════════════════════════════════════════════════════
echo ""
echo "═══ Experiment 4: 5G vs 6G Band Comparison ═══"
for band in 5g-3.5ghz 6g-140ghz; do
    for mode in ecc kyber hybrid; do
        RUN_SIM "Band $band, mode $mode" \
            "--cryptoMode=$mode --nDrones=10 --numRuns=$SEEDS --seed=$SEED --band=$band --simTime=10"
    done
done

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  Paper experiments complete."
echo "  Next steps:"
echo "    cd .. && python3 aggregate_results.py"
echo "    python3 scripts/paper_analysis.py"
echo "    python3 build_results_and_plots.py"
echo "═══════════════════════════════════════════════════════════"
