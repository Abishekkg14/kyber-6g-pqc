#!/usr/bin/env bash
# Kyber-6G unified experiment runner — Monte Carlo over config matrix
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS3_DIR="${SCRIPT_DIR}/ns-3-dev"
RESULTS_DIR="${NS3_DIR}/results"
NUM_RUNS="${NUM_RUNS:-30}"
SEED="${SEED:-42}"
SMOKE="${SMOKE:-0}"

MODES=(ecc kyber kyber_cached hybrid)
SIZES=(10 28 56 100 150 200)

if [[ "${CORE_ONLY:-0}" == "1" ]]; then
  SIZES=(10 28 56)
fi

if [[ "$SMOKE" == "1" ]]; then
  NUM_RUNS=3
  MODES=(ecc hybrid)
  SIZES=(10)
  echo "=== SMOKE MODE: ${NUM_RUNS} runs, modes=${MODES[*]}, sizes=${SIZES[*]} ==="
fi

mkdir -p "$RESULTS_DIR" "$RESULTS_DIR/metadata"

cd "$NS3_DIR"
echo "Building ns-3..."
./ns3 build >/dev/null

TOTAL=$((${#MODES[@]} * ${#SIZES[@]}))
COUNT=0

for mode in "${MODES[@]}"; do
  for nodes in "${SIZES[@]}"; do
    COUNT=$((COUNT + 1))
    CACHE_FLAG=false
    if [[ "$mode" == *cached* ]]; then
      CACHE_FLAG=true
    fi
    EXISTING=$(ls "${RESULTS_DIR}/${mode}_${nodes}nodes_run"*.csv 2>/dev/null | wc -l)
    if [[ "$EXISTING" -ge "$NUM_RUNS" ]]; then
      echo "[$COUNT/$TOTAL] SKIP $mode $nodes ($EXISTING runs exist)"
      continue
    fi
    echo "[$COUNT/$TOTAL] mode=$mode nodes=$nodes numRuns=$NUM_RUNS seed=$SEED (have $EXISTING)"
    ./ns3 run "drone-swarm-pqc-sim --cryptoMode=$mode --nDrones=$nodes \
      --numRuns=$NUM_RUNS --seed=$SEED --simTime=10 \
      --hardwareProfile=jetson-nano --cacheEnabled=$CACHE_FLAG" \
      2>&1 | tail -3 || echo "  WARNING: batch failed"
  done
done

echo "Experiments complete. Results in $RESULTS_DIR"
echo "Next: python3 aggregate_results.py && python3 build_results_and_plots.py"

echo "Running Phase 3 Theoretical Monte Carlo Extensions..."
python3 ../scripts/simulate_mgs_mrpmc.py
python3 ../scripts/simulate_mosaic_swarm.py
echo "Phase 3 Simulations Complete."
