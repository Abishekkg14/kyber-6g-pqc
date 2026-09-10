#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS3_DIR="${SCRIPT_DIR}/ns-3-dev"
RESULTS_DIR="${NS3_DIR}/results"

NUM_RUNS=7
SEED=42
SIZES=(10 28 56)
MODES=(ecc kyber kyber_cached hybrid)

mkdir -p "$RESULTS_DIR" "$RESULTS_DIR/metadata"
rm -rf "${RESULTS_DIR}/"*

cd "$NS3_DIR"
echo "Building ns-3..."
./ns3 build >/dev/null

echo "Starting parallel simulation of ${#MODES[@]} modes for $NUM_RUNS runs each..."

for mode in "${MODES[@]}"; do
  (
    for nodes in "${SIZES[@]}"; do
      CACHE_FLAG="false"
      if [[ "$mode" == *cached* ]]; then
        CACHE_FLAG="true"
      fi
      
      echo "[START] mode=$mode nodes=$nodes numRuns=$NUM_RUNS seed=$SEED"
      ./ns3 run "drone-swarm-pqc-sim --cryptoMode=$mode --nDrones=$nodes --numRuns=$NUM_RUNS --seed=$SEED --simTime=10 --hardwareProfile=jetson-nano --cacheEnabled=$CACHE_FLAG" >/dev/null 2>&1
      echo "[DONE] mode=$mode nodes=$nodes"
    done
  ) &
done

wait
echo "All parallel simulations complete. Results in $RESULTS_DIR"

cd "$SCRIPT_DIR"
echo "Running Phase 3 Theoretical Monte Carlo Extensions..."
python3 scripts/simulate_mgs_mrpmc.py
python3 scripts/simulate_mosaic_swarm.py
echo "Phase 3 Simulations Complete."

echo "Aggregating results..."
python3 aggregate_results.py

echo "Generating final plots..."
python3 build_results_and_plots.py

echo "All tasks finished successfully!"
