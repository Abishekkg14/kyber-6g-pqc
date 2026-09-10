#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# Kyber-6G: Fully Concurrent Experiment Runner v2
# Runs 12 NS-3 processes in parallel (4 modes × 3 sizes)
# Each process does 10 internal Monte Carlo runs
# ──────────────────────────────────────────────────────────────
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NS3_DIR="${SCRIPT_DIR}/ns-3-dev"
RESULTS_DIR="${NS3_DIR}/results"
NPROC=$(nproc)

NUM_RUNS=10
SEED=42

MODES=(ecc kyber kyber_cached hybrid)
SIZES=(10 28 56)

TOTAL_CONFIGS=$(( ${#MODES[@]} * ${#SIZES[@]} ))

echo "═══════════════════════════════════════════════════════════"
echo "  Kyber-6G Concurrent Experiment Runner v2"
echo "  CPU cores: ${NPROC} | Runs/config: ${NUM_RUNS}"
echo "  Parallel configs: ${TOTAL_CONFIGS} (${#MODES[@]} modes × ${#SIZES[@]} sizes)"
echo "  Total simulations: $(( TOTAL_CONFIGS * NUM_RUNS ))"
echo "═══════════════════════════════════════════════════════════"

# Clean old results
rm -rf "${RESULTS_DIR}/"*
mkdir -p "$RESULTS_DIR" "$RESULTS_DIR/metadata"

# Step 1: Build ns-3 (already cached from previous run)
cd "$NS3_DIR"
echo ""
echo "[1/4] Building ns-3..."
./ns3 build >/dev/null 2>&1
echo "  ✓ Build complete"

START_TIME=$(date +%s)

# Step 2: Launch all 12 configs in parallel
# Each config runs numRuns=10 internally (sequential within each process)
# NS-3 handles _runN naming when numRuns > 1
echo ""
echo "[2/4] Launching ${TOTAL_CONFIGS} parallel NS-3 processes..."

PIDS=()
for mode in "${MODES[@]}"; do
  for nodes in "${SIZES[@]}"; do
    CACHE_FLAG="false"
    [[ "$mode" == *cached* ]] && CACHE_FLAG="true"
    
    (
      cd "$NS3_DIR"
      echo "  → Starting ${mode}/${nodes}nodes (${NUM_RUNS} runs)..."
      ./ns3 run "drone-swarm-pqc-sim --cryptoMode=${mode} --nDrones=${nodes} \
        --numRuns=${NUM_RUNS} --seed=${SEED} --simTime=10 \
        --hardwareProfile=jetson-nano --cacheEnabled=${CACHE_FLAG}" \
        >/dev/null 2>&1
      
      if [ $? -eq 0 ]; then
        echo "  ✓ DONE ${mode}/${nodes}nodes"
      else
        echo "  ✗ FAIL ${mode}/${nodes}nodes"
      fi
    ) &
    PIDS+=($!)
  done
done

echo "  Waiting for ${#PIDS[@]} processes (PIDs: ${PIDS[*]})..."

# Wait for all and track failures
FAIL_COUNT=0
for pid in "${PIDS[@]}"; do
  wait "$pid" || ((FAIL_COUNT++))
done

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

# Count results
CSV_COUNT=$(find "${RESULTS_DIR}" -name '*_run*.csv' ! -name '*timeseries*' 2>/dev/null | wc -l)
echo ""
echo "  ✓ Simulations complete in ${ELAPSED}s ($(( ELAPSED / 60 ))m $(( ELAPSED % 60 ))s)"
echo "  Generated ${CSV_COUNT} result CSV files (${FAIL_COUNT} failures)"

# Step 3: Phase 3 theoretical extensions
cd "$SCRIPT_DIR"
echo ""
echo "[3/4] Running Phase 3 theoretical extensions..."
python3 scripts/simulate_mgs_mrpmc.py 2>&1 | tail -2
python3 scripts/simulate_mosaic_swarm.py 2>&1 | tail -2
echo "  ✓ Phase 3 complete"

# Step 4: Aggregate + generate plots
echo ""
echo "[4/4] Aggregating results & generating plots..."
python3 aggregate_results.py
python3 build_results_and_plots.py

TOTAL_END=$(date +%s)
TOTAL_ELAPSED=$((TOTAL_END - START_TIME))
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  ALL DONE in ${TOTAL_ELAPSED}s ($(( TOTAL_ELAPSED / 60 ))m $(( TOTAL_ELAPSED % 60 ))s)"
echo "  Results: ${RESULTS_DIR}"
echo "  Plots:   ${SCRIPT_DIR}/final_publication_plots_2026/"
echo "═══════════════════════════════════════════════════════════"
