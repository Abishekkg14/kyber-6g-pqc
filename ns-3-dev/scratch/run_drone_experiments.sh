#!/bin/bash
# ═══════════════════════════════════════════════════════════
# Automated Experiment Execution Workflow
# Hybrid CRYSTALS-Kyber/X25519 Experimental Evaluation
# ═══════════════════════════════════════════════════════════

set -e

echo "Starting automated PQC vs ECC Drone Swarm evaluation..."

# Ensure we're in the right directory
if [ ! -f "ns3" ]; then
    echo "Error: Please run this script from the base ns-3 root directory."
    exit 1
fi

mkdir -p results

MODES=("ecc" "kyber" "kyber_cached" "hybrid")
NODES=(10 28 56)
TOTAL=$(( ${#MODES[@]} * ${#NODES[@]} ))
COUNT=0
FAILED=0

echo "
═══════════════════════════════════════════════════════════
  Evaluation Matrix: ${#MODES[@]} modes × ${#NODES[@]} sizes = $TOTAL runs
  Modes:  ${MODES[*]}
  Sizes:  ${NODES[*]}
═══════════════════════════════════════════════════════════"

for mode in "${MODES[@]}"; do
    for node in "${NODES[@]}"; do
        COUNT=$((COUNT + 1))
        CSV="results/${mode}_${node}nodes.csv"
        echo ""
        echo "[$COUNT/$TOTAL] Mode=$mode  Drones=$node  -> $CSV"
        if ./ns3 run "drone-swarm-pqc-sim --cryptoMode=$mode --nodes=$node" 2>&1; then
            echo "  ✓ $CSV written"
        else
            echo "  ✗ FAILED (mode=$mode, nodes=$node)"
            FAILED=$((FAILED + 1))
        fi
    done
done

# ── Validation ──
echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  RESULTS VALIDATION"
echo "═══════════════════════════════════════════════════════════"

REQUIRED_FIELDS="packet_delivery_ratio,crypto_computation_us,security_strength_score,security_latency_efficiency,handshake_latency_us,queueing_delay_us,e2e_app_latency_ms,packet_sent_events,packet_received_events"
MISSING=0

for csv in results/*.csv; do
    [ -f "$csv" ] || continue
    # Skip timeseries files
    echo "$csv" | grep -q "_timeseries" && continue
    echo -n "  Checking $csv ... "
    OK=true
    for field in $(echo "$REQUIRED_FIELDS" | tr ',' ' '); do
        if ! grep -q "$field" "$csv" 2>/dev/null; then
            echo ""
            echo "    MISSING field: $field"
            OK=false
            MISSING=$((MISSING + 1))
        fi
    done
    if $OK; then
        echo "✓ all fields present"
    fi
done

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  SUMMARY"
echo "  Completed: $((COUNT - FAILED)) / $COUNT"
echo "  Failed:    $FAILED"
echo "  Missing fields: $MISSING"
echo "═══════════════════════════════════════════════════════════"

if [ $FAILED -eq 0 ] && [ $MISSING -eq 0 ]; then
    echo "  ✓ All experiments passed validation."
else
    echo "  ✗ Some experiments had issues. Review output above."
    exit 1
fi
