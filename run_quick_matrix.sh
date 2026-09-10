#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/ns-3-dev"
for mode in ecc kyber kyber_cached hybrid; do
  for nodes in 10 28 56; do
    echo "RUN $mode $nodes"
    ./ns3 run "drone-swarm-pqc-sim --cryptoMode=$mode --nDrones=$nodes --numRuns=1 --seed=42" || echo "FAIL $mode $nodes"
  done
done
echo "Done: $(ls results/*nodes.csv 2>/dev/null | wc -l) CSV files"
