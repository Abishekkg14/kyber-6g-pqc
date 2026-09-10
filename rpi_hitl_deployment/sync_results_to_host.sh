#!/usr/bin/env bash
# ==============================================================================
# Kyber-6G Package Results Archiver
# Gathers all CSVs and logs generated on Raspberry Pi into a timestamped bundle
# ==============================================================================
RESULTS_DIR="$(dirname "$0")/results"
ARCHIVE_NAME="rpi4_hitl_results_$(date +%Y%m%d_%H%M%S).tar.gz"

cd "$RESULTS_DIR"
tar -czvf "$ARCHIVE_NAME" *.csv 2>/dev/null || true
echo "[+] Results packaged to: $RESULTS_DIR/$ARCHIVE_NAME"
echo "[+] You can copy this file to your Host PC using scp."
