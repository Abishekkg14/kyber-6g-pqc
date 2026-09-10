#!/bin/bash
set -e

cd "$(dirname "$0")"
echo "Working dir: $(pwd)"

CONFIG_FILE="../experiments/config.yaml"

if [ "$1" == "--config" ]; then
    CONFIG_FILE="$2"
fi

python3 run_experiments.py --config="$CONFIG_FILE"

