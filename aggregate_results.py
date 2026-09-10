#!/usr/bin/env python3
"""
Aggregate per-run NS-3 CSVs into simulation_results.json with 95% CI.
Reads: ns-3-dev/results/*_*nodes*.csv (and *_runN.csv variants)
"""
import csv
import glob
import json
import math
import os
import re
from collections import defaultdict

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
NS3_RESULTS = os.path.join(PROJECT_DIR, 'ns-3-dev', 'results')
JSON_OUT = os.path.join(PROJECT_DIR, 'simulation_results.json')
BASELINE_JSON = os.path.join(PROJECT_DIR, 'simulation_results_baseline.json')

MODE_MAP = {
    'ecc': 'ECC',
    'kyber': 'Kyber1024',
    'kyber_cached': 'Kyber1024-Cached',
    'hybrid': 'Hybrid-Kyber-ECDH',
}

METRICS_OF_INTEREST = [
    # Latency metrics
    'handshake_latency_us', 'handoff_latency_ms', 'e2e_app_latency_ms',
    'rrc_setup_latency_us', 'handshake_overhead_us',
    # Throughput & delivery
    'packet_delivery_ratio', 'throughput_mbps', 'throughput_bytes',
    'packet_sent_events',
    # Queueing & fragmentation
    'queueing_delay_us', 'fragment_count',
    # Crypto computation
    'crypto_computation_us', 'crypto_time_us', 'network_time_us',
    'total_cryptographic_computation_us',
    # Energy
    'crypto_compute_energy_mj', 'total_energy_mj',
    'estimated_battery_life_minutes',
    'tx_energy_mj', 'rx_energy_mj', 'idle_energy_mj', 'memory_energy_mj',
    # Cache & key management
    'cache_hit_rate', 'stale_key_events', 'revoked_key_reuse_attempts',
    # Security
    'security_bits_classical', 'security_bits_quantum', 'attack_cost_log2_ops',
    'security_strength_score', 'security_latency_efficiency',
    # RRC overhead
    'rrc_request_size_bytes', 'rrc_setup_size_bytes',
]


def t_crit_95(n):
    if n < 2:
        return 0.0
    table = {2: 12.706, 5: 2.776, 10: 2.228, 20: 2.086, 30: 2.045}
    if n >= 30:
        return 1.96
    keys = sorted(k for k in table if k <= n)
    return table.get(keys[-1], 2.0) if keys else 1.96


def parse_filename(fname):
    base = fname.replace('.csv', '')
    m = re.match(r'^(.+)_(\d+)nodes(_run(\d+))?$', base)
    if not m:
        return None
    mode_str, nodes, _, run_idx = m.groups()
    return mode_str, int(nodes), int(run_idx) if run_idx else 0


def load_csv_metrics(path):
    metrics = {}
    with open(path, 'r') as f:
        for row in csv.DictReader(f):
            name = row['metric']
            metrics[name] = {
                'mean': float(row['mean']),
                'stddev': float(row['stddev']),
                'count': int(row['count']),
            }
    return metrics


def aggregate_group(samples):
    """samples: list of per-run mean values"""
    n = len(samples)
    if n == 0:
        return None
    mean = sum(samples) / n
    if n < 2:
        stddev = 0.0
    else:
        stddev = math.sqrt(sum((x - mean) ** 2 for x in samples) / (n - 1))
    tc = t_crit_95(n)
    se = stddev / math.sqrt(n) if n > 0 else 0
    return {
        'count': n,
        'mean': mean,
        'stddev': stddev,
        'ci95_lower': mean - tc * se,
        'ci95_upper': mean + tc * se,
        'p50': sorted(samples)[n // 2],
        'p95': sorted(samples)[min(n - 1, int(n * 0.95))],
        'p99': sorted(samples)[min(n - 1, int(n * 0.99))],
        'min': min(samples),
        'max': max(samples),
    }


def main():
    pattern = os.path.join(NS3_RESULTS, '*_*nodes*.csv')
    files = [f for f in glob.glob(pattern) if 'timeseries' not in f]
    print(f"Found {len(files)} CSV files")

    groups = defaultdict(list)  # (mode, nodes) -> list of metric dicts
    for fpath in files:
        parsed = parse_filename(os.path.basename(fpath))
        if not parsed:
            continue
        mode_str, nodes, _ = parsed
        groups[(mode_str, nodes)].append(load_csv_metrics(fpath))

    results = []
    for (mode_str, nodes), run_metrics_list in sorted(groups.items()):
        crypto = MODE_MAP.get(mode_str, mode_str)
        entry = {'crypto': crypto, 'nodes': nodes, 'num_runs': len(run_metrics_list), 'metrics': {}}
        for metric_name in METRICS_OF_INTEREST:
            samples = []
            for rm in run_metrics_list:
                if metric_name in rm:
                    samples.append(rm[metric_name]['mean'])
            agg = aggregate_group(samples)
            if agg:
                entry['metrics'][metric_name] = agg
        results.append(entry)
        print(f"  Aggregated {crypto} @ {nodes} nodes ({len(run_metrics_list)} runs)")

    meta = {
        'source': 'aggregate_results.py',
        'num_files': len(files),
        'note': 'ci95_* uses t-distribution on per-run means; modeled fields labeled in docs',
    }

    out = {'metadata': meta, 'results': results}
    with open(JSON_OUT, 'w') as f:
        json.dump(out, f, indent=2)
    print(f"Wrote {JSON_OUT} ({len(results)} entries)")

    web_path = os.path.join(PROJECT_DIR, 'kyber6g-website', 'public', 'data', 'simulation_results.json')
    if os.path.isdir(os.path.dirname(web_path)):
        with open(web_path, 'w') as f:
            json.dump(out, f, indent=2)
        print(f"Mirrored to {web_path}")

    if not os.path.exists(BASELINE_JSON) and results:
        print(f"Saving baseline snapshot to {BASELINE_JSON}")
        with open(BASELINE_JSON, 'w') as f:
            json.dump(out, f, indent=2)


if __name__ == '__main__':
    main()
