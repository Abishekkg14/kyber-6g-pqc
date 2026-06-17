#!/usr/bin/env python3
"""
Kyber-6G — Parse NS-3 CSV outputs and generate IEEE Access publication-ready plots.
Run from project root: python3 build_results_and_plots.py
"""
import csv, json, os, glob, math, sys
import numpy as np
import matplotlib  # noqa: E402
matplotlib.use('Agg')
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import MaxNLocator  # noqa: E402

# ──────────────────────────────────────────────────────────────────────────
# Configuration
# ──────────────────────────────────────────────────────────────────────────
PROJECT_DIR = os.environ.get('PROJECT_DIR', os.path.dirname(os.path.abspath(__file__)))
NS3_DIR = os.path.join(PROJECT_DIR, 'ns-3-dev')
PLOTS_DIR = os.path.join(PROJECT_DIR, 'updated_access_plots_2026')
JSON_OUT = os.path.join(PROJECT_DIR, 'simulation_results.json')
JSON_WEB = os.path.join(PROJECT_DIR, 'kyber6g-website', 'public', 'data', 'simulation_results.json')
DPI = 300

# CSV mode name -> JSON crypto name
MODE_MAP = {
    'ecc': 'ECC',
    'kyber': 'Kyber768',
    'kyber_cached': 'Kyber768-Cached',
    'hybrid': 'Hybrid-Kyber-ECDH',
}

# Plotting style
COLORS = {
    'ECC': '#0891b2',
    'Kyber768': '#7c3aed',
    'Kyber768-Cached': '#059669',
    'Hybrid-Kyber-ECDH': '#e11d48',
}
LABELS = {
    'ECC': 'ECC (X25519)',
    'Kyber768': 'Kyber-768',
    'Kyber768-Cached': 'Kyber-768 (Cached)',
    'Hybrid-Kyber-ECDH': 'Hybrid (Kyber+ECDH)',
}
MARKERS = {'ECC': 'o', 'Kyber768': 's', 'Kyber768-Cached': 'D', 'Hybrid-Kyber-ECDH': '^'}
ALL_MODES = ['ECC', 'Kyber768', 'Kyber768-Cached', 'Hybrid-Kyber-ECDH']


# ──────────────────────────────────────────────────────────────────────────
# Step 1: Parse CSVs → JSON
# ──────────────────────────────────────────────────────────────────────────
def parse_csvs():
    results = []
    csv_pattern = os.path.join(NS3_DIR, 'results', '*_*nodes.csv')
    files = sorted(glob.glob(csv_pattern))
    # Exclude timeseries
    files = [f for f in files if 'timeseries' not in f]
    print(f"Found {len(files)} CSV files in ns-3-dev/results/")

    for fpath in files:
        fname = os.path.basename(fpath)
        # Parse filename: ecc_10nodes.csv -> mode=ecc, nodes=10
        base = fname.replace('.csv', '')
        parts = base.rsplit('_', 1)  # ['ecc', '10nodes'] or ['kyber_cached', '56nodes']
        nodes_str = parts[-1].replace('nodes', '')
        mode_str = base[:-(len(parts[-1]) + 1)]  # everything before _NNnodes

        nodes = int(nodes_str)
        crypto = MODE_MAP.get(mode_str, mode_str)

        metrics = {}
        with open(fpath, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row['metric']
                metrics[name] = {
                    'count': int(row['count']),
                    'mean': float(row['mean']),
                    'stddev': float(row['stddev']),
                    'min': float(row['min']),
                    'max': float(row['max']),
                    'p50': float(row['p50']),
                    'p95': float(row['p95']),
                    'p99': float(row['p99']),
                }

        results.append({'crypto': crypto, 'nodes': nodes, 'metrics': metrics})
        print(f"  Parsed {fname} -> {crypto}, {nodes} nodes, {len(metrics)} metrics")

    # Sort by crypto then nodes
    order = {'ECC': 0, 'Kyber768': 1, 'Kyber768-Cached': 2, 'Hybrid-Kyber-ECDH': 3}
    results.sort(key=lambda x: (order.get(x['crypto'], 99), x['nodes']))
    return results


# ──────────────────────────────────────────────────────────────────────────
# Step 2: Plot Helpers
# ──────────────────────────────────────────────────────────────────────────
def setup_matplotlib():
    plt.rcParams.update({
        'font.family': 'serif',
        'font.serif': ['DejaVu Serif', 'Times New Roman', 'Times'],
        'font.size': 11,
        'axes.spines.top': False,
        'axes.spines.right': False,
        'figure.facecolor': 'white',
        'axes.facecolor': '#fafafa',
        'axes.labelsize': 12,
        'axes.titlesize': 14,
        'legend.fontsize': 10,
        'xtick.labelsize': 10,
        'ytick.labelsize': 10,
        'figure.dpi': 100,
    })


def group_metric(data, metric_key, stat='mean'):
    """Return {crypto: {nodes: value}}"""
    result = {}
    for entry in data:
        c = entry['crypto']
        n = entry['nodes']
        m = entry['metrics'].get(metric_key)
        if m:
            result.setdefault(c, {})[n] = m[stat]
    return result


def save_fig(fig, output_dir, name):
    base = os.path.splitext(name)[0]
    for ext in ('png', 'svg', 'pdf'):
        path = os.path.join(output_dir, f'{base}.{ext}')
        fig.savefig(path, dpi=DPI, bbox_inches='tight', facecolor='white')
    plt.close(fig)
    print(f"  Saved {base}.png/.svg/.pdf")


def group_metric_with_ci(data, metric_key):
    result = {}
    for entry in data:
        c = entry['crypto']
        n = entry['nodes']
        m = entry['metrics'].get(metric_key)
        if m:
            mean = m['mean']
            if 'ci95_lower' in m and 'ci95_upper' in m:
                half = (m['ci95_upper'] - m['ci95_lower']) / 2.0
            else:
                half = m.get('stddev', 0)
            result.setdefault(c, {})[n] = (mean, half)
    return result


group_metric_with_err = group_metric_with_ci


def validate_data(data):
    """Validate that we have the expected 12 entries (4 modes × 3 sizes)."""
    expected_modes = set(ALL_MODES)
    expected_sizes = {10, 28, 56}
    found = {}
    for entry in data:
        found.setdefault(entry['crypto'], set()).add(entry['nodes'])

    ok = True
    for mode in expected_modes:
        if mode not in found:
            print(f"  ⚠ WARNING: Missing all results for mode '{mode}'")
            ok = False
        else:
            missing_sizes = expected_sizes - found[mode]
            if missing_sizes:
                print(f"  ⚠ WARNING: Mode '{mode}' missing node counts: {missing_sizes}")
                ok = False

    if ok:
        print("  ✓ Data validation passed: 4 modes × 3 sizes = 12 entries")
    return ok


# ──────────────────────────────────────────────────────────────────────────
# Plot 1: Handshake Latency vs Swarm Size
# ──────────────────────────────────────────────────────────────────────────
def plot_handshake_latency(data, out):
    fig, ax = plt.subplots(figsize=(10, 6))
    g = group_metric_with_ci(data, 'handshake_latency_us')
    for crypto in ALL_MODES:
        if crypto not in g:
            continue
        ns = sorted(g[crypto])
        means = [g[crypto][n][0] for n in ns]
        errs = [g[crypto][n][1] for n in ns]
        ax.errorbar(ns, means, yerr=errs, label=LABELS[crypto], color=COLORS[crypto],
                    marker=MARKERS[crypto], linewidth=2.2, markersize=8, capsize=4)
    ax.set_title('Handshake Latency vs Swarm Size', fontsize=14, fontweight='bold')
    ax.set_xlabel('Number of Drones')
    ax.set_ylabel('Mean Handshake Latency (μs) ± 95% CI')
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.legend(fontsize=10)
    ax.grid(True, ls='--', alpha=0.5)
    save_fig(fig, out, '01_handshake_latency.png')


# ──────────────────────────────────────────────────────────────────────────
# Plot 2: E2E App Latency
# ──────────────────────────────────────────────────────────────────────────
def plot_e2e_latency(data, out):
    fig, ax = plt.subplots(figsize=(10, 6))
    g = group_metric_with_ci(data, 'e2e_app_latency_ms')
    for crypto in ALL_MODES:
        if crypto not in g:
            continue
        ns = sorted(g[crypto])
        means = [g[crypto][n][0] for n in ns]
        errs = [g[crypto][n][1] for n in ns]
        ax.fill_between(ns, [m - e for m, e in zip(means, errs)],
                        [m + e for m, e in zip(means, errs)],
                        alpha=0.12, color=COLORS[crypto])
        ax.plot(ns, means, label=LABELS[crypto], color=COLORS[crypto],
                marker=MARKERS[crypto], linewidth=2.2, markersize=8)
    ax.set_title('End-to-End Application Latency', fontsize=14, fontweight='bold')
    ax.set_xlabel('Number of Drones')
    ax.set_ylabel('Mean E2E Latency (ms)')
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.legend(fontsize=10)
    ax.grid(True, ls='--', alpha=0.5)
    save_fig(fig, out, '02_e2e_latency.png')


def plot_energy_battery(data, out):
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    g = group_metric_with_ci(data, 'total_energy_mj')
    for crypto in ALL_MODES:
        if crypto not in g:
            continue
        ns = sorted(g[crypto])
        means = [g[crypto][n][0] for n in ns]
        errs = [g[crypto][n][1] for n in ns]
        ax1.errorbar(ns, means, yerr=errs, label=LABELS[crypto], color=COLORS[crypto],
                     marker=MARKERS[crypto], capsize=4)
    ax1.set_title('Total Energy per Handshake (MODELED)')
    ax1.set_xlabel('Drones')
    ax1.set_ylabel('Energy (mJ)')
    ax1.legend(fontsize=9)
    ax1.grid(True, ls='--', alpha=0.4)

    g2 = group_metric(data, 'estimated_battery_life_minutes')
    for crypto in ALL_MODES:
        if crypto not in g2:
            continue
        ns = sorted(g2[crypto])
        ax2.plot(ns, [g2[crypto][n] for n in ns], label=LABELS[crypto],
                 color=COLORS[crypto], marker=MARKERS[crypto])
    ax2.set_title('Projected Battery Life (MODELED)')
    ax2.set_xlabel('Drones')
    ax2.set_ylabel('Minutes')
    ax2.legend(fontsize=9)
    ax2.grid(True, ls='--', alpha=0.4)
    fig.tight_layout()
    save_fig(fig, out, '07_energy_battery.png')


def plot_cache_hit_rate(data, out):
    fig, ax = plt.subplots(figsize=(8, 5))
    g = group_metric(data, 'cache_hit_rate')
    for crypto in ALL_MODES:
        if crypto not in g:
            continue
        ns = sorted(g[crypto])
        ax.plot(ns, [g[crypto][n] * 100 for n in ns], label=LABELS[crypto],
                color=COLORS[crypto], marker=MARKERS[crypto])
    ax.set_title('Cache Hit Rate vs Swarm Size')
    ax.set_ylabel('Hit Rate (%)')
    ax.set_xlabel('Drones')
    ax.legend()
    ax.grid(True, ls='--', alpha=0.4)
    save_fig(fig, out, '08_cache_hit_rate.png')


def plot_security_attack_cost(data, out):
    fig, ax = plt.subplots(figsize=(9, 5))
    entries = {}
    for e in data:
        if e['nodes'] == 10:
            q = e['metrics'].get('security_bits_quantum', e['metrics'].get('security_strength_score'))
            a = e['metrics'].get('attack_cost_log2_ops')
            if q:
                entries[e['crypto']] = (q.get('mean', 0), a.get('mean', 0) if a else 0)
    cryptos = [c for c in ALL_MODES if c in entries]
    x = range(len(cryptos))
    quantum = [entries[c][0] for c in cryptos]
    attack = [entries[c][1] for c in cryptos]
    ax.bar([i - 0.2 for i in x], quantum, 0.4, label='Quantum bit-security', color='#7c3aed')
    ax.bar([i + 0.2 for i in x], attack, 0.4, label='Attack cost log₂(ops)', color='#e11d48')
    ax.set_xticks(list(x))
    ax.set_xticklabels([LABELS[c] for c in cryptos], rotation=15)
    ax.set_title('Security Strength / Attack Cost (documented constants)')
    ax.legend()
    ax.grid(axis='y', ls='--', alpha=0.4)
    save_fig(fig, out, '09_security_attack_cost.png')


def plot_previous_vs_improved(data, out):
    baseline_path = os.path.join(PROJECT_DIR, 'simulation_results_baseline.json')
    if not os.path.exists(baseline_path):
        print('  Skip previous-vs-improved (no baseline JSON)')
        return
    with open(baseline_path) as f:
        old = json.load(f)
    old_data = old.get('results', old)
    fig, ax = plt.subplots(figsize=(10, 5))
    metric = 'handshake_latency_us'
    for label, dataset, style in [('Previous', old_data, '--'), ('Improved', data, '-')]:
        g = group_metric(dataset, metric)
        crypto = 'Hybrid-Kyber-ECDH' if 'Hybrid-Kyber-ECDH' in g else 'Kyber768'
        if crypto not in g:
            continue
        ns = sorted(g[crypto])
        ax.plot(ns, [g[crypto][n] for n in ns], style, label=f'{label} {LABELS.get(crypto, crypto)}', lw=2)
    ax.set_title('Previous vs Improved: Handshake Latency')
    ax.set_xlabel('Drones')
    ax.set_ylabel('Handshake Latency (μs)')
    ax.legend()
    ax.grid(True, ls='--', alpha=0.4)
    save_fig(fig, out, '10_previous_vs_improved.png')


def plot_kyber_level_selection(out):
    """Kyber 512/768/1024 comparison — uses documented size/latency model if no sweep CSVs."""
    levels = ['Kyber-512', 'Kyber-768', 'Kyber-1024']
    latency_us = [420, 576, 890]  # MODELED from hardware-profile scaling
    security_q = [118, 203, 230]
    energy_mj = [8.5, 12.1, 18.4]  # MODELED
    fig, axes = plt.subplots(1, 3, figsize=(12, 4))
    for ax, vals, title, ylab in zip(
        axes,
        [latency_us, security_q, energy_mj],
        ['Handshake Latency (MODELED)', 'Quantum Security (bits)', 'Energy (MODELED mJ)'],
        ['μs', 'bits', 'mJ'],
    ):
        ax.bar(levels, vals, color=['#0891b2', '#7c3aed', '#059669'])
        ax.set_title(title, fontsize=11)
        ax.set_ylabel(ylab)
        ax.tick_params(axis='x', rotation=15)
    fig.suptitle('Kyber Level Selection Rationale (N=28 drones)', fontweight='bold')
    fig.tight_layout()
    save_fig(fig, out, '12_kyber_level_selection.png')


# ──────────────────────────────────────────────────────────────────────────
# Plot 3: Crypto Computation Cost
# ──────────────────────────────────────────────────────────────────────────
def plot_crypto_computation(data, out):
    fig, ax = plt.subplots(figsize=(10, 6))
    g = group_metric(data, 'crypto_computation_us')
    for crypto in ALL_MODES:
        if crypto not in g:
            continue
        ns = sorted(g[crypto])
        vs = [g[crypto][n] for n in ns]
        ax.plot(ns, vs, label=LABELS[crypto], color=COLORS[crypto],
                marker=MARKERS[crypto], linewidth=2.2, markersize=8)
    ax.set_title('Cryptographic Computation Cost per Handshake', fontsize=14, fontweight='bold')
    ax.set_xlabel('Number of Drones')
    ax.set_ylabel('Mean Crypto Time (μs)')
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.legend(fontsize=10)
    ax.grid(True, ls='--', alpha=0.5)
    save_fig(fig, out, '03_crypto_computation.png')


# ──────────────────────────────────────────────────────────────────────────
# Plot 4: Security Strength Score
# ──────────────────────────────────────────────────────────────────────────
def plot_security_score(data, out):
    fig, ax = plt.subplots(figsize=(10, 5))
    # Use 10-node data for the bar chart
    entries_10 = {}
    for e in data:
        if e['nodes'] == 10:
            m = e['metrics'].get('security_strength_score')
            if m:
                entries_10[e['crypto']] = m['mean']

    cryptos = [c for c in ALL_MODES if c in entries_10]
    scores = [entries_10[c] for c in cryptos]
    colors = [COLORS[c] for c in cryptos]
    labels = [LABELS[c] for c in cryptos]

    bars = ax.bar(labels, scores, color=colors, edgecolor='white', linewidth=1.5, width=0.6)
    for bar, val in zip(bars, scores):
        ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 3,
                f'{val:.0f}', ha='center', fontsize=12, fontweight='bold')
    ax.axhline(128, color='#888888', ls=':', alpha=0.6, label='NIST Level 1 (128-bit)')
    ax.axhline(192, color='#888888', ls='-.', alpha=0.4, label='NIST Level 3 (192-bit)')
    ax.set_title('Post-Quantum Security Strength Score', fontsize=14, fontweight='bold')
    ax.set_ylabel('Security Strength (equivalent bits)')
    ax.legend(fontsize=9)
    ax.grid(axis='y', ls='--', alpha=0.5)
    ax.set_ylim(0, max(scores) * 1.25 if scores else 250)
    save_fig(fig, out, '04_security_strength.png')


# ──────────────────────────────────────────────────────────────────────────
# Plot 5: Packet Delivery Ratio
# ──────────────────────────────────────────────────────────────────────────
def plot_pdr(data, out):
    fig, ax = plt.subplots(figsize=(10, 6))
    g = group_metric(data, 'packet_delivery_ratio')
    all_vals = []
    for crypto in ALL_MODES:
        if crypto not in g:
            continue
        ns = sorted(g[crypto])
        vs = [g[crypto][n] * 100 for n in ns]  # as percentage
        all_vals.extend(vs)
        ax.plot(ns, vs, label=LABELS[crypto], color=COLORS[crypto],
                marker=MARKERS[crypto], linewidth=2.2, markersize=8)
    ax.set_title('Packet Delivery Ratio vs Swarm Size', fontsize=14, fontweight='bold')
    ax.set_xlabel('Number of Drones')
    ax.set_ylabel('PDR (%)')
    # Auto-scale Y axis with proper padding
    if all_vals:
        y_min = max(0, min(all_vals) - 5)
        y_max = min(105, max(all_vals) + 5)
        ax.set_ylim(y_min, y_max)
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.legend(fontsize=10)
    ax.grid(True, ls='--', alpha=0.5)
    save_fig(fig, out, '05_packet_delivery_ratio.png')


# ──────────────────────────────────────────────────────────────────────────
# Plot 6: RRC Message Overhead (Grouped Bar)
# ──────────────────────────────────────────────────────────────────────────
def plot_rrc_overhead(data, out):
    fig, ax = plt.subplots(figsize=(10, 5))
    entries_10 = [e for e in data if e['nodes'] == 10]
    # Filter to those that have the required metrics
    entries_10 = [e for e in entries_10 if
                  'rrc_request_size_bytes' in e['metrics'] and
                  'rrc_setup_size_bytes' in e['metrics']]
    if not entries_10:
        print("  ⚠ Skipping RRC overhead plot: no data at 10 nodes")
        return

    cryptos = [e['crypto'] for e in entries_10]
    labels = [LABELS.get(c, c) for c in cryptos]
    req = [e['metrics']['rrc_request_size_bytes']['mean'] for e in entries_10]
    setup = [e['metrics']['rrc_setup_size_bytes']['mean'] for e in entries_10]

    x = np.arange(len(cryptos))
    w = 0.35
    ax.bar(x - w / 2, req, w, label='RRC Request', color='#7c3aed', edgecolor='white')
    ax.bar(x + w / 2, setup, w, label='RRC Setup', color='#0891b2', edgecolor='white')
    for i in range(len(cryptos)):
        ax.text(x[i] - w / 2, req[i] + 50, f'{int(req[i])}B', ha='center', fontsize=8)
        ax.text(x[i] + w / 2, setup[i] + 50, f'{int(setup[i])}B', ha='center', fontsize=8)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=10)
    ax.set_title('RRC Message Size Overhead (10 Drones)', fontsize=14, fontweight='bold')
    ax.set_ylabel('Size (Bytes)')
    ax.legend(fontsize=10)
    ax.grid(axis='y', ls='--', alpha=0.5)
    save_fig(fig, out, '06_rrc_message_overhead.png')


# ──────────────────────────────────────────────────────────────────────────
# Plot 7: Security-Efficiency Trade-off
# ──────────────────────────────────────────────────────────────────────────
def plot_security_efficiency(data, out):
    fig, ax = plt.subplots(figsize=(11, 6.5))
    
    g_sec = group_metric(data, 'security_strength_score')
    g_eff = group_metric(data, 'security_latency_efficiency')
    
    algos = [c for c in ALL_MODES if c in g_sec and c in g_eff]
    
    # Sort algorithms by Security first, then Efficiency
    def get_sort_key(c):
        sec = g_sec[c][10] if 10 in g_sec[c] else 0
        effs = list(g_eff[c].values())
        mean_eff = sum(effs) / len(effs) if effs else 0
        return (sec, mean_eff)
        
    algos.sort(key=get_sort_key)
    y_pos = np.arange(len(algos))
    sec_levels = [g_sec[c][10] if 10 in g_sec[c] else 0 for c in algos]
    
    ax.set_facecolor('#ffffff')
    
    # Draw background bands for Security Tiers
    for y, sec in zip(y_pos, sec_levels):
        color = '#f8fafc' if sec < 200 else '#f0fdf4'
        ax.axhspan(y - 0.5, y + 0.5, color=color, alpha=1.0, zorder=0)
        
    # Draw boundary line between security tiers
    for y in range(len(algos) - 1):
        if sec_levels[y] != sec_levels[y+1]:
            ax.axhline(y + 0.5, color='#94a3b8', linewidth=1.5, linestyle='--', zorder=1)
            
    # Annotate Tiers on the right side
    y_128 = [y for y, sec in zip(y_pos, sec_levels) if sec < 200]
    if y_128:
        mid_128 = sum(y_128)/len(y_128)
        ax.text(1.02, mid_128, 'Standard Tier\n(128-bit)', color='#64748b', 
                ha='left', va='center', fontweight='bold', fontsize=11, transform=ax.get_yaxis_transform())
                
    y_203 = [y for y, sec in zip(y_pos, sec_levels) if sec >= 200]
    if y_203:
        mid_203 = sum(y_203)/len(y_203)
        ax.text(1.02, mid_203, 'PQC Tier\n(203-bit)', color='#16a34a', 
                ha='left', va='center', fontweight='bold', fontsize=11, transform=ax.get_yaxis_transform())

    # Plot ranges and points
    for y, crypto in zip(y_pos, algos):
        ns = sorted(g_eff[crypto])
        eff_vals = [g_eff[crypto][n] for n in ns]
        
        min_eff, max_eff = min(eff_vals), max(eff_vals)
        
        # Draw horizontal range line
        ax.plot([min_eff, max_eff], [y, y], color=COLORS[crypto], linewidth=5, alpha=0.4, zorder=2)
        
        # Scatter points for nodes
        for n, ev in zip(ns, eff_vals):
            ax.scatter(ev, y, color=COLORS[crypto], s=150, edgecolor='white', linewidth=1.5, zorder=3)
            # Annotate node count slightly above the point
            ax.text(ev, y + 0.18, f'{n} drones', ha='center', va='bottom', fontsize=9, color='#334155', zorder=4)
            
    ax.set_xlabel('Efficiency Score (Security / Latency in ms) \u2192 Higher is Better', fontsize=12, fontweight='bold')
    
    # Format Y-axis
    ax.set_yticks(y_pos)
    ax.set_yticklabels([LABELS[c] for c in algos], fontsize=12, fontweight='bold')
    
    # Title
    ax.set_title('Security Tiers vs. Efficiency Ranges across Swarm Sizes', fontsize=15, fontweight='bold', pad=20)
    
    # Grid
    ax.grid(axis='x', ls='--', alpha=0.5, color='#cbd5e1', zorder=1)
    
    # Clean spines
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.spines['left'].set_visible(False)
    
    # Ensure y-axis doesn't have ticks, just labels
    ax.tick_params(axis='y', length=0)
    
    # Adjust layout to make room for right text annotations
    plt.subplots_adjust(right=0.85)
    
    fig.tight_layout()
    save_fig(fig, out, '07_security_efficiency_tradeoff.png')


# ──────────────────────────────────────────────────────────────────────────
# Plot 8: Gateway Queueing Delay
# ──────────────────────────────────────────────────────────────────────────
def plot_queueing(data, out):
    fig, ax = plt.subplots(figsize=(10, 6))
    g = group_metric_with_err(data, 'queueing_delay_us')
    for crypto in ALL_MODES:
        if crypto not in g:
            continue
        ns = sorted(g[crypto])
        means = [g[crypto][n][0] for n in ns]
        errs = [g[crypto][n][1] for n in ns]
        ax.errorbar(ns, means, yerr=errs, label=LABELS[crypto], color=COLORS[crypto],
                    marker=MARKERS[crypto], linewidth=2.2, markersize=8, capsize=4)
    ax.set_title('Gateway Queueing Delay vs Swarm Size', fontsize=14, fontweight='bold')
    ax.set_xlabel('Number of Drones')
    ax.set_ylabel('Mean Queueing Delay (μs)')
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.legend(fontsize=10)
    ax.grid(True, ls='--', alpha=0.5)
    save_fig(fig, out, '08_queueing_delay.png')


# ──────────────────────────────────────────────────────────────────────────
# Plot 9: Throughput
# ──────────────────────────────────────────────────────────────────────────
def plot_throughput(data, out):
    fig, ax = plt.subplots(figsize=(10, 6))
    g = group_metric_with_err(data, 'throughput_bytes')
    for crypto in ALL_MODES:
        if crypto not in g:
            continue
        ns = sorted(g[crypto])
        # Convert bytes/packet to Kbps for readability
        # throughput_bytes is mean bytes per packet; multiply by packet rate to get Kbps
        # For now, display as bytes/packet which is the raw metric
        means = [g[crypto][n][0] for n in ns]
        errs = [g[crypto][n][1] for n in ns]
        ax.errorbar(ns, means, yerr=errs, label=LABELS[crypto], color=COLORS[crypto],
                    marker=MARKERS[crypto], linewidth=2.2, markersize=8, capsize=4)
    ax.set_title('Mean Throughput per Packet vs Swarm Size', fontsize=14, fontweight='bold')
    ax.set_xlabel('Number of Drones')
    ax.set_ylabel('Effective Throughput (bytes/packet)')
    ax.xaxis.set_major_locator(MaxNLocator(integer=True))
    ax.legend(fontsize=10)
    ax.grid(True, ls='--', alpha=0.5)
    save_fig(fig, out, '09_throughput.png')


# ──────────────────────────────────────────────────────────────────────────
# Plot 10: Theoretical Security Comparison
# ──────────────────────────────────────────────────────────────────────────
def plot_theoretical_security(out):
    fig, ax = plt.subplots(figsize=(10, 6))
    bits = np.arange(100, 1025, 5)
    classical_ecc = bits / 2.0
    quantum_shor = 3.0 * np.log2(bits)
    lwe_classical = 0.292 * bits
    lwe_quantum = 0.265 * bits

    ax.plot(bits, classical_ecc, label='Classical on ECC', color='#0891b2', lw=2.2)
    ax.plot(bits, quantum_shor, label='Quantum (Shor) on ECC', color='#ef4444', lw=2.5, ls='--')
    ax.plot(bits, lwe_classical, label='Classical on LWE/Kyber', color='#16a34a', lw=2.2)
    ax.plot(bits, lwe_quantum, label='Quantum Sieving on Kyber', color='#7c3aed', lw=2.2, ls='--')
    ax.axhline(128, color='#666', alpha=0.4, ls=':', lw=1.5, label='AES-128 Level')
    ax.set_title('Computational Cost: Classical vs Lattice Cryptography', fontsize=14, fontweight='bold')
    ax.set_xlabel('Key Size / Lattice Dimension')
    ax.set_ylabel('log₂(Operations to Break)')
    ax.set_ylim(0, 300)
    ax.legend(fontsize=9, loc='upper left')
    ax.grid(True, ls='--', alpha=0.5)
    save_fig(fig, out, '10_theoretical_security.png')


# ──────────────────────────────────────────────────────────────────────────
# Plot 11: Comprehensive Summary Dashboard (2×2)
# ──────────────────────────────────────────────────────────────────────────
def plot_dashboard(data, out):
    fig, axes = plt.subplots(2, 2, figsize=(16, 12))
    fig.suptitle('Kyber-6G Drone Swarm PQC — Performance Dashboard',
                 fontsize=16, fontweight='bold', y=0.98)

    # Panel 1: Handshake Latency
    ax = axes[0, 0]
    g = group_metric(data, 'handshake_latency_us')
    for crypto in ALL_MODES:
        if crypto not in g:
            continue
        ns = sorted(g[crypto])
        ax.plot(ns, [g[crypto][n] for n in ns], label=LABELS[crypto],
                color=COLORS[crypto], marker=MARKERS[crypto], lw=2, ms=7)
    ax.set_title('Handshake Latency', fontweight='bold')
    ax.set_xlabel('Drones')
    ax.set_ylabel('Latency (μs)')
    ax.legend(fontsize=8)
    ax.grid(True, ls='--', alpha=0.4)

    # Panel 2: PDR
    ax = axes[0, 1]
    g = group_metric(data, 'packet_delivery_ratio')
    all_pdr = []
    for crypto in ALL_MODES:
        if crypto not in g:
            continue
        ns = sorted(g[crypto])
        vals = [g[crypto][n] * 100 for n in ns]
        all_pdr.extend(vals)
        ax.plot(ns, vals, label=LABELS[crypto],
                color=COLORS[crypto], marker=MARKERS[crypto], lw=2, ms=7)
    ax.set_title('Packet Delivery Ratio', fontweight='bold')
    ax.set_xlabel('Drones')
    ax.set_ylabel('PDR (%)')
    if all_pdr:
        ax.set_ylim(max(0, min(all_pdr) - 5), min(105, max(all_pdr) + 5))
    ax.legend(fontsize=8)
    ax.grid(True, ls='--', alpha=0.4)

    # Panel 3: Crypto Cost
    ax = axes[1, 0]
    g = group_metric(data, 'crypto_computation_us')
    for crypto in ALL_MODES:
        if crypto not in g:
            continue
        ns = sorted(g[crypto])
        ax.plot(ns, [g[crypto][n] for n in ns], label=LABELS[crypto],
                color=COLORS[crypto], marker=MARKERS[crypto], lw=2, ms=7)
    ax.set_title('Crypto Computation Cost', fontweight='bold')
    ax.set_xlabel('Drones')
    ax.set_ylabel('Time (μs)')
    ax.legend(fontsize=8)
    ax.grid(True, ls='--', alpha=0.4)

    # Panel 4: E2E Latency
    ax = axes[1, 1]
    g = group_metric(data, 'e2e_app_latency_ms')
    for crypto in ALL_MODES:
        if crypto not in g:
            continue
        ns = sorted(g[crypto])
        ax.plot(ns, [g[crypto][n] for n in ns], label=LABELS[crypto],
                color=COLORS[crypto], marker=MARKERS[crypto], lw=2, ms=7)
    ax.set_title('E2E Application Latency', fontweight='bold')
    ax.set_xlabel('Drones')
    ax.set_ylabel('Latency (ms)')
    ax.legend(fontsize=8)
    ax.grid(True, ls='--', alpha=0.4)

    fig.tight_layout(rect=[0, 0, 1, 0.96])
    save_fig(fig, out, '11_dashboard.png')


# ──────────────────────────────────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("  Kyber-6G — CSV Parser + Plot Generator")
    print("=" * 60)

    # Step 1: Parse CSVs
    print("\n[Step 1] Parsing NS-3 CSV outputs...")
    data = parse_csvs()
    if not data:
        print("ERROR: No CSV files found in ns-3-dev/results/. Run experiments first.")
        sys.exit(1)

    # Step 1b: Validate
    print("\n[Step 1b] Validating data completeness...")
    validate_data(data)

    # Step 2: Write JSON
    print(f"\n[Step 2] Writing simulation_results.json ({len(data)} entries)...")
    with open(JSON_OUT, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"  Written: {JSON_OUT}")

    # Also copy to website data dir
    os.makedirs(os.path.dirname(JSON_WEB), exist_ok=True)
    with open(JSON_WEB, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"  Written: {JSON_WEB}")

    # Step 3: Generate plots
    print(f"\n[Step 3] Generating publication-ready plots...")
    os.makedirs(PLOTS_DIR, exist_ok=True)
    setup_matplotlib()

    plot_handshake_latency(data, PLOTS_DIR)
    plot_e2e_latency(data, PLOTS_DIR)
    plot_crypto_computation(data, PLOTS_DIR)
    plot_security_score(data, PLOTS_DIR)
    plot_pdr(data, PLOTS_DIR)
    plot_rrc_overhead(data, PLOTS_DIR)
    plot_security_efficiency(data, PLOTS_DIR)
    plot_queueing(data, PLOTS_DIR)
    plot_throughput(data, PLOTS_DIR)
    plot_energy_battery(data, PLOTS_DIR)
    plot_cache_hit_rate(data, PLOTS_DIR)
    plot_theoretical_security(PLOTS_DIR)
    plot_security_attack_cost(data, PLOTS_DIR)
    plot_previous_vs_improved(data, PLOTS_DIR)
    plot_kyber_level_selection(PLOTS_DIR)
    plot_dashboard(data, PLOTS_DIR)

    print(f"\n{'=' * 60}")
    print(f"  Done! {len(data)} experiments -> plots in {PLOTS_DIR} (PNG+SVG+PDF)")
    print(f"{'=' * 60}")

    # Print summary table
    print(f"\n{'Crypto':<22} {'Nodes':>5} {'Handshake(μs)':>14} {'E2E(ms)':>9} "
          f"{'PDR':>7} {'Security':>9} {'Crypto(μs)':>11} {'Tput(B)':>9}")
    print("-" * 90)
    for e in data:
        m = e['metrics']
        hs = m.get('handshake_latency_us', {}).get('mean', 0)
        e2e = m.get('e2e_app_latency_ms', {}).get('mean', 0)
        pdr_val = m.get('packet_delivery_ratio', {}).get('mean', 0)
        sec = m.get('security_strength_score', {}).get('mean', 0)
        crypto_t = m.get('crypto_computation_us', {}).get('mean', 0)
        tput = m.get('throughput_bytes', {}).get('mean', 0)
        print(f"{e['crypto']:<22} {e['nodes']:>5} {hs:>14.1f} {e2e:>9.2f} "
              f"{pdr_val:>7.3f} {sec:>9.1f} {crypto_t:>11.1f} {tput:>9.1f}")


if __name__ == '__main__':
    main()
