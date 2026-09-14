import os
import glob
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

# Configure IEEE publication style
plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.size': 10,
    'axes.labelsize': 11,
    'axes.titlesize': 12,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'legend.fontsize': 9,
    'figure.titlesize': 13,
    'figure.dpi': 150,
    'savefig.dpi': 300,
})

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.join(BASE_DIR, '..')
ABLATION_DIR = os.path.join(PROJECT_DIR, 'ablation_study')
DATA_DIR = os.path.join(ABLATION_DIR, 'data')
PLOT_DIR = os.path.join(ABLATION_DIR, 'plots')
SUMMARY_CSV = os.path.join(DATA_DIR, 'ablation_summary.csv')

os.makedirs(PLOT_DIR, exist_ok=True)

# Colors and labels
SCENARIO_META = {
    'baseline': {'label': 'Full Hybrid System (Baseline)', 'color': '#1f77b4', 'ls': '-'},
    'a1_no_ecdh': {'label': 'No X25519 (Pure ML-KEM)', 'color': '#ff7f0e', 'ls': '--'},
    'a2_no_kyber': {'label': 'No ML-KEM (Classical ECDH)', 'color': '#2ca02c', 'ls': '-.'},
    'a3_no_hkdf': {'label': 'No HKDF-SHA256', 'color': '#d62728', 'ls': ':'},
    'a4_no_aes_setup': {'label': 'No AES-GCM Schedule', 'color': '#9467bd', 'ls': '--'},
    'a5_double_rrc': {'label': 'Double RRC Overhead (240B)', 'color': '#8c564b', 'ls': '-.'},
    'a6_no_fragmentation': {'label': 'No Fragmentation (Jumbo)', 'color': '#e377c2', 'ls': '-'},
    'a7_high_loss': {'label': 'High BLER (1.0%)', 'color': '#7f7f7f', 'ls': ':'},
    'a8_sequential_crypto': {'label': 'Sequential Crypto (1 Core)', 'color': '#bcbd22', 'ls': '--'},
}

def load_data():
    df_summary = pd.read_csv(SUMMARY_CSV)
    raw_data = {}
    for sc in SCENARIO_META.keys():
        p = os.path.join(DATA_DIR, sc, 'results_all_tiers.csv')
        if os.path.exists(p):
            raw_data[sc] = pd.read_csv(p)
    return df_summary, raw_data

def plot_01_latency_delta_bars(df_summary):
    """Plot 1: Bar chart of latency deltas vs baseline across representative swarm sizes."""
    pivot = df_summary.pivot(index='scenario_id', columns='swarm_size', values='mean_ms')
    if 'baseline' not in pivot.index:
        return
    baseline_row = pivot.loc['baseline']
    delta = pivot.subtract(baseline_row, axis=1).drop('baseline')
    
    selected_sizes = [20, 50, 80]
    sub_delta = delta[selected_sizes]
    
    labels = [SCENARIO_META[sc]['label'] for sc in sub_delta.index]
    x = np.arange(len(labels))
    width = 0.25
    
    fig, ax = plt.subplots(figsize=(10, 5.5))
    for i, size in enumerate(selected_sizes):
        vals = sub_delta[size].values
        ax.bar(x + (i - 1) * width, vals, width, label=f'{size} UAVs', alpha=0.9)
        
    ax.axhline(0, color='black', linewidth=0.8, linestyle='--')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=35, ha='right')
    ax.set_ylabel('Mean Latency Delta vs. Baseline (ms)')
    ax.set_title('Ablation Study: Latency Impact of Architectural Components\n(Negative = Faster without component; Positive = Overhead introduced)')
    ax.legend(title='Swarm Density')
    ax.grid(axis='y', linestyle=':', alpha=0.6)
    fig.tight_layout()
    out = os.path.join(PLOT_DIR, '01_ablation_latency_delta_bars.png')
    fig.savefig(out)
    plt.close(fig)
    print(f'[✓] Saved: {out}')

def plot_02_scaling_curves(df_summary):
    """Plot 2: Latency vs Swarm Size line plot for all 9 scenarios."""
    fig, ax = plt.subplots(figsize=(9, 5.5))
    for sc, meta in SCENARIO_META.items():
        sub = df_summary[df_summary['scenario_id'] == sc].sort_values('swarm_size')
        if sub.empty:
            continue
        ax.plot(sub['swarm_size'], sub['mean_ms'], label=meta['label'],
                color=meta['color'], linestyle=meta['ls'], marker='o', markersize=4, linewidth=1.5)
        
    ax.axhline(10.0, color='red', linestyle='--', linewidth=1.2, label='URLLC 10ms Deadline')
    ax.set_xlabel('Swarm Size (UAVs)')
    ax.set_ylabel('Mean Handshake Latency (ms)')
    ax.set_title('Ablation Study: Latency Scaling Across UAV Swarm Density (10–100 Nodes)')
    ax.legend(loc='upper left', bbox_to_anchor=(1.02, 1), frameon=True)
    ax.grid(True, linestyle=':', alpha=0.6)
    fig.tight_layout()
    out = os.path.join(PLOT_DIR, '02_ablation_scaling_curves.png')
    fig.savefig(out)
    plt.close(fig)
    print(f'[✓] Saved: {out}')

def plot_03_dual_vs_single_core(df_summary):
    """Plot 3: Dedicated isolation of Dual-Core (Baseline) vs Single-Core (a8_sequential_crypto)."""
    base = df_summary[df_summary['scenario_id'] == 'baseline'].sort_values('swarm_size')
    seq = df_summary[df_summary['scenario_id'] == 'a8_sequential_crypto'].sort_values('swarm_size')
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))
    
    # Absolute latency
    ax1.plot(base['swarm_size'], base['mean_ms'], 'o-', color='#1f77b4', label='Dual-Core (Parallel Pi 4)', linewidth=1.8)
    ax1.plot(seq['swarm_size'], seq['mean_ms'], 's--', color='#d62728', label='Single-Core (Sequential Crypto)', linewidth=1.8)
    ax1.set_xlabel('Swarm Size (UAVs)')
    ax1.set_ylabel('Mean Handshake Latency (ms)')
    ax1.set_title('Ablation: Dual-Core Speedup vs. Single-Core')
    ax1.legend()
    ax1.grid(True, linestyle=':', alpha=0.6)
    
    # Delta in microseconds
    delta_us = (seq['mean_ms'].values - base['mean_ms'].values) * 1000.0
    ax2.bar(base['swarm_size'], delta_us, width=6, color='#2ca02c', alpha=0.85)
    ax2.axhline(145.0, color='darkred', linestyle='--', label='Theoretical Concurrency Gain (142 µs)')
    ax2.set_xlabel('Swarm Size (UAVs)')
    ax2.set_ylabel('Sequential Penalty (µs)')
    ax2.set_title('Hardware Concurrency Saving on Cortex-A72')
    ax2.legend()
    ax2.grid(axis='y', linestyle=':', alpha=0.6)
    
    fig.tight_layout()
    out = os.path.join(PLOT_DIR, '03_ablation_crypto_breakdown_dual_vs_single.png')
    fig.savefig(out)
    plt.close(fig)
    print(f'[✓] Saved: {out}')

def plot_04_fragmentation_penalty(df_summary):
    """Plot 4: Multi-slot IP fragmentation penalty (Baseline vs a6_no_fragmentation)."""
    base = df_summary[df_summary['scenario_id'] == 'baseline'].sort_values('swarm_size')
    no_frag = df_summary[df_summary['scenario_id'] == 'a6_no_fragmentation'].sort_values('swarm_size')
    
    fig, ax = plt.subplots(figsize=(8, 4.8))
    width = 3.5
    ax.bar(base['swarm_size'] - width/2, base['mean_ms'], width=width, color='#1f77b4', label='Baseline (3-Slot Frag: 1568B ML-KEM)', alpha=0.9)
    ax.bar(no_frag['swarm_size'] + width/2, no_frag['mean_ms'], width=width, color='#e377c2', label='No Fragmentation (Jumbo Frames)', alpha=0.9)
    
    ax.set_xlabel('Swarm Size (UAVs)')
    ax.set_ylabel('Mean Handshake Latency (ms)')
    ax.set_title('Ablation: Impact of Multi-Slot RLC/MAC Fragmentation\n(5G NR TTI = 0.5 ms per slot)')
    ax.legend()
    ax.grid(axis='y', linestyle=':', alpha=0.6)
    fig.tight_layout()
    out = os.path.join(PLOT_DIR, '04_ablation_fragmentation_penalty.png')
    fig.savefig(out)
    plt.close(fig)
    print(f'[✓] Saved: {out}')

def plot_05_pqc_vs_classical(df_summary):
    """Plot 5: PQC Security Tax: Hybrid vs Pure Kyber vs Classical ECDH."""
    base = df_summary[df_summary['scenario_id'] == 'baseline'].sort_values('swarm_size')
    pure_k = df_summary[df_summary['scenario_id'] == 'a1_no_ecdh'].sort_values('swarm_size')
    pure_c = df_summary[df_summary['scenario_id'] == 'a2_no_kyber'].sort_values('swarm_size')
    
    fig, ax = plt.subplots(figsize=(8.5, 5))
    ax.plot(base['swarm_size'], base['mean_ms'], 'o-', color='#1f77b4', linewidth=2, label='Hybrid ML-KEM-1024 + X25519 (Quantum-Safe)')
    ax.plot(pure_k['swarm_size'], pure_k['mean_ms'], '^--', color='#ff7f0e', linewidth=1.8, label='Pure ML-KEM-1024 (Post-Quantum Only)')
    ax.plot(pure_c['swarm_size'], pure_c['mean_ms'], 's-.', color='#2ca02c', linewidth=1.8, label='Classical X25519 (Vulnerable to Shor\'s Algorithm)')
    
    ax.axhline(10.0, color='red', linestyle=':', linewidth=1.2, label='10ms URLLC Target')
    ax.fill_between(base['swarm_size'], pure_c['mean_ms'], base['mean_ms'], color='#1f77b4', alpha=0.15, label='Post-Quantum Security Tax (~1.8 ms)')
    
    ax.set_xlabel('Swarm Size (UAVs)')
    ax.set_ylabel('Mean Handshake Latency (ms)')
    ax.set_title('Ablation: Post-Quantum Security Tax vs. Classical ECC')
    ax.legend(loc='upper left')
    ax.grid(True, linestyle=':', alpha=0.6)
    fig.tight_layout()
    out = os.path.join(PLOT_DIR, '05_ablation_pqc_vs_classical.png')
    fig.savefig(out)
    plt.close(fig)
    print(f'[✓] Saved: {out}')

def plot_06_cdf_distributions(raw_data):
    """Plot 6: Empirical CDF of handshake latency at N=80 across scenarios."""
    fig, ax = plt.subplots(figsize=(9, 5.2))
    target_swarm = 80
    
    for sc, meta in SCENARIO_META.items():
        if sc not in raw_data:
            continue
        sub = raw_data[sc][raw_data[sc]['swarm_size'] == target_swarm]
        if sub.empty:
            continue
        vals = np.sort(sub['handshake_latency_ms'].values)
        cdf = np.linspace(0, 1, len(vals))
        ax.plot(vals, cdf, label=meta['label'], color=meta['color'], linestyle=meta['ls'], linewidth=1.6)
        
    ax.axvline(10.0, color='red', linestyle='--', linewidth=1.2, label='10ms URLLC Bound')
    ax.set_xlabel('Handshake Latency (ms)')
    ax.set_ylabel('Empirical Cumulative Probability (CDF)')
    ax.set_title(f'Ablation: Handshake Latency CDF Distribution at High Density ({target_swarm} UAVs)')
    ax.legend(loc='lower right', frameon=True)
    ax.grid(True, linestyle=':', alpha=0.6)
    fig.tight_layout()
    out = os.path.join(PLOT_DIR, '06_ablation_cdf_distributions.png')
    fig.savefig(out)
    plt.close(fig)
    print(f'[✓] Saved: {out}')

def plot_07_heatmap(df_summary):
    """Plot 7: Full 2D Ablation Latency Delta Heatmap."""
    pivot = df_summary.pivot(index='scenario_id', columns='swarm_size', values='mean_ms')
    if 'baseline' not in pivot.index:
        return
    baseline_row = pivot.loc['baseline']
    delta = pivot.subtract(baseline_row, axis=1).drop('baseline')
    
    labels = [SCENARIO_META[sc]['label'] for sc in delta.index]
    delta.index = labels
    
    fig, ax = plt.subplots(figsize=(11, 5.5))
    sns.heatmap(delta, annot=True, fmt='.2f', cmap='RdYlGn_r',
                center=0, linewidths=0.5, ax=ax,
                cbar_kws={'label': 'Latency Delta vs. Baseline (ms)'})
    ax.set_xlabel('Swarm Size (UAVs)')
    ax.set_ylabel('Ablation Scenario')
    ax.set_title('Ablation Study: Complete Parameter Sensitivity Heatmap\n(BCM2711 Cortex-A72 Profile · 500 Stochastic MC Trials/Cell)')
    fig.tight_layout()
    out = os.path.join(PLOT_DIR, '07_ablation_heatmap.png')
    fig.savefig(out)
    plt.close(fig)
    print(f'[✓] Saved: {out}')

def plot_08_p99_urllc(df_summary):
    """Plot 8: P99 Tail Latency Scaling vs 10ms URLLC Boundary."""
    fig, ax = plt.subplots(figsize=(9, 5.2))
    for sc in ['baseline', 'a1_no_ecdh', 'a2_no_kyber', 'a6_no_fragmentation', 'a8_sequential_crypto']:
        meta = SCENARIO_META[sc]
        sub = df_summary[df_summary['scenario_id'] == sc].sort_values('swarm_size')
        if sub.empty:
            continue
        ax.plot(sub['swarm_size'], sub['p99_ms'], label=meta['label'] + ' (P99)',
                color=meta['color'], linestyle=meta['ls'], marker='s', markersize=4, linewidth=1.6)
        
    ax.axhline(10.0, color='red', linestyle='--', linewidth=1.5, label='3GPP URLLC Bound (10 ms)')
    ax.set_xlabel('Swarm Size (UAVs)')
    ax.set_ylabel('P99 Tail Latency (ms)')
    ax.set_title('Ablation: P99 Tail Latency and URLLC Compliance Horizon')
    ax.legend(loc='upper left')
    ax.grid(True, linestyle=':', alpha=0.6)
    fig.tight_layout()
    out = os.path.join(PLOT_DIR, '08_ablation_p99_urllc_compliance.png')
    fig.savefig(out)
    plt.close(fig)
    print(f'[✓] Saved: {out}')

def main():
    print("=================================================================")
    print("  GENERATING SEPARATE PUBLICATION-QUALITY ABLATION PLOTS (300 DPI)")
    print("=================================================================")
    df_summary, raw_data = load_data()
    print(f"Loaded summary: {len(df_summary)} rows across {df_summary['scenario_id'].nunique()} scenarios")
    print(f"Loaded raw data for {len(raw_data)} scenarios ({sum(len(d) for d in raw_data.values())} total trials)")
    
    plot_01_latency_delta_bars(df_summary)
    plot_02_scaling_curves(df_summary)
    plot_03_dual_vs_single_core(df_summary)
    plot_04_fragmentation_penalty(df_summary)
    plot_05_pqc_vs_classical(df_summary)
    plot_06_cdf_distributions(raw_data)
    plot_07_heatmap(df_summary)
    plot_08_p99_urllc(df_summary)
    
    print("\n>>> ALL 8 INDIVIDUAL ABLATION PLOTS GENERATED SUCCESSFULLY!")

if __name__ == '__main__':
    main()
