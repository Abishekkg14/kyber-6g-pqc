#!/usr/bin/env python3
"""
Monte Carlo Simulation: MAC-Layer Serialization Delay across 6G Numerologies.

Physics model (3GPP TS 38.211 / 38.214):
  - T_slot(mu) = 1 ms / 2^mu
  - SCS(mu) = 15 * 2^mu kHz
  - TBS from TS 38.214 Table 5.1.3.1-2 (MCS 27, 256QAM, 106 PRBs, 2 layers)
  - n_frag = ceil(B / TBS(mu))
  - tau_serial = n_frag * T_slot(mu)

Monte Carlo: 10,000 iterations with +/-5% TBS jitter (scheduling variance).

Output: Publication-ready figure with violin plots + raw data arrays.

Author: Kyber-6G Project, 2026
"""

import os
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

# ═══════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════

SEED = 42
N_MONTE_CARLO = 10_000
TBS_JITTER_PCT = 0.05  # +/- 5% scheduling variance

# Output directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR = os.path.join(PROJECT_DIR, 'figures_rerun', 'crypto')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# 6G Numerologies
NUMEROLOGIES = {
    3: {'scs_khz': 120, 'tbs_bytes': 12000, 'label': r'$\mu=3$ (120 kHz)'},
    4: {'scs_khz': 240, 'tbs_bytes': 6000,  'label': r'$\mu=4$ (240 kHz)'},
    5: {'scs_khz': 480, 'tbs_bytes': 3000,  'label': r'$\mu=5$ (480 kHz)'},
}

# PQC Payload sizes (bytes) — NIST FIPS 203/204 wire formats
PAYLOADS = {
    'CSIDH-512\nMAC CE': 64,
    'X25519\nECDH PK': 32,
    'ML-KEM-768\nPK': 1184,
    'ML-KEM-768\nCT': 1088,
    'ML-KEM-1024\nPK': 1568,
    'ML-KEM-1024\nCT': 1568,
    'ML-DSA-87\nSig': 4627,
    'Full RRC\nRequest': 8679,   # ML-KEM-1024 PK + ECDH + ML-DSA-87 sig + cert
    'Full RRC\nResponse': 6227,  # ML-KEM-1024 CT + ECDH + ML-DSA-87 sig
}

# ═══════════════════════════════════════════════════
# Physics Functions
# ═══════════════════════════════════════════════════

def slot_duration_us(mu):
    """T_slot = 1 ms / 2^mu in microseconds."""
    return 1000.0 / (2 ** mu)

def compute_serialization_delay_us(payload_bytes, tbs_bytes, mu):
    """
    tau_serial = ceil(B / TBS) * T_slot(mu)
    
    Returns delay in microseconds.
    """
    n_frag = int(np.ceil(payload_bytes / tbs_bytes))
    n_frag = max(n_frag, 1)
    t_slot = slot_duration_us(mu)
    return n_frag * t_slot

# ═══════════════════════════════════════════════════
# Monte Carlo Simulation
# ═══════════════════════════════════════════════════

def run_monte_carlo():
    """Run Monte Carlo simulation for all (payload, numerology) pairs."""
    rng = np.random.default_rng(SEED)
    
    results = {}  # {(payload_name, mu): array of delays in us}
    
    for mu, mu_cfg in NUMEROLOGIES.items():
        nominal_tbs = mu_cfg['tbs_bytes']
        t_slot = slot_duration_us(mu)
        
        for payload_name, payload_bytes in PAYLOADS.items():
            # Jitter TBS by +/- 5% (scheduling variance from PRB allocation,
            # MCS adaptation, HARQ retransmissions)
            tbs_samples = rng.uniform(
                nominal_tbs * (1 - TBS_JITTER_PCT),
                nominal_tbs * (1 + TBS_JITTER_PCT),
                size=N_MONTE_CARLO
            )
            
            # Compute fragment count and serialization delay per sample
            n_frags = np.ceil(payload_bytes / tbs_samples).astype(int)
            n_frags = np.maximum(n_frags, 1)
            delays_us = n_frags * t_slot
            
            results[(payload_name, mu)] = delays_us
    
    return results

# ═══════════════════════════════════════════════════
# Publication-Quality Plotting
# ═══════════════════════════════════════════════════

def plot_results(results):
    """Generate publication-ready violin plot figure."""
    
    plt.rcParams.update({
        'font.family': 'serif',
        'font.serif': ['DejaVu Serif', 'Times New Roman', 'Times'],
        'font.size': 10,
        'axes.labelsize': 11,
        'axes.titlesize': 13,
        'legend.fontsize': 9,
        'figure.dpi': 300,
        'axes.spines.top': False,
        'axes.spines.right': False,
    })
    
    fig, axes = plt.subplots(1, 3, figsize=(16, 5.5), sharey=False)
    fig.suptitle('MAC-Layer Serialization Delay: PQC Payloads across 6G Numerologies',
                 fontsize=14, fontweight='bold', y=1.02)
    
    payload_names = list(PAYLOADS.keys())
    n_payloads = len(payload_names)
    
    # Color palette
    colors = ['#06b6d4', '#0ea5e9', '#6366f1', '#8b5cf6',
              '#a855f7', '#dc2626', '#f97316', '#059669']
    
    for ax_idx, (mu, mu_cfg) in enumerate(NUMEROLOGIES.items()):
        ax = axes[ax_idx]
        
        data_for_violin = []
        positions = []
        
        for p_idx, pname in enumerate(payload_names):
            delays = results[(pname, mu)]
            data_for_violin.append(delays)
            positions.append(p_idx)
        
        # Violin plot
        parts = ax.violinplot(data_for_violin, positions=positions,
                              showmeans=False, showmedians=False, showextrema=False)
        
        for i, pc in enumerate(parts['bodies']):
            pc.set_facecolor(colors[i % len(colors)])
            pc.set_edgecolor('#1e293b')
            pc.set_alpha(0.7)
            pc.set_linewidth(0.8)
        
        # Overlay box plots for median/IQR
        bp = ax.boxplot(data_for_violin, positions=positions, widths=0.15,
                        patch_artist=True, showfliers=False,
                        medianprops=dict(color='white', linewidth=1.5),
                        boxprops=dict(facecolor='#1e293b', alpha=0.8),
                        whiskerprops=dict(color='#475569', linewidth=1),
                        capprops=dict(color='#475569', linewidth=1))
        
        # Add mean markers
        for p_idx, pname in enumerate(payload_names):
            delays = results[(pname, mu)]
            mean_val = np.mean(delays)
            ax.scatter(p_idx, mean_val, color='white', s=20, zorder=5,
                       edgecolors='#1e293b', linewidths=0.8, marker='D')
        
        # Annotations for fragment counts
        for p_idx, pname in enumerate(payload_names):
            payload_bytes = PAYLOADS[pname]
            nominal_tbs = mu_cfg['tbs_bytes']
            n_frag = int(np.ceil(payload_bytes / nominal_tbs))
            n_frag = max(n_frag, 1)
            delays = results[(pname, mu)]
            y_top = np.percentile(delays, 95)
            ax.text(p_idx, y_top * 1.05, f'n={n_frag}',
                    ha='center', va='bottom', fontsize=7, color='#475569',
                    fontweight='bold')
        
        ax.set_xticks(range(n_payloads))
        ax.set_xticklabels([p.replace('\n', '\n') for p in payload_names],
                           fontsize=7.5, rotation=45, ha='right')
        ax.set_ylabel(r'Serialization Delay $\tau_{\mathrm{serial}}$ ($\mu$s)')
        ax.set_title(mu_cfg['label'], fontweight='bold')
        ax.grid(axis='y', ls='--', alpha=0.3, color='#94a3b8')
        ax.set_xlim(-0.7, n_payloads - 0.3)
        
        # Add slot duration annotation
        t_slot = slot_duration_us(mu)
        ax.axhline(t_slot, color='#059669', ls=':', lw=1.2, alpha=0.6)
        ax.text(n_payloads - 0.5, t_slot * 1.08,
                f'$T_{{slot}}$={t_slot:.1f} $\\mu$s',
                fontsize=8, color='#059669', ha='right')
    
    fig.tight_layout()
    
    # Save
    for ext in ('png', 'pdf', 'svg'):
        path = os.path.join(OUTPUT_DIR, f'fig_mac_serialization_delay.{ext}')
        fig.savefig(path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close(fig)
    
    print(f"Saved figures to {OUTPUT_DIR}/fig_mac_serialization_delay.[png|pdf|svg]")

def print_summary_table(results):
    """Print raw data summary for paper table."""
    print("\n" + "=" * 90)
    print("  MAC-Layer Serialization Delay Summary (Monte Carlo, N=10,000)")
    print("=" * 90)
    print(f"{'Payload':<20} {'mu':>3} {'n_frag':>6} {'Mean(us)':>10} "
          f"{'Median(us)':>11} {'P95(us)':>9} {'P99(us)':>9}")
    print("-" * 90)
    
    for mu, mu_cfg in NUMEROLOGIES.items():
        for pname, pbytes in PAYLOADS.items():
            delays = results[(pname, mu)]
            clean_name = pname.replace('\n', ' ')
            n_frag = int(np.ceil(pbytes / mu_cfg['tbs_bytes']))
            n_frag = max(n_frag, 1)
            print(f"{clean_name:<20} {mu:>3} {n_frag:>6} {np.mean(delays):>10.2f} "
                  f"{np.median(delays):>11.2f} {np.percentile(delays, 95):>9.2f} "
                  f"{np.percentile(delays, 99):>9.2f}")
        print("-" * 90)

# ═══════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  MAC-Layer Serialization Delay — Monte Carlo Simulation")
    print(f"  N={N_MONTE_CARLO} iterations, TBS jitter=+/-{TBS_JITTER_PCT*100:.0f}%")
    print("=" * 60)
    
    results = run_monte_carlo()
    plot_results(results)
    print_summary_table(results)
    
    print("\nDone.")

if __name__ == '__main__':
    main()
