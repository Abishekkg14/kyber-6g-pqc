#!/usr/bin/env python3
"""
Monte Carlo Simulation: Gilbert-Elliott PDR Decay & TCP RTO Cascade.

Physics model:
  - Two-state Markov chain: Good (eps_G=1e-4), Bad (eps_B=0.3)
  - Steady-state: pi_G = p_BG/(p_GB+p_BG), pi_B = p_GB/(p_GB+p_BG)
  - T_c = c/(f_c*v) = 3e8/(140e9*120) ~ 17.8 us
  - PDR(n) = pi_G*(1-eps_G)^n + pi_B*(1-eps_B)^n
  - TCP RTO cascade: geometric retry with exponential backoff
    RTO_k = min(2^k * RTO_0, 60s), success per attempt = PDR(n)
    P(cascade) = P(>= F consecutive failures)

Monte Carlo: 100,000 channel realizations per configuration.

Output: 2-panel figure — (a) PDR vs fragments, (b) TCP RTO cascade heatmap.

Author: Kyber-6G Project, 2026
"""

import os
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap, LogNorm
import matplotlib.ticker as ticker

# ═══════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════

SEED = 42
N_MONTE_CARLO = 100_000

# Output
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR = os.path.join(PROJECT_DIR, 'figures_rerun', 'channel')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Channel parameters
SPEED_OF_LIGHT = 3e8    # m/s
CARRIER_FREQ = 140e9    # Hz (140 GHz THz)
VELOCITY = 120.0        # m/s

EPSILON_G = 1e-4        # Good-state packet error rate
EPSILON_B = 0.3         # Bad-state packet error rate

# Sweep parameters
P_GB_VALUES = [0.01, 0.05, 0.10, 0.20, 0.30]  # G->B transition probabilities
P_BG = 0.3              # B->G transition probability (fixed)
FRAG_COUNTS = [1, 2, 3, 4, 5, 6]  # Number of IP fragments

# TCP RTO parameters
RTO_0_MS = 200.0        # Initial RTO in ms
RTO_MAX_MS = 60_000.0   # Maximum RTO in ms
CASCADE_THRESHOLD = 3   # Consecutive failures for "cascade"

# Heatmap grid
HEATMAP_P_GB = np.linspace(0.01, 0.40, 20)
HEATMAP_FRAGS = np.arange(1, 7)

# ═══════════════════════════════════════════════════
# Physics Functions
# ═══════════════════════════════════════════════════

def coherence_time_us():
    """T_c = c / (f_c * v) in microseconds."""
    return SPEED_OF_LIGHT / (CARRIER_FREQ * VELOCITY) * 1e6

def steady_state_probs(p_gb, p_bg):
    """Steady-state probabilities of Good and Bad states."""
    denom = p_gb + p_bg
    pi_g = p_bg / denom
    pi_b = p_gb / denom
    return pi_g, pi_b

def analytical_pdr(n_frag, p_gb, p_bg=P_BG, eps_g=EPSILON_G, eps_b=EPSILON_B):
    """
    Analytical PDR for n-fragment payload under Gilbert-Elliott model.
    
    PDR(n) = pi_G * (1-eps_G)^n + pi_B * (1-eps_B)^n
    
    This models the probability that ALL n fragments are delivered
    successfully, averaged over the channel's steady-state distribution.
    """
    pi_g, pi_b = steady_state_probs(p_gb, p_bg)
    pdr = pi_g * (1 - eps_g) ** n_frag + pi_b * (1 - eps_b) ** n_frag
    return pdr

def tcp_rto_cascade_prob_analytical(n_frag, p_gb, consecutive_failures=CASCADE_THRESHOLD):
    """
    Analytical probability of TCP RTO cascade.
    
    P(cascade) = (1 - PDR(n))^F
    
    where F is the number of consecutive transmission failures.
    """
    pdr = analytical_pdr(n_frag, p_gb)
    p_fail = 1.0 - pdr
    return p_fail ** consecutive_failures

# ═══════════════════════════════════════════════════
# Monte Carlo Simulation
# ═══════════════════════════════════════════════════

def simulate_gilbert_elliott_channel(n_frag, p_gb, p_bg, n_trials, rng):
    """
    Monte Carlo simulation of n-fragment transmission through
    a Gilbert-Elliott channel.
    
    Returns array of per-trial delivery outcomes (True/False).
    """
    eps_g = EPSILON_G
    eps_b = EPSILON_B
    
    # Initialize states based on steady-state distribution
    pi_g, _ = steady_state_probs(p_gb, p_bg)
    states = rng.random(n_trials) < pi_g  # True = Good, False = Bad
    
    # For each trial, simulate n_frag fragment deliveries
    # We model burst errors: all fragments in a trial experience the same
    # channel state (coherent burst within one handshake attempt)
    # This is justified because T_handshake >> T_c, so the channel state
    # is effectively static within a single fragment burst
    
    # However, for more realism, we step the channel between fragments
    all_delivered = np.ones(n_trials, dtype=bool)
    
    for frag_idx in range(n_frag):
        # Error probability depends on current state
        eps = np.where(states, eps_g, eps_b)
        
        # Each fragment independently fails with probability eps
        fragment_lost = rng.random(n_trials) < eps
        all_delivered &= ~fragment_lost
        
        # Step channel state (Markov transition between fragments)
        # This models intra-handshake state changes for very long payloads
        transition_rolls = rng.random(n_trials)
        # Good -> Bad with prob p_gb
        go_bad = states & (transition_rolls < p_gb)
        # Bad -> Good with prob p_bg
        go_good = ~states & (transition_rolls < p_bg)
        states = states & ~go_bad | go_good
    
    return all_delivered

def simulate_tcp_rto_cascade(n_frag, p_gb, p_bg, n_trials, rng,
                              max_retries=6):
    """
    Monte Carlo simulation of TCP RTO cascade behavior.
    
    Models geometric retries with exponential backoff.
    Returns: (cascade_count, total_delay_distribution_ms)
    """
    cascades = 0
    total_delays_ms = []
    
    # Vectorized simulation: for each trial, simulate up to max_retries
    consecutive_failures = np.zeros(n_trials, dtype=int)
    total_delay = np.zeros(n_trials)
    success = np.zeros(n_trials, dtype=bool)
    
    for retry in range(max_retries):
        # Only retry for trials that haven't succeeded yet
        active = ~success
        if not np.any(active):
            break
        
        n_active = np.sum(active)
        
        # Simulate delivery attempt
        delivered = simulate_gilbert_elliott_channel(
            n_frag, p_gb, p_bg, n_active, rng
        )
        
        # Update: mark successful trials
        active_indices = np.where(active)[0]
        newly_succeeded = active_indices[delivered]
        success[newly_succeeded] = True
        
        # Accumulate RTO delay for failures
        rto_ms = min(RTO_0_MS * (2 ** retry), RTO_MAX_MS)
        failed_indices = active_indices[~delivered]
        total_delay[failed_indices] += rto_ms
        consecutive_failures[failed_indices] += 1
    
    # Count cascades (>= CASCADE_THRESHOLD consecutive failures)
    cascade_mask = consecutive_failures >= CASCADE_THRESHOLD
    cascade_count = np.sum(cascade_mask)
    
    return cascade_count / n_trials, total_delay

# ═══════════════════════════════════════════════════
# Plotting
# ═══════════════════════════════════════════════════

def plot_results():
    """Generate the 2-panel publication figure."""
    rng = np.random.default_rng(SEED)
    
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
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5))
    fig.suptitle('Gilbert-Elliott Channel: PQC Fragmentation Impact on THz Links',
                 fontsize=14, fontweight='bold', y=1.02)
    
    # ── Panel (a): PDR vs Fragment Count ──
    colors_pdr = ['#06b6d4', '#3b82f6', '#8b5cf6', '#ec4899', '#ef4444']
    markers = ['o', 's', 'D', '^', 'v']
    
    for i, p_gb in enumerate(P_GB_VALUES):
        # Analytical PDR
        pdrs_analytical = [analytical_pdr(n, p_gb) for n in FRAG_COUNTS]
        
        # Monte Carlo PDR
        pdrs_mc = []
        pdrs_mc_ci = []
        for n in FRAG_COUNTS:
            delivered = simulate_gilbert_elliott_channel(
                n, p_gb, P_BG, N_MONTE_CARLO, rng
            )
            pdr_mc = np.mean(delivered)
            ci_half = 1.96 * np.sqrt(pdr_mc * (1 - pdr_mc) / N_MONTE_CARLO)
            pdrs_mc.append(pdr_mc)
            pdrs_mc_ci.append(ci_half)
        
        pi_b = p_gb / (p_gb + P_BG)
        label = f'$p_{{GB}}={p_gb}$ ($\\pi_B={pi_b:.2f}$)'
        
        # Plot analytical as lines
        ax1.plot(FRAG_COUNTS, pdrs_analytical, '--', color=colors_pdr[i],
                 alpha=0.5, lw=1.5)
        
        # Plot MC as points with error bars
        ax1.errorbar(FRAG_COUNTS, pdrs_mc, yerr=pdrs_mc_ci,
                     label=label, color=colors_pdr[i],
                     marker=markers[i], markersize=7, lw=2, capsize=3)
    
    # URLLC target line
    ax1.axhline(0.99999, color='#059669', ls=':', lw=1.5, alpha=0.7)
    ax1.text(5.5, 0.999, '6G URLLC\ntarget', fontsize=8, color='#059669',
             ha='right', va='top')
    
    # Annotate key PQC payload fragment counts
    kem_frags = {
        'ML-KEM-768\n(2 frag)': 2,
        'ML-KEM-1024\n(3 frag)': 3,
    }
    for label_txt, nf in kem_frags.items():
        ax1.annotate(label_txt, xy=(nf, analytical_pdr(nf, 0.05)),
                     xytext=(nf + 0.8, analytical_pdr(nf, 0.05) + 0.03),
                     fontsize=7, color='#475569',
                     arrowprops=dict(arrowstyle='->', color='#94a3b8', lw=0.8))
    
    ax1.set_xlabel('Number of IP Fragments ($n$)')
    ax1.set_ylabel('Packet Delivery Ratio (PDR)')
    ax1.set_title('(a) PDR Decay with Fragmentation', fontweight='bold')
    ax1.legend(fontsize=8, loc='lower left')
    ax1.grid(True, ls='--', alpha=0.3, color='#94a3b8')
    ax1.set_xlim(0.5, 6.5)
    ax1.set_ylim(0, 1.05)
    ax1.xaxis.set_major_locator(ticker.MultipleLocator(1))
    
    # ── Panel (b): TCP RTO Cascade Probability Heatmap ──
    cascade_grid = np.zeros((len(HEATMAP_FRAGS), len(HEATMAP_P_GB)))
    
    for i, n_frag in enumerate(HEATMAP_FRAGS):
        for j, p_gb in enumerate(HEATMAP_P_GB):
            # Use analytical formula for heatmap (MC is too slow for full grid)
            cascade_grid[i, j] = tcp_rto_cascade_prob_analytical(
                n_frag, p_gb, CASCADE_THRESHOLD
            )
    
    # Custom colormap: green (safe) -> yellow (warning) -> red (cascade)
    cmap = LinearSegmentedColormap.from_list(
        'cascade', ['#059669', '#fbbf24', '#ef4444', '#7f1d1d']
    )
    
    # Avoid log of zero by clipping to a minimum value
    cascade_grid = np.clip(cascade_grid, 1e-10, 1.0)
    im = ax2.imshow(cascade_grid, aspect='auto', origin='lower',
                    cmap=cmap, norm=LogNorm(vmin=1e-8, vmax=1.0),
                    extent=[HEATMAP_P_GB[0], HEATMAP_P_GB[-1],
                            HEATMAP_FRAGS[0] - 0.5, HEATMAP_FRAGS[-1] + 0.5])
    
    cbar = fig.colorbar(im, ax=ax2, shrink=0.8, pad=0.02)
    cbar.set_label(f'$P$(cascade $\\geq {CASCADE_THRESHOLD}$ failures)', fontsize=10)
    
    # Annotate specific cells with values
    for i, n_frag in enumerate(HEATMAP_FRAGS):
        for j_idx in range(0, len(HEATMAP_P_GB), 4):
            p_gb = HEATMAP_P_GB[j_idx]
            val = cascade_grid[i, j_idx]
            color = 'white' if val > 0.5 else '#1e293b'
            ax2.text(p_gb, n_frag, f'{val:.2f}',
                     ha='center', va='center', fontsize=7, color=color,
                     fontweight='bold')
    
    # Mark the ML-KEM-1024 operating point
    ax2.axhline(3, color='white', ls='--', lw=1, alpha=0.7)
    ax2.text(HEATMAP_P_GB[-1] * 0.95, 3.3, 'ML-KEM-1024',
             fontsize=8, color='white', ha='right', fontweight='bold')
    
    ax2.set_xlabel('Channel Burstiness $p_{GB}$ (Good $\\to$ Bad)')
    ax2.set_ylabel('Number of IP Fragments ($n$)')
    ax2.set_title(f'(b) TCP RTO Cascade Probability ($F \\geq {CASCADE_THRESHOLD}$)',
                  fontweight='bold')
    ax2.set_yticks(HEATMAP_FRAGS)
    ax2.grid(False)
    
    fig.tight_layout()
    
    for ext in ('png', 'pdf', 'svg'):
        path = os.path.join(OUTPUT_DIR, f'fig_gilbert_elliott_pdr.{ext}')
        fig.savefig(path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close(fig)
    
    print(f"Saved figures to {OUTPUT_DIR}/fig_gilbert_elliott_pdr.[png|pdf|svg]")

def print_summary():
    """Print raw data arrays for paper tables."""
    tc = coherence_time_us()
    print(f"\nChannel coherence time T_c = {tc:.2f} us")
    print(f"  (f_c={CARRIER_FREQ/1e9:.0f} GHz, v={VELOCITY:.0f} m/s)\n")
    
    print("=" * 80)
    print("  Gilbert-Elliott PDR Analytical Results")
    print("=" * 80)
    print(f"{'p_GB':>6} {'pi_B':>6} {'n=1':>8} {'n=2':>8} {'n=3':>8} {'n=4':>8}")
    print("-" * 80)
    
    for p_gb in P_GB_VALUES:
        _, pi_b = steady_state_probs(p_gb, P_BG)
        pdrs = [analytical_pdr(n, p_gb) for n in [1, 2, 3, 4]]
        print(f"{p_gb:>6.2f} {pi_b:>6.3f} " +
              " ".join(f"{p:>8.5f}" for p in pdrs))
    
    print("\n" + "=" * 80)
    print(f"  TCP RTO Cascade Probability (>= {CASCADE_THRESHOLD} failures)")
    print("=" * 80)
    print(f"{'p_GB':>6} {'n=1':>10} {'n=2':>10} {'n=3':>10} {'n=4':>10}")
    print("-" * 80)
    
    for p_gb in P_GB_VALUES:
        probs = [tcp_rto_cascade_prob_analytical(n, p_gb) for n in [1, 2, 3, 4]]
        print(f"{p_gb:>6.2f} " + " ".join(f"{p:>10.6f}" for p in probs))

# ═══════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  Gilbert-Elliott PDR Decay & TCP RTO Cascade")
    print(f"  Monte Carlo: N={N_MONTE_CARLO} channel realizations")
    print("=" * 60)
    
    print_summary()
    plot_results()
    
    print("\nDone.")

if __name__ == '__main__':
    main()
