#!/usr/bin/env python3
"""
Monte Carlo Simulation: CV-QKD Secure Key Rate from Holevo Bound.

Physics model (Gaussian modulation, reverse reconciliation):
  - Channel transmittance: eta in [0.01, 1.0]
  - Excess noise: xi = xi_0 + xi_turb(sigma_R^2)
  - Holevo information: chi(E) = g((lam1-1)/2) + g((lam2-1)/2) - g((lam3-1)/2) - g((lam4-1)/2)
    where g(x) = (x+1)*log2(x+1) - x*log2(x) and lam_i are symplectic eigenvalues
  - Mutual information: I_AB = log2((V + chi_tot) / (1 + chi_tot))
  - Key rate: K = beta*I_AB - chi(E) where beta = 0.95
  - Photon catalysis: effective transmittance boost eta_eff = eta * (1 + g_cat)

Monte Carlo: 50,000 turbulence realizations per (eta, sigma_R^2) pair
             using log-normal fading for channel transmittance fluctuations.

Output: 3-panel figure — (a) K vs eta, (b) photon catalysis improvement,
        (c) minimum eta for positive key rate vs excess noise.

Author: Kyber-6G Project, 2026
"""

import os
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from scipy.optimize import brentq

# ═══════════════════════════════════════════════════
# Configuration
# ═══════════════════════════════════════════════════

SEED = 42
N_MONTE_CARLO = 50_000

# Output
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SCRIPT_DIR)
OUTPUT_DIR = os.path.join(PROJECT_DIR, 'figures_rerun', 'cvqkd')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# QKD parameters
V_A = 20.0          # Alice's modulation variance (shot noise units, SNU)
XI_0 = 0.01         # Baseline excess noise (SNU, trusted device noise)
V_EL = 0.1          # Electronic noise at Bob's detector (SNU)
BETA = 0.95         # Reconciliation efficiency

# Turbulence parameters
SIGMA_R_VALUES = [0.1, 0.3, 0.6, 1.0, 1.5]  # Rytov variance values
WAVELENGTH_NM = 1550  # FSO wavelength in nm

# Transmittance sweep
ETA_VALUES = np.linspace(0.01, 1.0, 100)

# Photon catalysis gain values
G_CAT_VALUES = [0.0, 0.1, 0.2, 0.3]

# ═══════════════════════════════════════════════════
# CV-QKD Physics Functions
# ═══════════════════════════════════════════════════

def g_func(x):
    """
    Bosonic entropy function: g(x) = (x+1)*log2(x+1) - x*log2(x)
    
    This is the von Neumann entropy of a thermal state with mean
    photon number x.
    """
    if x <= 0:
        return 0.0
    return (x + 1) * np.log2(x + 1) - x * np.log2(x)

g_func_vec = np.vectorize(g_func)

def compute_cv_qkd_key_rate(eta, xi_excess, v_a=V_A, v_el=V_EL, beta=BETA):
    """
    Compute the CV-QKD secure key rate using the Holevo bound.
    
    Uses Gaussian modulation with reverse reconciliation (Bob measures,
    Alice corrects), which is optimal for high channel loss.
    
    Parameters:
        eta: channel transmittance [0, 1]
        xi_excess: total excess noise (SNU) = xi_0 + xi_turb
        v_a: Alice's modulation variance (SNU)
        v_el: Bob's electronic noise (SNU)
        beta: reconciliation efficiency
    
    Returns:
        key_rate: secure key rate (bits per channel use)
                  Returns 0 if key rate is negative (insecure).
    """
    if eta <= 0 or eta > 1:
        return 0.0
    
    # Total noise referred to the channel input
    chi_line = 1.0 / eta - 1.0 + xi_excess  # Channel added noise
    chi_het = 1.0 + v_el / eta               # Heterodyne detection noise (referred to input)
    chi_tot = chi_line + chi_het / eta        # Total noise
    
    # Covariance matrix elements
    V = v_a + 1.0  # Total variance at Alice (modulation + vacuum)
    
    # Bob's conditional variance (after Alice's measurement)
    V_B = eta * (V + chi_line) + 1.0 + v_el  # Bob's total variance
    
    # Mutual information I(A;B) for heterodyne detection
    snr = eta * v_a / (eta * chi_line + 1.0 + v_el)
    if snr <= 0:
        return 0.0
    I_AB = np.log2(1.0 + snr)
    
    # ── Holevo bound chi(B:E) ──
    # Symplectic eigenvalues of the covariance matrix
    # For a Gaussian channel with thermal noise model:
    
    A = V ** 2 * (1 - 2 * eta) + 2 * eta + eta ** 2 * (V + chi_line) ** 2
    B_val = (eta * (V * chi_line + 1)) ** 2
    
    # Eigenvalues of gamma_AB (full state)
    Delta = A ** 2 - 4 * B_val
    if Delta < 0:
        Delta = 0  # Numerical floor
    
    lambda_1_sq = 0.5 * (A + np.sqrt(Delta))
    lambda_2_sq = 0.5 * (A - np.sqrt(Delta))
    
    lambda_1 = np.sqrt(max(lambda_1_sq, 1.0))
    lambda_2 = np.sqrt(max(lambda_2_sq, 1.0))
    
    # Eigenvalues of gamma_A|B (conditional state after Bob's measurement)
    V_cond = V - eta * v_a ** 2 / (eta * (V + chi_line) + 1 + v_el)
    V_cond = max(V_cond, 1.0)
    
    # Simplified Holevo bound for thermal-loss channel
    chi_BE = g_func((lambda_1 - 1) / 2) + g_func((lambda_2 - 1) / 2) - g_func((V_cond - 1) / 2)
    
    # Secure key rate (reverse reconciliation)
    key_rate = beta * I_AB - chi_BE
    
    return max(key_rate, 0.0)

def turbulence_excess_noise(sigma_R_sq, base_xi=XI_0):
    """
    Compute excess noise contribution from atmospheric turbulence.
    
    Under the log-normal fading model (weak-to-moderate turbulence),
    the transmittance fluctuation adds effective excess noise:
    
    xi_turb ~ 2 * sigma_R^2 * V_A * (1 - eta_mean)
    
    Simplified model: xi_turb = sigma_R^2 * scaling_factor
    """
    # Empirical scaling from Usenko et al. (2012)
    xi_turb = 0.05 * sigma_R_sq  # SNU, proportional to Rytov variance
    return base_xi + xi_turb

# ═══════════════════════════════════════════════════
# Monte Carlo with Log-Normal Fading
# ═══════════════════════════════════════════════════

def monte_carlo_key_rate(eta_mean, sigma_R_sq, n_trials, rng, g_cat=0.0):
    """
    Monte Carlo simulation of CV-QKD key rate under turbulent fading.
    
    The instantaneous transmittance follows a log-normal distribution:
        eta_inst = eta_mean * exp(X - sigma_X^2/2)
    where X ~ N(0, sigma_X^2) and sigma_X^2 = ln(1 + sigma_I^2)
    with sigma_I^2 ~ exp(sigma_R^2) - 1 (scintillation index).
    
    Returns: (mean_key_rate, key_rate_samples)
    """
    # Scintillation index from Rytov variance
    sigma_I_sq = np.exp(min(sigma_R_sq, 10.0)) - 1.0  # Cap to avoid overflow
    sigma_I_sq = max(sigma_I_sq, 0.0)
    
    # Log-normal parameters
    sigma_X_sq = np.log(1.0 + sigma_I_sq)
    sigma_X = np.sqrt(sigma_X_sq)
    
    # Sample instantaneous transmittances
    X = rng.normal(0, sigma_X, size=n_trials) if sigma_X > 0 else np.zeros(n_trials)
    eta_inst = eta_mean * np.exp(X - sigma_X_sq / 2.0)
    eta_inst = np.clip(eta_inst, 1e-6, 1.0)
    
    # Apply photon catalysis boost
    if g_cat > 0:
        eta_inst = np.clip(eta_inst * (1.0 + g_cat), 1e-6, 1.0)
    
    # Compute excess noise for this turbulence level
    xi_total = turbulence_excess_noise(sigma_R_sq)
    
    # Compute key rate for each realization
    key_rates = np.array([
        compute_cv_qkd_key_rate(e, xi_total) for e in eta_inst
    ])
    
    return np.mean(key_rates), key_rates

# ═══════════════════════════════════════════════════
# Find minimum transmittance for positive key rate
# ═══════════════════════════════════════════════════

def find_min_eta_for_positive_rate(xi_total):
    """
    Find the minimum transmittance eta_min such that K(eta_min) > 0.
    Uses Brent's method for root finding.
    """
    def f(eta):
        return compute_cv_qkd_key_rate(eta, xi_total) - 1e-6
    
    try:
        eta_min = brentq(f, 0.001, 0.999, xtol=1e-5)
        return eta_min
    except ValueError:
        # No positive key rate exists for any eta
        return 1.0

# ═══════════════════════════════════════════════════
# Plotting
# ═══════════════════════════════════════════════════

def plot_results():
    """Generate the 3-panel publication figure."""
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
    
    fig, (ax1, ax2, ax3) = plt.subplots(1, 3, figsize=(17, 5.5))
    fig.suptitle('CV-QKD Secure Key Rate: Holevo Bound Analysis for 6G FSO Links',
                 fontsize=14, fontweight='bold', y=1.02)
    
    # ── Panel (a): Key rate vs transmittance for different turbulence ──
    colors_turb = ['#06b6d4', '#3b82f6', '#8b5cf6', '#ef4444', '#991b1b']
    markers = ['o', 's', 'D', '^', 'v']
    
    for i, sigma_R_sq in enumerate(SIGMA_R_VALUES):
        # Monte Carlo
        mc_rates = []
        mc_ci = []
        eta_subset = ETA_VALUES[::5]  # Subsample for MC (speed)
        
        for eta in eta_subset:
            mean_rate, samples = monte_carlo_key_rate(
                eta, sigma_R_sq, N_MONTE_CARLO, rng
            )
            mc_rates.append(mean_rate)
            # 95% CI
            if len(samples[samples > 0]) > 10:
                ci = 1.96 * np.std(samples) / np.sqrt(len(samples))
            else:
                ci = 0
            mc_ci.append(ci)
        
        # Analytical (deterministic, no fading)
        xi_total = turbulence_excess_noise(sigma_R_sq)
        analytical_rates = [compute_cv_qkd_key_rate(e, xi_total) for e in ETA_VALUES]
        
        label = f'$\\sigma_R^2={sigma_R_sq}$'
        
        # Analytical as line
        ax1.plot(ETA_VALUES, analytical_rates, '--', color=colors_turb[i],
                 alpha=0.4, lw=1.2)
        
        # MC as points
        ax1.errorbar(eta_subset, mc_rates, yerr=mc_ci,
                     label=label, color=colors_turb[i],
                     marker=markers[i], markersize=4, lw=1.5, capsize=2,
                     markevery=1, alpha=0.9)
    
    ax1.set_xlabel(r'Channel Transmittance $\eta$')
    ax1.set_ylabel(r'Secure Key Rate $K$ (bits/use)')
    ax1.set_title('(a) Key Rate vs Transmittance', fontweight='bold')
    ax1.legend(fontsize=8, title=r'Rytov variance $\sigma_R^2$',
               title_fontsize=8, loc='upper left')
    ax1.grid(True, ls='--', alpha=0.3, color='#94a3b8')
    ax1.set_xlim(0, 1.05)
    ax1.set_ylim(-0.1, None)
    ax1.axhline(0, color='#dc2626', ls=':', lw=1, alpha=0.5)
    ax1.text(0.05, 0.02, 'Insecure region', fontsize=8, color='#dc2626', alpha=0.7)
    
    # ── Panel (b): Photon catalysis improvement ──
    sigma_R_fixed = 0.6  # Moderate turbulence
    colors_cat = ['#64748b', '#06b6d4', '#3b82f6', '#6366f1']
    
    for i, g_cat in enumerate(G_CAT_VALUES):
        mc_rates = []
        eta_subset = ETA_VALUES[::5]
        
        for eta in eta_subset:
            mean_rate, _ = monte_carlo_key_rate(
                eta, sigma_R_fixed, N_MONTE_CARLO, rng, g_cat=g_cat
            )
            mc_rates.append(mean_rate)
        
        label = f'$g_{{cat}}={g_cat:.1f}$' if g_cat > 0 else 'No catalysis'
        ax2.plot(eta_subset, mc_rates, '-o', color=colors_cat[i],
                 markersize=4, lw=1.8, label=label, alpha=0.9)
    
    ax2.set_xlabel(r'Channel Transmittance $\eta$')
    ax2.set_ylabel(r'Secure Key Rate $K$ (bits/use)')
    ax2.set_title(f'(b) Photon Catalysis ($\\sigma_R^2={sigma_R_fixed}$)',
                  fontweight='bold')
    ax2.legend(fontsize=8, loc='upper left')
    ax2.grid(True, ls='--', alpha=0.3, color='#94a3b8')
    ax2.set_xlim(0, 1.05)
    ax2.set_ylim(-0.1, None)
    ax2.axhline(0, color='#dc2626', ls=':', lw=1, alpha=0.5)
    
    # Annotate improvement
    eta_example = 0.3
    rate_no_cat, _ = monte_carlo_key_rate(eta_example, sigma_R_fixed, N_MONTE_CARLO, rng, g_cat=0.0)
    rate_with_cat, _ = monte_carlo_key_rate(eta_example, sigma_R_fixed, N_MONTE_CARLO, rng, g_cat=0.3)
    if rate_no_cat > 0:
        improvement = (rate_with_cat - rate_no_cat) / rate_no_cat * 100
        ax2.annotate(f'+{improvement:.0f}%\nimprovement',
                     xy=(eta_example, rate_with_cat),
                     xytext=(eta_example + 0.15, rate_with_cat + 0.5),
                     fontsize=8, color='#6366f1',
                     arrowprops=dict(arrowstyle='->', color='#6366f1', lw=1))
    
    # ── Panel (c): Minimum eta for positive key rate vs excess noise ──
    xi_range = np.linspace(0.005, 0.5, 50)
    
    eta_min_values = [find_min_eta_for_positive_rate(xi) for xi in xi_range]
    
    ax3.fill_between(xi_range, eta_min_values, 1.0,
                     color='#dcfce7', alpha=0.5, label='Secure region')
    ax3.fill_between(xi_range, 0, eta_min_values,
                     color='#fecaca', alpha=0.5, label='Insecure region')
    ax3.plot(xi_range, eta_min_values, '-', color='#059669', lw=2.5,
             label=r'$\eta_{\min}$ boundary')
    
    # Mark turbulence levels
    for sigma_R_sq in [0.1, 0.6, 1.5]:
        xi = turbulence_excess_noise(sigma_R_sq)
        eta_min = find_min_eta_for_positive_rate(xi)
        ax3.scatter(xi, eta_min, color='#1e293b', s=50, zorder=5)
        ax3.annotate(f'$\\sigma_R^2={sigma_R_sq}$',
                     xy=(xi, eta_min),
                     xytext=(xi + 0.03, eta_min + 0.05),
                     fontsize=8, color='#1e293b',
                     arrowprops=dict(arrowstyle='->', color='#475569', lw=0.8))
    
    ax3.set_xlabel(r'Total Excess Noise $\xi$ (SNU)')
    ax3.set_ylabel(r'Minimum Transmittance $\eta_{\min}$')
    ax3.set_title(r'(c) Security Boundary', fontweight='bold')
    ax3.legend(fontsize=8, loc='upper left')
    ax3.grid(True, ls='--', alpha=0.3, color='#94a3b8')
    ax3.set_xlim(0, 0.5)
    ax3.set_ylim(0, 1.0)
    
    fig.tight_layout()
    
    for ext in ('png', 'pdf', 'svg'):
        path = os.path.join(OUTPUT_DIR, f'fig_cvqkd_keyrate.{ext}')
        fig.savefig(path, dpi=300, bbox_inches='tight', facecolor='white')
    plt.close(fig)
    
    print(f"Saved figures to {OUTPUT_DIR}/fig_cvqkd_keyrate.[png|pdf|svg]")

def print_summary():
    """Print raw data summary."""
    rng = np.random.default_rng(SEED)
    
    print("\n" + "=" * 80)
    print("  CV-QKD Secure Key Rate Summary")
    print(f"  lambda={WAVELENGTH_NM}nm, V_A={V_A} SNU, beta={BETA}")
    print("=" * 80)
    
    print(f"\n{'sigma_R^2':>10} {'xi_total':>10} {'eta_min':>10} "
          f"{'K(eta=0.3)':>12} {'K(eta=0.5)':>12} {'K(eta=0.8)':>12}")
    print("-" * 80)
    
    for sigma_R_sq in SIGMA_R_VALUES:
        xi = turbulence_excess_noise(sigma_R_sq)
        eta_min = find_min_eta_for_positive_rate(xi)
        
        rates = {}
        for eta in [0.3, 0.5, 0.8]:
            mean_rate, _ = monte_carlo_key_rate(eta, sigma_R_sq, N_MONTE_CARLO, rng)
            rates[eta] = mean_rate
        
        print(f"{sigma_R_sq:>10.2f} {xi:>10.4f} {eta_min:>10.4f} "
              f"{rates[0.3]:>12.4f} {rates[0.5]:>12.4f} {rates[0.8]:>12.4f}")
    
    print("\n  Photon catalysis improvement (sigma_R^2=0.6, eta=0.3):")
    for g_cat in G_CAT_VALUES:
        mean_rate, _ = monte_carlo_key_rate(0.3, 0.6, N_MONTE_CARLO, rng, g_cat=g_cat)
        print(f"    g_cat={g_cat:.1f}: K={mean_rate:.4f} bits/use")

# ═══════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════

def main():
    print("=" * 60)
    print("  CV-QKD Secure Key Rate — Monte Carlo Simulation")
    print(f"  N={N_MONTE_CARLO} turbulence realizations per point")
    print("=" * 60)
    
    print_summary()
    plot_results()
    
    print("\nDone.")

if __name__ == '__main__':
    main()
