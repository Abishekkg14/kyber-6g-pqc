#!/usr/bin/env python3
"""
================================================================================
  Kyber-6G · Publication-Ready Plot Generation
================================================================================
Generates calibrated simulation plots for IEEE Access submission.
All figures: 300 DPI, tight layout, explicit labels, units on all axes.

Requires:
  - sim_results_1to1_baseline.csv (from Tier A)
  - sim_results_swarm_sweep.csv (from Tier B)
  - hitl_benchmarks_extended.csv (HITL ground truth)

Outputs (simulation_results/plots/):
  1. hw_vs_sim_1to1_validation.png
  2. latency_vs_swarm_size.png
  3. latency_vs_mobility.png
  4. energy_vs_swarm_scale.png
  5. queuing_and_packet_loss.png
  6. crypto_latency_breakdown.png
  7. urllc_compliance_heatmap.png

Author: Kyber-6G Project, Sep 2026
================================================================================
"""

from __future__ import annotations

import os
import sys
import warnings
from typing import Optional

import numpy as np
import pandas as pd
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from matplotlib.patches import FancyBboxPatch
import matplotlib.patheffects as pe

warnings.filterwarnings("ignore", category=FutureWarning)

# ════════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ════════════════════════════════════════════════════════════════════════════════
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.join(SCRIPT_DIR, "..")
ROOT_DIR = os.path.abspath(os.path.join(PROJECT_DIR, "..", ".."))

SIM_DATA_DIR = os.path.join(PROJECT_DIR, "simulation_results", "data")
PLOT_DIR = os.path.join(PROJECT_DIR, "simulation_results", "plots")
os.makedirs(PLOT_DIR, exist_ok=True)

# Also save copies to root for easy access
ROOT_PLOT_DIR = ROOT_DIR

# Input files
HITL_CSV = os.path.join(ROOT_DIR, "hitl_benchmarks_extended.csv")
BASELINE_CSV = os.path.join(SIM_DATA_DIR, "sim_results_1to1_baseline.csv")
SWARM_CSV = os.path.join(SIM_DATA_DIR, "sim_results_swarm_sweep.csv")

# Plot style
DPI = 300
FIGSIZE_SINGLE = (8, 5)       # Single-column
FIGSIZE_DOUBLE = (10, 5.5)    # Double-column
FIGSIZE_WIDE = (12, 5)        # Wide

# Color palette (professional, accessible)
COLORS = {
    "hw": "#2E86AB",          # Steel blue — hardware
    "sim": "#E8550E",         # Burnt orange — simulation
    "full": "#D64045",        # Red — full handshake
    "rekey": "#1B998B",       # Teal — 0-RTT rekey
    "energy_full": "#7B2D8E", # Purple — full energy
    "energy_rekey": "#F0C808",# Gold — rekey energy
    "urllc": "#D64045",       # Red — URLLC deadline
    "grid": "#E0E0E0",
    "bg": "#FAFAFA",
    "accent1": "#3A86FF",
    "accent2": "#FF006E",
    "accent3": "#8338EC",
    "accent4": "#FB5607",
}

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 11,
    "axes.titlesize": 13,
    "axes.labelsize": 12,
    "xtick.labelsize": 10,
    "ytick.labelsize": 10,
    "legend.fontsize": 9,
    "figure.dpi": DPI,
    "savefig.dpi": DPI,
    "savefig.bbox": "tight",
    "axes.grid": True,
    "grid.alpha": 0.3,
    "axes.facecolor": COLORS["bg"],
})


def save_plot(fig: plt.Figure, name: str) -> None:
    """Save plot to both plot directory and root directory."""
    path1 = os.path.join(PLOT_DIR, name)
    fig.savefig(path1, dpi=DPI, bbox_inches="tight", facecolor="white")
    print(f"  → {path1}")

    path2 = os.path.join(ROOT_PLOT_DIR, name)
    fig.savefig(path2, dpi=DPI, bbox_inches="tight", facecolor="white")
    print(f"  → {path2}")

    plt.close(fig)


# ════════════════════════════════════════════════════════════════════════════════
# PLOT 1: HW vs SIM 1-to-1 Validation
# ════════════════════════════════════════════════════════════════════════════════
def plot_hw_vs_sim_validation(hitl_df: pd.DataFrame, sim_df: pd.DataFrame) -> None:
    """Direct side-by-side comparison: Physical RPi4 vs Calibrated Simulation."""
    print("\n  [1/7] Generating hw_vs_sim_1to1_validation.png ...")

    fig, axes = plt.subplots(1, 3, figsize=(14, 5))
    fig.suptitle("Hardware-in-the-Loop vs. Calibrated Simulation Validation\n"
                 "RPi4 Cortex-A72 · ML-KEM-1024 + X25519 + ML-DSA-87",
                 fontsize=13, fontweight="bold", y=1.02)

    # ── Panel A: Handshake Latency Box Plot ──
    ax = axes[0]
    hw_full = hitl_df[hitl_df["Mode"] == "FULL_PQC"]["Total_Handshake_ms"]
    hw_rekey = hitl_df[hitl_df["Mode"] == "0RTT_REKEY"]["Total_Handshake_ms"]
    sim_full = sim_df[sim_df["Mode"] == "FULL_PQC"]["Total_Handshake_ms"]
    sim_rekey = sim_df[sim_df["Mode"] == "0RTT_REKEY"]["Total_Handshake_ms"]

    bp_data = [hw_full, sim_full, hw_rekey, sim_rekey]
    bp_colors = [COLORS["hw"], COLORS["sim"], COLORS["hw"], COLORS["sim"]]
    bp_labels = ["H/W Full", "Sim Full", "H/W 0-RTT", "Sim 0-RTT"]

    bp = ax.boxplot(bp_data, patch_artist=True, widths=0.6,
                    tick_labels=bp_labels,
                    medianprops=dict(color="black", linewidth=1.5))
    for patch, color in zip(bp["boxes"], bp_colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)

    ax.set_ylabel("Handshake Latency (ms)")
    ax.set_title("(a) Latency Distribution")
    ax.axhline(y=10.0, color=COLORS["urllc"], linestyle="--", linewidth=1, alpha=0.7, label="URLLC 10 ms")
    ax.legend(loc="upper right", fontsize=8)

    # ── Panel B: Energy Bar Chart ──
    ax = axes[1]
    hw_full_e = hitl_df[hitl_df["Mode"] == "FULL_PQC"]["Energy_mJ"].mean()
    hw_rekey_e = hitl_df[hitl_df["Mode"] == "0RTT_REKEY"]["Energy_mJ"].mean()
    sim_full_e = sim_df[sim_df["Mode"] == "FULL_PQC"]["Energy_mJ"].mean()
    sim_rekey_e = sim_df[sim_df["Mode"] == "0RTT_REKEY"]["Energy_mJ"].mean()

    x = np.arange(2)
    width = 0.35
    bars1 = ax.bar(x - width / 2, [hw_full_e, hw_rekey_e], width,
                   label="Physical RPi4 (H/W)", color=COLORS["hw"], alpha=0.8, edgecolor="white")
    bars2 = ax.bar(x + width / 2, [sim_full_e, sim_rekey_e], width,
                   label="Calibrated Sim (S/W)", color=COLORS["sim"], alpha=0.8, edgecolor="white")

    ax.set_xticks(x)
    ax.set_xticklabels(["Full Handshake", "0-RTT Rekey"])
    ax.set_ylabel("Energy Dissipation (mJ)")
    ax.set_title("(b) Energy Profile")
    ax.legend(loc="upper right", fontsize=8)

    # Add value annotations
    for bar in bars1:
        ax.annotate(f"{bar.get_height():.1f}",
                    xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                    xytext=(0, 3), textcoords="offset points",
                    ha="center", va="bottom", fontsize=8)
    for bar in bars2:
        ax.annotate(f"{bar.get_height():.1f}",
                    xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                    xytext=(0, 3), textcoords="offset points",
                    ha="center", va="bottom", fontsize=8)

    # ── Panel C: Variance Summary ──
    ax = axes[2]
    metrics = ["Full Lat.", "0-RTT Lat.", "Full Energy", "0-RTT Energy"]
    hw_vals = [hw_full.mean(), hw_rekey.mean(), hw_full_e, hw_rekey_e]
    sim_vals = [sim_full.mean(), sim_rekey.mean(), sim_full_e, sim_rekey_e]
    variances = [abs(s - h) / h * 100 for h, s in zip(hw_vals, sim_vals)]

    bar_colors = [COLORS["accent1"] if v <= 2.0 else (COLORS["accent4"] if v <= 5.0 else COLORS["urllc"])
                  for v in variances]
    bars = ax.barh(metrics, variances, color=bar_colors, alpha=0.8, edgecolor="white", height=0.6)
    ax.axvline(x=2.0, color=COLORS["urllc"], linestyle="--", linewidth=1.5, alpha=0.7, label="±2% threshold")
    ax.set_xlabel("Variance (%)")
    ax.set_title("(c) H/W vs. Sim Variance")
    ax.legend(loc="lower right", fontsize=8)
    ax.set_xlim(0, max(variances) * 1.3 + 0.5)

    for bar, v in zip(bars, variances):
        ax.annotate(f"{v:.2f}%",
                    xy=(bar.get_width(), bar.get_y() + bar.get_height() / 2),
                    xytext=(3, 0), textcoords="offset points",
                    ha="left", va="center", fontsize=9, fontweight="bold")

    fig.tight_layout()
    save_plot(fig, "hw_vs_sim_1to1_validation.png")


# ════════════════════════════════════════════════════════════════════════════════
# PLOT 2: Latency vs Swarm Size
# ════════════════════════════════════════════════════════════════════════════════
def plot_latency_vs_swarm(swarm_df: pd.DataFrame) -> None:
    """End-to-end latency scaling from 1 to 80 drones."""
    print("  [2/7] Generating latency_vs_swarm_size.png ...")

    # Filter to default velocity (25 m/s)
    df = swarm_df[swarm_df["Velocity_ms"] == 25.0].copy()
    if df.empty:
        df = swarm_df[swarm_df["Velocity_ms"] == swarm_df["Velocity_ms"].max()].copy()

    fig, ax = plt.subplots(figsize=FIGSIZE_SINGLE)

    sizes = df["Swarm_Size"].values

    # Full handshake
    ax.plot(sizes, df["Full_Handshake_Mean_ms"], "o-", color=COLORS["full"],
            linewidth=2, markersize=6, label="Full Cold-Start (Mean)", zorder=5)
    ax.fill_between(sizes, df["Full_Handshake_P50_ms"], df["Full_Handshake_P99_ms"],
                    alpha=0.15, color=COLORS["full"], label="Full (P50–P99)")

    # 0-RTT rekey
    ax.plot(sizes, df["Rekey_0RTT_Mean_ms"], "s-", color=COLORS["rekey"],
            linewidth=2, markersize=6, label="0-RTT RapidRekey (Mean)", zorder=5)
    ax.fill_between(sizes, df["Rekey_0RTT_P50_ms"], df["Rekey_0RTT_P99_ms"],
                    alpha=0.15, color=COLORS["rekey"], label="0-RTT (P50–P99)")

    # URLLC deadline
    ax.axhline(y=10.0, color=COLORS["urllc"], linestyle="--", linewidth=2,
               alpha=0.8, label="URLLC 10 ms Deadline")

    # Find crossing point
    compliant = df[df["Rekey_0RTT_P99_ms"] < 10.0]
    if not compliant.empty:
        max_n = compliant["Swarm_Size"].max()
        ax.axvline(x=max_n, color=COLORS["urllc"], linestyle=":", linewidth=1, alpha=0.5)
        ax.annotate(f"URLLC limit: {max_n} drones",
                    xy=(max_n, 10.0), xytext=(max_n + 3, 12),
                    arrowprops=dict(arrowstyle="->", color=COLORS["urllc"]),
                    fontsize=9, color=COLORS["urllc"], fontweight="bold")

    ax.set_xlabel("Swarm Size (Number of Drones)")
    ax.set_ylabel("End-to-End Handshake Latency (ms)")
    ax.set_title("Handshake Latency Scaling with Drone Swarm Density\n"
                 "ML-KEM-1024 + X25519 + ML-DSA-87 | v = 25 m/s | 3.5 GHz n78")
    ax.legend(loc="upper left", framealpha=0.9)
    ax.set_xlim(0, max(sizes) + 5)

    fig.tight_layout()
    save_plot(fig, "latency_vs_swarm_size.png")


# ════════════════════════════════════════════════════════════════════════════════
# PLOT 3: Latency vs Mobility
# ════════════════════════════════════════════════════════════════════════════════
def plot_latency_vs_mobility(swarm_df: pd.DataFrame) -> None:
    """Latency progression across velocities, cached vs uncached."""
    print("  [3/7] Generating latency_vs_mobility.png ...")

    # Use N=20 drones as representative
    df20 = swarm_df[swarm_df["Swarm_Size"] == 20].copy()
    if df20.empty:
        df20 = swarm_df[swarm_df["Swarm_Size"] == swarm_df["Swarm_Size"].min()].copy()

    # Also generate extended velocity data
    from run_hitl_calibrated_pipeline import (
        load_hitl_calibration, generate_full_handshake_ms,
        generate_rekey_ms, queuing_delay_mm1_ms, handover_delay_ms,
        HITL_CSV, SEED
    )
    cal = load_hitl_calibration(HITL_CSV)

    velocities = np.arange(0, 125, 5)
    rng = np.random.default_rng(SEED + 100)
    full_means, rekey_means = [], []
    MC = 200

    for v in velocities:
        fulls, rekeys = [], []
        for _ in range(MC):
            f = generate_full_handshake_ms(rng, cal) + queuing_delay_mm1_ms(20, rng) + handover_delay_ms(v, rng)
            r = generate_rekey_ms(rng, cal) + queuing_delay_mm1_ms(20, rng)
            fulls.append(f)
            rekeys.append(r)
        full_means.append(np.mean(fulls))
        rekey_means.append(np.mean(rekeys))

    fig, ax = plt.subplots(figsize=FIGSIZE_SINGLE)

    ax.plot(velocities, full_means, "o-", color=COLORS["full"],
            linewidth=2, markersize=4, label="Full Cold-Start Handshake")
    ax.plot(velocities, rekey_means, "s-", color=COLORS["rekey"],
            linewidth=2, markersize=4, label="0-RTT RapidRekey (Cached)")

    ax.axhline(y=10.0, color=COLORS["urllc"], linestyle="--", linewidth=2,
               alpha=0.8, label="URLLC 10 ms Deadline")

    ax.set_xlabel("UAV Velocity (m/s)")
    ax.set_ylabel("Mean Handshake Latency (ms)")
    ax.set_title("Handshake Latency vs. UAV Mobility Speed\n"
                 "N = 20 Drones | ML-KEM-1024 + X25519 + ML-DSA-87")
    ax.legend(loc="upper left", framealpha=0.9)

    # Annotate key velocity points
    for v_label in [25, 50, 100, 120]:
        idx = int(v_label / 5)
        if idx < len(full_means):
            ax.annotate(f"{full_means[idx]:.1f} ms",
                        xy=(v_label, full_means[idx]),
                        xytext=(5, 10), textcoords="offset points",
                        fontsize=7, color=COLORS["full"])

    fig.tight_layout()
    save_plot(fig, "latency_vs_mobility.png")


# ════════════════════════════════════════════════════════════════════════════════
# PLOT 4: Energy vs Swarm Scale
# ════════════════════════════════════════════════════════════════════════════════
def plot_energy_vs_swarm(swarm_df: pd.DataFrame) -> None:
    """Cumulative energy dissipation curves."""
    print("  [4/7] Generating energy_vs_swarm_scale.png ...")

    df = swarm_df[swarm_df["Velocity_ms"] == 25.0].copy()
    if df.empty:
        df = swarm_df[swarm_df["Velocity_ms"] == swarm_df["Velocity_ms"].max()].copy()

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=FIGSIZE_DOUBLE)

    sizes = df["Swarm_Size"].values

    # Panel A: Per-handshake energy
    ax1.plot(sizes, df["Full_Energy_Mean_mJ"], "o-", color=COLORS["energy_full"],
             linewidth=2, markersize=6, label=f"Full Handshake (~240 mJ)")
    ax1.plot(sizes, df["Rekey_Energy_Mean_mJ"], "s-", color=COLORS["energy_rekey"],
             linewidth=2, markersize=6, label=f"0-RTT Rekey (~1.6 mJ)")

    ax1.set_xlabel("Swarm Size (Drones)")
    ax1.set_ylabel("Per-Handshake Energy (mJ)")
    ax1.set_title("(a) Per-Handshake Energy Dissipation")
    ax1.legend(loc="upper left")
    ax1.set_yscale("log")

    # Panel B: Cumulative energy for 100 handshakes per drone
    n_handshakes = 100  # per simulation run
    cumulative_full = df["Full_Energy_Mean_mJ"].values * sizes * n_handshakes / 1000.0  # Joules
    cumulative_rekey = df["Rekey_Energy_Mean_mJ"].values * sizes * n_handshakes / 1000.0

    ax2.bar(sizes - 2, cumulative_full, width=4, color=COLORS["energy_full"],
            alpha=0.8, label="Full Handshake (cumulative)", edgecolor="white")
    ax2.bar(sizes + 2, cumulative_rekey, width=4, color=COLORS["energy_rekey"],
            alpha=0.8, label="0-RTT Rekey (cumulative)", edgecolor="white")

    ax2.set_xlabel("Swarm Size (Drones)")
    ax2.set_ylabel("Cumulative Energy (J) — 100 Handshakes/Drone")
    ax2.set_title("(b) Swarm-Scale Energy Budget")
    ax2.legend(loc="upper left")

    # Annotate savings ratio
    if len(cumulative_full) > 0 and cumulative_rekey[-1] > 0:
        ratio = cumulative_full[-1] / cumulative_rekey[-1]
        ax2.annotate(f"Full/0-RTT ratio: {ratio:.0f}×",
                     xy=(sizes[-1], cumulative_full[-1]),
                     xytext=(-60, -20), textcoords="offset points",
                     fontsize=9, fontweight="bold", color=COLORS["energy_full"],
                     arrowprops=dict(arrowstyle="->", color=COLORS["energy_full"]))

    fig.suptitle("Energy Dissipation Analysis — RPi4 Cortex-A72 SWaP-C Profile\n"
                 "P_cpu=5.0W | P_idle=1.0W | P_tx=0.52W | P_rx=0.16W",
                 fontsize=12, fontweight="bold", y=1.04)
    fig.tight_layout()
    save_plot(fig, "energy_vs_swarm_scale.png")


# ════════════════════════════════════════════════════════════════════════════════
# PLOT 5: Queuing and Packet Loss
# ════════════════════════════════════════════════════════════════════════════════
def plot_queuing_and_pdr(swarm_df: pd.DataFrame) -> None:
    """M/M/1 buffer queuing delays and packet delivery ratios."""
    print("  [5/7] Generating queuing_and_packet_loss.png ...")

    df = swarm_df[swarm_df["Velocity_ms"] == 25.0].copy()
    if df.empty:
        df = swarm_df[swarm_df["Velocity_ms"] == swarm_df["Velocity_ms"].max()].copy()

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=FIGSIZE_DOUBLE)

    sizes = df["Swarm_Size"].values

    # Panel A: Queuing Delay
    ax1.plot(sizes, df["Queue_Delay_Mean_ms"], "D-", color=COLORS["accent3"],
             linewidth=2, markersize=6, label="M/M/1 Queue Delay (Mean)")
    ax1.fill_between(sizes, 0, df["Queue_Delay_Mean_ms"],
                     alpha=0.15, color=COLORS["accent3"])
    ax1.axhline(y=1.0, color=COLORS["urllc"], linestyle=":", linewidth=1,
                alpha=0.6, label="1 ms Reference")

    ax1.set_xlabel("Swarm Size (Drones)")
    ax1.set_ylabel("Mean Queue Delay (ms)")
    ax1.set_title("(a) M/M/1 Buffer Queue Delay\nρ per node = 0.011")
    ax1.legend(loc="upper left")

    # Panel B: PDR
    ax2.plot(sizes, df["PDR"] * 100, "^-", color=COLORS["accent1"],
             linewidth=2, markersize=6, label="Packet Delivery Ratio")
    ax2.fill_between(sizes, df["PDR"] * 100, 100,
                     alpha=0.1, color=COLORS["urllc"], label="Loss Region")
    ax2.axhline(y=99.9, color=COLORS["rekey"], linestyle="--", linewidth=1,
                alpha=0.7, label="99.9% Target")

    # Annotate fragmentation impact
    from run_hitl_calibrated_pipeline import _fragmentation_count, SIZES
    n_frags = _fragmentation_count(SIZES["mlkem1024_pk"] + SIZES["mldsa87_sig"])
    ax2.annotate(f"Level-5 payload: {n_frags} IP fragments\n"
                 f"(MTU={SIZES['transport_mtu']} B)",
                 xy=(sizes[len(sizes)//2], df["PDR"].iloc[len(sizes)//2] * 100),
                 xytext=(10, -25), textcoords="offset points",
                 fontsize=8, fontstyle="italic",
                 bbox=dict(boxstyle="round,pad=0.3", facecolor="lightyellow", alpha=0.8))

    ax2.set_xlabel("Swarm Size (Drones)")
    ax2.set_ylabel("Packet Delivery Ratio (%)")
    ax2.set_title("(b) PDR with Level-5 Fragmentation Overhead")
    ax2.legend(loc="lower left")
    ax2.set_ylim(min(df["PDR"].min() * 100 - 1, 98), 100.2)

    fig.suptitle("Queuing Dynamics & Packet Delivery — NIST Level-5 PQC Overhead\n"
                 "3.5 GHz n78 | MTU=1352 B | v=25 m/s",
                 fontsize=12, fontweight="bold", y=1.04)
    fig.tight_layout()
    save_plot(fig, "queuing_and_packet_loss.png")


# ════════════════════════════════════════════════════════════════════════════════
# PLOT 6: Crypto Latency Breakdown
# ════════════════════════════════════════════════════════════════════════════════
def plot_crypto_breakdown() -> None:
    """Stacked bar chart showing crypto component breakdown."""
    print("  [6/7] Generating crypto_latency_breakdown.png ...")

    # Component timings (ms)
    components = {
        "ML-KEM-1024\nKeyGen": 0.234,
        "X25519\nKeyGen": 0.038,
        "ML-KEM-1024\nEncaps": 0.282,
        "X25519\nDH": 0.104,
        "ML-DSA-87\nSign": 1.850,
        "ML-KEM-1024\nDecaps": 0.327,
        "ML-DSA-87\nVerify": 0.480,
        "HKDF +\nAES Setup": 0.027,
    }

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=FIGSIZE_DOUBLE)

    # Panel A: Individual components
    names = list(components.keys())
    values = list(components.values())
    colors_bar = [COLORS["accent1"], COLORS["accent2"], COLORS["accent1"],
                  COLORS["accent2"], COLORS["accent3"], COLORS["accent1"],
                  COLORS["accent3"], COLORS["accent4"]]

    bars = ax1.barh(names, values, color=colors_bar, alpha=0.85, edgecolor="white")
    ax1.set_xlabel("Processing Time (ms)")
    ax1.set_title("(a) Cryptographic Component Breakdown\nCortex-A72 @ 1.5 GHz")
    ax1.invert_yaxis()

    for bar, val in zip(bars, values):
        ax1.annotate(f"{val:.3f} ms",
                     xy=(bar.get_width(), bar.get_y() + bar.get_height() / 2),
                     xytext=(3, 0), textcoords="offset points",
                     ha="left", va="center", fontsize=8)

    # Panel B: Parallel vs Sequential
    # Sequential total
    seq_total = sum(values)
    # Parallel: KeyGen=max(MLKEM,X25519)*1.1, Encaps=max(MLKEM,X25519)*1.1
    par_keygen = max(0.234, 0.038) * 1.10
    par_encaps = max(0.282, 0.104) * 1.10
    par_decaps = max(0.327, 0.104) * 1.10
    par_total = par_keygen + par_encaps + 1.850 + par_decaps + 0.480 + 0.027

    modes = ["Sequential\n(Single-Core)", "Parallel\n(Dual-Core)"]
    totals = [seq_total, par_total]
    savings = (1.0 - par_total / seq_total) * 100

    bars2 = ax2.bar(modes, totals, color=[COLORS["accent4"], COLORS["rekey"]],
                    alpha=0.85, edgecolor="white", width=0.5)
    ax2.set_ylabel("Total Crypto Processing Time (ms)")
    ax2.set_title(f"(b) Parallelization Benefit: {savings:.1f}% Reduction")

    for bar, val in zip(bars2, totals):
        ax2.annotate(f"{val:.2f} ms",
                     xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
                     xytext=(0, 5), textcoords="offset points",
                     ha="center", va="bottom", fontsize=10, fontweight="bold")

    fig.suptitle("PQC Cryptographic Overhead Analysis\n"
                 "ML-KEM-1024 + X25519 + ML-DSA-87 + AES-256-GCM",
                 fontsize=12, fontweight="bold", y=1.04)
    fig.tight_layout()
    save_plot(fig, "crypto_latency_breakdown.png")


# ════════════════════════════════════════════════════════════════════════════════
# PLOT 7: URLLC Compliance Heatmap
# ════════════════════════════════════════════════════════════════════════════════
def plot_urllc_heatmap(swarm_df: pd.DataFrame) -> None:
    """Heatmap showing URLLC compliance across swarm size × velocity."""
    print("  [7/7] Generating urllc_compliance_heatmap.png ...")

    pivot = swarm_df.pivot_table(
        index="Velocity_ms",
        columns="Swarm_Size",
        values="Rekey_0RTT_P99_ms",
        aggfunc="mean"
    )

    fig, ax = plt.subplots(figsize=FIGSIZE_SINGLE)

    # Create binary compliance mask
    compliance = (pivot < 10.0).astype(float)

    # Plot heatmap of actual latency values
    import matplotlib.colors as mcolors
    norm = mcolors.TwoSlopeNorm(vmin=pivot.values.min(), vcenter=10.0, vmax=max(pivot.values.max(), 15.0))
    cmap = plt.cm.RdYlGn_r

    im = ax.imshow(pivot.values, cmap=cmap, norm=norm, aspect="auto")
    cbar = fig.colorbar(im, ax=ax, label="0-RTT P99 Latency (ms)")

    # Labels
    ax.set_xticks(range(len(pivot.columns)))
    ax.set_xticklabels(pivot.columns.astype(int))
    ax.set_yticks(range(len(pivot.index)))
    ax.set_yticklabels([f"{v:.0f}" for v in pivot.index])
    ax.set_xlabel("Swarm Size (Drones)")
    ax.set_ylabel("UAV Velocity (m/s)")
    ax.set_title("0-RTT RapidRekey P99 Latency — URLLC Compliance Map\n"
                 "Green ≤ 10 ms (URLLC) | Red > 10 ms (Non-compliant)")

    # Annotate cells
    for i in range(len(pivot.index)):
        for j in range(len(pivot.columns)):
            val = pivot.values[i, j]
            color = "white" if val > 12 else "black"
            marker = "✓" if val < 10.0 else "✗"
            ax.text(j, i, f"{val:.1f}\n{marker}",
                    ha="center", va="center", fontsize=7, color=color, fontweight="bold")

    fig.tight_layout()
    save_plot(fig, "urllc_compliance_heatmap.png")


# ════════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════════
def main() -> None:
    print("╔════════════════════════════════════════════════════════════╗")
    print("║  KYBER-6G · Publication-Ready Plot Generation            ║")
    print("║  IEEE Access Double-Column · 300 DPI · Tight Layout      ║")
    print("╚════════════════════════════════════════════════════════════╝")

    # Load data
    if not os.path.exists(HITL_CSV):
        print(f"  [ERROR] HITL CSV not found: {HITL_CSV}")
        sys.exit(1)
    if not os.path.exists(BASELINE_CSV):
        print(f"  [ERROR] Baseline CSV not found: {BASELINE_CSV}")
        print(f"  Run run_hitl_calibrated_pipeline.py first!")
        sys.exit(1)
    if not os.path.exists(SWARM_CSV):
        print(f"  [ERROR] Swarm CSV not found: {SWARM_CSV}")
        print(f"  Run run_hitl_calibrated_pipeline.py first!")
        sys.exit(1)

    hitl_df = pd.read_csv(HITL_CSV)
    sim_df = pd.read_csv(BASELINE_CSV)
    swarm_df = pd.read_csv(SWARM_CSV)

    print(f"\n  HITL data: {len(hitl_df)} rows | Sim baseline: {len(sim_df)} rows | Swarm: {len(swarm_df)} rows\n")

    # Generate all plots
    plot_hw_vs_sim_validation(hitl_df, sim_df)
    plot_latency_vs_swarm(swarm_df)
    plot_latency_vs_mobility(swarm_df)
    plot_energy_vs_swarm(swarm_df)
    plot_queuing_and_pdr(swarm_df)
    plot_crypto_breakdown()
    plot_urllc_heatmap(swarm_df)

    print(f"\n  ═══ ALL {7} PLOTS GENERATED SUCCESSFULLY ═══")
    print(f"  Output directory: {PLOT_DIR}")
    print()


if __name__ == "__main__":
    main()
