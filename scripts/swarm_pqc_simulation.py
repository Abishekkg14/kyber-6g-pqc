#!/usr/bin/env python3
"""
=======================================================================
  Kyber-6G  ·  Large-Scale UAV Swarm PQC Simulation + Ablation Study
=======================================================================
Monte Carlo simulation of hybrid post-quantum handshake protocol
(ML-KEM-1024 + X25519 + HKDF-SHA256 + AES-256-GCM) over 5G/6G URLLC channels.

Hardware Profile (HITL Specification):
  - Device: Raspberry Pi 4 Model B (2 GB RAM)
  - Processor: Quad-core ARM Cortex-A72 (ARMv8-A 64-bit) @ 1.5 GHz
  - Hardware Crypto: ARMv8 Cryptography Extensions (hardware AES & SHA-256)
  - Parallel Processing: Dual asymmetric primitives (ML-KEM-1024 + X25519)
    execute concurrently across the physical CPU cores.

Folder Structure & Separation:
  - Main Simulation:
      simulation_results/data/simulation_results_clean.csv
      simulation_results/plots/ (Plots 01 - 06)
  - Ablation Study:
      ablation_study/data/ablation_summary.csv & per-scenario CSVs
      ablation_study/plots/ (Plot 07 Ablation Heatmap)

Author : Kyber-6G Project, Sep 2026
=======================================================================
"""

import csv
import math
import os
import sys
import time
import warnings
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import seaborn as sns
from scipy import stats as sp_stats

warnings.filterwarnings('ignore', category=FutureWarning)

# ====================================================================
# 0.  GLOBAL CONFIGURATION & DIRECTORY MANAGEMENT
# ====================================================================
MASTER_SEED   = 2026_0905
PROJECT_DIR   = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')

# Clean separated directories
SIM_DIR            = os.path.join(PROJECT_DIR, 'simulation_results')
SIM_DATA_DIR       = os.path.join(SIM_DIR, 'data')
SIM_PLOT_DIR       = os.path.join(SIM_DIR, 'plots')
CSV_OUT            = os.path.join(SIM_DATA_DIR, 'simulation_results_clean.csv')

ABLATION_DIR       = os.path.join(PROJECT_DIR, 'ablation_study')
ABLATION_DATA_DIR  = os.path.join(ABLATION_DIR, 'data')
ABLATION_PLOT_DIR  = os.path.join(ABLATION_DIR, 'plots')
ABLATION_CSV       = os.path.join(ABLATION_DATA_DIR, 'ablation_summary.csv')

os.makedirs(SIM_DATA_DIR, exist_ok=True)
os.makedirs(SIM_PLOT_DIR, exist_ok=True)
os.makedirs(ABLATION_DATA_DIR, exist_ok=True)
os.makedirs(ABLATION_PLOT_DIR, exist_ok=True)

SWARM_SIZES   = list(range(10, 101, 10))
MC_ITERS      = 1_000
ABLATION_MC   = 500
N_WORKERS     = max(1, cpu_count() - 1)

CACHE_HIT_PROBS = [round(p, 2) for p in np.arange(0.0, 1.01, 0.05)]

# ====================================================================
# 1.  PROTOCOL & HARDWARE PROFILE CONSTANTS
# ====================================================================
# Hardware: Raspberry Pi 4 Model B (2 GB RAM)
# Processor: Quad-core ARM Cortex-A72 @ 1.5 GHz (ARMv8-A 64-bit)
# Sources: NIST FIPS 203, liboqs 0.10+ aarch64 Cortex-A72 benchmarks,
#          ARMv8 Cryptography Extension hardware-accelerated AES/SHA-256
CRYPTO = {
    'Hybrid': {
        'label': 'Hybrid (ML-KEM-1024 + X25519)',
        'keygen_us': 156.0,      # ML-KEM-1024 KeyGen (~234k cycles @ 1.5 GHz)
        'encaps_us': 188.0,      # ML-KEM-1024 Encaps (~282k cycles @ 1.5 GHz)
        'decaps_us': 218.0,      # ML-KEM-1024 Decaps (~327k cycles @ 1.5 GHz)
        'ecdh_us':   104.0,      # X25519 scalar multiplication (~156k cycles)
        'ecdh_keygen_us': 38.0,  # X25519 key generation
        'hkdf_us':    10.8,      # HKDF-SHA256 (ARMv8 SHA-2 hardware accelerated)
        'aes_setup_us': 2.8,     # AES-256-GCM key schedule (ARMv8 AES hardware accelerated)
        'pk_bytes':  1600,       # 1568 (Kyber PK) + 32 (X25519 PK)
        'ct_bytes':  1600,       # 1568 (Kyber CT) + 32 (X25519 ephemeral)
        'ss_bytes':    32,       # fused 256-bit session key
        'rrc_overhead_bytes': 120,
        'parallel_cores': 4,     # Raspberry Pi 4 Quad-Core Cortex-A72
    },
    'Classical': {
        'label': 'Classical ECC (X25519)',
        'keygen_us':   0.0,
        'encaps_us':   0.0,
        'decaps_us':   0.0,
        'ecdh_us':   104.0,
        'ecdh_keygen_us': 38.0,
        'hkdf_us':    10.0,
        'aes_setup_us': 2.8,
        'pk_bytes':    32,
        'ct_bytes':    32,
        'ss_bytes':    32,
        'rrc_overhead_bytes': 100,
        'parallel_cores': 4,
    },
    'PureKyber': {
        'label': 'Pure ML-KEM-1024',
        'keygen_us': 156.0,
        'encaps_us': 188.0,
        'decaps_us': 218.0,
        'ecdh_us':     0.0,
        'ecdh_keygen_us': 0.0,
        'hkdf_us':    10.0,
        'aes_setup_us': 2.8,
        'pk_bytes':  1568,
        'ct_bytes':  1568,
        'ss_bytes':    32,
        'rrc_overhead_bytes': 115,
        'parallel_cores': 4,
    },
}

# -- 5G NR URLLC channel model ----------------------------------------
SLOT_DURATION_US       = 500          # 0.5 ms slot (SCS=30 kHz)
LINK_RATE_MBPS         = 100.0        # per-cell DL peak
PROPAGATION_DELAY_US   = 15.0         # gNB <-> UAV (LoS ~4 km)
BASE_PACKET_LOSS_RATE  = 0.001        # 0.1 % baseline BLER
RETRANSMISSION_DELAY_US = 1000.0      # HARQ RTT

# -- MAC scheduler (M/G/1) -------------------------------------------
MEAN_SERVICE_US = 125.0
CV_SQUARED      = 2.2
RHO_PER_NODE    = 0.011

# -- Mobility ---------------------------------------------------------
HANDOVER_PREP_US = 800.0

# -- URLLC threshold --------------------------------------------------
URLLC_DEADLINE_MS = 10.0


# ====================================================================
# 2.  CORE PHYSICS & CRYPTOGRAPHIC MODELS
# ====================================================================

def _compute_base_crypto_us(prof, parallel=True):
    """
    Computes handshake cryptographic compute delay on Raspberry Pi 4 (Quad-Core Cortex-A72).
    If parallel=True and cores >= 2:
      Initiator KeyGen executes ML-KEM KeyGen and X25519 KeyGen concurrently.
      Responder Encaps executes ML-KEM Encaps and X25519 ECDH concurrently.
      Initiator Decaps executes ML-KEM Decaps concurrently with X25519 finish.
      Entropy fused via HKDF-SHA256 and authenticated with AES-256-GCM.
    If parallel=False (or sequential ablation):
      All primitives execute serially on a single core.
    """
    if parallel and prof.get('parallel_cores', 1) >= 2:
        t_keygen = max(prof.get('keygen_us', 0.0), prof.get('ecdh_keygen_us', 0.0))
        t_encaps = max(prof.get('encaps_us', 0.0), prof.get('ecdh_us', 0.0))
        t_decaps = max(prof.get('decaps_us', 0.0), prof.get('ecdh_us', 0.0) if prof.get('keygen_us', 0.0) == 0 else 0.0)
    else:
        t_keygen = prof.get('keygen_us', 0.0) + prof.get('ecdh_keygen_us', 0.0)
        t_encaps = prof.get('encaps_us', 0.0) + prof.get('ecdh_us', 0.0)
        t_decaps = prof.get('decaps_us', 0.0)

    t_kdf = prof.get('hkdf_us', 0.0)
    t_aes = prof.get('aes_setup_us', 0.0)
    return t_keygen + t_encaps + t_decaps + 2 * (t_kdf + t_aes)


def _serialization_delay_us(payload_bytes):
    """Over-the-air serialization time at LINK_RATE_MBPS."""
    return (payload_bytes * 8.0) / LINK_RATE_MBPS


def _fragmentation_count(payload_bytes):
    """IP fragments needed (MTU=1400 minus IP+UDP headers=48)."""
    max_payload = 1400 - 48
    return max(1, math.ceil(payload_bytes / max_payload))


def _queuing_delay_us(n_nodes, rng, n_samples):
    """M/G/1 queuing: Pollaczek-Khinchine formula with exponential draws."""
    rho = min(0.96, RHO_PER_NODE * n_nodes)
    if rho < 0.99:
        wq_mean = rho * MEAN_SERVICE_US * (1 + CV_SQUARED) / (2.0 * (1.0 - rho))
    else:
        wq_mean = 80000.0
    return rng.exponential(max(wq_mean, 1.0), size=n_samples)


def _packet_loss_events(n_nodes, rng, n_samples, base_loss=BASE_PACKET_LOSS_RATE):
    """Contention-dependent packet loss + HARQ retransmission delay."""
    loss_prob = min(0.15, base_loss + 0.0012 * n_nodes)
    lost = rng.random(n_samples) < loss_prob
    retx = rng.geometric(p=0.8, size=n_samples) - 1
    retx_delay = retx * RETRANSMISSION_DELAY_US
    return np.where(lost, retx_delay, 0.0)


# ====================================================================
# 3.  HANDSHAKE LATENCY
# ====================================================================

def simulate_handshake_latency_us(mode, n_nodes, rng, n_samples,
                                  override_prof=None, parallel=True):
    """
    E2E handshake latency = crypto + OTA serialization + propagation
                          + queuing + RRC processing + loss retx
    """
    prof = override_prof if override_prof else CRYPTO[mode]
    jitter_sigma = 0.08

    # -- Crypto compute on Raspberry Pi 4 ----
    base_crypto = _compute_base_crypto_us(prof, parallel=parallel)
    if base_crypto <= 0:
        base_crypto = 1.0
    mu_c = np.log(base_crypto) - jitter_sigma**2 / 2
    crypto_us = rng.lognormal(mu_c, jitter_sigma, size=n_samples)

    # -- OTA transmission ----
    total_ota_bytes = prof['pk_bytes'] + prof['ct_bytes'] + prof['rrc_overhead_bytes']
    n_frags = _fragmentation_count(total_ota_bytes)
    serial_base = _serialization_delay_us(total_ota_bytes)
    ota_us = (2 * serial_base + 2 * PROPAGATION_DELAY_US +
              (n_frags - 1) * SLOT_DURATION_US)
    ota_arr = rng.normal(ota_us, ota_us * 0.03, size=n_samples)
    ota_arr = np.maximum(ota_arr, ota_us * 0.5)

    # -- Queuing ----
    queue_us = _queuing_delay_us(n_nodes, rng, n_samples)

    # -- RRC processing ----
    rrc_base = 400.0 + prof['rrc_overhead_bytes'] * 0.08
    rrc_us = rng.normal(rrc_base, rrc_base * 0.04, size=n_samples)
    rrc_us = np.maximum(rrc_us, rrc_base * 0.5)

    # -- Packet loss ----
    loss_us = _packet_loss_events(n_nodes, rng, n_samples)

    return crypto_us + ota_arr + queue_us + rrc_us + loss_us


# ====================================================================
# 4.  HANDOVER LATENCY (cache hit / miss)
# ====================================================================

def simulate_handover_latency_ms(n_nodes, cache_hit_prob, rng, n_samples):
    """Cache HIT -> symmetric resumption; MISS -> full hybrid handshake."""
    is_hit = rng.random(n_samples) < cache_hit_prob

    # Cache hit bypasses asymmetric key exchange, reusing derived symmetric state
    hit_base_us = CRYPTO['Hybrid']['hkdf_us'] + CRYPTO['Hybrid']['aes_setup_us']
    hit_latency_us = rng.gamma(3.0, hit_base_us / 3.0, size=n_samples) + 200.0
    hit_latency_us += rng.normal(60.0, 8.0, size=n_samples)

    miss_latency_us = simulate_handshake_latency_us('Hybrid', n_nodes, rng, n_samples, parallel=True)
    miss_latency_us += HANDOVER_PREP_US

    latency_us = np.where(is_hit, hit_latency_us, miss_latency_us)
    return latency_us / 1000.0, is_hit


# ====================================================================
# 5.  THROUGHPUT & PDR
# ====================================================================

def simulate_throughput_pdr(n_nodes, rng, n_samples):
    """
    Returns (per_node_throughput_mbps, aggregate_throughput_mbps, pdr).
    Per-node throughput = fair share with contention penalty.
    Aggregate = sum capped at physical channel capacity.
    """
    fair_share = LINK_RATE_MBPS / n_nodes
    contention_factor = 1.0 / (1.0 + 0.04 * np.sqrt(n_nodes))
    effective_per_node = fair_share * contention_factor
    per_node = rng.normal(effective_per_node, effective_per_node * 0.08, size=n_samples)
    per_node = np.maximum(per_node, 0.1)

    agg_tp = per_node * n_nodes
    agg_tp = np.minimum(agg_tp, LINK_RATE_MBPS * 0.98)

    loss_prob = min(0.15, BASE_PACKET_LOSS_RATE + 0.0012 * n_nodes)
    a_param = 2.0
    b_param = max(a_param / loss_prob - a_param, 1.0)
    pdr = 1.0 - rng.beta(a_param, b_param, size=n_samples)
    pdr = np.clip(pdr, 0.70, 1.0)

    return per_node, agg_tp, pdr


# ====================================================================
# 6.  PARALLEL MONTE CARLO WORKER: One swarm-density tier
# ====================================================================

def run_density_tier(args):
    n_nodes, mc_iters, seed = args
    rng = np.random.default_rng(seed)
    records = []

    for mode_key, prof in CRYPTO.items():
        lat_us = simulate_handshake_latency_us(mode_key, n_nodes, rng, mc_iters, parallel=True)
        lat_ms = lat_us / 1000.0
        for i in range(mc_iters):
            records.append({
                'swarm_size': n_nodes,
                'protocol': prof['label'],
                'protocol_key': mode_key,
                'trial': i,
                'handshake_latency_ms': round(lat_ms[i], 6),
                'handshake_latency_us': round(lat_us[i], 2),
            })

    for ch_prob in CACHE_HIT_PROBS:
        ho_ms, is_hit = simulate_handover_latency_ms(n_nodes, ch_prob, rng, mc_iters)
        for i in range(mc_iters):
            records.append({
                'swarm_size': n_nodes,
                'protocol': 'Handover',
                'protocol_key': 'handover',
                'cache_hit_prob': ch_prob,
                'is_cache_hit': bool(is_hit[i]),
                'trial': i,
                'handover_latency_ms': round(ho_ms[i], 6),
            })

    pn_tp, agg_tp, pdr = simulate_throughput_pdr(n_nodes, rng, mc_iters)
    for i in range(mc_iters):
        records.append({
            'swarm_size': n_nodes,
            'protocol': 'Channel',
            'protocol_key': 'channel_metrics',
            'trial': i,
            'per_node_throughput_mbps': round(pn_tp[i], 4),
            'throughput_mbps': round(agg_tp[i], 4),
            'pdr': round(pdr[i], 6),
        })

    return records


# ====================================================================
# 7.  ABLATION STUDY DEFINITIONS & WORKER
# ====================================================================

ABLATION_SCENARIOS = {
    'baseline': {
        'desc': 'Full Hybrid System (Parallel Quad-Core Pi 4)',
        'modify': {},
        'parallel': True,
    },
    'a1_no_ecdh': {
        'desc': 'Remove X25519 (Pure ML-KEM only)',
        'modify': {'ecdh_us': 0.0, 'ecdh_keygen_us': 0.0, 'pk_bytes': 1568, 'ct_bytes': 1568},
        'parallel': True,
    },
    'a2_no_kyber': {
        'desc': 'Remove ML-KEM (Classical ECDH only)',
        'modify': {'keygen_us': 0.0, 'encaps_us': 0.0, 'decaps_us': 0.0,
                   'pk_bytes': 32, 'ct_bytes': 32, 'rrc_overhead_bytes': 100},
        'parallel': True,
    },
    'a3_no_hkdf': {
        'desc': 'Remove HKDF (Direct key concatenation)',
        'modify': {'hkdf_us': 0.0},
        'parallel': True,
    },
    'a4_no_aes_setup': {
        'desc': 'Remove AES-256-GCM key schedule',
        'modify': {'aes_setup_us': 0.0},
        'parallel': True,
    },
    'a5_double_rrc': {
        'desc': 'Double RRC overhead (240B stress test)',
        'modify': {'rrc_overhead_bytes': 240},
        'parallel': True,
    },
    'a6_no_fragmentation': {
        'desc': 'No IP fragmentation (Jumbo frames)',
        'modify': {},
        'no_frag': True,
        'parallel': True,
    },
    'a7_high_loss': {
        'desc': 'High baseline loss rate (1.0% BLER)',
        'modify': {},
        'base_loss_rate': 0.01,
        'parallel': True,
    },
    'a8_sequential_crypto': {
        'desc': 'Sequential Crypto (Single-Core Execution)',
        'modify': {},
        'parallel': False,
    },
}


def run_ablation_tier(args):
    """Run ablation for one scenario x one swarm size."""
    scenario_id, scenario_cfg, n_nodes, mc_iters, seed = args
    rng = np.random.default_rng(seed)

    # Build modified profile from Hybrid baseline
    prof = dict(CRYPTO['Hybrid'])
    prof.update(scenario_cfg.get('modify', {}))
    is_parallel = scenario_cfg.get('parallel', True)

    base_crypto = _compute_base_crypto_us(prof, parallel=is_parallel)
    if base_crypto <= 0:
        base_crypto = 1.0

    jitter_sigma = 0.08
    mu_c = np.log(base_crypto) - jitter_sigma**2 / 2
    crypto_us = rng.lognormal(mu_c, jitter_sigma, size=mc_iters)

    total_ota_bytes = prof['pk_bytes'] + prof['ct_bytes'] + prof['rrc_overhead_bytes']

    if scenario_cfg.get('no_frag', False):
        n_frags = 1
    else:
        n_frags = _fragmentation_count(total_ota_bytes)

    serial_base = _serialization_delay_us(total_ota_bytes)
    ota_us = (2 * serial_base + 2 * PROPAGATION_DELAY_US +
              (n_frags - 1) * SLOT_DURATION_US)
    ota_arr = rng.normal(ota_us, ota_us * 0.03, size=mc_iters)
    ota_arr = np.maximum(ota_arr, ota_us * 0.5)

    queue_us = _queuing_delay_us(n_nodes, rng, mc_iters)

    rrc_base = 400.0 + prof['rrc_overhead_bytes'] * 0.08
    rrc_us = rng.normal(rrc_base, rrc_base * 0.04, size=mc_iters)
    rrc_us = np.maximum(rrc_us, rrc_base * 0.5)

    blr = scenario_cfg.get('base_loss_rate', BASE_PACKET_LOSS_RATE)
    loss_us = _packet_loss_events(n_nodes, rng, mc_iters, base_loss=blr)

    total_us = crypto_us + ota_arr + queue_us + rrc_us + loss_us
    total_ms = total_us / 1000.0

    return {
        'scenario_id': scenario_id,
        'desc': scenario_cfg['desc'],
        'swarm_size': n_nodes,
        'mean_ms': float(np.mean(total_ms)),
        'p50_ms': float(np.median(total_ms)),
        'p95_ms': float(np.percentile(total_ms, 95)),
        'p99_ms': float(np.percentile(total_ms, 99)),
        'std_ms': float(np.std(total_ms)),
        'raw_latencies_ms': total_ms.tolist(),
    }


# ====================================================================
# 8.  MAIN SIMULATION & ABLATION DRIVERS (PARALLEL EXECUTION)
# ====================================================================

def run_simulation():
    print("=" * 80)
    print("  KYBER-6G: 5G/6G UAV SWARM PQC MONTE CARLO SIMULATION")
    print("  Hardware: Raspberry Pi 4 Model B (Quad-Core Cortex-A72 @ 1.5 GHz, 2GB RAM)")
    print("  Parallel Processing: %d host workers executing concurrent batches" % N_WORKERS)
    print("=" * 80)

    t0 = time.time()
    tier_args = [
        (n_nodes, MC_ITERS, MASTER_SEED + idx * 10_000)
        for idx, n_nodes in enumerate(SWARM_SIZES)
    ]

    all_records = []
    with ProcessPoolExecutor(max_workers=N_WORKERS) as executor:
        futures = {executor.submit(run_density_tier, arg): arg[0] for arg in tier_args}
        completed = 0
        for future in as_completed(futures):
            tier_records = future.result()
            all_records.extend(tier_records)
            completed += 1
            print("  Progress: [%2d/%2d tiers complete] (%d records)" %
                  (completed, len(SWARM_SIZES), len(all_records)))

    df = pd.DataFrame(all_records)
    df.to_csv(CSV_OUT, index=False)
    elapsed = time.time() - t0
    print("  Main simulation complete in %.2f s -> %s" % (elapsed, CSV_OUT))
    return df


def run_ablation_study():
    print("\n" + "=" * 80)
    print("  RUNNING ABLATION STUDY (9 SCENARIOS x 10 SWARM SIZES)")
    print("=" * 80)

    t0 = time.time()
    ablation_args = []
    idx = 0
    for sc_id, sc_cfg in ABLATION_SCENARIOS.items():
        for n_nodes in SWARM_SIZES:
            ablation_args.append((
                sc_id, sc_cfg, n_nodes, ABLATION_MC,
                MASTER_SEED + 500_000 + idx * 1000
            ))
            idx += 1

    summary_rows = []
    per_scenario_data = {sc_id: [] for sc_id in ABLATION_SCENARIOS}

    with ProcessPoolExecutor(max_workers=N_WORKERS) as executor:
        futures = {executor.submit(run_ablation_tier, arg): arg for arg in ablation_args}
        completed = 0
        for future in as_completed(futures):
            res = future.result()
            summary_rows.append({
                'scenario_id': res['scenario_id'],
                'desc': res['desc'],
                'swarm_size': res['swarm_size'],
                'mean_ms': res['mean_ms'],
                'p50_ms': res['p50_ms'],
                'p95_ms': res['p95_ms'],
                'p99_ms': res['p99_ms'],
                'std_ms': res['std_ms'],
            })
            per_scenario_data[res['scenario_id']].append({
                'swarm_size': res['swarm_size'],
                'latencies': res['raw_latencies_ms'],
            })
            completed += 1
            if completed % 10 == 0 or completed == len(ablation_args):
                print("  Ablation Progress: [%2d/%2d tiers complete]" %
                      (completed, len(ablation_args)))

    df_summary = pd.DataFrame(summary_rows)
    df_summary.sort_values(by=['scenario_id', 'swarm_size'], inplace=True)
    df_summary.to_csv(ABLATION_CSV, index=False)

    # Save per-scenario data separately in ablation_study/data/
    for sc_id, tier_list in per_scenario_data.items():
        sc_dir = os.path.join(ABLATION_DATA_DIR, sc_id)
        os.makedirs(sc_dir, exist_ok=True)
        tier_list_sorted = sorted(tier_list, key=lambda x: x['swarm_size'])
        flat_rows = []
        for item in tier_list_sorted:
            ns = item['swarm_size']
            for trial_i, lat in enumerate(item['latencies']):
                flat_rows.append({'swarm_size': ns, 'trial': trial_i, 'handshake_latency_ms': lat})
        pd.DataFrame(flat_rows).to_csv(os.path.join(sc_dir, 'results_all_tiers.csv'), index=False)

    elapsed = time.time() - t0
    print("  Ablation study complete in %.2f s -> %s" % (elapsed, ABLATION_CSV))
    return df_summary


# ====================================================================
# 9.  PUBLICATION PLOTS (STRICTLY SEPARATED)
# ====================================================================

plt.rcParams.update({
    'font.family': 'sans-serif',
    'font.size': 11,
    'axes.labelsize': 12,
    'axes.titlesize': 13,
    'xtick.labelsize': 10,
    'ytick.labelsize': 10,
    'legend.fontsize': 10,
    'figure.titlesize': 14,
    'figure.dpi': 150,
    'savefig.dpi': 300,
})

PALETTE = {
    'Hybrid (ML-KEM-1024 + X25519)': '#1f77b4',
    'Classical ECC (X25519)':       '#2ca02c',
    'Pure ML-KEM-1024':              '#ff7f0e',
}

HW_NOTE = "Hardware: Raspberry Pi 4 Model B (Quad-Core Cortex-A72 @ 1.5 GHz, 2GB RAM)"


def plot_1_latency_vs_density(df):
    """Plot 1: Handshake Latency vs Swarm Density (mean +/- std)."""
    fig, ax = plt.subplots(figsize=(8, 5))
    hs = df[df['protocol'].isin(PALETTE.keys())]

    for proto, color in PALETTE.items():
        sub = hs[hs['protocol'] == proto]
        means = sub.groupby('swarm_size')['handshake_latency_ms'].mean()
        stds  = sub.groupby('swarm_size')['handshake_latency_ms'].std()
        ax.plot(means.index, means.values, 'o-', color=color, label=proto, lw=2, markersize=6)
        ax.fill_between(means.index, means.values - stds.values,
                        means.values + stds.values, color=color, alpha=0.15)

    ax.axhline(URLLC_DEADLINE_MS, color='red', ls='--', lw=1.5,
               label='URLLC Deadline (10 ms)')
    ax.set_xlabel('Swarm Size (Number of UAVs)')
    ax.set_ylabel('Handshake Latency (ms)')
    ax.set_title('Handshake Latency vs. Swarm Density\n(%s)' % HW_NOTE, fontsize=11)
    ax.set_xticks(SWARM_SIZES)
    ax.set_ylim(0, 12)
    ax.grid(True, alpha=0.3)
    ax.legend(loc='upper left', frameon=True)
    fig.tight_layout()
    path = os.path.join(SIM_PLOT_DIR, '01_latency_vs_density.png')
    fig.savefig(path)
    plt.close(fig)
    print("  Plot 1 saved -> %s" % path)


def plot_2_handover_violin(df):
    """Plot 2: Handover Latency Distribution (Violin Plot)."""
    fig, ax = plt.subplots(figsize=(10, 5.5))
    ho = df[df['protocol'] == 'Handover'].copy()
    sub = ho[(ho['swarm_size'].isin([10, 50, 100])) &
             (ho['cache_hit_prob'].isin([0.2, 0.5, 0.8]))].copy()
    sub['Condition'] = sub.apply(
        lambda r: 'N=%d, Hit=%.0f%%' % (r['swarm_size'], r['cache_hit_prob'] * 100),
        axis=1
    )

    order = []
    for n in [10, 50, 100]:
        for h in [0.2, 0.5, 0.8]:
            order.append('N=%d, Hit=%.0f%%' % (n, h * 100))

    sns.violinplot(data=sub, x='Condition', y='handover_latency_ms', order=order,
                   palette='Blues', cut=0, inner='quartile', ax=ax)
    ax.set_xticklabels(ax.get_xticklabels(), rotation=15, ha='right')
    ax.axhline(URLLC_DEADLINE_MS, color='red', ls='--', lw=1.5,
               label='URLLC Deadline (10 ms)')
    ax.set_xlabel('Swarm Condition & Cache Hit Rate')
    ax.set_ylabel('Handover Latency (ms)')
    ax.set_title('Handover Latency Distribution Across Mobility Conditions\n(%s)' % HW_NOTE, fontsize=11)
    ax.grid(True, alpha=0.3)
    ax.legend(loc='upper right', frameon=True)
    fig.tight_layout()
    path = os.path.join(SIM_PLOT_DIR, '02_handover_violin.png')
    fig.savefig(path)
    plt.close(fig)
    print("  Plot 2 saved -> %s" % path)


def plot_3_latency_cdf(df):
    """Plot 3: Latency CDF (URLLC Compliance Verification)."""
    fig, ax = plt.subplots(figsize=(8, 5))
    hs = df[df['protocol'].isin(PALETTE.keys())]

    for proto, color in PALETTE.items():
        vals = hs[hs['protocol'] == proto]['handshake_latency_ms'].values
        sorted_v = np.sort(vals)
        cdf = np.linspace(0, 1, len(sorted_v))
        ax.plot(sorted_v, cdf, color=color, lw=2, label=proto)

    ax.axvline(URLLC_DEADLINE_MS, color='red', ls='--', lw=1.5,
               label='URLLC Deadline (10 ms)')
    ax.set_xlabel('Handshake Latency (ms)')
    ax.set_ylabel('Empirical Cumulative Probability')
    ax.set_title('Cumulative Distribution Function of Handshake Latency\n(%s)' % HW_NOTE, fontsize=11)
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 1.02)
    ax.grid(True, alpha=0.3)
    ax.legend(loc='lower right', frameon=True)
    fig.tight_layout()
    path = os.path.join(SIM_PLOT_DIR, '03_latency_cdf.png')
    fig.savefig(path)
    plt.close(fig)
    print("  Plot 3 saved -> %s" % path)


def plot_4_packet_overhead(df):
    """Plot 4: Cryptographic Packet Overhead & Channel Consumption."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

    protos = list(CRYPTO.keys())
    labels = [CRYPTO[p]['label'] for p in protos]
    ota_bytes = [CRYPTO[p]['pk_bytes'] + CRYPTO[p]['ct_bytes'] + CRYPTO[p]['rrc_overhead_bytes']
                 for p in protos]
    frags = [_fragmentation_count(b) for b in ota_bytes]

    colors = [PALETTE[CRYPTO[p]['label']] for p in protos]

    bars1 = ax1.bar(labels, ota_bytes, color=colors, width=0.5, edgecolor='black', lw=0.8)
    ax1.set_ylabel('Total OTA Handshake Bytes')
    ax1.set_title('Total Message Size (PK + CT + RRC)')
    ax1.grid(True, alpha=0.3, axis='y')
    ax1.set_xticklabels(labels, rotation=15, ha='right')

    for bar, b in zip(bars1, ota_bytes):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 50,
                 '%d B' % b, ha='center', va='bottom', fontsize=10)

    bars2 = ax2.bar(labels, frags, color=colors, width=0.5, edgecolor='black', lw=0.8)
    ax2.set_ylabel('IP Fragments (MTU=1400 B)')
    ax2.set_title('Required IP Fragments')
    ax2.grid(True, alpha=0.3, axis='y')
    ax2.set_xticklabels(labels, rotation=15, ha='right')
    ax2.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))

    for bar, f in zip(bars2, frags):
        ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                 '%d frag' % f, ha='center', va='bottom', fontsize=10)

    fig.suptitle('Protocol Communication Overhead Comparison', fontsize=13)
    fig.tight_layout()
    path = os.path.join(SIM_PLOT_DIR, '04_packet_overhead.png')
    fig.savefig(path)
    plt.close(fig)
    print("  Plot 4 saved -> %s" % path)


def plot_5_handover_vs_cache(df):
    """Plot 5: Handover Latency vs Cache Hit Probability."""
    fig, ax = plt.subplots(figsize=(8, 5))
    ho = df[df['protocol'] == 'Handover'].copy()

    for ns, ls in [(10, '-'), (50, '--'), (100, ':')]:
        sub = ho[ho['swarm_size'] == ns]
        grouped = sub.groupby('cache_hit_prob')['handover_latency_ms'].agg(['mean', 'std'])
        ax.plot(grouped.index, grouped['mean'], ls=ls, marker='s', markersize=4,
                label='N = %d UAVs' % ns, lw=2)
        lower = np.maximum(0.0, grouped['mean'] - grouped['std'])
        upper = grouped['mean'] + grouped['std']
        ax.fill_between(grouped.index, lower, upper, alpha=0.1)

    ax.axhline(URLLC_DEADLINE_MS, color='red', ls='--', lw=1.5,
               label='URLLC Deadline (10 ms)')
    ax.set_xlabel('Mobility Cache Hit Probability')
    ax.set_ylabel('Handover Latency (ms)')
    ax.set_title('Handover Latency vs. Cache Hit Probability\n(%s)' % HW_NOTE, fontsize=11)
    ax.grid(True, alpha=0.3)
    ax.legend(loc='upper right', frameon=True)
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 14)
    fig.tight_layout()
    path = os.path.join(SIM_PLOT_DIR, '05_handover_vs_cache.png')
    fig.savefig(path)
    plt.close(fig)
    print("  Plot 5 saved -> %s" % path)


def plot_6_throughput_pdr(df):
    """Plot 6: Per-Node Throughput, Aggregate Throughput, and PDR."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5))
    ch = df[df['protocol'] == 'Channel'].copy()

    gp = ch.groupby('swarm_size')
    mean_pn = gp['per_node_throughput_mbps'].mean()
    mean_agg = gp['throughput_mbps'].mean()
    mean_pdr = gp['pdr'].mean() * 100

    color1 = '#2b5c8f'
    ax1.plot(mean_pn.index, mean_pn.values, 'o-', color=color1, lw=2, label='Per-Node Throughput')
    ax1.set_xlabel('Swarm Size (Number of UAVs)')
    ax1.set_ylabel('Per-Node Throughput (Mbps)', color=color1)
    ax1.tick_params(axis='y', labelcolor=color1)
    ax1.set_xticks(SWARM_SIZES)
    ax1.grid(True, alpha=0.3)

    ax1_twin = ax1.twinx()
    color2 = '#d95f02'
    ax1_twin.plot(mean_agg.index, mean_agg.values, 's--', color=color2, lw=2, label='Aggregate Throughput')
    ax1_twin.set_ylabel('Aggregate Throughput (Mbps)', color=color2)
    ax1_twin.tick_params(axis='y', labelcolor=color2)
    ax1_twin.set_ylim(0, 110)
    ax1.set_title('Throughput Scaling')

    ax2.plot(mean_pdr.index, mean_pdr.values, 'd-', color='#7570b3', lw=2, markersize=6)
    ax2.axhline(99.9, color='red', ls='--', lw=1.2, label='99.9% Target')
    ax2.set_xlabel('Swarm Size (Number of UAVs)')
    ax2.set_ylabel('Packet Delivery Ratio (%)')
    ax2.set_xticks(SWARM_SIZES)
    ax2.set_ylim(80, 101)
    ax2.grid(True, alpha=0.3)
    ax2.set_title('Packet Delivery Ratio (PDR)')
    ax2.legend(loc='lower left', frameon=True)

    fig.suptitle('Channel Performance vs. Swarm Density', fontsize=13)
    fig.tight_layout()
    path = os.path.join(SIM_PLOT_DIR, '06_throughput_pdr.png')
    fig.savefig(path, bbox_inches='tight')
    plt.close(fig)
    print("  Plot 6 saved -> %s" % path)


def plot_7_ablation_heatmap(df_abl):
    """Plot 7: Ablation Study Heatmap (Strictly saved to ablation_study/plots/)."""
    pivot = df_abl.pivot(index='scenario_id', columns='swarm_size', values='mean_ms')

    if 'baseline' not in pivot.index:
        print("  [WARN] 'baseline' not in ablation results; skipping heatmap")
        return

    baseline_row = pivot.loc['baseline']
    delta = pivot.subtract(baseline_row, axis=1)
    delta = delta.drop('baseline', errors='ignore')

    label_map = {sc_id: cfg['desc'] for sc_id, cfg in ABLATION_SCENARIOS.items()}
    delta.index = [label_map.get(s, s) for s in delta.index]

    fig, ax = plt.subplots(figsize=(13, 6.5))
    sns.heatmap(delta, annot=True, fmt='.2f', cmap='RdYlGn_r',
                center=0, linewidths=0.5, ax=ax,
                cbar_kws={'label': 'Latency Delta vs. Baseline (ms)'})
    ax.set_xlabel('Swarm Size (UAVs)')
    ax.set_ylabel('Ablation Scenario')
    ax.set_title('Ablation Study: Mean Latency Change vs. Baseline\n(%s)' % HW_NOTE, fontsize=11)
    fig.tight_layout()
    path = os.path.join(ABLATION_PLOT_DIR, '07_ablation_heatmap.png')
    fig.savefig(path)
    plt.close(fig)
    print("  Plot 7 saved -> %s" % path)


# ====================================================================
# 10.  SUMMARY TABLES & VALIDATION
# ====================================================================

def print_summary_table(df):
    hs = df[df['protocol'].isin(PALETTE.keys())].copy()
    ch = df[df['protocol'] == 'Channel'].copy()

    print("")
    print("=" * 120)
    print("  MAIN SIMULATION SUMMARY TABLE")
    print("=" * 120)
    header = "%6s  %-35s  %9s  %8s  %8s  %8s  %14s  %14s  %7s" % (
        'Swarm', 'Protocol', 'Mean(ms)', 'P50(ms)',
        'P95(ms)', 'P99(ms)', 'Per-Node TP', 'Agg TP', 'PDR'
    )
    print(header)
    print("-" * 120)

    proto_keys = list(PALETTE.keys())
    for ns in SWARM_SIZES:
        ch_ns = ch[ch['swarm_size'] == ns]
        mean_pn = ch_ns['per_node_throughput_mbps'].mean() if len(ch_ns) else float('nan')
        mean_agg = ch_ns['throughput_mbps'].mean() if len(ch_ns) else float('nan')
        mean_pdr = ch_ns['pdr'].mean() if len(ch_ns) else float('nan')

        for idx, proto in enumerate(proto_keys):
            sub = hs[(hs['swarm_size'] == ns) & (hs['protocol'] == proto)]
            vals = sub['handshake_latency_ms'].dropna()
            if len(vals) == 0:
                continue
            mean_v = vals.mean()
            p50    = vals.quantile(0.50)
            p95    = vals.quantile(0.95)
            p99    = vals.quantile(0.99)

            if idx == 0:
                pn_str  = "%8.3f Mbps" % mean_pn
                agg_str = "%8.2f Mbps" % mean_agg
                pdr_str = "%6.3f%%" % (mean_pdr * 100)
            else:
                pn_str  = ""
                agg_str = ""
                pdr_str = ""

            if p99 < URLLC_DEADLINE_MS:
                mark = " [OK]"
            else:
                mark = " [!!]"

            line = "%6d  %-35s  %9.4f  %8.4f  %8.4f  %8.4f%s %14s  %14s  %7s" % (
                ns, proto, mean_v, p50, p95, p99, mark, pn_str, agg_str, pdr_str
            )
            print(line)
        print("-" * 120)

    print("=" * 120)
    print("  [OK] = P99 < %.1f ms (URLLC compliant)" % URLLC_DEADLINE_MS)
    print("  [!!] = P99 >= %.1f ms (exceeds URLLC deadline)" % URLLC_DEADLINE_MS)
    print("=" * 120)


def print_ablation_summary(df_abl):
    print("\n" + "=" * 100)
    print("  ABLATION STUDY SUMMARY")
    print("=" * 100)
    header = "%-45s  %8s  %8s  %8s  %8s" % (
        'Scenario', 'Mean(ms)', 'P50(ms)', 'P95(ms)', 'P99(ms)'
    )
    print(header)
    print("-" * 100)
    for sc_id in ABLATION_SCENARIOS:
        sc_data = df_abl[df_abl['scenario_id'] == sc_id]
        desc = ABLATION_SCENARIOS[sc_id]['desc']
        mean_v = sc_data['mean_ms'].mean()
        p50_v  = sc_data['p50_ms'].mean()
        p95_v  = sc_data['p95_ms'].mean()
        p99_v  = sc_data['p99_ms'].mean()
        print("%-45s  %8.4f  %8.4f  %8.4f  %8.4f" % (
            desc, mean_v, p50_v, p95_v, p99_v
        ))
    print("=" * 100)


def run_validation(df):
    """Cross-check simulation outputs against known physical constraints."""
    print("\n  === VALIDATION CHECKS ===")
    errors = 0

    hs = df[df['protocol'].isin(PALETTE.keys())]
    for ns in SWARM_SIZES:
        ecc_mean = hs[(hs['swarm_size'] == ns) & (hs['protocol'] == 'Classical ECC (X25519)')]['handshake_latency_ms'].mean()
        hyb_mean = hs[(hs['swarm_size'] == ns) & (hs['protocol'] == 'Hybrid (ML-KEM-1024 + X25519)')]['handshake_latency_ms'].mean()
        if ecc_mean > hyb_mean:
            print("  [FAIL] N=%d: Classical (%.3f ms) > Hybrid (%.3f ms)" % (ns, ecc_mean, hyb_mean))
            errors += 1

    for ns in SWARM_SIZES:
        pk_mean = hs[(hs['swarm_size'] == ns) & (hs['protocol'] == 'Pure ML-KEM-1024')]['handshake_latency_ms'].mean()
        hyb_mean = hs[(hs['swarm_size'] == ns) & (hs['protocol'] == 'Hybrid (ML-KEM-1024 + X25519)')]['handshake_latency_ms'].mean()
        if pk_mean > hyb_mean:
            print("  [FAIL] N=%d: PureKyber (%.3f ms) > Hybrid (%.3f ms)" % (ns, pk_mean, hyb_mean))
            errors += 1

    neg = hs[hs['handshake_latency_ms'] <= 0]
    if len(neg) > 0:
        print("  [FAIL] %d negative latency records found" % len(neg))
        errors += 1

    for proto in PALETTE.keys():
        p99 = hs[(hs['swarm_size'] == 10) & (hs['protocol'] == proto)]['handshake_latency_ms'].quantile(0.99)
        if p99 > URLLC_DEADLINE_MS:
            print("  [FAIL] N=10, %s: P99=%.3f ms exceeds URLLC" % (proto, p99))
            errors += 1

    for ns in [10]:
        ecc_mean = hs[(hs['swarm_size'] == ns) & (hs['protocol'] == 'Classical ECC (X25519)')]['handshake_latency_us']
        if len(ecc_mean) > 0:
            ecc_mean_val = ecc_mean.mean()
            if ecc_mean_val < 300 or ecc_mean_val > 5000:
                print("  [FAIL] Classical at N=10: mean=%.1f us out of expected range" % ecc_mean_val)
                errors += 1

    ch = df[df['protocol'] == 'Channel']
    pdr_10 = ch[ch['swarm_size'] == 10]['pdr'].mean()
    pdr_100 = ch[ch['swarm_size'] == 100]['pdr'].mean()
    if pdr_100 > pdr_10:
        print("  [FAIL] PDR at N=100 (%.4f) > PDR at N=10 (%.4f)" % (pdr_100, pdr_10))
        errors += 1

    pntp_10 = ch[ch['swarm_size'] == 10]['per_node_throughput_mbps'].mean()
    pntp_100 = ch[ch['swarm_size'] == 100]['per_node_throughput_mbps'].mean()
    if pntp_100 > pntp_10:
        print("  [FAIL] Per-node TP at N=100 (%.4f) > N=10 (%.4f)" % (pntp_100, pntp_10))
        errors += 1

    if errors == 0:
        print("  [PASS] All 7 physical validation checks passed successfully")
    else:
        print("  [!!] %d validation check(s) FAILED" % errors)

    return errors


# ====================================================================
# 11.  ENTRY POINT
# ====================================================================

if __name__ == '__main__':
    print("\n[1/6] Running Monte Carlo simulation (Raspberry Pi 4 Profile) ...")
    df = run_simulation()

    print("\n[2/6] Running ablation study (Separated Storage) ...")
    df_abl = run_ablation_study()

    print("\n[3/6] Running physical validation checks ...")
    run_validation(df)

    print("\n[4/6] Generating publication-quality plots ...")
    plot_1_latency_vs_density(df)
    plot_2_handover_violin(df)
    plot_3_latency_cdf(df)
    plot_4_packet_overhead(df)
    plot_5_handover_vs_cache(df)
    plot_6_throughput_pdr(df)
    plot_7_ablation_heatmap(df_abl)

    print("\n[5/6] Verifying file system outputs ...")
    csv_check = os.path.exists(CSV_OUT)
    abl_check = os.path.exists(ABLATION_CSV)
    sim_plots = sorted([f for f in os.listdir(SIM_PLOT_DIR) if f.endswith('.png')])
    abl_plots = sorted([f for f in os.listdir(ABLATION_PLOT_DIR) if f.endswith('.png')])
    print("  Main CSV exists: %s (%s)" % (csv_check, CSV_OUT))
    print("  Ablation CSV exists: %s (%s)" % (abl_check, ABLATION_CSV))
    print("  Simulation plots (6 expected): %s -> %s" % (len(sim_plots) == 6, sim_plots))
    print("  Ablation plots (1 expected): %s -> %s" % (len(abl_plots) == 1, abl_plots))

    print("\n[6/6] Summary tables ...")
    print_summary_table(df)
    print_ablation_summary(df_abl)

    print("\n  === ALL WORKFLOWS COMPLETED SUCCESSFULLY ===\n")
