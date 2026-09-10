#!/usr/bin/env python3
"""
Algorithm 4: MGS-MRPMC Signal Detection for Massive MIMO
Mixed Gibbs Sampling Multiple Random Parallel Markov Chains
"""

import numpy as np
import time

def generate_uncorrelated_markov_chains(K, N_t):
    # Generates K random permutation chains for Gibbs sampling order
    chains = []
    for _ in range(K):
        chains.append(np.random.permutation(N_t))
    return chains

def compute_ml_cost(y, H, x):
    # Maximum Likelihood cost ||y - Hx||^2
    err = y - np.dot(H, x)
    return np.linalg.norm(err)**2

def mgs_mrpmc_signal_detection(y, H, QAM_order, N_t, max_iter=100, q_mix=0.1):
    # Symbol alphabet for PAM (assuming real decomposition of QAM)
    # E.g., for 16-QAM (4-PAM per dimension), symbols are {-3, -1, 1, 3}
    M_sqrt = int(np.sqrt(QAM_order))
    symbols = np.array([2*i - (M_sqrt - 1) for i in range(M_sqrt)])
    
    K = max(1, int(QAM_order * np.sqrt(N_t) / 4)) # Parallel chains
    chains = generate_uncorrelated_markov_chains(K, N_t)
    candidate_solutions = []
    
    max_stalling_limit = max_iter

    # Parallel Markov Chain Execution
    for k in range(K):
        # Initialize with random symbols
        x_k = np.random.choice(symbols, size=N_t)
        stalling_count = 0
        
        while stalling_count < max_stalling_limit:
            for symbol_idx in chains[k]:
                if np.random.uniform(0, 1) < q_mix:
                    # Random Uniform Sampling
                    x_k[symbol_idx] = np.random.choice(symbols)
                else:
                    # Gibbs Conditional Sampling
                    costs = []
                    for s in symbols:
                        x_temp = x_k.copy()
                        x_temp[symbol_idx] = s
                        costs.append(compute_ml_cost(y, H, x_temp))
                    
                    # Convert costs to probabilities (Gibbs distribution)
                    costs = np.array(costs)
                    probs = np.exp(-costs / (2.0)) # simplified temperature
                    probs /= np.sum(probs)
                    
                    x_k[symbol_idx] = np.random.choice(symbols, p=probs)
            
            stalling_count += 1
            
        candidate_solutions.append((compute_ml_cost(y, H, x_k), x_k))
        
    # Select Candidate with Minimum ML Cost
    candidate_solutions.sort(key=lambda item: item[0])
    best_cost, hat_x_opt = candidate_solutions[0]
    return hat_x_opt, best_cost

def run_simulation():
    print("Running MGS-MRPMC Signal Detection Simulation...")
    # Parameters for a massive MIMO system
    N_r = 64  # Receive antennas (Real domain -> 128)
    N_t = 16  # Transmit antennas (Real domain -> 32)
    QAM_order = 16
    
    # Real-valued equivalent channel model
    N_r_real = 2 * N_r
    N_t_real = 2 * N_t
    
    H = np.random.randn(N_r_real, N_t_real) / np.sqrt(N_r_real)
    
    M_sqrt = int(np.sqrt(QAM_order))
    symbols = np.array([2*i - (M_sqrt - 1) for i in range(M_sqrt)])
    
    # True transmitted vector
    x_true = np.random.choice(symbols, size=N_t_real)
    
    # Additive White Gaussian Noise
    SNR_dB = 15
    noise_var = 10**(-SNR_dB/10.0)
    noise = np.sqrt(noise_var) * np.random.randn(N_r_real)
    
    # Received signal
    y = np.dot(H, x_true) + noise
    
    start_time = time.time()
    x_est, cost = mgs_mrpmc_signal_detection(y, H, QAM_order, N_t_real, max_iter=50, q_mix=0.05)
    end_time = time.time()
    
    # Calculate Symbol Error Rate (SER)
    ser = np.sum(x_true != x_est) / N_t_real
    
    print(f"Simulation completed in {end_time - start_time:.4f} seconds.")
    print(f"Optimal ML Cost: {cost:.4f}")
    print(f"Symbol Error Rate (SER): {ser:.4f}")

if __name__ == "__main__":
    run_simulation()
