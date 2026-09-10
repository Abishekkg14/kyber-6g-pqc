import os
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

def generate_queueing_plot():
    # Setup
    out_dir = "figures_rerun/queueing"
    os.makedirs(out_dir, exist_ok=True)
    sns.set_theme(style="whitegrid")
    plt.rcParams.update({'font.size': 12, 'font.family': 'serif'})

    # Range of traffic intensity rho
    rho = np.linspace(0.1, 0.95, 100)
    
    # M/M/1 Queueing Delay: W_q = (rho * E[S]) / (1 - rho)
    # E[S] = Mean service time. Let's say E[S] = 1.5 ms
    mean_S = 1.5
    Wq_mm1 = (rho * mean_S) / (1 - rho)
    
    # M/G/1 Pollaczek-Khinchine Queueing Delay: 
    # W_q = rho * E[S] * (1 + C_v^2) / (2 * (1 - rho))
    # where C_v = coefficient of variation = std_dev / mean
    # For bimodal micro-bursts of PQC, C_v is large. Let's say C_v^2 = 5.0
    cv_squared = 2.2  # Realistic for PQC micro-bursts (was 5.0, unrealistic)
    Wq_mg1 = (rho * mean_S * (1 + cv_squared)) / (2 * (1 - rho))
    
    # TTI Quantization (6G numerology mu=5, TTI = 31.25 us = 0.03125 ms)
    tti = 0.03125
    Wq_mg1_tti = np.ceil((Wq_mg1 + mean_S) / tti) * tti - mean_S

    plt.figure(figsize=(8, 6))
    
    plt.plot(rho, Wq_mm1, label='M/M/1 (Theoretical)', linestyle='--', color='blue', linewidth=2)
    plt.plot(rho, Wq_mg1, label='M/G/1 P-K (Micro-bursts)', color='red', linewidth=2)
    plt.plot(rho, Wq_mg1_tti, label='M/G/1 P-K with TTI Quantization ($\\mu=5$)', linestyle=':', color='green', linewidth=2)
    
    # Mark the URLLC constraint
    plt.axhline(y=10.0, color='black', linestyle='-.', label='10 ms URLLC Deadline')
    
    plt.ylim(0, 25)
    plt.xlim(0.1, 0.95)
    
    plt.xlabel('Traffic Intensity ($\\rho$)')
    plt.ylabel('Queueing Delay (ms)')
    plt.title('Queueing Delay: M/M/1 vs. M/G/1 Pollaczek-Khinchine')
    plt.legend()
    plt.tight_layout()
    
    plot_path = os.path.join(out_dir, 'fig_queueing_delay.png')
    plt.savefig(plot_path, dpi=300)
    plt.close()
    
    print(f"Saved queueing plot to {plot_path}")

if __name__ == "__main__":
    generate_queueing_plot()
