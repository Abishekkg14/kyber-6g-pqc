import csv
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

script_dir = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(script_dir, "..", "data", "hitl_benchmarks_extended.csv")
if not os.path.exists(csv_path):
    csv_path = "hitl_benchmarks_extended.csv"

out_dir = os.path.join(script_dir, "..", "plots")
os.makedirs(out_dir, exist_ok=True)
out_file = os.path.join(out_dir, "crypto_overhead_breakdown.png")

modes = []
crypto_ms = []
aes_ms = []

with open(csv_path, mode="r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        modes.append(row["Mode"])
        crypto_ms.append(float(row["Crypto_Proc_ms"]))
        aes_ms.append(float(row["AES_GCM_Tx_Rx_ms"]))

# Separate data by mode
full_crypto = [crypto_ms[i] for i in range(len(modes)) if modes[i] == 'FULL_PQC']
full_aes = [aes_ms[i] for i in range(len(modes)) if modes[i] == 'FULL_PQC']

rtt_crypto = [crypto_ms[i] for i in range(len(modes)) if modes[i] in ('CACHED_REKEY', '0RTT_REKEY')]
rtt_aes = [aes_ms[i] for i in range(len(modes)) if modes[i] in ('CACHED_REKEY', '0RTT_REKEY')]

# Calculate averages
avg_full_crypto = np.mean(full_crypto)
avg_full_aes = np.mean(full_aes)
avg_rtt_crypto = np.mean(rtt_crypto)
avg_rtt_aes = np.mean(rtt_aes)

labels = ['FULL_PQC (Cold Start / Miss)', 'Cached Rekey 1-RTT (Cache Hit)']
crypto_means = [avg_full_crypto, avg_rtt_crypto]
aes_means = [avg_full_aes, avg_rtt_aes]

x = np.arange(len(labels))
width = 0.42

fig, ax = plt.subplots(figsize=(8, 6))
p1 = ax.bar(x, crypto_means, width, label='CPU Crypto Processing (ms)', color='#c0392b')
p2 = ax.bar(x, aes_means, width, bottom=crypto_means, label='AES-GCM Tx/Rx Delay (ms)', color='#2980b9')

ax.set_ylabel('Latency Overhead (ms)', fontsize=11, fontweight='bold')
ax.set_title('Kyber-6G HITL: Cryptographic vs Network Overhead (ARM Cortex-A72)', fontsize=12, fontweight='bold')
ax.set_xticks(x)
ax.set_xticklabels(labels, fontsize=10, fontweight='bold')
ax.legend(framealpha=0.9)
ax.grid(axis='y', linestyle='--', alpha=0.6)

# Annotate bars with values
for i, c in enumerate(p1):
    ax.text(c.get_x() + c.get_width()/2, max(0.05, c.get_height()/2), f'{c.get_height():.2f} ms', 
            ha='center', va='center', color='white', weight='bold', fontsize=10)
    a = p2[i]
    ax.text(a.get_x() + a.get_width()/2, c.get_height() + a.get_height()/2, f'{a.get_height():.2f} ms', 
            ha='center', va='center', color='white', weight='bold', fontsize=10)

plt.tight_layout()
plt.savefig(out_file, dpi=300)
plt.savefig(os.path.join(script_dir, "..", "crypto_overhead_breakdown.png"), dpi=300)
print(f"[+] Visualization saved successfully as '{out_file}'!")
