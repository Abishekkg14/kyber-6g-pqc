import csv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

modes = []
crypto_ms = []
aes_ms = []

with open("hitl_benchmarks_extended.csv", mode="r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        modes.append(row["Mode"])
        crypto_ms.append(float(row["Crypto_Proc_ms"]))
        aes_ms.append(float(row["AES_GCM_Tx_Rx_ms"]))

# Separate data by mode
full_crypto = [crypto_ms[i] for i in range(len(modes)) if modes[i] == 'FULL_PQC']
full_aes = [aes_ms[i] for i in range(len(modes)) if modes[i] == 'FULL_PQC']

rtt_crypto = [crypto_ms[i] for i in range(len(modes)) if modes[i] == '0RTT_REKEY']
rtt_aes = [aes_ms[i] for i in range(len(modes)) if modes[i] == '0RTT_REKEY']

# Calculate averages
avg_full_crypto = np.mean(full_crypto)
avg_full_aes = np.mean(full_aes)
avg_rtt_crypto = np.mean(rtt_crypto)
avg_rtt_aes = np.mean(rtt_aes)

labels = ['FULL_PQC (Cache Miss)', '0RTT_REKEY (Cache Hit)']
crypto_means = [avg_full_crypto, avg_rtt_crypto]
aes_means = [avg_full_aes, avg_rtt_aes]

x = np.arange(len(labels))
width = 0.4

fig, ax = plt.subplots(figsize=(8, 6))
p1 = ax.bar(x, crypto_means, width, label='CPU Crypto Processing (ms)', color='crimson')
p2 = ax.bar(x, aes_means, width, bottom=crypto_means, label='AES-GCM Tx/Rx Delay (ms)', color='royalblue')

ax.set_ylabel('Latency Overhead (ms)')
ax.set_title('6G HITL: Cryptographic vs Network Overhead (Cortex-A72)')
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.legend()
ax.grid(axis='y', linestyle='--', alpha=0.6)

# Annotate bars with values
for i, c in enumerate(p1):
    # Crypto text
    ax.text(c.get_x() + c.get_width()/2, c.get_height()/2, f'{c.get_height():.2f} ms', 
            ha='center', va='center', color='white', weight='bold')
    # AES text
    a = p2[i]
    ax.text(a.get_x() + a.get_width()/2, c.get_height() + a.get_height()/2, f'{a.get_height():.2f} ms', 
            ha='center', va='center', color='white', weight='bold')

plt.tight_layout()
plt.savefig("crypto_overhead_breakdown.png", dpi=300)
print("[+] Visualization saved successfully as 'crypto_overhead_breakdown.png'!")
