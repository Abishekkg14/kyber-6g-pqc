import csv
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

script_dir = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(script_dir, "..", "data", "hitl_benchmarks_extended.csv")
if not os.path.exists(csv_path):
    csv_path = "hitl_benchmarks_extended.csv"

out_dir = os.path.join(script_dir, "..", "plots")
os.makedirs(out_dir, exist_ok=True)
out_file = os.path.join(out_dir, "hitl_urllc_avionics.png")

iterations = []
modes = []
latencies = []
cpu_loads = []

with open(csv_path, mode="r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        iterations.append(int(row["Iteration"]))
        modes.append(row["Mode"])
        latencies.append(float(row["Total_Handshake_ms"]))
        cpu_loads.append(float(row["CPU_Load_Percent"]))

full_pqc_lat = [latencies[i] for i in range(len(modes)) if modes[i] == 'FULL_PQC']
rtt_lat = [latencies[i] for i in range(len(modes)) if modes[i] in ('CACHED_REKEY', '0RTT_REKEY')]

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

# Panel 1: URLLC Latency Distribution
boxprops = dict(linewidth=2, color='#2c3e50')
medianprops = dict(linewidth=2, color='#e74c3c')

bplot = ax1.boxplot([full_pqc_lat, rtt_lat],
                    boxprops=boxprops, medianprops=medianprops, patch_artist=True)

ax1.set_xticklabels(['FULL_PQC\n(Cold Start / Miss)', 'Cached Rekey (1-RTT)\n(MEC Cache Hit)'], fontsize=10, fontweight='bold')

colors = ['#f1948a', '#85c1e9']
for patch, color in zip(bplot['boxes'], colors):
    patch.set_facecolor(color)

ax1.set_ylabel("Latency (ms)", fontsize=11, fontweight='bold')
ax1.set_title("URLLC Reliability: Handshake Jitter", fontsize=12, fontweight='bold')
ax1.grid(True, linestyle=':', alpha=0.6)
ax1.axhline(y=10.0, color='red', linestyle='--', linewidth=1.5, label='10ms URLLC Bound')
ax1.legend(loc='upper right')

# Panel 2: Avionics CPU Utilization
ax2.plot(iterations, cpu_loads, color='#d35400', linewidth=1.8, marker='.', markersize=6)
ax2.set_ylabel("CPU Utilization (%)", fontsize=11, fontweight='bold')
ax2.set_xlabel("Physical Benchmark Iteration", fontsize=11, fontweight='bold')
ax2.set_title("Avionics Hardware Utilization (Quad-Core Cortex-A72)", fontsize=12, fontweight='bold')
ax2.set_ylim(-5, 105)
ax2.grid(True, linestyle=':', alpha=0.6)
ax2.axhline(y=50.0, color='#27ae60', linestyle='--', linewidth=1.5, label='Dual-Core Active Threshold')
ax2.legend(loc='upper right')

plt.tight_layout()
plt.savefig(out_file, dpi=300)
plt.savefig(os.path.join(script_dir, "..", "hitl_urllc_avionics.png"), dpi=300)
print(f"[+] Visualization saved successfully as '{out_file}'!")
