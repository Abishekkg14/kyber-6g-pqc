import csv
import os
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

script_dir = os.path.dirname(os.path.abspath(__file__))
csv_path = os.path.join(script_dir, "..", "data", "hitl_benchmarks_extended.csv")
if not os.path.exists(csv_path):
    csv_path = "hitl_benchmarks_extended.csv"

out_dir = os.path.join(script_dir, "..", "plots")
os.makedirs(out_dir, exist_ok=True)
out_path = os.path.join(out_dir, "hitl_benchmark_analysis.png")

iterations = []
modes = []
handshake_latencies = []
energy_mj = []
temperatures = []

with open(csv_path, mode="r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        iterations.append(int(row["Iteration"]))
        modes.append(row["Mode"])
        handshake_latencies.append(float(row["Total_Handshake_ms"]))
        energy_mj.append(float(row["Energy_mJ"]))
        temperatures.append(float(row["SoC_Temp_C"]))

fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 11), sharex=True)

# Panel 1: Handshake Latency (Full PQC vs Cached Rekey)
colors = ['#e74c3c' if m == 'FULL_PQC' else '#2980b9' for m in modes]
ax1.scatter(iterations, handshake_latencies, c=colors, s=25, alpha=0.85, edgecolors='none')
ax1.plot(iterations, handshake_latencies, color='#bdc3c7', alpha=0.5, linestyle=':', linewidth=1.2)
ax1.set_ylabel("Handshake Latency (ms)", fontsize=11, fontweight='bold')
ax1.set_title("Kyber-6G Physical HITL Validation: Latency, Energy & Thermal Profile (Raspberry Pi 4)", fontsize=13, fontweight='bold')
ax1.grid(True, linestyle=':', alpha=0.6)

legend_elements = [
    Line2D([0], [0], marker='o', color='w', label='Full PQC (Cold Start / Miss)', markerfacecolor='#e74c3c', markersize=8),
    Line2D([0], [0], marker='o', color='w', label='Cached Rapid Rekey (1-RTT / Hit)', markerfacecolor='#2980b9', markersize=8)
]
ax1.legend(handles=legend_elements, loc='upper right', framealpha=0.95)

# Panel 2: Energy Dissipated
ax2.plot(iterations, energy_mj, color='#27ae60', linewidth=1.8)
ax2.set_ylabel("SWaP-C Energy (mJ)", fontsize=11, fontweight='bold')
ax2.grid(True, linestyle=':', alpha=0.6)

# Panel 3: SoC Temperature
ax3.plot(iterations, temperatures, color='#8e44ad', linewidth=1.8)
ax3.set_ylabel("SoC Temperature (°C)", fontsize=11, fontweight='bold')
ax3.set_xlabel("Physical Benchmark Iteration (1 to 100)", fontsize=11, fontweight='bold')
ax3.grid(True, linestyle=':', alpha=0.6)

plt.tight_layout()
plt.savefig(out_path, dpi=300)
# Also copy to root hitl_benchmark_analysis.png if needed
plt.savefig(os.path.join(script_dir, "..", "hitl_benchmark_analysis.png"), dpi=300)
print(f"[+] Visualization saved successfully as '{out_path}'!")
