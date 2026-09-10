import csv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

iterations = []
modes = []
handshake_latencies = []
energy_mj = []
temperatures = []

with open("hitl_benchmarks_extended.csv", mode="r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        iterations.append(int(row["Iteration"]))
        modes.append(row["Mode"])
        handshake_latencies.append(float(row["Total_Handshake_ms"]))
        energy_mj.append(float(row["Energy_mJ"]))
        temperatures.append(float(row["SoC_Temp_C"]))

fig, (ax1, ax2, ax3) = plt.subplots(3, 1, figsize=(10, 12), sharex=True)

# Panel 1: Handshake Latency (Full PQC vs 0-RTT)
colors = ['red' if m == 'FULL_PQC' else 'blue' for m in modes]
ax1.scatter(iterations, handshake_latencies, c=colors, s=15, alpha=0.7)
ax1.plot(iterations, handshake_latencies, color='gray', alpha=0.3, linestyle='--')
ax1.set_ylabel("Handshake Latency (ms)")
ax1.set_title("6G HITL Physical Validation: Latency, Energy & Thermal Profile")
ax1.grid(True, linestyle=':', alpha=0.6)

legend_elements = [
    Line2D([0], [0], marker='o', color='w', label='Full PQC (Cache Miss)', markerfacecolor='red', markersize=8),
    Line2D([0], [0], marker='o', color='w', label='0-RTT Rekey (Cache Hit)', markerfacecolor='blue', markersize=8)
]
ax1.legend(handles=legend_elements, loc='upper right')

# Panel 2: Energy Dissipated
ax2.plot(iterations, energy_mj, color='green', linewidth=1.5)
ax2.set_ylabel("Energy Dissipated (mJ)")
ax2.grid(True, linestyle=':', alpha=0.6)

# Panel 3: SoC Temperature
ax3.plot(iterations, temperatures, color='purple', linewidth=1.5)
ax3.set_ylabel("SoC Temperature (°C)")
ax3.set_xlabel("Benchmark Iteration (1 to 100)")
ax3.grid(True, linestyle=':', alpha=0.6)

plt.tight_layout()
plt.savefig("hitl_benchmark_analysis.png", dpi=300)
print("[+] Visualization saved successfully as 'hitl_benchmark_analysis.png'!")
