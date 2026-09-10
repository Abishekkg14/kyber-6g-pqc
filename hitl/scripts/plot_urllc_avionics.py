import csv
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

iterations = []
modes = []
latencies = []
cpu_loads = []

with open("hitl_benchmarks_extended.csv", mode="r") as file:
    reader = csv.DictReader(file)
    for row in reader:
        iterations.append(int(row["Iteration"]))
        modes.append(row["Mode"])
        latencies.append(float(row["Total_Handshake_ms"]))
        cpu_loads.append(float(row["CPU_Load_Percent"]))

full_pqc_lat = [latencies[i] for i in range(len(modes)) if modes[i] == 'FULL_PQC']
rtt_lat = [latencies[i] for i in range(len(modes)) if modes[i] == '0RTT_REKEY']

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

# Panel 1: URLLC Latency Distribution
boxprops = dict(linewidth=2, color='darkblue')
medianprops = dict(linewidth=2, color='crimson')

# Generate the boxplot without the invalid kwargs
bplot = ax1.boxplot([full_pqc_lat, rtt_lat],
                    boxprops=boxprops, medianprops=medianprops, patch_artist=True)

# Safely apply labels
ax1.set_xticklabels(['FULL_PQC\n(Cold Start)', '0-RTT Rekey\n(MEC Cache)'])

# Safely apply face colors
colors = ['lightcoral', 'lightblue']
for patch, color in zip(bplot['boxes'], colors):
    patch.set_facecolor(color)

ax1.set_ylabel("Latency (ms)")
ax1.set_title("URLLC Reliability: Handshake Jitter")
ax1.grid(True, linestyle=':', alpha=0.6)
ax1.axhline(y=10.0, color='red', linestyle='--', alpha=0.5, label='10ms URLLC Limit')
ax1.legend()

# Panel 2: Avionics CPU Utilization
ax2.plot(iterations, cpu_loads, color='darkorange', linewidth=1.5, marker='.')
ax2.set_ylabel("CPU Utilization (%)")
ax2.set_xlabel("Benchmark Iteration")
ax2.set_title("Avionics Hardware Stress (Cortex-A72)")
ax2.set_ylim(0, 100)
ax2.grid(True, linestyle=':', alpha=0.6)
ax2.axhline(y=50.0, color='green', linestyle='--', alpha=0.5, label='2-Core Target')
ax2.legend()

plt.tight_layout()
plt.savefig("hitl_urllc_avionics.png", dpi=300)
print("[+] Visualization saved successfully as 'hitl_urllc_avionics.png'!")
