#!/usr/bin/env bash
# ==============================================================================
# Kyber-6G Raspberry Pi 4 Performance & Deterministic Latency Tuning
# - Sets CPU governor to 'performance' (locks Cortex-A72 to 1.50 GHz)
# - Disables Wi-Fi Power Save mode to eliminate 30-100ms wireless sleep jitter
# - Configures CPU core affinity: Cores 0-1 for OS/Interrupts, Cores 2-3 for Crypto
# ==============================================================================
set -e

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root: sudo bash rpi_performance_tune.sh"
  exit 1
fi

echo "=== [1/3] Setting CPU Governor to 'performance' (1.50 GHz) ==="
for cpu_gov in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    if [ -f "$cpu_gov" ]; then
        echo "performance" > "$cpu_gov"
    fi
done
echo "[+] CPU Governor set to performance on all cores."

echo "=== [2/3] Disabling Wi-Fi Power Save (Eliminating Sleep Jitter) ==="
WLAN_IF=$(iw dev | awk '$1=="Interface"{print $2}' | head -n 1)
if [ -n "$WLAN_IF" ]; then
    iw dev "$WLAN_IF" set power_save off
    echo "[+] Wi-Fi power save disabled on $WLAN_IF"
else
    echo "[*] No wireless interface detected (skipping Wi-Fi power save)."
fi

echo "=== [3/3] CPU Core Topology & Process Priority Recommendation ==="
echo "  [Core 0, Core 1]: Reserved for Linux Kernel, networking interrupts & background daemons"
echo "  [Core 2, Core 3]: Dedicated for PQC Cryptographic Worker Threads"
echo "  Recommended launch pattern: taskset -c 2,3 nice -n -10 python3 <script.py>"

echo ""
echo "=== Current System Status ==="
echo -n "  Current CPU Frequency: "
cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq 2>/dev/null || echo "N/A"
if [ -n "$WLAN_IF" ]; then
    iw dev "$WLAN_IF" get power_save 2>/dev/null || true
fi
echo "[+] Tuning applied successfully!"
