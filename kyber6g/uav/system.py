"""Raspberry Pi health: CPU, memory, temperature, throttling, Wi-Fi."""
import subprocess
import time

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def throttled():
    try:
        out = subprocess.run(["vcgencmd", "get_throttled"], capture_output=True, text=True, timeout=2).stdout
        return out.strip().split("=")[-1]
    except Exception:
        return None


def wifi():
    txt = _read("/proc/net/wireless") or ""
    for line in txt.splitlines()[2:]:
        parts = line.split()
        if parts and parts[0].startswith("wlan"):
            return {"iface": parts[0].rstrip(":"), "link_quality": float(parts[2].rstrip(".")),
                    "signal_dbm": float(parts[3].rstrip("."))}
    return None


class SystemMonitor:
    def __init__(self):
        self._thr = (0, None)
        if psutil:
            psutil.cpu_percent(None)

    def snapshot(self):
        now = time.time()
        if now - self._thr[0] > 10:
            self._thr = (now, throttled())
        t = _read("/sys/class/thermal/thermal_zone0/temp")
        f = _read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq")      # kHz; the governor lowers it when idle
        d = {"temp_c": round(int(t) / 1000, 1) if t else None, "throttled": self._thr[1], "wifi": wifi(),
             "cpu_mhz": round(int(f) / 1000) if f and f.isdigit() else None}
        if psutil:
            vm = psutil.virtual_memory()
            d.update(cpu_percent=psutil.cpu_percent(None), per_cpu=psutil.cpu_percent(None, percpu=True),
                     mem_percent=vm.percent, mem_used_mb=round(vm.used / 2**20), load=list(psutil.getloadavg()))
        return d
