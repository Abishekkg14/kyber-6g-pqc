"""Options for the SSH calls of the tools (the management channel to the Pi: deploy, service control, measurements).

The secure link is post-quantum; the channel the tools use to reach the Pi should not be the weak spot. OpenSSH has
hybrid post-quantum key exchanges - ML-KEM-768 + X25519 from version 9.9, Streamlined NTRU Prime 761 + X25519 from
8.5 - but a client older than 9.0 still prefers X25519 alone (measured here: OpenSSH 8.9 on the laptop and 10.0 on the
Pi settled for curve25519-sha256). `ssh_base()` puts the hybrid ones this client knows at the head of its list; the
classical ones stay behind them, so a server without any still works.

The same is done for the shell scripts by `pq_kex` in run/kyber6g.sh.
"""
import functools
import re
import subprocess

PQ_KEX = ("mlkem768x25519-sha256", "sntrup761x25519-sha512", "sntrup761x25519-sha512@openssh.com")


@functools.lru_cache(maxsize=1)
def pq_kex_option() -> tuple:
    try:
        have = set(subprocess.run(["ssh", "-Q", "kex"], capture_output=True, text=True, timeout=5).stdout.split())
    except Exception:
        return ()
    mine = [k for k in PQ_KEX if k in have]
    return ("-o", "KexAlgorithms=^" + ",".join(mine)) if mine else ()


def ssh_base(host: str, timeout: int = 8) -> list:
    """The start of an ssh command line for `host`: no password prompt, a connect timeout, hybrid key exchange first."""
    return ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={timeout}", *pq_kex_option(), host]


def negotiated_kex(host: str, timeout: int = 8):
    """The key exchange a connection to `host` really uses (from ssh's own debug output), or None if it cannot connect."""
    try:
        r = subprocess.run(ssh_base(host, timeout)[:-1] + ["-v", host, "true"], capture_output=True, text=True, timeout=timeout + 10)
    except Exception:
        return None
    m = re.search(r"kex: algorithm: (\S+)", r.stderr)
    return m.group(1) if m and r.returncode == 0 else None


def is_post_quantum(kex: str) -> bool:
    return bool(kex) and (kex.startswith("mlkem") or kex.startswith("sntrup"))
