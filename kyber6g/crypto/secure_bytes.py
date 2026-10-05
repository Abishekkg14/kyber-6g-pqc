"""Best-effort zeroisation of secret byte buffers.

CPython cannot guarantee erasure: immutable `bytes` objects, copies made by
C extensions (OpenSSL keeps its own key schedule inside AEAD objects) and the
garbage collector may leave copies in memory. We keep long-lived secrets in
`bytearray`s and overwrite them when they are retired, which removes the
copies we control. See docs/SECURITY_ARCHITECTURE.md (limitations).
"""
import hmac


def wipe(buf) -> None:
    if isinstance(buf, bytearray):
        for i in range(len(buf)):
            buf[i] = 0
    elif isinstance(buf, memoryview) and not buf.readonly:
        buf[:] = b"\x00" * len(buf)


def ct_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)


def no_core_dumps() -> bool:
    """Make this process non-dumpable: a crash must not write its memory (session keys, the identity signing key,
    the recording decapsulation key) to disk.

    Measured: a segfault of the ground station under WSL was captured by WSL's crash handler as a 4 GB dump in the
    Windows temp folder, and the capture took ~90 s, during which the automatic restart could not begin. The resource
    limit alone does not prevent that (a piped core handler ignores RLIMIT_CORE); PR_SET_DUMPABLE = 0 does.
    Returns True if the process is now non-dumpable (Linux), False where that is not available."""
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, ValueError, OSError):
        pass
    try:
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        PR_SET_DUMPABLE, PR_GET_DUMPABLE = 4, 3
        libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
        return libc.prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
    except (OSError, AttributeError):
        return False
