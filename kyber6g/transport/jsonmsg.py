"""MTU-safe JSON messages: split into pieces that each become one AEAD record.

ext = msg_no(4) | idx(2) | count(2); pieces of one message share msg_no.
"""
import json
import math
import struct

EXT = struct.Struct("!IHH")
PIECE = 1100
MAX_DEPTH, MAX_ITEMS, MAX_STR = 8, 4096, 4096


def _no_constant(name):
    raise ValueError(f"{name} is not JSON")


def tame(v, depth=0):
    """Parsed JSON from the peer, reduced to bounded plain data: finite numbers, strings and containers of limited
    size and depth; anything else becomes None. The peer is authenticated, but a faulty or taken-over peer must not
    be able to hand this side a value that breaks it later (a NaN that the browser cannot parse, a 10 MB string,
    nesting that exhausts the stack)."""
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v if -2**63 <= v < 2**63 else None
    if isinstance(v, float):
        return v if math.isfinite(v) else None
    if isinstance(v, str):
        return v[:MAX_STR]
    if depth >= MAX_DEPTH:
        return None
    if isinstance(v, list):
        return [tame(x, depth + 1) for x in v[:MAX_ITEMS]]
    if isinstance(v, dict):
        return {str(k)[:64]: tame(x, depth + 1) for k, x in list(v.items())[:MAX_ITEMS]}
    return None


def loads(data: bytes):
    """One JSON message from the peer as a dict of tame values, or None if it is not one."""
    try:
        obj = json.loads(data, parse_constant=_no_constant)       # NaN / Infinity are not JSON; browsers reject them
    except (ValueError, RecursionError):                          # RecursionError: nesting deeper than the parser allows
        return None
    return tame(obj) if isinstance(obj, dict) else None


def num(v, lo=None, hi=None):
    """v if it is a real number (not a bool) within [lo, hi], else None: for values that go into arithmetic."""
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        return None
    if (lo is not None and v < lo) or (hi is not None and v > hi):
        return None
    return v


def split(obj, msg_no: int):
    data = json.dumps(obj, separators=(",", ":"), default=str).encode()
    cnt = max(1, -(-len(data) // PIECE))
    return [(EXT.pack(msg_no & 0xFFFFFFFF, i, cnt), data[i * PIECE:(i + 1) * PIECE]) for i in range(cnt)]


class Reassembler:
    def __init__(self, max_pending: int = 16):
        self.parts = {}
        self.max_pending = max_pending

    def add(self, ext: bytes, chunk: bytes):
        if len(ext) != EXT.size:
            return None
        no, idx, cnt = EXT.unpack(ext)
        if cnt == 0 or idx >= cnt or cnt > 64:
            return None
        p = self.parts.setdefault(no, {})
        p[idx] = chunk
        if len(p) >= cnt:
            del self.parts[no]
            if any(i not in p for i in range(cnt)):     # pieces of two messages with one number and different counts
                return None
            return loads(b"".join(p[i] for i in range(cnt)))
        while len(self.parts) > self.max_pending:
            self.parts.pop(min(self.parts))
        return None
