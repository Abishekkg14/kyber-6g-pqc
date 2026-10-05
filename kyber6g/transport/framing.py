"""Handshake-message fragmentation (MTU-safe, bounded reassembly).

Handshake header: ver(1) | mtype(1) | hs_id(4) | idx(1) | cnt(1)
Records (ptype 0x10) are never fragmented: every media/telemetry record is
built to fit in one datagram so it can be decrypted independently.
"""
import hashlib
import struct
import time

HS_HDR = struct.Struct("!BB4sBB")
MAX_FRAG_PAYLOAD = 1180
MAX_FRAGS = 16
MAX_PENDING = 128              # partial messages kept in total (worst case 128 * 16 * 1180 B = 2.4 MB)
MAX_PENDING_PER_SOURCE = 4     # ... and from one source address (a peer has one or two messages in flight)
REASSEMBLY_TIMEOUT = 5.0


def fragment(mtype: int, body: bytes, version: int = 1, hs_id: bytes = None):
    # Content-derived id: retransmissions of the same message share an id, so
    # fragments that survived different attempts can be combined.
    hs_id = hs_id or hashlib.sha256(bytes([mtype]) + body).digest()[:4]
    chunks = [body[i:i + MAX_FRAG_PAYLOAD] for i in range(0, len(body), MAX_FRAG_PAYLOAD)] or [b""]
    if len(chunks) > MAX_FRAGS:
        raise ValueError("handshake message too large")
    return [HS_HDR.pack(version, mtype, hs_id, i, len(chunks)) + c for i, c in enumerate(chunks)]


class Reassembler:
    """Bounded table of partly received handshake messages.

    Fragments are unauthenticated (the message they belong to is verified only once it is complete), so anyone who
    can send a datagram can open entries here. A full table therefore never refuses a new message - that would let
    32 forged first fragments every 5 s lock every genuine handshake out - it drops the OLDEST entry instead, first
    within the sender's own quota, then overall. Memory stays bounded by MAX_PENDING * MAX_FRAGS * MAX_FRAG_PAYLOAD."""

    def __init__(self):
        self.buf = {}          # (addr, mtype, hs_id) -> [first seen, fragments]; dict order = oldest first
        self.evicted = 0

    def _evict(self, key):
        del self.buf[key]
        self.evicted += 1

    def add(self, addr, pkt: bytes):
        """Returns (mtype, body) when complete, else None. Malformed input is dropped."""
        if len(pkt) < HS_HDR.size or len(pkt) > HS_HDR.size + MAX_FRAG_PAYLOAD:
            return None
        ver, mtype, hs_id, idx, cnt = HS_HDR.unpack_from(pkt)
        if cnt == 0 or cnt > MAX_FRAGS or idx >= cnt:
            return None
        now = time.monotonic()
        for k in [k for k, v in self.buf.items() if now - v[0] > REASSEMBLY_TIMEOUT]:
            del self.buf[k]
        key = (addr, mtype, hs_id)
        if key not in self.buf:
            mine = [k for k in self.buf if k[0] == addr]
            if len(mine) >= MAX_PENDING_PER_SOURCE:
                self._evict(mine[0])
            if len(self.buf) >= MAX_PENDING:
                self._evict(next(iter(self.buf)))
            self.buf[key] = [now, [None] * cnt]
        frags = self.buf[key][1]
        if len(frags) != cnt:
            return None
        frags[idx] = pkt[HS_HDR.size:]
        if all(f is not None for f in frags):
            del self.buf[key]
            return mtype, b"".join(frags)
        return None
