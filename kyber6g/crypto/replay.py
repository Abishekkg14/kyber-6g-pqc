"""Sliding-window anti-replay (RFC 6479 / IPsec-ESP style).

Replay protection and reordering are separate concerns: this window only
answers "has this sequence number been accepted before, or is it too old?".
Packets that arrive out of order but inside the window are accepted; the
media layer reorders them. The window is updated only AFTER the AEAD tag
has verified, so forged packets cannot poison it.
"""

ACCEPT = "accept"
DUPLICATE = "duplicate"
STALE = "stale"


class ReplayWindow:
    def __init__(self, size: int = 2048):
        self.size = size
        self.top = -1          # highest accepted sequence number
        self.bits = 0          # bit i set => (top - i) accepted

    def check(self, seq: int) -> str:
        if seq > self.top:
            return ACCEPT
        off = self.top - seq
        if off >= self.size:
            return STALE
        if (self.bits >> off) & 1:
            return DUPLICATE
        return ACCEPT

    def commit(self, seq: int) -> None:
        if seq > self.top:
            shift = seq - self.top
            self.bits = ((self.bits << shift) | 1) & ((1 << self.size) - 1) if shift < self.size else 1
            self.top = seq
        else:
            self.bits |= 1 << (self.top - seq)
