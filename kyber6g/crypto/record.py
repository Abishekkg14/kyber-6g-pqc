"""AEAD record layer.

Wire format of an encrypted record (all integers big-endian):

    ver(1) | ptype(1)=0x10 | stream(1) | ext_len(1) | session_id(8)
    | epoch(4) | seq(8) | ext(ext_len) | ciphertext || tag(16)

AAD   = every byte before the ciphertext (header + stream-specific ext), so
        version, stream, session, epoch, sequence number and media metadata
        cannot be modified without detection.
Nonce = 0x00000000 || seq(8). Keys are unique per (session, stream,
        direction, epoch) and seq is strictly increasing per (session, stream,
        direction) for the lifetime of the session, so a (key, nonce) pair is
        never reused. The nonce is not transmitted separately; it is derived
        from the authenticated sequence number (as in TLS 1.3 / WireGuard).

Thread safety: one stream is used by several threads (the control stream
carries commands, telemetry back-fill, file transfers and link control), so
"take the next sequence number" and "encrypt under the key of the current
epoch" are one step under a per-stream lock. Without it two threads could
read the same sequence number before either stored the next one, i.e. two
plaintexts under one (key, nonce) pair - which breaks AES-GCM and
ChaCha20-Poly1305 alike.
"""
import struct
import threading
import time

from . import keyschedule as ks
from .replay import ACCEPT, ReplayWindow
from .suites import Suite

PTYPE_RECORD = 0x10
HDR = struct.Struct("!BBBB8sIQ")
HDR_LEN = HDR.size  # 24
MAX_EPOCH_SKIP = 8
MAX_SEQ = 2**64 - 1


class RecordError(Exception):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def nonce_for(seq: int) -> bytes:
    return b"\x00\x00\x00\x00" + seq.to_bytes(8, "big")


def parse_header(pkt: bytes):
    if len(pkt) < HDR_LEN + 16:
        raise RecordError("malformed")
    ver, ptype, stream, ext_len, sid, epoch, seq = HDR.unpack_from(pkt)
    if ptype != PTYPE_RECORD:
        raise RecordError("malformed")
    aad_len = HDR_LEN + ext_len
    if len(pkt) < aad_len + 16:
        raise RecordError("malformed")
    return ver, stream, sid, epoch, seq, pkt[HDR_LEN:aad_len], aad_len


class TxStream:
    def __init__(self, suite: Suite, session_id: bytes, stream: int, chain0: bytearray,
                 rotate_seconds: float, rotate_packets: int):
        self.suite = suite
        self.session_id = session_id
        self.stream = stream
        self.chain = ks.EpochChain(chain0)
        self.seq = 0
        self.rotate_seconds = rotate_seconds
        self.rotate_packets = rotate_packets
        self._aead = suite.aead_cls(self.chain.key())
        self._epoch_start = time.monotonic()
        self._epoch_packets = 0
        self.packets = 0
        self.bytes = 0
        self.rotations = 0
        self._lock = threading.Lock()

    def _maybe_rotate(self):
        if (self._epoch_packets >= self.rotate_packets or
                time.monotonic() - self._epoch_start >= self.rotate_seconds):
            self.chain.advance()
            self._aead = self.suite.aead_cls(self.chain.key())
            self._epoch_start = time.monotonic()
            self._epoch_packets = 0
            self.rotations += 1

    def seal(self, payload: bytes, ext: bytes = b"", version: int = 1) -> bytes:
        if len(ext) > 255:
            raise ValueError("record extension longer than 255 bytes")
        with self._lock:                 # see "Thread safety" in the module docstring
            self._maybe_rotate()
            seq = self.seq
            if seq > MAX_SEQ:            # cannot be reached in practice (2^64 records); never wrap a nonce
                raise RecordError("sequence-exhausted")
            self.seq = seq + 1
            hdr = HDR.pack(version, PTYPE_RECORD, self.stream, len(ext), self.session_id, self.chain.epoch, seq) + ext
            ct = self._aead.encrypt(nonce_for(seq), payload, hdr)
            self._epoch_packets += 1
            self.packets += 1
            self.bytes += len(payload)
        return hdr + ct

    @property
    def epoch(self):
        return self.chain.epoch

    def wipe(self):
        self.chain.wipe()


class RxStream:
    def __init__(self, suite: Suite, stream: int, chain0: bytearray, grace_seconds: float, window: int):
        self.suite = suite
        self.stream = stream
        self.chain = ks.EpochChain(chain0)
        self.keys = {0: suite.aead_cls(self.chain.key())}
        self.current = 0
        self.retire_at = {}
        self.grace = grace_seconds
        self.window = ReplayWindow(window)
        self.accepted = 0
        self.rejected = {}
        self._lock = threading.Lock()

    def _note(self, reason):
        self.rejected[reason] = self.rejected.get(reason, 0) + 1

    def _aead_for(self, epoch: int):
        now = time.monotonic()
        for e in [e for e, t in self.retire_at.items() if t <= now]:
            self.keys.pop(e, None)
            self.retire_at.pop(e, None)
        if epoch in self.keys:
            return self.keys[epoch]
        if epoch < self.current:
            return None
        # Bound against the last *authenticated* epoch so forged headers
        # cannot push the one-way chain (and key cache) arbitrarily far.
        if epoch - self.current > MAX_EPOCH_SKIP:
            return None
        while self.chain.epoch < epoch:
            self.chain.advance()
            self.keys[self.chain.epoch] = self.suite.aead_cls(self.chain.key())
        return self.keys.get(epoch)

    def open(self, pkt: bytes, epoch: int, seq: int, aad_len: int) -> bytes:
        # The replay window is checked and committed in one step under the lock, so a record offered twice at the
        # same moment (two threads) is accepted exactly once. The link itself opens records on one thread only.
        with self._lock:
            verdict = self.window.check(seq)
            if verdict != ACCEPT:
                self._note(verdict)
                raise RecordError(verdict)
            aead = self._aead_for(epoch)
            if aead is None:
                self._note("stale-epoch")
                raise RecordError("stale-epoch")
            try:
                pt = aead.decrypt(nonce_for(seq), pkt[aad_len:], pkt[:aad_len])
            except Exception:
                self._note("auth-fail")
                raise RecordError("auth-fail") from None
            self.window.commit(seq)
            if epoch > self.current:
                for e in range(self.current, epoch):
                    self.retire_at.setdefault(e, time.monotonic() + self.grace)
                self.current = epoch
            self.accepted += 1
            return pt

    def wipe(self):
        self.chain.wipe()
        self.keys.clear()


class Session:
    """Directional record state for one established session."""

    def __init__(self, secrets: ks.SessionSecrets, suite: Suite, role: str, cfg):
        self.secrets = secrets
        self.suite = suite
        self.session_id = secrets.session_id
        self.role = role
        self.created = time.monotonic()
        self.last_rx = time.monotonic()
        tx_dir, rx_dir = (ks.DIR_U2G, ks.DIR_G2U) if role == "uav" else (ks.DIR_G2U, ks.DIR_U2G)
        self.tx = {}
        self.rx = {}
        for stream in ks.STREAM_NAMES:
            self.tx[stream] = TxStream(suite, self.session_id, stream, secrets.chain_key(stream, tx_dir),
                                       cfg.rotate_seconds, cfg.rotate_packets)
            self.rx[stream] = RxStream(suite, stream, secrets.chain_key(stream, rx_dir),
                                       cfg.epoch_grace_seconds, cfg.replay_window)

    def seal(self, stream: int, payload: bytes, ext: bytes = b"") -> bytes:
        return self.tx[stream].seal(payload, ext)

    def open(self, pkt: bytes):
        ver, stream, sid, epoch, seq, ext, aad_len = parse_header(pkt)
        if sid != self.session_id:
            raise RecordError("wrong-session")
        if stream not in self.rx:
            raise RecordError("malformed")
        pt = self.rx[stream].open(pkt, epoch, seq, aad_len)
        self.last_rx = time.monotonic()
        return stream, ext, pt, epoch, seq

    def stats(self):
        rej = {}
        for r in self.rx.values():
            for k, v in r.rejected.items():
                rej[k] = rej.get(k, 0) + v
        return {
            "tx_packets": sum(t.packets for t in self.tx.values()),
            "rx_packets": sum(r.accepted for r in self.rx.values()),
            "rotations": sum(t.rotations for t in self.tx.values()),
            "epochs": {ks.STREAM_NAMES[s]: t.epoch for s, t in self.tx.items()},
            "rejected": rej,
        }

    def wipe(self):
        for t in self.tx.values():
            t.wipe()
        for r in self.rx.values():
            r.wipe()
        self.secrets.wipe()
