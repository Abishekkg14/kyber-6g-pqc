"""Reliable transfer of images / recordings over the secure UDP link.

Every chunk is an independent AEAD record (stream = image or recording).
META record: ext = b"M" + blob_id(4); payload = JSON (name, size, sha256 ...)
DATA record: ext = b"C" + blob_id(4) + idx(4); payload = chunk
The receiver NACKs missing chunks over the control stream; the sender
retransmits them (each retransmission gets a fresh sequence number/nonce).
Integrity: per-chunk AEAD tags plus SHA-256 of the whole plaintext.
"""
import hashlib
import json
import os
import re
import struct
import threading
import time                                              # every time here is a duration: monotonic clock only

from . import jsonmsg

CHUNK = 1100
MAX_BLOB = 256 << 20
MAX_BUFFERED = MAX_BLOB + (64 << 20)     # all transfers being received together: one full-size blob plus small ones
MAX_NACK = 512                           # chunks re-sent for one NACK (the receiver asks for 150 at a time)
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


def valid_info(info) -> bool:
    """Is this the metadata of a transfer we are prepared to receive? Checked field by field: the values become a
    file name, buffer sizes and loop counts on this side."""
    if not isinstance(info, dict):
        return False
    size, chunks, name = info.get("size"), info.get("chunks"), info.get("name")
    if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= MAX_BLOB:
        return False
    if isinstance(chunks, bool) or not isinstance(chunks, int) or chunks != max(1, -(-size // CHUNK)):
        return False
    if not isinstance(name, str) or not _NAME.fullmatch(name):
        return False
    if not isinstance(info.get("sha256"), str) or not _SHA256.fullmatch(info["sha256"]):
        return False
    return isinstance(info.get("kind"), str) and len(info["kind"]) <= 32 and isinstance(info.get("meta") or {}, dict)


class BlobSender:
    def __init__(self, send_record, pace_s: float = 0.0004):
        self.send_record = send_record          # (stream, payload, ext) -> bool
        self.pace = pace_s
        self.active = {}
        self.lock = threading.Lock()
        self.completed = []

    def send(self, stream: int, kind: str, name: str, data: bytes, meta: dict = None):
        if len(data) > MAX_BLOB:                 # the receiver would refuse it; say so instead of sending for minutes
            raise ValueError(f"{name}: {len(data) / 1e6:.0f} MB is over the {MAX_BLOB >> 20} MB transfer limit")
        bid = os.urandom(4)
        chunks = [data[i:i + CHUNK] for i in range(0, len(data), CHUNK)] or [b""]
        info = {"id": bid.hex(), "kind": kind, "name": name, "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(), "chunks": len(chunks), "meta": meta or {}}
        with self.lock:
            self.active[bid] = {"stream": stream, "chunks": chunks, "info": info, "t0": time.monotonic(), "retx": 0,
                                "last": time.monotonic(), "pushing": True}
        threading.Thread(target=self._push, args=(bid, range(len(chunks)), True), daemon=True).start()
        return info

    def _push(self, bid, idxs, with_meta):
        e = self.active.get(bid)
        if e is None:
            return
        try:
            if with_meta:
                self.send_record(e["stream"], json.dumps(e["info"]).encode(), b"M" + bid)
            for i in idxs:
                if bid not in self.active:
                    return
                self.send_record(e["stream"], e["chunks"][i], b"C" + bid + struct.pack("!I", i))
                e["last"] = time.monotonic()
                if self.pace:
                    time.sleep(self.pace)
        finally:
            e["pushing"] = False

    def on_control(self, msg) -> bool:
        t = msg.get("t")
        if t not in ("blob_nack", "blob_done"):
            return False
        try:
            bid = bytes.fromhex(msg.get("id", ""))
        except (ValueError, TypeError):
            return True                                   # ours by type, but not a transfer id: ignored
        e = self.active.get(bid)
        if e is None:
            return True
        if t == "blob_done":
            with self.lock:
                self.active.pop(bid, None)
            e["info"]["seconds"] = round(time.monotonic() - e["t0"], 3)
            e["info"]["retransmitted"] = e["retx"]
            self.completed.append(e["info"])
            del self.completed[:-64]
            return True
        want = msg.get("missing")
        missing = [i for i in (want if isinstance(want, list) else [])[:MAX_NACK]
                   if isinstance(i, int) and not isinstance(i, bool) and 0 <= i < len(e["chunks"])]
        with self.lock:
            # One sending thread per transfer: a NACK that arrives while chunks are still going out is not answered
            # with a second thread (the receiver asks again 0.25 s after the stream goes quiet), so a flood of NACKs
            # cannot multiply the traffic or the threads.
            if e.get("pushing"):
                return True
            e["pushing"] = True
        e["retx"] += len(missing)
        e["last"] = time.monotonic()
        threading.Thread(target=self._push, args=(bid, missing, bool(msg.get("meta"))), daemon=True).start()
        return True

    def expire(self, max_idle=60):
        """Forget transfers the receiver stopped asking about. Idle time, not age: a large recording on a slow
        link legitimately takes minutes and must not be dropped half-way."""
        now = time.monotonic()
        with self.lock:
            for bid in [b for b, e in self.active.items() if now - e.get("last", e["t0"]) > max_idle]:
                self.active.pop(bid)


class BlobReceiver:
    def __init__(self, send_control, on_complete, on_fail=None):
        self.send_control = send_control
        self.on_complete = on_complete
        self.on_fail = on_fail              # callable(info, chunks_received): a transfer was abandoned
        self.rx = {}
        self.failed = 0
        self.ok = 0
        self.refused = 0                    # transfers whose metadata was not acceptable (see valid_info)

    def on_record(self, ext: bytes, payload: bytes):
        if len(ext) < 5:
            return
        kind, bid = ext[:1], ext[1:5]
        e = self.rx.get(bid)
        if e is None:
            if len(self.rx) >= 8:
                return
            now = time.monotonic()
            e = self.rx[bid] = {"info": None, "parts": {}, "t0": now, "last": now, "progress": now, "nacks": 0}
        e["last"] = time.monotonic()
        if kind == b"M":
            info = jsonmsg.loads(payload)
            if not valid_info(info):
                self.rx.pop(bid, None)
                self.refused += 1
                return
            if e["info"] is None:                        # the first metadata of a transfer stands; a repeat changes nothing
                e["progress"], e["nacks"] = e["last"], 0
                e["info"] = info
                for idx in [i for i in e["parts"] if i >= info["chunks"]]:
                    del e["parts"][idx]
        elif kind == b"C" and len(ext) == 9:
            (idx,) = struct.unpack("!I", ext[5:9])
            if idx > MAX_BLOB // CHUNK or len(payload) > CHUNK or (e["info"] is None and len(e["parts"]) > 4096):
                return                                   # no metadata yet: do not buffer an unbounded amount
            if e["info"] is None or idx < e["info"]["chunks"]:
                if idx not in e["parts"]:
                    if sum(len(x["parts"]) for x in self.rx.values()) * CHUNK >= MAX_BUFFERED:
                        return                           # memory bound over all transfers; this one stalls and is dropped
                    e["progress"], e["nacks"] = e["last"], 0     # new data: the transfer is alive
                e["parts"][idx] = payload
        self._check(bid, e)

    def _check(self, bid, e):
        info = e["info"]
        if info is None or len(e["parts"]) < info["chunks"]:
            return
        data = b"".join(e["parts"][i] for i in range(info["chunks"]))
        self.rx.pop(bid, None)
        ok = len(data) == info["size"] and hashlib.sha256(data).hexdigest() == info["sha256"]
        info["seconds"] = round(time.monotonic() - e["t0"], 3)
        info["integrity"] = "PASS" if ok else "FAIL"
        if ok:
            self.ok += 1
            self.send_control({"t": "blob_done", "id": bid.hex()})
        else:
            self.failed += 1
        self.on_complete(info, data if ok else None)

    def tick(self):
        now = time.monotonic()
        for bid, e in list(self.rx.items()):
            # Give up when the transfer has STALLED (no new chunk for 30 s / 40 unanswered NACKs), not after a fixed
            # age: a 250 MB recording takes minutes and used to be cut off at 120 s.
            if now - e.get("progress", e["t0"]) > 30 or e["nacks"] > 40 or now - e["t0"] > 3600:
                self.rx.pop(bid, None)
                self.failed += 1
                if self.on_fail:
                    try:
                        self.on_fail(e["info"] or {"id": bid.hex()}, len(e["parts"]))
                    except Exception:
                        pass
                continue
            if now - e["last"] < 0.25:
                continue
            info = e["info"]
            missing = [] if info is None else [i for i in range(info["chunks"]) if i not in e["parts"]]
            self.send_control({"t": "blob_nack", "id": bid.hex(), "meta": info is None, "missing": missing[:150]})
            e["nacks"] += 1
            e["last"] = now
