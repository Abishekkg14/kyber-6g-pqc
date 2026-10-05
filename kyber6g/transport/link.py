"""Secure UDP link: handshake orchestration, sessions, keepalive, recovery.

UavLink (Pi) is the initiator; GcsLink (laptop) is the responder. Both run a
receive thread. All application traffic is sealed by the current Session's
AEAD record layer; handshake messages are fragmented plaintext whose
authenticity comes from ML-DSA signatures and Finished MACs.
"""
import base64
import hashlib
import ipaddress
import json
import logging
import os
import socket
import struct
import threading
import time
from collections import deque
from types import SimpleNamespace

from ..crypto import handshake as hs
from ..crypto import identity as idm
from ..crypto import keyschedule as ks
from ..crypto.record import PTYPE_RECORD, RecordError, Session
from ..crypto.suites import get_suite
from . import jsonmsg
from .framing import Reassembler, fragment

log = logging.getLogger("kyber6g.link")
b64e = lambda b: base64.b64encode(b).decode()


def b64d(s, length=None) -> bytes:
    """Strict base64 from a control message; ValueError unless it is a string that decodes (to `length` bytes)."""
    if not isinstance(s, str):
        raise ValueError("not a base64 string")
    b = base64.b64decode(s, validate=True)
    if length is not None and len(b) != length:
        raise ValueError(f"expected {length} bytes, got {len(b)}")
    return b


class TokenBucket:
    """`burst` tokens, refilled at `rate` per second: a ration for work that anybody can make this side do."""

    def __init__(self, rate: float, burst: float):
        self.rate, self.burst = rate, burst
        self.tokens, self.at = float(burst), time.monotonic()

    def _refill(self):
        now = time.monotonic()
        self.tokens = min(self.burst, self.tokens + (now - self.at) * self.rate)
        self.at = now

    def available(self) -> bool:
        self._refill()
        return self.tokens >= 1

    def take(self) -> bool:
        self._refill()
        if self.tokens < 1:
            return False
        self.tokens -= 1
        return True

# Every datagram must fit the path MTU: IP-fragmented UDP is dropped on some
# paths (measured: >1472-byte datagrams are lost even on WSL loopback).
CONTROL_CHUNK = 1100
MAX_CONTROL_PARTS = 32

def control_records(payload: bytes):
    """Split a control message into (ext, chunk) pieces, each sealed separately."""
    if len(payload) <= CONTROL_CHUNK:
        return [(b"", payload)]
    mid = os.urandom(4)
    parts = [payload[i:i + CONTROL_CHUNK] for i in range(0, len(payload), CONTROL_CHUNK)]
    if len(parts) > MAX_CONTROL_PARTS:
        # the receiver refuses longer messages; failing here lets the caller answer with an error instead of
        # sending something that silently never arrives (the other side would only see a timeout)
        raise ValueError(f"control message too large ({len(payload)} bytes, limit {MAX_CONTROL_PARTS * CONTROL_CHUNK})")
    return [(b"F" + mid + bytes([i, len(parts)]), p) for i, p in enumerate(parts)]


class ControlReassembler:
    def __init__(self):
        self.buf = {}

    def add(self, ext: bytes, chunk: bytes):
        if not ext:
            return chunk
        if len(ext) != 7 or ext[:1] != b"F" or ext[6] == 0 or ext[5] >= ext[6] or ext[6] > MAX_CONTROL_PARTS:
            return None
        now = time.monotonic()
        for k in [k for k, v in self.buf.items() if now - v[0] > 5]:
            del self.buf[k]
        mid, idx, cnt = ext[1:5], ext[5], ext[6]
        if mid not in self.buf:
            if len(self.buf) >= 16:                   # full: the oldest unfinished message makes room, a new one is never refused
                del self.buf[next(iter(self.buf))]
            self.buf[mid] = [now, [None] * cnt]
        parts = self.buf[mid][1]
        if len(parts) != cnt:
            return None
        parts[idx] = chunk
        if all(p is not None for p in parts):
            del self.buf[mid]
            return b"".join(parts)
        return None


class ClockSync:
    """UAV clock minus this machine's clock, estimated from ping/pong exchanges.

    Every latency figure and the alignment of detection boxes with the video depend on it. One exchange is wrong by
    at most rtt/2, so the low-RTT exchanges of the last 30 s are used (NTP-style). Two things that really happen to
    the ground-station clock are handled as well (measured in WSL after the laptop woke from sleep: the VM clock ran
    8.33 % slow and was pushed forward by 2.9 s every 35 s by the host):

      * a clock that runs at the wrong RATE: the offset is a line, not a constant. A straight line is fitted through
        the good samples and extrapolated to the moment the offset is asked for;
      * a clock that is STEPPED: a sample further from the prediction than any path asymmetry can explain means the
        clock jumped; everything measured before the jump is discarded at once instead of polluting 30 s of results.
    """
    WINDOW = 30.0
    STEP = 0.25                # s: beyond rtt/2, a difference this large is a clock step, not network jitter

    def __init__(self):
        self.samples = deque(maxlen=32)        # (monotonic time, rtt, offset)
        self.offset = None                     # estimate valid at monotonic time `at`
        self.at = None
        self.rate = 0.0                        # d(offset)/dt: +0.09 means the local clock loses 90 ms per second
        self.steps = 0
        self.last_step = None

    def at_time(self, mono):
        """The offset at local monotonic time `mono` (extrapolated along the measured drift, for at most 10 s)."""
        if self.offset is None:
            return None
        return self.offset + self.rate * max(0.0, min(mono - self.at, 10.0))

    def add(self, mono, rtt, offset):
        pred = self.at_time(mono)
        best_rtt = min((s[1] for s in self.samples), default=rtt)
        if pred is not None and abs(offset - pred) > (rtt + best_rtt) / 2 + self.STEP:
            self.steps += 1
            self.last_step = round(offset - pred, 3)
            self.samples.clear()
        self.samples.append((mono, rtt, offset))
        recent = [s for s in self.samples if mono - s[0] < self.WINDOW]
        floor = min(s[1] for s in recent)
        good = [s for s in recent if s[1] <= 1.5 * floor + 0.002]          # the exchanges with little queueing
        if len(good) >= 3 and good[-1][0] - good[0][0] >= 3.5:
            n = len(good)
            mx, my = sum(s[0] for s in good) / n, sum(s[2] for s in good) / n
            sxx = sum((s[0] - mx) ** 2 for s in good)
            slope = sum((s[0] - mx) * (s[2] - my) for s in good) / sxx if sxx > 0 else 0.0
            self.rate = max(-0.2, min(0.2, slope))
            self.offset, self.at = my + self.rate * (mono - mx), mono
        else:                    # too little to fit a line: the newest good sample, moved along the drift known so far
            b = good[-1]
            self.offset, self.at = b[2] + self.rate * (mono - b[0]), mono


def udp_counters():
    """Kernel UDP counters of THIS host (Linux): datagrams the kernel dropped because the socket buffer was full."""
    try:
        with open("/proc/net/snmp") as f:
            rows = [l.split() for l in f if l.startswith("Udp:")]
        return dict(zip(rows[0][1:], (int(x) for x in rows[1][1:]))) if len(rows) >= 2 else {}
    except (OSError, ValueError, IndexError):
        return {}


class LinkBase:
    def __init__(self, cfg):
        self.cfg = cfg
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
        # Linux clamps the request to net.core.rmem_max and reports twice the granted value: keep what we really got
        self.rcvbuf_bytes = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        self.reasm = Reassembler()
        self.running = False
        self.lock = threading.RLock()
        self.stats = {"handshakes_ok": 0, "handshakes_fail": 0, "cached_rekeys_ok": 0, "cached_rekey_rejects": 0,
                      "pq_ratchets": 0, "rx_records": 0, "tx_records": 0, "rx_bytes": 0, "tx_bytes": 0,
                      "drops": {}, "last_handshake_ms": None, "last_cached_rekey_ms": None,
                      "last_pq_ratchet_ms": None, "last_error": None}
        self.on_message = lambda stream, ext, payload, meta: None
        self.on_control = lambda msg: None
        self.ctrl_reasm = ControlReassembler()
        self._rx_logged = -1e9

    def _parse_control(self, ext, pt):
        data = self.ctrl_reasm.add(ext, pt)
        if data is None:
            return None
        msg = jsonmsg.loads(data)                 # a dict of bounded, finite values - or None
        if msg is None:
            self.drop("bad-control")
        return msg

    def _hs_source_ok(self, addr) -> bool:
        """May a handshake datagram from this address be looked at? (Records need no such test: they authenticate.)"""
        return True

    def drop(self, reason):
        d = self.stats["drops"]
        d[reason] = d.get(reason, 0) + 1

    def _send_raw(self, pkt, addr):
        try:
            self.sock.sendto(pkt, addr)
        except OSError as e:
            self.drop("send-error")
            self.stats["last_error"] = str(e)

    def _send_hs(self, mtype, body, addr, reverse=False):
        frags = fragment(mtype, body)
        for f in (reversed(frags) if reverse else frags):
            self._send_raw(f, addr)

    def _rx_loop(self):
        while self.running:
            try:
                pkt, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                if self.running:
                    time.sleep(0.05)
                continue
            if len(pkt) < 2:
                self.drop("malformed")
                continue
            try:
                if pkt[1] == PTYPE_RECORD:
                    self._on_record(pkt, addr)
                elif not self._hs_source_ok(addr):
                    self.drop("wrong-source")
                else:
                    done = self.reasm.add(addr, pkt)
                    if done:
                        self._on_handshake(done[0], done[1], addr)
            except Exception as e:  # never let one bad packet kill the link
                self.drop("internal")
                self.stats["last_error"] = repr(e)
                now = time.monotonic()
                if now - self._rx_logged > 10:        # one traceback per 10 s: a sender must not be able to fill the log
                    self._rx_logged = now
                    log.exception("rx error (further ones are only counted for 10 s)")

    def start(self):
        self.running = True
        self.sock.settimeout(0.5)
        threading.Thread(target=self._rx_loop, name="link-rx", daemon=True).start()

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass


# ======================================================================= UAV
class UavLink(LinkBase):
    def __init__(self, cfg, ident, gcs_pk, mobility_fn):
        super().__init__(cfg)
        self.ident = ident
        self.gcs_pk = gcs_pk
        self.mobility_fn = mobility_fn
        self.gcs_addr = (cfg.gcs_host, cfg.gcs_port)
        try:                                   # the ground station is configured by address: only that address may answer a handshake
            self._gcs_ip = str(ipaddress.ip_address(cfg.gcs_host))
        except ValueError:                     # configured by name: the source cannot be compared, so it is not filtered
            self._gcs_ip = None
        self._hs_note = None                   # last unauthenticated complaint about a handshake (diagnosis only)
        self._hs_proc_ms = None                # time spent verifying the answer of the last handshake / rekey
        self.suite = get_suite(cfg.suite_id)
        self.state = "DOWN"
        self.session = None
        self.session_mobility = None
        self.old = []                      # (Session, expires_at) kept for rx grace
        self.secrets_time = 0
        self._hs = None
        self._hs_lock = threading.Lock()
        self._hs_event = threading.Event()
        self._hs_result = None
        self._cf = None                    # ClientFinished to retransmit until confirmed
        self._ratchet = None
        self._ratchet_msg = self._ratchet_session = None
        self._ratchet_sent, self._ratchet_tx = 0.0, 0
        self._ratchet_t0, self._ratchet_build_ms, self._ratchet_tag = 0.0, 0.0, "auto"
        self._rid = 0
        self.last_rekey = time.monotonic()
        self.last_ratchet = time.monotonic()
        self.state_since = time.monotonic()
        self.events = deque(maxlen=50)
        self.oplog = deque(maxlen=4000)        # see _log_op
        self._op_n = 0
        self._ratchet_tag = "auto"
        self._echo, self._echo_rtt, self._echo_n = {}, [], 0      # see rtt_probe
        self._mob_retry_at, self._mob_backoff, self._mob_busy = 0.0, 0.5, False   # see _manage: handshake after a change of cell

    def _set_state(self, st, why=""):
        if st != self.state:
            self.state = st
            self.state_since = time.monotonic()
            self.events.append((time.time(), st, why))
            log.info("link %s %s", st, why)

    def start(self):
        super().start()
        threading.Thread(target=self._manager, name="link-mgr", daemon=True).start()

    # ------------------------------------------------------------- sending
    def send(self, stream, payload: bytes, ext: bytes = b"") -> bool:
        s = self.session
        if s is None or self.state != "UP":
            return False
        pkt = s.seal(stream, payload, ext)
        self._send_raw(pkt, self.gcs_addr)
        self.stats["tx_records"] += 1
        self.stats["tx_bytes"] += len(pkt)
        return True

    def send_control(self, msg: dict, force=False) -> bool:
        s = self.session
        if s is None or (self.state != "UP" and not force):
            return False
        for ext, chunk in control_records(json.dumps(msg, separators=(",", ":")).encode()):
            self._send_raw(s.seal(ks.STREAM_CONTROL, chunk, ext), self.gcs_addr)
        return True

    # ---------------------------------------------------------- handshake
    def _install(self, secrets, mobility, kind):
        new = Session(secrets, self.suite, "uav", self.cfg)
        with self.lock:
            if self.session is not None:
                self.old.append((self.session, time.monotonic() + self.cfg.epoch_grace_seconds + 2))
            self.session = new
            self.session_mobility = mobility
            self.secrets_time = time.monotonic()
        return new

    def _log_op(self, kind, ok, ms, tag, **more):
        """One line per handshake / rekey / ratchet, kept on this node: when (its own clock), which kind, whether it
        worked and how long it took. `tag` says who asked: "auto" (the link itself) or the label a measurement gave."""
        self._op_n += 1
        self.oplog.append({"n": self._op_n, "t": round(time.time(), 3), "kind": kind, "ok": bool(ok), "ms": ms, "tag": tag, **more})

    # One handshake or rekey at a time: they share the slot the answer is delivered to. The manager thread and a rekey
    # asked for from the dashboard used to be able to run together, each cancelling the other's pending answer.
    def _full_handshake(self, tag="auto"):
        with self._hs_lock:
            ok = self._do_full_handshake()
            self._log_op("full", ok, self.stats["last_handshake_ms"] if ok else None, tag,
                         **(self.stats.get("last_handshake_parts") or {} if ok else {"error": str(self.stats["last_error"])[:80]}))
            return ok

    def _cached_rekey(self, reason, tag="auto"):
        with self._hs_lock:
            n = self.stats["cached_rekeys_ok"] + self.stats["cached_rekey_rejects"]
            ok = self._do_cached_rekey(reason)
            if self.stats["cached_rekeys_ok"] + self.stats["cached_rekey_rejects"] != n:      # it was attempted at all
                self._log_op("cached", ok, self.stats["last_cached_rekey_ms"] if ok else None, tag,
                             **(self.stats.get("last_cached_rekey_parts") or {} if ok else {"error": str(self.stats["last_error"])[:80]}))
            return ok

    def _do_full_handshake(self):
        mobility = self.mobility_fn()
        t0 = time.perf_counter()
        ch = hs.ClientHandshake(self.ident, self.gcs_pk, self.suite.suite_id, mobility)
        hello = ch.client_hello()
        t_built = time.perf_counter()
        self._hs_result = self._hs_note = None
        self._hs_event.clear()
        self._hs = ("full", ch)
        for attempt in range(5):
            # alternate fragment order so a periodic loss pattern cannot hit
            # the same fragment index on every retransmission
            self._send_hs(hs.MSG_CLIENT_HELLO, hello, self.gcs_addr, reverse=attempt % 2 == 1)
            if self._hs_event.wait(1.2):
                break
        t_answer = time.perf_counter()
        self._hs = None
        res = self._hs_result
        self._hs_result = None
        if not res or res[0] != "ok":
            self.stats["handshakes_fail"] += 1
            self.stats["last_error"] = res[1] if res else f"handshake timeout{' (' + self._hs_note + ')' if self._hs_note else ''}"
            return False
        secrets, cf = res[1], res[2]
        self._install(secrets, mobility, "full")
        self._cf = cf
        self._send_hs(hs.MSG_CLIENT_FINISHED, cf, self.gcs_addr)
        self.stats["handshakes_ok"] += 1
        self.stats["last_handshake_ms"] = round((time.perf_counter() - t0) * 1000, 3)
        # where the time went, all on this node's clock: building the ClientHello (key generation + signature), waiting
        # for the answer (network both ways + the ground station's work + `process`), and `process` itself (verifying
        # the ServerHello and deriving the keys here)
        self.stats["last_handshake_parts"] = {"build_ms": round((t_built - t0) * 1000, 3), "wait_ms": round((t_answer - t_built) * 1000, 3),
                                              "process_ms": self._hs_proc_ms, "hello_sent": attempt + 1}
        self.last_rekey = self.last_ratchet = time.monotonic()
        return True

    def _do_cached_rekey(self, reason):
        s = self.session
        if s is None or time.monotonic() - self.secrets_time > self.cfg.cached_rekey_ttl_s:
            return False
        mobility = self.mobility_fn()
        t0 = time.perf_counter()
        req = hs.build_rekey_request(self.ident.node_id, s.secrets, mobility)
        t_built = time.perf_counter()
        self._hs_result = self._hs_note = None
        self._hs_event.clear()
        self._hs = ("rekey", req, s.secrets)
        for attempt in range(3):
            self._send_hs(hs.MSG_REKEY_REQ, req, self.gcs_addr)
            if self._hs_event.wait(0.7):
                break
        t_answer = time.perf_counter()
        self._hs = None
        res = self._hs_result
        self._hs_result = None
        if not res or res[0] != "ok":
            self.stats["cached_rekey_rejects"] += 1
            self.stats["last_error"] = f"cached rekey: {res[1] if res else 'timeout'}"
            return False
        self._install(res[1], mobility, "cached")
        self._cf = res[2]
        self._send_hs(hs.MSG_CLIENT_FINISHED, res[2], self.gcs_addr)
        self.stats["cached_rekeys_ok"] += 1
        self.stats["last_cached_rekey_ms"] = round((time.perf_counter() - t0) * 1000, 3)
        self.stats["last_cached_rekey_parts"] = {"build_ms": round((t_built - t0) * 1000, 3), "wait_ms": round((t_answer - t_built) * 1000, 3),
                                                 "process_ms": self._hs_proc_ms, "request_sent": attempt + 1}
        self.last_rekey = time.monotonic()
        self.events.append((time.time(), "CACHED_REKEY", reason))
        return True

    def _hs_source_ok(self, addr) -> bool:
        return self._gcs_ip is None or (addr[0], addr[1]) == (self._gcs_ip, self.cfg.gcs_port)

    def _on_handshake(self, mtype, body, addr):
        """An answer to the handshake in progress. Nothing here is trusted until it verifies, and a message that
        does not verify - a forgery, a stray duplicate, a damaged datagram - is counted and dropped while the
        attempt keeps waiting for the genuine answer. (Before, the first invalid ServerHello or an unauthenticated
        ERROR ended the attempt: one datagram per attempt from anyone on the network kept the link down for good.)
        The one message acted on without proof is a cached-rekey REJECT naming exactly our request: a hint to fall
        back to the full handshake at once. A forged one costs a full handshake, never security."""
        pending = self._hs
        if pending is None or self._hs_result is not None:
            return
        t0 = time.perf_counter()
        try:
            if mtype == hs.MSG_SERVER_HELLO and pending[0] == "full":
                secrets, cf = pending[1].process_server_hello(body)
                result = ("ok", secrets, cf)
            elif mtype == hs.MSG_REKEY_RESP and pending[0] == "rekey":
                new, cf = hs.client_process_rekey_resp(pending[1], pending[2], body)
                result = ("ok", new, cf)
            elif mtype == hs.MSG_REKEY_REJECT and pending[0] == "rekey":
                if len(body) != 17 or body[:16] != pending[1][:16]:        # UAV id | session id of OUR request | code
                    self.drop("handshake-invalid")
                    return
                result = ("reject", hs.REJECT_NAMES.get(body[16], str(body[16])))
            elif mtype == hs.MSG_HS_ERROR:
                self._hs_note = body.decode(errors="replace")[:80]         # remembered for the log, never acted on
                return
            else:
                return
        except (hs.HandshakeError, ValueError, struct.error) as e:
            self.drop("handshake-invalid")
            self._hs_note = str(e)[:80]
            return
        self._hs_proc_ms = round((time.perf_counter() - t0) * 1000, 3)
        self._hs_result = result
        self._hs_event.set()

    # --------------------------------------------------------------- receive
    def _on_record(self, pkt, addr):
        sid = pkt[4:12]
        with self.lock:
            cands = [self.session] + [o for o, _ in self.old] if self.session else [o for o, _ in self.old]
        sess = next((s for s in cands if s and s.session_id == sid), None)
        if sess is None:
            self.drop("unknown-session")
            return
        try:
            stream, ext, pt, epoch, seq = sess.open(pkt)
        except RecordError as e:
            self.drop(e.reason)
            return
        self.stats["rx_records"] += 1
        self.stats["rx_bytes"] += len(pkt)
        if sess is self.session:
            self._cf = None                 # GCS has confirmed this session
            if self.state != "UP":
                self._set_state("UP", "authenticated record from GCS")
        if stream == ks.STREAM_CONTROL:
            msg = self._parse_control(ext, pt)
            if msg is None or self._link_control(msg):
                return
            self.on_control(msg)
        else:
            self.on_message(stream, ext, pt, {"epoch": epoch, "seq": seq})

    def _link_control(self, msg):
        t = msg.get("t")
        if t == "ping":
            self.send_control({"t": "pong", "t1": msg.get("t1"), "t2": time.time(), "t3": time.time()})
            return True
        if t in ("welcome", "hb_ack"):
            sent = self._echo.pop(msg.get("echo"), None) if isinstance(msg.get("echo"), int) else None
            if sent is not None:                              # the answer to one of our probes: a round trip on THIS clock
                self._echo_rtt.append(round((time.perf_counter() - sent) * 1000, 3))
            return True
        if t == "ratchet_resp":
            r = self._ratchet
            if r is None or msg.get("rid") != r.rid:
                return True                                   # answer to an attempt that was already completed or given up
            old = self._ratchet_session
            if old is not self.session:                       # the session was replaced meanwhile (cached rekey / handshake):
                self._ratchet = None                          # the GCS mixed into the old one, so this result is not used
                return True
            t_resp = time.perf_counter()
            try:
                sid = bytes.fromhex(msg["sid"]) if isinstance(msg.get("sid"), str) else b""
                if len(sid) != 8:
                    raise ValueError("bad session id")
                new_secrets = r.finish(old.secrets, b64d(msg.get("x"), hs.X25519_LEN),
                                       b64d(msg.get("ct"), self.suite.kem_ct_len), sid)
            except (ValueError, hs.HandshakeError):           # a malformed answer: this attempt is over, a new one may follow
                self._ratchet = None
                self.drop("ratchet-invalid")
                return True
            t_fin = time.perf_counter()
            self._ratchet = None
            self._install(new_secrets, self.session_mobility, "pq")
            t_done = time.perf_counter()
            self.stats["last_pq_ratchet_ms"] = round((t_done - self._ratchet_t0) * 1000, 3)
            # where the time went, on this node's clock (as for the handshake): making the key pairs (before the clock of
            # the ratchet starts), waiting for the answer, deriving the new secrets from it, installing the session
            parts = {"build_ms": self._ratchet_build_ms, "wait_ms": round((t_resp - self._ratchet_t0) * 1000, 3),
                     "finish_ms": round((t_fin - t_resp) * 1000, 3), "install_ms": round((t_done - t_fin) * 1000, 3)}
            self.stats["last_pq_ratchet_parts"] = parts
            self.stats["pq_ratchets"] += 1
            self._log_op("ratchet", True, self.stats["last_pq_ratchet_ms"], self._ratchet_tag, requests_sent=self._ratchet_tx, **parts)
            self.last_ratchet = time.monotonic()
            self.events.append((time.time(), "PQ_RATCHET", "fresh ML-KEM-1024 + X25519 mixed in"))
            self.send_control({"t": "hb", "after": "ratchet"})
            return True
        return False

    RATCHET_TIMEOUT = 3.0            # s: a ratchet attempt that got no answer is given up (and may be started again)

    def request_pq_ratchet(self, tag="auto"):
        """Start a PQ ratchet. The request and the answer are single datagrams on a lossy link: the request is repeated
        by the manager until answered, and an attempt that is never answered expires. (Before, one lost datagram left
        `_ratchet` set for good and every later ratchet - periodic or from the dashboard - was refused.)"""
        with self.lock:                                           # the manager and the command thread both come here
            if self.state != "UP" or self.session is None:
                return False
            if self._ratchet is not None and time.monotonic() - self._ratchet_sent < self.RATCHET_TIMEOUT:
                return False                                      # one is in flight
            self._ratchet_tag = tag
            self._rid = (self._rid + 1) & 0xFFFFFFFF
            t_build = time.perf_counter()
            r = hs.PQRatchetInitiator(self.suite.suite_id, self._rid)
            self._ratchet_msg = {"t": "ratchet_req", "rid": self._rid, "x": b64e(r.x_pub), "ek": b64e(r.ek)}
            self._ratchet_session = self.session                  # the session whose secrets both sides mix the new ones into
            self._ratchet_t0 = time.perf_counter()
            self._ratchet_build_ms = round((self._ratchet_t0 - t_build) * 1000, 3)
            self._ratchet_sent, self._ratchet_tx = time.monotonic(), 1
            self._ratchet = r
        return self.send_control(self._ratchet_msg)

    def _ratchet_tick(self, now):
        """Called by the manager while UP: repeat an unanswered ratchet request, give it up after RATCHET_TIMEOUT."""
        if self._ratchet is None:
            return
        age = now - self._ratchet_sent
        if age > self.RATCHET_TIMEOUT:
            self._ratchet = None
            self.stats["pq_ratchet_timeouts"] = self.stats.get("pq_ratchet_timeouts", 0) + 1
            self._log_op("ratchet", False, None, self._ratchet_tag, requests_sent=self._ratchet_tx, error="no answer")
            self.events.append((time.time(), "PQ_RATCHET_TIMEOUT", "no answer from the GCS; will be tried again"))
        elif age > 0.35 * self._ratchet_tx and self._ratchet_tx < 5:
            self._ratchet_tx += 1
            self.send_control(self._ratchet_msg)

    def request_cached_rekey(self):
        threading.Thread(target=self._cached_rekey, args=("manual",), daemon=True).start()

    def rekey_now(self, kind: str, tag: str = "manual"):
        """A fresh session NOW, in the calling thread: kind "full" (complete PQC handshake) or "cached" (1-RTT Cached
        RapidRekey). For the operator and for measurements: returns what happened and how long it took, timed on
        this node's clock. The running session keeps carrying traffic until the new one is installed."""
        if self.state != "UP":
            return {"ok": False, "error": f"link is {self.state}"}
        if kind == "cached":
            ok, key = self._cached_rekey("manual", tag), "last_cached_rekey"
        else:
            ok, key = self._full_handshake(tag), "last_handshake"
        s = self.session
        return {"ok": bool(ok), "ms": self.stats.get(key + "_ms") if ok else None, "parts": self.stats.get(key + "_parts") if ok else None,
                "error": None if ok else self.stats["last_error"], "session": s.session_id.hex() if s else None}

    def rtt_probe(self, n: int = 100, interval: float = 0.05, timeout: float = 1.0, pad: int = 0):
        """Round-trip time of a control message through the whole secure path (seal, UDP over the radio, open on the
        ground station, its answer sealed and sent back, opened here), measured on this node's clock: `n` probes,
        `interval` seconds apart. Returns the round trips in ms and how many probes got no answer.
        `pad` > 0 adds that many bytes of padding, which the ground station sends back: the round trip of a message
        of several datagrams in each direction (what a handshake message is)."""
        n, interval = max(1, min(int(n), 2000)), max(0.005, min(float(interval), 1.0))
        pad = max(0, min(int(pad), 8000))
        padding = ["p" * 1000] * (pad // 1000) + (["p" * (pad % 1000)] if pad % 1000 else [])
        self._echo, self._echo_rtt = {}, []
        for _ in range(n):
            self._echo_n = (self._echo_n + 1) & 0x7FFFFFFF
            self._echo[self._echo_n] = time.perf_counter()
            msg = {"t": "hb", "echo": self._echo_n, "pad": padding} if padding else {"t": "hb", "echo": self._echo_n}
            if not self.send_control(msg):
                self._echo.pop(self._echo_n, None)
            time.sleep(interval)
        deadline = time.monotonic() + timeout
        while self._echo and time.monotonic() < deadline:
            time.sleep(0.01)
        lost, self._echo = len(self._echo), {}
        return {"rtt_ms": list(self._echo_rtt), "sent": n, "lost": lost}

    def pq_ratchet_now(self, tag: str = "manual", timeout: float = 4.0):
        """A PQ ratchet started now and waited for; same kind of answer as `rekey_now`."""
        n = self.stats["pq_ratchets"]
        if not self.request_pq_ratchet(tag):
            return {"ok": False, "error": "not started: the link is not up, or a ratchet is already in flight"}
        deadline = time.monotonic() + timeout
        while self.stats["pq_ratchets"] == n and self._ratchet is not None and time.monotonic() < deadline:
            time.sleep(0.002)
        ok, s = self.stats["pq_ratchets"] > n, self.session
        return {"ok": ok, "ms": self.stats["last_pq_ratchet_ms"] if ok else None, "parts": self.stats.get("last_pq_ratchet_parts") if ok else None,
                "requests_sent": self._ratchet_tx,
                "error": None if ok else "no answer from the ground station", "session": s.session_id.hex() if s else None}

    # --------------------------------------------------------------- manager
    def _manager(self):
        """Supervises the state machine: an unexpected error in a handshake step must never end this thread,
        or the link would stay down until the service is restarted."""
        while self.running:
            try:
                self._manage()
            except Exception as e:
                log.exception("link manager")
                self.stats["last_error"] = f"link manager: {e!r}"
                self._hs = None
                if self.state in ("HANDSHAKING", "CONFIRMING"):
                    self._set_state("DOWN", "internal error, retrying")
                time.sleep(1.0)

    def _manage(self):
        backoff = 0.5
        last_hb = 0
        while self.running:
            now = time.monotonic()
            with self.lock:
                self.old = [(o, t) for o, t in self.old if t > now or o.wipe()]
            if self.state in ("DOWN", "RECOVERING"):
                self._set_state("HANDSHAKING", "establishing session")
                ok = False
                if self.session is not None and self.session_mobility == self.mobility_fn():
                    ok = self._cached_rekey("recovery")
                if not ok:
                    ok = self._full_handshake()
                if ok:
                    backoff = 0.5
                    self._set_state("CONFIRMING", "Finished sent")
                else:
                    self._set_state("DOWN", self.stats["last_error"] or "")
                    time.sleep(backoff)
                    backoff = min(backoff * 2, 8.0)
                continue
            if self.state == "CONFIRMING":
                if self._cf is not None:
                    self._send_hs(hs.MSG_CLIENT_FINISHED, self._cf, self.gcs_addr)
                self.send_control({"t": "hb"}, force=True)
                if now - self.state_since > self.cfg.link_timeout_s:
                    self._set_state("DOWN", "no confirmation from GCS")
                time.sleep(0.25)
                continue
            # UP
            if now - last_hb >= self.cfg.heartbeat_s:
                self.send_control({"t": "hb"})
                last_hb = now
            s = self.session
            if s and now - s.last_rx > self.cfg.link_timeout_s:
                self._set_state("RECOVERING", "link timeout (no authenticated traffic)")
                continue
            if self.mobility_fn() != self.session_mobility:
                # A session belongs to the cell it was made in; a new cell needs a new full handshake. It is made IN
                # PLACE: the running session keeps carrying traffic until the new one is installed, exactly as for a
                # rekey the operator asks for. (Before, the link left the UP state for the handshake and nothing was
                # sent meanwhile: one or two video frames per cell change, and with them the picture up to the next
                # keyframe - at 30 m/s that is every few seconds.) It runs in a thread of its own: a handshake that
                # gets no answer takes 6 s, and this loop must go on sending heartbeats and watching the link.
                if not self._mob_busy and now >= self._mob_retry_at:
                    self._mob_busy = True
                    threading.Thread(target=self._mobility_handshake, name="k6g-mobility", daemon=True).start()
            elif self.cfg.cached_rekey_interval_s and now - self.last_rekey > self.cfg.cached_rekey_interval_s:
                if not self._cached_rekey("periodic"):
                    self.last_rekey = now
            if self.cfg.pq_ratchet_interval_s and now - self.last_ratchet > self.cfg.pq_ratchet_interval_s:
                self.last_ratchet = now
                self.request_pq_ratchet()
            self._ratchet_tick(now)
            time.sleep(0.1)

    def _mobility_handshake(self):
        """The full handshake after a change of cell (see _manage). If it does not complete, the running session
        goes on working and the handshake is tried again, further apart each time."""
        try:
            if self.state != "UP":                    # the link dropped meanwhile: recovery makes its own handshake
                return
            self.events.append((time.time(), "MOBILITY", "cell changed -> full PQC handshake"))
            if self._full_handshake("mobility"):
                self._mob_backoff = 0.5
            else:
                self._mob_retry_at = time.monotonic() + self._mob_backoff
                self._mob_backoff = min(self._mob_backoff * 2, 8.0)
        except Exception as e:
            log.exception("mobility handshake")
            self.stats["last_error"] = f"mobility handshake: {e!r}"
            self._mob_retry_at = time.monotonic() + 2.0
        finally:
            self._mob_busy = False

    def status(self):
        s = self.session
        return {"state": self.state, "session_id": s.session_id.hex() if s else None,
                "suite": self.suite.name, "suite_id": self.suite.suite_id,
                "session_age_s": round(time.monotonic() - s.created, 1) if s else None,
                "record": s.stats() if s else None, **{k: v for k, v in self.stats.items()}}


# ======================================================================= GCS
class GcsLink(LinkBase):
    def __init__(self, cfg, ident, uav_pins: dict, bind=("0.0.0.0", None)):
        super().__init__(cfg)
        self.ident = ident
        self.server = hs.ServerHandshake(ident, uav_pins, suites=(1, 2))
        self.cache = hs.RekeyCache(cfg.cached_rekey_ttl_s)
        self.sessions = {}       # sid -> SimpleNamespace(session, uav_id, addr, mobility, confirmed)
        self.active = None
        self.uav_addr = None
        self.hello_cache = {}    # sha256(hello) -> (expires, response)
        self.rekey_cache = {}    # sha256(rekey request) -> (expires, answer type, answer)
        # Rations for work an unauthenticated sender can cause. They are global, not per source address: the address
        # of a UDP datagram is whatever its sender wrote, so a per-address limit (as used before: 8 hellos per 10 s)
        # let one forged datagram per second, carrying the UAV's address, lock the UAV itself out.
        #   bad_sigs  ClientHellos that reached the signature check and failed it (ML-DSA-87 verify, the only costly
        #             step an outsider can trigger). Empty bucket: hellos are dropped unverified until it refills.
        #             Its size follows from what a check costs on THIS machine (measured here, once): failed checks may
        #             take a quarter of one core, not more. A fixed 50 per second, as before, was reached by a flood
        #             of 0.3 MB/s, and from then on a genuine hello got through only by luck; at 80 us per check (the
        #             project's laptop) the ration is about 3000 per second, i.e. 20 MB/s of forged hellos.
        #   replies   REJECT answers to rekey requests that do not verify (keeps this port from being a reflector).
        self.bad_sigs = TokenBucket(*self._verify_ration())
        self.replies = TokenBucket(rate=20, burst=40)
        self._trial = {}         # pending session id -> the one Session object built for it (see _on_record)
        self._last_ratchet = 0.0
        self.clock = ClockSync()                       # uav_clock - gcs_clock, from the ping/pong exchanges
        self.rtt_ms = None
        self._rekey_sids = set()                       # session ids created by a cached rekey, until confirmed
        self._ratchet_done = {}                        # (old session id, rid) -> answer already given (repeats get the same)
        self.events = deque(maxlen=50)
        self.sock.bind((bind[0], bind[1] or cfg.gcs_port))

    def start(self):
        super().start()
        threading.Thread(target=self._housekeeping, name="gcs-house", daemon=True).start()

    @property
    def time_offset(self):
        """uav_clock - gcs_clock (s) right now, or None before the first ping/pong."""
        return self.clock.at_time(time.monotonic())

    def _verify_ration(self, share: float = 0.25):
        """(rate per second, burst) for the bucket of failed signature checks: `share` of one core's time, from the
        cost of a check measured with this node's own key (a genuine signature takes the full path through the check).
        Never below 50 per second, whatever the machine; the burst is one second's worth."""
        try:
            msg = b"KYBER6G/ration-probe"
            sig = self.ident.sign(msg)
            costs = []
            for _ in range(5):
                t0 = time.perf_counter()
                idm.verify(self.ident.sig_alg, msg, sig, self.ident.pk)
                costs.append(time.perf_counter() - t0)
            cost = max(sorted(costs)[len(costs) // 2], 10e-6)
        except Exception:                                 # cannot be measured: the old, conservative ration
            return 50.0, 100.0
        rate = float(max(50, min(20000, int(share / cost))))
        return rate, max(100.0, rate)

    def send(self, stream, payload: bytes, ext: bytes = b"") -> bool:
        e = self.sessions.get(self.active)
        if e is None or self.uav_addr is None:
            return False
        pkt = e.session.seal(stream, payload, ext)
        self._send_raw(pkt, self.uav_addr)
        self.stats["tx_records"] += 1
        self.stats["tx_bytes"] += len(pkt)
        return True

    def send_control(self, msg: dict) -> bool:
        ok = True
        for ext, chunk in control_records(json.dumps(msg, separators=(",", ":")).encode()):
            ok = self.send(ks.STREAM_CONTROL, chunk, ext) and ok
        return ok

    def link_up(self):
        e = self.sessions.get(self.active)
        return bool(e and time.monotonic() - e.session.last_rx < self.cfg.link_timeout_s)

    def _confirm(self, secrets, uav_id, mobility, suite, addr, why, session=None):
        # Exactly one Session object per set of secrets: two objects would
        # both start at seq 0 and reuse AEAD nonces under the same key.
        s = session or Session(secrets, suite, "gcs", self.cfg)
        if secrets.session_id in self._rekey_sids:               # a confirmed 1-RTT Cached RapidRekey, counted when answered
            self._rekey_sids.discard(secrets.session_id)
        else:                                                    # a full PQC handshake (confirmed by Finished or implicitly)
            self.stats["handshakes_ok"] += 1
        self.sessions[secrets.session_id] = SimpleNamespace(session=s, uav_id=uav_id, addr=addr,
                                                            mobility=mobility, confirmed=time.time())
        self.cache.put(uav_id, secrets, mobility, suite.suite_id)
        self.active = secrets.session_id
        self.uav_addr = addr
        self.events.append((time.time(), "SESSION", f"{why} {secrets.session_id.hex()}"))
        self.send_control({"t": "welcome", "sid": secrets.session_id.hex()})
        return s

    def _on_handshake(self, mtype, body, addr):
        try:
            if mtype == hs.MSG_CLIENT_HELLO:
                key = hashlib.sha256(body).digest()
                cached = self.hello_cache.get(key)
                if cached and cached[0] > time.monotonic():
                    cached[2] += 1                                         # idempotent retransmit
                    self._send_hs(hs.MSG_SERVER_HELLO, cached[1], addr, reverse=cached[2] % 2 == 1)
                    return
                if not self.bad_sigs.available():                          # see __init__: a flood of forged hellos
                    self.drop("hello-flood")
                    return
                t0 = time.perf_counter()
                try:
                    resp = self.server.process_client_hello(body)
                except hs.SignatureInvalid:
                    self.bad_sigs.take()
                    raise
                self.stats["last_handshake_ms"] = round((time.perf_counter() - t0) * 1000, 3)
                self.hello_cache = {k: v for k, v in self.hello_cache.items() if v[0] > time.monotonic()}
                self.hello_cache[key] = [time.monotonic() + 10, resp, 0]
                self._send_hs(hs.MSG_SERVER_HELLO, resp, addr)
            elif mtype == hs.MSG_CLIENT_FINISHED:
                sid = body[:8]
                if sid in self.sessions:
                    self.send_control({"t": "welcome", "sid": sid.hex()}) if sid == self.active else None
                    return
                secrets, uav_id, mobility, suite = self.server.process_client_finished(body)
                self._confirm(secrets, uav_id, mobility, suite, addr, "confirmed")
            elif mtype == hs.MSG_REKEY_REQ:
                # The UAV repeats a request it got no answer to. The first one used up the cached secret, so a repeat
                # would be refused (CACHE_MISS) and the UAV would fall back to a full handshake although nothing was
                # wrong but one lost datagram: the same request gets the same answer again for a few seconds.
                now = time.monotonic()
                key = hashlib.sha256(body).digest()
                self.rekey_cache = {k: v for k, v in self.rekey_cache.items() if v[0] > now}
                cached = self.rekey_cache.get(key)
                if cached:
                    self._send_hs(cached[1], cached[2], addr)
                    return
                t0 = time.perf_counter()
                rtype, rbody, new, uav_id = hs.server_process_rekey(self.cache, self.server, body)
                if rtype == hs.MSG_REKEY_RESP:
                    self.stats["last_cached_rekey_ms"] = round((time.perf_counter() - t0) * 1000, 3)
                    # remember the new session id so its confirmation is not also counted as a full handshake
                    # (the SECURITY tab showed "handshakes ok 96" after 2 real handshakes and 94 cached rekeys)
                    if len(self._rekey_sids) > 256:
                        self._rekey_sids.clear()
                    self._rekey_sids.add(new.session_id)
                    self.rekey_cache[key] = (now + 5, rtype, rbody)
                    self.stats["cached_rekeys_ok"] += 1
                    self.events.append((time.time(), "CACHED_REKEY", "1-RTT Cached RapidRekey accepted"))
                else:
                    self.stats["cached_rekey_rejects"] += 1
                    self.events.append((time.time(), "CACHED_REKEY_REJECT", hs.REJECT_NAMES.get(rbody[-1], "?")))
                    if not self.replies.take():                            # refusals are rationed; the UAV then simply times out
                        self.drop("reject-not-sent")
                        return
                self._send_hs(rtype, rbody, addr)
        except (hs.HandshakeError, ValueError, struct.error) as e:
            self.stats["handshakes_fail"] += 1
            self.stats["last_error"] = str(e)
            self.drop("handshake-invalid")
            self.events.append((time.time(), "HANDSHAKE_REJECT", str(e)))

    def _on_record(self, pkt, addr):
        sid = pkt[4:12]
        e = self.sessions.get(sid)
        if e is None:
            if sid not in self.server.pending:
                self.drop("unknown-session")
                return
            # A record that authenticates under a pending session's keys is
            # implicit key confirmation (covers ClientFinished loss/reorder).
            secrets, _, _, uav_id, mobility, suite = self.server.pending[sid]
            # The Session for a pending id is built once and kept: the id travels in clear in the ServerHello, so
            # anyone who saw it can send records "for" it, and each would otherwise cost a full key derivation.
            self._trial = {k: v for k, v in self._trial.items() if k in self.server.pending}
            trial = self._trial.get(sid)
            if trial is None:
                trial = self._trial[sid] = Session(secrets, suite, "gcs", self.cfg)
            try:
                opened = trial.open(pkt)
            except RecordError:
                self.drop("unknown-session")
                return
            self.server.pending.pop(sid)
            self._trial.pop(sid, None)
            self._confirm(secrets, uav_id, mobility, suite, addr, "implicitly confirmed", session=trial)
            e = self.sessions[sid]
        else:
            try:
                opened = e.session.open(pkt)
            except RecordError as err:
                self.drop(err.reason)
                return
        self._dispatch(e, opened, pkt, addr)

    def _dispatch(self, e, opened, pkt, addr):
        stream, ext, pt, epoch, seq = opened
        self.stats["rx_records"] += 1
        self.stats["rx_bytes"] += len(pkt)
        sid = e.session.session_id
        if sid != self.active and e.confirmed >= self.sessions.get(self.active, e).confirmed:
            self.active = sid
            self.events.append((time.time(), "SWITCH", f"active session {sid.hex()}"))
        if sid == self.active and addr != self.uav_addr:
            self.events.append((time.time(), "ROAM", f"UAV address {addr}"))
            self.uav_addr = addr                # roaming accepted only after authentication
        if stream == ks.STREAM_CONTROL:
            msg = self._parse_control(ext, pt)
            if msg is None or self._link_control(msg, e):
                return
            self.on_control(msg)
        else:
            self.on_message(stream, ext, pt, {"epoch": epoch, "seq": seq, "sid": sid})

    def _link_control(self, msg, e):
        t = msg.get("t")
        if t == "hb":
            # liveness for the UAV's link monitor; a probe number is echoed (the UAV times the round trip on its clock)
            t0 = time.perf_counter()
            echo, ack = msg.get("echo"), {"t": "hb_ack"}
            if isinstance(echo, int) and not isinstance(echo, bool):
                ack["echo"] = echo
                # a probe may carry padding to be sent back (round trip of a message of several datagrams). Bounded:
                # the answer is never larger than the authenticated request it answers.
                pad = msg.get("pad")
                if isinstance(pad, list) and 0 < len(pad) <= 8 and all(isinstance(p, str) and len(p) <= 1000 for p in pad):
                    ack["pad"] = pad
            self.send_control(ack)
            if "echo" in ack:
                # how long this station took over the probe, from the complete request to the answer sent: the same
                # stretch that last_handshake_ms / last_cached_rekey_ms / last_pq_ratchet_ms give for a session operation
                self.stats["last_echo_ms"], self.stats["last_echo_n"] = round((time.perf_counter() - t0) * 1000, 3), echo
            return True
        if t == "pong":
            t4 = time.time()
            t1, t2, t3 = (jsonmsg.num(msg.get(k), 0, 1e11) for k in ("t1", "t2", "t3"))
            if t1 is None or t2 is None or t3 is None or t3 < t2 or not 0 <= t4 - t1 < 60:
                self.drop("bad-pong")                 # not three times, or not the answer to a ping of the last minute
                return True
            rtt = (t4 - t1) - (t3 - t2)
            offset = ((t2 - t1) + (t3 - t4)) / 2
            self.rtt_ms = round(rtt * 1000, 2)
            if rtt > 0:
                steps = self.clock.steps
                self.clock.add(time.monotonic(), rtt, offset)
                n = self.clock.steps
                if n != steps and (n <= 3 or n % 50 == 0):       # a broken clock steps every half minute: do not flood the log
                    self.events.append((time.time(), "CLOCK_STEP", f"ground-station clock jumped by {-self.clock.last_step:+.3f} s "
                                                                   f"relative to the UAV (host time sync / wake from sleep), "
                                                                   f"{n} jump(s) so far"))
            return True
        if t == "ratchet_req":
            old = e.session
            # The UAV repeats a request it got no answer to. Answering a repeat with a fresh computation would create
            # a second new session and leave the rekey cache holding secrets the UAV never adopted: the same request
            # (same session, same rid) gets the same answer again.
            rid = msg.get("rid")
            if isinstance(rid, bool) or not isinstance(rid, int) or not 0 <= rid <= 0xFFFFFFFF:
                self.drop("ratchet-invalid")
                return True
            key = (old.session_id, rid)
            if key in self._ratchet_done:
                self.send_control(self._ratchet_done[key])
                return True
            now = time.monotonic()
            if now - self._last_ratchet < 0.5:        # each one creates a session: two a second is more than any use needs
                self.drop("ratchet-rate")
                return True
            t0 = time.perf_counter()
            try:
                x_s, ct, new_sid, new_secrets = hs.pq_ratchet_respond(
                    old.secrets, rid, b64d(msg.get("x"), hs.X25519_LEN), b64d(msg.get("ek"), old.suite.kem_ek_len))
            except (ValueError, hs.HandshakeError):   # wrong sizes, not base64, a key X25519 refuses
                self.drop("ratchet-invalid")
                return True
            self._last_ratchet = now
            new = Session(new_secrets, old.suite, "gcs", self.cfg)
            self.sessions[new_sid] = SimpleNamespace(session=new, uav_id=e.uav_id, addr=e.addr,
                                                     mobility=e.mobility, confirmed=time.time())
            self.cache.put(e.uav_id, new_secrets, e.mobility, old.suite.suite_id)
            resp = {"t": "ratchet_resp", "rid": rid, "x": b64e(x_s), "ct": b64e(ct), "sid": new_sid.hex()}
            if len(self._ratchet_done) >= 8:
                self._ratchet_done.pop(next(iter(self._ratchet_done)))
            self._ratchet_done[key] = resp
            self.send_control(resp)
            self.stats["pq_ratchets"] += 1
            self.stats["last_pq_ratchet_ms"] = round((time.perf_counter() - t0) * 1000, 3)
            self.events.append((time.time(), "PQ_RATCHET", f"new session {new_sid.hex()}"))
            return True
        return False

    def _housekeeping(self):
        last_ping = 0
        while self.running:
            try:
                now = time.monotonic()
                for sid in list(self.sessions):
                    e = self.sessions.get(sid)
                    if e is not None and sid != self.active and now - e.session.last_rx > self.cfg.epoch_grace_seconds + 10:
                        e.session.wipe()
                        self.sessions.pop(sid, None)
                if self.link_up() and now - last_ping > 2:
                    self.send_control({"t": "ping", "t1": time.time()})
                    last_ping = now
            except Exception as e:                    # housekeeping must outlive any single failure (pings stop otherwise)
                log.exception("gcs housekeeping")
                self.stats["last_error"] = f"housekeeping: {e!r}"
            time.sleep(0.5)

    def status(self):
        e = self.sessions.get(self.active)
        s = e.session if e else None
        off = self.time_offset
        return {"state": "UP" if self.link_up() else ("STALE" if s else "DOWN"),
                "session_id": s.session_id.hex() if s else None,
                "suite": s.suite.name if s else get_suite(self.cfg.suite_id).name,
                "uav_id": e.uav_id.decode(errors="replace") if e else None,
                "uav_addr": f"{self.uav_addr[0]}:{self.uav_addr[1]}" if self.uav_addr else None,
                "session_age_s": round(time.monotonic() - s.created, 1) if s else None,
                "sessions_held": len(self.sessions), "record": s.stats() if s else None,
                "rtt_ms": self.rtt_ms, "clock_offset_ms": round(off * 1000, 2) if off is not None else None,
                # how fast the UAV clock moves away from ours: 0 for two healthy clocks; +9 % was measured when the
                # WSL clock ran slow after the laptop woke from sleep (latency figures are then only approximate)
                "clock_rate_pct": round(self.clock.rate * 100, 2), "clock_steps": self.clock.steps,
                "rcvbuf_bytes": self.rcvbuf_bytes, "udp": udp_counters(), **self.stats}
