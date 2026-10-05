"""Hybrid post-quantum handshake, 1-RTT Cached RapidRekey and PQ ratchet.

Full handshake (UAV = client, GCS = server), 1.5 RTT:

  C -> S  CLIENT_HELLO  suite | uav_id | nonce_c | mobility_cell | ts
                        | X25519 eph pk | ML-KEM-1024 eph ek
                        | ML-DSA-87 sig_uav(label || all of the above)
  S -> C  SERVER_HELLO  suite | session_id | nonce_s | gcs_id
                        | X25519 eph pk | ML-KEM ciphertext
                        | ML-DSA-87 sig_gcs(label || TH) | Finished_S
  C -> S  CLIENT_FINISHED session_id | Finished_C

  TH        = SHA-256(label || ClientHello || sig_uav || ServerHello-body)
  IKM       = ss_ML-KEM || ss_X25519            (concatenation combiner)
  PRK       = HKDF-Extract(salt = TH, IKM)
  keys      = HKDF-Expand(PRK, "KYBER6G/<purpose>/v1|" suite session_id)
  Finished  = HMAC(finished key, transcript)    (explicit key confirmation)

Both long-term ML-DSA keys are pinned from disk. ML-DSA authenticates the
handshake; it does not encrypt anything. All application data is protected
by the AEAD of the negotiated suite (AES-256-GCM by default).
"""
import os
import struct
import time

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import oqs

from . import identity as idm
from . import keyschedule as ks
from .secure_bytes import ct_equal, wipe
from .suites import get_suite

MSG_CLIENT_HELLO = 0x01
MSG_SERVER_HELLO = 0x02
MSG_CLIENT_FINISHED = 0x03
MSG_REKEY_REQ = 0x05
MSG_REKEY_RESP = 0x06
MSG_REKEY_REJECT = 0x07
MSG_HS_ERROR = 0x08

REJECT_MISS = 1
REJECT_STALE = 2
REJECT_STALE_MOBILITY = 3
REJECT_AUTH = 4
REJECT_NAMES = {REJECT_MISS: "CACHE_MISS", REJECT_STALE: "CACHE_EXPIRED",
                REJECT_STALE_MOBILITY: "STALE_MOBILITY", REJECT_AUTH: "AUTH_FAIL"}

LBL_CH = b"KYBER6G/hs/client-hello/v1"
LBL_TH = b"KYBER6G/hs/th/v1"
LBL_SS = b"KYBER6G/hs/server-sig/v1"
LBL_RK_REQ = b"KYBER6G/hs/cached-rekey-req/v1"
LBL_RK_TH = b"KYBER6G/hs/cached-rekey-th/v1"
LBL_PQR = b"KYBER6G/hs/pq-ratchet/v1"

CH_FIXED = struct.Struct("!H8s32s8sQ")      # suite, uav_id, nonce_c, mobility, ts_ms
SH_FIXED = struct.Struct("!H8s32s8s")       # suite, session_id, nonce_s, gcs_id
RK_FIXED = struct.Struct("!8s8s8s32sQ")     # uav_id, old_sid, mobility, nonce_c, ts_ms
X25519_LEN = 32
FIN_LEN = 32


class HandshakeError(Exception):
    pass


class SignatureInvalid(HandshakeError):
    """A message that got as far as the (expensive) signature check and failed it: what a flood is rationed on."""


def now_ms() -> int:
    return int(time.time() * 1000)


def _x25519_pub(priv) -> bytes:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def mobility_cell(lat, lon, cell_deg: float) -> bytes:
    """Coarse position cell used as rekey CONTEXT (not a secret)."""
    if lat is None or lon is None:
        tag = b"NOFIX"
    else:
        tag = f"{round(lat / cell_deg)},{round(lon / cell_deg)}".encode()
    return ks.sha256(b"KYBER6G/mobility-cell/v1|", tag)[:8]


class MobilityTracker:
    """The current mobility cell, with hysteresis.

    A GNSS fix wanders by tens of metres even when standing still. With a plain `round(lat / cell)` a UAV resting near a
    cell edge flips cells every few seconds, and every flip forces a full handshake (observed: 4 re-handshakes in 2 min
    at +/-23 m). The cell is only changed once the position is more than `margin` of a cell beyond the old cell's edge.
    The cell id for index (i, j) equals `mobility_cell` of any point that rounds to (i, j), so both ends agree."""

    def __init__(self, cell_deg: float, margin: float = 0.3):
        self.deg, self.margin = cell_deg, margin
        self.idx = None
        self.current = mobility_cell(None, None, cell_deg)

    def update(self, lat, lon) -> bytes:
        if lat is None or lon is None:
            return self.current                      # fix lost for a moment: keep the last known cell
        fi, fj = lat / self.deg, lon / self.deg
        if self.idx is None or abs(fi - self.idx[0]) > 0.5 + self.margin or abs(fj - self.idx[1]) > 0.5 + self.margin:
            self.idx = (round(fi), round(fj))
            self.current = mobility_cell(self.idx[0] * self.deg, self.idx[1] * self.deg, self.deg)
        return self.current


# --------------------------------------------------------------------- client
class ClientHandshake:
    def __init__(self, ident: idm.Identity, gcs_pk: bytes, suite_id: int, mobility: bytes):
        self.ident = ident
        self.gcs_pk = gcs_pk
        self.suite = get_suite(suite_id)
        self.mobility = mobility
        self._x = x25519.X25519PrivateKey.generate()
        self._kem = oqs.KeyEncapsulation(self.suite.kem)
        ek = self._kem.generate_keypair()
        self.nonce_c = os.urandom(32)
        self.signed = (CH_FIXED.pack(self.suite.suite_id, ident.node_id, self.nonce_c, mobility, now_ms())
                       + _x25519_pub(self._x) + ek)
        self.sig = ident.sign(LBL_CH + self.signed)
        self.t_start = time.perf_counter()
        self.done = False

    def client_hello(self) -> bytes:
        return self.signed + struct.pack("!H", len(self.sig)) + self.sig

    def process_server_hello(self, body: bytes):
        """Returns (secrets, ClientFinished). A ServerHello that does not verify raises HandshakeError and leaves this
        object unchanged, so the genuine one can still be processed afterwards; after success every further call is
        refused (the ephemeral KEM key is freed then: a duplicate ServerHello must never reach it again)."""
        if self.done:
            raise HandshakeError("handshake already completed")
        fl = SH_FIXED.size + X25519_LEN + self.suite.kem_ct_len
        if len(body) < fl + 2 + FIN_LEN:
            raise HandshakeError("malformed ServerHello")
        server_part = body[:fl]
        suite_id, session_id, nonce_s, gcs_id = SH_FIXED.unpack_from(server_part)
        if suite_id != self.suite.suite_id:
            raise HandshakeError("suite mismatch (possible downgrade)")
        x_s = server_part[SH_FIXED.size:SH_FIXED.size + X25519_LEN]
        ct = server_part[SH_FIXED.size + X25519_LEN:]
        (slen,) = struct.unpack_from("!H", body, fl)
        sig_s = body[fl + 2:fl + 2 + slen]
        fin_s = body[fl + 2 + slen:fl + 2 + slen + FIN_LEN]
        if len(fin_s) != FIN_LEN:
            raise HandshakeError("malformed ServerHello")
        th = ks.sha256(LBL_TH, self.signed, self.sig, server_part)
        if not idm.verify(self.suite.sig, LBL_SS + th, sig_s, self.gcs_pk):
            raise SignatureInvalid("GCS signature invalid (pinned key)")
        ss_k = bytearray(self._kem.decap_secret(ct))
        try:
            ss_x = bytearray(self._x.exchange(x25519.X25519PublicKey.from_public_bytes(x_s)))
        except ValueError:                       # a low-order point: X25519 would give an all-zero secret
            raise HandshakeError("X25519 public key rejected") from None
        ikm = bytearray(ss_k + ss_x)
        secrets = ks.derive_session(th, bytes(ikm), self.suite.suite_id, session_id)
        for b in (ss_k, ss_x, ikm):
            wipe(b)
        th2 = ks.sha256(th, sig_s)
        if not ct_equal(ks.hmac256(secrets.finished_server, th2), fin_s):
            secrets.wipe()
            raise HandshakeError("server Finished invalid")
        fin_c = ks.hmac256(secrets.finished_client, ks.sha256(th2, fin_s))
        self.handshake_ms = (time.perf_counter() - self.t_start) * 1000
        self.done = True
        self._kem.free()
        return secrets, session_id + fin_c


# --------------------------------------------------------------------- server
class ServerHandshake:
    def __init__(self, ident: idm.Identity, uav_pins: dict, suites=(1, 2), freshness_s: int = 120):
        self.ident = ident
        self.uav_pins = uav_pins            # uav_id(8 bytes) -> pinned ML-DSA pk
        self.suites = set(suites)
        self.freshness_ms = freshness_s * 1000
        self.seen_nonces = {}               # nonce -> expiry (ClientHello / rekey replay cache)
        self.pending = {}                   # session_id -> (secrets, expected fin_c, created)

    def _stale(self, ts_ms: int, nonce: bytes):
        """Why a message with this time stamp and nonce is not fresh, or None. Changes nothing: it may be asked about
        a message that has not been authenticated yet."""
        now = now_ms()
        for n in [n for n, exp in self.seen_nonces.items() if exp < now]:
            del self.seen_nonces[n]
        if nonce in self.seen_nonces:
            return "replayed message (nonce already seen)"
        if abs(now - ts_ms) > self.freshness_ms:
            return (f"time stamp is {abs(now - ts_ms) / 1000:.0f} s away from this clock (limit "
                    f"{self.freshness_ms // 1000} s): an old message, or the two clocks disagree")
        if len(self.seen_nonces) > 4096:
            return "replay cache full"
        return None

    def _fresh(self, ts_ms: int, nonce: bytes) -> bool:
        """True (and the nonce is remembered) if an AUTHENTICATED message is fresh. A nonce is kept for twice the
        freshness window, so it is still known for as long as its time stamp would be accepted."""
        if self._stale(ts_ms, nonce):
            return False
        self.seen_nonces[nonce] = now_ms() + 2 * self.freshness_ms
        return True

    def process_client_hello(self, body: bytes):
        if len(body) < CH_FIXED.size + 2:
            raise HandshakeError("malformed ClientHello")
        suite_id, uav_id, nonce_c, mobility, ts_ms = CH_FIXED.unpack_from(body)
        if suite_id not in self.suites:
            raise HandshakeError("unsupported suite")
        suite = get_suite(suite_id)
        fl = CH_FIXED.size + X25519_LEN + suite.kem_ek_len
        if len(body) < fl + 2:
            raise HandshakeError("malformed ClientHello")
        signed = body[:fl]
        (slen,) = struct.unpack_from("!H", body, fl)
        sig_c = body[fl + 2:fl + 2 + slen]
        pin = self.uav_pins.get(uav_id)
        if pin is None:
            raise HandshakeError("unknown UAV identity")
        # The cheap checks come before the signature: a replayed or old ClientHello (the only kind an outsider can
        # produce with a VALID signature) is refused without the cost of verifying it. Nothing is remembered yet.
        why = self._stale(ts_ms, nonce_c)
        if why:
            raise HandshakeError(f"ClientHello refused: {why}")
        if not idm.verify(suite.sig, LBL_CH + signed, sig_c, pin):
            raise SignatureInvalid("UAV signature invalid (pinned key)")
        if not self._fresh(ts_ms, nonce_c):
            raise HandshakeError("ClientHello refused: not fresh")
        x_c = signed[CH_FIXED.size:CH_FIXED.size + X25519_LEN]
        ek = signed[CH_FIXED.size + X25519_LEN:]
        xs = x25519.X25519PrivateKey.generate()
        kem = oqs.KeyEncapsulation(suite.kem)
        ct, ss_k = kem.encap_secret(ek)
        kem.free()
        try:
            ss_x = xs.exchange(x25519.X25519PublicKey.from_public_bytes(x_c))
        except ValueError:                       # a low-order point: X25519 would give an all-zero secret
            raise HandshakeError("X25519 public key rejected") from None
        session_id = os.urandom(8)
        nonce_s = os.urandom(32)
        server_part = SH_FIXED.pack(suite_id, session_id, nonce_s, self.ident.node_id) + _x25519_pub(xs) + ct
        th = ks.sha256(LBL_TH, signed, sig_c, server_part)
        sig_s = self.ident.sign(LBL_SS + th)
        ikm = bytearray(ss_k + ss_x)
        secrets = ks.derive_session(th, bytes(ikm), suite_id, session_id)
        wipe(ikm)
        th2 = ks.sha256(th, sig_s)
        fin_s = ks.hmac256(secrets.finished_server, th2)
        expected_fin_c = ks.hmac256(secrets.finished_client, ks.sha256(th2, fin_s))
        self._expire_pending()
        if len(self.pending) > 64:
            raise HandshakeError("too many half-open sessions")
        self.pending[session_id] = (secrets, expected_fin_c, time.monotonic(), uav_id, mobility, suite)
        return server_part + struct.pack("!H", len(sig_s)) + sig_s + fin_s

    def _expire_pending(self):
        now = time.monotonic()
        for sid in [s for s, v in self.pending.items() if now - v[2] > 10]:
            self.pending.pop(sid)[0].wipe()

    def process_client_finished(self, body: bytes):
        if len(body) != 8 + FIN_LEN:
            raise HandshakeError("malformed ClientFinished")
        sid, fin_c = body[:8], body[8:]
        entry = self.pending.get(sid)
        if entry is None:
            raise HandshakeError("unknown session")
        secrets, expected, _, uav_id, mobility, suite = entry
        if not ct_equal(fin_c, expected):
            raise HandshakeError("client Finished invalid")
        del self.pending[sid]
        return secrets, uav_id, mobility, suite


# ------------------------------------------------- 1-RTT Cached RapidRekey
class RekeyCache:
    """GCS-side cache of resumption secrets, keyed by UAV id."""

    def __init__(self, ttl_s: float):
        self.ttl = ttl_s
        self.entries = {}

    def put(self, uav_id, secrets: ks.SessionSecrets, mobility: bytes, suite_id: int):
        old = self.entries.get(uav_id)
        if old:
            wipe(old["resumption"])
        self.entries[uav_id] = {
            "resumption": bytearray(secrets.resumption), "auth": secrets.cached_rekey_auth,
            "mobility": mobility, "created": time.monotonic(), "sid": secrets.session_id, "suite": suite_id}

    def drop(self, uav_id):
        e = self.entries.pop(uav_id, None)
        if e:
            wipe(e["resumption"])


def build_rekey_request(uav_id: bytes, secrets: ks.SessionSecrets, mobility: bytes):
    nonce_c = os.urandom(32)
    fixed = RK_FIXED.pack(uav_id, secrets.session_id, mobility, nonce_c, now_ms())
    mac = ks.hmac256(secrets.cached_rekey_auth, LBL_RK_REQ + fixed)
    return fixed + mac


def server_process_rekey(cache: RekeyCache, server: ServerHandshake, body: bytes):
    """Returns (MSG_REKEY_RESP, body, new_secrets, uav_id) or (MSG_REKEY_REJECT, body, None, uav_id)."""
    if len(body) != RK_FIXED.size + 32:
        raise HandshakeError("malformed rekey request")
    uav_id, old_sid, mobility, nonce_c, ts_ms = RK_FIXED.unpack_from(body)
    fixed, mac = body[:RK_FIXED.size], body[RK_FIXED.size:]

    def reject(code):
        return MSG_REKEY_REJECT, uav_id + old_sid + bytes([code]), None, uav_id

    e = cache.entries.get(uav_id)
    if e is None or e["sid"] != old_sid:
        return reject(REJECT_MISS)
    if time.monotonic() - e["created"] > cache.ttl:
        cache.drop(uav_id)
        return reject(REJECT_STALE)
    # MAC first: an unauthenticated request must never change cache state.
    if not ct_equal(ks.hmac256(e["auth"], LBL_RK_REQ + fixed), mac):
        return reject(REJECT_AUTH)
    if not server._fresh(ts_ms, nonce_c):
        return reject(REJECT_AUTH)
    if e["mobility"] != mobility:
        cache.drop(uav_id)
        return reject(REJECT_STALE_MOBILITY)
    new_sid = os.urandom(8)
    nonce_s = os.urandom(32)
    th_r = ks.sha256(LBL_RK_TH, body, nonce_s, new_sid)
    new = ks.derive_session(th_r, bytes(e["resumption"]), e["suite"], new_sid)
    fin_s = ks.hmac256(new.finished_server, th_r)
    expected_fin_c = ks.hmac256(new.finished_client, ks.sha256(th_r, fin_s))
    suite = get_suite(e["suite"])
    cache.drop(uav_id)  # old resumption secret is deleted (one-way evolution)
    server.pending[new_sid] = (new, expected_fin_c, time.monotonic(), uav_id, mobility, suite)
    return MSG_REKEY_RESP, old_sid + new_sid + nonce_s + fin_s, new, uav_id


def client_process_rekey_resp(req_body: bytes, old: ks.SessionSecrets, body: bytes):
    if len(body) != 8 + 8 + 32 + 32:
        raise HandshakeError("malformed rekey response")
    old_sid, new_sid, nonce_s, fin_s = body[:8], body[8:16], body[16:48], body[48:]
    if old_sid != old.session_id:
        raise HandshakeError("rekey response for another session")
    th_r = ks.sha256(LBL_RK_TH, req_body, nonce_s, new_sid)
    new = ks.derive_session(th_r, bytes(old.resumption), old.suite_id, new_sid)
    if not ct_equal(ks.hmac256(new.finished_server, th_r), fin_s):
        new.wipe()
        raise HandshakeError("rekey Finished invalid")
    fin_c = ks.hmac256(new.finished_client, ks.sha256(th_r, fin_s))
    return new, new_sid + fin_c


# --------------------------------------------- PQ ratchet (FS + PCS rekey)
class PQRatchetInitiator:
    """Fresh ML-KEM + X25519 exchange mixed into the current master secret.

    Carried inside the already-authenticated control stream, so no signatures
    are needed. Unlike Cached RapidRekey this injects new ephemeral secrets,
    giving forward secrecy and post-compromise security for the new epoch.
    """

    def __init__(self, suite_id: int, rid: int):
        self.suite = get_suite(suite_id)
        self.rid = rid
        self._x = x25519.X25519PrivateKey.generate()
        self._kem = oqs.KeyEncapsulation(self.suite.kem)
        self.ek = self._kem.generate_keypair()
        self.x_pub = _x25519_pub(self._x)

    def finish(self, old: ks.SessionSecrets, x_s: bytes, ct: bytes, new_sid: bytes):
        ss_k = self._kem.decap_secret(ct)
        self._kem.free()
        ss_x = self._x.exchange(x25519.X25519PublicKey.from_public_bytes(x_s))
        return _pq_mix(old, self.rid, self.x_pub, self.ek, x_s, ct, new_sid, ss_k, ss_x)


def pq_ratchet_respond(old: ks.SessionSecrets, rid: int, x_c: bytes, ek: bytes):
    suite = get_suite(old.suite_id)
    xs = x25519.X25519PrivateKey.generate()
    kem = oqs.KeyEncapsulation(suite.kem)
    ct, ss_k = kem.encap_secret(ek)
    kem.free()
    ss_x = xs.exchange(x25519.X25519PublicKey.from_public_bytes(x_c))
    new_sid = os.urandom(8)
    x_s = _x25519_pub(xs)
    return x_s, ct, new_sid, _pq_mix(old, rid, x_c, ek, x_s, ct, new_sid, ss_k, ss_x)


def _pq_mix(old, rid, x_c, ek, x_s, ct, new_sid, ss_k, ss_x):
    th = ks.sha256(LBL_PQR, old.session_id, struct.pack("!I", rid), x_c, ek, x_s, ct, new_sid)
    ikm = bytearray(ss_k + ss_x + bytes(old.master))
    new = ks.derive_session(th, bytes(ikm), old.suite_id, new_sid)
    wipe(ikm)
    return new
