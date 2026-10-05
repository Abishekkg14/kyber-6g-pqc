"""HKDF-SHA256 key schedule with explicit context separation.

Every derived key uses an info string of the form
    b"KYBER6G/<purpose>/v1|" + suite_id(2) + session_id(8) [+ extra]
so keys for different purposes, directions, sessions and suites are
independent outputs of the PRF.
"""
import hashlib
import hmac
import struct

from .secure_bytes import wipe

HASH_LEN = 32

# Stream / purpose identifiers carried in every record header.
STREAM_CONTROL = 1
STREAM_TELEMETRY = 2
STREAM_IMAGE = 3
STREAM_VIDEO = 4
STREAM_RECORDING = 5
STREAM_STATUS = 6
STREAM_AUDIO = 7

STREAM_NAMES = {
    STREAM_CONTROL: "control",
    STREAM_TELEMETRY: "telemetry",
    STREAM_IMAGE: "image",
    STREAM_VIDEO: "video",
    STREAM_RECORDING: "recording",
    STREAM_STATUS: "status",
    STREAM_AUDIO: "audio",
}

DIR_U2G = "uav-to-gcs"
DIR_G2U = "gcs-to-uav"


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt or b"\x00" * HASH_LEN, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def label(purpose: str, suite_id: int, session_id: bytes, extra: bytes = b"") -> bytes:
    return b"KYBER6G/" + purpose.encode() + b"/v1|" + struct.pack("!H", suite_id) + session_id + extra


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def hmac256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


class SessionSecrets:
    """All secrets of one session, derived from a PRK bound to the transcript."""

    def __init__(self, prk: bytes, suite_id: int, session_id: bytes):
        self.suite_id = suite_id
        self.session_id = session_id
        L = lambda p: label(p, suite_id, session_id)
        self.master = bytearray(hkdf_expand(prk, L("master")))
        self.finished_server = hkdf_expand(prk, L("finished/server"))
        self.finished_client = hkdf_expand(prk, L("finished/client"))
        self.resumption = bytearray(hkdf_expand(bytes(self.master), L("resumption")))
        self.cached_rekey_auth = hkdf_expand(bytes(self.resumption), L("cached-rekey/auth"))

    def chain_key(self, stream: int, direction: str) -> bytearray:
        info = label(f"{STREAM_NAMES[stream]}/{direction}/chain", self.suite_id, self.session_id)
        return bytearray(hkdf_expand(bytes(self.master), info))

    def wipe(self):
        wipe(self.master)
        wipe(self.resumption)


def derive_session(transcript_hash: bytes, ikm: bytes, suite_id: int, session_id: bytes) -> SessionSecrets:
    prk = hkdf_extract(transcript_hash, ikm)
    return SessionSecrets(prk, suite_id, session_id)


class EpochChain:
    """One-way symmetric chain: chain_{e+1} = H(chain_e), key_e = H'(chain_e).

    Advancing deletes the previous chain value, so compromise of the current
    state does not reveal keys of earlier epochs (forward secrecy within the
    session, under the assumption that deleted values are gone).
    """

    def __init__(self, chain0: bytearray):
        self.epoch = 0
        self._chain = chain0

    def key(self) -> bytes:
        return hkdf_expand(bytes(self._chain), b"KYBER6G/epoch-key/v1" + struct.pack("!I", self.epoch))

    def advance(self):
        nxt = bytearray(hkdf_expand(bytes(self._chain), b"KYBER6G/epoch-chain/v1" + struct.pack("!I", self.epoch)))
        wipe(self._chain)
        self._chain = nxt
        self.epoch += 1

    def wipe(self):
        wipe(self._chain)
