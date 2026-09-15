"""
Kyber-6G Canonical Protocol Module
===================================
Single source of truth for protocol constants, transcript construction,
and algorithm identifiers. All servers and clients MUST import from here
to prevent transcript/signature drift (ref: P0-4, P0-5 discrepancy report).
"""
import struct

# ── Protocol Constants ──
PROTOCOL_VERSION = b"\x01"
SIG_ALG = "ML-DSA-87"
KEM_ALG = "ML-KEM-1024"
ECDH_ALG = "X25519"
CIPHER_ALG = "AES-256-GCM"

# ── NIST Level-5 Wire Sizes (bytes) ──
MLKEM1024_PK_SIZE = 1568
MLKEM1024_CT_SIZE = 1568
MLKEM1024_SS_SIZE = 32
X25519_PK_SIZE = 32
MLDSA87_SIG_MAX_SIZE = 4627

# ── Message Types ──
MSG_HANDSHAKE_REQ = 0x01
MSG_HANDSHAKE_RESP = 0x02
MSG_CACHED_REKEY_REQ = 0x03
MSG_CACHED_REKEY_RESP = 0x04
MSG_C2_COMMAND = 0x08
MSG_C2_ACK = 0x09

# ── Fragment Limits ──
MAX_FRAGMENTS = 64
TRANSPORT_MTU = 1352


def build_auth_transcript(ue_id: bytes, mobility_hash: int,
                          pk_ecdh: bytes, pk_kem: bytes) -> bytes:
    """
    Build the canonical byte string that is signed by the UAV and
    verified by the server. This MUST be identical on both sides.

    Format: ue_id (8B) || mobility_hash (4B big-endian) || X25519_pk (32B) || ML-KEM_pk (1568B)
    """
    return ue_id + struct.pack("!I", mobility_hash) + pk_ecdh + pk_kem


def parse_handshake_request(payload: bytes):
    """
    Parse a MSG_HANDSHAKE_REQ (0x01) payload into named fields.

    Returns dict with keys: ue_id, mobility_hash, pk_ecdh, pk_kem,
                             sig_len, drone_sig, drone_sig_pk
    """
    ue_id = payload[:8]
    mobility_hash = struct.unpack("!I", payload[8:12])[0]
    pk_ecdh = payload[12:44]
    pk_kem = payload[44:1612]
    sig_len = struct.unpack("!H", payload[1612:1614])[0]
    drone_sig = payload[1614:1614 + sig_len]
    drone_sig_pk = payload[1614 + sig_len:]
    return {
        "ue_id": ue_id,
        "mobility_hash": mobility_hash,
        "pk_ecdh": pk_ecdh,
        "pk_kem": pk_kem,
        "sig_len": sig_len,
        "drone_sig": drone_sig,
        "drone_sig_pk": drone_sig_pk,
    }


def validate_fragment_bounds(frag_idx: int, total_frags: int) -> bool:
    """
    Validate fragment index and total count against protocol limits.
    Returns True if valid, False if the fragment should be dropped.
    """
    if total_frags == 0 or total_frags > MAX_FRAGMENTS:
        return False
    if frag_idx >= total_frags:
        return False
    return True
