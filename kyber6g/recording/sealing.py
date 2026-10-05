"""Key wrapping and signing shared by stored photos (.k6gimg) and recordings (.k6grec), file format 2.

Format 1 wrapped the content key with ML-KEM-1024 alone and carried no signature. Format 2 applies the link's own
rule - never rest on one assumption, and say who you are - to the files as well:

  hybrid key wrap   The content key is wrapped under a key derived from BOTH an ML-KEM-1024 encapsulation and an
                    X25519 exchange with a key made for this one file. Reading a file needs both secret keys of the
                    ground station; breaking one of the two schemes is not enough (as in the handshake).
  signature         The UAV signs SHA-256 of the whole file with its ML-DSA-87 identity key, the one the ground
                    station has pinned. The file now proves its origin: with format 1, anyone who knew the ground
                    station's PUBLIC recording key could write a file that decrypted and authenticated.

    ct, ss_k = ML-KEM-1024.Encaps(ek)             xe = new X25519 key;  ss_x = X25519(xe, ground station's x_pk)
    KEK      = HKDF(salt = SHA-256(header_json || ct || xe_pub), ikm = ss_k || ss_x, info = label || file id)
    wrapped  = AES-256-GCM(KEK, nonce 0, CEK, aad = magic || header_json || ct || xe_pub)     (the KEK is used once)
    trailer  = "K6GSIG01" | u16 len | ML-DSA-87("KYBER6G/at-rest/sig/v1|" kind "|" || SHA-256(every byte before it))

The UAV keeps none of ss_k, ss_x, xe, KEK or CEK after the file is closed: it cannot read its own files back.
"""
import hashlib
import os
import struct

import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ..crypto import identity as idm
from ..crypto import keyschedule as ks
from ..crypto.secure_bytes import wipe

KEM_CT = 1568                 # ML-KEM-1024 ciphertext
X_LEN = 32                    # X25519 public key
WRAPPED = 48                  # 32-byte content key + 16-byte tag
SIG_MAGIC = b"K6GSIG01"
SIG_LABEL = b"KYBER6G/at-rest/sig/v1|"
KEM_NAME, HYBRID_NAME = "ML-KEM-1024", "ML-KEM-1024+X25519"


class SealError(Exception):
    """A key block that does not open, or a signature that is missing or wrong."""


def _kek(label: bytes, file_id: bytes, header_json: bytes, kem_ct: bytes, xe_pub: bytes, ss: bytes) -> bytes:
    prk = ks.hkdf_extract(ks.sha256(header_json, kem_ct, xe_pub), ss)
    return ks.hkdf_expand(prk, label + file_id)


def wrap(magic: bytes, label: bytes, file_id: bytes, header_json: bytes, ek: bytes, x_pk: bytes = None,
         kem_alg: str = KEM_NAME):
    """A new content key and the key block that carries it: (cek, block). `x_pk` given: the hybrid wrap of format 2
    (block = ct | xe_pub | wrapped); not given: ML-KEM alone, as in format 1 (block = ct | wrapped). The caller wipes
    `cek` when it is done with it."""
    kem = oqs.KeyEncapsulation(kem_alg)
    # the exact size first: the binding would fill a short key with zeros and encapsulate to a key nobody holds
    ct, ss_k = kem.encap_secret(idm.sized(ek, kem_alg, "public", "recording key"))
    kem.free()
    if x_pk is not None and len(x_pk) != X_LEN:
        raise ValueError(f"recording key: {len(x_pk)} bytes is not an X25519 public key ({X_LEN} bytes)")
    xe_pub, ikm = b"", bytearray(ss_k)
    if x_pk is not None:
        xe = x25519.X25519PrivateKey.generate()
        xe_pub = xe.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        ikm += xe.exchange(x25519.X25519PublicKey.from_public_bytes(x_pk))
    cek = bytearray(os.urandom(32))
    kek = bytearray(_kek(label, file_id, header_json, ct, xe_pub, bytes(ikm)))
    wrapped = AESGCM(bytes(kek)).encrypt(b"\x00" * 12, bytes(cek), magic + header_json + ct + xe_pub)
    wipe(kek); wipe(ikm)
    return cek, ct + xe_pub + wrapped


def block_len(hybrid: bool) -> int:
    return KEM_CT + (X_LEN if hybrid else 0) + WRAPPED


def unwrap(magic: bytes, label: bytes, file_id: bytes, header_json: bytes, block: bytes, dk: bytes, x_sk: bytes = None,
           kem_alg: str = KEM_NAME) -> bytes:
    """The content key out of a key block. Raises SealError if the block is not for these keys or was changed."""
    hybrid = x_sk is not None
    if len(block) != block_len(hybrid):
        raise SealError("truncated key block")
    ct = block[:KEM_CT]
    xe_pub = block[KEM_CT:KEM_CT + X_LEN] if hybrid else b""
    wrapped = block[-WRAPPED:]
    try:
        kem = oqs.KeyEncapsulation(kem_alg, secret_key=dk)
        ikm = bytearray(kem.decap_secret(ct))
        kem.free()
        if hybrid:
            ikm += x25519.X25519PrivateKey.from_private_bytes(x_sk).exchange(x25519.X25519PublicKey.from_public_bytes(xe_pub))
    except Exception as e:                       # liboqs refuses the key or the ciphertext; X25519 a low-order point
        raise SealError(f"key decapsulation failed: {type(e).__name__}") from None
    kek = _kek(label, file_id, header_json, ct, xe_pub, bytes(ikm))
    wipe(ikm)
    try:
        return AESGCM(kek).decrypt(b"\x00" * 12, wrapped, magic + header_json + ct + xe_pub)
    except Exception:
        raise SealError("content key unwrap failed (wrong ground-station key, or header changed)") from None


def signer_fields(signer) -> dict:
    """What a signed file says about its signature, in its (authenticated) header."""
    if signer is None:
        return {"sig": None}
    return {"sig": signer.sig_alg, "signer": signer.node_id.decode("ascii", "replace"), "signer_fp": signer.fingerprint}


def sign_trailer(kind: bytes, digest: bytes, signer) -> bytes:
    sig = signer.sign(SIG_LABEL + kind + b"|" + digest)
    return SIG_MAGIC + struct.pack("!H", len(sig)) + sig


def trailer_len(hdr: dict, sig_alg: str = "ML-DSA-87") -> int:
    """Length of the signature trailer a header announces: 0 for an unsigned file. The header is not trusted for
    it: the only signature accepted is `sig_alg` (the algorithm of the pinned identity keys), at its own length."""
    if not isinstance(hdr, dict) or not hdr.get("sig"):
        return 0
    if hdr.get("sig") != sig_alg:
        raise SealError("unsupported signature algorithm in the header")
    return 10 + oqs.Signature(sig_alg).length_signature


def check_trailer(kind: bytes, signed_part: bytes, trailer: bytes, hdr: dict, signer_pk: bytes = None,
                  sig_alg: str = "ML-DSA-87") -> str:
    """Verdict on the signature of a format-2 file: "PASS"; "NOT CHECKED" when no signer key was given; "ABSENT"
    for an unsigned file when none is required. Raises SealError when a signer key is given and the signature is
    missing, cut short or wrong. `signed_part` is every byte of the file before the trailer."""
    n = trailer_len(hdr, sig_alg)
    if n == 0:
        if signer_pk is not None:
            raise SealError("unsigned file where the UAV's signature is required")
        return "ABSENT"
    if len(trailer) < n or trailer[:8] != SIG_MAGIC or struct.unpack_from("!H", trailer, 8)[0] != n - 10:
        raise SealError("signature missing or cut short")
    if signer_pk is None:
        return "NOT CHECKED"
    digest = hashlib.sha256(signed_part).digest()
    if not idm.verify(sig_alg, SIG_LABEL + kind + b"|" + digest, trailer[10:n], signer_pk):
        raise SealError("signature invalid: not written by the pinned UAV key, or changed afterwards")
    return "PASS"
