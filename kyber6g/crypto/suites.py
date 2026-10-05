"""Crypto-suite registry (algorithm agility).

Protocol code refers only to a suite id; algorithm names live here. The suite
id is carried in the handshake and bound into the transcript hash, so a
downgrade to a different suite is detected by the signature check.
"""
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305


@dataclass(frozen=True)
class Suite:
    suite_id: int
    name: str
    kem: str
    kem_ek_len: int
    kem_ct_len: int
    ecdh: str
    sig: str
    hash: str
    aead_name: str
    aead_cls: type
    key_len: int = 32
    tag_len: int = 16


SUITES = {
    0x0001: Suite(0x0001, "K6G-MLKEM1024-X25519-MLDSA87-HKDFSHA256-AES256GCM",
                  "ML-KEM-1024", 1568, 1568, "X25519", "ML-DSA-87", "SHA256",
                  "AES-256-GCM", AESGCM),
    0x0002: Suite(0x0002, "K6G-MLKEM1024-X25519-MLDSA87-HKDFSHA256-CHACHA20POLY1305",
                  "ML-KEM-1024", 1568, 1568, "X25519", "ML-DSA-87", "SHA256",
                  "ChaCha20-Poly1305", ChaCha20Poly1305),
}

DEFAULT_SUITE = 0x0001


def get_suite(suite_id: int) -> Suite:
    try:
        return SUITES[suite_id]
    except KeyError:
        raise ValueError(f"unsupported crypto suite 0x{suite_id:04x}") from None
