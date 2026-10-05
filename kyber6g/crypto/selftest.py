"""Self-test of the cryptography at start-up: a node that computes wrong, or whose key files do not belong
together, refuses to start instead of talking nonsense with a clear conscience.

What is checked (about 20 ms on the Pi), each against a published value or against itself:

  known answers     SHA-256, HMAC-SHA-256 and HKDF as written in keyschedule.py; AES-256-GCM and
                    ChaCha20-Poly1305 round trip + published GCM tag; X25519 (RFC 7748);
                    ML-KEM-1024 key generation from the seed of NIST's ACVP vector 51 (the keys' hashes are the
                    published ones: this is FIPS 203 as standardised, not a pre-standard Kyber)
  round trips       ML-KEM-1024 encapsulate / decapsulate, a damaged ciphertext gives ANOTHER secret (and no error:
                    implicit rejection); ML-DSA-87 sign / verify, a changed message and a changed signature are refused
  this node's keys  its ML-DSA-87 secret key signs and its own public-key file verifies; on the ground station the
                    two recording key pairs (ML-KEM-1024, X25519) fit together

What is NOT here: ML-DSA-87 known answers (they need the library's random bytes replaced, which a process that makes
real keys must never do) and the rest of NIST's vectors. Those run as their own program on both machines:
`python -m kyber6g.tools.pq_conformance` (150 ACVP vectors).
"""
import os
import time

import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from . import identity as idm
from . import keyschedule as ks

H = bytes.fromhex
# NIST ACVP, ML-KEM-keyGen-FIPS203, ML-KEM-1024, tcId 51 (the first of tests/data_acvp_fips203_204.json.gz)
KEM_D = H("F3A706FAF090C03DB506863AB0B20BD8A1627956318E88C67EB875E8E7266009")
KEM_Z = H("35D2BC43DD1CC879F765BF2A0C5E297889DDE910E57E2BB0EAE417B90AB7A275")
KEM_EK_SHA256 = "b78619e4fceeeb86dee3fedb945eca6da61dae312771ef8fa871951d391bd7b6"
KEM_DK_SHA256 = "925ed6f1cf0379ede29d8209432d6e08c73ed0423883febf85416343f4fa1f86"


class SelfTestFailed(RuntimeError):
    pass


def _symmetric():
    yield "SHA-256", ks.sha256(b"a", b"bc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    yield "HMAC-SHA-256", ks.hmac256(b"Jefe", b"what do ya want for nothing?").hex() == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
    prk = ks.hkdf_extract(H("000102030405060708090a0b0c"), H("0b" * 22))
    yield "HKDF-SHA-256", (prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5" and
                           ks.hkdf_expand(prk, H("f0f1f2f3f4f5f6f7f8f9"), 42).hex() ==
                           "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    gcm = AESGCM(bytes(32)).encrypt(bytes(12), bytes(16), None)
    yield "AES-256-GCM", (gcm.hex() == "cea7403d4d606b6e074ec5d3baf39d18" "d0d1c8a799996bf0265b98b5d48ab919" and
                          AESGCM(bytes(32)).decrypt(bytes(12), gcm, None) == bytes(16))
    key, nonce = os.urandom(32), os.urandom(12)
    box = ChaCha20Poly1305(key).encrypt(nonce, b"kyber6g", b"aad")
    yield "ChaCha20-Poly1305", ChaCha20Poly1305(key).decrypt(nonce, box, b"aad") == b"kyber6g" and _refuses(
        lambda: ChaCha20Poly1305(key).decrypt(nonce, box[:-1] + bytes([box[-1] ^ 1]), b"aad"))
    dh = x25519.X25519PrivateKey.from_private_bytes(H("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")).exchange(
        x25519.X25519PublicKey.from_public_bytes(H("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")))
    yield "X25519", dh.hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"


def _refuses(fn) -> bool:
    try:
        fn()
    except Exception:
        return True
    return False


def _post_quantum(kem_alg, sig_alg):
    kem = oqs.KeyEncapsulation(kem_alg)
    yield f"{kem_alg} is FIPS 203", kem.details.get("version") == "FIPS203" and kem.details.get("claimed_nist_level") == 5
    if kem_alg == "ML-KEM-1024":
        ek = kem.generate_keypair_seed(KEM_D + KEM_Z)
        yield "ML-KEM-1024 key generation (NIST vector)", (ks.sha256(ek).hex(), ks.sha256(kem.export_secret_key()).hex()) == (KEM_EK_SHA256, KEM_DK_SHA256)
    else:
        ek = kem.generate_keypair()
    ct, ss = oqs.KeyEncapsulation(kem_alg).encap_secret(ek)
    bad = ct[:7] + bytes([ct[7] ^ 0x20]) + ct[8:]
    yield f"{kem_alg} encapsulate / decapsulate", kem.decap_secret(ct) == ss
    yield f"{kem_alg} damaged ciphertext gives another secret", kem.decap_secret(bad) not in (ss, bytes(len(ss)))
    kem.free()
    sig = oqs.Signature(sig_alg)
    yield f"{sig_alg} is FIPS 204", sig.details.get("version") == "FIPS204" and sig.details.get("claimed_nist_level") == 5
    pk = sig.generate_keypair()
    msg = b"KYBER6G/selftest/v1|" + os.urandom(16)
    s = sig.sign(msg)
    yield f"{sig_alg} sign / verify", idm.verify(sig_alg, msg, s, pk)
    yield f"{sig_alg} refuses a changed message", not idm.verify(sig_alg, msg + b"x", s, pk)
    yield f"{sig_alg} refuses a changed signature", not idm.verify(sig_alg, msg, s[:40] + bytes([s[40] ^ 1]) + s[41:], pk)
    yield f"{sig_alg} refuses a key of the wrong size", not idm.verify(sig_alg, msg, s, pk[:-1])


def _own_keys(ident, rec_ek, rec_dk, rec_xpk, rec_xsk):
    if ident is not None:
        msg = b"KYBER6G/selftest/v1|" + os.urandom(16)       # its own label: never a protocol message
        yield "this node's identity key pair fits", idm.verify(ident.sig_alg, msg, ident.sign(msg), ident.pk)
    if rec_ek is not None and rec_dk is not None:
        ct, ss = oqs.KeyEncapsulation("ML-KEM-1024").encap_secret(idm.sized(rec_ek, "ML-KEM-1024", "public", "recording key"))
        yield "the ML-KEM-1024 recording key pair fits", oqs.KeyEncapsulation("ML-KEM-1024", secret_key=rec_dk).decap_secret(ct) == ss
    if rec_xpk is not None and rec_xsk is not None:
        pub = x25519.X25519PrivateKey.from_private_bytes(rec_xsk).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        yield "the X25519 recording key pair fits", pub == rec_xpk


def run(ident=None, rec_ek=None, rec_dk=None, rec_xpk=None, rec_xsk=None, kem_alg="ML-KEM-1024", sig_alg="ML-DSA-87") -> dict:
    """All checks; returns {"ok", "ms", "checks": [{"name", "ok"}], "failed": [names], "liboqs", "at"}. Never raises:
    an exception inside a check is that check's failure."""
    t0, checks = time.perf_counter(), []
    for label, gen in (("classical primitives", _symmetric()), ("post-quantum primitives", _post_quantum(kem_alg, sig_alg)),
                       ("this node's keys", _own_keys(ident, rec_ek, rec_dk, rec_xpk, rec_xsk))):
        while True:
            try:
                name, ok = next(gen)
            except StopIteration:
                break
            except Exception as e:                       # the check that was being computed: it failed, and so did the rest of its group
                checks.append({"name": f"{label}: {type(e).__name__}: {e}"[:120], "ok": False})
                break
            checks.append({"name": name, "ok": bool(ok)})
    failed = [c["name"] for c in checks if not c["ok"]]
    return {"ok": not failed, "ms": round((time.perf_counter() - t0) * 1000, 1), "checks": checks, "failed": failed,
            "liboqs": oqs.oqs_version(), "at": time.time()}


def require(**keys) -> dict:
    """`run`, and SelfTestFailed if anything failed: called once when a node starts."""
    res = run(**keys)
    if not res["ok"]:
        raise SelfTestFailed("cryptographic self-test FAILED: " + "; ".join(res["failed"]))
    return res


def summary(res: dict) -> dict:
    """What goes into a status message."""
    return {"ok": res["ok"], "checks": len(res["checks"]), "failed": res["failed"][:6], "ms": res["ms"], "liboqs": res["liboqs"], "at": res["at"]}
