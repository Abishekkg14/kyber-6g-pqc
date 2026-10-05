"""Does the cryptography this machine actually runs compute what the standards say?

    python -m kyber6g.tools.pq_conformance [--json FILE]

  * NIST's ACVP test vectors for FIPS 203 (ML-KEM-1024) and FIPS 204 (ML-DSA-87) through the installed liboqs: key
    generation from a seed, encapsulation with given coins, decapsulation (including ciphertexts that were tampered
    with: the "implicit rejection" answer must be the published one), the checks of FIPS 203 section 7 on
    encapsulation and decapsulation keys, signing (deterministic and hedged, with context) and verification (valid
    signatures and four kinds of damaged ones). The vectors are tests/data_acvp_fips203_204.json.gz; that file says
    where they come from.
  * Published vectors for the classical parts, through the functions this project calls: X25519 (RFC 7748), HKDF
    (RFC 5869) and HMAC (RFC 4231) as written in crypto/keyschedule.py, SHA-256, AES-256-GCM (the GCM specification).

Key generation and signing draw random bytes inside liboqs. For those known-answer tests liboqs is told, for the
duration of one call, to take its "random" bytes from the vector (OQS_randombytes_custom_algorithm), and is switched
back to the system's generator before anything else happens; the tool then checks that fresh keys differ again.
This must never be done in a process that also makes real keys, which is why it lives here and not in the unit
tests that run next to other code: run it as its own program.

A pass says that the library on THIS machine implements the final standards (not a pre-standard Kyber or Dilithium)
bit for bit on these inputs. It says nothing about side channels and is not a FIPS 140-3 validation.
"""
import argparse
import ctypes
import gzip
import hashlib
import json
import os
import platform
import sys
import time
from pathlib import Path

VECTORS = Path(__file__).resolve().parents[2] / "tests" / "data_acvp_fips203_204.json.gz"
KEM, SIG = "ML-KEM-1024", "ML-DSA-87"
sha = lambda b: hashlib.sha256(b).hexdigest()
H = bytes.fromhex


class FixedRandom:
    """liboqs takes its random bytes from `feed` while this is entered (see the module's note)."""
    CALLBACK = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t)

    def __init__(self, lib):
        self.lib, self.feed, self.asked, self.short = lib, b"", [], False
        self._cb = self.CALLBACK(self._fill)             # kept alive as long as liboqs may call it

    def _fill(self, buf, n):
        chunk, self.feed = self.feed[:n], self.feed[n:]
        self.asked.append(n)
        if len(chunk) < n:
            self.short = True
            chunk += bytes(n - len(chunk))
        ctypes.memmove(buf, chunk, n)

    def __enter__(self):
        self.lib.OQS_randombytes_custom_algorithm(self._cb)
        return self

    def __exit__(self, *exc):
        if self.lib.OQS_randombytes_switch_algorithm(b"system") != 0:
            os._exit(3)                                  # never go on with a generator that is not the system's
        return False


class Report:
    def __init__(self):
        self.groups = []

    def group(self, name, what, cases):
        """cases: iterable of (id, passed, note-or-None)."""
        cases = list(cases)
        failed = [{"id": i, "note": n} for i, ok, n in cases if not ok]
        self.groups.append({"name": name, "what": what, "vectors": len(cases), "passed": len(cases) - len(failed), "failed": failed[:10]})
        print(f"{'PASS' if not failed else 'FAIL'}  {name:36s} {len(cases) - len(failed):3d} of {len(cases):3d}   {what}"
              + (f"   FAILED: {failed[:4]}" if failed else ""), flush=True)


def guard(fn):
    """One vector must not end the run: an exception is that vector's failure."""
    try:
        return fn()
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"[:120]


def fips203(V, rep, oqs):
    lib = oqs.native()

    def keygen(t):
        k = oqs.KeyEncapsulation(KEM)
        ek = k.generate_keypair_seed(H(t["d"]) + H(t["z"]))
        return (sha(ek), sha(k.export_secret_key())) == (t["ek_sha256"], t["dk_sha256"]), None
    rep.group("ML-KEM-1024 keyGen", "seed (d, z) -> encapsulation and decapsulation key", [(t["tc"], *guard(lambda: keygen(t))) for t in V["mlkem_keygen"]])

    def encap(t, want_ok=None):
        k = oqs.KeyEncapsulation(KEM)
        c = k._kem.contents
        ek, m = H(t["ek"]), H(t.get("m", "00" * 32))
        if len(ek) != c.length_public_key:
            return False, "key length"
        ct, ss = ctypes.create_string_buffer(c.length_ciphertext), ctypes.create_string_buffer(c.length_shared_secret)
        rv = lib.OQS_KEM_encaps_derand(k._kem, ctypes.byref(ct), ctypes.byref(ss), ctypes.create_string_buffer(ek, len(ek)), ctypes.create_string_buffer(m, len(m)))
        if want_ok is not None:                          # a key check: only whether the key is taken
            return (rv == 0) == want_ok, None if (rv == 0) == want_ok else f"encapsulation {'accepted' if rv == 0 else 'refused'} this key"
        return rv == 0 and (sha(bytes(ct)), bytes(ss).hex()) == (t["c_sha256"], t["k"].lower()), None
    rep.group("ML-KEM-1024 encapsulation", "key, coins m -> ciphertext, shared secret", [(t["tc"], *guard(lambda: encap(t))) for t in V["mlkem_encap"]])

    def decap(t):
        k = oqs.KeyEncapsulation(KEM, secret_key=H(t["dk"]))
        return k.decap_secret(H(t["c"])).hex() == t["k"].lower(), t.get("reason")
    rep.group("ML-KEM-1024 decapsulation", "valid and modified ciphertexts -> shared secret (implicit rejection)",
              [(t["tc"], *guard(lambda: decap(t))) for t in V["mlkem_decap"]])

    rep.group("ML-KEM-1024 encapsulation key check", "FIPS 203 7.2: a key with a coefficient out of range must be refused",
              [(t["tc"], *guard(lambda: encap(t, want_ok=t["passed"]))) for t in V["mlkem_ek_check"]])

    def dk_check(t):
        try:
            oqs.KeyEncapsulation(KEM, secret_key=H(t["dk"])).decap_secret(bytes(1568))
            taken = True
        except RuntimeError:
            taken = False
        return taken == t["passed"], None if taken == t["passed"] else f"decapsulation {'accepted' if taken else 'refused'} this key ({t.get('reason')})"
    rep.group("ML-KEM-1024 decapsulation key check", "FIPS 203 7.3: a key whose stored hash does not fit must be refused",
              [(t["tc"], *guard(lambda: dk_check(t))) for t in V["mlkem_dk_check"]])


def fips204(V, rep, oqs):
    rnd = FixedRandom(oqs.native())
    drawn = {}

    def keygen(t):
        s = oqs.Signature(SIG)
        rnd.feed, rnd.asked, rnd.short = H(t["seed"]), [], False
        with rnd:
            pk = s.generate_keypair()
        drawn["keyGen"] = list(rnd.asked)
        return (sha(pk), sha(s.export_secret_key())) == (t["pk_sha256"], t["sk_sha256"]) and not rnd.short, None
    rep.group("ML-DSA-87 keyGen", "seed -> public and secret key", [(t["tc"], *guard(lambda: keygen(t))) for t in V["mldsa_keygen"]])

    def siggen(t):
        s = oqs.Signature(SIG, secret_key=H(t["sk"]))
        rnd.feed, rnd.asked, rnd.short = H(t["rnd"]) if t["rnd"] else bytes(32), [], False      # deterministic = rnd of 32 zero bytes (FIPS 204)
        with rnd:
            sig = s.sign_with_ctx_str(H(t["message"]), H(t["context"]))
        drawn["sigGen"] = list(rnd.asked)
        return sha(sig) == t["signature_sha256"] and not rnd.short, "hedged" if t["rnd"] else "deterministic"
    rep.group("ML-DSA-87 sigGen", "secret key, message, context, rnd -> signature (15 deterministic, 15 hedged)",
              [(t["tc"], *guard(lambda: siggen(t))) for t in V["mldsa_siggen"]])

    def sigver(t):
        got = oqs.Signature(SIG).verify_with_ctx_str(H(t["message"]), H(t["signature"]), H(t["context"]), H(t["pk"]))
        return bool(got) == t["passed"], t.get("reason")
    rep.group("ML-DSA-87 sigVer", "valid signatures, and message / commitment / z / hint modified -> accept or refuse",
              [(t["tc"], *guard(lambda: sigver(t))) for t in V["mldsa_sigver"]])

    # the system's generator is back: two fresh keys must differ, from each other and from every seeded one
    a, b = oqs.KeyEncapsulation(KEM).generate_keypair(), oqs.KeyEncapsulation(KEM).generate_keypair()
    c, d = oqs.Signature(SIG).generate_keypair(), oqs.Signature(SIG).generate_keypair()
    rep.group("random generator restored", "after the seeded tests liboqs draws from the system again",
              [("ML-KEM", a != b, None), ("ML-DSA", c != d and sha(c) not in {t["pk_sha256"] for t in V["mldsa_keygen"]}, None)])
    return drawn


def classical(rep):
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from ..crypto import keyschedule as ks

    def dh(sk, pk):
        return x25519.X25519PrivateKey.from_private_bytes(H(sk)).exchange(x25519.X25519PublicKey.from_public_bytes(H(pk))).hex()
    alice = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    bob = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    apub = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    bpub = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    rep.group("X25519", "RFC 7748 section 6.1, both directions",
              [("alice", *guard(lambda: (dh(alice, bpub) == shared, None))), ("bob", *guard(lambda: (dh(bob, apub) == shared, None)))])

    def hkdf(ikm, salt, info, n, prk, okm):
        p = ks.hkdf_extract(H(salt), H(ikm))
        return p.hex() == prk and ks.hkdf_expand(p, H(info), n).hex() == okm, None
    rep.group("HKDF-SHA-256 (crypto/keyschedule.py)", "RFC 5869 A.1 and A.3 (no salt, no info)", [
        ("A.1", *guard(lambda: hkdf("0b" * 22, "000102030405060708090a0b0c", "f0f1f2f3f4f5f6f7f8f9", 42,
                                    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                                    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"))),
        ("A.3", *guard(lambda: hkdf("0b" * 22, "", "", 42, "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                                    "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")))])
    rep.group("HMAC-SHA-256 (crypto/keyschedule.py)", "RFC 4231 test cases 1 and 2", [
        ("1", ks.hmac256(H("0b" * 20), b"Hi There").hex() == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", None),
        ("2", ks.hmac256(b"Jefe", b"what do ya want for nothing?").hex() == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", None)])
    rep.group("SHA-256 (crypto/keyschedule.py)", "FIPS 180-4 \"abc\", given in two pieces",
              [("abc", ks.sha256(b"a", b"bc").hex() == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", None)])

    def gcm(key, iv, pt, aad, ct, tag):
        out = AESGCM(H(key)).encrypt(H(iv), H(pt), H(aad) or None)
        return out.hex() == ct + tag and AESGCM(H(key)).decrypt(H(iv), out, H(aad) or None).hex() == pt, None
    k16 = "feffe9928665731c6d6a8f9467308308" * 2
    p16 = ("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525"
           "b16aedf5aa0de657ba637b39")
    c16 = ("522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa8cb08e48590dbb3da7b08b1056828838"
           "c5f61e6393ba7a0abcc9f662")
    rep.group("AES-256-GCM", "GCM specification (McGrew, Viega) test cases 13, 14 and 16", [
        ("13", *guard(lambda: gcm("00" * 32, "00" * 12, "", "", "", "530f8afbc74536b9a963b4f1c4cb738b"))),
        ("14", *guard(lambda: gcm("00" * 32, "00" * 12, "00" * 16, "", "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"))),
        ("16", *guard(lambda: gcm(k16, "cafebabefacedbaddecaf888", p16, "feedfacedeadbeeffeedfacedeadbeefabaddad2", c16,
                                  "76fc6ece0f4e1768cddf8853bb2d551b")))])


def main():
    ap = argparse.ArgumentParser(description="known-answer tests of the cryptography in use on this machine")
    ap.add_argument("--json", help="write the result here")
    a = ap.parse_args()
    import cryptography
    import oqs
    from cryptography.hazmat.backends.openssl import backend
    V = json.loads(gzip.decompress(VECTORS.read_bytes()))
    rep, t0 = Report(), time.perf_counter()
    kem, sig = oqs.KeyEncapsulation(KEM), oqs.Signature(SIG)
    print(f"{platform.node()} ({platform.machine()}), liboqs {oqs.oqs_version()}, {KEM} as \"{kem.details['version']}\", "
          f"{SIG} as \"{sig.details['version']}\", cryptography {cryptography.__version__} / {backend.openssl_version_text()}")
    fips203(V, rep, oqs)
    drawn = fips204(V, rep, oqs)
    classical(rep)
    total, passed = sum(g["vectors"] for g in rep.groups), sum(g["passed"] for g in rep.groups)
    acvp = sum(g["vectors"] for g in rep.groups if g["name"].startswith("ML-") and "check" not in g["name"])
    out = {"what": "known-answer tests of the cryptography in use", "when": time.strftime("%Y-%m-%d %H:%M:%S %Z"),
           "machine": {"node": platform.node(), "arch": platform.machine(), "system": platform.platform(), "python": platform.python_version()},
           "liboqs": oqs.oqs_version(), "liboqs_python": oqs.oqs_python_version(),
           "algorithms": {KEM: kem.details, SIG: sig.details}, "cryptography": cryptography.__version__, "openssl": backend.openssl_version_text(),
           "vectors_source": V["source"], "vectors_selection": V["selection"], "vectors_sha256": sha(VECTORS.read_bytes()),
           "random_bytes_drawn_by_liboqs": drawn, "groups": rep.groups, "vectors": total, "passed": passed, "all_passed": passed == total,
           "seconds": round(time.perf_counter() - t0, 2)}
    print(f"{'ALL PASS' if passed == total else 'FAILURES'}: {passed} of {total} vectors in {out['seconds']} s "
          f"(liboqs drew {drawn.get('keyGen')} bytes for an ML-DSA key and {drawn.get('sigGen')} for a signature)")
    if a.json:
        Path(a.json).write_text(json.dumps(out, indent=1) + "\n")
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
