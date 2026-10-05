"""Cryptographic bill of materials (CBOM) of this system, in CycloneDX 1.6 form.

    python -m kyber6g.tools.cbom [--out docs/CBOM.json]

An inventory of every cryptographic algorithm the system uses, with its parameter set, its standard, where it is
used and which library computes it - what the migration guidance of CISA / NIST asks every system to keep. It is
GENERATED from the code (the suite table, the labels of the file formats, the versions of the installed libraries),
and tests/test_pq.py fails if an algorithm named in the code is missing here or docs/CBOM.json is out of date.

Security levels: `nistQuantumSecurityLevel` is the category NIST assigns (FIPS 203 / 204) or, for symmetric
primitives, the category whose definition they are (AES-256 key search = 5; SHA-256 collision = 2, used here only
where second-preimage resistance is what counts - see docs/SECURITY_PROOFS.md section 2). X25519 has none: Shor's
algorithm breaks it, which is why it never stands alone. The object identifiers were entered by hand from the
standards; check them before relying on them elsewhere.
"""
import argparse
import json
import platform
import sys
import time
import uuid
from pathlib import Path


def algorithms():
    """name -> (primitive, parameter set, functions, classical bits, NIST quantum category, standard, OID, where used)"""
    return {
        "ML-KEM-1024": ("kem", "1024", ["keygen", "encapsulate", "decapsulate"], 256, 5, "FIPS 203", "2.16.840.1.101.3.4.4.3",
                        "session establishment and PQ ratchet (one-time keys); key wrap of stored photos, recordings and audio clips (the ground station's recording key)"),
        "X25519": ("key-agree", "Curve25519", ["keygen", "keyderive"], 128, 0, "RFC 7748", "1.3.101.110",
                   "the classical half of every key establishment and key wrap; never alone"),
        "ML-DSA-87": ("signature", "87", ["keygen", "sign", "verify"], 256, 5, "FIPS 204", "2.16.840.1.101.3.4.3.19",
                      "both ends of the handshake (pinned identity keys); every stored photo, recording and audio clip (the UAV's signature)"),
        "AES-256-GCM": ("ae", "256", ["encrypt", "decrypt", "tag"], 256, 5, "NIST SP 800-38D", "2.16.840.1.101.3.4.1.46",
                        "every record on the link (suite 0x0001); content and content-key wrap of every stored file; every audio block"),
        "ChaCha20-Poly1305": ("ae", "256", ["encrypt", "decrypt", "tag"], 256, 5, "RFC 8439", "1.2.840.113549.1.9.16.3.18",
                              "every record on the link when suite 0x0002 is configured (not the default)"),
        "HKDF-SHA-256": ("kdf", "SHA-256", ["keyderive"], 256, 5, "RFC 5869 / NIST SP 800-56C", "1.2.840.113549.1.9.16.3.28",
                         "session key schedule, epoch chains, key-encryption keys of stored files, the audio key tree's root"),
        "HMAC-SHA-256": ("mac", "SHA-256", ["tag"], 256, 5, "FIPS 198-1", "1.2.840.113549.2.9",
                         "Finished messages, cached-rekey request, the audio key tree (GGM) and block commitments"),
        "SHA-256": ("hash", "256", ["digest"], 128, 2, "FIPS 180-4", "2.16.840.1.101.3.4.2.1",
                    "transcript hashes, the digest a file signature covers, Merkle tree of audio blocks, key fingerprints"),
    }


def build() -> dict:
    import cryptography
    import oqs
    from cryptography.hazmat.backends.openssl import backend
    from ..crypto.suites import SUITES
    algs = algorithms()
    ref = lambda name: "crypto/algorithm/" + name.lower()
    comps = []
    for name, (prim, pset, funcs, classical, quantum, std, oid, where) in algs.items():
        comps.append({"type": "cryptographic-asset", "bom-ref": ref(name), "name": name, "description": where,
                      "cryptoProperties": {"assetType": "algorithm", "oid": oid, "algorithmProperties": {
                          "primitive": prim, "parameterSetIdentifier": pset, "executionEnvironment": "software-plain-ram",
                          "implementationPlatform": "generic", "certificationLevel": ["none"], "cryptoFunctions": funcs,
                          "classicalSecurityLevel": classical, "nistQuantumSecurityLevel": quantum}},
                      "properties": [{"name": "kyber6g:standard", "value": std}]})
    for s in SUITES.values():
        uses = [s.kem, s.ecdh, s.sig, "HKDF-SHA-256", "HMAC-SHA-256", "SHA-256", s.aead_name]
        comps.append({"type": "cryptographic-asset", "bom-ref": f"crypto/protocol/kyber6g-link/0x{s.suite_id:04x}", "name": s.name,
                      "description": "Kyber-6G link: full handshake (PQ/T hybrid key establishment, ML-DSA-87 on both sides), "
                                     "1-RTT Cached RapidRekey, PQ ratchet, AEAD records",
                      "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
                          "type": "other", "version": "1", "cipherSuites": [{"name": s.name, "algorithms": [ref(a) for a in uses],
                                                                             "identifiers": [f"0x{s.suite_id:04x}"]}]}}})
    for name, fmt, uses in (("sealed file, format 2 (.k6gimg, .k6grec)", "K6GIMG02 / K6GREC02 + K6GSIG01",
                             ["ML-KEM-1024", "X25519", "HKDF-SHA-256", "AES-256-GCM", "SHA-256", "ML-DSA-87"]),
                            ("sealed audio clip (.k6gaud) and excerpt (.k6gax)", "K6GAUD01 / K6GAEX01",
                             ["ML-KEM-1024", "X25519", "HKDF-SHA-256", "HMAC-SHA-256", "AES-256-GCM", "SHA-256", "ML-DSA-87"])):
        comps.append({"type": "cryptographic-asset", "bom-ref": "crypto/format/" + fmt.split()[0].lower(), "name": name, "description": fmt,
                      "cryptoProperties": {"assetType": "protocol", "protocolProperties": {
                          "type": "other", "version": "2" if "02" in fmt else "1",
                          "cipherSuites": [{"name": fmt, "algorithms": [ref(a) for a in uses]}]}}})
    libs = [("liboqs", oqs.oqs_version(), "ML-KEM-1024, ML-DSA-87"), ("liboqs-python", oqs.oqs_python_version(), "binding"),
            ("cryptography", cryptography.__version__, "X25519, AES-256-GCM, ChaCha20-Poly1305 (through OpenSSL)"),
            ("OpenSSL", backend.openssl_version_text().replace("OpenSSL ", ""), "backend of `cryptography`"),
            ("python-hashlib-hmac", platform.python_version(), "SHA-256, HMAC-SHA-256; HKDF is written on top of them in crypto/keyschedule.py")]
    for name, version, what in libs:
        comps.append({"type": "library", "bom-ref": "lib/" + name.lower(), "name": name, "version": version, "description": what})
    deps = [{"ref": "lib/liboqs", "provides": [ref("ML-KEM-1024"), ref("ML-DSA-87")]},
            {"ref": "lib/cryptography", "dependsOn": ["lib/openssl"], "provides": [ref("X25519"), ref("AES-256-GCM"), ref("ChaCha20-Poly1305")]},
            {"ref": "lib/python-hashlib-hmac", "provides": [ref("SHA-256"), ref("HMAC-SHA-256"), ref("HKDF-SHA-256")]}]
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:" + str(uuid.uuid4()), "version": 1,
            "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                         "component": {"type": "application", "name": "Kyber-6G secure UAV link", "version": "feature/multimodal-secure-hitl"},
                         "properties": [{"name": "kyber6g:generated-by", "value": "python -m kyber6g.tools.cbom"},
                                        {"name": "kyber6g:generated-on", "value": f"{platform.node()} ({platform.machine()})"},
                                        {"name": "kyber6g:classical-only-public-key-algorithms", "value": "none (X25519 is used only together with ML-KEM-1024)"}]},
            "components": comps, "dependencies": deps}


def main():
    ap = argparse.ArgumentParser(description="write the cryptographic bill of materials (CycloneDX 1.6)")
    ap.add_argument("--out", default=str(Path(__file__).resolve().parents[2] / "docs" / "CBOM.json"))
    a = ap.parse_args()
    bom = build()
    Path(a.out).write_text(json.dumps(bom, indent=1) + "\n")
    n = sum(c["type"] == "cryptographic-asset" for c in bom["components"])
    print(f"{a.out}: {n} cryptographic assets ({len(algorithms())} algorithms), {len(bom['components']) - n} libraries")
    return 0


if __name__ == "__main__":
    sys.exit(main())
