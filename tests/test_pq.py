"""The post-quantum part, held to its standards: which library versions run, that both halves of every hybrid are
needed, that nothing signed can be taken for something else, that keys of the wrong size never reach the library, the
self-test at start-up, and a part of NIST's vectors (all of them run in `python -m kyber6g.tools.pq_conformance`)."""
import gzip
import hashlib
import inspect
import json
import os
import struct
import tempfile
import unittest
from pathlib import Path

import oqs
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from kyber6g.crypto import handshake as hs
from kyber6g.crypto import identity as idm
from kyber6g.crypto import keyschedule as ks
from kyber6g.crypto import selftest
from kyber6g.crypto.suites import SUITES
from kyber6g.recording import sealing

UAV_ID, GCS_ID = b"UAV-ALPH", b"GCS-MEC1"
VECTORS = Path(__file__).with_name("data_acvp_fips203_204.json.gz")


def identities():
    d = Path(tempfile.mkdtemp())
    upk, gpk = idm.generate_identity(d, "uav"), idm.generate_identity(d, "gcs")
    return d, idm.load_identity(d, "uav", UAV_ID), idm.load_identity(d, "gcs", GCS_ID), upk, gpk


class TestStandards(unittest.TestCase):
    def test_the_library_implements_the_final_standards_at_category_5(self):
        kem, sig = oqs.KeyEncapsulation("ML-KEM-1024").details, oqs.Signature("ML-DSA-87").details
        self.assertEqual((kem["version"], kem["claimed_nist_level"], kem["is_ind_cca"]), ("FIPS203", 5, True))
        self.assertEqual((kem["length_public_key"], kem["length_secret_key"], kem["length_ciphertext"], kem["length_shared_secret"]),
                         (1568, 3168, 1568, 32))
        self.assertEqual((sig["version"], sig["claimed_nist_level"], sig["is_euf_cma"]), ("FIPS204", 5, True))
        self.assertEqual((sig["length_public_key"], sig["length_secret_key"], sig["length_signature"]), (2592, 4896, 4627))

    def test_every_suite_is_the_same_post_quantum_pair(self):
        """Algorithm agility is in the AEAD only: whichever suite is negotiated, key establishment and signatures
        are ML-KEM-1024 + X25519 and ML-DSA-87. There is nothing weaker to be talked down to."""
        self.assertEqual({(s.kem, s.ecdh, s.sig, s.hash, s.key_len) for s in SUITES.values()},
                         {("ML-KEM-1024", "X25519", "ML-DSA-87", "SHA256", 32)})
        self.assertEqual({s.aead_name for s in SUITES.values()}, {"AES-256-GCM", "ChaCha20-Poly1305"})

    @unittest.skipUnless(VECTORS.is_file(), "NIST vector file not present")
    def test_nist_vectors_that_need_no_random_bytes(self):
        v = json.loads(gzip.decompress(VECTORS.read_bytes()))
        sha, h = lambda b: hashlib.sha256(b).hexdigest(), bytes.fromhex
        for t in v["mlkem_keygen"]:
            k = oqs.KeyEncapsulation("ML-KEM-1024")
            ek = k.generate_keypair_seed(h(t["d"]) + h(t["z"]))
            self.assertEqual((sha(ek), sha(k.export_secret_key())), (t["ek_sha256"], t["dk_sha256"]), t["tc"])
        for t in v["mlkem_decap"]:                          # five of these ciphertexts were tampered with
            self.assertEqual(oqs.KeyEncapsulation("ML-KEM-1024", secret_key=h(t["dk"])).decap_secret(h(t["c"])).hex(), t["k"].lower(), t["tc"])
        for t in v["mldsa_sigver"]:
            got = oqs.Signature("ML-DSA-87").verify_with_ctx_str(h(t["message"]), h(t["signature"]), h(t["context"]), h(t["pk"]))
            self.assertEqual(bool(got), t["passed"], (t["tc"], t["reason"]))
        self.assertEqual((len(v["mlkem_keygen"]), len(v["mlkem_decap"]), len(v["mldsa_sigver"])), (25, 10, 15))
        self.assertEqual({t["passed"] for t in v["mldsa_sigver"]}, {True, False})


class TestHybridSession(unittest.TestCase):
    """The session's master secret needs BOTH shared secrets. Checked by doing what an attacker with one of them
    would do: derive the keys from the public transcript, the secret he has and a guess for the other."""

    def setUp(self):
        _, self.uav, self.gcs, self.upk, self.gpk = identities()

    def run_handshake(self):
        server = hs.ServerHandshake(self.gcs, {UAV_ID: self.upk})
        client = hs.ClientHandshake(self.uav, self.gpk, 1, b"\x00" * 8)
        hello = client.client_hello()
        answer = server.process_client_hello(hello)
        x_client, kem_client = client._x, client._kem           # the UAV's two one-time secrets (taken before it frees them)
        dk = kem_client.export_secret_key()
        secrets, _ = client.process_server_hello(answer)
        fl = hs.SH_FIXED.size + hs.X25519_LEN + client.suite.kem_ct_len
        server_part = answer[:fl]
        _, sid, _, _ = hs.SH_FIXED.unpack_from(server_part)
        x_s, ct = server_part[hs.SH_FIXED.size:hs.SH_FIXED.size + 32], server_part[hs.SH_FIXED.size + 32:]
        th = ks.sha256(hs.LBL_TH, client.signed, client.sig, server_part)
        ss_x = x_client.exchange(x25519.X25519PublicKey.from_public_bytes(x_s))
        ss_k = oqs.KeyEncapsulation("ML-KEM-1024", secret_key=dk).decap_secret(ct)
        return bytes(secrets.master), th, sid, ss_k, ss_x

    def test_master_secret_needs_both_shared_secrets(self):
        master, th, sid, ss_k, ss_x = self.run_handshake()
        derive = lambda k, x: bytes(ks.derive_session(th, k + x, 1, sid).master)
        self.assertEqual(derive(ss_k, ss_x), master)                         # with both: the real key (the test is not vacuous)
        for guess in (bytes(32), os.urandom(32)):
            self.assertNotEqual(derive(guess, ss_x), master)                 # X25519 broken, ML-KEM not: no key
            self.assertNotEqual(derive(ss_k, guess), master)                 # ML-KEM broken, X25519 not: no key
        for k, x in ((ss_x, ss_x), (ss_k, ss_k), (ss_x, ss_k)):              # one secret twice, or the two in the other order
            self.assertNotEqual(derive(k, x), master)

    def test_master_secret_is_bound_to_the_whole_transcript(self):
        master, th, sid, ss_k, ss_x = self.run_handshake()
        other_th = bytes([th[0] ^ 1]) + th[1:]
        self.assertNotEqual(bytes(ks.derive_session(other_th, ss_k + ss_x, 1, sid).master), master)
        self.assertNotEqual(bytes(ks.derive_session(th, ss_k + ss_x, 2, sid).master), master)          # the suite
        self.assertNotEqual(bytes(ks.derive_session(th, ss_k + ss_x, 1, bytes(8)).master), master)     # the session id

    def test_ratchet_needs_both_new_secrets_and_the_old_master(self):
        from kyber6g.crypto.handshake import PQRatchetInitiator, _pq_mix, pq_ratchet_respond
        old = ks.derive_session(os.urandom(32), os.urandom(64), 1, os.urandom(8))
        init = PQRatchetInitiator(1, 7)
        x_i, dk = init._x, init._kem.export_secret_key()
        x_s, ct, new_sid, new_gcs = pq_ratchet_respond(old, 7, init.x_pub, init.ek)
        new_uav = init.finish(old, x_s, ct, new_sid)
        self.assertEqual(bytes(new_uav.master), bytes(new_gcs.master))
        ss_x = x_i.exchange(x25519.X25519PublicKey.from_public_bytes(x_s))
        ss_k = oqs.KeyEncapsulation("ML-KEM-1024", secret_key=dk).decap_secret(ct)
        mix = lambda k, x, o: bytes(_pq_mix(o, 7, init.x_pub, init.ek, x_s, ct, new_sid, k, x).master)
        self.assertEqual(mix(ss_k, ss_x, old), bytes(new_uav.master))
        stranger = ks.derive_session(os.urandom(32), os.urandom(64), 1, old.session_id)
        self.assertNotEqual(mix(os.urandom(32), ss_x, old), bytes(new_uav.master))
        self.assertNotEqual(mix(ss_k, os.urandom(32), old), bytes(new_uav.master))
        self.assertNotEqual(mix(ss_k, ss_x, stranger), bytes(new_uav.master))    # both new secrets but not the old master: no key

    def test_another_suite_in_the_answer_is_refused(self):
        server = hs.ServerHandshake(self.gcs, {UAV_ID: self.upk})
        client = hs.ClientHandshake(self.uav, self.gpk, 1, b"\x00" * 8)
        answer = bytearray(server.process_client_hello(client.client_hello()))
        struct.pack_into("!H", answer, 0, 2)
        with self.assertRaises(hs.HandshakeError):
            client.process_server_hello(bytes(answer))
        hello = bytearray(hs.ClientHandshake(self.uav, self.gpk, 1, b"\x00" * 8).client_hello())
        struct.pack_into("!H", hello, 0, 2)                                    # the suite is under the UAV's signature
        with self.assertRaises(hs.HandshakeError):
            hs.ServerHandshake(self.gcs, {UAV_ID: self.upk}).process_client_hello(bytes(hello))
        struct.pack_into("!H", hello, 0, 9)
        with self.assertRaises(hs.HandshakeError):
            hs.ServerHandshake(self.gcs, {UAV_ID: self.upk}).process_client_hello(bytes(hello))


class TestStoredFilesHybrid(unittest.TestCase):
    """One key block (recording/sealing.py) serves stored photos, recordings and audio clips."""

    @classmethod
    def setUpClass(cls):
        cls.d = Path(tempfile.mkdtemp())
        cls.ek, cls.xpk = idm.generate_recording_kem(cls.d), idm.generate_recording_x25519(cls.d)
        cls.dk, cls.xsk = idm.load_recording_dk(cls.d), idm.load_recording_xsk(cls.d)
        other = Path(tempfile.mkdtemp())
        idm.generate_recording_kem(other)
        cls.other_dk = idm.load_recording_dk(other)
        cls.other_xsk = x25519.X25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def test_the_content_key_needs_both_recording_keys(self):
        hdr = b'{"v":2}'
        cek, block = sealing.wrap(b"K6GTEST2", b"lbl|", b"file-1", hdr, self.ek, self.xpk)
        open_ = lambda dk, xsk, **kw: sealing.unwrap(kw.get("magic", b"K6GTEST2"), b"lbl|", kw.get("fid", b"file-1"), kw.get("hdr", hdr), block, dk, xsk)
        self.assertEqual(open_(self.dk, self.xsk), bytes(cek))
        with self.assertRaises(sealing.SealError):                            # the X25519 key alone (ML-KEM "broken": not here)
            open_(self.other_dk, self.xsk)
        with self.assertRaises(sealing.SealError):                            # the ML-KEM key alone
            open_(self.dk, self.other_xsk)
        for change in ({"magic": b"K6GTEST3"}, {"fid": b"file-2"}, {"hdr": b'{"v":3}'}):   # and it is bound to its file
            with self.assertRaises(sealing.SealError, msg=change):
                open_(self.dk, self.xsk, **change)

    def test_all_three_stored_kinds_use_this_key_block(self):
        from kyber6g.audio import quaver
        from kyber6g.recording import photos, recorder
        for module in (photos, recorder, quaver):
            src = inspect.getsource(module)
            self.assertIn("sealing.wrap(", src, module.__name__)
            self.assertIn("sealing.unwrap(", src, module.__name__)

    def test_a_key_of_the_wrong_size_is_refused_not_padded(self):
        """The binding fills a short key with zeros: a recording key file cut short would seal to nobody."""
        for bad in (self.ek[:-1], self.ek + b"\x00", b"", self.ek[:800]):
            with self.assertRaises(ValueError):
                sealing.wrap(b"K6GTEST2", b"lbl|", b"f", b"{}", bad, self.xpk)
        with self.assertRaises(ValueError):
            sealing.wrap(b"K6GTEST2", b"lbl|", b"f", b"{}", self.ek, self.xpk[:31])
        peers = self.d / "peers"
        peers.mkdir(exist_ok=True)
        (peers / "gcs_recording_ML-KEM-1024.ek").write_bytes(self.ek[:1000])
        with self.assertRaises(ValueError):
            idm.load_recording_ek(self.d)
        (peers / "gcs_ML-DSA-87.pk").write_bytes(os.urandom(2591))
        with self.assertRaises(ValueError):
            idm.load_pinned_peer(self.d, "gcs")
        self.assertEqual(idm.key_length("ML-KEM-1024", "public"), 1568)
        self.assertEqual(idm.key_length("ML-DSA-87", "secret"), 4896)


class TestSignedMessagesCannotBeConfused(unittest.TestCase):
    def test_labels_of_everything_that_is_signed_are_prefix_free(self):
        """One ML-DSA-87 key signs handshake messages, stored files and audio roots. A signature made for one kind
        must never verify as another: every signed message starts with a label, and no label is the beginning of
        another (so two messages of different kinds are never the same bytes)."""
        from kyber6g.audio import quaver
        labels = [hs.LBL_CH, hs.LBL_SS, sealing.SIG_LABEL + b"image|", sealing.SIG_LABEL + b"recording|", sealing.SIG_LABEL + b"audio|",
                  b"KYBER6G/ration-probe", b"KYBER6G/selftest/v1|"]
        for a in labels:
            for b in labels:
                if a is not b:
                    self.assertFalse(b.startswith(a), (a, b))
        self.assertTrue(quaver.ROOT_LABEL)                                    # hashed INTO what is signed for audio, see below
        src = inspect.getsource(sealing) + inspect.getsource(hs) + inspect.getsource(quaver)
        self.assertEqual(src.count(".sign("), 3)                             # ClientHello, ServerHello, file trailer: nothing else signs

    def test_a_signature_of_one_kind_does_not_verify_as_another(self):
        _, uav, gcs, upk, gpk = identities()
        digest = os.urandom(32)
        trailer = sealing.sign_trailer(b"image", digest, uav)
        sig = trailer[10:]
        self.assertTrue(idm.verify("ML-DSA-87", sealing.SIG_LABEL + b"image|" + digest, sig, upk))
        for msg in (sealing.SIG_LABEL + b"recording|" + digest, sealing.SIG_LABEL + b"audio|" + digest, hs.LBL_SS + digest,
                    hs.LBL_CH + digest, digest):
            self.assertFalse(idm.verify("ML-DSA-87", msg, sig, upk), msg[:30])
        self.assertFalse(idm.verify("ML-DSA-87", sealing.SIG_LABEL + b"image|" + digest, sig, gpk))    # nor under another key

    def test_key_derivation_labels_are_distinct(self):
        s = ks.derive_session(os.urandom(32), os.urandom(64), 1, os.urandom(8))
        keys = [bytes(s.master), s.finished_server, s.finished_client, bytes(s.resumption), s.cached_rekey_auth]
        for stream in ks.STREAM_NAMES:
            for direction in (ks.DIR_U2G, ks.DIR_G2U):
                keys.append(bytes(s.chain_key(stream, direction)))
        self.assertEqual(len(set(keys)), len(keys))                          # 5 + 7 streams x 2 directions, all different
        self.assertEqual(len(keys), 5 + 2 * len(ks.STREAM_NAMES))


class TestInventory(unittest.TestCase):
    """docs/CBOM.json (python -m kyber6g.tools.cbom): the list of everything cryptographic, made from the code."""

    def test_every_algorithm_in_the_code_is_in_the_bill_of_materials(self):
        from kyber6g.audio import quaver
        from kyber6g.tools import cbom
        bom = cbom.build()
        json.dumps(bom)
        assets = [c for c in bom["components"] if c["type"] == "cryptographic-asset"]
        names = {c["name"] for c in assets}
        used = {quaver.SIG_ALG, sealing.KEM_NAME, *sealing.HYBRID_NAME.split("+"), "HKDF-SHA-256", "HMAC-SHA-256", "SHA-256"}
        for s in SUITES.values():
            used |= {s.kem, s.ecdh, s.sig, s.aead_name}
            self.assertIn(s.name, names)
        self.assertLessEqual(used, names, used - names)
        self.assertEqual(names & set(cbom.algorithms()), set(cbom.algorithms()))
        # X25519 is the one algorithm a quantum computer breaks: wherever it is used, ML-KEM-1024 is used with it
        x, kem = "crypto/algorithm/x25519", "crypto/algorithm/ml-kem-1024"
        protocols = [c for c in assets if c["cryptoProperties"]["assetType"] == "protocol"]
        self.assertEqual(len(protocols), len(SUITES) + 2)
        for p in protocols:
            algs = p["cryptoProperties"]["protocolProperties"]["cipherSuites"][0]["algorithms"]
            self.assertIn(x, algs, p["name"])
            self.assertIn(kem, algs, p["name"])
        levels = {c["name"]: c["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] for c in assets
                  if c["cryptoProperties"]["assetType"] == "algorithm"}
        self.assertEqual((levels["ML-KEM-1024"], levels["ML-DSA-87"], levels["AES-256-GCM"], levels["X25519"]), (5, 5, 5, 0))

    def test_the_file_in_docs_is_up_to_date(self):
        from kyber6g.tools import cbom
        path = Path(__file__).resolve().parents[1] / "docs" / "CBOM.json"
        if not path.is_file():
            self.skipTest("docs/CBOM.json is not on this machine (the UAV has no docs)")
        on_disk, now = json.loads(path.read_text()), cbom.build()
        key = lambda bom: sorted((c["type"], c["name"], c.get("version", "")) for c in bom["components"] if c["type"] == "cryptographic-asset")
        self.assertEqual(key(on_disk), key(now), "run: python -m kyber6g.tools.cbom")


class TestSelfTest(unittest.TestCase):
    def test_passes_on_this_machine_and_checks_this_nodes_keys(self):
        d, uav, gcs, upk, gpk = identities()
        ek, xpk = idm.generate_recording_kem(d), idm.generate_recording_x25519(d)
        res = selftest.run(ident=gcs, rec_ek=ek, rec_dk=idm.load_recording_dk(d), rec_xpk=xpk, rec_xsk=idm.load_recording_xsk(d))
        self.assertTrue(res["ok"], res["failed"])
        names = " | ".join(c["name"] for c in res["checks"])
        for part in ("SHA-256", "HKDF", "AES-256-GCM", "X25519", "NIST vector", "damaged ciphertext", "refuses a changed message",
                     "identity key pair fits", "ML-KEM-1024 recording key pair fits", "X25519 recording key pair fits"):
            self.assertIn(part, names)
        self.assertEqual(len(res["checks"]), 18)
        self.assertLess(res["ms"], 3000)
        s = selftest.summary(selftest.require(ident=uav))
        self.assertEqual((s["ok"], s["failed"], s["liboqs"]), (True, [], oqs.oqs_version()))

    def test_key_files_that_do_not_belong_together_stop_the_start(self):
        d, uav, gcs, upk, gpk = identities()
        swapped = idm.Identity(UAV_ID, "ML-DSA-87", uav._signer.export_secret_key(), gpk)      # the UAV's secret key, another public key
        res = selftest.run(ident=swapped)
        self.assertFalse(res["ok"])
        self.assertEqual(res["failed"], ["this node's identity key pair fits"])
        with self.assertRaises(selftest.SelfTestFailed):
            selftest.require(ident=swapped)
        ek = idm.generate_recording_kem(d)
        other = Path(tempfile.mkdtemp())
        idm.generate_recording_kem(other)
        res = selftest.run(rec_ek=ek, rec_dk=idm.load_recording_dk(other))
        self.assertEqual(res["failed"], ["the ML-KEM-1024 recording key pair fits"])
        xpk = idm.generate_recording_x25519(d)
        res = selftest.run(rec_xpk=xpk, rec_xsk=os.urandom(32))
        self.assertEqual(res["failed"], ["the X25519 recording key pair fits"])

    def test_a_wrong_answer_is_a_failure_not_an_exception(self):
        from unittest import mock
        with mock.patch.object(ks, "hmac256", lambda key, msg: bytes(32)):   # as if the hash were broken
            res = selftest.run()
        self.assertFalse(res["ok"])
        self.assertIn("HMAC-SHA-256", res["failed"])
        with mock.patch.object(selftest.oqs, "KeyEncapsulation", side_effect=RuntimeError("library missing")):
            res = selftest.run()
        self.assertFalse(res["ok"])
        self.assertTrue(any("post-quantum primitives" in f for f in res["failed"]), res["failed"])


if __name__ == "__main__":
    unittest.main()
