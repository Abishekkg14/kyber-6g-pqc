"""Stored photos and recordings, file format 2: the content key is wrapped with ML-KEM-1024 AND X25519, and the UAV
signs the file with its ML-DSA-87 identity key (kyber6g/recording/sealing.py)."""
import os
import random
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat

from kyber6g.crypto import identity as idm
from kyber6g.recording import sealing
from kyber6g.recording.photos import MAGIC2 as IMG2, PhotoError, PhotoStore, open_image, read_header, seal_image
from kyber6g.recording.recorder import MAGIC2 as REC2, EncryptedRecorder, RecordingError, RollingRecorder, decrypt_recording


class Keys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = Path(tempfile.mkdtemp())
        cls.ek = idm.generate_recording_kem(cls.d)
        cls.dk = idm.load_recording_dk(cls.d)
        cls.xpk = idm.generate_recording_x25519(cls.d)
        cls.xsk = idm.load_recording_xsk(cls.d)
        cls.upk = idm.generate_identity(cls.d, "uav")
        cls.uav = idm.load_identity(cls.d, "uav", b"UAV-ALPH")
        other = Path(tempfile.mkdtemp())
        cls.other_pk = idm.generate_identity(other, "uav")                 # another UAV's key pair
        cls.other = idm.load_identity(other, "uav", b"UAV-EVIL")
        cls.other_dk_dir = Path(tempfile.mkdtemp())
        idm.generate_recording_kem(cls.other_dk_dir)
        cls.other_dk = idm.load_recording_dk(cls.other_dk_dir)
        cls.other_xsk = x25519.X25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


class TestPhotoFormat2(Keys):
    JPEG = b"\xff\xd8" + os.urandom(30_000)

    def seal(self, **kw):
        return seal_image(self.ek, self.JPEG, {"width": 1280, "mode": "NORMAL"}, x25519_pk=self.xpk, signer=self.uav, **kw)

    def open(self, blob, **kw):
        kw = {"x25519_sk": self.xsk, "signer_pk": self.upk, **kw}
        return open_image(blob, self.dk, **kw)

    def test_round_trip_names_the_signer(self):
        blob = self.seal()
        self.assertEqual(blob[:8], IMG2)
        hdr, jpeg = self.open(blob)
        self.assertEqual(jpeg, self.JPEG)
        self.assertEqual((hdr["v"], hdr["kem"], hdr["sig"], hdr["signer"], hdr["sig_status"]),
                         (2, "ML-KEM-1024+X25519", "ML-DSA-87", "UAV-ALPH", "PASS"))
        self.assertEqual(hdr["signer_fp"], idm.fingerprint(self.upk))
        self.assertNotIn(self.JPEG[2:40], blob)                             # nothing of the picture in the file
        self.assertEqual(len(blob) - len(self.JPEG), 10 + len(blob[10:10 + int.from_bytes(blob[8:10], "big")])
                         + sealing.KEM_CT + sealing.X_LEN + sealing.WRAPPED + 16 + 10 + 4627)   # every byte of overhead accounted for

    def test_both_recording_keys_are_needed(self):
        """Hybrid means: the ML-KEM key alone does not open the file, and neither does the X25519 key alone."""
        blob = self.seal()
        with self.assertRaises(PhotoError):
            open_image(blob, self.dk)                                      # no X25519 key at all
        with self.assertRaises(PhotoError):
            self.open(blob, x25519_sk=self.other_xsk)                      # right ML-KEM key, wrong X25519 key
        with self.assertRaises(PhotoError):
            open_image(blob, self.other_dk, x25519_sk=self.xsk, signer_pk=self.upk)      # right X25519 key, wrong ML-KEM key

    def test_every_changed_byte_is_detected(self):
        blob = self.seal()
        rng = random.Random(7)
        positions = sorted(set([0, 7, 8, 9, 12, len(blob) - 1, len(blob) - 4627, len(blob) - 4638]
                               + [rng.randrange(len(blob)) for _ in range(300)]))
        for pos in positions:
            bad = bytearray(blob)
            bad[pos] ^= 1 << rng.randrange(8)
            with self.assertRaises(PhotoError, msg=f"a change at byte {pos} of {len(blob)} was accepted"):
                self.open(bytes(bad))

    def test_every_truncation_is_detected(self):
        blob = self.seal()
        for n in list(range(0, 2000, 37)) + [len(blob) - 4638, len(blob) - 4637, len(blob) - 100, len(blob) - 1]:
            with self.assertRaises(PhotoError, msg=f"the first {n} bytes were accepted"):
                self.open(blob[:n])
        with self.assertRaises(PhotoError):
            self.open(blob + b"\x00")                                      # one byte appended

    def test_a_file_from_someone_else_is_refused(self):
        """Format 1 could be written by anyone who knew the ground station's PUBLIC keys. Format 2: not without the
        UAV's signing key."""
        forged = seal_image(self.ek, self.JPEG, {"width": 1}, x25519_pk=self.xpk, signer=self.other)   # signed by another key
        with self.assertRaisesRegex(PhotoError, "signature invalid"):
            self.open(forged)
        unsigned = seal_image(self.ek, self.JPEG, {"width": 1}, x25519_pk=self.xpk)                    # format 2, not signed
        with self.assertRaisesRegex(PhotoError, "unsigned"):
            self.open(unsigned)
        self.assertEqual(self.open(unsigned, signer_pk=None)[0]["sig_status"], "ABSENT")               # no key given: said so
        stripped = self.seal()[:-4637]                                                                 # signature cut off
        with self.assertRaises(PhotoError):
            self.open(stripped)
        with self.assertRaises(PhotoError):
            self.open(stripped, signer_pk=None)                            # announced in the header, so it must be there

    def test_the_signature_cannot_be_moved_to_another_file(self):
        a, b = self.seal(), self.seal()
        with self.assertRaises(PhotoError):
            self.open(a[:-4637] + b[-4637:])

    def test_header_cannot_choose_the_signature_algorithm(self):
        """The header is written by whoever made the file: it must not be able to switch the check to another
        algorithm (or to none) once a signer key is given."""
        import json
        import struct
        blob = self.seal()
        jl = struct.unpack_from("!H", blob, 8)[0]
        hdr = json.loads(blob[10:10 + jl])
        for sig in (None, "ML-DSA-44", "Ed25519", ""):
            hdr2 = {**hdr, "sig": sig}
            hj = json.dumps(hdr2, sort_keys=True, default=str).encode()
            bad = blob[:8] + struct.pack("!H", len(hj)) + hj + blob[10 + jl:]
            with self.assertRaises(PhotoError, msg=f"sig={sig!r} was accepted"):
                self.open(bad)

    def test_format_1_is_still_read_and_says_it_is_unsigned(self):
        old = seal_image(self.ek, self.JPEG, {"width": 1})
        hdr, jpeg = self.open(old)
        self.assertEqual((jpeg, hdr["v"], hdr["sig_status"]), (self.JPEG, 1, "ABSENT (format 1)"))
        with self.assertRaises(ValueError):
            seal_image(self.ek, self.JPEG, {}, signer=self.uav)            # a signature needs format 2

    def test_store_writes_format_2_when_it_has_the_keys(self):
        st = PhotoStore(self.d / "photos", self.ek, x25519_pk=self.xpk, signer=self.uav)
        info = st.save("img_x.jpg", self.JPEG, {"width": 2592, "height": 1944, "mode": "NIGHT"})
        self.assertEqual((info["format"], info["signed"]), (2, True))
        raw = st.read(info["stored_as"])
        self.assertEqual(read_header(raw)["mode"], "NIGHT")
        self.assertEqual(self.open(raw)[1], self.JPEG)
        self.assertEqual(st.list()[0]["width"], 2592)
        old = PhotoStore(self.d / "photos_v1", self.ek)                    # a node that was never given the X25519 key
        self.assertEqual(old.save("a.jpg", self.JPEG, {})["format"], 1)


class TestRecordingFormat2(Keys):
    def record(self, n=95, **kw):
        kw = {"x25519_pk": self.xpk, "signer": self.uav, **kw}
        rec = EncryptedRecorder(self.d / f"rec{random.randrange(10**9)}", self.ek, {"codec": "h264", "fps": 30}, **kw)
        frames = []
        for i in range(n):
            data = os.urandom(random.randint(200, 3000))
            frames.append(data)
            rec.add_frame(data, keyframe=(i % 30 == 0), ts_us=i * 33333)
        return rec.path, b"".join(frames), rec.close()

    def decrypt(self, path, **kw):
        kw = {"x25519_sk": self.xsk, "signer_pk": self.upk, **kw}
        return decrypt_recording(path, self.dk, **kw)

    def test_round_trip_signed(self):
        path, plain, summary = self.record()
        self.assertEqual((summary["format"], summary["signed"]), (2, True))
        self.assertEqual(path.read_bytes()[:8], REC2)
        self.assertEqual(summary["file_bytes"], path.stat().st_size)
        hdr, h264, rep = self.decrypt(path)
        self.assertEqual(h264, plain)
        self.assertEqual((rep["status"], rep["signature"], rep["signer"], rep["format"], rep["trailing_bytes"]),
                         ("PASS", "PASS", "UAV-ALPH", 2, 0))
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")

    def test_both_recording_keys_are_needed(self):
        path, _, _ = self.record(10)
        with self.assertRaises(RecordingError):
            decrypt_recording(path, self.dk)
        with self.assertRaises(RecordingError):
            self.decrypt(path, x25519_sk=self.other_xsk)
        with self.assertRaises(RecordingError):
            decrypt_recording(path, self.other_dk, x25519_sk=self.xsk, signer_pk=self.upk)

    def test_every_changed_byte_is_detected(self):
        path, _, _ = self.record(35)
        raw = path.read_bytes()
        rng = random.Random(11)
        for pos in sorted(set([0, 8, 9, len(raw) - 1, len(raw) - 4637, len(raw) - 4640] + [rng.randrange(len(raw)) for _ in range(250)])):
            bad = bytearray(raw)
            bad[pos] ^= 1 << rng.randrange(8)
            path.write_bytes(bytes(bad))
            with self.assertRaises(RecordingError, msg=f"a change at byte {pos} of {len(raw)} was accepted"):
                self.decrypt(path)

    def test_a_recording_cut_short_is_reported_and_has_no_signature(self):
        path, plain, _ = self.record()
        raw = path.read_bytes()
        seen = set()
        for cut in (len(raw) // 3, len(raw) // 2, len(raw) - 4637 - 40):
            path.write_bytes(raw[:cut])
            try:
                _, h264, rep = self.decrypt(path)
            except RecordingError:
                seen.add("refused")
                continue
            seen.add(rep["status"])
            self.assertFalse(rep["complete"])
            self.assertEqual(rep["signature"], "ABSENT (file is cut short)")
            self.assertTrue(plain.startswith(h264))                        # what could be read is the true beginning
        self.assertTrue(seen <= {"refused", "TRUNCATED (no FINAL segment)"}, seen)
        path.write_bytes(raw[:-4637])                                      # complete, but the signature is gone
        with self.assertRaisesRegex(RecordingError, "signature"):
            self.decrypt(path)
        _, h264, rep = self.decrypt(path, signer_pk=None)                  # the video can still be got at, and it says why
        self.assertEqual((h264, rep["signature"], rep["status"]), (plain, "MISSING", "UNSIGNED (the signature is missing)"))

    def test_a_recording_from_someone_else_is_refused(self):
        path, _, _ = self.record(10, signer=self.other)
        with self.assertRaisesRegex(RecordingError, "signature invalid"):
            self.decrypt(path)
        path, plain, _ = self.record(10, signer=None)                      # format 2 without a signature
        with self.assertRaisesRegex(RecordingError, "unsigned"):
            self.decrypt(path)
        self.assertEqual(self.decrypt(path, signer_pk=None)[2]["signature"], "ABSENT")

    def test_bytes_after_the_signature_are_reported(self):
        path, plain, _ = self.record(10)
        path.write_bytes(path.read_bytes() + b"extra")
        _, h264, rep = self.decrypt(path)
        self.assertEqual((h264, rep["trailing_bytes"], rep["signature"]), (plain, 5, "PASS"))

    def test_format_1_is_still_read(self):
        path, plain, summary = self.record(10, x25519_pk=None)
        self.assertEqual((summary["format"], summary["signed"]), (1, False))
        _, h264, rep = self.decrypt(path)
        self.assertEqual((h264, rep["format"], rep["signature"], rep["status"]), (plain, 1, "ABSENT (format 1)", "PASS"))

    def test_every_part_of_a_long_recording_is_signed(self):
        rec = RollingRecorder(self.d / "roll2", self.ek, {"codec": "h264", "fps": 30}, max_bytes=60_000,
                              x25519_pk=self.xpk, signer=self.uav)
        frames = []
        for i in range(240):
            data = os.urandom(1500)
            frames.append(data)
            rec.add_frame(data, keyframe=(i % 30 == 0), ts_us=i * 33333)
        summary = rec.close()
        self.assertGreater(len(summary["parts"]), 2)
        out = b""
        for name in summary["parts"]:
            _, h264, rep = self.decrypt(self.d / "roll2" / name)
            self.assertEqual((rep["status"], rep["signature"]), ("PASS", "PASS"))
            out += h264
        self.assertEqual(out, b"".join(frames))


class TestRecordingKeys(unittest.TestCase):
    def test_x25519_recording_key_files(self):
        d = Path(tempfile.mkdtemp())
        self.assertIsNone(idm.load_recording_xsk(d))                       # a station provisioned before format 2
        pk = idm.generate_recording_x25519(d)
        self.assertEqual((len(pk), len(idm.load_recording_xsk(d))), (32, 32))
        self.assertEqual(oct((d / "gcs_recording_X25519.sk").stat().st_mode & 0o777), "0o600")
        os.chmod(d / "gcs_recording_X25519.sk", 0o640)
        with self.assertRaises(PermissionError):
            idm.load_recording_xsk(d)                                      # readable by the group: refused
        self.assertIsNone(idm.load_recording_xpk(d))                       # the UAV side, no key delivered yet
        (d / "peers").mkdir()
        (d / "peers" / "gcs_recording_X25519.pk").write_bytes(pk)
        self.assertEqual(idm.load_recording_xpk(d), pk)
        (d / "peers" / "gcs_recording_X25519.pk").write_bytes(pk[:31])
        with self.assertRaises(ValueError):
            idm.load_recording_xpk(d)


if __name__ == "__main__":
    unittest.main()
