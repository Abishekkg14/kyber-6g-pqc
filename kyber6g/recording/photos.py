"""Encrypted-at-rest still images on the UAV (.k6gimg).

Every captured photo is kept on the Pi's SD card, so a capture is not lost if
the link drops during transfer, but - like .k6grec recordings - the Pi cannot
decrypt it afterwards.

Format 2 ("K6GIMG02", written whenever the ground station's X25519 recording key is known; see sealing.py):

  CEK      = 32 random bytes (one per photo)
  ct, ss_k = ML-KEM-1024.Encaps(GCS recording encapsulation key)
  ss_x     = X25519(key made for this photo, GCS recording X25519 key)
  KEK      = HKDF(salt = SHA-256(header_json || ct || xe_pub), ikm = ss_k || ss_x,
                  info = "KYBER6G/image/v2|kek|" img_id)
  wrapped  = AES-256-GCM(KEK, nonce = 0, CEK, aad = magic || header_json || ct || xe_pub)
  body     = AES-256-GCM(CEK, nonce = 0^11 || 1, JPEG, aad = SHA-256(file head))
  trailer  = "K6GSIG01" | u16 len | ML-DSA-87 signature of the UAV over SHA-256(head || body)

  layout: "K6GIMG02" | u16 json_len | header_json | kem_ct(1568) | xe_pub(32) | wrapped_cek(48) | body | trailer

Format 1 ("K6GIMG01": ML-KEM-1024 alone, no signature) is still read, and is written only when no X25519 key was
given. The header (capture time, size, mode, GNSS, signer) is authenticated but not secret.
"""
import hashlib
import json
import os
import struct
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..crypto import identity as idm
from ..crypto.secure_bytes import wipe
from . import sealing

MAGIC, MAGIC2 = b"K6GIMG01", b"K6GIMG02"
KEM_CT = sealing.KEM_CT
BODY_NONCE = b"\x00" * 11 + b"\x01"
LABEL = {MAGIC: b"KYBER6G/image/v1|kek|", MAGIC2: b"KYBER6G/image/v2|kek|"}


class PhotoError(Exception):
    pass


def seal_image(gcs_rec_ek: bytes, jpeg: bytes, meta: dict, kem_alg="ML-KEM-1024", x25519_pk: bytes = None, signer=None) -> bytes:
    """One photo as a .k6gimg. With `x25519_pk` (the ground station's X25519 recording key): format 2, hybrid key
    wrap, and signed with `signer` (the UAV's identity) if that is given. Without: format 1."""
    hybrid = x25519_pk is not None
    if signer is not None and not hybrid:
        raise ValueError("a signed photo is a format-2 photo: the X25519 recording key is needed as well")
    magic = MAGIC2 if hybrid else MAGIC
    img_id = os.urandom(16)
    hdr = {"v": 2 if hybrid else 1, "suite": "AES-256-GCM", "kem": sealing.HYBRID_NAME if hybrid else kem_alg,
           "img_id": img_id.hex(), "created": time.time(), "gcs_ek_fp": idm.fingerprint(gcs_rec_ek), "bytes": len(jpeg),
           "sha256": hashlib.sha256(jpeg).hexdigest(), **meta}
    if hybrid:
        hdr.update(gcs_x_fp=idm.fingerprint(x25519_pk), **sealing.signer_fields(signer))
    hj = json.dumps(hdr, sort_keys=True, default=str).encode()
    cek, block = sealing.wrap(magic, LABEL[magic], img_id, hj, gcs_rec_ek, x25519_pk, kem_alg)
    head = magic + struct.pack("!H", len(hj)) + hj + block
    body = AESGCM(bytes(cek)).encrypt(BODY_NONCE, jpeg, hashlib.sha256(head).digest())
    wipe(cek)
    out = head + body
    if signer is not None:
        out += sealing.sign_trailer(b"image", hashlib.sha256(out).digest(), signer)
    return out


def read_header(raw: bytes) -> dict:
    if raw[:8] not in (MAGIC, MAGIC2):
        raise PhotoError("not a K6GIMG file")
    (jl,) = struct.unpack_from("!H", raw, 8)
    return json.loads(raw[10:10 + jl])


def open_image(raw: bytes, rec_dk: bytes, kem_alg="ML-KEM-1024", x25519_sk: bytes = None, signer_pk: bytes = None):
    """Returns (header, jpeg). Raises PhotoError - and nothing else - on a wrong key or any change to the file.

    `signer_pk` (the pinned ML-DSA-87 key of the UAV) given: a format-2 photo must carry a valid signature of that
    key, or it is refused. The verdict is returned as header["sig_status"]: "PASS", "NOT CHECKED" (no key given),
    "ABSENT" (unsigned and none required) or "ABSENT (format 1)" for a photo of the old format, which has none."""
    try:
        hdr = read_header(raw)
        img_id = bytes.fromhex(hdr["img_id"])
        (jl,) = struct.unpack_from("!H", raw, 8)
    except (ValueError, KeyError, TypeError, struct.error, RecursionError) as e:
        raise PhotoError(f"malformed header: {type(e).__name__}") from None
    if not isinstance(hdr, dict):
        raise PhotoError("malformed header: not an object")
    magic = raw[:8]
    hybrid = magic == MAGIC2
    if hybrid and x25519_sk is None:
        raise PhotoError("a format-2 photo needs the ground station's X25519 recording key as well")
    hj = raw[10:10 + jl]
    off = 10 + jl
    n = sealing.block_len(hybrid)
    block, head = raw[off:off + n], raw[:off + n]
    try:
        tl = sealing.trailer_len(hdr) if hybrid else 0
        if len(block) != n or len(raw) < len(head) + 16 + tl:
            raise PhotoError("truncated file")
        end = len(raw) - tl
        # the signature first: the ground station's long-term secret keys are not used on a file that the pinned
        # UAV key did not sign (nothing to probe them with, and a forged file is refused at the cost of one check)
        status = sealing.check_trailer(b"image", raw[:end], raw[end:], hdr, signer_pk) if hybrid else "ABSENT (format 1)"
        cek = sealing.unwrap(magic, LABEL[magic], img_id, hj, block, rec_dk, x25519_sk if hybrid else None, kem_alg)
    except sealing.SealError as e:
        raise PhotoError(str(e)) from None
    try:
        jpeg = AESGCM(cek).decrypt(BODY_NONCE, raw[len(head):end], hashlib.sha256(head).digest())
    except Exception:
        raise PhotoError("authentication failed (wrong GCS key or file tampered)") from None
    if hashlib.sha256(jpeg).hexdigest() != hdr.get("sha256"):
        raise PhotoError("plaintext hash mismatch")
    hdr["sig_status"] = status
    return hdr, jpeg


class PhotoStore:
    """~/kyber6g_photos on the UAV: one .k6gimg per capture, written with fsync."""

    def __init__(self, directory, gcs_rec_ek: bytes, x25519_pk: bytes = None, signer=None):
        self.dir = idm.private_dir(Path(directory).expanduser())      # owner-only, like the recordings directory
        self.ek, self.x_pk, self.signer = gcs_rec_ek, x25519_pk, signer if x25519_pk is not None else None

    def save(self, name: str, jpeg: bytes, meta: dict):
        t0 = time.perf_counter()
        blob = seal_image(self.ek, jpeg, meta, x25519_pk=self.x_pk, signer=self.signer)
        path, n = self.dir / (Path(name).stem + ".k6gimg"), 1
        while path.exists():                              # a stored photo is never replaced by another one of the same name
            n += 1
            path = self.dir / f"{Path(name).stem}-{n}.k6gimg"
        tmp = path.with_suffix(".tmp")
        with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
            os.chmod(tmp, 0o600)
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        return {"stored_as": path.name, "stored_bytes": len(blob), "format": 2 if self.x_pk is not None else 1,
                "signed": self.signer is not None, "seal_ms": round((time.perf_counter() - t0) * 1000, 2)}

    def list(self):
        out = []
        for p in sorted(self.dir.glob("*.k6gimg")):
            try:
                st = p.stat()
            except OSError:                       # deleted between the listing and the stat
                continue
            try:
                with open(p, "rb") as f:
                    head = f.read(4096)
                h = read_header(head)
                out.append({"name": p.name, "bytes": st.st_size, "mtime": st.st_mtime,
                            "width": h.get("width"), "height": h.get("height"), "mode": h.get("mode")})
            except Exception:
                out.append({"name": p.name, "bytes": st.st_size, "mtime": st.st_mtime, "error": "unreadable"})
        return out

    def read(self, name: str) -> bytes:
        p = self.dir / Path(name).name
        if p.suffix != ".k6gimg" or not p.exists():
            raise FileNotFoundError(name)
        return p.read_bytes()

    def usage(self):
        files = list(self.dir.glob("*.k6gimg"))
        return {"count": len(files), "bytes": sum(p.stat().st_size for p in files)}
