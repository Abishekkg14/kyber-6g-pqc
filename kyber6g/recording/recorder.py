"""Encrypted-at-rest segmented recording (.k6grec).

The UAV never holds a key that can decrypt a finished recording.

Format 2 ("K6GREC02", written whenever the ground station's X25519 recording key is known; see sealing.py):

  CEK      = 32 random bytes (content-encryption key, one per recording)
  ct, ss_k = ML-KEM-1024.Encaps(GCS recording encapsulation key)
  ss_x     = X25519(key made for this recording, GCS recording X25519 key)
  KEK      = HKDF(salt = SHA-256(header_json || ct || xe_pub), ikm = ss_k || ss_x,
                  info = "KYBER6G/recording/v2|kek|" rec_id)
  wrapped  = AES-256-GCM(KEK, nonce = 0, CEK, aad = magic || header_json || ct || xe_pub)

ss_k, ss_x, KEK and the plaintext CEK exist only in RAM while recording. Only the GCS (holding the ML-KEM
decapsulation key AND the X25519 key) can unwrap the CEK afterwards.

File layout:
  "K6GREC02" | u16 json_len | header_json | kem_ct(1568) | xe_pub(32) | wrapped_cek(48)
  segment*  : u32 ct_len | u64 seg_idx | u8 flags | AES-256-GCM(CEK, nonce = 0^4||seg_idx,
              aad = SHA-256(file header) || seg_idx || flags, frames)
  frames    : u64 ts_us | u8 keyframe | u32 len | H.264 access unit
  trailer   : "K6GSIG01" | u16 len | ML-DSA-87 signature of the UAV over SHA-256(every byte before the trailer)
flags bit0 = FINAL. A file without a FINAL segment was truncated (power loss / tampering) and is reported as such
(it has no signature either); segments cannot be reordered, dropped or moved between files without failing
authentication. The trailer follows the FINAL segment: the file names the UAV that wrote it.

Format 1 ("K6GREC01": ML-KEM-1024 alone, no signature) is still read, and is written only when no X25519 key was given.
"""
import hashlib
import json
import os
import struct
import threading
import time
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..crypto import identity as idm
from ..crypto.secure_bytes import wipe
from . import sealing

MAGIC, MAGIC2 = b"K6GREC01", b"K6GREC02"
LABEL = {MAGIC: b"KYBER6G/recording/v1|kek|", MAGIC2: b"KYBER6G/recording/v2|kek|"}
FLAG_FINAL = 1
SEG_HDR = struct.Struct("!IQB")
FRAME_HDR = struct.Struct("!QBI")


class EncryptedRecorder:
    def __init__(self, directory, gcs_rec_ek: bytes, meta: dict, kem_alg="ML-KEM-1024", x25519_pk: bytes = None, signer=None):
        """`x25519_pk` (the ground station's X25519 recording key) given: format 2 with the hybrid key wrap, signed
        with `signer` (the UAV's identity) when the recording is closed. Not given: format 1."""
        self.dir = idm.private_dir(Path(directory).expanduser())
        self.rec_id = os.urandom(16)
        self.name = time.strftime("rec_%Y%m%d_%H%M%S_") + self.rec_id.hex()[:8] + ".k6grec"
        self.path = self.dir / self.name
        hybrid = x25519_pk is not None
        self.magic = MAGIC2 if hybrid else MAGIC
        self.signer = signer if hybrid else None
        hdr = {"v": 2 if hybrid else 1, "suite": "AES-256-GCM", "kem": sealing.HYBRID_NAME if hybrid else kem_alg,
               "rec_id": self.rec_id.hex(), "created": time.time(), "gcs_ek_fp": idm.fingerprint(gcs_rec_ek), **meta}
        if hybrid:
            hdr.update(gcs_x_fp=idm.fingerprint(x25519_pk), **sealing.signer_fields(self.signer))
        self.header_json = json.dumps(hdr, sort_keys=True).encode()
        cek, block = sealing.wrap(self.magic, LABEL[self.magic], self.rec_id, self.header_json, gcs_rec_ek, x25519_pk, kem_alg)
        self.file_header = self.magic + struct.pack("!H", len(self.header_json)) + self.header_json + block
        self.hdr_hash = hashlib.sha256(self.file_header).digest()
        self._aead = AESGCM(bytes(cek))
        wipe(cek)
        # created owner-only from the first byte, and never through a file or link that is already there
        self.f = os.fdopen(os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")
        self._digest = hashlib.sha256(self.file_header)        # of every byte written: what the UAV signs at the end
        self.f.write(self.file_header)
        self.file_bytes = len(self.file_header)
        self.seg_idx = 0
        self.buf = bytearray()
        self.frames = 0
        self.skipped_before_idr = 0
        self.bytes_in = 0
        self.first_ts_us = self.last_ts_us = None
        self.t0 = time.time()
        self.lock = threading.Lock()
        self.closed = False
        self.encrypt_s = 0.0
        self.sign_ms = self.sign_error = None

    def _write_segment(self, final=False):
        flags = FLAG_FINAL if final else 0
        aad = self.hdr_hash + struct.pack("!QB", self.seg_idx, flags)
        t = time.perf_counter()
        ct = self._aead.encrypt(b"\x00\x00\x00\x00" + self.seg_idx.to_bytes(8, "big"), bytes(self.buf), aad)
        self.encrypt_s += time.perf_counter() - t
        seg = SEG_HDR.pack(len(ct), self.seg_idx, flags) + ct
        self._digest.update(seg)
        self.f.write(seg)
        self.f.flush()
        self.file_bytes += len(seg)
        wipe(self.buf)
        self.buf = bytearray()
        self.seg_idx += 1

    def add_frame(self, data: bytes, keyframe: bool, ts_us: int):
        with self.lock:
            if self.closed:
                return
            if self.frames == 0 and not keyframe:
                # recording attached to a running encoder: frames before the
                # first IDR cannot be decoded, so the file starts at an IDR
                self.skipped_before_idr += 1
                return
            if keyframe and self.buf:
                self._write_segment()
            self.buf += FRAME_HDR.pack(ts_us, 1 if keyframe else 0, len(data)) + data
            self.frames += 1
            self.bytes_in += len(data)
            if self.first_ts_us is None:
                self.first_ts_us = ts_us
            self.last_ts_us = ts_us
            if len(self.buf) > (4 << 20):
                self._write_segment()

    def close(self):
        with self.lock:
            if self.closed:
                return
            self._write_segment(final=True)
            if self.signer is not None:                  # the UAV's signature over everything written, FINAL segment included
                t = time.perf_counter()
                try:
                    trailer = sealing.sign_trailer(b"recording", self._digest.digest(), self.signer)
                except Exception as e:                   # the recording itself is complete: close it properly whatever happens
                    trailer, self.sign_error = b"", f"{type(e).__name__}: {e}"
                self.sign_ms = round((time.perf_counter() - t) * 1000, 3)
                self.f.write(trailer)
                self.file_bytes += len(trailer)
            self.f.flush()
            os.fsync(self.f.fileno())
            self.f.close()
            self.closed = True
            self._aead = None
        return self.summary()

    def abort(self):
        """Discard a recording that never started (no frames): close and delete
        the header-only file so failed starts leave no orphan files."""
        with self.lock:
            self.closed = True
            self._aead = None
            try:
                self.f.close()
            finally:
                if self.frames == 0:
                    self.path.unlink(missing_ok=True)

    def live_status(self):
        """Cheap snapshot for the camcorder-style REC indicator (no file I/O)."""
        media = (self.last_ts_us - self.first_ts_us) / 1e6 if self.first_ts_us is not None else 0.0
        return {"recording_name": self.name, "recording_frames": self.frames,
                "recording_started_at": self.t0, "recording_elapsed_s": round(time.time() - self.t0, 1),
                "recording_media_s": round(media, 1), "recording_bytes": self.file_bytes + len(self.buf)}

    def summary(self):
        dur = time.time() - self.t0
        return {"name": self.name, "frames": self.frames, "skipped_before_first_idr": self.skipped_before_idr,
                "segments": self.seg_idx, "format": 2 if self.magic == MAGIC2 else 1,
                "signed": self.signer is not None and not self.sign_error, "sign_ms": self.sign_ms,
                **({"sign_error": self.sign_error} if self.sign_error else {}),
                "plain_bytes": self.bytes_in, "file_bytes": self.path.stat().st_size if self.path.exists() else 0,
                "duration_s": round(dur, 2), "encrypt_ms_total": round(self.encrypt_s * 1000, 2),
                "throughput_MBps": round(self.bytes_in / self.encrypt_s / 1e6, 1) if self.encrypt_s else None}


class RollingRecorder:
    """A recording that never outgrows the secure link.

    When the current file reaches `max_bytes`, the next keyframe starts a new, independent .k6grec (its own content
    key, header and FINAL segment). Every part is a complete recording that decrypts on its own, so a long recording
    stays fetchable (one transfer is limited to 256 MB; a 46-minute single file of 1 GB could not be fetched at all)
    and a power cut costs at most the tail of one part. The parts play back to back: each starts with an IDR frame.
    """

    def __init__(self, directory, gcs_rec_ek: bytes, meta: dict, max_bytes: int = 192 << 20, kem_alg="ML-KEM-1024",
                 x25519_pk: bytes = None, signer=None):
        self._new = lambda part, first: EncryptedRecorder(
            directory, gcs_rec_ek, {**meta, "part": part, **({"first_part": first} if first else {})}, kem_alg,
            x25519_pk=x25519_pk, signer=signer)
        self.max_bytes = max_bytes
        self.cur = self._new(1, None)
        self.name = self.cur.name               # the FIRST part: what start_rec reports
        self.t0 = self.cur.t0
        self.done = []                          # summaries of the finished parts
        self.lock = threading.Lock()

    @property
    def current_name(self):
        cur = self.cur
        return cur.name if cur else None

    @property
    def frames(self):
        cur = self.cur
        return sum(p["frames"] for p in self.done) + (cur.frames if cur else 0)

    def add_frame(self, data: bytes, keyframe: bool, ts_us: int):
        with self.lock:
            cur = self.cur
            if cur is None:
                return
            if keyframe and cur.frames and cur.file_bytes + len(cur.buf) >= self.max_bytes:
                self.done.append(cur.close())
                cur = self.cur = self._new(len(self.done) + 1, self.name)
            cur.add_frame(data, keyframe, ts_us)

    def close(self):
        with self.lock:
            cur, self.cur = self.cur, None
            if cur is None:
                return None
            parts = self.done + [cur.close()]
        if len(parts) == 1:
            return {**parts[0], "parts": [parts[0]["name"]]}
        enc_ms = sum(p["encrypt_ms_total"] for p in parts)
        plain = sum(p["plain_bytes"] for p in parts)
        return {"name": self.name, "parts": [p["name"] for p in parts], "frames": sum(p["frames"] for p in parts),
                "skipped_before_first_idr": parts[0]["skipped_before_first_idr"],
                "segments": sum(p["segments"] for p in parts), "plain_bytes": plain,
                "file_bytes": sum(p["file_bytes"] for p in parts), "duration_s": round(time.time() - self.t0, 2),
                "encrypt_ms_total": round(enc_ms, 2),
                "throughput_MBps": round(plain / (enc_ms / 1000) / 1e6, 1) if enc_ms else None}

    def abort(self):
        with self.lock:
            cur, self.cur = self.cur, None
        if cur is not None:
            cur.abort()

    def live_status(self):
        cur, done = self.cur, list(self.done)
        if cur is None:
            return {"recording_name": None, "recording_frames": None}
        st = cur.live_status()
        st.update(recording_started_at=self.t0, recording_elapsed_s=round(time.time() - self.t0, 1),
                  recording_frames=st["recording_frames"] + sum(p["frames"] for p in done),
                  recording_bytes=st["recording_bytes"] + sum(p["file_bytes"] for p in done),
                  recording_part=len(done) + 1, recording_first=self.name)
        return st


class RecordingError(Exception):
    pass


KEM_CT = sealing.KEM_CT      # ML-KEM-1024 ciphertext
WRAPPED = sealing.WRAPPED    # 32-byte CEK + 16-byte tag


def decrypt_recording(path, rec_dk: bytes, kem_alg="ML-KEM-1024", x25519_sk: bytes = None, signer_pk: bytes = None,
                      index: bool = False):
    """Returns (header_dict, h264_bytes, report). Raises RecordingError - and nothing else - for a file that is
    not a recording, is cut short in its header, was made for another key or was changed in any way.

    What the file proves. Format 1: that it is intact and was written for this ground station's key (anyone holding
    that public key can write such a file). Format 2 with `signer_pk` (the pinned ML-DSA-87 key of the UAV): also that
    this UAV wrote it. A complete format-2 file whose signature is missing or wrong is refused when `signer_pk` is
    given; report["signature"] is then "PASS". Without `signer_pk` it is "NOT CHECKED", or "MISSING" if the trailer is
    not there. A file with no FINAL segment (power cut) has no signature: "ABSENT (file is cut short)".
    `index`: also return report["frame_index"], one [time stamp in us, keyframe 0/1, bytes] per frame."""
    raw = Path(path).read_bytes()
    magic = raw[:8]
    if magic not in (MAGIC, MAGIC2):
        raise RecordingError("not a K6GREC file")
    hybrid = magic == MAGIC2
    if len(raw) < 10:
        raise RecordingError("truncated file (no header)")
    if hybrid and x25519_sk is None:
        raise RecordingError("a format-2 recording needs the ground station's X25519 recording key as well")
    (jl,) = struct.unpack_from("!H", raw, 8)
    hj = raw[10:10 + jl]
    off = 10 + jl
    n = sealing.block_len(hybrid)
    block = raw[off:off + n]; off += n
    if len(hj) != jl or len(block) != n:
        raise RecordingError("truncated file (header incomplete)")
    try:
        hdr = json.loads(hj)
        rec_id = bytes.fromhex(hdr["rec_id"])
    except (ValueError, KeyError, TypeError, RecursionError) as e:
        raise RecordingError(f"malformed header: {type(e).__name__}") from None
    file_header = raw[:off]
    try:
        cek = sealing.unwrap(magic, LABEL[magic], rec_id, hj, block, rec_dk, x25519_sk if hybrid else None, kem_alg)
    except sealing.SealError as e:
        raise RecordingError(str(e)) from None
    aead = AESGCM(cek)
    hh = hashlib.sha256(file_header).digest()
    out = bytearray()
    frames = keyframes = 0
    frame_index = []
    expected = 0
    final = False
    while off < len(raw):
        if len(raw) - off < SEG_HDR.size:
            break
        clen, idx, flags = SEG_HDR.unpack_from(raw, off)
        off += SEG_HDR.size
        if idx != expected or off + clen > len(raw):
            raise RecordingError(f"segment {expected} missing/reordered/truncated")
        try:
            pt = aead.decrypt(b"\x00\x00\x00\x00" + idx.to_bytes(8, "big"), raw[off:off + clen],
                              hh + struct.pack("!QB", idx, flags))
        except Exception:
            raise RecordingError(f"segment {idx} failed authentication") from None
        off += clen
        expected += 1
        p = 0
        while p < len(pt):
            if len(pt) - p < FRAME_HDR.size:
                raise RecordingError(f"segment {idx}: frame list is cut short")
            ts, kf, ln = FRAME_HDR.unpack_from(pt, p)
            p += FRAME_HDR.size
            if p + ln > len(pt):
                raise RecordingError(f"segment {idx}: frame runs past the end of the segment")
            out += pt[p:p + ln]
            p += ln
            frames += 1
            keyframes += 1 if kf else 0
            if index:
                frame_index.append([ts, 1 if kf else 0, ln])
        if flags & FLAG_FINAL:
            final = True
            break
    # the signature of the UAV, format 2: it follows the FINAL segment and covers every byte before it
    signature = "ABSENT (format 1)" if not hybrid else "ABSENT (file is cut short)"
    if hybrid and final:
        try:
            tl = sealing.trailer_len(hdr)
            signature = sealing.check_trailer(b"recording", raw[:off], raw[off:off + tl], hdr, signer_pk)
            off += tl
        except sealing.SealError as e:
            if signer_pk is not None or "invalid" in str(e) or "unsupported" in str(e):
                raise RecordingError(str(e)) from None
            signature = "MISSING"                # no key to check with, and nothing to check: say so, keep the video
    # bytes after the end of the file's content are not covered by any tag or signature: they are ignored and reported
    ok = final and signature in ("PASS", "NOT CHECKED", "ABSENT", "ABSENT (format 1)")
    report = {"segments": expected, "frames": frames, "keyframes": keyframes, "complete": final, "format": 2 if hybrid else 1,
              "signature": signature, "signer": hdr.get("signer") if hybrid and isinstance(hdr, dict) else None,
              "trailing_bytes": len(raw) - off if final else 0,
              "status": "PASS" if ok else ("TRUNCATED (no FINAL segment)" if not final else "UNSIGNED (the signature is missing)")}
    if index:
        report["frame_index"] = frame_index
    return hdr, bytes(out), report


def frame_rate(hdr: dict, default: int = 30):
    """The frame rate from a recording header, for the remux command line: a plain number within 1..240 or the
    default (the header is written by whoever made the file)."""
    v = hdr.get("fps") if isinstance(hdr, dict) else None
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) and 1 <= v <= 240 else default
