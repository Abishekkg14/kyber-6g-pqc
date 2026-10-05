"""What the stored-photo encryption does to a picture, in the numbers image-encryption papers report.

    python -m kyber6g.tools.media_stats --image PICTURE [-o media_stats.json] [--png-dir DIR] [--max-side 768]

The system stores a photo as a JPEG sealed in a .k6gimg file (kyber6g/recording/photos.py, file format 2: content key
wrapped with ML-KEM-1024 + X25519, content under AES-256-GCM, file signed with ML-DSA-87). A JPEG is compressed and
already looks random, so the classical picture statistics say little about it. To make them visible, this tool seals
the UNCOMPRESSED pixels of a picture with the very same function and looks at the result as a picture again:

  histogram       of plain and of cipher pixels, per colour channel; chi-square against a flat histogram
  entropy         bits per pixel value (8 = flat)
  correlation     of every pixel with its right, lower and lower-right neighbour
  NPCR / UACI     share of pixel values that differ, and their mean difference, between two cipher pictures:
                    - the same picture stored twice (a new key every time, as the system does)
                    - the picture with ONE pixel value changed by one, stored again
                    - the same key and nonce for both (which the system never does): shows the stream structure of
                      GCM, and why "never the same key and nonce twice" is the rule that matters
  wrong key       the keystream of a key that differs in one bit, applied without the tag check (the implementation
                  itself refuses the file: the tag fails)
  round trip      opening the file gives back every byte (and the SHA-256 in the header says so too)

These are sanity checks: a broken cipher would show here, a secure one cannot be proven here. The security of the
format rests on ML-KEM-1024, X25519, AES-256-GCM and ML-DSA-87 (docs/CRYPTANALYSIS_REPORT.txt).
"""
import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from PIL import Image

from ..crypto import identity as idm
from ..recording import sealing
from ..recording.photos import BODY_NONCE, PhotoError, open_image, seal_image
from .bench_crypto import environment

RNG = np.random.default_rng(20261004)
IDEAL = {"npcr_pct": 100 * 255 / 256, "uaci_pct": 100 * (256 ** 2 - 1) / (3 * 256 * 255), "entropy_bits": 8.0,
         "chi_square_5pct_limit": 293.25}            # two independent uniform bytes; chi-square, 255 degrees of freedom


def channel_stats(a: np.ndarray):
    """a: H x W x 3, uint8."""
    out = {"entropy_bits": [], "chi_square": [], "histogram": [], "correlation": {"horizontal": [], "vertical": [], "diagonal": []}}
    for c in range(3):
        x = a[:, :, c].astype(np.float64)
        h = np.bincount(a[:, :, c].ravel(), minlength=256).astype(np.float64)
        p = h[h > 0] / h.sum()
        out["entropy_bits"].append(round(float(-(p * np.log2(p)).sum()), 5))
        e = h.sum() / 256
        out["chi_square"].append(round(float(((h - e) ** 2 / e).sum()), 1))
        out["histogram"].append([int(v) for v in h])
        for name, (u, v) in (("horizontal", (x[:, :-1], x[:, 1:])), ("vertical", (x[:-1, :], x[1:, :])), ("diagonal", (x[:-1, :-1], x[1:, 1:]))):
            out["correlation"][name].append(round(float(np.corrcoef(u.ravel(), v.ravel())[0, 1]), 5))
    return out


def npcr_uaci(a: np.ndarray, b: np.ndarray):
    a, b = a.astype(np.int16).ravel(), b.astype(np.int16).ravel()
    return {"npcr_pct": round(float(100 * np.mean(a != b)), 4), "uaci_pct": round(float(100 * np.mean(np.abs(a - b)) / 255), 4),
            "values_that_differ": int(np.sum(a != b)), "values": int(a.size)}


def scatter(a: np.ndarray, n=3000):
    """n random pairs (pixel, right neighbour) of the green channel."""
    g = a[:, :, 1]
    ys, xs = RNG.integers(0, g.shape[0], n), RNG.integers(0, g.shape[1] - 1, n)
    return [[int(g[y, x]), int(g[y, x + 1])] for y, x in zip(ys, xs)]


def body_of(blob: bytes, n: int) -> bytes:
    """The encrypted content of a format-2 file (its last bytes before tag and signature trailer)."""
    tl = 10 + 4627
    return blob[len(blob) - tl - 16 - n:len(blob) - tl - 16]


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--image", required=True)
    ap.add_argument("-o", "--out", default="media_stats.json")
    ap.add_argument("--png-dir", help="write the plain and the cipher picture here (PNG)")
    ap.add_argument("--max-side", type=int, default=768)
    ap.add_argument("--source-note", default="", help="where the picture comes from (written into the output)")
    a = ap.parse_args()
    t_start = time.time()
    im = Image.open(a.image).convert("RGB")
    if max(im.size) > a.max_side:
        im.thumbnail((a.max_side, a.max_side), Image.LANCZOS)
    plain = np.asarray(im, dtype=np.uint8)
    H, W, _ = plain.shape
    raw = plain.tobytes()

    d = Path(tempfile.mkdtemp(prefix="k6g_media_"))
    upk = idm.generate_identity(d, "uav")
    uav = idm.load_identity(d, "uav", b"UAV-STAT")
    ek, dk = idm.generate_recording_kem(d), None
    dk = idm.load_recording_dk(d)
    xpk, xsk = idm.generate_recording_x25519(d), None
    xsk = idm.load_recording_xsk(d)
    meta = {"width": W, "height": H, "pixel_format": "RGB8 (uncompressed, for the statistics)"}
    seal = lambda data: seal_image(ek, data, meta, x25519_pk=xpk, signer=uav)
    seal_ms, open_ms = [], []
    for _ in range(5):
        t0 = time.perf_counter(); blob = seal(raw); seal_ms.append((time.perf_counter() - t0) * 1000)
        t0 = time.perf_counter(); hdr, back = open_image(blob, dk, x25519_sk=xsk, signer_pk=upk); open_ms.append((time.perf_counter() - t0) * 1000)
    cipher = np.frombuffer(body_of(blob, len(raw)), dtype=np.uint8).reshape(H, W, 3)

    out = {"tool": "kyber6g.tools.media_stats", "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t_start)), "environment": environment(),
           "ideal": IDEAL,
           "image": {"file": Path(a.image).name, "source": a.source_note, "width": W, "height": H, "plain_bytes": len(raw), "file_bytes": len(blob),
                     "added_bytes": len(blob) - len(raw), "format": hdr.get("v"), "kem": hdr.get("kem"), "signature": hdr.get("sig_status"),
                     "seal_ms_median": round(statistics.median(seal_ms), 2), "open_ms_median": round(statistics.median(open_ms), 2),
                     "round_trip_identical": back == raw, "plain": channel_stats(plain), "cipher": channel_stats(cipher),
                     "scatter_plain": scatter(plain), "scatter_cipher": scatter(cipher)}}

    # two cipher pictures of the same plain picture, and of one that differs in one pixel value
    blob2 = seal(raw)
    c2 = np.frombuffer(body_of(blob2, len(raw)), dtype=np.uint8).reshape(H, W, 3)
    changed = bytearray(raw)
    pos = (H // 2 * W + W // 2) * 3 + 1
    changed[pos] = (changed[pos] + 1) % 256
    c3 = np.frombuffer(body_of(seal(bytes(changed)), len(raw)), dtype=np.uint8).reshape(H, W, 3)
    key, aad = RNG.bytes(32), b"media-stats"
    g1 = np.frombuffer(AESGCM(key).encrypt(BODY_NONCE, raw, aad)[:-16], dtype=np.uint8)
    g2 = np.frombuffer(AESGCM(key).encrypt(BODY_NONCE, bytes(changed), aad)[:-16], dtype=np.uint8)
    out["differences"] = [
        {"what": "the same picture stored twice (a new key each time, as the system does)", **npcr_uaci(cipher, c2)},
        {"what": "the picture with one pixel value changed by one, stored again (a new key, as the system does)", **npcr_uaci(cipher, c3)},
        {"what": "one pixel value changed, SAME key and nonce (never done by the system): only that value differs", **npcr_uaci(g1, g2)},
    ]

    # a key that is wrong in one bit: what its keystream gives when the tag is not checked (GCM's data counter starts at 2)
    def ctr(k, data):
        dec = Cipher(algorithms.AES(k), modes.CTR(BODY_NONCE[:12] + (2).to_bytes(4, "big"))).decryptor()
        return dec.update(data) + dec.finalize()
    ct = AESGCM(key).encrypt(BODY_NONCE, raw, aad)[:-16]
    assert ctr(key, ct) == raw, "the counter-mode view of GCM does not reproduce the plaintext"
    wrong = np.frombuffer(ctr(bytes([key[0] ^ 1]) + key[1:], ct), dtype=np.uint8).reshape(H, W, 3)
    try:
        AESGCM(bytes([key[0] ^ 1]) + key[1:]).decrypt(BODY_NONCE, AESGCM(key).encrypt(BODY_NONCE, raw, aad), aad)
        refused = False
    except Exception:
        refused = True
    out["wrong_key"] = {"what": "decryption with a key that differs in ONE bit", "implementation_refuses": refused,
                        "without_the_tag_check": {**npcr_uaci(wrong, plain), "entropy_bits": channel_stats(wrong)["entropy_bits"]}}
    # the file as the attacker finds it: one bit changed anywhere must be refused
    flips, refused_n = 200, 0
    for i in RNG.integers(0, len(blob) * 8, flips):
        b = bytearray(blob)
        b[int(i) // 8] ^= 1 << (int(i) % 8)
        try:
            open_image(bytes(b), dk, x25519_sk=xsk, signer_pk=upk)
        except PhotoError:
            refused_n += 1
    out["tamper"] = {"files_with_one_bit_changed": flips, "refused": refused_n}
    out["key_block"] = {"ml_kem_1024_ciphertext": sealing.KEM_CT, "x25519_public_key": sealing.X_LEN, "wrapped_content_key": sealing.WRAPPED,
                        "content_tag": 16, "signature_trailer": 10 + 4627}
    Path(a.out).write_text(json.dumps(out))
    if a.png_dir:
        p = Path(a.png_dir)
        p.mkdir(parents=True, exist_ok=True)
        Image.fromarray(plain).save(p / "plain.png")
        Image.fromarray(cipher).save(p / "cipher.png")
        Image.fromarray(wrong).save(p / "wrong_key.png")
    for f in d.glob("**/*"):
        if f.is_file():
            f.unlink()
    im_ = out["image"]
    print(f"{im_['file']} {W}x{H}: entropy plain {im_['plain']['entropy_bits']} cipher {im_['cipher']['entropy_bits']}")
    print(f"  correlation plain {im_['plain']['correlation']['horizontal']} cipher {im_['cipher']['correlation']['horizontal']} (horizontal)")
    print(f"  chi-square plain {im_['plain']['chi_square']} cipher {im_['cipher']['chi_square']} (5 % limit {IDEAL['chi_square_5pct_limit']})")
    for x in out["differences"]:
        print(f"  NPCR {x['npcr_pct']:8.4f} %  UACI {x['uaci_pct']:8.4f} %  {x['what']}")
    print(f"  wrong key: refused {refused}; without tag check NPCR {out['wrong_key']['without_the_tag_check']['npcr_pct']} %")
    print(f"  seal {im_['seal_ms_median']} ms, open {im_['open_ms_median']} ms, +{im_['added_bytes']} B; round trip identical: {im_['round_trip_identical']}; "
          f"tampered files refused: {refused_n}/{flips}")
    print(f"-> {a.out}")
    return 0 if im_["round_trip_identical"] and refused_n == flips and refused else 1


if __name__ == "__main__":
    sys.exit(main())
