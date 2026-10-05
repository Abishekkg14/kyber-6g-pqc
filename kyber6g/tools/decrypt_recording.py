"""Decrypt a .k6grec recording on the GCS (requires the GCS recording keys).

    python -m kyber6g.tools.decrypt_recording rec.k6grec -o out.mp4

A recording of format 2 is opened with both recording keys (ML-KEM-1024 and X25519) and its ML-DSA-87 signature is
checked against the pinned key of the UAV (~/.kyber6g/peers/uav_ML-DSA-87.pk): a file that the UAV did not write,
or that was changed, is refused. `--no-verify` skips the signature check (to get at the video of a file whose
signature is missing, e.g. after a power cut in the instant it was closed); the report then says so.
"""
import argparse
import subprocess
import sys
from pathlib import Path

from ..crypto import identity as idm
from ..recording.recorder import RecordingError, decrypt_recording, frame_rate


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("-o", "--out", help=".mp4 (remux) or .h264 (raw)")
    ap.add_argument("--keydir", default=str(idm.DEFAULT_DIR))
    ap.add_argument("--no-verify", action="store_true", help="do not check the UAV's signature (format 2)")
    a = ap.parse_args()
    keydir = Path(a.keydir).expanduser()
    dk = idm.load_recording_dk(keydir)
    xsk = idm.load_recording_xsk(keydir)
    signer_pk = None
    if not a.no_verify:
        try:
            signer_pk = idm.load_pinned_peer(keydir, "uav")
        except OSError:
            print("note: no pinned UAV key in the key directory; the signature is not checked")
    try:
        hdr, h264, rep = decrypt_recording(a.file, dk, x25519_sk=xsk, signer_pk=signer_pk)
    except RecordingError as e:
        print(f"FAILED: {e}")
        return 2
    print(f"header: {hdr}\nreport: {rep}")
    if a.out:
        out = Path(a.out)
        if out.suffix == ".mp4":
            r = subprocess.run(["ffmpeg", "-y", "-loglevel", "error", "-framerate", str(frame_rate(hdr)),
                                "-f", "h264", "-i", "pipe:0", "-c", "copy", "-movflags", "+faststart", str(out)], input=h264)
            return r.returncode
        out.write_bytes(h264)
    return 0 if rep["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
