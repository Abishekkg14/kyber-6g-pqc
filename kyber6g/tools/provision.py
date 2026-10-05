"""Create long-term keys for one node (run once per node).

    python -m kyber6g.tools.provision uav   # on the Pi
    python -m kyber6g.tools.provision gcs   # on the ground station

Secret keys stay on the node (mode 0600). Copy ONLY the printed public files
to the peer's ~/.kyber6g/peers/ directory (deploy/deploy_pi.sh does this).
"""
import argparse
import sys
from pathlib import Path

from ..crypto import identity as idm


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=["uav", "gcs"])
    ap.add_argument("--keydir", default=str(idm.DEFAULT_DIR))
    ap.add_argument("--force", action="store_true", help="overwrite existing keys")
    a = ap.parse_args()
    d = Path(a.keydir).expanduser()
    sk = d / f"{a.role}_ML-DSA-87.sk"
    if sk.exists() and not a.force:
        pk = (d / f"{a.role}_ML-DSA-87.pk").read_bytes()
        print(f"{a.role} identity already exists; fingerprint {idm.fingerprint(pk)}")
    else:
        pk = idm.generate_identity(d, a.role)
        print(f"generated {a.role} ML-DSA-87 identity; fingerprint {idm.fingerprint(pk)}")
    print(f"public: {d / f'{a.role}_ML-DSA-87.pk'}")
    if a.role == "gcs":
        ek_path = d / "gcs_recording_ML-KEM-1024.ek"
        if not ek_path.exists() or a.force:
            ek = idm.generate_recording_kem(d)
            print(f"generated GCS recording ML-KEM-1024 keypair; ek fingerprint {idm.fingerprint(ek)}")
        print(f"public: {ek_path}")
        # the classical half of the recording key: stored photos and recordings use a hybrid key wrap
        # (ML-KEM-1024 AND X25519). Made once; an existing key is kept, or the files written for it could not be read.
        x_path = d / f"{idm.RECORDING_X}.pk"
        if not x_path.exists() or a.force:
            x_pk = idm.generate_recording_x25519(d)
            print(f"generated GCS recording X25519 keypair; pk fingerprint {idm.fingerprint(x_pk)}")
        print(f"public: {x_path}")
    idm.private_dir(d)                    # 0700, also for a directory made earlier under a permissive umask
    idm.private_dir(d / "peers")
    return 0


if __name__ == "__main__":
    sys.exit(main())
