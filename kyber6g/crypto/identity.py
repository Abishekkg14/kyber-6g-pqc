"""Long-term identities: ML-DSA-87 signing keys with pinned peer keys.

Provisioning (tools/provision.py) creates each node's keypair once and copies
only PUBLIC keys between nodes. During the handshake each side verifies the
peer's signature against the pinned key from disk, never against a key that
arrived in the same message (trust-on-first-use is not used).

The GCS additionally holds an ML-KEM-1024 "recording" keypair. The UAV only
stores its public encapsulation key, so recordings written on the UAV can be
decrypted only by the GCS.
"""
import hashlib
import logging
import os
import stat
from pathlib import Path

import oqs

DEFAULT_DIR = Path(os.environ.get("KYBER6G_KEYDIR", Path.home() / ".kyber6g"))
POSIX = os.name == "posix"
log = logging.getLogger("kyber6g.identity")


def fingerprint(pk: bytes) -> str:
    return hashlib.sha256(pk).hexdigest()[:32]


_LENGTHS = {}


def key_length(alg: str, kind: str) -> int:
    """Size in bytes of a key of `alg`: kind "public" or "secret" (ML-KEM: encapsulation / decapsulation key)."""
    if alg not in _LENGTHS:
        o = oqs.Signature(alg) if alg in oqs.get_enabled_sig_mechanisms() else oqs.KeyEncapsulation(alg)
        _LENGTHS[alg] = {"public": o.details["length_public_key"], "secret": o.details["length_secret_key"]}
    return _LENGTHS[alg][kind]


def sized(data: bytes, alg: str, kind: str, what="key") -> bytes:
    """`data` if it has exactly the size of such a key, else ValueError.

    Every key that comes from a file or from the peer passes here before liboqs sees it: the Python binding copies a
    key into a buffer of the right size and FILLS A SHORT ONE WITH ZEROS without a word. A recording key file cut
    short would encapsulate to a key nobody holds - every file sealed with it would be lost, with no error."""
    want = key_length(alg, kind)
    if not isinstance(data, (bytes, bytearray)) or len(data) != want:
        n = len(data) if isinstance(data, (bytes, bytearray)) else type(data).__name__
        raise ValueError(f"{what}: {n} bytes is not an {alg} {kind} key ({want} bytes)")
    return bytes(data)


def _foreign(st) -> bool:
    """True if the file belongs to somebody other than this user or root."""
    return POSIX and st.st_uid not in (os.getuid(), 0)


def private_dir(path: Path) -> Path:
    """The key directory: only its owner may enter it (0700).

    Created if missing. A directory of ours that is wider than 0700 (made by `mkdir` under a permissive umask, as
    on a stock Raspberry Pi OS: 0775) is tightened and the fact is logged; one that belongs to another user is
    refused, because whoever owns the directory can replace the pinned keys in it."""
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not POSIX:
        return path
    st = path.stat()
    if _foreign(st):
        raise PermissionError(f"{path} belongs to another user (uid {st.st_uid}); refusing to use keys from it")
    if st.st_mode & stat.S_ISVTX or path.resolve() == Path(path.anchor):
        # a shared directory (/tmp, /var/tmp) or the file-system root is never taken over and closed to everyone else
        raise PermissionError(f"{path} is a shared directory; use a directory of its own")
    if stat.S_IMODE(st.st_mode) & 0o077:
        try:
            os.chmod(path, 0o700)
        except OSError as e:                     # e.g. a read-only file system (the UAV service runs confined)
            raise PermissionError(f"{path} must be mode 0700 (run: chmod 700 {path}): {e}") from None
        if stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise PermissionError(f"{path} must be mode 0700 and this file system does not enforce it")
        log.warning("%s was accessible to group/others (mode %o); tightened to 0700", path, stat.S_IMODE(st.st_mode))
    return path


def read_secret(path: Path) -> bytes:
    """A secret key file: refused unless it is ours and readable by nobody else."""
    path = Path(path)
    st = path.stat()
    mode = stat.S_IMODE(st.st_mode)
    if POSIX and (mode & 0o077 or _foreign(st)):
        raise PermissionError(f"{path} must belong to this user and not be readable by group/others (mode {oct(mode)})")
    return path.read_bytes()


def read_pinned(path: Path) -> bytes:
    """A trust anchor (a pinned public key): it decides whom this node trusts and to whom recordings are encrypted,
    so nobody but its owner may be able to replace it. The key itself is public; what matters is who can WRITE it."""
    path = Path(path)
    private_dir(path.parent)
    st = path.stat()
    if _foreign(st):
        raise PermissionError(f"{path} belongs to another user (uid {st.st_uid}); refusing to trust it")
    mode = stat.S_IMODE(st.st_mode)
    if POSIX and mode & 0o022:
        try:
            os.chmod(path, mode & ~0o022)
        except OSError as e:
            raise PermissionError(f"{path} must not be writable by group/others (run: chmod go-w {path}): {e}") from None
        if stat.S_IMODE(path.stat().st_mode) & 0o022:
            raise PermissionError(f"{path} must not be writable by group/others and this file system does not enforce it")
        log.warning("%s was writable by group/others (mode %o); tightened. Check its fingerprint: %s",
                    path, mode, fingerprint(path.read_bytes()))
    return path.read_bytes()


def _write_secret(path: Path, data: bytes):
    private_dir(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)


def _write_public(path: Path, data: bytes):
    private_dir(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.chmod(path, 0o644)


class Identity:
    def __init__(self, node_id: bytes, sig_alg: str, sk: bytes, pk: bytes):
        if len(node_id) != 8:
            raise ValueError("node id must be 8 bytes")
        self.node_id = node_id
        self.sig_alg = sig_alg
        self._signer = oqs.Signature(sig_alg, secret_key=sized(sk, sig_alg, "secret", "identity key"))
        self.pk = sized(pk, sig_alg, "public", "identity key")

    def sign(self, msg: bytes) -> bytes:
        return self._signer.sign(msg)

    @property
    def fingerprint(self):
        return fingerprint(self.pk)


def generate_identity(keydir: Path, role: str, sig_alg: str = "ML-DSA-87") -> bytes:
    s = oqs.Signature(sig_alg)
    pk = s.generate_keypair()
    _write_secret(keydir / f"{role}_{sig_alg}.sk", s.export_secret_key())
    _write_public(keydir / f"{role}_{sig_alg}.pk", pk)
    return pk


def load_identity(keydir: Path, role: str, node_id: bytes, sig_alg: str = "ML-DSA-87") -> Identity:
    keydir = Path(keydir)
    if keydir.is_dir():
        private_dir(keydir)
    sk = read_secret(keydir / f"{role}_{sig_alg}.sk")
    return Identity(node_id, sig_alg, sk, (keydir / f"{role}_{sig_alg}.pk").read_bytes())


def load_pinned_peer(keydir: Path, peer_role: str, sig_alg: str = "ML-DSA-87") -> bytes:
    p = Path(keydir) / "peers" / f"{peer_role}_{sig_alg}.pk"
    return sized(read_pinned(p), sig_alg, "public", p)


def load_recording_ek(keydir: Path, kem_alg: str = "ML-KEM-1024") -> bytes:
    """UAV: the ground station's public recording key (pinned: recordings are encrypted to whoever holds its pair)."""
    p = Path(keydir) / "peers" / f"gcs_recording_{kem_alg}.ek"
    return sized(read_pinned(p), kem_alg, "public", p)


def load_recording_dk(keydir: Path, kem_alg: str = "ML-KEM-1024") -> bytes:
    """Ground station: the secret recording key."""
    p = Path(keydir) / f"gcs_recording_{kem_alg}.dk"
    return sized(read_secret(p), kem_alg, "secret", p)


def verify(sig_alg: str, msg: bytes, sig: bytes, pk: bytes) -> bool:
    """True only for a signature of `msg` under `pk`. A key or signature of the wrong size is refused here (the
    binding would fill a short key with zeros), and no error of the library is ever taken for "valid"."""
    try:
        v = oqs.Signature(sig_alg)
        if len(pk) != v.details["length_public_key"] or not 0 < len(sig) <= v.details["length_signature"]:
            return False
        return bool(v.verify(msg, sig, pk))
    except Exception:
        return False


def generate_recording_kem(keydir: Path, kem_alg: str = "ML-KEM-1024") -> bytes:
    k = oqs.KeyEncapsulation(kem_alg)
    ek = k.generate_keypair()
    _write_secret(keydir / f"gcs_recording_{kem_alg}.dk", k.export_secret_key())
    _write_public(keydir / f"gcs_recording_{kem_alg}.ek", ek)
    return ek


# The classical half of the recording key (stored files use a hybrid key wrap: ML-KEM-1024 AND X25519, see
# recording/sealing.py). Raw 32-byte keys, as X25519 defines them.
RECORDING_X = "gcs_recording_X25519"


def generate_recording_x25519(keydir: Path) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import x25519
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
    sk = x25519.X25519PrivateKey.generate()
    pk = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    _write_secret(Path(keydir) / f"{RECORDING_X}.sk", sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()))
    _write_public(Path(keydir) / f"{RECORDING_X}.pk", pk)
    return pk


def load_recording_xpk(keydir: Path):
    """UAV: the ground station's public X25519 recording key (pinned), or None if this node has not been given one
    yet (a deployment made before format 2: files are then written in format 1, ML-KEM-1024 alone, unsigned)."""
    p = Path(keydir) / "peers" / f"{RECORDING_X}.pk"
    if not p.exists():
        return None
    pk = read_pinned(p)
    if len(pk) != 32:
        raise ValueError(f"{p} is not an X25519 public key (32 bytes)")
    return pk


def load_recording_xsk(keydir: Path):
    """Ground station: the secret X25519 recording key, or None if none was made yet (only format-1 files can then
    be opened)."""
    p = Path(keydir) / f"{RECORDING_X}.sk"
    if not p.exists():
        return None
    sk = read_secret(p)
    if len(sk) != 32:
        raise ValueError(f"{p} is not an X25519 secret key (32 bytes)")
    return sk
