"""Sealed audio clips on the UAV (~/kyber6g_audio).

    aud_YYYYmmdd_HHMMSS_NNNNNN.k6gaud   one clip (quaver.py); only the ground station can open it
    chain.json                           number and Merkle root of the last clip this UAV sealed
    inbox/                               audio files waiting to be sealed

Where the audio comes from. With a microphone, frames would come from the sound card as they are spoken. This board
has none, so a file put into inbox/ (run/kyber6g.sh audio-put) stands in for it: `record()` reads it frame by frame,
seals it exactly as a microphone's frames would be sealed, and removes the file: after that the UAV holds the clip
only in a form it cannot read itself.

The chain. Every clip's sealed description names the clip before it (its number and the root the UAV signed for it).
A clip that is deleted from the card, put back in an older state or replaced leaves a gap that the ground station
sees when it has the clips on either side.
"""
import json
import os
import time
from pathlib import Path

from ..crypto import identity as idm
from . import framing, quaver

MAX_SOURCE = 200 << 20                       # a source file is read into memory: 200 MB is 100 minutes of 256 kbit/s


class AudioStore:
    def __init__(self, directory, gcs_rec_ek: bytes, x25519_pk: bytes, signer, uav_id: str = "", gnss=None):
        self.dir = idm.private_dir(Path(directory).expanduser())
        self.inbox = idm.private_dir(self.dir / "inbox")
        self.ek, self.x_pk, self.signer, self.uav_id = gcs_rec_ek, x25519_pk, signer, uav_id
        self.gnss = gnss or (lambda: {})                 # () -> the GNSS state of this moment (fix, lat, lon, ...)
        self._chain = self.dir / "chain.json"

    # ------------------------------------------------------------------ what could be recorded
    def sources(self):
        out = []
        for p in sorted(self.inbox.iterdir()):
            try:
                if p.is_file() and not p.name.startswith("."):
                    out.append({"name": p.name, "bytes": p.stat().st_size})
            except OSError:
                continue
        return out

    def chain(self) -> dict:
        try:
            c = json.loads(self._chain.read_text())
            if isinstance(c, dict) and isinstance(c.get("clip_no"), int):
                return c
        except (OSError, ValueError):
            pass
        return {"clip_no": 0, "root": None}

    # ------------------------------------------------------------------------------- recording
    def record(self, source: str, frames_per_block: int = 8, keep_source: bool = False, on_block=None, realtime: bool = False,
               should_stop=None, frame_cap: int = 0) -> dict:
        """Seal the file inbox/<source> as one clip, as if it were being spoken into a microphone now.

        on_block(kind, index, bytes): called with ("head", -1, head), then ("block", i, block) for every sealed
        block in order, then ("trailer", n, trailer): the bytes that are written to the card, for sending them on.
        realtime: frames are taken at the speed a microphone would deliver them (a block of 0.2 s every 0.2 s).
        should_stop(): asked before every frame; True closes the clip there, cleanly.
        frame_cap: the largest frame the encoder may produce, in bytes: the block size then does not depend on what
        was recorded (0: the largest frame of this source decides).
        """
        src = self.inbox / Path(source).name
        if not src.is_file():
            raise FileNotFoundError(f"no such audio source on the UAV: {Path(source).name}")
        if src.stat().st_size > MAX_SOURCE:
            raise ValueError(f"{src.name} is larger than {MAX_SOURCE >> 20} MB")
        data = src.read_bytes()
        fmt, prefix, frames, suffix = framing.split(data)
        fmt = quaver.with_cap(fmt, frame_cap)
        t0 = time.time()
        g = self.gnss() or {}
        has_fix = (g.get("mode") or 0) >= 2 and g.get("lat") is not None
        chain = self.chain()
        per_frame = (fmt["samples_per_frame"] / fmt["sample_rate"]) if fmt.get("sample_rate") and fmt.get("samples_per_frame") else 0.0

        def context(frame):                  # when and where the block that starts with this frame was captured
            now = self.gnss() or {} if has_fix else {}
            return int((t0 + frame * per_frame) * 1000), now.get("lat") if has_fix else None, now.get("lon") if has_fix else None

        meta = {"uav": self.uav_id, "source": "file", "source_name": src.name[:80], "clip_no": chain["clip_no"] + 1,
                "prev_root": chain.get("root"), "gnss": {k: g.get(k) for k in ("mode", "lat", "lon", "alt_m", "time", "sats_used")}}
        sealer = quaver.AudioSealer(self.ek, self.x_pk, self.signer, fmt, frames_per_block=frames_per_block, prefix=prefix,
                                    meta=meta, context=context)
        name = time.strftime("aud_%Y%m%d_%H%M%S", time.localtime(t0)) + f"_{meta['clip_no']:06d}.k6gaud"
        path, tmp = self.dir / name, self.dir / (name + ".part")
        emit = on_block or (lambda kind, i, b: None)
        n = 0
        with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
            def put(blocks):
                nonlocal n
                for b in blocks:
                    f.write(b)
                    emit("block", n, b)
                    n += 1
            f.write(sealer.head)
            emit("head", -1, sealer.head)
            put(sealer.start())
            clock0, taken = time.monotonic(), 0
            for fr in frames:
                if should_stop is not None and should_stop():
                    suffix = b""                         # stopped: the clip ends here, without what followed the audio
                    break
                blocks = sealer.add(fr)
                taken += 1
                if realtime and blocks:
                    wait = clock0 + taken * per_frame - time.monotonic()
                    if wait > 0:
                        time.sleep(wait)
                put(blocks)
            tail, trailer = sealer.finish(suffix)
            put(tail)
            f.write(trailer)
            emit("trailer", n, trailer)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        root = trailer[13:45].hex()
        self._write_chain({"clip_no": meta["clip_no"], "root": root, "name": name, "t": t0})
        if not keep_source:
            try:
                src.unlink()                 # the plain file is gone; a flash card may keep its blocks until they are reused
            except OSError:
                pass
        return {"name": name, "clip_id": sealer.clip_id.hex(), "clip_no": meta["clip_no"], "codec": fmt["codec"], "frames": sealer.n_frames,
                "audio_blocks": sealer.audio_blocks, "blocks": n, "block_bytes": sealer.block_len, "bytes": path.stat().st_size,
                "source_bytes": len(data), "duration_s": framing.duration_s(fmt, sealer.n_frames), "root": root,
                "seal_ms": round(sealer.seal_s * 1000, 1), "total_ms": round((time.time() - t0) * 1000, 1), "source_kept": bool(keep_source)}

    def _write_chain(self, c: dict):
        tmp = self._chain.with_suffix(".tmp")
        with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as f:
            json.dump(c, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self._chain)

    def recover_parts(self):
        """Clips whose sealing was cut off (a power failure): closed from what reached the card and signed as
        'not closed by its sealer'. Called at start-up."""
        done = []
        for part in sorted(self.dir.glob("*.k6gaud.part")):
            final = part.with_suffix("")                 # aud_....k6gaud
            try:
                fixed = quaver.recover(part.read_bytes(), self.signer)
                with os.fdopen(os.open(final, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:
                    f.write(fixed)
                    f.flush()
                    os.fsync(f.fileno())
                done.append(final.name)
            except (quaver.AudioError, OSError):
                pass                                     # not even one whole block: nothing to keep
            try:
                part.unlink()
            except OSError:
                pass
        return done

    # ---------------------------------------------------------------------------- what is there
    def list(self):
        out = []
        for p in sorted(self.dir.glob("*.k6gaud")):
            try:
                st = p.stat()
                with open(p, "rb") as f:
                    head = f.read(4096)
                hl = int.from_bytes(head[8:10], "big")
                hdr = json.loads(head[10:10 + hl])
                out.append({"name": p.name, "bytes": st.st_size, "mtime": st.st_mtime, "clip_id": hdr.get("clip_id"),
                            "block_bytes": hdr.get("block")})
            except (OSError, ValueError):
                out.append({"name": p.name, "error": "unreadable"})
        return out

    def path(self, name: str) -> Path:
        p = self.dir / Path(name).name
        if p.suffix != ".k6gaud" or not p.is_file():
            raise FileNotFoundError(f"no such audio clip on the UAV: {Path(name).name}")
        return p

    def read(self, name: str) -> bytes:
        return self.path(name).read_bytes()

    def blocks(self, name: str, indices) -> bytes:
        """The sealed blocks with these numbers, one after the other: what the ground station asks for when blocks
        of a live clip did not arrive. It checks each against the root the UAV signed."""
        sa = quaver.SealedAudio(self.read(name))
        idx = [i for i in indices if isinstance(i, int) and not isinstance(i, bool)][:4096]
        return b"".join(sa.block(i) for i in idx)

    def check(self, name: str, own_pk: bytes) -> dict:
        """The stored clip against its own signature (no secret needed, and none is here that could open it)."""
        sa = quaver.SealedAudio(self.read(name))
        sa.verify(own_pk)
        return sa.public()

    def listing(self, clips: int = 120, sources: int = 40) -> dict:
        """What `list_audio` answers: the counts of usage(), the newest clips, and the files waiting in the inbox by name
        (usage() only counts them: "sources" is the list here)."""
        return {**self.usage(), "clips": self.list()[-clips:], "sources": self.sources()[:sources], "dir": str(self.dir)}

    def usage(self):
        files = list(self.dir.glob("*.k6gaud"))
        return {"count": len(files), "bytes": sum(p.stat().st_size for p in files), "sources": len(self.sources()),
                "last_clip_no": self.chain()["clip_no"]}
