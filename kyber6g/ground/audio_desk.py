"""The ground station's side of sealed audio (audio/quaver.py).

A clip reaches the ground station in one of two ways, and ends up as the same bytes either way:

  from the card   `fetch_audio`: the whole .k6gaud over the link's reliable transfer.
  live            while the UAV seals it: the head (reliable), every sealed block as it is made (not repeated: a block
                  that is lost on the air is simply missing for now), and at the end the root record and signature
                  (reliable). The blocks that did not arrive are then asked for by number from the UAV's stored copy.
                  The clip is accepted when all its blocks hash to the root the UAV signed, so it does not matter by
                  which of the two ways a block came.

While a clip comes in live its blocks are opened as they arrive and offered as a stream to listen to (/audio_live).
That is the only use made of a block before the signature is there: the head and the blocks came through the link's
authenticated session with the pinned UAV, and nothing is stored as a clip until root and signature have passed.

An EXCERPT (seconds a to b of a stored clip) can be handed to someone else: see quaver.make_excerpt. This module
writes the bundle and, to show what its receiver gets, verifies it the way they would: with the UAV's public key only.
"""
import collections
import hashlib
import json
import struct
import threading
import time
from pathlib import Path

from ..audio import quaver
from ..audio.quaver import AudioError

LIVE_EXT = struct.Struct("!c4sIHH")          # b"L", tag, block number, chunk, chunks  (uav/main.py AUDIO_EXT)
EXT_OF = {"mp3": ".mp3", "raw": ".bin"}
MAX_LIVE_BLOCKS = 1 << 16                    # blocks of one live clip kept in memory (6.7 kB each for 256 kbit/s MP3)
SKIP_AFTER_S = 0.6                           # live listening: a block that has not come by then is not waited for
LISTEN_WAIT_S = 8.0                          # a listener that names a clip by its tag waits this long for it to begin
KEEP_DONE_S = 60.0                           # a finished live clip's blocks stay in memory this long (late listeners)
REPAIR_RETRY_S = 6.0                         # missing blocks that were asked for and have not come are asked for again after
REPAIR_TRIES = 6                             # this long, twice as long each time (6, 12, 24, 48, 96 s), this many times in all


def audio_ext(codec) -> str:
    return EXT_OF.get(codec, ".wav" if str(codec).startswith("pcm") else ".bin")


class LiveClip:
    def __init__(self, tag: str):
        self.tag, self.t0 = tag, time.monotonic()
        self.head = self.hdr = self.tree = self.clip_id = self.head_hash = None
        self.S = self.plain_len = 0
        self.parts = {}                      # block number -> {chunk: bytes}, until complete
        self.blocks = {}                     # block number -> sealed block
        self.on_air = set()                  # numbers of the blocks that arrived live (not fetched afterwards)
        self.trailer = self.info = None
        self.next_play, self.waiting_since = 0, None
        self.played = collections.deque()    # (seq, bytes) of the stream opened so far, for listeners
        self.play_seq = 0
        self.done, self.done_at, self.count = False, None, 0
        self.asked, self.asked_at = 0, None      # requests made for missing blocks, and when the last one was made
        self.bad = 0


class AudioDesk:
    def __init__(self, data_dir: Path, rec_dk: bytes, rec_xsk: bytes, uav_pk: bytes, note, ask_uav=None):
        self.dir = Path(data_dir) / "audio"
        for sub in ("sealed", "excerpts"):
            (self.dir / sub).mkdir(parents=True, exist_ok=True)
        self.dk, self.xsk, self.uav_pk = rec_dk, rec_xsk, uav_pk
        self.note, self.ask_uav = note, ask_uav          # ask_uav(cmd, args) -> the UAV's answer
        self.clips = []                                  # newest first, for the dashboard
        self.live = collections.OrderedDict()            # tag -> LiveClip (the last few)
        self.cond = threading.Condition()
        self.stats = {"clips_ok": 0, "clips_refused": 0, "live_blocks": 0, "live_blocks_bad": 0, "blocks_repaired": 0, "excerpts": 0}
        self._chain_path = self.dir / "chain.json"
        try:
            self.chain = {int(k): v for k, v in json.loads(self._chain_path.read_text()).items()}
        except (OSError, ValueError, AttributeError):
            self.chain = {}
        self._restore()

    # ------------------------------------------------------------------------------- state
    def _restore(self):
        try:
            metas = sorted(self.dir.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
            for m in metas[:24]:
                if m.name == "chain.json":
                    continue
                e = json.loads(m.read_text())
                if isinstance(e, dict) and e.get("file") and (self.dir / e["file"]).is_file():
                    self.clips.append(e)
        except (OSError, ValueError):
            pass

    def state(self) -> dict:
        live = None
        if self.live:
            lc = next(reversed(self.live.values()))
            live = {"tag": lc.tag, "blocks": lc.count or len(lc.blocks), "on_air": len(lc.on_air), "done": lc.done, "has_head": lc.head is not None,
                    "expected": (lc.info or {}).get("blocks"), "age_s": round(time.monotonic() - lc.t0, 1)}
        return {"clips": self.clips[:12], "live": live, "stats": dict(self.stats), "chain_known": len(self.chain)}

    # ------------------------------------------------------------------- a whole clip arrives
    def on_clip(self, info: dict, data, how: str = "from the UAV's card", extra: dict = None):
        """A complete .k6gaud: verify, open, store. Returns the entry shown on the dashboard."""
        entry = {"name": info.get("name"), "size": info.get("size"), "integrity": info.get("integrity"), "seconds": info.get("seconds"),
                 "received_at": time.time(), "how": how, **(extra or {})}
        if data is None:
            entry["decrypt"] = "FAILED: transfer incomplete"
            return self._keep(entry, None)
        t0 = time.perf_counter()
        try:
            meta, stream, rep = quaver.open_audio(data, self.dk, self.xsk, self.uav_pk)
        except AudioError as e:
            self.stats["clips_refused"] += 1
            entry.update(decrypt=f"FAILED: {e}", signature="FAIL" if "signature" in str(e) or "signed" in str(e) else None)
            return self._keep(entry, None)
        name = Path(str(info["name"])).stem
        (self.dir / "sealed" / (name + ".k6gaud")).write_bytes(data)
        out = name + audio_ext(meta.get("codec"))
        (self.dir / out).write_bytes(stream)
        first = rep["context"][0] if rep["context"] else {}
        entry.update(decrypt="PASS", signature=rep["signature"], open_ms=round((time.perf_counter() - t0) * 1000, 1), file=out,
                     url=f"/audio/{out}", clip_id=rep["clip_id"], clip_no=meta.get("clip_no"), codec=meta.get("codec"),
                     sample_rate=meta.get("sample_rate"), channels=meta.get("channels"), bitrate=meta.get("bitrate"),
                     duration_s=rep["duration_s"], frames=rep["frames"], blocks=rep["blocks"], audio_blocks=rep["audio_blocks"],
                     block_bytes=rep["block_bytes"], stream_bytes=rep["stream_bytes"], sha256=rep["sha256"], complete=rep["complete"],
                     source=meta.get("source"), uav=meta.get("uav"), captured_ms=first.get("t_ms"), lat=first.get("lat"), lon=first.get("lon"),
                     chain=self._chain_check(meta, data))
        self.stats["clips_ok"] += 1
        return self._keep(entry, name)

    def _chain_check(self, meta: dict, data: bytes) -> str:
        """Where this clip stands in the UAV's chain of clips: each names the one before it (number and signed root)."""
        no, prev = meta.get("clip_no"), meta.get("prev_root")
        root = quaver.SealedAudio(data).root.hex()
        if not isinstance(no, int) or isinstance(no, bool):
            return "no number"
        known = self.chain.get(no)
        self.chain[no] = root
        try:
            self._chain_path.write_text(json.dumps(self.chain))
        except OSError:
            pass
        if known is not None and known != root:
            return f"CONFLICT: another clip no. {no} was received before"
        if no - 1 in self.chain:
            return "OK: follows clip %d" % (no - 1) if self.chain[no - 1] == prev else f"BROKEN: clip {no - 1} here is not the one this clip follows"
        return "first clip" if prev is None else f"clip {no - 1} not fetched: cannot be checked"

    def _keep(self, entry: dict, stem):
        if stem:
            try:
                (self.dir / (stem + ".json")).write_text(json.dumps(entry, indent=1, default=str))
            except OSError:
                pass
        self.clips[:] = [entry] + [c for c in self.clips if c.get("name") != entry.get("name")][:23]
        self.note("AUDIO", f"{entry.get('name')} {entry.get('how')}: transfer {entry.get('integrity')} signature {entry.get('signature')} "
                           f"decrypt {entry.get('decrypt')} chain {entry.get('chain')}")
        return entry

    # ----------------------------------------------------------------------- a clip comes in live
    def _live(self, tag: str) -> LiveClip:
        lc = self.live.get(tag)
        if lc is None:
            lc = self.live[tag] = LiveClip(tag)
            while len(self.live) > 3:
                self.live.popitem(last=False)
        return lc

    def on_head(self, info: dict, data):
        tag = str((info.get("meta") or {}).get("tag") or "")[:16]
        if data is None or not tag:
            return
        with self.cond:
            lc = self._live(tag)
            try:
                sa_head, hdr, rest = quaver._split_head(data)
                if rest:
                    raise AudioError("bytes after the head")
                lc.head, lc.hdr, lc.S = data, hdr, hdr["block"]
                lc.clip_id, lc.head_hash = bytes.fromhex(hdr["clip_id"]), hashlib.sha256(data).digest()
                lc.plain_len = lc.S - quaver.COMMIT - quaver.TAG

                class _Head:                              # what _clip_tree needs of a clip: its head and id
                    head, clip_id = data, lc.clip_id
                lc.tree = quaver._clip_tree(_Head, self.dk, self.xsk)
            except AudioError as e:
                self.note("AUDIO", f"live clip {tag}: head refused ({e})")
                lc.head = None
                return
            self._play(lc)
            self.cond.notify_all()
        self.note("AUDIO", f"live clip {tag} begins (clip id {hdr['clip_id'][:12]}, blocks of {lc.S} bytes)")

    def on_live_chunk(self, ext: bytes, payload: bytes):
        if len(ext) != LIVE_EXT.size:
            return
        _, tag, index, idx, cnt = LIVE_EXT.unpack(ext)
        if not 0 < cnt <= 64 or idx >= cnt or index >= MAX_LIVE_BLOCKS:
            return
        with self.cond:
            lc = self._live(tag.hex())
            if lc.done or index in lc.blocks:
                return
            parts = lc.parts.setdefault(index, {})
            parts[idx] = payload
            if len(parts) < cnt:
                if len(lc.parts) > 64:                    # blocks that will never be completed are not kept
                    for old in sorted(lc.parts)[:-32]:
                        lc.parts.pop(old, None)
                return
            block = b"".join(parts[k] for k in range(cnt))
            lc.parts.pop(index, None)
            lc.blocks[index] = block
            lc.on_air.add(index)
            self.stats["live_blocks"] += 1
            self._play(lc)
            self.cond.notify_all()

    def _play(self, lc: LiveClip):
        """Open, in order, the blocks that are there, for whoever listens. A block that has not come after
        SKIP_AFTER_S is passed over: live audio that waits is not live."""
        if lc.tree is None:
            return
        now = time.monotonic()
        while True:
            blk = lc.blocks.get(lc.next_play)
            if blk is None:
                later = [i for i in lc.blocks if i > lc.next_play]
                if not later:
                    lc.waiting_since = None
                    return
                if lc.waiting_since is None:
                    lc.waiting_since = now
                if now - lc.waiting_since < SKIP_AFTER_S and len(later) < 4:
                    return
                lc.next_play = min(later)
                lc.waiting_since = None
                continue
            lc.waiting_since = None
            try:
                b = quaver.open_block(lc.tree, lc.clip_id, lc.head_hash, lc.next_play, blk, lc.plain_len)
                if b["kind"] in (quaver.AUDIO, quaver.ANCILLARY) and b["data"]:
                    lc.play_seq += 1
                    lc.played.append((lc.play_seq, b["data"]))
            except AudioError:
                lc.bad += 1
                self.stats["live_blocks_bad"] += 1
                lc.blocks.pop(lc.next_play, None)         # not a block of this clip: it will be asked for again at the end
                lc.on_air.discard(lc.next_play)
            lc.next_play += 1

    def on_trailer(self, info: dict, data):
        meta = info.get("meta") or {}
        tag = str(meta.get("tag") or "")[:16]
        if data is None or not tag or len(data) < 45 or data[:8] != quaver.ROOT_MAGIC:
            return
        with self.cond:
            lc = self._live(tag)
            lc.trailer, lc.info = data, meta
            self.cond.notify_all()
        self._finish(lc)

    def on_blocks(self, info: dict, data):
        """Blocks fetched again from the UAV's card, in the order they were asked for."""
        meta = info.get("meta") or {}
        lc = self.live.get(str(meta.get("tag") or ""))
        idx = meta.get("blocks")
        if lc is None or data is None or not isinstance(idx, list) or not lc.S or len(data) != len(idx) * lc.S:
            return
        with self.cond:
            for k, i in enumerate(idx):
                if isinstance(i, int) and not isinstance(i, bool) and 0 <= i < MAX_LIVE_BLOCKS and i not in lc.blocks:
                    lc.blocks[i] = data[k * lc.S:(k + 1) * lc.S]
                    self.stats["blocks_repaired"] += 1
        self._finish(lc)

    def _finish(self, lc: LiveClip):
        """Root record and signature are there: complete the clip, or ask the UAV for the blocks that are missing.

        The request, or its answer, can be lost like anything else on the link (measured: with 5 % and 20 % of the
        datagrams dropped, two of twelve clips were never completed because the one request made got no answer). So the
        request is not waited for: tick() makes it again when the blocks have not come, and whatever arrives is taken.
        What is decided here is decided under the lock, so that the receive path and the timer cannot both complete
        the same clip."""
        ask = data = None
        with self.cond:
            if lc.done or lc.trailer is None or lc.head is None:
                return
            n = struct.unpack_from("!I", lc.trailer, 9)[0]
            if not 1 <= n <= MAX_LIVE_BLOCKS:
                return
            missing = [i for i in range(n) if i not in lc.blocks]
            name = str((lc.info or {}).get("name") or f"live_{lc.tag}.k6gaud")
            if not missing:
                data = lc.head + b"".join(lc.blocks[i] for i in range(n)) + lc.trailer
                on_air = len([i for i in lc.on_air if i < n])
                lc.done, lc.count = True, n
                self.cond.notify_all()
            elif lc.asked >= REPAIR_TRIES or self.ask_uav is None:
                lc.done = True
            else:
                lc.asked, lc.asked_at = lc.asked + 1, time.monotonic()
                ask = {"name": name, "blocks": missing[:1024], "tag": lc.tag}
        if data is not None:
            self.on_clip({"name": name, "size": len(data), "integrity": "PASS", "seconds": round(time.monotonic() - lc.t0, 1)}, data,
                         how="live", extra={"live_blocks_on_air": on_air, "live_blocks_repaired": n - on_air, "live_blocks_refused": lc.bad,
                                            "live_requests_for_blocks": lc.asked})
        elif ask is not None:
            self.ask_uav("audio_blocks", ask)             # the blocks come back through on_blocks; no answer: tick() asks again
        else:
            self.note("AUDIO", f"live clip {name}: {len(missing)} of {n} blocks did not come after {lc.asked} requests; fetch the clip from the card")

    def tick(self):
        """Once in a while: move on past a block that never came, so listeners are not kept waiting; ask again for
        missing blocks that were asked for and did not come; and let go of the blocks of a clip that was finished a
        while ago (the clip itself is on disk by then)."""
        now = time.monotonic()
        again = []
        with self.cond:
            for lc in self.live.values():
                if not lc.done and lc.waiting_since is not None:
                    before = lc.play_seq
                    self._play(lc)
                    if lc.play_seq != before:
                        self.cond.notify_all()
                elif lc.done:
                    if lc.done_at is None:
                        lc.done_at = now
                    elif now - lc.done_at > KEEP_DONE_S and (lc.blocks or lc.played):
                        lc.blocks.clear(); lc.parts.clear(); lc.played.clear()
                # blocks that were asked for and have not come: the request (or its answer) was lost
                if not lc.done and lc.asked_at is not None and now - lc.asked_at > REPAIR_RETRY_S * 2 ** (lc.asked - 1):
                    again.append(lc)
        for lc in again:
            self._finish(lc)

    def listen(self, tag: str = None, timeout: float = 20.0):
        """The opened stream of a live clip as it grows: yields bytes until the clip is complete (or nothing comes
        for `timeout` seconds). Without a tag: the clip that began last."""
        with self.cond:
            if tag:
                # The listener is usually here first: the UAV answers "started, tag X" before the clip's head has
                # come over the link. So a clip that was asked for by its tag is waited for (briefly: a tag that
                # never comes must not hold a server thread for long).
                tag = str(tag)[:16]
                self.cond.wait_for(lambda: tag in self.live, timeout=min(timeout, LISTEN_WAIT_S))
                lc = self.live.get(tag)
            else:
                if not self.live:
                    self.cond.wait_for(lambda: bool(self.live), timeout=timeout)
                lc = next(reversed(self.live.values())) if self.live else None
        if lc is None:
            return
        seq = 0
        while True:
            with self.cond:
                self.cond.wait_for(lambda: (lc.played and lc.played[-1][0] > seq) or lc.done, timeout=timeout)
                out = [d for s, d in lc.played if s > seq]
                if lc.played:
                    seq = lc.played[-1][0]
                done = lc.done
            if not out and not done:
                return                                    # nothing for `timeout` seconds
            for d in out:
                yield d
            if done and not out:
                return

    # -------------------------------------------------------------------------------- excerpt
    def excerpt(self, name: str, t0: float, t1: float, with_meta: bool = True) -> dict:
        """Seconds t0..t1 of a stored clip as a bundle for a third party, and what that party can check with the
        UAV's public key alone."""
        stem = Path(str(name)).stem
        sealed = self.dir / "sealed" / (stem + ".k6gaud")
        if not sealed.is_file():
            raise FileNotFoundError(f"no such clip on the ground station: {stem}")
        raw = sealed.read_bytes()
        meta, stream, rep = quaver.open_audio(raw, self.dk, self.xsk, self.uav_pk)
        a, b = quaver.blocks_for_time(meta, rep["audio_blocks"], float(t0), float(t1))
        bundle = quaver.make_excerpt(raw, self.dk, self.xsk, self.uav_pk, a, b, with_meta=bool(with_meta))
        info, audio, blocks = quaver.verify_excerpt(bundle, self.uav_pk)        # as its receiver would
        base = f"{stem}_blocks{a}-{b}"
        (self.dir / "excerpts" / (base + ".k6gax")).write_bytes(bundle)
        aud = base + audio_ext(meta.get("codec"))
        (self.dir / "excerpts" / aud).write_bytes(wav_wrap(meta, audio) if str(meta.get("codec")).startswith("pcm") else audio)
        first = next((x for x in blocks if x["kind"] == quaver.AUDIO), {})
        self.stats["excerpts"] += 1
        res = {"clip": stem, "blocks": [a, b], "blocks_in_clip": rep["blocks"], "bundle": f"/audio/excerpts/{base}.k6gax", "bundle_bytes": len(bundle),
               "audio": f"/audio/excerpts/{aud}", "audio_bytes": len(audio), "frames": info["frames"],
               "duration_s": info["duration_s"] if info["duration_s"] is not None else quaver.framing.duration_s(meta, info["frames"]),
               "keys_released": sum(len(quaver.cover(lo, hi, quaver.DEPTH)) for lo, hi in info["ranges"]),
               "verified_with_public_key_only": info["signature"], "with_description": bool(with_meta),
               "captured_ms": first.get("t_ms"), "lat": first.get("lat"), "lon": first.get("lon"), "clip_bytes": len(raw)}
        self.note("AUDIO", f"excerpt of {stem}: blocks {a}..{b} of {rep['blocks']} ({res['duration_s']:.1f} s), {len(bundle)} B, "
                           f"{res['keys_released']} keys released; verifies with the UAV's public key alone")
        return res


def wav_wrap(meta: dict, pcm: bytes) -> bytes:
    """PCM frames of an excerpt as a WAVE file of their own (the clip's own header is not part of an excerpt)."""
    ch, sr, bits = int(meta.get("channels") or 1), int(meta.get("sample_rate") or 16000), int(meta.get("bits") or 16)
    return b"RIFF" + struct.pack("<I", 36 + len(pcm)) + b"WAVEfmt " + struct.pack("<IHHIIHH", 16, 1, ch, sr, sr * ch * bits // 8, ch * bits // 8, bits) + \
        b"data" + struct.pack("<I", len(pcm)) + pcm
