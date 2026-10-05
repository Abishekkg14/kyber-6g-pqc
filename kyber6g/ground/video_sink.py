"""Ground-side video: reorder/reassemble decrypted H.264 chunks, decode, serve.

Reordering (a small time-bounded jitter buffer) is separate from replay
protection (done earlier in the record layer). A frame that is still
incomplete after the jitter window is declared lost; the decoder is then
fed nothing until the next IDR keyframe so it never decodes from a broken
reference chain.
"""
import collections
import queue
import struct
import subprocess
import threading
import time

VIDEO_EXT = struct.Struct("!IHHB")
FLAG_KEY = 1
# Live video must stay live. Frames wait in a queue for the decoder; the queue used to be bounded in FRAMES only (120),
# and when the decoder got slow (measured: a laptop that throttles its processor for 50 s every few minutes under the
# load of the detector and the finder, decoding at a fifth of its normal speed) 120 waiting frames meant a picture
# 20 s behind the camera. A frame that has waited longer than this is given up together with everything behind it, and
# decoding starts again at the next keyframe: the picture skips, it does not fall behind.
BACKLOG_S = 1.0
# An access unit delimiter, written to the decoder after every frame. ffmpeg's H.264 parser knows that a frame has
# ended only when it sees the next one begin, so a frame fed alone waited for the next frame: one frame period (33 ms
# at 30 fps) of latency for nothing, and after a pause the last frame was shown when the stream came back. Measured
# with a recording of the Pi's encoder fed at 30 fps into this very decoder: the picture came out 41 ms (median) after
# its frame was written, 8 ms after the NEXT frame was written; with the delimiter, 8 ms after its own frame.
AUD = b"\x00\x00\x00\x01\x09\xf0"


class VideoSink:
    def __init__(self, ffmpeg="ffmpeg", jitter_ms=150, clock_offset=lambda: None):
        self.ffmpeg = ffmpeg
        self.jitter = jitter_ms / 1000
        self.clock_offset = clock_offset
        self.lock = threading.Lock()
        self.pending = {}           # fid -> {cnt, parts, flags, first}
        self.done = {}              # fid -> (ts_us, data, key, t_complete)
        self.next_fid = None
        self.need_key = True
        self.dec = None
        # one input queue and one timestamp FIFO PER decoder process: threads of a decoder that is being replaced
        # must never take frames meant for the new one, and input/output pairing starts clean with every decoder
        self.inq = queue.Queue(maxsize=120)
        self.latest = None
        self.latest_ts = None           # capture time of `latest` on the camera's clock
        self._latest_mono = 0.0
        self.jpeg_seq = 0
        self.cond = threading.Condition()
        self.fifo = collections.deque(maxlen=300)
        self.s = {"chunks_rx": 0, "frames_complete": 0, "frames_lost": 0, "frames_decoded": 0,
                  "frames_skipped_wait_key": 0, "keyframes": 0, "bytes": 0, "fps": 0.0, "kbps": 0.0,
                  "network_latency_ms": None, "display_latency_ms": None, "decode_ms": None,
                  "chunk_loss_pct": 0.0, "expected_chunks": 0, "decoder": "stopped", "decoder_restarts": 0,
                  "late_chunks": 0, "stream_gaps": 0, "last_gap": None,
                  "decoder_behind": 0, "frames_dropped_decoder_behind": 0,   # times the decoder fell behind / frames given up for it
                  "frames_without_picture": 0}                               # frames the decoder took and gave no picture for
        self._sps = None                # sequence parameter set of the stream being decoded (changes with resolution)
        self._last_frame = None         # arrival time of the newest complete frame
        self._stream_started = 0.0      # arrival time of the first frame after a pause
        self._win = collections.deque()
        self._lat = collections.deque(maxlen=60)
        self._disp = collections.deque(maxlen=60)
        self._dec_ms = collections.deque(maxlen=60)
        self.running = True
        threading.Thread(target=self._reaper, daemon=True, name="video-reaper").start()

    # ------------------------------------------------------------ chunks
    def on_chunk(self, ext: bytes, payload: bytes):
        if len(ext) != VIDEO_EXT.size:
            return
        fid, idx, cnt, flags = VIDEO_EXT.unpack(ext)
        if cnt == 0 or idx >= cnt or cnt > 2000:
            return
        # intervals are measured on the monotonic clock: the wall clock can be stepped (time sync, wake from sleep), and a
        # forward step made every half-received frame look "too old" and be counted as lost
        now = time.monotonic()
        with self.lock:
            self.s["chunks_rx"] += 1
            if self.next_fid is not None and ((fid - self.next_fid) & 0xFFFFFFFF) > 0x7FFFFFFF:
                if ((self.next_fid - fid) & 0xFFFFFFFF) <= self.RESYNC:
                    self.s["late_chunks"] += 1          # arrived after its frame was given up (jitter window too short?)
                    return                              # older than already-delivered frames
                # far behind: not a late chunk but a NEW stream whose numbering started again (the UAV app restarted).
                # Dropping these as "old" would leave the picture frozen until someone pressed LIVE again.
                self._resync("frame numbering restarted", clear_done=True)
            f = self.pending.get(fid)
            if f is None:
                if fid in self.done:
                    return
                if len(self.pending) >= self.MAX_PENDING:     # bounded: the oldest half-received frame makes room
                    del self.pending[next(iter(self.pending))]
                f = self.pending[fid] = {"cnt": cnt, "parts": {}, "flags": flags, "first": now}
            if f["cnt"] != cnt:
                return
            f["parts"][idx] = payload
            if len(f["parts"]) == cnt:
                body = b"".join(f["parts"][i] for i in range(cnt))
                del self.pending[fid]
                self.s["expected_chunks"] += cnt
                if len(body) < 8:                             # no room for the capture time stamp: not a frame
                    self.s["malformed_frames"] = self.s.get("malformed_frames", 0) + 1
                    return
                (ts_us,) = struct.unpack_from("!Q", body)
                self.done[fid] = (ts_us, body[8:], bool(flags & FLAG_KEY), now)
                self._record_latency(ts_us, time.time())
                self._deliver()

    def _record_latency(self, ts_us, now):
        off = self.clock_offset()
        if off is None:
            return
        self._lat.append((now - (ts_us / 1e6 - off)) * 1000)
        self.s["network_latency_ms"] = round(sorted(self._lat)[len(self._lat) // 2], 1)

    def _deliver(self, force_skip=False):
        if self.next_fid is None:
            # (re)start only at a complete IDR keyframe; anything older is useless
            keys = [f for f, v in self.done.items() if v[2]]
            if not keys:
                if len(self.done) > 300:
                    self.done.pop(min(self.done))
                return
            self.next_fid = min(keys)
            for f in [f for f in self.done if ((f - self.next_fid) & 0xFFFFFFFF) > 0x7FFFFFFF]:
                del self.done[f]
        while self.next_fid is not None:
            if self.next_fid in self.done:
                ts_us, data, key, tc = self.done.pop(self.next_fid)
                self._emit(ts_us, data, key)
                self.next_fid = (self.next_fid + 1) & 0xFFFFFFFF
                continue
            # next frame not complete: give up on it if it is too old or newer frames are waiting long
            oldest_done = min((v[3] for v in self.done.values()), default=None)
            p = self.pending.get(self.next_fid)
            mono = time.monotonic()
            stale = (p is not None and mono - p["first"] > self.jitter) or \
                    (p is None and oldest_done is not None and mono - oldest_done > self.jitter)
            if not (stale or force_skip):
                break
            # Far behind what is arriving (complete frames more than 3 s of video ahead of the one we are waiting
            # for): the stream was interrupted - link outage, or this machine was suspended. Start again at the next
            # keyframe instead of walking through, and counting as lost, every frame number in between: after a
            # 43-minute standby of the laptop that showed "92,966 frames lost".
            if self.done and max((f - self.next_fid) & 0xFFFFFFFF for f in self.done) > self.RESYNC:
                self._resync("stream interrupted")
                return self._deliver()
            if p is not None:
                self.s["expected_chunks"] += p["cnt"]
                del self.pending[self.next_fid]
            elif self.done:
                self.s["expected_chunks"] += 1          # entire frame missing (>=1 chunk)
            else:
                break
            self.s["frames_lost"] += 1
            self.need_key = True
            self.next_fid = (self.next_fid + 1) & 0xFFFFFFFF
        self._update_loss()

    RESYNC = 90         # frames (3 s at 30 fps): a jump in the frame numbers larger than this is a new / interrupted stream
    MAX_PENDING = 256   # half-received frames kept at once (8 s of video; normally 1-3)

    def _resync(self, why, clear_done=False):
        """Forget the position in the stream and wait for the next keyframe (called with the lock held). Counted as
        one interruption, not as thousands of lost frames. `clear_done`: complete frames still waiting belong to the
        old numbering and are dropped too."""
        self.s["stream_gaps"] += 1
        self.s["last_gap"] = why
        self.pending.clear()
        if clear_done:
            self.done.clear()
        self.next_fid = None
        self.need_key = True

    def _update_loss(self):
        s = self.s
        frames = s["frames_complete"] + s["frames_lost"]
        s["frame_loss_pct"] = round(100 * s["frames_lost"] / frames, 2) if frames else 0.0
        # expected = chunk counts of completed + abandoned frames (+1 per wholly
        # missing frame, so this is a LOWER BOUND on true packet loss)
        exp = s["expected_chunks"]
        settled_rx = s["chunks_rx"] - sum(len(p["parts"]) for p in self.pending.values())
        s["chunk_loss_pct"] = round(100 * max(0, exp - settled_rx) / exp, 2) if exp else 0.0

    def _emit(self, ts_us, data, key):
        self.s["frames_complete"] += 1
        self.s["bytes"] += len(data)
        self.s["keyframes"] += key
        now = time.monotonic()
        if self._last_frame is None or now - self._last_frame > 2.0:
            self._stream_started = now                  # first frame after a pause
            self._win.clear()
        self._last_frame = now
        self._win.append((now, len(data), ts_us / 1e6))
        while self._win and now - self._win[0][0] > 2:
            self._win.popleft()
        self._rate(now)
        if self.decoder_lag(now) > BACKLOG_S:           # the decoder is behind: skip ahead instead of showing the past
            self.s["decoder_behind"] += 1
            self.s["frames_dropped_decoder_behind"] += self._flush_queue()
            self.need_key = True
        if self.need_key and not key:
            self.s["frames_skipped_wait_key"] += 1
            return
        if key:
            # A new resolution / encoder restart shows as a different SPS. ffmpeg's MJPEG output would keep the
            # size of the first stream (it rescales silently), so the decoder is replaced instead.
            sps = _sps_of(data)
            if sps is not None and self._sps is not None and sps != self._sps:
                self._stop_decoder()
            if sps is not None:
                self._sps = sps
        self.need_key = False
        self._ensure_decoder()
        try:
            self.inq.put_nowait((ts_us, data, time.monotonic()))
        except queue.Full:
            self.need_key = True

    def decoder_lag(self, now=None):
        """How long the oldest frame that is still waiting to be handed to the decoder has waited (seconds); 0.0 when
        nothing waits, which is the normal state (a frame is decoded in about 10 ms). The ML workers look at this too
        and leave the processor to the decoder while it is behind (sched.video_behind)."""
        q = self.inq
        with q.mutex:
            t_in = q.queue[0][2] if q.queue else None
        return 0.0 if t_in is None else max(0.0, (time.monotonic() if now is None else now) - t_in)

    def _flush_queue(self):
        """Give up every frame that waits for the decoder; returns how many. (What the decoder already holds, a few
        frames in its pipe, is still decoded.)"""
        n = 0
        try:
            while True:
                self.inq.get_nowait()
                n += 1
        except queue.Empty:
            return n

    def _rate(self, now):
        """Frame and bit rate of the frames that arrived in the last 2 s.

        Measured on the CAMERA's clock: (frames - 1) / (capture time of the last - capture time of the first). The
        arrival times cannot be trusted for this: frames arrive in bursts when the machine is busy, and the
        ground-station clock itself can run at the wrong rate (a WSL clock 8.3 % slow after the laptop woke from sleep
        made a 30 fps camera read 32.7-34.5 'fps'). Arrival times are only the fallback when frames carry no
        capture time."""
        w = self._win
        if len(w) < 2:
            return
        cap_span = w[-1][2] - w[0][2]
        if cap_span > 0.25:
            n, nbytes, span = len(w) - 1, sum(x[1] for x in list(w)[1:]), cap_span
        else:
            elapsed = now - self._stream_started
            if elapsed >= 2.0:                          # the window is full: count / window
                n, nbytes, span = len(w), sum(x[1] for x in w), 2.0
            else:                                       # stream just started: intervals / time since its first frame
                n, nbytes, span = len(w) - 1, sum(x[1] for x in list(w)[1:]), max(elapsed, 0.5)
        self.s["fps"] = round(n / span, 1)
        self.s["kbps"] = round(nbytes * 8 / span / 1000, 1)

    def _reaper(self):
        while self.running:
            time.sleep(0.05)
            with self.lock:
                self._deliver()
                if self.pending and not self.done:
                    # whole-frame tails: drop very old partial frames
                    for fid in [f for f, p in self.pending.items() if time.monotonic() - p["first"] > 1.0]:
                        self.s["expected_chunks"] += self.pending[fid]["cnt"]
                        del self.pending[fid]
                        self.s["frames_lost"] += 1
                        self.need_key = True
                        if self.next_fid == fid:
                            self.next_fid = (fid + 1) & 0xFFFFFFFF

    # ----------------------------------------------------------- decoder
    def _stop_decoder(self):
        """Retire the running decoder (new stream / new resolution). Its threads end with it; the next frame starts
        a fresh process with its own queue and timestamp FIFO, so capture times cannot be paired with the wrong frame."""
        p, self.dec = self.dec, None
        if p is None:
            return
        self.s["decoder_restarts"] += 1
        for close in (p.stdin.close, p.terminate):
            try:
                close()
            except OSError:
                pass

    def _ensure_decoder(self):
        if self.dec and self.dec.poll() is None:
            return
        self.inq = queue.Queue(maxsize=120)
        self.fifo = collections.deque(maxlen=300)
        # No "-fflags nobuffer": it discards the packets read while probing
        # (incl. the first IDR's SPS/PPS), so ffmpeg drops the first GOP and
        # output/input pairing is off by ~30 frames.
        # One picture out for one frame in, nothing else: without a sync mode ffmpeg keeps a constant frame rate for
        # this output and may repeat or drop a picture to do so, and every picture is paired with the capture time of
        # its frame by counting (the FIFO below).
        cmd = [self.ffmpeg, "-hide_banner", "-loglevel", "error", "-flags", "low_delay",
               "-probesize", "32", "-analyzeduration", "0", "-threads", "1", "-f", "h264", "-i", "pipe:0",
               "-threads", "1", "-f", "image2pipe", "-c:v", "mjpeg", "-q:v", "5", "-flush_packets", "1",
               *_passthrough_args(self.ffmpeg), "pipe:1"]
        self.dec = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0)
        threading.Thread(target=self._writer, args=(self.dec, self.inq, self.fifo), daemon=True, name="video-dec-in").start()
        threading.Thread(target=self._reader, args=(self.dec, self.fifo), daemon=True, name="video-dec-out").start()

    def _writer(self, p, inq, fifo):
        written = time.monotonic()
        while p.poll() is None:
            try:
                ts_us, data, t_in = inq.get(timeout=0.5)
            except queue.Empty:
                # Nothing was written for a second, and a picture takes about 10 ms: a frame whose capture time still
                # waits here has given no picture. It must not be paired with the next picture, or every picture
                # from then on would carry the capture time of the frame before it.
                if fifo and time.monotonic() - written > 1.0:
                    self.s["frames_without_picture"] += len(fifo)
                    fifo.clear()
                continue
            fifo.append((ts_us, t_in))
            try:
                p.stdin.write(data if _starts_with_aud(data) else data + AUD)
            except (BrokenPipeError, OSError, ValueError):       # decoder exited / was retired
                break
            written = time.monotonic()

    def _reader(self, p, fifo):
        buf = b""
        while True:
            try:
                chunk = p.stdout.read(65536)
            except (OSError, ValueError):
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) > (8 << 20) and buf.find(b"\xff\xd8") < 0:   # never a JPEG start in 8 MB: not our decoder's output
                buf = b""
            while True:
                s = buf.find(b"\xff\xd8")
                e = buf.find(b"\xff\xd9", s + 2)
                if s < 0 or e < 0:
                    break
                jpg = buf[s:e + 2]
                buf = buf[e + 2:]
                if p is not self.dec:                   # a retired decoder must not overwrite the new stream's picture
                    continue
                now = time.time()                       # wall clock: only for latencies against the UAV's clock
                self.s["frames_decoded"] += 1
                try:
                    paired = fifo.popleft()
                except IndexError:                      # a picture no frame is waiting for: shown, but without a capture time
                    paired = None
                if paired:
                    ts_us, t_in = paired
                    self._dec_ms.append((time.monotonic() - t_in) * 1000)
                    self.s["decode_ms"] = round(sorted(self._dec_ms)[len(self._dec_ms) // 2], 1)
                    off = self.clock_offset()
                    if off is not None:
                        self._disp.append((now - (ts_us / 1e6 - off)) * 1000)
                        self.s["display_latency_ms"] = round(sorted(self._disp)[len(self._disp) // 2], 1)
                    cap = ts_us / 1e6                   # capture time of this frame on the CAMERA's clock
                else:
                    cap = None
                with self.cond:
                    self.latest = jpg
                    # Detections and the overlay are timed on the camera's clock: a box is placed by how much later
                    # the displayed frame was captured than the analysed one, which needs no clock of this machine.
                    self.latest_ts = cap
                    self._latest_mono = time.monotonic()
                    self.jpeg_seq += 1
                    self.cond.notify_all()
        try:
            p.wait(timeout=5)                           # reap the process (no zombies after a decoder restart)
        except (subprocess.TimeoutExpired, OSError):
            p.kill()

    def view_ts(self):
        """Capture time (camera clock) of what a viewer of the stream is seeing right now: the newest decoded frame's
        capture time plus the time since it was decoded. None while there is no live picture."""
        with self.cond:
            ts, m = self.latest_ts, self._latest_mono
        age = time.monotonic() - m
        return ts + age if ts is not None and age < 2.0 else None

    def stats(self):
        with self.lock:
            s = dict(self.s, pending_frames=len(self.pending))
        age = time.monotonic() - self._last_frame if self._last_frame else None
        s["frame_age_s"] = round(age, 1) if age is not None else None
        s["streaming"] = age is not None and age < 2.0
        if not s["streaming"]:                          # rates are measured on arrival: without frames they would stay
            s["fps"] = s["kbps"] = 0.0                  # at the last value forever ("30 fps" on a stopped stream)
        s["decoder"] = "running" if self.dec is not None and self.dec.poll() is None else "stopped"
        return s

    def reset(self):
        """A new live stream is about to start: forget partial frames and start with a fresh decoder."""
        with self.lock:
            self.pending.clear(); self.done.clear()
            self.next_fid = None
            self.need_key = True
            self._sps = None
            self._stop_decoder()


def _starts_with_aud(au: bytes) -> bool:
    """True if the access unit begins with a delimiter of its own (an encoder set up to write them)."""
    i = 4 if au[:4] == b"\x00\x00\x00\x01" else 3 if au[:3] == b"\x00\x00\x01" else -1
    return i > 0 and len(au) > i and au[i] & 0x1F == 9


_PASSTHROUGH = {}


def _passthrough_args(ffmpeg: str) -> list:
    """The option that makes this ffmpeg pass every decoded picture on as it is (its name changed with version 5.1)."""
    if ffmpeg not in _PASSTHROUGH:
        args = []
        try:
            out = subprocess.run([ffmpeg, "-version"], capture_output=True, text=True, timeout=10).stdout
            ver = out.split()[2].lstrip("n").split("-")[0].split(".")
            major, minor = int(ver[0]), int(ver[1]) if len(ver) > 1 and ver[1].isdigit() else 0
            args = ["-fps_mode", "passthrough"] if (major, minor) >= (5, 1) else ["-vsync", "passthrough"]
        except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
            pass                                        # an ffmpeg that does not say its version: its default, as before
        _PASSTHROUGH[ffmpeg] = args
    return _PASSTHROUGH[ffmpeg]


def _sps_of(au: bytes):
    """The first sequence parameter set (NAL type 7) of an Annex-B access unit, or None."""
    i = au.find(b"\x00\x00\x01")
    while 0 <= i < len(au) - 4 and i < 4096:            # parameter sets come first; never scan a whole keyframe
        if au[i + 3] & 0x1F == 7:
            j = au.find(b"\x00\x00\x01", i + 3)
            return bytes(au[i + 3:j if j > 0 else i + 64]).rstrip(b"\x00")
        i = au.find(b"\x00\x00\x01", i + 3)
    return None
