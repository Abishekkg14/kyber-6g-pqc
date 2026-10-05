"""Scheduling hygiene for the ground station: the machine is shared by the secure link receiver, ffmpeg and two ML workers.

Measured on the real system (docs/TEST_REPORT.md 12.6): with the OWLv2 finder running next to the real-time detector the UDP
receive thread starved and the kernel dropped video datagrams (24 frames lost in 25 s; 0 with the finder off, rekeys or not).
Network and decode must always win against inference, so the ML worker threads lower their own priority.
Threads created afterwards by the worker (PyTorch's OpenMP team) inherit it."""
import os
import threading
import time

# The picture comes before the boxes, also when the cause is heat. Measured on the project's laptop (docs/TEST_REPORT.md
# 15.7): with the ACCURATE detector and the finder running, its processor reached 89 degrees C after about 105 s and its
# firmware then ran it at 17 % of its speed for about 55 s, again and again; at half the ML load, the same. No program
# keeps real time on a processor that slow, so the load that heats it has to come down until it stays cool:
#   - every episode in which the decoder was behind for seconds halves the rate of the ML workers once more (1/2, 1/4, 1/8);
#   - after EASE_HOLD_S without an episode the rate is raised one step again, to find out whether the machine now copes;
#   - if the next episode follows such a raise, the wait before the next try doubles (up to an hour), so a machine that
#     cannot carry the load is tried rarely; a long quiet time at full rate resets it.
EASE_HOLD_S, EASE_HOLD_MAX_S, EASE_MAX_LEVEL = 600.0, 3600.0, 3
EPISODE_GAP_S = 60.0        # behind again after this long without: a new episode
EPISODE_MIN_S = 2.0         # behind for at least this long: an episode (a single late frame is not)
PROBE_S = 300.0             # an episode this soon after the rate was raised is blamed on the raise
_ease = {"level": 0, "until": 0.0, "hold": EASE_HOLD_S, "episodes": 0, "last": -1e9, "first": -1e9, "counted": True, "raised_at": -1e9}
_ease_lock = threading.Lock()


def next_frame(video, last_seq, timeout: float = 0.5):
    """Wait for a decoded frame newer than `last_seq`; returns (jpeg, seq, capture_ts) or None after `timeout`.

    It must BLOCK while there is no frame at all. Before the first frame of a session `video.latest` is None while its
    sequence number (0) already differs from a fresh worker's last_seq (-1); waiting on the sequence number alone
    returned at once, and both ML workers spun in a tight Python loop from start-up until LIVE was first pressed:
    one CPU core at 100 %, and every other thread (HTTP, link receiver, model loading) starved of the interpreter
    lock - loading the finder model took 128 s instead of 8 s."""
    with video.cond:
        video.cond.wait_for(lambda: video.latest is not None and video.jpeg_seq != last_seq, timeout=timeout)
        jpg, seq = video.latest, video.jpeg_seq
        if jpg is None or seq == last_seq:
            return None
        return jpg, seq, getattr(video, "latest_ts", None)


def video_behind(video, limit_s: float = 0.25) -> bool:
    """True while frames have been waiting for the video decoder longer than `limit_s`.

    A lower priority (below) keeps the ML workers from taking the decoder's core, but not from heating the processor
    until the laptop throttles all of it: the decoder then needs a full core and still falls behind. A worker that
    sees the decoder behind starts no new inference until it has caught up, and both run slower for a while afterwards
    (`ease_factor`)."""
    lag = getattr(video, "decoder_lag", None)
    try:
        behind = lag is not None and lag() > limit_s
    except Exception:
        return False
    if behind:
        _note_behind(time.monotonic())
    return behind


def _note_behind(now: float):
    with _ease_lock:
        e = _ease
        if now - e["last"] > EPISODE_GAP_S:               # the decoder kept up for a minute: this is a new episode
            e["first"], e["counted"] = now, False
        e["last"] = now
        if not e["counted"] and now - e["first"] >= EPISODE_MIN_S:
            e["counted"] = True
            e["episodes"] += 1
            if now - e["raised_at"] <= PROBE_S:           # it follows a raise of the rate: wait longer before the next one
                e["hold"] = min(EASE_HOLD_MAX_S, e["hold"] * 2)
            elif e["level"] == 0:                         # out of the blue, at full rate: start with the short wait
                e["hold"] = EASE_HOLD_S
            e["level"] = min(EASE_MAX_LEVEL, e["level"] + 1)
        if e["level"]:
            e["until"] = now + e["hold"]


def ease_factor(now: float | None = None) -> int:
    """1 normally; 2, 4 or 8 while the ML workers are eased: they then use a half, a quarter, an eighth of their time."""
    now = time.monotonic() if now is None else now
    with _ease_lock:
        e = _ease
        if e["level"] and now >= e["until"]:              # no episode for the whole wait: one step back towards full rate
            e["level"] -= 1
            e["raised_at"] = now
            e["until"] = now + e["hold"]
        return 1 << e["level"]


def ease_state(now: float | None = None) -> dict:
    """For the dashboard and the logs: how much the workers are eased, for how much longer, how often it happened."""
    now = time.monotonic() if now is None else now
    factor = ease_factor(now)
    return {"factor": factor, "seconds_left": round(max(0.0, _ease["until"] - now)) if factor > 1 else 0,
            "episodes": _ease["episodes"], "hold_s": round(_ease["hold"])}


def lower_priority(nice: int) -> int | None:
    """Raise the niceness of the CALLING thread (Linux; no privileges needed to lower priority). Returns the new value."""
    try:
        tid = threading.get_native_id()
        os.setpriority(os.PRIO_PROCESS, tid, nice)
        return os.getpriority(os.PRIO_PROCESS, tid)
    except (AttributeError, OSError):
        return None
