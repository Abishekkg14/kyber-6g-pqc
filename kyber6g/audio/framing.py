"""Cutting an audio stream into its codec frames, without decoding it.

A sealed audio clip (quaver.py) is built from whole codec frames, so that every sealed block can be played by itself
and a block is a fixed stretch of time. This module finds the frames:

  mp3   MPEG-1/2/2.5 audio, layers I to III: the frames as the encoder wrote them (26 ms each at 44.1 kHz, layer III)
  wav   PCM in a RIFF/WAVE file: pieces of 20 ms (what a microphone read with `arecord` would deliver)
  raw   anything else: pieces of 1024 bytes, no time base

`split(data)` returns (fmt, prefix, frames, suffix): prefix and suffix are the bytes that are not audio frames (an ID3
tag, the WAVE header), kept so that prefix + frames + suffix is the file again, byte for byte.
"""
import struct

_BR = {  # kbit/s by (version is MPEG-1, layer)
    (True, 1): (0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448),
    (True, 2): (0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384),
    (True, 3): (0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320),
    (False, 1): (0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256),
    (False, 2): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
    (False, 3): (0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160),
}
_SR = {3: (44100, 48000, 32000), 2: (22050, 24000, 16000), 0: (11025, 12000, 8000)}     # by version bits
RAW_FRAME = 1024
PCM_FRAME_MS = 20


def mp3_header(b: bytes, i: int = 0):
    """The frame that starts at b[i], as a dict (len, sample_rate, bitrate, channels, samples, mpeg, layer), or None."""
    if i + 4 > len(b) or b[i] != 0xFF or b[i + 1] & 0xE0 != 0xE0:
        return None
    ver, layer_bits = (b[i + 1] >> 3) & 3, (b[i + 1] >> 1) & 3
    br_i, sr_i, pad = b[i + 2] >> 4, (b[i + 2] >> 2) & 3, (b[i + 2] >> 1) & 1
    if ver == 1 or layer_bits == 0 or br_i in (0, 15) or sr_i == 3:
        return None
    layer, v1 = 4 - layer_bits, ver == 3
    br, sr = _BR[(v1, layer)][br_i] * 1000, _SR[ver][sr_i]
    if layer == 1:
        n, samples = (12 * br // sr + pad) * 4, 384
    elif layer == 2 or v1:
        n, samples = 144 * br // sr + pad, 1152
    else:
        n, samples = 72 * br // sr + pad, 576
    if n < 24:
        return None
    return {"len": n, "sample_rate": sr, "bitrate": br, "channels": 1 if b[i + 3] >> 6 == 3 else 2, "samples": samples,
            "mpeg": {3: 1, 2: 2, 0: 2.5}[ver], "layer": layer}


def _id3v2_len(b: bytes) -> int:
    if len(b) < 10 or b[:3] != b"ID3" or any(x & 0x80 for x in b[6:10]):
        return 0
    n = (b[6] << 21) | (b[7] << 14) | (b[8] << 7) | b[9]
    return 10 + n + (10 if b[5] & 0x10 else 0)


def split_mp3(data: bytes):
    """(fmt, prefix, frames, suffix) of an MP3 stream, or None if it is not one (fewer than 3 frames in a row)."""
    i = min(_id3v2_len(data), len(data))
    end = len(data)
    while i < end - 4:                      # the first header that is followed by another one where it says so
        h = mp3_header(data, i)
        if h and (i + h["len"] == end or mp3_header(data, i + h["len"])):
            break
        i += 1
    else:
        return None
    start, frames, first = i, [], None
    while True:
        h = mp3_header(data, i)
        if h is None or i + h["len"] > end:
            break
        if first is None:
            first = h
        elif (h["sample_rate"], h["layer"], h["mpeg"]) != (first["sample_rate"], first["layer"], first["mpeg"]):
            break                           # another stream begins here: not ours
        frames.append(data[i:i + h["len"]])
        i += h["len"]
    if len(frames) < 3:
        return None
    rates = {mp3_header(f)["bitrate"] for f in frames[:400]}
    fmt = {"codec": "mp3", "mpeg": first["mpeg"], "layer": first["layer"], "sample_rate": first["sample_rate"],
           "channels": first["channels"], "bitrate": first["bitrate"] if len(rates) == 1 else None, "cbr": len(rates) == 1,
           "samples_per_frame": first["samples"], "frame_len_max": max(len(f) for f in frames)}
    return fmt, data[:start], frames, data[i:]


def split_wav(data: bytes):
    """(fmt, prefix, frames, suffix) of a PCM WAVE file, or None."""
    if len(data) < 44 or data[:4] != b"RIFF" or data[8:12] != b"WAVE":
        return None
    i, fmt = 12, None
    while i + 8 <= len(data):
        cid, n = data[i:i + 4], struct.unpack_from("<I", data, i + 4)[0]
        if cid == b"fmt " and n >= 16:
            tag, ch, sr, _, align, bits = struct.unpack_from("<HHIIHH", data, i + 8)
            if tag not in (1, 0xFFFE) or not 1 <= ch <= 8 or not 8000 <= sr <= 192000 or align != ch * bits // 8 or bits not in (8, 16, 24, 32):
                return None
            fmt = {"codec": f"pcm_s{bits}le" if bits > 8 else "pcm_u8", "sample_rate": sr, "channels": ch, "bits": bits,
                   "bitrate": sr * align * 8, "cbr": True}
        elif cid == b"data":
            if fmt is None:
                return None
            start = i + 8
            n = min(n, len(data) - start)
            align = fmt["channels"] * fmt["bits"] // 8
            n -= n % align
            samples = fmt["sample_rate"] * PCM_FRAME_MS // 1000
            step = samples * align
            frames = [data[k:k + step] for k in range(start, start + n, step)]
            fmt.update(samples_per_frame=samples, frame_len_max=step)
            return fmt, data[:start], frames, data[start + n:]
        i += 8 + n + (n & 1)
    return None


def split(data: bytes):
    """(fmt, prefix, frames, suffix) for any input: an MP3 stream, a PCM WAVE file, or anything else as raw pieces."""
    got = split_wav(data) or split_mp3(data)
    if got:
        return got
    frames = [data[k:k + RAW_FRAME] for k in range(0, len(data), RAW_FRAME)]
    return {"codec": "raw", "sample_rate": None, "channels": None, "bitrate": None, "cbr": True, "samples_per_frame": 0,
            "frame_len_max": RAW_FRAME}, b"", frames, b""


def duration_s(fmt: dict, n_frames: int):
    """Seconds of audio in n_frames frames, or None when the stream has no time base (raw)."""
    if not fmt.get("sample_rate") or not fmt.get("samples_per_frame"):
        return None
    return n_frames * fmt["samples_per_frame"] / fmt["sample_rate"]
