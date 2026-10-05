"""Configuration with defaults; optional JSON override file (-c path)."""
import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path


@dataclass
class LinkConfig:
    gcs_host: str = "10.88.242.139"
    gcs_port: int = 14600
    suite_id: int = 0x0001
    uav_id: str = "UAV-ALPH"
    gcs_id: str = "GCS-MEC1"
    keydir: str = ""                    # default ~/.kyber6g
    rotate_seconds: float = 30.0        # symmetric epoch rotation (per stream)
    rotate_packets: int = 1 << 20
    epoch_grace_seconds: float = 3.0
    replay_window: int = 2048
    heartbeat_s: float = 1.0
    link_timeout_s: float = 5.0
    cached_rekey_ttl_s: float = 300.0
    cached_rekey_interval_s: float = 120.0  # periodic 1-RTT Cached RapidRekey (0 = off)
    pq_ratchet_interval_s: float = 600.0    # periodic PQ ratchet (FS+PCS, 0 = off)
    mobility_cell_deg: float = 0.001        # ~110 m cell for the rekey context


@dataclass
class CameraConfig:
    width: int = 1280
    height: int = 720
    fps: int = 30
    bitrate: int = 3_000_000
    iperiod: int = 30                    # IDR every second at 30 fps
    rotation: int = 180                  # camera is mounted inverted
    still_width: int = 2592
    still_height: int = 1944
    jpeg_quality: int = 90
    recordings_dir: str = "~/kyber6g_recordings"
    # A recording rolls over into a new, independent .k6grec at the first keyframe after this size, so every part
    # stays below the 256 MB limit of one transfer over the link (192 MB = about 8.5 min at 3 Mbit/s).
    recording_part_mb: int = 192
    photos_dir: str = "~/kyber6g_photos"         # encrypted .k6gimg copies of every capture
    # The module has no IR-cut filter, so libcamera's default OV5647 tuning gives a magenta cast
    # (measured R/G 2.25, B/G 1.83). The NoIR tuning ships with libcamera and measured 0.99 / 1.00.
    tuning: str = "ov5647_noir.json"
    exposure_value: float = 0.0                  # EV bias in NORMAL mode (the NoIR sensor sees IR and can over-expose)    segment_keyframes: int = 1
    # Motion watch (camera/motion.py): the ISP makes a small second picture beside the video and its brightness is
    # analysed on board a few times a second; what moves is reported as text in the status stream.
    motion: bool = True                          # False: no second picture is asked for, nothing is analysed
    motion_width: int = 320                      # width of that picture (its height follows the shape of the video)
    motion_hz: float = 8.0                       # looks per second (1..15)
    motion_sensitivity: str = "medium"           # low | medium | high
    motion_photo_gap_s: float = 15.0             # PHOTO ON MOTION takes at most one sealed photo in this many seconds


@dataclass
class UavConfig:
    link: LinkConfig = field(default_factory=LinkConfig)
    camera: CameraConfig = field(default_factory=CameraConfig)
    gpsd_host: str = "127.0.0.1"
    gpsd_port: int = 2947
    telemetry_hz: float = 1.0
    lcd_enabled: bool = True
    lcd_bus: int = 1
    lcd_addr: int = 0x27
    lcd_screen_s: float = 2.5
    gnss_synthetic: bool = False         # test mode only; real L89 is the default
    audio_dir: str = "~/kyber6g_audio"   # sealed audio clips (.k6gaud) and, in inbox/, files that stand in for a microphone
    audio_frames_per_block: int = 8      # codec frames in one sealed block (8 MP3 frames at 44.1 kHz = 0.21 s)
    # bytes of the largest frame the audio encoder may produce: every block of every clip is laid out for it, so the
    # block size says nothing about what was recorded. 0: the largest frame of the clip itself decides (the same for
    # constant-bit-rate and PCM sources; with a variable bit rate it is one number that depends on the recording).
    audio_frame_cap: int = 0


@dataclass
class GroundConfig:
    link: LinkConfig = field(default_factory=LinkConfig)
    bind_host: str = "0.0.0.0"           # UDP listener for the UAV
    http_host: str = "127.0.0.1"         # dashboard: local only (it can command the UAV and has no login)
    http_port: int = 8600
    # Host names (besides localhost and IP addresses) under which the dashboard may be opened; anything else is
    # refused as a possible DNS-rebinding request. Only needed if http_host is changed to serve other machines.
    http_allowed_hosts: list = field(default_factory=list)
    data_dir: str = "~/kyber6g_ground"
    ffmpeg: str = "ffmpeg"
    # A recording that has just been saved on the UAV (SAVE) is fetched and decrypted by itself if it is at most
    # this many megabytes (0: never; larger ones wait on the MEDIA page for FETCH & DECRYPT). 64 MB is nearly three
    # minutes of video at 3 Mbit/s.
    auto_fetch_mb: int = 64
    # Real-time detector profile at start-up ("general" | "accurate" | "fast" | "open"). Measured (ground/detector.py,
    # docs/TEST_REPORT.md 13.6): ACCURATE labels are a little more trustworthy (79 % vs 75 % correct, 17 % more objects
    # found) but with the FINDER running it analyses 1.7 frames/s against 3.3 for GENERAL, and the boxes follow
    # movement visibly later. GENERAL is the default; ACCURATE is one click away and is switched to by TEACH.
    detector_profile: str = "general"
    # FINDER: slower, accurate named-object search (see ground/finder.py); runs beside the real-time detector
    finder_enabled: bool = True
    finder_backend: str = "owlv2"                # "owlv2" | "gdino"
    finder_size: int = 640                       # OWLv2 input side: 640 px = same recall as 960 on the benchmark at 3x the speed
    finder_period: float = 4.0                   # seconds between finder passes (a pass takes ~2 s of CPU; the rest goes to the live detector)
    finder_words: list = field(default_factory=lambda: ["pencil", "screwdriver"])


def _merge(obj, data: dict):
    for f in fields(obj):
        if f.name not in data:
            continue
        cur = getattr(obj, f.name)
        if hasattr(cur, "__dataclass_fields__"):
            _merge(cur, data[f.name])
        else:
            setattr(obj, f.name, type(cur)(data[f.name]) if cur is not None else data[f.name])
    return obj


def load(cls, path: str = None):
    cfg = cls()
    if path:
        _merge(cfg, json.loads(Path(path).expanduser().read_text()))
    return cfg


def to_dict(cfg):
    return asdict(cfg)
