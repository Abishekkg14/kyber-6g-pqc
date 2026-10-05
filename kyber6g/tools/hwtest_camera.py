"""On-Pi camera pipeline test (no network): one encode -> live sink + encrypted recorder.

    python -m kyber6g.tools.hwtest_camera
Prints measured values only.
"""
import json
import tempfile
import time
from pathlib import Path

from ..config import CameraConfig
from ..crypto import identity as idm
from ..camera.camera import CameraService
from ..recording.recorder import EncryptedRecorder


def main():
    cfg = CameraConfig()
    live = {"frames": 0, "key": 0, "bytes": 0, "t": []}

    def sink(data, key, ts_us):
        live["frames"] += 1; live["key"] += key; live["bytes"] += len(data); live["t"].append(time.time())

    cam = CameraService(cfg, sink)
    print(json.dumps({"available": cam.available, "sensor": cam.model, "error": cam.error,
                      "pixel_array": cam.sensor_res if cam.available else None}))
    if not cam.available:
        return 1
    out = {}
    # the stills are plaintext pictures: a fresh directory only this user can read, not fixed names in /tmp
    tmp = Path(tempfile.mkdtemp(prefix="k6g_hwtest_"))
    out["stills_dir"] = str(tmp)
    jpeg, info = cam.capture_still()
    (tmp / "still_full.jpg").write_bytes(jpeg)
    out["still_full"] = {**info, "bytes": len(jpeg)}

    ek = idm.load_recording_ek(idm.DEFAULT_DIR)
    rec = EncryptedRecorder("~/kyber6g_recordings", ek, {"codec": "h264", "width": cfg.width, "height": cfg.height,
                                                          "fps": cfg.fps, "bitrate": cfg.bitrate, "test": True})
    cam.set_live(True)
    cam.start_recording(rec)
    time.sleep(6)
    jpeg2, info2 = cam.capture_still()
    (tmp / "still_video.jpg").write_bytes(jpeg2)
    out["still_during_video"] = {**info2, "bytes": len(jpeg2)}
    cam.set_mode("NIGHT")
    time.sleep(3)
    jpeg3, info3 = cam.capture_still()
    (tmp / "still_night.jpg").write_bytes(jpeg3)
    out["still_night"] = {**info3, "bytes": len(jpeg3)}
    cam.set_mode("NORMAL")
    time.sleep(1)
    out["camera_status"] = cam.status()
    out["recording"] = cam.stop_recording()
    t = live["t"]
    cam.set_live(False)
    out["live_sink"] = {"frames": live["frames"], "keyframes": live["key"], "bytes": live["bytes"],
                        "fps_measured": round((len(t) - 1) / (t[-1] - t[0]), 2) if len(t) > 1 else None,
                        "kbps_measured": round(live["bytes"] * 8 / (t[-1] - t[0]) / 1000, 1) if len(t) > 1 else None}
    out["same_frames_to_both_sinks"] = out["live_sink"]["frames"] == out["recording"]["frames"]
    cam.close()
    print(json.dumps(out, indent=1, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
