"""Does the Pi's encoder make a keyframe when the ground station asks for one? Under injected loss (so that frames are
lost and the ground station asks), count the keyframes the camera makes with the requests on and off.

    python -m kyber6g.tools.kf_check [--loss 5] [--seconds 20]

Prints numbers only. The loss rule on the Pi is removed at the end, and by a timer on the Pi if this program dies."""
import argparse
import time

from .bench_link import NFT, Api, need_live, nft_clear, nft_set, snap, ssh


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--api", default="http://127.0.0.1:8600")
    ap.add_argument("--pi", default="kyber-pi")
    ap.add_argument("--loss", type=float, default=5.0)
    ap.add_argument("--seconds", type=float, default=20.0)
    a = ap.parse_args()
    api = Api(a.api)
    need_live(api)
    rc, _, err = ssh(a.pi, "sudo -n systemctl stop k6g-loss-cleanup.timer 2>/dev/null; sudo -n systemctl reset-failed k6g-loss-cleanup.service 2>/dev/null; "
                           f"sudo -n systemd-run --quiet --collect --on-active=300 --unit k6g-loss-cleanup {NFT} delete table inet k6gloss", 30)
    if rc != 0:
        raise SystemExit(f"could not arm the clean-up timer on the Pi: {err.strip()[:200]}")
    try:
        for kf in ("on", "off", "on"):
            api.cmd("video_tuning", keyframe_request=(kf == "on"))
            nft_set(a.pi, a.loss)
            time.sleep(3)
            s0, m0 = snap(api), time.monotonic()
            time.sleep(a.seconds)
            s1, dt = snap(api), time.monotonic() - m0
            d = lambda k: (s1.get(k) or 0) - (s0.get(k) or 0)
            print(f"requests {kf:3s} {dt:4.1f} s at {a.loss:g} % loss: camera frames {d('cam_frames')}, camera keyframes {d('cam_keyframes')} "
                  f"({d('cam_keyframes') / dt:.2f}/s); requests sent {d('keyframe_requests_gcs')}, carried out on the UAV {d('keyframe_requests_uav')}, "
                  f"failed {d('keyframe_requests_failed_uav')}; frames complete {d('frames_complete')}, lost {d('frames_lost')}, "
                  f"to the decoder {d('frames_decoded')}", flush=True)
    finally:
        nft_clear(a.pi)
        api.cmd("video_tuning", keyframe_request=True)


if __name__ == "__main__":
    main()
