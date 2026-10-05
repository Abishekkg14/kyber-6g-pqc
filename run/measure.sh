#!/bin/bash
# The measurement campaign behind the paper's plots: everything is measured on the real hardware (Raspberry Pi 4B and
# ground station over Wi-Fi) and written, sample by sample, to paper_plots/data. Nothing is simulated.
#
#   bash run/kyber6g.sh measure [phases]      phases: all (default) or a comma-separated selection of
#                                             crypto,attacks,idle,rtt,ops,transfer,timeline,loss,audio,pq,motion  (and: latency)
# Needs the ground station running and the UAV connected (bash run/kyber6g.sh status). Takes about 110 minutes in full.
# `pq` runs NIST's known-answer vectors on both machines, the ProVerif models and the bill of materials;
# `motion` measures the motion watch (generated scenes, the UAV's camera with drawn-in targets, its cost).
# `attacks` runs the attack experiments (kyber6g.tools.attack_bench) on both machines and the statistics of a sealed
# picture (kyber6g.tools.media_stats); docs/CRYPTANALYSIS_REPORT.txt is written from their results (bash run/kyber6g.sh report).
# `audio` runs the experiments on sealed audio (kyber6g.tools.audio_bench): attacks and cost on both machines, the
# statistics of the sealed sample, and a clip sent live under injected loss; docs/AUDIO_CRYPTANALYSIS_REPORT.txt is
# written from their results (bash run/kyber6g.sh report).
# The loss phases drop datagrams on the Pi with nftables (UDP port 14600 only) and remove their rules afterwards;
# a timer on the Pi removes them as well, should this script be interrupted.
# The operator's detector / finder / camera settings are put back at the end.
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="${KYBER6G_PY:-/root/kyber6g_gcs_venv/bin/python}"
PI="${KYBER6G_PI:-kyber-pi}"
URL="http://127.0.0.1:8600"
OUT="$REPO/paper_plots/data"
# ssh options: from run/kyber6g.sh when started by it (post-quantum hybrid key exchange first, see pq_kex there)
if [ -z "${KYBER6G_SSHO:-}" ]; then
  KYBER6G_SSHO="-o BatchMode=yes"
  for k in sntrup761x25519-sha512@openssh.com sntrup761x25519-sha512 mlkem768x25519-sha256; do
    ssh -Q kex 2>/dev/null | grep -qx -- "$k" && pq="$k${pq:+,$pq}"
  done
  [ -n "${pq:-}" ] && KYBER6G_SSHO="$KYBER6G_SSHO -o KexAlgorithms=^$pq"
fi
SSH="ssh $KYBER6G_SSHO -o ConnectTimeout=8 $PI"
only="${1:-all}"
mkdir -p "$OUT"; cd "$REPO" || exit 1
post() { curl -s -m 90 -X POST -H 'Content-Type: application/json' -d "$1" "$URL/api/cmd" >/dev/null; }
run() { echo; echo "===== $(date +%T) $*"; "$PY" -W ignore -m "$@" 2>&1 | grep -v faulthandler; }
want() { [ "$only" = all ] || [[ ",$only," == *",$1,"* ]]; }

curl -s -m 5 "$URL/api/state" > "$OUT/.state_before.json" || { echo "the ground station does not answer at $URL"; exit 1; }
"$PY" - "$OUT/.state_before.json" <<'EOF' || exit 1
import json, sys
s = json.load(open(sys.argv[1]))
if s["link"]["state"] != "UP":
    sys.exit("the secure link is not up: start the UAV (bash run/kyber6g.sh uav-start)")
EOF
echo "campaign started $(date '+%F %T') (phases: $only)"
# operating point during the link measurements: the shipped defaults (GENERAL detector at 0.40, finder on, NORMAL camera mode)
post '{"cmd":"detector","args":{"profile":"general","conf":0.4,"enhance":false,"enabled":true}}'
post '{"cmd":"finder","args":{"enabled":true}}'
post '{"cmd":"set_video","args":{"width":1280,"height":720,"fps":30,"bitrate":3000000}}'
post '{"cmd":"set_mode","args":{"mode":"NORMAL"}}'

if want crypto; then
  post '{"cmd":"stop_live"}'; sleep 4
  echo; echo "===== $(date +%T) crypto on the Pi (UAV application idle, camera not streaming)"
  $SSH 'cd ~/kyber6g_app && ~/kyber6g_venv/bin/python -W ignore -m kyber6g.tools.bench_crypto -n 300 -o /tmp/k6g_crypto_pi.json 2>&1 | grep -v faulthandler'
  $SSH 'cat /tmp/k6g_crypto_pi.json; rm -f /tmp/k6g_crypto_pi.json' > "$OUT/crypto_pi.json"
  # the laptop: detector and finder paused meanwhile (they use all cores); its clock rate is measured against the Pi
  post '{"cmd":"detector","args":{"enabled":false}}'; post '{"cmd":"finder","args":{"enabled":false}}'; sleep 6
  run kyber6g.tools.bench_crypto -n 300 -o "$OUT/crypto_laptop.json" --ref-ssh "$PI"
  post '{"cmd":"detector","args":{"enabled":true}}'; post '{"cmd":"finder","args":{"enabled":true}}'
fi
if want attacks; then
  post '{"cmd":"stop_live"}'; sleep 4
  echo; echo "===== $(date +%T) attack experiments on the Pi (UAV application idle, camera not streaming)"
  $SSH 'cd ~/kyber6g_app && ~/kyber6g_venv/bin/python -W ignore -m kyber6g.tools.attack_bench -n 1 -o /tmp/k6g_attacks_pi.json 2>&1 | grep -v faulthandler'
  $SSH 'cat /tmp/k6g_attacks_pi.json; rm -f /tmp/k6g_attacks_pi.json' > "$OUT/attacks_pi.json"
  # the laptop: detector and finder paused (the timing test wants quiet cores); the photos and recordings the ground
  # station holds, encrypted and decrypted, are what the ciphertext statistics are computed on
  post '{"cmd":"detector","args":{"enabled":false}}'; post '{"cmd":"finder","args":{"enabled":false}}'; sleep 6
  run kyber6g.tools.attack_bench -n 1 -o "$OUT/attacks_laptop.json" --media "${KYBER6G_DATA:-$HOME/kyber6g_ground}"
  # the statistics of one picture before and after sealing (plot 9): a public-domain aerial photograph, not a camera
  # capture (those show the operator), sealed as a stored photo
  PIC="$REPO/paper_figures/assets/photos/aerial_usda_naip.jpg"
  [ -f "$PIC" ] && run kyber6g.tools.media_stats --image "$PIC" -o "$OUT/media_stats.json" --png-dir "$OUT/media" \
      --source-note "public-domain aerial photograph (USDA NAIP, 2006, via Wikimedia Commons); not taken by the prototype"
  post '{"cmd":"detector","args":{"enabled":true}}'; post '{"cmd":"finder","args":{"enabled":true}}'
fi
if want idle; then
  post '{"cmd":"stop_live"}'; sleep 5
  run kyber6g.tools.bench_link timeline --seconds 90 --idle --name idle --pi "$PI" -o "$OUT"
fi
# round trips of messages of 1..6 datagrams are measured right before AND right after the session operations: the
# simulation is calibrated with them (simulation/calibrate.py) and checked against the operations, and the radio's
# behaviour is not the same from one hour to the next
SIZES=0,1500,2600,3700,4800,6000
want rtt && run kyber6g.tools.bench_link rtt -n 600 --pad-sizes $SIZES --pad-n 300 --pi "$PI" -o "$OUT"
want ops && run kyber6g.tools.bench_link ops -n 150 --pi "$PI" -o "$OUT"
want rtt && run kyber6g.tools.bench_link rtt -n 100 --pad-sizes $SIZES --pad-n 300 --name link_rtt_after --pi "$PI" -o "$OUT"
want transfer && run kyber6g.tools.bench_link transfer -n 5 --record-s 20 --photos 10 --pi "$PI" -o "$OUT"
want timeline && run kyber6g.tools.bench_link timeline --seconds 780 --record-at 420 --record-for 120 --pi "$PI" -o "$OUT"
# `latency` (only when named): two minutes of live video for the latency budget of plot 7 alone. It was added after the
# ground station's decoder was changed (docs/TEST_REPORT.md 15.5 no. 9) without repeating the 13-minute timeline; a new
# timeline run makes it obsolete and removes it. Run it on a laptop that has cooled down (15.7).
want timeline && rm -f "$OUT/latency.json"
[[ ",$only," == *",latency,"* ]] && run kyber6g.tools.bench_link timeline --seconds 120 --name latency --pi "$PI" -o "$OUT"
want loss && run kyber6g.tools.bench_link loss --levels 0,0.5,1,2,5,10,20 --seconds 40 --ops 10 --photos 3 --pi "$PI" -o "$OUT"

if want audio; then
  post '{"cmd":"stop_live"}'; sleep 4
  echo; echo "===== $(date +%T) sealed audio: attacks and cost on the Pi (UAV application idle, camera not streaming)"
  for what in attacks cost; do
    $SSH "cd ~/kyber6g_app && ~/kyber6g_venv/bin/python -W ignore -m kyber6g.tools.audio_bench $what -n 1 -o /tmp/k6g_audio_$what.json 2>&1 | grep -v faulthandler | tail -12"
    $SSH "cat /tmp/k6g_audio_$what.json; rm -f /tmp/k6g_audio_$what.json" > "$OUT/audio_${what}_pi.json"
  done
  post '{"cmd":"detector","args":{"enabled":false}}'; post '{"cmd":"finder","args":{"enabled":false}}'; sleep 6
  run kyber6g.tools.audio_bench attacks -n 1 -o "$OUT/audio_attacks_laptop.json"
  run kyber6g.tools.audio_bench cost -n 1 -o "$OUT/audio_cost_laptop.json"
  # the sample that stands in for a microphone (the Pi has none): its statistics before and after sealing, and the
  # same clip sent while it is sealed with datagrams dropped on the Pi (8 frames a block, and 1)
  AUD="${KYBER6G_AUDIO:-$REPO/audio encryption/audio_sample1_test.mp3}"
  if [ -f "$AUD" ]; then
    run kyber6g.tools.audio_bench stats --audio "$AUD" -o "$OUT/audio_stats.json"         --source-note "the sample the operator supplied (37.5 s, MPEG-1 layer III, 256 kbit/s, 44.1 kHz stereo); not recorded by the prototype, which has no microphone"
    post '{"cmd":"detector","args":{"enabled":true}}'; post '{"cmd":"finder","args":{"enabled":true}}'
    run kyber6g.tools.audio_bench loss --audio "$AUD" --pi "$PI" --levels 0,1,2,5,10,20 --frames-per-block 8,1 -o "$OUT"
  else
    post '{"cmd":"detector","args":{"enabled":true}}'; post '{"cmd":"finder","args":{"enabled":true}}'
    echo "no audio sample at $AUD (set KYBER6G_AUDIO): statistics and live loss not measured"
  fi
fi

if want pq; then
  # the cryptography in use against NIST's known answers (ACVP vectors for FIPS 203 / 204) on both machines, the
  # protocol models (ProVerif) and the bill of materials: what docs/SECURITY_PROOFS.md refers to
  echo; echo "===== $(date +%T) known-answer tests on the Pi"
  $SSH 'cd ~/kyber6g_app && ~/kyber6g_venv/bin/python -W ignore -m kyber6g.tools.pq_conformance --json /tmp/k6g_pqc.json 2>&1 | grep -v faulthandler | tail -16'
  $SSH 'cat /tmp/k6g_pqc.json; rm -f /tmp/k6g_pqc.json' > "$OUT/pq_conformance_pi.json"
  run kyber6g.tools.pq_conformance --json "$OUT/pq_conformance_laptop.json"
  echo; echo "===== $(date +%T) protocol models (ProVerif)"
  python3 formal/run.py | tail -2
  run kyber6g.tools.cbom
fi

if want motion; then
  # the motion watch: generated scenes (here, no hardware), then the UAV's own camera in both modes with targets
  # drawn into its pictures on the UAV, what the watch costs the UAV, and five minutes of the scene as it is
  run kyber6g.tools.motion_bench synthetic --seeds 10 --out "$OUT/motion_synthetic.json"
  post '{"cmd":"motion","args":{"enabled":true,"sensitivity":"medium"}}'
  post '{"cmd":"start_live"}'
  for mode in NORMAL NIGHT; do
    post "{\"cmd\":\"set_mode\",\"args\":{\"mode\":\"$mode\"}}"; sleep 12
    run kyber6g.tools.motion_bench camera --captures 3 --out "$OUT/motion_camera_$(echo $mode | tr A-Z a-z).json"
  done
  post '{"cmd":"set_mode","args":{"mode":"NORMAL"}}'; sleep 8
  run kyber6g.tools.motion_bench cost --rounds 4 --seconds 30 --ops 6 --out "$OUT/motion_cost.json"
  run kyber6g.tools.motion_bench quiet --minutes 5 --out "$OUT/motion_quiet.json"
fi

echo; echo "===== $(date +%T) afterwards"
$SSH 'echo "loss rules left on the Pi: [$(sudo -n /usr/sbin/nft list tables 2>/dev/null | grep -c k6gloss)]"; systemctl is-active kyber6g-uav; vcgencmd measure_temp; vcgencmd get_throttled'
# the operator's settings as they were
"$PY" - "$OUT/.state_before.json" "$URL" <<'EOF'
import json, sys, urllib.request
s, url = json.load(open(sys.argv[1])), sys.argv[2]
det, cam = s.get("detector") or {}, (s.get("uav") or {}).get("camera") or {}
fin = det.get("finder") or {}
def cmd(c, **args):
    req = urllib.request.Request(url + "/api/cmd", json.dumps({"cmd": c, "args": args}).encode(), {"Content-Type": "application/json"})
    try:
        return json.load(urllib.request.urlopen(req, timeout=120)).get("ok")
    except Exception as e:
        return f"{type(e).__name__}"
args = {"enabled": bool(det.get("enabled")), "enhance": bool(det.get("enhance"))}
args.update({k: det[k] for k in ("conf", "imgsz") if det.get(k) is not None})
if det.get("custom_vocab"):                    # the operator's own word list, whichever profile is on
    args["vocab"] = ", ".join(det["custom_vocab"])
if det.get("profile"):                         # (given together with a word list, the profile decides)
    args["profile"] = det["profile"]
print("settings put back: detector", cmd("detector", **args), "| finder", cmd("finder", **{k: fin[k] for k in ("enabled", "words", "threshold", "period") if fin.get(k) is not None}),
      "| video", cmd("set_video", width=cam.get("width"), height=cam.get("height"), fps=cam.get("fps_target"), bitrate=cam.get("bitrate_target")) if cam.get("width") else "-",
      "| mode", cmd("set_mode", mode=cam["mode"]) if cam.get("mode") else "-", "| live", cmd("start_live" if cam.get("live") else "stop_live"))
EOF
rm -f "$OUT/.state_before.json"
find kyber6g tests -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null
echo "campaign finished $(date '+%F %T'); draw the plots with: bash run/kyber6g.sh plots"
