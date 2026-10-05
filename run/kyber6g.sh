#!/bin/bash
# Kyber-6G control script (run inside WSL / Linux on the ground station).
#   run        start ground station in the foreground (used by Kyber6G.bat); Ctrl+C / closing the window stops it
#   start      start ground station in the background      stop | restart | status | logs
#   uav-start  start the UAV service on the Pi             uav-stop | uav-restart | uav-status | uav-logs
#   deploy     copy code to the Pi, set the modes and the unit file its confined service needs, restart the service
#   test       run the automated test suite                pipeline   run the end-to-end pipeline test
#   audit      check everything stored on the laptop and on the Pi (SQLite, images, recordings, permissions, secrets)
#   ui-test    drive the dashboard in a real (headless) browser: layout stability, errors, every control
#   measure    measurement campaign for the paper's plots (Pi + ground station, ~110 min)  plots   draw and check them
#   report     write docs/CRYPTANALYSIS_REPORT.txt from the attack experiments             simulate   the ns-3 studies
#   formal     the ProVerif models of the protocols      conformance   NIST's known-answer vectors, here and on the Pi
#   cbom       write docs/CBOM.json, the list of all cryptography in use (see docs/SECURITY_PROOFS.md for all three)
#   pull NAME  copy + decrypt a recording that is too large to fetch over the secure link
#   audio-put FILE   copy an audio file into the Pi's inbox: it stands in for a microphone and is sealed there
set -u
REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="${KYBER6G_PY:-/root/kyber6g_gcs_venv/bin/python}"
PI="${KYBER6G_PI:-kyber-pi}"
DATA="$HOME/kyber6g_ground"
LOG="$DATA/ground.log"
PIDF="$DATA/ground.pid"
URL="http://127.0.0.1:8600"
mkdir -p "$DATA"

# The management channel to the Pi (deploy, service control, measurements) is SSH. Its key exchange is asked to be a
# post-quantum hybrid as well, when this OpenSSH has one: ML-KEM-768 + X25519 (OpenSSH 9.9 and later) or Streamlined
# NTRU Prime 761 + X25519 (8.5 and later). A client older than 9.0 would otherwise settle for X25519 alone. The
# classical methods stay in the list behind them, so a server without a hybrid one still works.
pq_kex() {
  local have list="" k
  have=$(ssh -Q kex 2>/dev/null)
  for k in mlkem768x25519-sha256 sntrup761x25519-sha512 sntrup761x25519-sha512@openssh.com; do
    grep -qx -- "$k" <<<"$have" && list="${list:+$list,}$k"
  done
  [ -n "$list" ] && echo "-o KexAlgorithms=^$list"
}
SSHO="-o BatchMode=yes $(pq_kex)"

running() { pgrep -f "kyber6g.ground.main" >/dev/null; }
wait_http() { for _ in $(seq 1 60); do curl -s -o /dev/null "$URL/api/db" && return 0; sleep 1; done; return 1; }
uav() { ssh $SSHO -o ConnectTimeout=5 "$PI" "sudo systemctl $1 kyber6g-uav" 2>&1; }

# The ground station asks for a 4 MB UDP receive buffer, but Linux clamps that to net.core.rmem_max (212992 by default in
# WSL): a 1 s stall of the receive thread then drops video datagrams (measured: RcvbufErrors > 0). Raise the limit for this
# boot of the WSL VM; harmless and not persistent. Needs root (the launcher runs as root in WSL).
raise_udp_buffers() {
  sysctl -qw net.core.rmem_max=8388608 net.core.rmem_default=1048576 >/dev/null 2>&1 \
    && echo "[kyber6g] UDP receive buffer limit: $(sysctl -n net.core.rmem_max) bytes" \
    || echo "[kyber6g] note: could not raise net.core.rmem_max (not root?) - video may drop datagrams if the machine is overloaded"
}

stop_ground() {
  if running; then pkill -f "kyber6g.ground.main"; sleep 1; pkill -9 -f "kyber6g.ground.main" 2>/dev/null; echo "ground station stopped"; else echo "ground station not running"; fi
}

# On this laptop the clock of the WSL VM often runs at the wrong RATE (measured: 8.33 % slow, with the host pushing the
# wall clock forward by ~2.9 s every 35 s). First seen after a wake-up from standby; a restarted VM was right for about
# two minutes and slow again as soon as the CPU was under load. Switching the kernel clock source did not help, and a
# WSL restart does not last, so nothing is restarted here. The ground station is built to work with it (video, boxes
# and frame rates are timed on the camera's clock); latency figures are then estimates and the dashboard says so.
# This compares 3 s of this machine's clock with 3 s of the Pi's: prints the drift in percent, exit code 3 if over 2 %.
clock_check() {
  "$PY" - "$PI" $SSHO <<'EOF'
import subprocess, sys, time
try:
    p = subprocess.Popen(["ssh", *sys.argv[2:], "-o", "ConnectTimeout=5", sys.argv[1], "date +%s.%N; sleep 3; date +%s.%N"],
                         stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    a = float(p.stdout.readline()); m0 = time.monotonic()
    b = float(p.stdout.readline()); m1 = time.monotonic()
    drift = ((m1 - m0) / (b - a) - 1) * 100
except Exception:
    print("unknown"); sys.exit(0)
print(f"{drift:+.1f}")
sys.exit(3 if abs(drift) > 2 else 0)
EOF
}

case "${1:-status}" in
  clock) d=$(clock_check); rc=$?; echo "WSL clock against the Pi clock: $d %  ($([ $rc = 3 ] && echo 'WRONG RATE - latency figures are estimates' || echo ok))" ;;
  run)
    stop_ground >/dev/null
    echo "[kyber6g] making sure the UAV service is running on the Pi..."
    uav start >/dev/null && echo "[kyber6g] UAV service: $(uav is-active)" || echo "[kyber6g] WARNING: cannot reach the Pi ($PI) - ground station starts anyway"
    case " $* " in *" --skip-clock-check "*) ;; *)
      drift=$(clock_check)
      if [ $? = 3 ]; then
        echo "[kyber6g] NOTE: the clock of this WSL VM runs at the wrong speed ($drift % against the Pi)."
        echo "[kyber6g]       Video, boxes and frame rates use the camera's clock and are not affected;"
        echo "[kyber6g]       latency figures on the dashboard are estimates (marked APPROX)."
      else
        echo "[kyber6g] clock check against the Pi: $drift %"
      fi ;;
    esac
    raise_udp_buffers
    echo "[kyber6g] ground station starting; dashboard $URL  (close this window or Ctrl+C to stop)"
    cd "$REPO" || exit 1
    # open the dashboard in the Windows browser once it really answers (not after a fixed delay)
    case " $* " in *" --open "*) ( wait_http && cd /mnt/c 2>/dev/null && explorer.exe "$URL" >/dev/null 2>&1 ) & ;; esac
    # Supervised: if the process dies unexpectedly (not Ctrl+C, the stop command or a closed window) it is started
    # again, so the dashboard comes back by itself instead of showing "ground station not reachable" until someone notices.
    fails=0
    while true; do
      started=$(date +%s)
      "$PY" -W ignore -m kyber6g.ground.main 2>&1 | grep --line-buffered -v faulthandler | tee -a "$LOG"
      rc=${PIPESTATUS[0]}
      case "$rc" in 0|130|137|143) break ;; esac          # finished / Ctrl+C / killed / stopped on purpose
      [ $(( $(date +%s) - started )) -gt 300 ] && fails=0  # it ran fine for a while: not a crash loop
      fails=$((fails + 1))
      if [ "$fails" -ge 5 ]; then echo "[kyber6g] ground station failed $fails times in a row - giving up. Log: $LOG" | tee -a "$LOG"; break; fi
      echo "[kyber6g] $(date '+%F %T') ground station exited unexpectedly (code $rc) - restarting in 3 s ($fails/5)" | tee -a "$LOG"
      sleep 3
    done
    ;;
  start)
    if running; then echo "already running: $URL"; exit 0; fi
    raise_udp_buffers
    cd "$REPO" && setsid nohup "$PY" -W ignore -m kyber6g.ground.main >> "$LOG" 2>&1 < /dev/null &
    echo $! > "$PIDF"
    if wait_http; then echo "ground station up: $URL"; else echo "ground station did not come up; last log lines:"; tail -20 "$LOG"; exit 1; fi
    ;;
  stop) stop_ground ;;
  restart) stop_ground; "$0" start ;;
  status)
    if running; then echo "ground station: RUNNING ($URL)"; else echo "ground station: STOPPED"; fi
    curl -s "$URL/api/state" 2>/dev/null | "$PY" -c "
import json,sys
try: d=json.load(sys.stdin)
except Exception: sys.exit()
L=d['link']; t=d.get('telemetry') or {}; v=d['video']; det=d.get('detector') or {}
print('secure link :', L['state'], '| session', L['session_id'], '| UAV', L.get('uav_addr'))
print('gnss        :', t.get('fix'), '| sats', t.get('sats_used'), '/', t.get('sats_seen'))
print('video       :', v.get('fps'), 'fps | detector', 'ON' if det.get('available') else det.get('error'))
print('database    :', d.get('db'))" 2>/dev/null
    echo "UAV service : $(uav is-active)"
    echo "management  : SSH, key exchange $(ssh $SSHO -o ConnectTimeout=5 -v "$PI" true 2>&1 | sed -n 's/.*kex: algorithm: //p' | head -1)"
    ;;
  logs) tail -n 60 -f "$LOG" ;;
  uav-start) uav start; uav is-active ;;
  uav-stop) uav stop ;;
  uav-restart) uav restart; uav is-active ;;
  uav-status) ssh $SSHO "$PI" "systemctl status kyber6g-uav --no-pager | head -12" ;;
  uav-logs) ssh $SSHO "$PI" "journalctl -u kyber6g-uav -n 80 -f --no-pager" ;;
  deploy)
    # The code, then what the confined service needs and cannot do for itself (deploy/kyber6g-uav.service): key and
    # media directories that only the owner can enter, code that nobody else can write, byte code compiled now (the
    # service may not write any), and this repository's unit file (installed only when it differs; the one it
    # replaces is kept as .bak-<time>). The unit names the login user of the Pi it was written on; another user name
    # is filled in here. Needs sudo without a password on the Pi, like every uav-* command.
    cd "$REPO" || exit 1
    tar --exclude='__pycache__' -czf - kyber6g tests deploy run | ssh $SSHO "$PI" 'mkdir -p ~/kyber6g_app && tar -C ~/kyber6g_app -xzf -' || exit 1
    # the PUBLIC X25519 recording key (stored photos and recordings use a hybrid key wrap and are signed): a Pi set
    # up before that format gets it here; without it the UAV writes the older format (ML-KEM-1024 alone, unsigned)
    XPK="${KYBER6G_KEYDIR:-$HOME/.kyber6g}/gcs_recording_X25519.pk"
    if [ -f "$XPK" ]; then scp -q $SSHO "$XPK" "$PI":.kyber6g/peers/gcs_recording_X25519.pk || exit 1
    else echo "note: no X25519 recording key here yet (python -m kyber6g.tools.provision gcs makes one)"; fi
    ssh $SSHO "$PI" 'set -e
      mkdir -p ~/kyber6g_recordings ~/kyber6g_photos ~/kyber6g_audio/inbox
      chmod 700 ~/kyber6g_recordings ~/kyber6g_photos ~/kyber6g_audio ~/kyber6g_audio/inbox
      if [ -d ~/.kyber6g ]; then
        chmod 700 ~/.kyber6g; [ -d ~/.kyber6g/peers ] && chmod 700 ~/.kyber6g/peers
        find ~/.kyber6g -type f ! -name "*.sk" -exec chmod go-w {} +
      else
        echo "no keys on the Pi yet: run deploy/deploy_pi.sh first"; exit 1
      fi
      chmod -R go-w ~/kyber6g_app
      cd ~/kyber6g_app
      find . -name __pycache__ -prune -exec rm -rf {} +
      ~/kyber6g_venv/bin/python -m compileall -q kyber6g
      unit=/etc/systemd/system/kyber6g-uav.service
      new=$(mktemp); trap "rm -f $new" EXIT
      sed "s/abishekkg14/$(id -un)/g" deploy/kyber6g-uav.service > "$new"
      if ! cmp -s "$new" "$unit"; then
        if [ -f "$unit" ]; then sudo -n cp "$unit" "$unit.bak-$(date +%Y%m%d-%H%M%S)"; fi
        sudo -n install -m 644 "$new" "$unit"
        sudo -n systemctl daemon-reload
        sudo -n systemctl enable -q kyber6g-uav
        echo "unit file installed: $(systemd-analyze security kyber6g-uav --no-pager 2>/dev/null | tail -1)"
      fi' || { echo "deploy FAILED on the Pi (see above); the service was not restarted"; exit 1; }
    uav restart && echo "deployed; UAV service $(uav is-active)" ;;
  test) cd "$REPO" && "$PY" -W ignore -m unittest discover -s tests -t . ;;
  pipeline) cd "$REPO" && "$PY" -W ignore -m kyber6g.tools.pipeline_test "${@:2}" ;;
  audit) cd "$REPO" && "$PY" -W ignore -m kyber6g.tools.data_audit --pi "$PI" "${@:2}" ;;
  ui-test) cd "$REPO" && "$PY" -W ignore -m kyber6g.tools.ui_test "${@:2}" ;;
  # the measurement campaign behind the paper's plots (real hardware, about 110 min; see run/measure.sh), and the plots
  measure) KYBER6G_SSHO="$SSHO" bash "$REPO/run/measure.sh" "${2:-all}" ;;
  plots) cd "$REPO" && "$PY" -W ignore paper_plots/scripts/build.py "${@:2}" ;;
  # docs/CRYPTANALYSIS_REPORT.txt from the attack experiments of the last campaign (measure attacks), and
  # docs/AUDIO_CRYPTANALYSIS_REPORT.txt from the experiments on sealed audio (measure audio)
  report) cd "$REPO" && "$PY" -W ignore -m kyber6g.tools.crypto_report "${@:2}"
          "$PY" -W ignore -m kyber6g.tools.audio_report ;;
  # What docs/SECURITY_PROOFS.md rests on. `formal`: every ProVerif model under every attacker, each result compared
  # with what is claimed (ProVerif must be installed, see formal/README.md). `conformance`: NIST's ACVP vectors for
  # ML-KEM-1024 and ML-DSA-87 and published vectors for the classical parts, through the libraries on this machine
  # and on the Pi. `cbom`: the cryptographic bill of materials, generated from the code.
  formal) cd "$REPO" && python3 formal/run.py "${@:2}" ;;
  conformance)
    cd "$REPO" && "$PY" -W ignore -m kyber6g.tools.pq_conformance "${@:2}" 2>&1 | grep -v faulthandler
    echo "--- on the Pi"
    ssh $SSHO "$PI" 'cd ~/kyber6g_app && ~/kyber6g_venv/bin/python -W ignore -m kyber6g.tools.pq_conformance 2>&1 | grep -v faulthandler' ;;
  cbom) cd "$REPO" && "$PY" -W ignore -m kyber6g.tools.cbom "${@:2}" ;;
  # the simulation studies (ns-3 with 5G-LENA; calibrated from the measurements, see simulation/README.md): every
  # study on all cores but two, then the tables and plots. `simulate list` shows the runs, `simulate analyze` only
  # draws again from the results that are there.
  simulate)
    cd "$REPO" || exit 1
    case "${2:-all}" in
      analyze) "$PY" -W ignore simulation/analyze.py "${@:3}" ;;
      list) "$PY" -W ignore simulation/run_sweep.py --list "${@:3}" ;;
      all) "$PY" -W ignore simulation/run_sweep.py && "$PY" -W ignore simulation/analyze.py ;;
      *) "$PY" -W ignore simulation/run_sweep.py "${@:2}" && "$PY" -W ignore simulation/analyze.py ;;
    esac ;;
  pull)
    # A recording over the 256 MB limit of one transfer on the secure link: copy the file itself (it is encrypted at
    # rest: its key is wrapped with ML-KEM-1024 and X25519, so it stays unreadable on the way and on the Pi) and
    # decrypt it here.
    name="$(basename "${2:?usage: kyber6g.sh pull <rec_....k6grec>}")"
    mkdir -p "$DATA/recordings"
    echo "copying $name from the Pi ..."
    scp -q $SSHO "$PI:kyber6g_recordings/$name" "$DATA/recordings/$name" || { echo "copy failed (is the name right? see: LIST ON UAV)"; exit 1; }
    cd "$REPO" && "$PY" -W ignore -m kyber6g.tools.decrypt_recording "$DATA/recordings/$name" -o "$DATA/recordings/${name%.k6grec}.mp4" \
      && echo "decrypted: $DATA/recordings/${name%.k6grec}.mp4   (play it: $URL/recordings/${name%.k6grec}.mp4)"
    ;;
  audio-put)
    # No microphone is attached to the Pi: a file in the inbox of its audio store stands in for one. It travels over
    # SSH (post-quantum hybrid key exchange, see pq_kex) into a directory only the UAV's user can enter; the UAV seals
    # it (record_audio: MEDIA tab, SEAL SOURCE) and deletes the plain file.
    f="${2:?usage: kyber6g.sh audio-put <audio file>}"
    [ -f "$f" ] || { echo "no such file: $f"; exit 1; }
    name="$(printf %s "$(basename "$f")" | tr -c 'A-Za-z0-9._-' '_')"
    ssh $SSHO "$PI" 'mkdir -p ~/kyber6g_audio/inbox && chmod 700 ~/kyber6g_audio ~/kyber6g_audio/inbox' || exit 1
    scp -q $SSHO "$f" "$PI:kyber6g_audio/inbox/$name" || { echo "copy failed"; exit 1; }
    ssh $SSHO "$PI" "chmod 600 ~/kyber6g_audio/inbox/$name"
    echo "on the Pi: kyber6g_audio/inbox/$name  ($(stat -c %s "$f") bytes, SHA-256 $(sha256sum "$f" | cut -c1-16)...)"
    ;;
  *) sed -n '2,15p' "$0" ;;
esac
