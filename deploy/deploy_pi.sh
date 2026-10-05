#!/bin/bash
# Deploy the kyber6g package to the Raspberry Pi and exchange PUBLIC keys.
# Usage: deploy/deploy_pi.sh [ssh-target]   (default: kyber-pi from ~/.ssh/config)
# Requires: GCS keys already provisioned locally (python -m kyber6g.tools.provision gcs)
set -euo pipefail
PI="${1:-kyber-pi}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
KEYDIR="${KYBER6G_KEYDIR:-$HOME/.kyber6g}"
# SSH with a post-quantum hybrid key exchange first, when this OpenSSH has one (see pq_kex in run/kyber6g.sh)
pq=""
for k in sntrup761x25519-sha512@openssh.com sntrup761x25519-sha512 mlkem768x25519-sha256; do
  ssh -Q kex 2>/dev/null | grep -qx -- "$k" && pq="$k${pq:+,$pq}"
done
SSHO="${pq:+-o KexAlgorithms=^$pq}"

echo "[1/5] copying code to $PI:~/kyber6g_app"
ssh $SSHO "$PI" 'mkdir -p ~/kyber6g_app'
tar -C "$HERE" --exclude='__pycache__' -czf - kyber6g tests deploy/uav.json | ssh $SSHO "$PI" 'tar -C ~/kyber6g_app -xzf -'

echo "[2/5] Python environment (system site-packages for picamera2/libcamera)"
ssh $SSHO "$PI" 'test -x ~/kyber6g_venv/bin/python || python3 -m venv --system-site-packages ~/kyber6g_venv;
  ~/kyber6g_venv/bin/pip install -q "liboqs-python==0.16.0" "cryptography==50.0.1" 2>&1 | tail -2'

echo "[3/5] UAV identity (secret key never leaves the Pi)"
ssh $SSHO "$PI" 'cd ~/kyber6g_app && ~/kyber6g_venv/bin/python -m kyber6g.tools.provision uav'

echo "[4/5] exchanging public keys"
# The pinned keys decide whom each node trusts: the directories are owner-only and the files not writable by anyone else.
# Only PUBLIC keys travel here. That they are the right ones rests on SSH's authentication of the Pi at this moment;
# to be sure, compare the fingerprints printed below with `sha256sum` of the same files, run on the Pi itself.
mkdir -p "$KEYDIR/peers"
chmod 700 "$KEYDIR" "$KEYDIR/peers"
scp -q $SSHO "$PI":.kyber6g/uav_ML-DSA-87.pk "$KEYDIR/peers/uav_ML-DSA-87.pk"
scp -q $SSHO "$KEYDIR/gcs_ML-DSA-87.pk" "$PI":.kyber6g/peers/gcs_ML-DSA-87.pk
scp -q $SSHO "$KEYDIR/gcs_recording_ML-KEM-1024.ek" "$PI":.kyber6g/peers/gcs_recording_ML-KEM-1024.ek
# the classical half of the recording key (stored files use a hybrid key wrap); made by `provision gcs`
[ -f "$KEYDIR/gcs_recording_X25519.pk" ] || { echo "  missing $KEYDIR/gcs_recording_X25519.pk: run  python -m kyber6g.tools.provision gcs  first (it keeps the keys that exist)"; exit 1; }
scp -q $SSHO "$KEYDIR/gcs_recording_X25519.pk" "$PI":.kyber6g/peers/gcs_recording_X25519.pk
chmod 644 "$KEYDIR"/peers/*
ssh $SSHO "$PI" 'chmod 700 ~/.kyber6g ~/.kyber6g/peers && chmod 644 ~/.kyber6g/peers/* ~/.kyber6g/*.pk'
echo "  UAV fingerprint: $(sha256sum "$KEYDIR/peers/uav_ML-DSA-87.pk" | cut -c1-32)"
echo "  GCS fingerprint: $(sha256sum "$KEYDIR/gcs_ML-DSA-87.pk" | cut -c1-32)"

echo "[5/5] done. Install and start the confined service on the Pi (needs sudo there):  bash run/kyber6g.sh deploy"
echo "      or run it by hand on the Pi:  cd ~/kyber6g_app && ~/kyber6g_venv/bin/python -m kyber6g.uav.main -c deploy/uav.json"
