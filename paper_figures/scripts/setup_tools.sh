#!/bin/bash
# One-time tool setup for the paper figures. Run as root inside Ubuntu 22.04 / WSL:
#     sudo bash paper_figures/scripts/setup_tools.sh
# Installs only what is missing:
#   draw.io Desktop (CLI export of .drawio -> PDF, no GUI needed; run under xvfb)
#   ghostscript + pdfcrop (texlive-extra-utils)   tight bounding boxes
#   poppler-utils (pdftops, pdftoppm, pdffonts)   EPS, 600 dpi PNG, font check
#   Arial / Times New Roman                        taken from the Windows host when this is WSL
#   Pillow, pypdf (Python)                         text measurement, exact page width
# Then:  python3 paper_figures/scripts/fetch_artwork.py        (pictograms and the public-domain photograph)
#        python3 paper_figures/scripts/make_illustrations.py   (needs the Python package 'cryptography')
#        python3 paper_figures/scripts/build.py
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DRAWIO_VERSION="${DRAWIO_VERSION:-31.7.0}"
CACHE="${XDG_CACHE_HOME:-$HOME/.cache}/kyber6g-figures"
export DEBIAN_FRONTEND=noninteractive
have() { command -v "$1" >/dev/null 2>&1; }

mkdir -p "$ROOT"/{raw_drawio,assets,exported_pdf,exported_png,exported_eps} "$CACHE"

pkgs=()
have gs || pkgs+=(ghostscript)
have pdfcrop || pkgs+=(texlive-extra-utils)
have pdftops || pkgs+=(poppler-utils)
have xvfb-run || pkgs+=(xvfb)
have curl || pkgs+=(curl)
if [ ${#pkgs[@]} -gt 0 ]; then
  echo "[setup] apt: ${pkgs[*]}"
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends "${pkgs[@]}" >/dev/null
fi

if ! have drawio; then
  deb="$CACHE/drawio-amd64-$DRAWIO_VERSION.deb"
  url="https://github.com/jgraph/drawio-desktop/releases/download/v$DRAWIO_VERSION/drawio-amd64-$DRAWIO_VERSION.deb"
  echo "[setup] draw.io Desktop $DRAWIO_VERSION from the official release page"
  [ -s "$deb" ] || curl -fL --retry 3 -sS -o "$deb" "$url"
  # the digest GitHub publishes for the release asset must match what was downloaded
  want=$(curl -fsS "https://api.github.com/repos/jgraph/drawio-desktop/releases/tags/v$DRAWIO_VERSION" \
         | python3 -c "import json,sys; print(next((a.get('digest') or '' for a in json.load(sys.stdin)['assets'] if a['name']=='drawio-amd64-$DRAWIO_VERSION.deb'), ''))")
  got="sha256:$(sha256sum "$deb" | cut -d' ' -f1)"
  if [ -n "$want" ] && [ "$want" != "$got" ]; then echo "[setup] CHECKSUM MISMATCH for $deb ($got, expected $want)"; rm -f "$deb"; exit 1; fi
  echo "[setup] checksum ${want:+verified }$got"
  apt-get install -y -qq "$deb" >/dev/null
fi

# Elsevier accepts Arial, Helvetica or Times New Roman. In WSL the real fonts are on the Windows side.
if ! fc-list | grep -qi '/arial\.ttf'; then
  win=/mnt/c/Windows/Fonts
  if [ -f "$win/arial.ttf" ]; then
    dst=/usr/local/share/fonts/windows-core
    mkdir -p "$dst"
    cp "$win"/arial.ttf "$win"/arialbd.ttf "$win"/ariali.ttf "$win"/arialbi.ttf "$win"/times.ttf "$win"/timesbd.ttf "$win"/timesi.ttf "$win"/timesbi.ttf "$dst"/
    fc-cache -f "$dst"
    echo "[setup] Arial and Times New Roman made available to fontconfig"
  else
    apt-get install -y -qq fonts-liberation >/dev/null
    echo "[setup] no Windows fonts found: Liberation Sans (metric-compatible with Arial) will be used"
  fi
fi

# Python: Pillow measures text (label fits its block?), pypdf scales the cropped page to the exact column width
python3 -c "import PIL" 2>/dev/null || pip3 install -q pillow
python3 -c "import pypdf" 2>/dev/null || pip3 install -q pypdf

echo "[setup] tools:"
for t in drawio gs pdfcrop pdftops pdftoppm pdffonts xvfb-run; do printf '   %-10s %s\n' "$t" "$(command -v "$t" || echo MISSING)"; done
echo "   draw.io    $(xvfb-run -a drawio --no-sandbox --version 2>/dev/null | grep -E '^[0-9.]+$' | tail -1)"
echo "   gs         $(gs --version)"
echo "   arial      $(fc-match Arial | cut -d: -f1)"
python3 -c "import PIL, pypdf; print('   Pillow    ', PIL.__version__); print('   pypdf     ', pypdf.__version__)"
