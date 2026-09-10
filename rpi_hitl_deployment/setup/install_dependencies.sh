#!/usr/bin/env bash
# ==============================================================================
# Kyber-6G Raspberry Pi 4 Fast & Smart Dependency Installer
# - Skips already-installed packages for instantaneous 3-second startup
# - Installs system tools, C liboqs, and python bindings only if missing
# ==============================================================================
set -e

echo "=== [1/4] Checking Python Cryptographic & Math Packages ==="
if python3 -c "import cryptography, psutil, numpy, yaml" 2>/dev/null; then
    echo "  [OK] Python libraries (cryptography, psutil, numpy, pyyaml) already installed."
else
    echo "  [*] Installing missing python packages..."
    sudo apt-get update
    sudo apt-get install -y python3-pip python3-dev
    pip3 install --upgrade pip
    pip3 install cryptography psutil numpy pyyaml
fi

echo "=== [2/4] Checking Essential System Build & Network Tools ==="
MISSING_PKGS=""
for pkg in build-essential cmake ninja-build git pkg-config libssl-dev cpufrequtils sysstat net-tools wireless-tools iw; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
        MISSING_PKGS="$MISSING_PKGS $pkg"
    fi
done

if [ -n "$MISSING_PKGS" ]; then
    echo "  [*] Installing missing system packages: $MISSING_PKGS"
    sudo apt-get update
    sudo apt-get install -y $MISSING_PKGS
else
    echo "  [OK] All system build and wireless tools are already present."
fi

echo "=== [3/4] Checking liboqs C Library (v0.10.0) ==="
if [ -f /usr/local/lib/liboqs.so ] || [ -f /usr/local/lib/aarch64-linux-gnu/liboqs.so ] || [ -f /usr/lib/liboqs.so ]; then
    echo "  [OK] liboqs shared library is already installed."
else
    echo "  [*] Building liboqs v0.10.0 from source for ARM Cortex-A72..."
    cd /tmp
    rm -rf liboqs
    git clone --depth 1 --branch 0.10.0 https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    mkdir -p build && cd build
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=ON ..
    ninja
    sudo ninja install
    sudo ldconfig
    echo "  [+] liboqs successfully installed."
fi

echo "=== [4/4] Checking liboqs-python Bindings ==="
if python3 -c "import oqs" 2>/dev/null; then
    echo "  [OK] oqs Python module is already functional."
else
    echo "  [*] Installing oqs python wrapper..."
    pip3 install liboqs-python || {
        cd /tmp
        rm -rf liboqs-python
        git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git
        cd liboqs-python
        pip3 install .
    }
fi

echo ""
echo "=== Final Environment Verification ==="
python3 -c "
import oqs, cryptography, psutil
print('  [SUCCESS] oqs module loaded')
print('  [SUCCESS] cryptography version:', cryptography.__version__)
print('  [SUCCESS] ML-KEM-1024 Level-5 enabled:', 'ML-KEM-1024' in oqs.get_enabled_KEM_mechanisms())
sigs = oqs.get_enabled_sig_mechanisms()
has_sig = 'ML-DSA-87' in sigs or 'Dilithium5' in sigs
print('  [SUCCESS] ML-DSA-87 Level-5 enabled:', has_sig)
"
echo "=== All Raspberry Pi 4 dependencies verified! ==="
