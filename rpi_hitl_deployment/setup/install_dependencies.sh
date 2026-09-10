#!/usr/bin/env bash
# ==============================================================================
# Kyber-6G Raspberry Pi 4 Environment & Dependency Installer
# Target: Raspberry Pi OS (Debian 11/12) / Ubuntu 22.04 LTS (ARMv8 64-bit)
# ==============================================================================
set -e

echo "=== [1/4] Updating Package Lists & Installing System Tools ==="
sudo apt-get update
sudo apt-get install -y \
    build-essential cmake ninja-build git pkg-config \
    python3 python3-pip python3-dev libssl-dev \
    cpufrequtils sysstat net-tools wireless-tools iw

echo "=== [2/4] Installing Python Cryptographic & Benchmarking Packages ==="
pip3 install --upgrade pip
pip3 install cryptography psutil numpy pyyaml

echo "=== [3/4] Checking and Installing liboqs (C Library) ==="
if [ ! -f /usr/local/lib/liboqs.so ] && [ ! -f /usr/local/lib/aarch64-linux-gnu/liboqs.so ]; then
    echo "[*] Building liboqs v0.10.0 from source for ARM Cortex-A72..."
    cd /tmp
    rm -rf liboqs
    git clone --depth 1 --branch 0.10.0 https://github.com/open-quantum-safe/liboqs.git
    cd liboqs
    mkdir -p build && cd build
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local -DBUILD_SHARED_LIBS=ON -DOQS_USE_OPENSSL=ON ..
    ninja
    sudo ninja install
    sudo ldconfig
    echo "[+] liboqs C library successfully installed to /usr/local/lib"
else
    echo "[+] liboqs already present in /usr/local/lib"
fi

echo "=== [4/4] Installing liboqs-python Bindings ==="
if ! python3 -c "import oqs" 2>/dev/null; then
    echo "[*] Installing oqs python wrapper..."
    pip3 install liboqs-python || {
        cd /tmp
        rm -rf liboqs-python
        git clone --depth 1 https://github.com/open-quantum-safe/liboqs-python.git
        cd liboqs-python
        pip3 install .
    }
fi

echo "=== Verification ==="
python3 -c "
import oqs, cryptography, psutil
print('  [OK] oqs version:', oqs.__version__ if hasattr(oqs, '__version__') else 'loaded')
print('  [OK] cryptography version:', cryptography.__version__)
print('  [OK] ML-KEM-1024 enabled:', 'ML-KEM-1024' in oqs.get_enabled_KEM_mechanisms())
sigs = oqs.get_enabled_sig_mechanisms()
has_sig = 'ML-DSA-87' in sigs or 'Dilithium5' in sigs
print('  [OK] Level-5 ML-DSA enabled:', has_sig)
"
echo "=== All Raspberry Pi 4 dependencies successfully installed! ==="
