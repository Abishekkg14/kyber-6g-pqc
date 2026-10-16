#!/bin/bash
# Build dtls_bench against a private wolfSSL 5.9.4 install and make the two pinned ML-DSA-87 certificates.
#   bash kyber6g/tools/dtls_baseline/build.sh PREFIX OUTDIR
# PREFIX: where wolfSSL was installed (cmake --install), OUTDIR: where dtls_bench goes.
# wolfSSL was configured with CMake: -DWOLFSSL_DTLS=yes -DWOLFSSL_DTLS13=yes -DWOLFSSL_DTLS_CH_FRAG=yes -DWOLFSSL_TLS13=yes
# -DWOLFSSL_MLKEM=yes -DWOLFSSL_MLDSA=yes -DWOLFSSL_CURVE25519=yes -DWOLFSSL_ECC=yes -DWOLFSSL_SESSION_TICKET=yes
# -DWOLFSSL_HRR_COOKIE=yes (source: github.com/wolfSSL/wolfssl, tag v5.9.4-stable).
set -e
PREFIX="$1"; OUT="$2"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
gcc -O2 -Wall -o "$OUT/dtls_bench" "$HERE/dtls_bench.c" -I"$PREFIX/include" -L"$PREFIX/lib" -lwolfssl -Wl,-rpath,"$PREFIX/lib"
echo "built $OUT/dtls_bench"
