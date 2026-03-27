#!/bin/bash
#
# build-wolfssl.sh — Build and install wolfSSL with QUIC + post-quantum support
#
# Builds from ~/wolfssl source tree.
# Installs to /usr/local by default.
#
# Usage: ./build-wolfssl.sh [--prefix=/usr/local] [--clean]

set -e

WOLFSSL_DIR="$HOME/wolfssl"
PREFIX="/usr/local"
CLEAN=0
JOBS="$(nproc 2>/dev/null || echo 4)"

for arg in "$@"; do
    case "$arg" in
        --prefix=*) PREFIX="${arg#--prefix=}" ;;
        --clean)    CLEAN=1 ;;
        --help|-h)
            echo "Usage: $0 [--prefix=/usr/local] [--clean]"
            echo "  --prefix=DIR  Install to DIR (default: /usr/local)"
            echo "  --clean       Run make clean before building"
            exit 0
            ;;
        *) echo "Unknown option: $arg"; exit 1 ;;
    esac
done

echo "=== Building wolfSSL ==="
echo "    Source:  $WOLFSSL_DIR"
echo "    Prefix:  $PREFIX"
echo "    Jobs:    $JOBS"
echo

cd "$WOLFSSL_DIR"

# Generate configure if needed
if [ ! -f configure ]; then
    echo "[1/4] Running autoreconf..."
    autoreconf -fi
else
    echo "[1/4] configure exists, skipping autoreconf"
fi

if [ "$CLEAN" -eq 1 ] && [ -f Makefile ]; then
    echo "       make clean..."
    make clean >/dev/null 2>&1 || true
fi

# Configure
echo "[2/4] Configuring..."
./configure \
    --prefix="$PREFIX" \
    --enable-harden-tls \
    --disable-oldtls \
    --enable-mlkem \
    --enable-mldsa \
    --enable-slhdsa \
    --enable-tls-mlkem-standalone \
    --enable-ech \
    --enable-quic \
    --enable-session-ticket \
    --enable-opensslall \
    --disable-dh \
    --enable-static \
    CFLAGS="-DWOLFSSL_AES_ECB -DHAVE_AES_ECB" \
    >/dev/null 2>&1

# Build
echo "[3/4] Building (make -j$JOBS)..."
make -j"$JOBS" >/dev/null 2>&1

# Install
echo "[4/4] Installing to $PREFIX..."
sudo make install >/dev/null 2>&1

# Refresh shared library cache
sudo ldconfig 2>/dev/null || true

echo
echo "=== Done ==="
echo
pkg-config --modversion wolfssl 2>/dev/null && \
    echo "  wolfssl $(pkg-config --modversion wolfssl)"
