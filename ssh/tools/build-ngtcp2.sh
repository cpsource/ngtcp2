#!/bin/bash
#
# build-ngtcp2.sh — Build and install ngtcp2 with wolfSSL crypto backend
#
# Builds from the ngtcp2 source tree (parent of ssh/tools/).
# Installs to /usr/local by default.
#
# Usage: ./build-ngtcp2.sh [--prefix=/usr/local] [--clean]

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
NGTCP2_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
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

echo "=== Building ngtcp2 ==="
echo "    Source:  $NGTCP2_DIR"
echo "    Prefix:  $PREFIX"
echo "    Jobs:    $JOBS"
echo

cd "$NGTCP2_DIR"

# Generate configure if needed (git checkout without release tarball)
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

# Configure with wolfSSL crypto backend
echo "[2/4] Configuring (--with-wolfssl --prefix=$PREFIX)..."
./configure --with-wolfssl --prefix="$PREFIX" >/dev/null 2>&1

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
pkg-config --modversion libngtcp2 2>/dev/null && \
    echo "  libngtcp2            $(pkg-config --modversion libngtcp2)"
pkg-config --modversion libngtcp2_crypto_wolfssl 2>/dev/null && \
    echo "  libngtcp2_crypto_wolfssl $(pkg-config --modversion libngtcp2_crypto_wolfssl)"
