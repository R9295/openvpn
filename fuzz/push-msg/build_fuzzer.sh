#!/bin/bash
set -e

# Fuzzer build script for process_incoming_link
# This creates a fuzzing harness for OpenVPN's incoming packet processing

# Determine the OpenVPN root directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENVPN_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
FUZZ_DIR="${OPENVPN_ROOT}/fuzz/push-msg"
BUILD_DIR="${FUZZ_DIR}/build"

echo "=== OpenVPN process_incoming_link Fuzzer Build Script ==="
echo "OpenVPN root: ${OPENVPN_ROOT}"
echo "Fuzz directory: ${FUZZ_DIR}"

# Set compiler and flags for fuzzing
export CC="afl-clang-fast"
export CXX="afl-clang-fast++"
export CFLAGS="${CFLAGS:--g -O1 -fsanitize=fuzzer-no-link,address,undefined}"
export CXXFLAGS="${CXXFLAGS:--g -O1 -fsanitize=fuzzer-no-link,address,undefined}"
export LDFLAGS="${LDFLAGS:--fsanitize=address,undefined}"
export AFL_LLVM_CMPLOG=1
cd $OPENVPN_ROOT
make clean
autoreconf -ivf
./configure --disable-lz4 --with-crypto-library=openssl OPENSSL_LIBS="-L/usr/local/ssl/ -lssl -lcrypto" OPENSSL_CFLAGS="-I/usr/local/ssl/include/" --disable-dco
make -j$(nproc)
echo "Step 1: Compiling fuzzer harness..."
$CC -DHAVE_CONFIG_H -D_GNU_SOURCE -I. -I./src/openvpn -I./include -I./src/compat -I/usr/include/libnl3/ \
      -DPLUGIN_LIBDIR=\"/usr/local/lib/openvpn/plugins\" -std=gnu99 $CFLAGS \
      -c ./fuzz/push-msg/push_msg_fuzzer.c -o ./fuzz/push-msg/push_msg_fuzzer.o

echo "Step 2: Linking fuzzer with libopenvpn.a..."
$CC -fsanitize=address,fuzzer,undefined \
      ./fuzz/push-msg/push_msg_fuzzer.o \
      ./src/openvpn/libopenvpn.a \
      ./src/compat/.libs/libcompat.a \
      /usr/lib/x86_64-linux-gnu/libnsl.a \
      /usr/lib/x86_64-linux-gnu/libresolv.a \
      /usr/lib/x86_64-linux-gnu/liblzo2.a \
      -lssl -lcrypto -ldl -l:libnl-3.a -l:libnl-genl-3.a -lcap-ng \
      -o ./fuzz/push-msg/push_msg_fuzzer

echo ""
echo "=== Build complete ==="
echo "Fuzzer binary: ./fuzz/push-msg/push_msg_fuzzer"
echo ""
echo "To run:"
echo "  mkdir -p fuzz/push-msg/corpus"
echo "  ./fuzz/push-msg/push_msg_fuzzer fuzz/push-msg/corpus"
