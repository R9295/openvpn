#!/bin/bash
set -e

# Build script for push message fuzzer
# This script builds a standalone libfuzzer harness for OpenVPN's push message parsing

echo "=== Building OpenVPN Push Message Fuzzer ==="

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPENVPN_ROOT="${SCRIPT_DIR}/../.."
OPENVPN_SRC="${OPENVPN_ROOT}/src/openvpn"

# Set compiler and flags for fuzzing
export CC="${CC:-clang}"
export CXX="${CXX:-clang++}"
export CFLAGS="${CFLAGS:--g -O1 -fsanitize=fuzzer,address,undefined}"
export CXXFLAGS="${CFLAGS:--g -O1 -fsanitize=fuzzer,address,undefined}"
export LDFLAGS="${LDFLAGS:--fsanitize=fuzzer,address,undefined}"

# Check if OpenVPN source exists
if [ ! -d "${OPENVPN_SRC}" ]; then
    echo "ERROR: OpenVPN source directory not found: ${OPENVPN_SRC}"
    exit 1
fi

# Build the fuzzer
echo "Building fuzzer..."
${CC} ${CFLAGS} ${LDFLAGS} \
    -DHAVE_CONFIG_H \
    -I"${OPENVPN_ROOT}" \
    -I"${OPENVPN_SRC}" \
    -I"${OPENVPN_ROOT}/include" \
    "${SCRIPT_DIR}/push_msg_fuzzer.c" \
    "${OPENVPN_SRC}/buffer.c" \
    "${OPENVPN_SRC}/push.c" \
    "${OPENVPN_SRC}/options.c" \
    "${OPENVPN_SRC}/options_util.c" \
    "${OPENVPN_SRC}/push_util.c" \
    "${OPENVPN_SRC}/base64.c" \
    "${OPENVPN_SRC}/misc.c" \
    "${OPENVPN_SRC}/console.c" \
    "${OPENVPN_SRC}/error.c" \
    "${OPENVPN_SRC}/otime.c" \
    "${OPENVPN_SRC}/platform.c" \
    "${OPENVPN_SRC}/argv.c" \
    -lssl -lcrypto -ldl -lpthread \
    -o "${SCRIPT_DIR}/push_msg_fuzzer" \
    2>&1 | tee build.log

if [ ${PIPESTATUS[0]} -eq 0 ]; then
    echo ""
    echo "=== Build complete ==="
    echo "Fuzzer binary: ${SCRIPT_DIR}/push_msg_fuzzer"
    echo ""
    echo "To create initial corpus:"
    echo "  cd ${SCRIPT_DIR}"
    echo "  mkdir -p corpus"
    echo "  echo 'PUSH_UPDATE,dhcp-option DNS 8.8.8.8' > corpus/test1.txt"
    echo "  echo 'PUSH_REQUEST' > corpus/test2.txt"
    echo ""
    echo "To run the fuzzer:"
    echo "  cd ${SCRIPT_DIR}"
    echo "  ./push_msg_fuzzer corpus"
    echo ""
    echo "Advanced options:"
    echo "  ./push_msg_fuzzer -max_total_time=60 corpus"
    echo "  ./push_msg_fuzzer -jobs=4 -workers=4 corpus"
    echo "  ./push_msg_fuzzer -dict=push_msg.dict corpus"
else
    echo ""
    echo "=== Build failed ==="
    echo "Check build.log for errors"
    exit 1
fi
