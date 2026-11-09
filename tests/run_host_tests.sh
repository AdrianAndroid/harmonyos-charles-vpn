#!/usr/bin/env bash
# Host (macOS/Linux) unit + integration tests for the portable parts of the
# Charles TUN proxy. The Node-API bridge and hilog are HarmonyOS-only and are
# excluded here; everything under test is portable POSIX/C++17.
set -euo pipefail

cd "$(dirname "$0")"
ROOT="$(cd .. && pwd)"
CPP="$ROOT/entry/src/main/cpp"
OUT="$(mktemp -d -t charles_vpn_tests)"
trap 'rm -rf "$OUT"' EXIT

CXX="${CXX:-clang++}"
WARN="-Wall -Wextra -Werror"
STD="-std=c++17"

echo "== building http_request_test =="
$CXX $STD $WARN "$CPP/http_request.cpp" http_request_test.cpp -o "$OUT/http_request_test"

echo "== building engine_test =="
$CXX $STD $WARN "$CPP/http_request.cpp" "$CPP/tun_proxy.cpp" engine_test.cpp \
    -o "$OUT/engine_test" -lpthread

echo "== building integration_test =="
$CXX $STD $WARN "$CPP/http_request.cpp" "$CPP/tun_proxy.cpp" integration_test.cpp \
    -o "$OUT/integration_test" -lpthread

echo "== running http_request_test =="
"$OUT/http_request_test"
echo "== running engine_test =="
"$OUT/engine_test"
echo "== running integration_test =="
"$OUT/integration_test"

echo "ALL HOST TESTS PASSED"
