#!/usr/bin/env bash
#
# nettle/mayhem/test.sh — GOLDEN-KAT oracle. Nettle's full `make check` testsuite needs extra test
# scaffolding that is awkward in the build sandbox, so we ship an additive golden oracle
# (mayhem/golden_oracle.c) that drives the SAME public parse APIs the fuzzers hit (rsa_keypair_from_sexp
# + base16/base64 decode) on byte-exact known-good vectors and asserts the EXPECTED results. A no-op /
# "return 0" patch to those parsers makes the oracle FAIL. The oracle links the SAME sanitized
# libnettle.a/libhogweed.a that mayhem/build.sh produced, so the golden parse runs under ASan+UBSan too.
#
# Emits a CTRF (ctrf.io) summary. exit 0 iff the oracle passes. build.sh must run first.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=$(cd "$(dirname "$0")/.." && pwd)}"
: "${CC:=clang}"
cd "$SRC"

PREFIX="$SRC/nettle-install"
LIBNETTLE="$PREFIX/lib/libnettle.a"
LIBHOGWEED="$PREFIX/lib/libhogweed.a"
INC="-I$PREFIX/include"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

if [ ! -f "$LIBHOGWEED" ] || [ ! -f "$LIBNETTLE" ]; then
  echo "missing $LIBHOGWEED / $LIBNETTLE — run mayhem/build.sh first" >&2
  emit_ctrf "nettle-golden" 0 1 0; exit 2
fi

# libnettle.a/libhogweed.a were built WITH $SANITIZER_FLAGS (+ -fsanitize=fuzzer-no-link for coverage),
# so the oracle must link the matching sanitizer runtimes — otherwise the instrumented libraries'
# __asan_*/__ubsan_*/__sanitizer_cov_* symbols are undefined at link time. Pass the SAME flags here.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
BIN="$SRC/mayhem-build-test/golden_oracle"
mkdir -p "$SRC/mayhem-build-test"
if ! "$CC" $SANITIZER_FLAGS -fsanitize=fuzzer-no-link -O1 -g $INC "$SRC/mayhem/golden_oracle.c" \
       "$LIBHOGWEED" "$LIBNETTLE" -lgmp -o "$BIN" 2> "$SRC/mayhem-build-test/build.log"; then
  echo "FAIL: could not compile golden oracle" >&2
  cat "$SRC/mayhem-build-test/build.log" >&2
  emit_ctrf "nettle-golden" 0 1 0; exit 1
fi

echo "=== running golden KAT oracle ==="
oracle_out="$SRC/mayhem-build-test/oracle.log"
"$BIN" >"$oracle_out" 2>&1
oracle_rc=$?
cat "$oracle_out"
# Verify both exit code AND expected output from the oracle.
# A neutered binary (LD_PRELOAD exit(0)) produces NO output — grep catches it.
if [ "$oracle_rc" -ne 0 ]; then
  echo "golden oracle exited $oracle_rc" >&2
  emit_ctrf "nettle-golden" 0 1 0; exit 1
elif ! grep -q "golden KAT oracle passed" "$oracle_out"; then
  echo "FAIL: oracle exited 0 but expected confirmation message missing (neutered/no-op?)" >&2
  emit_ctrf "nettle-golden" 0 1 0; exit 1
else
  emit_ctrf "nettle-golden" 1 0 0
fi
