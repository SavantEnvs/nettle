#!/usr/bin/env bash
#
# nettle/mayhem/build.sh — build GNU Nettle's OSS-Fuzz harnesses as sanitized libFuzzer targets
# (+ standalone run-once reproducers).
#
# Fuzzed surface: Nettle's low-level crypto KEY/SIGNATURE PARSERS — the ASN.1/DER decoders
# (der2rsa/der2dsa via asn1_der_iterator), the S-expression parsers (sexp2rsa/sexp2dsa/sexp2bignum),
# and the bignum_from_* helpers underneath. The 7 harnesses (verbatim from OSS-Fuzz) each feed a raw
# in-memory byte buffer to one public parse entry point:
#   fuzz_rsa_public_key_from_der          rsa_public_key_from_der_iterator (ASN.1 DER)
#   fuzz_rsa_keypair_from_der             rsa_keypair_from_der             (PKCS#1 DER)
#   fuzz_rsa_keypair_from_sexp            rsa_keypair_from_sexp            (S-expression)
#   fuzz_dsa_openssl_private_key_from_der dsa_openssl_private_key_from_der (ASN.1 DER)
#   fuzz_dsa_sha1_keypair_from_sexp       dsa_sha1_keypair_from_sexp       (S-expression)
#   fuzz_dsa_sha256_keypair_from_sexp     dsa_sha256_keypair_from_sexp     (S-expression)
#   fuzz_dsa_signature_from_sexp          dsa_signature_from_sexp          (S-expression)
#
# We build libnettle + libhogweed FROM SOURCE with $SANITIZER_FLAGS + -fsanitize=fuzzer-no-link so the
# fuzzed parser code (not just the harness) is instrumented, install them to a prefix, then link
# $LIB_FUZZING_ENGINE into each harness only. Unlike OSS-Fuzz (which uses --enable-mini-gmp) we link
# the real GMP (libgmp-dev, installed by the commit Dockerfile) — the canonical Nettle bignum backend.
#
# Build contract comes from the org base ENV: CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/SRC/OUT/
# STANDALONE_FUZZ_MAIN. Outputs land in $OUT (=/mayhem).
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
# DEBUG_FLAGS: DWARF ≤ 3 symbols for Mayhem triage (clang-19 plain -g emits DWARF-5; be explicit).
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${SRC:=$(cd "$(dirname "$0")/.." && pwd)}"
: "${OUT:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE SRC OUT STANDALONE_FUZZ_MAIN MAYHEM_JOBS

# Coverage instrumentation for the library (the libFuzzer target also gets -fsanitize=fuzzer via
# $LIB_FUZZING_ENGINE; the standalone reproducer does not, so build the library with
# -fsanitize=fuzzer-no-link to keep both link forms resolving the coverage symbols).
COV="-fsanitize=fuzzer-no-link"

cd "$SRC"

HARNESS_DIR="$SRC/mayhem/harnesses"
PREFIX="$SRC/nettle-install"
mkdir -p "$OUT"

# ── 1) Build libnettle + libhogweed from source WITH sanitizers, install to $PREFIX ───────────────
# .bootstrap just runs autoconf+autoheader to generate ./configure.
bash .bootstrap

export CFLAGS="${CFLAGS:-} $SANITIZER_FLAGS $DEBUG_FLAGS $COV"
# Static libs only (we link the .a archives), no docs, no openssl glue (test-only), real GMP.
./configure --disable-shared --enable-static --disable-documentation --disable-openssl \
            --prefix="$PREFIX"
# Build + install ONLY the libraries/headers (the top-level `*-here` targets). Plain `make` recurses
# into SUBDIRS (testsuite/tools/examples); those test binaries statically link EVERY object (aes/
# salsa20/... whose implementations come from the assembler path) and can fail to link under our
# instrumented CFLAGS — and we don't need them. We only need libnettle.a + libhogweed.a + headers.
make -j"$MAYHEM_JOBS" all-here
make install-here

LIBNETTLE="$PREFIX/lib/libnettle.a"
LIBHOGWEED="$PREFIX/lib/libhogweed.a"
[ -f "$LIBNETTLE" ]  || { echo "ERROR: $LIBNETTLE not built"  >&2; exit 1; }
[ -f "$LIBHOGWEED" ] || { echo "ERROR: $LIBHOGWEED not built" >&2; exit 1; }

# Harnesses include <nettle/dsa.h> etc. — they resolve from $PREFIX/include.
INC="-I$PREFIX/include"

# ── 2) Build each harness twice: libFuzzer (-> $OUT/<fuzzer>) + standalone reproducer ─────────────
# Link order matters: libhogweed (rsa/dsa/asn1/sexp parsers) depends on libnettle, which depends on
# GMP. Keep hogweed before nettle before -lgmp.
FUZZERS="
fuzz_rsa_public_key_from_der
fuzz_rsa_keypair_from_der
fuzz_rsa_keypair_from_sexp
fuzz_dsa_openssl_private_key_from_der
fuzz_dsa_sha1_keypair_from_sexp
fuzz_dsa_sha256_keypair_from_sexp
fuzz_dsa_signature_from_sexp
"

for harness in $FUZZERS; do
  src="$HARNESS_DIR/$harness.c"
  [ -f "$src" ] || { echo "ERROR: harness source $src missing" >&2; exit 1; }

  # libFuzzer target
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $INC \
      "$src" $LIB_FUZZING_ENGINE \
      "$LIBHOGWEED" "$LIBNETTLE" -lgmp \
      -o "$OUT/$harness"

  # standalone reproducer (canonical LLVM StandaloneFuzzTargetMain, no libFuzzer runtime)
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $COV $INC \
      "$src" "$STANDALONE_FUZZ_MAIN" \
      "$LIBHOGWEED" "$LIBNETTLE" -lgmp \
      -o "$OUT/$harness-standalone"

  echo "built $harness (+ standalone)"
done

echo "build.sh complete:"
for harness in $FUZZERS; do ls -la "$OUT/$harness" "$OUT/$harness-standalone" 2>&1 || true; done
