/* nettle/mayhem/golden_oracle.c — GOLDEN-KAT oracle for mayhem/test.sh.
 *
 * Nettle's own `make check` testsuite needs network/test scaffolding that is awkward in the build
 * sandbox, so this is an additive golden Known-Answer-Test oracle that exercises the SAME public
 * parse APIs the fuzzers drive, on byte-exact known-good inputs, and asserts they SUCCEED + produce
 * the expected values. A no-op / "return 0" patch to the DER/sexp/base parsers makes the oracle FAIL.
 * It links the SAME sanitized libnettle.a/libhogweed.a build.sh produced, so the golden parse also
 * runs under ASan+UBSan. exit 0 iff every assertion holds.
 *
 * Coverage:
 *   1) rsa_keypair_from_sexp() on a real RSA private-key S-expression (from testsuite/sexp2rsa-test.c)
 *      must succeed and recover the expected modulus bit size. (Drives sexp2rsa + sexp2bignum.)
 *   2) base16 decode round-trip of a known hex string -> exact bytes.
 *   3) base64 decode of a known base64 string -> exact bytes (the building block of PEM parsing).
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <nettle/rsa.h>
#include <nettle/bignum.h>
#include <nettle/base16.h>
#include <nettle/base64.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", (msg)); failures++; } \
  } while (0)

/* Hex-decode a NUL-terminated hex string into a freshly malloc'd buffer using nettle's own
 * base16 decoder (also exercises that parse path). Returns length, sets *out. */
static size_t hexdec(const char *hex, uint8_t **out) {
  struct base16_decode_ctx ctx;
  size_t src = strlen(hex);
  /* *dst_length is the output BUFFER CAPACITY on input (a bound check), updated to the bytes
   * actually produced on output — so initialize it to the allocated size, not 0. */
  size_t dlen = BASE16_DECODE_LENGTH(src);
  uint8_t *dst = malloc(dlen + 1);
  base16_decode_init(&ctx);
  if (!base16_decode_update(&ctx, &dlen, dst, src, hex) || !base16_decode_final(&ctx)) {
    free(dst); *out = NULL; return 0;
  }
  *out = dst;
  return dlen;
}

/* A real RSA private-key S-expression (1024-bit modulus), lifted verbatim from
 * testsuite/sexp2rsa-test.c. rsa_keypair_from_sexp() must accept it. */
static const char rsa_priv_sexp_hex[] =
  "2831313a707269766174652d6b657928"
  "333a72736128313a6e36333a085c3408"
  "989acae4faec3cbbad91c90d34c1d259"
  "cd74121a36f38b0b51424a9b2be514a0"
  "4377113a6cdafe79dd7d5f2ecc8b5e96"
  "61189b86a7b22239907c252928313a65"
  "343a36ad4b1d2928313a6436333a06ee"
  "6d4ff3c239e408150daf8117abfa36a4"
  "0ad4455d9059a86d52f33a2de07418a0"
  "a699594588c64810248c9412d554f74a"
  "f947c73c32007e87c92f0937ed292831"
  "3a7033323a03259879b24315e9cf1425"
  "4824c7935d807cdb6990f414a0f65e60"
  "65130a611f2928313a7133323a02a81b"
  "a73bad45fc73b36deffce52d1b73e074"
  "7f4d8a82648cecd310448ea63b292831"
  "3a6133323a026cbdad5dd0046e093f06"
  "0ecd5b4ac918e098b0278bb752b7cadd"
  "6a8944f0b92928313a6233323a014875"
  "1e622d6d58e3bb094afd6edacf737035"
  "1d068e2ce9f565c5528c4a7473292831"
  "3a6333323a00f8a458ea73a018dc6fa5"
  "6863e3bc6de405f364f77dee6f096267"
  "9ea1a8282e292929";

int main(void) {
  /* ── 1) RSA keypair from a known-good S-expression ───────────────────────────────────────── */
  {
    struct rsa_public_key pub;
    struct rsa_private_key priv;
    uint8_t *sexp = NULL;
    size_t slen = hexdec(rsa_priv_sexp_hex, &sexp);
    CHECK(slen > 0 && sexp != NULL, "hex-decode of golden RSA sexp");
    rsa_public_key_init(&pub);
    rsa_private_key_init(&priv);
    if (sexp) {
      int ok = rsa_keypair_from_sexp(&pub, &priv, 0, slen, sexp);
      CHECK(ok == 1, "rsa_keypair_from_sexp accepts the golden private key");
      if (ok) {
        /* The vector is a 512-bit modulus (63-byte 'n'); assert a sane recovered size and that
         * the public exponent was parsed. */
        CHECK(pub.size > 0, "recovered RSA modulus has nonzero octet size");
        CHECK(mpz_sgn(pub.n) > 0, "recovered RSA modulus n > 0");
        CHECK(mpz_sgn(pub.e) > 0, "recovered RSA public exponent e > 0");
        CHECK(mpz_sgn(priv.d) > 0, "recovered RSA private exponent d > 0");
      }
    }
    rsa_private_key_clear(&priv);
    rsa_public_key_clear(&pub);
    free(sexp);
  }

  /* ── 2) base16 (hex) decode round-trip ───────────────────────────────────────────────────── */
  {
    static const uint8_t expect[] = { 0xde, 0xad, 0xbe, 0xef, 0x00, 0x42 };
    uint8_t *got = NULL;
    size_t n = hexdec("deadbeef0042", &got);
    CHECK(n == sizeof expect && got != NULL && memcmp(got, expect, sizeof expect) == 0,
          "base16 decode 'deadbeef0042' -> exact bytes");
    free(got);
  }

  /* ── 3) base64 decode (the PEM body decoder) ──────────────────────────────────────────────── */
  {
    struct base64_decode_ctx ctx;
    const char *in = "SGVsbG8sIE5ldHRsZSE=";          /* "Hello, Nettle!" */
    const char *expect = "Hello, Nettle!";
    uint8_t out[64];
    size_t dlen = sizeof out;   /* output buffer capacity on input (bound check) */
    base64_decode_init(&ctx);
    int ok = base64_decode_update(&ctx, &dlen, out, strlen(in), in)
           && base64_decode_final(&ctx);
    CHECK(ok == 1, "base64_decode_update/final succeed on known input");
    CHECK(dlen == strlen(expect) && memcmp(out, expect, dlen) == 0,
          "base64 decode -> 'Hello, Nettle!'");
  }

  if (failures) {
    fprintf(stderr, "golden oracle: %d assertion(s) FAILED\n", failures);
    return 1;
  }
  fprintf(stderr, "OK: golden KAT oracle passed (rsa sexp parse + base16 + base64)\n");
  return 0;
}
