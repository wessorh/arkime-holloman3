/* test_http_holloman3.c — integration test for Arkime http.c holloman3 path.
 *
 * Simulates the HTTP body buffering → holloman3 fingerprint → hex encoding
 * flow that http.c uses.  No Arkime headers required — only libholloman3.
 *
 * NOTE: libholloman3 requires buffers >= 256 bytes for a valid fingerprint.
 * Buffers smaller than 256 bytes return -3 (too small).  All positive
 * tests below use bodies of at least 256 bytes.
 *
 * Compile: cc -I../../libholloman3/include -o test_http_holloman3 \
 *              test_http_holloman3.c -L../../libholloman3 -lholloman3 -lm
 *
 * Run:     LD_LIBRARY_PATH=../../libholloman3 ./test_http_holloman3
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>

#include "holloman3.h"

/* ── Minimal GByteArray stand-in ──────────────────────────────────────── */

typedef struct {
    uint8_t *data;
    size_t    len;
    size_t    cap;
} ByteBuf;

static ByteBuf *byte_buf_new(void) {
    ByteBuf *b = calloc(1, sizeof(ByteBuf));
    b->cap = 512;
    b->data = malloc(b->cap);
    return b;
}

static void byte_buf_append(ByteBuf *b, const uint8_t *src, size_t n) {
    if (b->len + n > b->cap) {
        while (b->len + n > b->cap) b->cap *= 2;
        b->data = realloc(b->data, b->cap);
    }
    memcpy(b->data + b->len, src, n);
    b->len += n;
}

static void byte_buf_reset(ByteBuf *b) { b->len = 0; }
static void byte_buf_free(ByteBuf *b) { free(b->data); free(b); }

/* ── test helpers ───────────────────────────────────────────────────── */

static int tests_run  = 0;
static int tests_pass = 0;
static int tests_fail = 0;

#define TEST(name) do { tests_run++; printf("  %-55s", name); } while (0)
#define PASS()      do { tests_pass++; printf("PASS\n");       } while (0)
#define FAIL(...)   do { tests_fail++; printf("FAIL: ");       \
                          printf(__VA_ARGS__); printf("\n");     \
                          return; } while (0)
#define CHECK(c, ...) do { if (!(c)) { FAIL(__VA_ARGS__); } } while (0)

/* ── Configuration simulation ───────────────────────────────────────── */

static int support_holloman3 = 1;
static int max_body_len     = 1024 * 1024;  /* 1 MB */

/* ── Body generator: fills a buffer with >= 256 bytes of content ─────── */

static void make_body(uint8_t *buf, size_t n, uint8_t seed) {
    for (size_t i = 0; i < n; i++)
        buf[i] = (uint8_t)(seed + i * 7);
}

/* ── Simulate http.c body buffering and fingerprinting flow ──────────── */

static int process_http_body(const char *desc __attribute__((unused)),
                              const uint8_t **chunks, const size_t *chunk_lens,
                              int nchunks,
                              uint8_t fp_out[16]) {
    ByteBuf *buf = byte_buf_new();
    if (!buf) return -1;

    int fp_done = 0;

    /* Phase 1: receive body chunks */
    for (int i = 0; i < nchunks; i++) {
        size_t len = chunk_lens[i];
        if (support_holloman3 && buf->len < (size_t)max_body_len) {
            size_t room = max_body_len - buf->len;
            byte_buf_append(buf, chunks[i], len < room ? len : room);
        }
    }

    /* Phase 2: body complete — fingerprint */
    if (support_holloman3 && buf->len > 0) {
        uint8_t fp[16];
        int ret = holloman3_fingerprint_buffer(buf->data, buf->len, fp);
        if (ret == 0) {
            memcpy(fp_out, fp, 16);
            fp_done = 1;
        }
        byte_buf_reset(buf);
    }

    byte_buf_free(buf);
    return fp_done ? 0 : -1;
}

/* ── Tests ───────────────────────────────────────────────────────────── */

static void test_single_chunk(void) {
    TEST("single chunk: deterministic fingerprint (300 bytes)");
    uint8_t body[300];
    make_body(body, 300, 1);
    const uint8_t *body_ptr = body;
    size_t len = 300;
    uint8_t fp1[16], fp2[16];

    CHECK(process_http_body("single-1", &body_ptr, &len, 1, fp1) == 0,
          "first call failed");
    CHECK(process_http_body("single-2", &body_ptr, &len, 1, fp2) == 0,
          "second call failed");
    CHECK(memcmp(fp1, fp2, 16) == 0,
          "non-deterministic (single chunk)");
    PASS();
}

static void test_multi_chunk(void) {
    TEST("multi-chunk: same as single chunk fingerprint");

    /* Single chunk of the full body */
    uint8_t full[512];
    make_body(full, 512, 5);
    size_t full_len = 512;
    const uint8_t *full_ptr = full;
    uint8_t fp_full[16];
    CHECK(process_http_body("full", &full_ptr, &full_len, 1, fp_full) == 0,
          "full fingerprint failed");

    /* Same body split into 3 chunks */
    const uint8_t *c1 = full;
    const uint8_t *c2 = full + 200;
    const uint8_t *c3 = full + 400;
    size_t l1 = 200, l2 = 200, l3 = 112;
    const uint8_t *chunks[3] = {c1, c2, c3};
    size_t lens[3] = {l1, l2, l3};
    uint8_t fp_chunked[16];
    CHECK(process_http_body("chunked", chunks, lens, 3, fp_chunked) == 0,
          "chunked fingerprint failed");

    CHECK(memcmp(fp_full, fp_chunked, 16) == 0,
          "single-chunk ≠ multi-chunk");
    PASS();
}

static void test_empty_body(void) {
    TEST("empty body: no fingerprint, returns -1");
    const uint8_t *body = (const uint8_t *)"";
    size_t len = 0;
    uint8_t fp[16] = {0xFF};
    CHECK(process_http_body("empty", &body, &len, 1, fp) == -1,
          "empty body should return -1");
    PASS();
}

static void test_config_disabled(void) {
    TEST("config: support disabled skips fingerprinting");
    support_holloman3 = 0;
    uint8_t body[300];
    make_body(body, 300, 9);
    const uint8_t *body_ptr = body;
    size_t len = 300;
    uint8_t fp[16];
    CHECK(process_http_body("disabled", &body_ptr, &len, 1, fp) == -1,
          "should return -1 when disabled");
    support_holloman3 = 1;  /* re-enable */
    PASS();
}

static void test_body_over_max(void) {
    TEST("config: body truncated at max_body_len");
    int saved_max = max_body_len;
    max_body_len = 300;  /* limit for testing */

    /* 512 bytes of body → only first 300 should be fingerprinted */
    uint8_t body[512];
    make_body(body, 512, 13);
    const uint8_t *body_ptr = body;
    size_t len = 512;
    uint8_t fp_short[16];
    CHECK(process_http_body("truncated", &body_ptr, &len, 1, fp_short) == 0,
          "truncated fingerprint failed");

    /* Now fingerprint only the first 300 bytes directly */
    uint8_t fp_direct[16];
    CHECK(holloman3_fingerprint_buffer(body, 300, fp_direct) == 0,
          "direct 300-byte fingerprint failed");
    CHECK(memcmp(fp_short, fp_direct, 16) == 0,
          "truncated body ≠ first N bytes");
    max_body_len = saved_max;
    PASS();
}

static void test_hex_encoding(void) {
    TEST("hex encoding: produces '<c>.<32 hex>' using holloman3_fingerprint_string");
    uint8_t body[300];
    make_body(body, 300, 21);
    const uint8_t *body_ptr = body;
    size_t len = 300;
    uint8_t fp[16];

    CHECK(process_http_body("hex", &body_ptr, &len, 1, fp) == 0,
          "fingerprint failed");

    /* Format using holloman3_fingerprint_string — the canonical encoding */
    char id[35];
    CHECK(holloman3_fingerprint_string(fp, id) == 0,
          "fingerprint_string failed");
    CHECK(strlen(id) == 34, "length should be 34, got %zu", strlen(id));

    /* The order char depends on buffer size (300 bytes → order 5 → 'f') */
    char expected_prefix = holloman3_order_char();
    CHECK(id[0] == expected_prefix, "first char should be '%c', got '%c'",
          expected_prefix, id[0]);
    CHECK(id[1] == '.', "second char should be '.'");

    /* All chars after "<c>." should be lowercase hex */
    int valid = 1;
    for (int i = 2; i < 34; i++) {
        if (!((id[i] >= '0' && id[i] <= '9') ||
              (id[i] >= 'a' && id[i] <= 'f'))) {
            valid = 0;
            break;
        }
    }
    CHECK(valid, "invalid hex characters in id");
    PASS();
}

static void test_concurrent_bodies(void) {
    TEST("concurrent: two bodies produce different fingerprints");

    uint8_t body1[300], body2[300];
    make_body(body1, 300, 1);
    make_body(body2, 300, 100);
    const uint8_t *p1 = body1, *p2 = body2;
    size_t len1 = 300, len2 = 300;
    uint8_t fp1[16], fp2[16];

    CHECK(process_http_body("body1", &p1, &len1, 1, fp1) == 0,
          "body1 failed");
    CHECK(process_http_body("body2", &p2, &len2, 1, fp2) == 0,
          "body2 failed");
    CHECK(memcmp(fp1, fp2, 16) != 0,
          "different bodies should not match");
    PASS();
}

static void test_determinism_across_inits(void) {
    TEST("determinism: survives cleanup + reinit");

    uint8_t body[300];
    make_body(body, 300, 33);
    const uint8_t *body_ptr = body;
    size_t len = 300;
    uint8_t fp1[16];

    CHECK(process_http_body("before", &body_ptr, &len, 1, fp1) == 0,
          "before cleanup failed");

    holloman3_cleanup();
    CHECK(holloman3_init(8) == 0, "reinit failed");

    uint8_t fp2[16];
    CHECK(process_http_body("after", &body_ptr, &len, 1, fp2) == 0,
          "after cleanup failed");
    CHECK(memcmp(fp1, fp2, 16) == 0,
          "fingerprint changed after cleanup/reinit");
    PASS();
}

/* ── main ────────────────────────────────────────────────────────────── */

int main(void) {
    /* Init once for all tests */
    if (holloman3_init(8) != 0) {
        fprintf(stderr, "holloman3_init failed\n");
        return 1;
    }
    printf("libholloman3 %s, avx2=%d\n",
           holloman3_version(), holloman3_has_avx2());

    printf("\n=== HTTP Body Buffering & Fingerprinting ===\n");
    test_single_chunk();
    test_multi_chunk();
    test_empty_body();
    test_config_disabled();
    test_body_over_max();
    test_hex_encoding();
    test_concurrent_bodies();
    test_determinism_across_inits();

    holloman3_cleanup();

    printf("\n---\n");
    printf("Tests: %d run, %d passed, %d failed\n",
           tests_run, tests_pass, tests_fail);
    return tests_fail > 0 ? 1 : 0;
}