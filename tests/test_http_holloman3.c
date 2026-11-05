/* test_http_holloman3.c — integration test for Arkime http.c holloman3 path.
 *
 * Simulates the HTTP body buffering → holloman3 fingerprint → hex encoding
 * flow that http.c uses.  No Arkime headers required — only libholloman3.
 *
 * Compile: cc -I../../libholloman3/include -o test_http_holloman3 \
 *              test_http_holloman3.c -L../../libholloman3 -lholloman3 -lm
 *
 * Run:     ./test_http_holloman3
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
    b->cap = 256;
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

/* ── Hex encoding (same logic as http.c + arkime_sprint_hex_string) ──── */

static void sprint_hex(char *out, const uint8_t *bin, int n) {
    for (int i = 0; i < n; i++)
        sprintf(out + i * 2, "%02x", bin[i]);
}

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
    TEST("single chunk: deterministic fingerprint");
    const uint8_t *body = (const uint8_t *)"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    size_t len = strlen((const char *)body);
    uint8_t fp1[16], fp2[16];

    CHECK(process_http_body("single-1", &body, &len, 1, fp1) == 0,
          "first call failed");
    CHECK(process_http_body("single-2", &body, &len, 1, fp2) == 0,
          "second call failed");
    CHECK(memcmp(fp1, fp2, 16) == 0,
          "non-deterministic (single chunk)");
    PASS();
}

static void test_multi_chunk(void) {
    TEST("multi-chunk: same as single chunk fingerprint");

    /* Single chunk of the full body */
    const char *full = "POST /api/data HTTP/1.1\r\nContent-Type: application/json\r\n\r\n"
                       "{\"key\":\"value\",\"items\":[1,2,3,4,5]}";
    size_t full_len = strlen(full);
    const uint8_t *full_ptr = (const uint8_t *)full;
    uint8_t fp_full[16];
    CHECK(process_http_body("full", &full_ptr, &full_len, 1, fp_full) == 0,
          "full fingerprint failed");

    /* Same body split into 3 chunks of different sizes */
    const uint8_t *c1 = (const uint8_t *)"POST /api/data HTT";
    const uint8_t *c2 = (const uint8_t *)"P/1.1\r\nContent-Type: application/json\r\n";
    const uint8_t *c3 = (const uint8_t *)"\r\n{\"key\":\"value\",\"items\":[1,2,3,4,5]}";
    const size_t l1 = strlen((const char *)c1);
    const size_t l2 = strlen((const char *)c2);
    const size_t l3 = strlen((const char *)c3);
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
    const uint8_t *body = (const uint8_t *)"some body data for testing";
    size_t len = strlen((const char *)body);
    uint8_t fp[16];
    CHECK(process_http_body("disabled", &body, &len, 1, fp) == -1,
          "should return -1 when disabled");
    support_holloman3 = 1;  /* re-enable */
    PASS();
}

static void test_body_over_max(void) {
    TEST("config: body truncated at max_body_len");
    int saved_max = max_body_len;
    max_body_len = 8;  /* tiny limit for testing */

    /* 16 bytes of body → only first 8 should be fingerprinted */
    const uint8_t *body = (const uint8_t *)"ABCDEFGHIJKLMNOP";
    size_t len = 16;
    uint8_t fp_short[16];
    CHECK(process_http_body("truncated", &body, &len, 1, fp_short) == 0,
          "truncated fingerprint failed");

    /* Now fingerprint only the first 8 bytes directly */
    uint8_t fp_direct[16];
    CHECK(holloman3_fingerprint_buffer(body, 8, fp_direct) == 0,
          "direct 8-byte fingerprint failed");
    CHECK(memcmp(fp_short, fp_direct, 16) == 0,
          "truncated body ≠ first N bytes");
    max_body_len = saved_max;
    PASS();
}

static void test_hex_encoding(void) {
    TEST("hex encoding: produces 'h.' + 32 lowercase hex");
    const uint8_t *body = (const uint8_t *)"Hello, World!";
    size_t len = strlen((const char *)body);
    uint8_t fp[16];
    uint8_t fp2[16];

    CHECK(process_http_body("hex", &body, &len, 1, fp) == 0,
          "fingerprint failed");
    CHECK(holloman3_fingerprint_buffer(body, len, fp2) == 0,
          "direct fingerprint failed");
    CHECK(memcmp(fp, fp2, 16) == 0,
          "http-emulated ≠ direct fingerprint");

    /* Encode as http.c does: "h." + 32 hex */
    char hex[35];
    hex[0] = 'h'; hex[1] = '.';
    sprint_hex(hex + 2, fp, 16);
    hex[34] = '\0';

    CHECK(strlen(hex) == 34, "hex length should be 34, got %zu", strlen(hex));
    CHECK(hex[0] == 'h', "first char should be 'h'");
    CHECK(hex[1] == '.', "second char should be '.'");

    /* All chars after "h." should be lowercase hex (0-9, a-f) */
    int valid = 1;
    for (int i = 2; i < 34; i++) {
        if (!((hex[i] >= '0' && hex[i] <= '9') ||
              (hex[i] >= 'a' && hex[i] <= 'f'))) {
            valid = 0;
            break;
        }
    }
    CHECK(valid, "invalid hex characters in fingerprint");
    PASS();
}

static void test_concurrent_bodies(void) {
    TEST("concurrent: two bodies produce different fingerprints");

    const uint8_t *body1 = (const uint8_t *)"AAAA";
    const uint8_t *body2 = (const uint8_t *)"BBBB";
    size_t len1 = 4, len2 = 4;
    uint8_t fp1[16], fp2[16];

    CHECK(process_http_body("body1", &body1, &len1, 1, fp1) == 0,
          "body1 failed");
    CHECK(process_http_body("body2", &body2, &len2, 1, fp2) == 0,
          "body2 failed");
    CHECK(memcmp(fp1, fp2, 16) != 0,
          "different bodies should not match");
    PASS();
}

static void test_determinism_across_inits(void) {
    TEST("determinism: survives cleanup + reinit");

    const uint8_t *body = (const uint8_t *)"test body";
    size_t len = strlen((const char *)body);
    uint8_t fp1[16];

    CHECK(process_http_body("before", &body, &len, 1, fp1) == 0,
          "before cleanup failed");

    holloman3_cleanup();
    CHECK(holloman3_init(8) == 0, "reinit failed");

    uint8_t fp2[16];
    CHECK(process_http_body("after", &body, &len, 1, fp2) == 0,
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