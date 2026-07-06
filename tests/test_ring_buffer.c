/*
 * test_ring_buffer.c — 环形缓冲区单元测试
 *
 * 编译: make test-ring
 * 运行: ./tests/test_ring_buffer
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include "common.h"
#include "ring_buffer.h"

static int g_failures = 0;
static int g_passed   = 0;

#define TEST(name)  printf("  [TEST] %-50s ", name)
#define PASS()      do { printf("PASS\n"); g_passed++; } while(0)
#define FAIL(msg)   do { printf("FAIL: %s\n", msg); g_failures++; } while(0)
#define ASSERT(cond, msg)  do { if (!(cond)) { FAIL(msg); return; } } while(0)

/* ── 测试 1: 基本 push/pop ── */
static void test_basic_push_pop(void)
{
    TEST("basic push/pop");
    ring_buffer_t *rb = rb_init(8);
    ASSERT(rb != NULL, "rb_init failed");

    struct pcap_pkthdr hdr_in = { .len = 100, .caplen = 100 };
    uint8_t data_in[100];
    memset(data_in, 0xAA, sizeof(data_in));

    rb_push(rb, &hdr_in, data_in);

    struct pcap_pkthdr hdr_out;
    uint8_t data_out[MAX_PKT_SIZE];
    uint32_t len_out;
    rb_pop_timeout(rb, &hdr_out, data_out, &len_out, 1000);

    ASSERT(hdr_out.len == 100,            "header.len mismatch");
    ASSERT(hdr_out.caplen == 100,         "header.caplen mismatch");
    ASSERT(len_out == 100,                 "data_len mismatch");
    ASSERT(memcmp(data_in, data_out, 100) == 0, "data mismatch");

    rb_destroy(rb);
    PASS();
}

/* ── 测试 2: FIFO 顺序 ── */
static void test_fifo_order(void)
{
    TEST("FIFO order (8 items)");
    ring_buffer_t *rb = rb_init(8);
    ASSERT(rb != NULL, "rb_init failed");

    for (int i = 0; i < 8; i++) {
        struct pcap_pkthdr hdr = { .len = (bpf_u_int32)(i + 1), .caplen = (bpf_u_int32)(i + 1) };
        uint8_t data[1] = { (uint8_t)i };
        rb_push(rb, &hdr, data);
    }

    for (int i = 0; i < 8; i++) {
        struct pcap_pkthdr hdr;
        uint8_t data[MAX_PKT_SIZE];
        uint32_t len;
        rb_pop_timeout(rb, &hdr, data, &len, 1000);

        ASSERT(hdr.len == (bpf_u_int32)(i + 1), "FIFO order broken (len)");
        ASSERT(data[0] == (uint8_t)i,       "FIFO order broken (data)");
    }

    rb_destroy(rb);
    PASS();
}

/* ── 测试 3: 超时 ── */
static void test_pop_timeout(void)
{
    TEST("pop timeout on empty buffer");
    ring_buffer_t *rb = rb_init(4);
    ASSERT(rb != NULL, "rb_init failed");

    struct pcap_pkthdr hdr;
    uint8_t data[MAX_PKT_SIZE];
    uint32_t len;
    int got = rb_pop_timeout(rb, &hdr, data, &len, 100); /* 100ms */

    ASSERT(got == 0, "expected timeout (got=0), but got data");

    rb_destroy(rb);
    PASS();
}

/* ── 测试 4: rb_count ── */
static void test_count(void)
{
    TEST("rb_count correctness");
    ring_buffer_t *rb = rb_init(8);
    ASSERT(rb != NULL, "rb_init failed");
    ASSERT(rb_count(rb) == 0, "initial count not 0");

    struct pcap_pkthdr hdr = {0};
    uint8_t data[1] = {0};

    rb_push(rb, &hdr, data);
    ASSERT(rb_count(rb) == 1, "count after 1 push != 1");

    rb_push(rb, &hdr, data);
    rb_push(rb, &hdr, data);
    ASSERT(rb_count(rb) == 3, "count after 3 pushes != 3");

    uint32_t len;
    rb_pop_timeout(rb, &hdr, data, &len, 1000);
    ASSERT(rb_count(rb) == 2, "count after 1 pop != 2");

    rb_destroy(rb);
    PASS();
}

/* ── 测试 5: 环绕 ── */
static void test_wraparound(void)
{
    TEST("wraparound (capacity=4, push 6)");
    ring_buffer_t *rb = rb_init(4);
    ASSERT(rb != NULL, "rb_init failed");

    /* push 3, pop 2, push 3: 触发环绕 (tail 回绕到 head 前面) */

    for (int i = 0; i < 3; i++) {
        struct pcap_pkthdr hdr = { .len = i, .caplen = i };
        uint8_t data[1] = { (uint8_t)i };
        rb_push(rb, &hdr, data);
    }

    for (int i = 0; i < 2; i++) {
        struct pcap_pkthdr hdr;
        uint8_t data[MAX_PKT_SIZE];
        uint32_t len;
        rb_pop_timeout(rb, &hdr, data, &len, 1000);
        ASSERT(hdr.len == (bpf_u_int32)i, "pre-wrap data mismatch");
    }

    for (int i = 3; i < 6; i++) {
        struct pcap_pkthdr hdr = { .len = i, .caplen = i };
        uint8_t data[1] = { (uint8_t)i };
        rb_push(rb, &hdr, data);
    }

    /* 此时应还有 1+3=4 个 */
    ASSERT(rb_count(rb) == 4, "count after wraparound != 4");

    for (int i = 2; i < 6; i++) {
        struct pcap_pkthdr hdr;
        uint8_t data[MAX_PKT_SIZE];
        uint32_t len;
        rb_pop_timeout(rb, &hdr, data, &len, 1000);
        ASSERT(hdr.len == (bpf_u_int32)i, "post-wrap data mismatch");
    }

    ASSERT(rb_count(rb) == 0, "final count != 0");

    rb_destroy(rb);
    PASS();
}

/* ── 测试 6: 大容量压测 ── */
static void test_large_volume(void)
{
    TEST("large volume (4096 items)");
    int cap = 4096;
    ring_buffer_t *rb = rb_init(cap);
    ASSERT(rb != NULL, "rb_init failed");

    /* 全量 push */
    for (int i = 0; i < cap; i++) {
        struct pcap_pkthdr hdr = { .len = i, .caplen = i };
        uint8_t data[1] = { (uint8_t)(i & 0xFF) };
        rb_push(rb, &hdr, data);
    }

    ASSERT(rb_count(rb) == cap, "count after full push != capacity");

    /* 全量 pop */
    for (int i = 0; i < cap; i++) {
        struct pcap_pkthdr hdr;
        uint8_t data[MAX_PKT_SIZE];
        uint32_t len;
        rb_pop_timeout(rb, &hdr, data, &len, 1000);
        ASSERT(hdr.len == (bpf_u_int32)i, "large volume mismatch");
    }

    ASSERT(rb_count(rb) == 0, "final count != 0");

    rb_destroy(rb);
    PASS();
}

/* ── 测试 7: NULL 参数防御 ── */
static void test_null_defense(void)
{
    TEST("NULL parameter defense");
    /* 这些调用都不该崩溃 */
    rb_push(NULL, NULL, NULL);
    rb_pop_timeout(NULL, NULL, NULL, NULL, 0);
    ASSERT(rb_count(NULL) == 0, "rb_count(NULL) != 0");

    ring_buffer_t *rb = rb_init(4);
    rb_push(rb, NULL, NULL);   /* 静默忽略 */
    rb_destroy(rb);
    rb_destroy(NULL);           /* 静默忽略 */

    PASS();
}

/* ================================================================
 *  main
 * ================================================================ */

int main(void)
{
    printf("\n=== Ring Buffer Unit Tests ===\n\n");

    test_basic_push_pop();
    test_fifo_order();
    test_pop_timeout();
    test_count();
    test_wraparound();
    test_large_volume();
    test_null_defense();

    printf("\n=== Results: %d passed, %d failed ===\n\n", g_passed, g_failures);
    return g_failures > 0 ? 1 : 0;
}
