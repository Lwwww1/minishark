/*
 * test_ip_reasm.c — IP 分片重组测试
 *
 * 编译：gcc -Wall -Wextra -O2 -g -I../include test_ip_reasm.c ../src/ip_reasm.c ../src/tcp_reasm.c -o test_ip_reasm
 * 运行：./test_ip_reasm
 */

#include "ip_reasm.h"
#include "common.h"
#include "protocol.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================================
 *  测试基础设施
 * ============================================================ */

static int tests_passed = 0;
static int tests_failed = 0;
static int current_test = 0;

/* #define VERBOSE */

static void test_begin(const char *name)
{
    current_test++;
#ifdef VERBOSE
    printf("\n--- [Test %d] %s ---\n", current_test, name);
#else
    (void)name;
#endif
}

static void test_end(int result, const char *name)
{
    if (result == 0) {
        tests_passed++;
#ifdef VERBOSE
        printf("  PASS: %s\n", name);
#endif
    } else {
        tests_failed++;
#ifdef VERBOSE
        printf("  FAIL: %s (expected 0, got %d)\n", name, result);
#endif
    }
}

static void test_end_nonzero(int result, const char *name)
{
    if (result != 0) {
        tests_passed++;
#ifdef VERBOSE
        printf("  PASS: %s (=%d)\n", name, result);
#endif
    } else {
        tests_failed++;
        printf("  FAIL: %s (expected non-zero, got 0)\n", name);
    }
}

static void test_end_int_eq(int got, int expected, const char *name)
{
    if (got == expected) {
        tests_passed++;
#ifdef VERBOSE
        printf("  PASS: %s (=%d)\n", name, got);
#endif
    } else {
        tests_failed++;
        printf("  FAIL: %s (expected %d, got %d)\n", name, expected, got);
    }
}

static void capture_output(void)
{
#ifndef VERBOSE
    freopen("/dev/null", "w", stdout);
    freopen("/dev/null", "w", stderr);
#endif
}

static void restore_output(void)
{
#ifndef VERBOSE
    freopen("CON", "w", stdout);
    freopen("CON", "w", stderr);
#endif
}

/* ============================================================
 *  Helper: 构造 IPv4 分片
 *
 * 构建一个分片的以太网+IPv4 帧。
 * pkt_offset 和 pkt_data_len 以字节为单位。
 * mf=0 表示最后一片, mf=1 表示还有后续。
 *
 * 返回缓冲区长度。
 * ============================================================ */

#define MAX_FRAME 1514

static size_t build_ipv4_frag(uint8_t *buf, uint16_t ident,
                               uint32_t src_ip, uint32_t dst_ip,
                               uint16_t data_offset,    /* 分片在原始数据中的偏移 */
                               uint16_t pkt_data_len,   /* 本分片中的数据长度 */
                               uint8_t mf,              /* More Fragments flag */
                               const uint8_t *payload)  /* 原始未分片数据 */
{
    size_t off = 0;

    /* 以太网头 */
    memset(buf, 0, ETH_HDR_LEN);
    buf[12] = 0x08; buf[13] = 0x00;  /* ETH_TYPE_IPV4 */
    off += ETH_HDR_LEN;

    /* IPv4 头 (20 bytes, no options) */
    memset(buf + off, 0, 20);
    buf[off] = 0x45;                              /* ver=4, ihl=5 */
    uint16_t total_len = 20 + pkt_data_len;
    buf[off+2] = (total_len >> 8) & 0xFF;
    buf[off+3] = total_len & 0xFF;
    buf[off+4] = (ident >> 8) & 0xFF;             /* ident hi */
    buf[off+5] = ident & 0xFF;                    /* ident lo */
    /* frag_off: flags (3 bits) + offset (13 bits, 8-byte units) */
    uint16_t frag_val = (data_offset / 8) & 0x1FFF;
    if (mf) frag_val |= 0x2000;                   /* MF bit */
    buf[off+6] = (frag_val >> 8) & 0xFF;
    buf[off+7] = frag_val & 0xFF;
    buf[off+8] = 64;                              /* TTL */
    buf[off+9] = IP_PROTO_TCP;                     /* protocol */
    /* src */
    memcpy(buf + off + 12, &src_ip, 4);
    /* dst */
    memcpy(buf + off + 16, &dst_ip, 4);
    /* 校验和 (简单计算) */
    uint32_t sum = 0;
    for (int i = 0; i < 20; i += 2) {
        uint16_t w;
        memcpy(&w, buf + off + i, 2);
        sum += ntohs(w);
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    uint16_t cksum = ~sum & 0xFFFF;
    buf[off+10] = (cksum >> 8) & 0xFF;
    buf[off+11] = cksum & 0xFF;
    off += 20;

    /* 分片数据 */
    if (payload != NULL && pkt_data_len > 0) {
        memcpy(buf + off, payload + data_offset, pkt_data_len);
        off += pkt_data_len;
    }

    return off;
}

/* ============================================================
 *  测试用例
 * ============================================================ */

static void test_init_destroy(void)
{
    test_begin("ip_reasm_init/destroy: lifecycle");
    capture_output();
    ip_reasm_init();
    test_end_int_eq(ip_reasm_stream_count(), 0, "init, stream count=0");
    ip_reasm_destroy();
    restore_output();
}

static void test_non_frag_passthrough(void)
{
    test_begin("ip_reasm_insert: non-frag returns 0");
    uint8_t buf[MAX_FRAME];
    /* 构建一个非分片的 IPv4 TCP 包 (MF=0, offset=0) */
    size_t len = build_ipv4_frag(buf, 1, 0xC0A80001, 0xC0A80002,
                                  0, 20, 0, NULL);
    uint8_t *out_buf = NULL;
    uint16_t out_len = 0;

    capture_output();
    ip_reasm_init();
    int r = ip_reasm_insert(buf, len, &out_buf, &out_len);
    test_end_int_eq(r, 0, "non-frag returns 0");
    test_end_null(out_buf, "out_buf is NULL");
    ip_reasm_destroy();
    restore_output();
}

static void test_single_frag(void)
{
    test_begin("ip_reasm_insert: single MF frag not complete");
    uint8_t buf[MAX_FRAME];
    uint8_t data[100] = "HelloIPFragmentationReassembly";

    /* 第一个分片: offset=0, MF=1, 40 bytes */
    size_t len = build_ipv4_frag(buf, 1234, 0xC0A80001, 0xC0A80002,
                                  0, 40, 1, data);
    uint8_t *out_buf = NULL;
    uint16_t out_len = 0;

    capture_output();
    ip_reasm_init();
    int r = ip_reasm_insert(buf, len, &out_buf, &out_len);
    test_end_int_eq(r, 0, "single MF frag, not complete");
    test_end_null(out_buf, "out_buf is NULL");
    test_end_int_eq(ip_reasm_stream_count(), 1, "1 frag stream active");
    ip_reasm_destroy();
    restore_output();
}

static void test_two_frags_reassemble(void)
{
    test_begin("ip_reasm_insert: two fragments reassemble");
    uint8_t buf[MAX_FRAME];
    /* 原始数据: 60 bytes */
    uint8_t data[60];
    memset(data, 'A', 60);
    memcpy(data, "IPFRAGTEST", 10);
    memset(data + 10, 'B', 50);

    uint8_t *out_buf = NULL;
    uint16_t out_len = 0;

    capture_output();
    ip_reasm_init();

    /* 分片 1: offset=0, data=40 bytes, MF=1 */
    size_t len1 = build_ipv4_frag(buf, 5678, 0xC0A80001, 0xC0A80002,
                                   0, 40, 1, data);
    int r1 = ip_reasm_insert(buf, len1, &out_buf, &out_len);
    test_end_int_eq(r1, 0, "frag1 inserted (not complete)");

    /* 分片 2: offset=40, data=20 bytes, MF=0 */
    size_t len2 = build_ipv4_frag(buf, 5678, 0xC0A80001, 0xC0A80002,
                                   40, 20, 0, data);
    int r2 = ip_reasm_insert(buf, len2, &out_buf, &out_len);
    test_end_int_eq(r2, 1, "frag2 completes reassembly");
    test_end_nonzero(out_buf, "reassembled buffer returned");
    test_end_int_eq(ip_reasm_stream_count(), 0, "stream cleaned up after reassembly");

    if (out_buf) {
        test_end_int_eq(out_len, 20 + 60, "total length = IP header(20) + data(60)");
        /* 验证数据内容: offset 0 should be "IPFRAGTEST" */
        if (out_len > 20 + 10) {
            test_end(memcmp(out_buf + 20, "IPFRAGTEST", 10), "data prefix: IPFRAGTEST");
        }
        free(out_buf);
    }

    ip_reasm_destroy();
    restore_output();
}

static void test_frag_dup_discard(void)
{
    test_begin("ip_reasm_insert: duplicate frag discarded");
    uint8_t buf[MAX_FRAME];
    uint8_t data[40];
    memset(data, 'X', 40);

    uint8_t *out_buf = NULL;
    uint16_t out_len = 0;

    capture_output();
    ip_reasm_init();

    /* 分片 1: offset=0, 20 bytes, MF=1 */
    size_t len1 = build_ipv4_frag(buf, 9999, 0xC0A80001, 0xC0A80002,
                                   0, 20, 1, data);
    ip_reasm_insert(buf, len1, &out_buf, &out_len);

    /* 重复相同的分片 */
    int r = ip_reasm_insert(buf, len1, &out_buf, &out_len);
    test_end_int_eq(r, 0, "duplicate frag returns 0 (no error)");

    test_end_int_eq(ip_reasm_frag_count(), 1, "only 1 frag stored (dup discarded)");

    ip_reasm_destroy();
    restore_output();
}

static void test_many_frags(void)
{
    test_begin("ip_reasm_insert: 4 fragments reassembly");
    uint8_t buf[MAX_FRAME];
    uint8_t data[200];
    for (int i = 0; i < 200; i++)
        data[i] = (uint8_t)(i & 0xFF);

    uint8_t *out_buf = NULL;
    uint16_t out_len = 0;

    capture_output();
    ip_reasm_init();

    /* 插入 4 个分片: 每个 40 bytes (+ offset: 0, 40, 80, 120) */
    /* 打乱顺序插入 */
    int offsets[] = {80, 0, 120, 40};
    for (int i = 0; i < 4; i++) {
        int off = offsets[i];
        uint8_t mf = (off + 40 >= 200) ? 0 : 1;
        size_t len = build_ipv4_frag(buf, 4321, 0xC0A80001, 0xC0A80002,
                                     (uint16_t)off, 40, mf, data);
        int r = ip_reasm_insert(buf, len, &out_buf, &out_len);
        if (i < 3) {
            test_end_int_eq(r, 0, "frag %d inserted (pending)", i+1);
        } else {
            test_end_int_eq(r, 1, "frag %d completes reassembly", i+1);
        }
    }

    if (out_buf) {
        /* Verify: 20 (IP hdr) + 160 (data) = 180 */
        test_end_int_eq(out_len, 180, "reassembled length = 180");
        /* Check a few bytes in the data portion */
        if (out_len > 20 + 50) {
            test_end(memcmp(out_buf + 20, data, 160), "all 160 data bytes match");
        }
        free(out_buf);
    }

    ip_reasm_destroy();
    restore_output();
}

static void test_cleanup_timeout(void)
{
    test_begin("ip_reasm_cleanup: timeout removes old streams");
    uint8_t buf[MAX_FRAME];
    uint8_t data[10];

    capture_output();
    ip_reasm_init();

    /* 插入一个不完整的分片流 */
    size_t len = build_ipv4_frag(buf, 1111, 0xC0A80001, 0xC0A80002,
                                  0, 20, 1, data);
    uint8_t *out_buf = NULL;
    uint16_t out_len = 0;
    ip_reasm_insert(buf, len, &out_buf, &out_len);

    test_end_int_eq(ip_reasm_stream_count(), 1, "1 stream active");

    /* 清理超时（即使不超时，cleanup 也应能安全运行） */
    int cleaned = ip_reasm_cleanup();
    test_end_int_eq(cleaned, 0, "no timed-out streams cleaned (just inserted)");

    ip_reasm_destroy();
    restore_output();
}

/* ============================================================
 *  主测试入口
 * ============================================================ */

int main(void)
{
    printf("============================================\n");
    printf("  minishark — IP Fragment Reassembly Test\n");
    printf("============================================\n\n");

    printf("--- Lifecycle ---\n");
    test_init_destroy();
    printf("\n");

    printf("--- Basic Insert ---\n");
    test_non_frag_passthrough();
    test_single_frag();
    printf("\n");

    printf("--- Reassembly ---\n");
    test_two_frags_reassemble();
    test_many_frags();
    printf("\n");

    printf("--- Edge Cases ---\n");
    test_frag_dup_discard();
    test_cleanup_timeout();
    printf("\n");

    printf("============================================\n");
    printf("  Results: %d passed, %d failed out of %d\n",
           tests_passed, tests_failed, current_test);
    printf("============================================\n");

    return tests_failed > 0 ? 1 : 0;
}
