/*
 * test_tcp_reasm.c — TCP 流重组框架全面测试
 *
 * 手工构造 IP+TCP 包缓冲区，测试五元组哈希表、按 SEQ 排序插入、
 * 状态机（SYN → ESTABLISHED → FIN）。
 *
 * 编译：gcc -Wall -Wextra -O2 -g -I../include test_tcp_reasm.c ../src/tcp_reasm.c -o test_tcp_reasm
 * 运行：./test_tcp_reasm
 */

#include "tcp_reasm.h"
#include "common.h"
#include "protocol.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================================
 *  测试基础设施（与 test_protocol.c 一致）
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
#else
        (void)name;
#endif
    }
}

static void test_end_neg(int result, const char *name)
{
    if (result == -1) {
        tests_passed++;
#ifdef VERBOSE
        printf("  PASS: %s (got -1 as expected)\n", name);
#endif
    } else {
        tests_failed++;
        printf("  FAIL: %s (expected -1, got %d)\n", name, result);
    }
}

static void test_end_nonnull(void *ptr, const char *name)
{
    if (ptr != NULL) {
        tests_passed++;
#ifdef VERBOSE
        printf("  PASS: %s (non-NULL)\n", name);
#endif
    } else {
        tests_failed++;
        printf("  FAIL: %s (unexpected NULL)\n", name);
    }
}

static void test_end_null(void *ptr, const char *name)
{
    if (ptr == NULL) {
        tests_passed++;
#ifdef VERBOSE
        printf("  PASS: %s (NULL as expected)\n", name);
#endif
    } else {
        tests_failed++;
        printf("  FAIL: %s (expected NULL)\n", name);
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
 *  Helper：构造各类以太网+IP+TCP 包
 *
 *  使用与 test_protocol.c 一致的构建函数风格。
 * ============================================================ */

#define PKT_BUF_SIZE 1514

/* 构建以太网头 */
static void build_eth(uint8_t *buf, uint16_t ethertype)
{
    memset(buf, 0, ETH_HDR_LEN);
    buf[12] = (ethertype >> 8) & 0xFF;
    buf[13] = ethertype & 0xFF;
}

/* 构建 IPv4 头（最小 20 字节），返回 IP 头长度 */
static size_t build_ipv4(uint8_t *buf, uint8_t ihl_words, uint16_t total_len,
                          uint8_t proto, uint32_t src, uint32_t dst)
{
    memset(buf, 0, 60);
    buf[0] = 0x40 | (ihl_words & 0x0F);
    buf[2] = (total_len >> 8) & 0xFF;
    buf[3] = total_len & 0xFF;
    buf[8] = 64;            /* TTL */
    buf[9] = proto;
    memcpy(buf + 12, &src, 4);
    memcpy(buf + 16, &dst, 4);
    return (size_t)ihl_words * 4;
}

/* 构建 TCP 头，返回 TCP 头长度 */
static size_t build_tcp(uint8_t *buf, uint8_t data_off_words,
                         uint16_t src_port, uint16_t dst_port,
                         uint32_t seq, uint32_t ack, uint8_t flags)
{
    memset(buf, 0, 60);
    buf[0] = (src_port >> 8) & 0xFF;
    buf[1] = src_port & 0xFF;
    buf[2] = (dst_port >> 8) & 0xFF;
    buf[3] = dst_port & 0xFF;
    buf[12] = (data_off_words << 4) & 0xF0;
    buf[13] = flags;
    /* SEQ */
    buf[4] = (seq >> 24) & 0xFF;
    buf[5] = (seq >> 16) & 0xFF;
    buf[6] = (seq >> 8) & 0xFF;
    buf[7] = seq & 0xFF;
    /* ACK */
    buf[8] = (ack >> 24) & 0xFF;
    buf[9] = (ack >> 16) & 0xFF;
    buf[10] = (ack >> 8) & 0xFF;
    buf[11] = ack & 0xFF;
    return (size_t)data_off_words * 4;
}

/*
 * build_syn_pkt — 构造一个 SYN 包（以太网+IPv4+TCP SYN）
 *
 * pkt    — 输出缓冲区
 * pktlen — [输出] 包总长度
 *
 * 参数:
 *   payload     — TCP 载荷数据（可为 NULL）
 *   payload_len — 载荷长度
 */
static void build_syn_pkt(uint8_t *pkt, size_t *pktlen,
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           uint32_t seq,
                           const uint8_t *payload, uint16_t payload_len)
{
    size_t off = 0;

    build_eth(pkt + off, ETH_TYPE_IPV4);
    off += ETH_HDR_LEN;

    size_t ip_tot = 20 + 20 + payload_len;  /* IP头 + TCP头 + 载荷 */
    size_t ip_hdr_len = build_ipv4(pkt + off, 5, (uint16_t)ip_tot,
                                    IP_PROTO_TCP, src_ip, dst_ip);
    off += ip_hdr_len;

    size_t tcp_hdr_len = build_tcp(pkt + off, 5, src_port, dst_port,
                                    seq, 0, TCP_FLAG_SYN);
    off += tcp_hdr_len;

    if (payload != NULL && payload_len > 0) {
        memcpy(pkt + off, payload, payload_len);
        off += payload_len;
    }

    *pktlen = off;
}

static void build_synack_pkt(uint8_t *pkt, size_t *pktlen,
                              uint32_t src_ip, uint32_t dst_ip,
                              uint16_t src_port, uint16_t dst_port,
                              uint32_t seq, uint32_t ack,
                              const uint8_t *payload, uint16_t payload_len)
{
    size_t off = 0;

    build_eth(pkt + off, ETH_TYPE_IPV4);
    off += ETH_HDR_LEN;

    size_t ip_tot = 20 + 20 + payload_len;
    size_t ip_hdr_len = build_ipv4(pkt + off, 5, (uint16_t)ip_tot,
                                    IP_PROTO_TCP, src_ip, dst_ip);
    off += ip_hdr_len;

    size_t tcp_hdr_len = build_tcp(pkt + off, 5, src_port, dst_port,
                                    seq, ack, TCP_FLAG_SYN | TCP_FLAG_ACK);
    off += tcp_hdr_len;

    if (payload != NULL && payload_len > 0) {
        memcpy(pkt + off, payload, payload_len);
        off += payload_len;
    }

    *pktlen = off;
}

static void build_ack_pkt(uint8_t *pkt, size_t *pktlen,
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           uint32_t seq, uint32_t ack,
                           const uint8_t *payload, uint16_t payload_len)
{
    size_t off = 0;

    build_eth(pkt + off, ETH_TYPE_IPV4);
    off += ETH_HDR_LEN;

    size_t ip_tot = 20 + 20 + payload_len;
    size_t ip_hdr_len = build_ipv4(pkt + off, 5, (uint16_t)ip_tot,
                                    IP_PROTO_TCP, src_ip, dst_ip);
    off += ip_hdr_len;

    size_t tcp_hdr_len = build_tcp(pkt + off, 5, src_port, dst_port,
                                    seq, ack, TCP_FLAG_ACK);
    off += tcp_hdr_len;

    if (payload != NULL && payload_len > 0) {
        memcpy(pkt + off, payload, payload_len);
        off += payload_len;
    }

    *pktlen = off;
}

static void build_fin_pkt(uint8_t *pkt, size_t *pktlen,
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port,
                           uint32_t seq, uint32_t ack,
                           const uint8_t *payload, uint16_t payload_len)
{
    size_t off = 0;

    build_eth(pkt + off, ETH_TYPE_IPV4);
    off += ETH_HDR_LEN;

    size_t ip_tot = 20 + 20 + payload_len;
    size_t ip_hdr_len = build_ipv4(pkt + off, 5, (uint16_t)ip_tot,
                                    IP_PROTO_TCP, src_ip, dst_ip);
    off += ip_hdr_len;

    size_t tcp_hdr_len = build_tcp(pkt + off, 5, src_port, dst_port,
                                    seq, ack, TCP_FLAG_FIN | TCP_FLAG_ACK);
    off += tcp_hdr_len;

    if (payload != NULL && payload_len > 0) {
        memcpy(pkt + off, payload, payload_len);
        off += payload_len;
    }

    *pktlen = off;
}

static void build_data_pkt(uint8_t *pkt, size_t *pktlen,
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port,
                            uint32_t seq, uint32_t ack,
                            const uint8_t *data, uint16_t data_len)
{
    size_t off = 0;

    build_eth(pkt + off, ETH_TYPE_IPV4);
    off += ETH_HDR_LEN;

    size_t ip_tot = 20 + 20 + data_len;
    size_t ip_hdr_len = build_ipv4(pkt + off, 5, (uint16_t)ip_tot,
                                    IP_PROTO_TCP, src_ip, dst_ip);
    off += ip_hdr_len;

    size_t tcp_hdr_len = build_tcp(pkt + off, 5, src_port, dst_port,
                                    seq, ack, TCP_FLAG_ACK | TCP_FLAG_PSH);
    off += tcp_hdr_len;

    if (data != NULL && data_len > 0) {
        memcpy(pkt + off, data, data_len);
        off += data_len;
    }

    *pktlen = off;
}

/* 构造 IPv6 TCP 包（简化：无扩展头） */
static void build_ipv6_tcp_pkt(uint8_t *pkt, size_t *pktlen,
                                const uint8_t *src6, const uint8_t *dst6,
                                uint16_t src_port, uint16_t dst_port,
                                uint32_t seq, uint32_t ack, uint8_t flags)
{
    size_t off = 0;

    /* 以太网 */
    build_eth(pkt + off, ETH_TYPE_IPV6);
    off += ETH_HDR_LEN;

    /* IPv6 头 (40 bytes) */
    memset(pkt + off, 0, 40);
    pkt[off] = 0x60;  /* version=6 */
    /* payload_len = 20 (TCP) */
    pkt[off + 4] = 0x00;
    pkt[off + 5] = 0x14;
    pkt[off + 6] = IP_PROTO_TCP;  /* next_hdr */
    pkt[off + 7] = 64;           /* hop_limit */
    memcpy(pkt + off + 8, src6, 16);
    memcpy(pkt + off + 24, dst6, 16);
    off += 40;

    /* TCP 头 */
    build_tcp(pkt + off, 5, src_port, dst_port, seq, ack, flags);
    off += 20;

    *pktlen = off;
}

/* 构建数据包获取 TCP 载荷指针（用于验证排序和内容） */
static const uint8_t *get_payload_ptr(const uint8_t *pkt, size_t len)
{
    if (len < ETH_HDR_LEN + 20 + 20) return NULL;
    /* 跳过 eth + IPv4 (20) + TCP (20) */
    return pkt + ETH_HDR_LEN + 20 + 20;
}

/* ============================================================
 *  五元组哈希表测试
 * ============================================================ */

static void test_init_destroy(void)
{
    test_begin("tcp_reasm_init/destroy: basic lifecycle");
    capture_output();
    tcp_reasm_init();
    test_end_int_eq(tcp_reasm_stream_count(), 0, "init: stream count 0");
    tcp_reasm_destroy();
    restore_output();
}

static void test_insert_syn_creates_stream(void)
{
    test_begin("tcp_reasm_insert: SYN creates a new stream");
    uint8_t pkt[PKT_BUF_SIZE];
    size_t pktlen;

    build_syn_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                  12345, 80, 1000, NULL, 0);

    capture_output();
    tcp_reasm_init();
    int r = tcp_reasm_insert(pkt, pktlen);
    test_end(r, "insert SYN");
    test_end_int_eq(tcp_reasm_stream_count(), 1, "stream count = 1");
    tcp_reasm_destroy();
    restore_output();
}

static void test_two_streams(void)
{
    test_begin("tcp_reasm_insert: two separate streams");
    uint8_t pkt1[PKT_BUF_SIZE], pkt2[PKT_BUF_SIZE];
    size_t len1, len2;

    /* 流 1: 192.168.1.1:12345 → 10.0.0.1:80 */
    build_syn_pkt(pkt1, &len1, 0xC0A80001, 0x0A000001,
                  12345, 80, 1000, NULL, 0);
    /* 流 2: 192.168.1.2:54321 → 10.0.0.2:443 */
    build_syn_pkt(pkt2, &len2, 0xC0A80002, 0x0A000002,
                  54321, 443, 2000, NULL, 0);

    capture_output();
    tcp_reasm_init();
    test_end(tcp_reasm_insert(pkt1, len1), "insert stream1 SYN");
    test_end(tcp_reasm_insert(pkt2, len2), "insert stream2 SYN");
    test_end_int_eq(tcp_reasm_stream_count(), 2, "stream count = 2");
    tcp_reasm_destroy();
    restore_output();
}

static void test_get_stream_by_key(void)
{
    test_begin("tcp_reasm_get_stream: lookup by key");
    uint8_t pkt[PKT_BUF_SIZE];
    size_t pktlen;

    build_syn_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                  12345, 80, 1000, NULL, 0);

    capture_output();
    tcp_reasm_init();
    tcp_reasm_insert(pkt, pktlen);

    struct tcp_key key;
    tcp_reasm_extract_key(pkt, pktlen, &key);
    struct tcp_stream *s = tcp_reasm_get_stream(&key);
    test_end_nonnull(s, "get stream");

    /* 反向键也应该能找到（因为内部会尝试交换） */
    struct tcp_key swapped;
    swapped = key;
    swapped.src = key.dst;
    swapped.dst = key.src;
    swapped.src_port = key.dst_port;
    swapped.dst_port = key.src_port;
    struct tcp_stream *s2 = tcp_reasm_get_stream(&swapped);
    test_end_nonnull(s2, "get stream with swapped key");

    tcp_reasm_destroy();
    restore_output();
}

static void test_get_stream_nonexistent(void)
{
    test_begin("tcp_reasm_get_stream: nonexistent key returns NULL");
    struct tcp_key key;
    memset(&key, 0, sizeof(key));
    key.af = TCP_KEY_AF_IPV4;
    key.src.ipv4 = 0xC0A80001;
    key.dst.ipv4 = 0xC0A80002;
    key.src_port = htons(12345);
    key.dst_port = htons(80);
    key.proto = IP_PROTO_TCP;

    capture_output();
    tcp_reasm_init();
    struct tcp_stream *s = tcp_reasm_get_stream(&key);
    test_end_null(s, "get stream nonexistent");
    tcp_reasm_destroy();
    restore_output();
}

static void test_extract_key_non_tcp(void)
{
    test_begin("tcp_reasm_extract_key: non-TCP returns -1");
    uint8_t pkt[PKT_BUF_SIZE];
    size_t off = 0;

    /* 以太网 + IP 头(TCP 协议号)，但不含 TCP 头（截断） */
    build_eth(pkt + off, ETH_TYPE_IPV4);
    off += ETH_HDR_LEN;
    build_ipv4(pkt + off, 5, 40, IP_PROTO_UDP, 0xC0A80001, 0xC0A80002);
    off += 20;
    /* 假装是 UDP，无 TCP 头 */
    struct tcp_key key;
    capture_output();
    tcp_reasm_init();
    int r = tcp_reasm_extract_key(pkt, off, &key);
    test_end_neg(r, "extract key from UDP packet");
    tcp_reasm_destroy();
    restore_output();
}

static void test_extract_key_null(void)
{
    test_begin("tcp_reasm_extract_key: NULL params");
    capture_output();
    tcp_reasm_init();
    struct tcp_key key;
    int r = tcp_reasm_extract_key(NULL, 100, &key);
    test_end_neg(r, "NULL pkt");
    tcp_reasm_destroy();
    restore_output();
}

/* ============================================================
 *  状态机测试
 * ============================================================ */

static void test_state_machine_syn_synack(void)
{
    test_begin("state machine: SYN → ESTABLISHED");
    uint8_t pkt[PKT_BUF_SIZE];
    size_t pktlen;

    capture_output();
    tcp_reasm_init();

    /* 客户端 → 服务端: SYN */
    build_syn_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                  12345, 80, 1000, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    struct tcp_key key;
    tcp_reasm_extract_key(pkt, pktlen, &key);
    struct tcp_stream *s = tcp_reasm_get_stream(&key);
    test_end_nonnull(s, "stream exists after SYN");
    if (s) {
        test_end_int_eq(s->state, TCP_STATE_SYN_RCVD, "state = SYN_RCVD");
    }

    /* 服务端 → 客户端: SYN+ACK */
    build_synack_pkt(pkt, &pktlen, 0xC0A80002, 0xC0A80001,
                      80, 12345, 5000, 1001, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    if (s) {
        test_end_int_eq(s->state, TCP_STATE_ESTABLISHED, "state = ESTABLISHED");
        test_end_int_eq(s->client_isn, 1000, "client ISN = 1000");
        test_end_int_eq(s->server_isn, 5000, "server ISN = 5000");
    }

    tcp_reasm_destroy();
    restore_output();
}

static void test_state_machine_fin(void)
{
    test_begin("state machine: ESTABLISHED → FIN_RCVD → CLOSING");
    uint8_t pkt[PKT_BUF_SIZE];
    size_t pktlen;

    capture_output();
    tcp_reasm_init();

    /* 三次握手 */
    build_syn_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                  12345, 80, 1000, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    build_synack_pkt(pkt, &pktlen, 0xC0A80002, 0xC0A80001,
                      80, 12345, 5000, 1001, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    /* 客户端 ACK */
    build_ack_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                   12345, 80, 1001, 5001, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    struct tcp_key key;
    tcp_reasm_extract_key(pkt, pktlen, &key);
    struct tcp_stream *s = tcp_reasm_get_stream(&key);
    test_end_nonnull(s, "stream exists");

    /* 客户端 → 服务端: FIN */
    build_fin_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                   12345, 80, 1001, 5001, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    if (s) {
        test_end_int_eq(s->state, TCP_STATE_FIN_RCVD, "state = FIN_RCVD");
    }

    /* 服务端 → 客户端: FIN */
    build_fin_pkt(pkt, &pktlen, 0xC0A80002, 0xC0A80001,
                   80, 12345, 5001, 1002, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    if (s) {
        test_end_int_eq(s->state, TCP_STATE_CLOSING, "state = CLOSING");
    }

    tcp_reasm_destroy();
    restore_output();
}

static void test_state_machine_rst(void)
{
    test_begin("state machine: RST → CLOSED");
    uint8_t pkt[PKT_BUF_SIZE];
    size_t pktlen;

    capture_output();
    tcp_reasm_init();

    /* 三次握手 */
    build_syn_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                  12345, 80, 1000, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);
    build_synack_pkt(pkt, &pktlen, 0xC0A80002, 0xC0A80001,
                      80, 12345, 5000, 1001, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    struct tcp_key key;
    tcp_reasm_extract_key(pkt, pktlen, &key);
    struct tcp_stream *s = tcp_reasm_get_stream(&key);

    /* 发送 RST */
    size_t off = 0;
    build_eth(pkt + off, ETH_TYPE_IPV4);
    off += ETH_HDR_LEN;
    build_ipv4(pkt + off, 5, 40, IP_PROTO_TCP, 0xC0A80002, 0xC0A80001);
    off += 20;
    build_tcp(pkt + off, 5, 80, 12345, 5000, 0, TCP_FLAG_RST);
    off += 20;
    tcp_reasm_insert(pkt, off);

    if (s) {
        test_end_int_eq(s->state, TCP_STATE_CLOSED, "state = CLOSED after RST");
    }

    tcp_reasm_destroy();
    restore_output();
}

/* ============================================================
 *  按 SEQ 排序插入测试
 * ============================================================ */

static void test_segment_sorted_insert(void)
{
    test_begin("segment: sorted insertion by SEQ");
    uint8_t pkt[PKT_BUF_SIZE];
    size_t pktlen;

    capture_output();
    tcp_reasm_init();

    /* SYN + 建立连接 */
    build_syn_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                  12345, 80, 1000, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);
    build_synack_pkt(pkt, &pktlen, 0xC0A80002, 0xC0A80001,
                      80, 12345, 5000, 1001, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);
    /* ACK for handshake */
    build_ack_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                   12345, 80, 1001, 5001, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    struct tcp_key key;
    tcp_reasm_extract_key(pkt, pktlen, &key);
    struct tcp_stream *s = tcp_reasm_get_stream(&key);

    /* 插入 SEQ=1100 的数据段 */
    build_data_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                    12345, 80, 1100, 5001,
                    (const uint8_t *)"Hello World", 11);
    tcp_reasm_insert(pkt, pktlen);

    /* 插入 SEQ=1050 的数据段（应该排在 1100 前面） */
    build_data_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                    12345, 80, 1050, 5001,
                    (const uint8_t *)"Previous ", 9);
    tcp_reasm_insert(pkt, pktlen);

    /* 插入 SEQ=1001 的数据段（应该排在最前面） */
    build_data_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                    12345, 80, 1001, 5001,
                    (const uint8_t *)"Start ", 6);
    tcp_reasm_insert(pkt, pktlen);

    if (s) {
        test_end_int_eq(s->seg_count, 3, "segment count = 3");

        /* 遍历链表验证顺序 */
        struct tcp_segment *seg = s->segments;
        int ok = 1;
        uint32_t prev_seq = 0;
        int idx = 0;
        while (seg != NULL) {
#ifdef VERBOSE
            printf("  seg[%d]: seq=0x%08x data_len=%u\n",
                   idx, seg->seq, seg->data_len);
#endif
            if (idx > 0 && seg->seq <= prev_seq) {
                ok = 0;
                break;
            }
            prev_seq = seg->seq;
            seg = seg->next;
            idx++;
        }
        test_end_int_eq(ok, 1, "segments in ascending SEQ order");

        /* 验证 SEQ 值 */
        if (s->segments) {
            test_end_int_eq((int)s->segments->seq, 1001, "first segment SEQ=1001");
        }
    }

    tcp_reasm_destroy();
    restore_output();
}

static void test_segment_dup_rejection(void)
{
    test_begin("segment: duplicate SEQ rejection");
    uint8_t pkt[PKT_BUF_SIZE];
    size_t pktlen;

    capture_output();
    tcp_reasm_init();

    /* 三次握手 */
    build_syn_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                  12345, 80, 1000, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);
    build_synack_pkt(pkt, &pktlen, 0xC0A80002, 0xC0A80001,
                      80, 12345, 5000, 1001, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);
    build_ack_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                   12345, 80, 1001, 5001, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    struct tcp_key key;
    tcp_reasm_extract_key(pkt, pktlen, &key);
    struct tcp_stream *s = tcp_reasm_get_stream(&key);

    /* 插入 SEQ=1100 */
    build_data_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                    12345, 80, 1100, 5001,
                    (const uint8_t *)"First", 5);
    tcp_reasm_insert(pkt, pktlen);

    /* 再次插入相同 SEQ=1100（应被拒绝） */
    build_data_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                    12345, 80, 1100, 5001,
                    (const uint8_t *)"Duplicate", 9);
    tcp_reasm_insert(pkt, pktlen);

    if (s) {
        test_end_int_eq(s->seg_count, 1, "segment count = 1 (dup rejected)");
        if (s->segments) {
            test_end_int_eq(s->segments->data_len, 5, "original data preserved (len=5)");
        }
    }

    tcp_reasm_destroy();
    restore_output();
}

static void test_segment_no_payload_skip(void)
{
    test_begin("segment: pure ACK (no payload) creates no segment");
    uint8_t pkt[PKT_BUF_SIZE];
    size_t pktlen;

    capture_output();
    tcp_reasm_init();

    /* SYN */
    build_syn_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                  12345, 80, 1000, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);
    build_synack_pkt(pkt, &pktlen, 0xC0A80002, 0xC0A80001,
                      80, 12345, 5000, 1001, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    struct tcp_key key;
    tcp_reasm_extract_key(pkt, pktlen, &key);
    struct tcp_stream *s = tcp_reasm_get_stream(&key);

    /* ACK（无载荷）— 不应插入段 */
    build_ack_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                   12345, 80, 1001, 5001, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    if (s) {
        /* SYN 段和 SYN+ACK 段已经插入，加上纯 ACK 应不增加 */
        test_end_int_eq(s->seg_count, 2, "segment count = 2 (SYN + SYN+ACK only)");
    }

    tcp_reasm_destroy();
    restore_output();
}

/* ============================================================
 *  IPv6 测试
 * ============================================================ */

static void test_ipv6_syn(void)
{
    test_begin("IPv6: SYN creates stream");
    uint8_t pkt[PKT_BUF_SIZE];
    size_t pktlen;

    uint8_t src6[16], dst6[16];
    memset(src6, 0, 16); src6[0] = 0x20; src6[1] = 0x01; /* 2001::1 */
    src6[15] = 1;
    memset(dst6, 0, 16); dst6[0] = 0x26; dst6[1] = 0x00; /* 2600::1 */
    dst6[15] = 1;

    build_ipv6_tcp_pkt(pkt, &pktlen, src6, dst6, 12345, 80,
                        1000, 0, TCP_FLAG_SYN);

    capture_output();
    tcp_reasm_init();
    int r = tcp_reasm_insert(pkt, pktlen);
    test_end(r, "insert IPv6 SYN");
    test_end_int_eq(tcp_reasm_stream_count(), 1, "stream count = 1");
    tcp_reasm_destroy();
    restore_output();
}

static void test_ipv6_state_machine(void)
{
    test_begin("IPv6: SYN → ESTABLISHED");
    uint8_t pkt[PKT_BUF_SIZE];
    size_t pktlen;

    uint8_t src6[16], dst6[16];
    memset(src6, 0, 16); src6[0] = 0x20; src6[1] = 0x01; src6[15] = 1;
    memset(dst6, 0, 16); dst6[0] = 0x26; dst6[1] = 0x00; dst6[15] = 1;

    capture_output();
    tcp_reasm_init();

    /* Client SYN */
    build_ipv6_tcp_pkt(pkt, &pktlen, src6, dst6, 12345, 80,
                        1000, 0, TCP_FLAG_SYN);
    tcp_reasm_insert(pkt, pktlen);

    /* Server SYN+ACK */
    build_ipv6_tcp_pkt(pkt, &pktlen, dst6, src6, 80, 12345,
                        5000, 1001, TCP_FLAG_SYN | TCP_FLAG_ACK);
    tcp_reasm_insert(pkt, pktlen);

    struct tcp_key key;
    tcp_reasm_extract_key(pkt, pktlen, &key);
    struct tcp_stream *s = tcp_reasm_get_stream(&key);
    test_end_nonnull(s, "stream exists");
    if (s) {
        test_end_int_eq(s->state, TCP_STATE_ESTABLISHED, "state = ESTABLISHED");
    }

    tcp_reasm_destroy();
    restore_output();
}

/* ============================================================
 *  边界条件测试
 * ============================================================ */

static void test_null_insert(void)
{
    test_begin("tcp_reasm_insert: NULL packet");
    capture_output();
    tcp_reasm_init();
    int r = tcp_reasm_insert(NULL, 100);
    test_end_neg(r, "NULL insert returns -1");
    tcp_reasm_destroy();
    restore_output();
}

static void test_insert_short_frame(void)
{
    test_begin("tcp_reasm_insert: too short frame");
    uint8_t buf[13];
    memset(buf, 0, 13);
    capture_output();
    tcp_reasm_init();
    int r = tcp_reasm_insert(buf, 13);
    test_end_neg(r, "short frame returns -1");
    tcp_reasm_destroy();
    restore_output();
}

static void test_insert_non_ip(void)
{
    test_begin("tcp_reasm_insert: non-IP frame (ARP)");
    uint8_t buf[ETH_HDR_LEN + 20];
    build_eth(buf, ETH_TYPE_ARP);
    capture_output();
    tcp_reasm_init();
    int r = tcp_reasm_insert(buf, sizeof(buf));
    test_end_neg(r, "ARP returns -1");
    tcp_reasm_destroy();
    restore_output();
}

static void test_multiple_stream_same_hash(void)
{
    test_begin("hash collision: multiple streams in same bucket");
    uint8_t pkt[PKT_BUF_SIZE];
    size_t pktlen;

    capture_output();
    tcp_reasm_init();

    /* 插入多个不同五元组的流以验证桶内链式遍历 */
    build_syn_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                  12345, 80, 1000, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    build_syn_pkt(pkt, &pktlen, 0xC0A80003, 0xC0A80004,
                  12346, 81, 2000, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    build_syn_pkt(pkt, &pktlen, 0xC0A80005, 0xC0A80006,
                  12347, 82, 3000, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    test_end_int_eq(tcp_reasm_stream_count(), 3, "stream count = 3");

    /* 验证每个流可以通过 get_stream 定位 */
    struct tcp_key key;

    build_syn_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                  12345, 80, 1000, NULL, 0);
    tcp_reasm_extract_key(pkt, pktlen, &key);
    test_end_nonnull(tcp_reasm_get_stream(&key), "find stream 1");

    build_syn_pkt(pkt, &pktlen, 0xC0A80003, 0xC0A80004,
                  12346, 81, 2000, NULL, 0);
    tcp_reasm_extract_key(pkt, pktlen, &key);
    test_end_nonnull(tcp_reasm_get_stream(&key), "find stream 2");

    build_syn_pkt(pkt, &pktlen, 0xC0A80005, 0xC0A80006,
                  12347, 82, 3000, NULL, 0);
    tcp_reasm_extract_key(pkt, pktlen, &key);
    test_end_nonnull(tcp_reasm_get_stream(&key), "find stream 3");

    tcp_reasm_destroy();
    restore_output();
}

static void test_state_machine_null(void)
{
    test_begin("tcp_state_machine: NULL stream (no crash)");
    capture_output();
    tcp_state_machine(NULL, TCP_FLAG_SYN, 1000, 0, 1);
    test_end(0, "NULL state machine call");
    restore_output();
}

static void test_destroy_with_segments(void)
{
    test_begin("destroy with segments: no leaks");
    uint8_t pkt[PKT_BUF_SIZE];
    size_t pktlen;

    capture_output();
    tcp_reasm_init();

    build_syn_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                  12345, 80, 1000, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);
    build_synack_pkt(pkt, &pktlen, 0xC0A80002, 0xC0A80001,
                      80, 12345, 5000, 1001, NULL, 0);
    tcp_reasm_insert(pkt, pktlen);

    /* 多插入几个数据段 */
    build_data_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                    12345, 80, 1001, 5001,
                    (const uint8_t *)"AAAA", 4);
    tcp_reasm_insert(pkt, pktlen);
    build_data_pkt(pkt, &pktlen, 0xC0A80001, 0xC0A80002,
                    12345, 80, 1111, 5001,
                    (const uint8_t *)"BBBB", 4);
    tcp_reasm_insert(pkt, pktlen);

    test_end_int_eq(tcp_reasm_segment_count(), 4, "4 segments total (SYN+SYNACK+2 data)");

    /* destroy 应释放所有 (无内存泄漏检查工具，但至少不崩溃) */
    tcp_reasm_destroy();
    test_end(0, "destroy with segments completed");
    restore_output();
}

/* ============================================================
 *  主测试入口
 * ============================================================ */

int main(void)
{
    printf("============================================\n");
    printf("  minishark — TCP Reassembly Test Suite\n");
    printf("============================================\n\n");

    /* ---- 生命周期 ---- */
    printf("--- Lifecycle ---\n");
    test_init_destroy();
    printf("\n");

    /* ---- 五元组哈希表 ---- */
    printf("--- 5-Tuple Hash Table ---\n");
    test_insert_syn_creates_stream();
    test_two_streams();
    test_get_stream_by_key();
    test_get_stream_nonexistent();
    test_extract_key_non_tcp();
    test_extract_key_null();
    printf("\n");

    /* ---- 状态机 ---- */
    printf("--- State Machine ---\n");
    test_state_machine_syn_synack();
    test_state_machine_fin();
    test_state_machine_rst();
    test_state_machine_null();
    printf("\n");

    /* ---- 按 SEQ 排序插入 ---- */
    printf("--- SEQ Sorted Insertion ---\n");
    test_segment_sorted_insert();
    test_segment_dup_rejection();
    test_segment_no_payload_skip();
    printf("\n");

    /* ---- IPv6 ---- */
    printf("--- IPv6 ---\n");
    test_ipv6_syn();
    test_ipv6_state_machine();
    printf("\n");

    /* ---- 边界条件 ---- */
    printf("--- Edge Cases ---\n");
    test_null_insert();
    test_insert_short_frame();
    test_insert_non_ip();
    test_multiple_stream_same_hash();
    test_destroy_with_segments();
    printf("\n");

    /* ---- 摘要 ---- */
    printf("============================================\n");
    printf("  Results: %d passed, %d failed out of %d\n",
           tests_passed, tests_failed, current_test);
    printf("============================================\n");

    return tests_failed > 0 ? 1 : 0;
}
