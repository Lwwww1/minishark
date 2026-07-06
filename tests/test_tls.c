/*
 * test_tls.c — TLS 解析器单元测试
 *
 * 测试覆盖：
 *   - ClientHello with/without SNI
 *   - ServerHello
 *   - 截断、畸形、异常包
 *   - 边界情况（空扩展、空 SNI、多记录聚合）
 *
 * 编译：gcc -Wall -Wextra -O2 -g -I../include test_tls.c ../src/tls_parser.c ../src/protocol.c -o test_tls
 * 运行：./test_tls
 */

#include "tls_parser.h"
#include "common.h"
#include "protocol.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ============================================================
 *  测试基础设施（复用 test_protocol.c 风格）
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
    } else {
        tests_failed++;
        printf("  FAIL: %s (expected -1, got %d)\n", name, result);
    }
}

static void capture_output(void)
{
#ifndef VERBOSE
    if (freopen("/dev/null", "w", stdout)) {}
    if (freopen("/dev/null", "w", stderr)) {}
#endif
}

static void restore_output(void)
{
#ifndef VERBOSE
    if (freopen("/dev/tty", "w", stdout)) {}
    if (freopen("/dev/tty", "w", stderr)) {}
#endif
}

/* ============================================================
 *  辅助：TLS 报文构建
 * ============================================================ */

/* 写 2 字节大端 */
static size_t write_u16(uint8_t *buf, uint16_t val)
{
    buf[0] = (val >> 8) & 0xFF;
    buf[1] = val & 0xFF;
    return 2;
}

/* 写 3 字节大端 (24-bit TLS 长度) */
static size_t write_u24(uint8_t *buf, uint32_t val)
{
    buf[0] = (val >> 16) & 0xFF;
    buf[1] = (val >> 8) & 0xFF;
    buf[2] = val & 0xFF;
    return 3;
}

/* 写固定随机数 (32 字节) */
static size_t write_random(uint8_t *buf)
{
    for (int i = 0; i < 32; i++)
        buf[i] = (uint8_t)i;
    return 32;
}

/*
 * 构造 TLS Record + Handshake 头，返回 body 起始位置和剩余空间。
 * buf 大小至少 13 字节。
 */
static size_t build_record_hdr(uint8_t *buf, uint8_t content_type,
                               uint8_t ver_major, uint8_t ver_minor,
                               uint16_t record_len)
{
    size_t off = 0;
    buf[off++] = content_type;
    buf[off++] = ver_major;
    buf[off++] = ver_minor;
    off += write_u16(buf + off, record_len);
    return off; /* = 5 */
}

static size_t build_handshake_hdr(uint8_t *buf, uint8_t hs_type,
                                  uint32_t hs_len)
{
    size_t off = 0;
    buf[off++] = hs_type;
    off += write_u24(buf + off, hs_len);
    return off; /* = 4 */
}

/*
 * 构建完整 ClientHello（含可选的 SNI 扩展）
 * 返回总长度，0 表示 buf 太小。
 */
static size_t build_clienthello(uint8_t *buf, size_t buf_size,
                                uint16_t version, uint8_t sid_len,
                                const char *sni_hostname)
{
    /* ---- 1. 先构造 body（handshake payload），算出总长 ---- */
    uint8_t body[512];
    size_t bo = 0;

    /* version */
    bo += write_u16(body + bo, version);
    /* random (32 字节) */
    bo += write_random(body + bo);
    /* session_id */
    body[bo++] = sid_len;
    memset(body + bo, 0, sid_len);
    bo += sid_len;
    /* cipher_suites: 一个 TLS_AES_128_GCM_SHA256 (0x1301) */
    write_u16(body + bo, 2);
    bo += 2;
    write_u16(body + bo, 0x1301);
    bo += 2;
    /* compression_methods: 一个 null (0x00) */
    body[bo++] = 1;
    body[bo++] = 0;

    /* extensions (若 SNI 非空则添加) */
    size_t ext_start = bo;
    bo += 2; /* 预留 extensions_len */

    if (sni_hostname) {
        size_t name_len = strlen(sni_hostname);
        /* SNI extension header */
        uint8_t ext_body[32 + 256];
        size_t ebo = 0;
        /* server_name_list length */
        ebo += write_u16(ext_body + ebo, (uint16_t)(1 + 2 + name_len));
        /* server_name: name_type=0x00 (host_name) */
        ext_body[ebo++] = 0x00;
        ebo += write_u16(ext_body + ebo, (uint16_t)name_len);
        memcpy(ext_body + ebo, sni_hostname, name_len);
        ebo += name_len;

        /* extension: type=0x0000 (SNI) */
        write_u16(body + bo, TLS_EXT_SNI);
        bo += 2;
        write_u16(body + bo, (uint16_t)ebo);
        bo += 2;
        memcpy(body + bo, ext_body, ebo);
        bo += ebo;
    }

    /* 回填 extensions_len */
    uint16_t ext_total = (uint16_t)(bo - ext_start - 2);
    write_u16(body + ext_start, ext_total);

    uint32_t hs_len = (uint32_t)bo;

    /* ---- 2. 组装 record + handshake headers ---- */
    size_t total = 0;
    uint16_t record_len = (uint16_t)(4 + hs_len); /* handshake hdr(4) + body */

    if (buf_size < (size_t)5 + record_len)
        return 0;

    total += build_record_hdr(buf + total, TLS_CONTENT_HANDSHAKE,
                               version >> 8, version & 0xFF, record_len);
    total += build_handshake_hdr(buf + total,
                                  TLS_HANDSHAKE_CLIENT_HELLO, hs_len);
    memcpy(buf + total, body, hs_len);
    total += hs_len;

    return total;
}

/*
 * 构建完整 ServerHello
 * 返回总长度，0 表示 buf 太小。
 */
static size_t build_serverhello(uint8_t *buf, size_t buf_size,
                                uint16_t version, uint16_t cipher_suite)
{
    uint8_t body[128];
    size_t bo = 0;

    /* version */
    bo += write_u16(body + bo, version);
    /* random (32 字节) */
    bo += write_random(body + bo);
    /* session_id: len=0 */
    body[bo++] = 0;
    /* cipher_suite */
    bo += write_u16(body + bo, cipher_suite);
    /* compression_method */
    body[bo++] = 0;

    uint32_t hs_len = (uint32_t)bo;

    size_t total = 0;
    uint16_t record_len = (uint16_t)(4 + hs_len);

    if (buf_size < (size_t)5 + record_len)
        return 0;

    total += build_record_hdr(buf + total, TLS_CONTENT_HANDSHAKE,
                               version >> 8, version & 0xFF, record_len);
    total += build_handshake_hdr(buf + total,
                                  TLS_HANDSHAKE_SERVER_HELLO, hs_len);
    memcpy(buf + total, body, hs_len);
    total += hs_len;

    return total;
}

/*
 * 构造一个 ClientHello（不含 SNI，但有非 SNI 扩展）。
 */
static size_t build_clienthello_other_ext(uint8_t *buf, size_t buf_size,
                                           uint16_t version)
{
    uint8_t body[512];
    size_t bo = 0;

    bo += write_u16(body + bo, version);
    bo += write_random(body + bo);
    body[bo++] = 0; /* session_id len */
    write_u16(body + bo, 2); /* cipher_suites_len */
    bo += 2;
    write_u16(body + bo, 0x1301);
    bo += 2;
    body[bo++] = 1; /* compression len */
    body[bo++] = 0;

    /* 添加一个非 SNI 扩展：supported_groups (type=0x000a) */
    size_t ext_start = bo;
    bo += 2; /* extensions_len placeholder */

    uint16_t ext_type = 0x000a; /* supported_groups */
    uint8_t ext_data[6];
    size_t eo = 0;
    eo += write_u16(ext_data + eo, 2); /* groups length */
    eo += write_u16(ext_data + eo, 0x001d); /* x25519 */
    eo += write_u16(ext_data + eo, 0x0017); /* secp256r1 */

    write_u16(body + bo, ext_type);
    bo += 2;
    write_u16(body + bo, (uint16_t)eo);
    bo += 2;
    memcpy(body + bo, ext_data, eo);
    bo += eo;

    write_u16(body + ext_start, (uint16_t)(bo - ext_start - 2));

    uint32_t hs_len = (uint32_t)bo;
    size_t total = 0;
    uint16_t record_len = (uint16_t)(4 + hs_len);

    if (buf_size < (size_t)5 + record_len) return 0;

    total += build_record_hdr(buf + total, TLS_CONTENT_HANDSHAKE,
                               version >> 8, version & 0xFF, record_len);
    total += build_handshake_hdr(buf + total,
                                  TLS_HANDSHAKE_CLIENT_HELLO, hs_len);
    memcpy(buf + total, body, hs_len);
    total += hs_len;
    return total;
}

/* ============================================================
 *  测试用例
 * ============================================================ */

static void test_clienthello_with_sni(void)
{
    test_begin("ClientHello with SNI (www.example.com)");
    uint8_t buf[512];
    size_t len = build_clienthello(buf, sizeof(buf), 0x0303, 0,
                                    "www.example.com");
    capture_output();
    int r = parse_tls(buf, len);
    restore_output();
    test_end(r, "ClientHello with SNI");
}

static void test_clienthello_no_extensions(void)
{
    test_begin("ClientHello without extensions");
    uint8_t buf[512];
    size_t len = build_clienthello(buf, sizeof(buf), 0x0303, 0, NULL);
    capture_output();
    int r = parse_tls(buf, len);
    restore_output();
    test_end(r, "ClientHello no extensions");
}

static void test_clienthello_other_ext_no_sni(void)
{
    test_begin("ClientHello with other extension (no SNI)");
    uint8_t buf[512];
    size_t len = build_clienthello_other_ext(buf, sizeof(buf), 0x0303);
    capture_output();
    int r = parse_tls(buf, len);
    restore_output();
    test_end(r, "ClientHello other ext no SNI");
}

static void test_clienthello_with_session_id(void)
{
    test_begin("ClientHello with session_id (32 bytes)");
    uint8_t buf[512];
    size_t len = build_clienthello(buf, sizeof(buf), 0x0303, 32,
                                    "session.example.com");
    capture_output();
    int r = parse_tls(buf, len);
    restore_output();
    test_end(r, "ClientHello with session_id");
}

static void test_clienthello_large_sid(void)
{
    test_begin("ClientHello with invalid session_id_len (33 > 32)");
    uint8_t buf[512];
    /* 手工构建：session_id_len = 33 */
    memset(buf, 0, sizeof(buf));
    size_t off = 0;
    off += build_record_hdr(buf + off, TLS_CONTENT_HANDSHAKE, 3, 3, 0);
    size_t hs_len_off = off;
    off += build_handshake_hdr(buf + off, TLS_HANDSHAKE_CLIENT_HELLO, 0);

    size_t body_off = off;
    off += write_u16(buf + off, 0x0303);
    off += write_random(buf + off);
    buf[off++] = 33; /* session_id_len > 32, expect failure */
    /* no more data */

    uint32_t hs_len = (uint32_t)(off - body_off);
    write_u24(buf + hs_len_off + 1, hs_len);
    uint16_t rlen = (uint16_t)(4 + hs_len);
    write_u16(buf + 3, rlen);

    capture_output();
    int r = parse_tls(buf, off);
    restore_output();
    test_end(r, "ClientHello invalid session_id_len (graceful)");
}

static void test_serverhello_normal(void)
{
    test_begin("ServerHello normal (TLS 1.2, cipher=0xc030)");
    uint8_t buf[256];
    size_t len = build_serverhello(buf, sizeof(buf), 0x0303, 0xc030);
    capture_output();
    int r = parse_tls(buf, len);
    restore_output();
    test_end(r, "ServerHello normal");
}

static void test_serverhello_tls13(void)
{
    test_begin("ServerHello TLS 1.3 (ver=0x0304, cipher=0x1301)");
    uint8_t buf[256];
    size_t len = build_serverhello(buf, sizeof(buf), 0x0304, 0x1301);
    capture_output();
    int r = parse_tls(buf, len);
    restore_output();
    test_end(r, "ServerHello TLS 1.3");
}

static void test_tls_null(void)
{
    test_begin("TLS null packet");
    capture_output();
    int r = parse_tls(NULL, 10);
    restore_output();
    test_end_neg(r, "TLS null");
}

static void test_tls_zero_len(void)
{
    test_begin("TLS zero length");
    uint8_t buf[1];
    capture_output();
    int r = parse_tls(buf, 0);
    restore_output();
    test_end_neg(r, "TLS zero length");
}

static void test_tls_truncated_record(void)
{
    test_begin("TLS truncated record header (3 bytes)");
    uint8_t buf[3];
    memset(buf, 0, 3);
    capture_output();
    int r = parse_tls(buf, 3);
    restore_output();
    test_end_neg(r, "TLS truncated record");
}

static void test_tls_truncated_handshake(void)
{
    test_begin("TLS truncated handshake (record OK, handshake too short)");
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    /* record hdr: content=0x16, ver=3.3, length=3 (too short for handshake hdr) */
    size_t off = 0;
    off += build_record_hdr(buf + off, TLS_CONTENT_HANDSHAKE, 3, 3, 3);
    /* only 3 bytes of payload */
    buf[off++] = 0x01; /* handshake type */
    capture_output();
    int r = parse_tls(buf, off);
    restore_output();
    test_end(r, "TLS truncated handshake (gracefully skipped)");
}

static void test_tls_non_handshake(void)
{
    test_begin("TLS non-handshake record (AppData)");
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    size_t off = 0;
    off += build_record_hdr(buf + off, TLS_CONTENT_APP_DATA, 3, 3, 10);
    capture_output();
    int r = parse_tls(buf, off + 10);
    restore_output();
    test_end(r, "TLS non-handshake");
}

static void test_tls_alert_record(void)
{
    test_begin("TLS Alert record");
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    size_t off = 0;
    off += build_record_hdr(buf + off, TLS_CONTENT_ALERT, 3, 3, 2);
    buf[off++] = 1; /* warning */
    buf[off++] = 0; /* close_notify */
    capture_output();
    int r = parse_tls(buf, off);
    restore_output();
    test_end(r, "TLS Alert record");
}

static void test_tls_change_cipher(void)
{
    test_begin("TLS Change Cipher Spec record");
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    size_t off = 0;
    off += build_record_hdr(buf + off, TLS_CONTENT_CHANGE_CIPHER, 3, 3, 1);
    buf[off++] = 1;
    capture_output();
    int r = parse_tls(buf, off);
    restore_output();
    test_end(r, "TLS Change Cipher");
}

static void test_tls_multiple_records(void)
{
    test_begin("TLS multiple records (handshake + appdata)");
    uint8_t buf[1024];
    size_t off = 0;
    /* 第一个 record: ClientHello */
    size_t ch_len = build_clienthello(buf + off, sizeof(buf) - off,
                                       0x0303, 0, "multi.example.com");
    if (ch_len > 0) off += ch_len;
    /* 第二个 record: AppData */
    off += build_record_hdr(buf + off, TLS_CONTENT_APP_DATA, 3, 3, 5);
    memset(buf + off, 0xAB, 5);
    off += 5;
    capture_output();
    int r = parse_tls(buf, off);
    restore_output();
    test_end(r, "TLS multiple records (parses first)");
}

static void test_tls_empty_sni(void)
{
    test_begin("ClientHello with empty SNI name");

    /* Construct: SNI extension with name_length = 0 */
    uint8_t buf[512];
    memset(buf, 0, sizeof(buf));
    size_t off = 0;

    /* 先写 body 算长度 */
    uint8_t body[256];
    size_t bo = 0;
    bo += write_u16(body + bo, 0x0303);
    bo += write_random(body + bo);
    body[bo++] = 0; /* session_id_len */
    write_u16(body + bo, 2); bo += 2;
    write_u16(body + bo, 0x1301); bo += 2;
    body[bo++] = 1; /* compression len */
    body[bo++] = 0;

    size_t ext_start = bo;
    bo += 2; /* ext_len placeholder */

    /* SNI extension with name_length=0 */
    write_u16(body + bo, TLS_EXT_SNI); bo += 2;
    write_u16(body + bo, 5); bo += 2; /* ext body len: list_len(2) + type(1) + name_len(2) + name(0) */
    write_u16(body + bo, 3); bo += 2; /* server_name_list_len = 3 (type + name_len + 0 name) */
    body[bo++] = 0x00; /* name_type = host_name */
    write_u16(body + bo, 0); bo += 2; /* name_length = 0 */

    write_u16(body + ext_start, (uint16_t)(bo - ext_start - 2));

    uint32_t hs_len = (uint32_t)(bo);
    uint16_t rec_len = (uint16_t)(4 + hs_len);

    off += build_record_hdr(buf + off, TLS_CONTENT_HANDSHAKE, 3, 3, rec_len);
    off += build_handshake_hdr(buf + off, TLS_HANDSHAKE_CLIENT_HELLO, hs_len);
    memcpy(buf + off, body, hs_len);
    off += hs_len;

    capture_output();
    int r = parse_tls(buf, off);
    restore_output();
    test_end(r, "ClientHello with empty SNI (no crash)");
}

static void test_tls_clienthello_tls13(void)
{
    test_begin("ClientHello TLS 1.3 (ver=0x0304) with SNI");
    uint8_t buf[512];
    size_t len = build_clienthello(buf, sizeof(buf), 0x0304, 0,
                                    "tls13.example.com");
    capture_output();
    int r = parse_tls(buf, len);
    restore_output();
    test_end(r, "ClientHello TLS 1.3");
}

static void test_tls_unsupported_handshake(void)
{
    test_begin("TLS unsupported handshake type (Certificate=0x0b)");
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    size_t off = 0;
    off += build_record_hdr(buf + off, TLS_CONTENT_HANDSHAKE, 3, 3, 4);
    off += build_handshake_hdr(buf + off, 0x0b, 0); /* Certificate */
    capture_output();
    int r = parse_tls(buf, off);
    restore_output();
    test_end(r, "TLS unsupported handshake (ignored)");
}

static void test_tls_record_len_exceeds_buffer(void)
{
    test_begin("TLS record length exceeds buffer");
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));
    /* 声称 record_len = 1000，但 buffer 只有 256 */
    size_t off = 0;
    off += build_record_hdr(buf + off, TLS_CONTENT_HANDSHAKE, 3, 3, 1000);
    capture_output();
    int r = parse_tls(buf, off);
    restore_output();
    test_end(r, "TLS record len exceeds buffer (graceful)");
}

/* ============================================================
 *  主测试入口
 * ============================================================ */

int main(void)
{
    printf("========================================\n");
    printf("  minishark — TLS Parser Test Suite\n");
    printf("========================================\n\n");

    printf("--- TLS Handshake ---\n");
    test_clienthello_with_sni();
    test_clienthello_no_extensions();
    test_clienthello_other_ext_no_sni();
    test_clienthello_with_session_id();
    test_clienthello_large_sid();
    test_serverhello_normal();
    test_serverhello_tls13();
    test_tls_null();
    test_tls_zero_len();
    test_tls_truncated_record();
    test_tls_truncated_handshake();
    test_tls_non_handshake();
    test_tls_alert_record();
    test_tls_change_cipher();
    test_tls_multiple_records();
    test_tls_empty_sni();
    test_tls_clienthello_tls13();
    test_tls_unsupported_handshake();
    test_tls_record_len_exceeds_buffer();
    printf("\n");

    printf("========================================\n");
    printf("  Results: %d passed, %d failed out of %d\n",
           tests_passed, tests_failed, current_test);
    printf("========================================\n");

    return tests_failed > 0 ? 1 : 0;
}
