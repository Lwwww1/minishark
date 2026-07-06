#include "tls_parser.h"
#include "common.h"

#include <arpa/inet.h>

/*
 * tls_parser.c — TLS Record Layer 与 Handshake 协议解析
 *
 * 本模块解析位于 TCP 载荷中的 TLS 记录，识别 ClientHello 和 ServerHello，
 * 并从 ClientHello 的 extensions 中提取 SNI（Server Name Indication）域名。
 *
 * 输出（stdout）示例：
 *   TLS : ClientHello ver=3.3 sni=www.example.com
 *   TLS : ServerHello ver=3.3 cipher=0xc030
 */

/* ============================================================
 *  内部辅助 — 读取大端多字节值
 * ============================================================ */

/* 从 p 读取 2 字节大端无符号整数（p 无需对齐） */
static inline uint16_t read_u16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] << 8) | p[1];
}

/* 从 p 读取 3 字节大端无符号整数（TLS 24-bit 长度字段） */
static inline uint32_t read_u24(const uint8_t *p)
{
    return ((uint32_t)p[0] << 16) | ((uint32_t)p[1] << 8) | p[2];
}

/* ============================================================
 *  parse_client_hello — 解析 ClientHello 消息体，提取 SNI
 *
 *  参数：
 *    body — 指向 Handshake body（已跳过 handshake_type + length[3]）
 *    len  — body 剩余可用字节数
 *    ver_out — [输出] ClientHello 中声明的协议版本（ver_major << 8 | ver_minor）
 *    sni_out  — [输出] 提取到的 SNI 域名，无 SNI 时置空
 *    sni_len  — sni_out 缓冲区大小
 *
 *  返回 0 成功，-1 输入无效。
 * ============================================================ */
static int parse_client_hello(const uint8_t *body, size_t len,
                              uint16_t *ver_out,
                              char *sni_out, size_t sni_len)
{
    if (ver_out)  *ver_out  = 0;
    if (sni_out)  sni_out[0] = '\0';

    /* 最小固定部分：version(2) + random(32) = 34 */
    if (len < 34) {
        LOG_WARN("parse_tls: ClientHello body truncated (%zu < 34)", len);
        return -1;
    }

    /* 输出版本号 */
    uint16_t version = read_u16(body);
    if (ver_out) *ver_out = version;

    /* 跳过 version(2) + random(32) */
    const uint8_t *p = body + 34;
    size_t remaining = len - 34;

    /* ——— session_id ——— */
    if (remaining < 1) {
        LOG_WARN("parse_tls: ClientHello truncated at session_id_len");
        return 0;
    }
    uint8_t sid_len = p[0];
    p += 1;
    remaining -= 1;
    if (sid_len > 32) {
        LOG_WARN("parse_tls: ClientHello session_id_len %u > 32", sid_len);
        return -1;
    }
    if (remaining < sid_len) {
        LOG_WARN("parse_tls: ClientHello session_id truncated");
        return 0;
    }
    p += sid_len;
    remaining -= sid_len;

    /* ——— cipher_suites ——— */
    if (remaining < 2) {
        LOG_WARN("parse_tls: ClientHello truncated at cipher_suites_len");
        return 0;
    }
    uint16_t cs_len = read_u16(p);
    p += 2;
    remaining -= 2;
    if (cs_len % 2 != 0 || cs_len > remaining) {
        LOG_WARN("parse_tls: ClientHello invalid cipher_suites_len %u", cs_len);
        return 0;
    }
    p += cs_len;
    remaining -= cs_len;

    /* ——— compression_methods ——— */
    if (remaining < 1) {
        LOG_WARN("parse_tls: ClientHello truncated at compression_len");
        return 0;
    }
    uint8_t comp_len = p[0];
    p += 1;
    remaining -= 1;
    if (comp_len > remaining) {
        LOG_WARN("parse_tls: ClientHello compression truncated");
        return 0;
    }
    p += comp_len;
    remaining -= comp_len;

    /* ——— extensions ——— */
    if (remaining < 2) {
        /* 没有扩展是合法的 */
        return 0;
    }
    uint16_t ext_total_len = read_u16(p);
    p += 2;
    remaining -= 2;
    if (ext_total_len > remaining) {
        LOG_WARN("parse_tls: ClientHello extensions_len %u > remaining %zu",
                 ext_total_len, remaining);
        return 0;
    }
    remaining = ext_total_len;  /* 只遍历声明范围内的扩展 */

    /* 遍历 extensions，查找 SNI (type=0x0000) */
    while (remaining >= 4) {
        uint16_t ext_type = read_u16(p);
        uint16_t ext_len  = read_u16(p + 2);

        p += 4;
        remaining -= 4;

        if (ext_len > remaining) {
            LOG_WARN("parse_tls: extension %u length %u exceeds remaining %zu",
                     ext_type, ext_len, remaining);
            break;
        }

        if (ext_type == TLS_EXT_SNI && ext_len > 0) {
            /* ——— 解析 SNI（Server Name Indication）——— */
            const uint8_t *sni_data = p;
            size_t sni_remaining = ext_len;

            if (sni_remaining < 2) break;
            uint16_t name_list_len = read_u16(sni_data);
            sni_data += 2;
            sni_remaining -= 2;

            if (name_list_len > sni_remaining) break;

            /* 取第一个 server_name（通常只有一个） */
            if (sni_remaining < 1) break;
            uint8_t name_type = sni_data[0];  /* 0x00 = host_name */
            if (sni_remaining < 3) break;
            uint16_t name_len = read_u16(sni_data + 1);

            if (name_type == 0x00 && name_len > 0 && name_len <= sni_remaining - 3) {
                size_t copy_len = name_len;
                if (copy_len >= sni_len)
                    copy_len = sni_len - 1;
                memcpy(sni_out, sni_data + 3, copy_len);
                sni_out[copy_len] = '\0';
            }
            /* 找到 SNI 扩展后无需继续遍历 */
            break;
        }

        p += ext_len;
        remaining -= ext_len;
    }

    return 0;
}

/* ============================================================
 *  parse_server_hello — 解析 ServerHello 消息体
 *
 *  参数：
 *    body — 指向 Handshake body
 *    len  — body 长度
 *    ver_out — [输出] ServerHello 协议版本
 *    cipher_out — [输出] 选定的 cipher suite
 *
 *  返回 0 成功，-1 输入无效。
 * ============================================================ */
static int parse_server_hello(const uint8_t *body, size_t len,
                              uint16_t *ver_out, uint16_t *cipher_out)
{
    if (ver_out)   *ver_out   = 0;
    if (cipher_out) *cipher_out = 0;

    /* 最小固定部分：version(2) + random(32) + session_id_len(1) = 35 */
    if (len < 35) {
        LOG_WARN("parse_tls: ServerHello body truncated (%zu < 35)", len);
        return -1;
    }

    uint16_t version = read_u16(body);
    if (ver_out) *ver_out = version;

    /* 跳过 version(2) + random(32) */
    const uint8_t *p = body + 34;
    size_t remaining = len - 34;

    /* session_id */
    if (remaining < 1) return 0;
    uint8_t sid_len = p[0];
    p += 1;
    remaining -= 1;
    if (sid_len > 32 || remaining < sid_len) return 0;
    p += sid_len;
    remaining -= sid_len;

    /* cipher_suite(2) + compression(1) */
    if (remaining < 3) return 0;
    uint16_t cipher_suite = read_u16(p);
    if (cipher_out) *cipher_out = cipher_suite;

    return 0;
}

/* ============================================================
 *  parse_tls — 公共入口
 *
 *  解析 TLS Record Layer 首部，识别 Handshake 记录并分发给
 *  ClientHello / ServerHello 解析函数。
 * ============================================================ */
int parse_tls(const uint8_t *pkt, size_t len)
{
    if (pkt == NULL) {
        LOG_ERROR("parse_tls: null packet");
        return -1;
    }
    if (len < TLS_RECORD_HDR_LEN) {
        LOG_ERROR("parse_tls: truncated record header (len=%zu, need=%d)",
                  len, TLS_RECORD_HDR_LEN);
        return -1;
    }

    const struct tls_record_hdr *rec = (const struct tls_record_hdr *)pkt;

    /* 只处理 Handshake 记录 */
    if (rec->content_type != TLS_CONTENT_HANDSHAKE) {
        return 0;
    }

    uint16_t rec_len = ntohs(rec->length);

    /* 校验记录长度 */
    if (rec_len < TLS_HANDSHAKE_HDR_LEN) {
        LOG_WARN("parse_tls: record length %u too small for handshake header", rec_len);
        return 0;
    }
    if (rec_len > len - TLS_RECORD_HDR_LEN) {
        LOG_WARN("parse_tls: record length %u exceeds buffer (%zu)", rec_len,
                 len - TLS_RECORD_HDR_LEN);
        return 0;
    }

    /* 定位 Handshake 头部 */
    const uint8_t *hs = pkt + TLS_RECORD_HDR_LEN;
    size_t hs_buf_remaining = rec_len;

    const struct tls_handshake_hdr *hsh =
        (const struct tls_handshake_hdr *)hs;

    uint32_t hs_len = read_u24(hsh->length);
    if (hs_len > hs_buf_remaining - TLS_HANDSHAKE_HDR_LEN) {
        LOG_WARN("parse_tls: handshake length %u exceeds record payload %zu",
                 hs_len, hs_buf_remaining - TLS_HANDSHAKE_HDR_LEN);
        return 0;
    }

    /* 消息体指针与长度 */
    const uint8_t *body = hs + TLS_HANDSHAKE_HDR_LEN;
    size_t body_len = hs_len;
    int rc = 0;

    switch (hsh->type) {
    case TLS_HANDSHAKE_CLIENT_HELLO: {
        uint16_t version = 0;
        char sni[256] = "";
        parse_client_hello(body, body_len, &version, sni, sizeof(sni));
        printf("TLS : ClientHello ver=%u.%u%s%s\n",
               version >> 8, version & 0xFF,
               sni[0] ? " sni=" : "",
               sni[0] ? sni : "");
        break;
    }
    case TLS_HANDSHAKE_SERVER_HELLO: {
        uint16_t version = 0;
        uint16_t cipher = 0;
        parse_server_hello(body, body_len, &version, &cipher);
        printf("TLS : ServerHello ver=%u.%u cipher=0x%04x\n",
               version >> 8, version & 0xFF, cipher);
        break;
    }
    default:
        /* 其他握手类型（Certificate, Finished, etc.）忽略 */
        break;
    }

    return rc;
}
