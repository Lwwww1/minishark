#ifndef TLS_PARSER_H
#define TLS_PARSER_H

/*
 * tls_parser.h — TLS 记录层与握手协议解析（ClientHello / ServerHello / SNI）
 *
 * 解析范围：
 *   - TLS Record Layer 头（content_type + version + length）
 *   - Handshake Protocol 头（handshake_type + length）
 *   - ClientHello：提取 SNI（Server Name Indication，RFC 6066）
 *   - ServerHello：输出版本与 cipher suite
 *
 * 符合 RFC 8446 (TLS 1.3) 与 RFC 6066 (SNI) 线路格式。
 * 仅解析单个 TCP 段内的完整 TLS Record；跨段分片需由 TCP 重组层处理后馈入。
 */

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 *  常量定义
 * ============================================================ */

/* TLS Record Layer Content Types — RFC 8446 §5 */
#define TLS_CONTENT_CHANGE_CIPHER  0x14  /* Change Cipher Spec */
#define TLS_CONTENT_ALERT          0x15  /* Alert */
#define TLS_CONTENT_HANDSHAKE      0x16  /* Handshake */
#define TLS_CONTENT_APP_DATA       0x17  /* Application Data */

/* TLS Handshake Types — RFC 8446 §4 */
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01  /* ClientHello */
#define TLS_HANDSHAKE_SERVER_HELLO 0x02  /* ServerHello */

/* TLS Extension Types — RFC 6066 §3 */
#define TLS_EXT_SNI                0x0000 /* Server Name Indication */

/* 固定头部长度常量 */
#define TLS_RECORD_HDR_LEN   5    /* content_type(1) + version(2) + length(2) */
#define TLS_HANDSHAKE_HDR_LEN 4   /* handshake_type(1) + length(3) */

/* ============================================================
 *  线路格式结构体（packed，可直接强制转换读取）
 * ============================================================ */

/* TLS Record Layer 固定首部 — RFC 8446 §5.1 */
struct tls_record_hdr {
    uint8_t  content_type;       /* 内容类型 */
    uint8_t  version[2];         /* 协议版本（大端） */
    uint16_t length;             /* 负载长度（网络字节序） */
} __attribute__((packed));

/* TLS Handshake 固定首部 — RFC 8446 §4 */
struct tls_handshake_hdr {
    uint8_t  type;               /* 握手消息类型 */
    uint8_t  length[3];          /* 消息体长度（24 位大端） */
} __attribute__((packed));

/* ============================================================
 *  函数声明
 * ============================================================ */

/*
 * parse_tls — 解析一段以 TLS Record 首部起始的数据。
 *
 * 参数：
 *   pkt — 指向 TLS Record 起始位置（TCP 载荷起点）
 *   len — 可安全访问的字节数
 *
 * 返回：
 *   0  — 解析成功，或内容无需处理（非 Handshake 记录、未识别的握手类型）
 *  -1  — 输入无效（NULL、首部截断）
 *
 * 输出（stdout）：
 *   "TLS : ClientHello ver=%x.%x sni=<域名>\n"
 *   "TLS : ServerHello ver=%x.%x cipher=0x%04x\n"
 */
int parse_tls(const uint8_t *pkt, size_t len);

#endif /* TLS_PARSER_H */
