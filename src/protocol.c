#include "protocol.h"
#include "common.h"

/*
 * protocol.c — 协议解析实现
 *
 * 提供从链路层到传输层的逐层解析入口：
 *   parse_eth  → parse_ipv4 / parse_ipv6
 *              → parse_tcp / parse_udp / parse_icmp（按 proto/next_hdr 分发）
 *
 * 所有 parser 接受原始包缓冲区和长度，约定：
 *   pkt    — 指向当前层起始位置的字节流（不一定包头，libpcap 回调中即为整包）
 *   len    — 从 pkt 起可安全访问的字节数
 * 返回 0 表示成功，-1 表示输入不合法（截断、版本号错误、IHL 越界等）。
 * 解析结果通过 stdout 以 tcpdump 风格的一行摘要打印，便于联调与抓包对照。
 */

/* ============================================================
 *                         内部辅助
 * ============================================================ */

/* Ethernet 类型名称表（按网络字节序存储的常见 Ethertype） */
static const char *ethertype_name(uint16_t type)
{
    switch (type) {
    case ETH_TYPE_IPV4:  return "IPv4";
    case ETH_TYPE_IPV6:  return "IPv6";
    case ETH_TYPE_ARP:   return "ARP";
    case ETH_TYPE_VLAN:  return "VLAN";
    default:             return NULL;
    }
}

/* IPv4 协议号名称 */
static const char *ipv4_proto_name(uint8_t proto)
{
    switch (proto) {
    case IP_PROTO_ICMP:   return "ICMP";
    case IP_PROTO_TCP:    return "TCP";
    case IP_PROTO_UDP:    return "UDP";
    case IP_PROTO_ICMPV6: return "ICMPv6";     /* IPv4 中极少见，作防御性映射 */
    default:              return NULL;
    }
}

/* IPv6 next header 名称（与 IPv4 共用同一组常量） */
static const char *ipv6_next_name(uint8_t next)
{
    switch (next) {
    case IP_PROTO_ICMP:   return "ICMP";
    case IP_PROTO_TCP:    return "TCP";
    case IP_PROTO_UDP:    return "UDP";
    case IP_PROTO_ICMPV6: return "ICMPv6";
    default:              return NULL;
    }
}

/* 格式化 MAC 地址为 "aa:bb:cc:dd:ee:ff"。outlen >= 18 */
static void format_mac(const uint8_t *mac, char *out, size_t outlen)
{
    if (outlen < 18) {
        if (outlen > 0) out[0] = '\0';
        return;
    }
    snprintf(out, outlen, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* 格式化 IPv4 地址。outlen >= INET_ADDRSTRLEN(16) */
static void format_ipv4(uint32_t addr /* 网络字节序 */, char *out, size_t outlen)
{
    struct in_addr a;
    a.s_addr = addr;
    if (!inet_ntop(AF_INET, &a, out, (int)outlen)) {
        snprintf(out, outlen, "?");
    }
}

/* 格式化 IPv6 地址。outlen >= INET6_ADDRSTRLEN(46) */
static void format_ipv6(const uint8_t *addr, char *out, size_t outlen)
{
    struct in6_addr a;
    memcpy(&a, addr, sizeof(a));
    if (!inet_ntop(AF_INET6, &a, out, (int)outlen)) {
        snprintf(out, outlen, "?");
    }
}

/* IPv4 frag_off 字段中 flag 集合转字符串，例如 "DF" / "MF" / "DF+MF" / "" */
static const char *ipv4_frag_flags_str(uint16_t frag_off /* 网络字节序 */)
{
    /* 主机序 flags 位 */
    static char buf[16];
    uint16_t flags = ntohs(frag_off) >> 13;  /* 高 3 位 */
    buf[0] = '\0';
    if (flags & 0x4) strcat(buf, "DF");
    if (flags & 0x2) { if (buf[0]) strcat(buf, "+"); strcat(buf, "MF"); }
    if (flags & 0x1) { if (buf[0]) strcat(buf, "+"); strcat(buf, "RF"); }
    return buf;
}

/* TCP 标志位按常见顺序拼接为字符串，例如 "SYN" / "SYN+ACK" / "FIN+ACK+PSH" / "None"。
 * 使用 static buffer，调用方应立即使用返回值，不要跨调用持有。 */
static const char *tcp_flags_str(uint8_t flags)
{
    static char buf[32];
    buf[0] = '\0';
    /* 顺序与 tcpdump 习惯一致：SYN/ACK/FIN/RST/PSH/URG/ECE/CWR */
    if (flags & TCP_FLAG_SYN) strcat(buf, "SYN");
    if (flags & TCP_FLAG_ACK) { if (buf[0]) strcat(buf, "+"); strcat(buf, "ACK"); }
    if (flags & TCP_FLAG_FIN) { if (buf[0]) strcat(buf, "+"); strcat(buf, "FIN"); }
    if (flags & TCP_FLAG_RST) { if (buf[0]) strcat(buf, "+"); strcat(buf, "RST"); }
    if (flags & TCP_FLAG_PSH) { if (buf[0]) strcat(buf, "+"); strcat(buf, "PSH"); }
    if (flags & TCP_FLAG_URG) { if (buf[0]) strcat(buf, "+"); strcat(buf, "URG"); }
    if (flags & TCP_FLAG_ECE) { if (buf[0]) strcat(buf, "+"); strcat(buf, "ECE"); }
    if (flags & TCP_FLAG_CWR) { if (buf[0]) strcat(buf, "+"); strcat(buf, "CWR"); }
    if (buf[0] == '\0') strcpy(buf, "None");
    return buf;
}

/* ICMP/ICMPv6 type 字段转可读名称。返回 NULL 表示未识别。
 * is_ipv6 = 0 用 RFC 792 常量；is_ipv6 = 1 用 RFC 4443 常见常量。 */
static const char *icmp_type_name(uint8_t type, int is_ipv6)
{
    if (!is_ipv6) {
        switch (type) {
        case ICMP_TYPE_ECHO_REPLY:    return "Echo Reply";
        case ICMP_TYPE_DEST_UNREACH:  return "Destination Unreachable";
        case ICMP_TYPE_SRC_QUENCH:    return "Source Quench";
        case ICMP_TYPE_REDIRECT:      return "Redirect";
        case ICMP_TYPE_ECHO_REQUEST:  return "Echo Request";
        case ICMP_TYPE_TIME_EXCEEDED: return "Time Exceeded";
        case ICMP_TYPE_PARAM_PROBLEM: return "Parameter Problem";
        default:                      return NULL;
        }
    } else {
        switch (type) {
        case ICMPV6_TYPE_DEST_UNREACH: return "Destination Unreachable";
        case ICMPV6_TYPE_ECHO_REQUEST: return "Echo Request";
        case ICMPV6_TYPE_ECHO_REPLY:   return "Echo Reply";
        default:                       return NULL;
        }
    }
}

/* ============================================================
 *                     parse_ipv4 — RFC 791
 * ============================================================ */

/*
 * 解析一段以 IPv4 头起始的数据。
 * 成功时打印一行摘要并返回 0；长度不足 / IHL 越界 / 版本错误返回 -1。
 *
 * 重要：IHL 字段以 4 字节为单位，最小为 5 (20 字节)。
 *       入参 len 仅保证头本身；载荷是否足够留给上层解析。
 */
int parse_ipv4(const uint8_t *pkt, size_t len)
{
    if (pkt == NULL) {
        LOG_ERROR("parse_ipv4: null packet");
        return -1;
    }
    if (len < sizeof(struct ipv4_hdr)) {
        LOG_ERROR("parse_ipv4: truncated header (len=%zu, need=%zu)",
                  len, sizeof(struct ipv4_hdr));
        return -1;
    }

    const struct ipv4_hdr *h = (const struct ipv4_hdr *)pkt;

    /* 版本必须为 4 */
    if (IPV4_VERSION(h) != 4) {
        LOG_ERROR("parse_ipv4: bad version %u", IPV4_VERSION(h));
        return -1;
    }

    /* IHL 合法范围：[5, 15] */
    size_t ihl = IPV4_IHL(h);
    if (ihl < 20 || ihl > 60 || (ihl % 4) != 0) {
        LOG_ERROR("parse_ipv4: bad IHL=%zu", ihl);
        return -1;
    }
    if (len < ihl) {
        LOG_ERROR("parse_ipv4: header (ihl=%zu) exceeds buffer (len=%zu)", ihl, len);
        return -1;
    }

    /* 按主机序整理供打印 */
    uint16_t total_len = ntohs(h->total_len);
    uint16_t ident     = ntohs(h->ident);
    uint16_t frag_off  = ntohs(h->frag_off);
    uint16_t frag_ofs  = frag_off & 0x1FFF;        /* 低 13 位 */
    const char *flags  = ipv4_frag_flags_str(h->frag_off);
    const char *pname  = ipv4_proto_name(h->proto);

    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    format_ipv4(h->src, src, sizeof(src));
    format_ipv4(h->dst, dst, sizeof(dst));

    printf("IPv4: %s -> %s | proto=%u(%s) ttl=%u ihl=%zu total_len=%u "
           "id=0x%04x frag=%s@%u cksum=0x%04x\n",
           src, dst,
           h->proto, pname ? pname : "Unknown",
           h->ttl, ihl, total_len,
           ident, flags, frag_ofs,
           ntohs(h->checksum));

    /* Day 3：依据 proto 分发到 L4 parser。
     * 载荷起点 = pkt + ihl；长度取 min(总长-IHL, 缓冲区剩余)，避免越过 IP 包边界。 */
    const uint8_t *l4 = pkt + ihl;
    size_t l4_len = len - ihl;
    if (total_len > ihl) {
        size_t from_total = (size_t)total_len - ihl;
        if (from_total < l4_len) l4_len = from_total;
    }
    if (l4_len == 0) {
        return 0;  /* 仅 IP 头，无载荷 */
    }

    int rc = 0;
    switch (h->proto) {
    case IP_PROTO_TCP:
        rc = parse_tcp(l4, l4_len);
        break;
    case IP_PROTO_UDP:
        rc = parse_udp(l4, l4_len);
        break;
    case IP_PROTO_ICMP:
        rc = parse_icmp(l4, l4_len, 0);
        break;
    default:
        /* 未识别的 L4 协议（如 IGMP=2、SCTP=132）或扩展协议：不递归 */
        break;
    }

    return rc;
}

/* ============================================================
 *                     parse_ipv6 — RFC 8200
 * ============================================================ */

/*
 * 解析一段以 IPv6 头起始的数据。
 * IPv6 固定首部 40 字节，无 options；本函数不处理扩展头（hop-by-hop、
 * routing、fragment 等），遇到 next_hdr == 41/0/43/44/50/51/60 等扩展头类型
 * 时仅打印提示并返回，由 Day 3+ 后续工作补全。
 */
int parse_ipv6(const uint8_t *pkt, size_t len)
{
    if (pkt == NULL) {
        LOG_ERROR("parse_ipv6: null packet");
        return -1;
    }
    if (len < sizeof(struct ipv6_hdr)) {
        LOG_ERROR("parse_ipv6: truncated header (len=%zu, need=%zu)",
                  len, sizeof(struct ipv6_hdr));
        return -1;
    }

    const struct ipv6_hdr *h = (const struct ipv6_hdr *)pkt;

    if (IPV6_VERSION(h) != 6) {
        LOG_ERROR("parse_ipv6: bad version %u", IPV6_VERSION(h));
        return -1;
    }

    uint16_t plen = ntohs(h->payload_len);
    uint32_t ver_tc_fl = ntohl(h->ver_tc_fl);
    uint8_t  tc   = (ver_tc_fl >> 20) & 0xFF;
    uint32_t fl   = ver_tc_fl & 0xFFFFF;
    const char *nname = ipv6_next_name(h->next_hdr);

    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    format_ipv6(h->src, src, sizeof(src));
    format_ipv6(h->dst, dst, sizeof(dst));

    printf("IPv6: %s -> %s | next=%u(%s) hlim=%u plen=%u tc=0x%02x fl=0x%05x\n",
           src, dst,
           h->next_hdr, nname ? nname : "Unknown",
           h->hop_limit, plen, tc, fl);

    /* Day 3：按 next_hdr 分发到 L4 parser。
     * 载荷起点 = pkt + 40；长度取 min(payload_len, 缓冲区剩余)。
     * 注意：本函数尚未剥扩展头（hop-by-hop/routing/fragment 等），
     *       若 next_hdr 是扩展头类型则会落到 default 分支不解析。 */
    const uint8_t *l4 = pkt + sizeof(struct ipv6_hdr);
    size_t l4_len = len - sizeof(struct ipv6_hdr);
    if (plen < l4_len) l4_len = plen;
    if (l4_len == 0) {
        return 0;
    }

    int rc = 0;
    switch (h->next_hdr) {
    case IP_PROTO_TCP:
        rc = parse_tcp(l4, l4_len);
        break;
    case IP_PROTO_UDP:
        rc = parse_udp(l4, l4_len);
        break;
    case IP_PROTO_ICMP:
        /* IPv6 中 next_hdr=1 极少见，按 ICMPv4 处理以防误判 */
        rc = parse_icmp(l4, l4_len, 0);
        break;
    case IP_PROTO_ICMPV6:
        rc = parse_icmp(l4, l4_len, 1);
        break;
    default:
        /* 扩展头类型（hop-by-hop=0, routing=43, fragment=44, dest opt=60, AH=51）
         * 或未识别协议：不递归，Day 4+ 再补扩展头剥离。 */
        break;
    }

    return rc;
}

/* ============================================================
 *                    parse_eth — RFC 894
 * ============================================================ */

/*
 * 以太网入口。pkt 指向整包开头（libpcap 回调链路层），len 为整包可用字节数。
 * 成功解析后打印 MAC + EtherType；若是 IPv4/IPv6 则继续下钻到对应 parser。
 *
 * 注意：本函数默认入参不含 802.1Q VLAN tag；若上层确实见到了 VLAN 帧，
 * libpcap 在多数抓包场景下已经把它剥离（datalink == DLT_EN10MB），
 * 否则调用方需要先自行处理 4 字节 VLAN tag 再调用本函数。
 */
int parse_eth(const uint8_t *pkt, size_t len)
{
    if (pkt == NULL) {
        LOG_ERROR("parse_eth: null packet");
        return -1;
    }
    if (len < ETH_HDR_LEN) {
        LOG_ERROR("parse_eth: truncated ethernet header (len=%zu, need=%u)",
                  len, ETH_HDR_LEN);
        return -1;
    }

    const struct eth_hdr *h = (const struct eth_hdr *)pkt;

    char dmac[18], smac[18];
    format_mac(h->dst, dmac, sizeof(dmac));
    format_mac(h->src, smac, sizeof(smac));

    /* type 字段已是网络字节序，但此处仅用作查表/打印，统一转主机序以便人读 */
    uint16_t type = ntohs(h->type);
    const char *tname = ethertype_name(type);

    printf("ETH : %s -> %s | type=0x%04x(%s)\n",
           smac, dmac, type, tname ? tname : "Unknown");

    /* 继续下钻：载荷起点 = pkt + 14，长度 = len - 14 */
    const uint8_t *payload = pkt + ETH_HDR_LEN;
    size_t plen = len - ETH_HDR_LEN;

    int rc = 0;
    if (type == ETH_TYPE_IPV4) {
        rc = parse_ipv4(payload, plen);
    } else if (type == ETH_TYPE_IPV6) {
        rc = parse_ipv6(payload, plen);
    } else {
        /* ARP / VLAN / 其它 EtherType：Day 2 暂不深入。
         * 后续可在此处补 parse_arp / VLAN tag 剥离。 */
    }

    return rc;
}

/* ============================================================
 *                     parse_tcp — RFC 793
 * ============================================================ */

/*
 * 解析一段以 TCP 头起始的数据。
 * 成功打印端口、SEQ/ACK、Flags（字符串形式）、窗口/校验和/紧急指针/首部长度。
 * data_off 以 4 字节为单位，必须落在 [5, 15] 且 4 字节对齐。
 */
int parse_tcp(const uint8_t *pkt, size_t len)
{
    if (pkt == NULL) {
        LOG_ERROR("parse_tcp: null packet");
        return -1;
    }
    if (len < TCP_HDR_MIN_LEN) {
        LOG_ERROR("parse_tcp: truncated header (len=%zu, need=%u)",
                  len, TCP_HDR_MIN_LEN);
        return -1;
    }

    const struct tcp_hdr *h = (const struct tcp_hdr *)pkt;

    /* data_off 高 4 位为头部长度，单位 4 字节。合法范围 [5, 15] */
    size_t hdr_len = TCP_DATA_OFFSET(h);
    if (hdr_len < TCP_HDR_MIN_LEN || hdr_len > 60 || (hdr_len % 4) != 0) {
        LOG_ERROR("parse_tcp: bad data offset %zu", hdr_len);
        return -1;
    }

    uint16_t src_port = ntohs(h->src_port);
    uint16_t dst_port = ntohs(h->dst_port);
    uint32_t seq      = ntohl(h->seq);
    uint32_t ack      = ntohl(h->ack);
    uint16_t window   = ntohs(h->window);
    uint16_t checksum = ntohs(h->checksum);
    uint16_t urgent   = ntohs(h->urgent);
    const char *flags = tcp_flags_str(h->flags);

    printf("TCP : %u -> %u | seq=0x%08x ack=0x%08x flags=%s "
           "win=%u cksum=0x%04x urg=%u hdr=%zu\n",
           src_port, dst_port,
           seq, ack, flags,
           window, checksum, urgent, hdr_len);

    return 0;
}

/* ============================================================
 *                     parse_udp — RFC 768
 * ============================================================ */

/*
 * 解析一段以 UDP 头起始的数据。
 * UDP 固定首部 8 字节，length 字段含首部本身。checksum 为 0 表示未启用（IPv4）。
 */
int parse_udp(const uint8_t *pkt, size_t len)
{
    if (pkt == NULL) {
        LOG_ERROR("parse_udp: null packet");
        return -1;
    }
    if (len < UDP_HDR_LEN) {
        LOG_ERROR("parse_udp: truncated header (len=%zu, need=%u)",
                  len, UDP_HDR_LEN);
        return -1;
    }

    const struct udp_hdr *h = (const struct udp_hdr *)pkt;

    uint16_t src_port = ntohs(h->src_port);
    uint16_t dst_port = ntohs(h->dst_port);
    uint16_t length   = ntohs(h->length);
    uint16_t checksum = ntohs(h->checksum);

    printf("UDP : %u -> %u | len=%u cksum=0x%04x\n",
           src_port, dst_port,
           length, checksum);

    return 0;
}

/* ============================================================
 *                  parse_icmp — RFC 792 / RFC 4443
 * ============================================================ */

/*
 * 解析一段以 ICMP/ICMPv6 头起始的数据。
 * ICMP 与 ICMPv6 头布局相同（type + code + checksum + 4 字节），
 * 仅 type 常量集不同。is_ipv6 = 1 时按 RFC 4443 解释类型；否则按 RFC 792。
 */
int parse_icmp(const uint8_t *pkt, size_t len, int is_ipv6)
{
    if (pkt == NULL) {
        LOG_ERROR("parse_icmp: null packet");
        return -1;
    }
    if (len < ICMP_HDR_LEN) {
        LOG_ERROR("parse_icmp: truncated header (len=%zu, need=%u)",
                  len, ICMP_HDR_LEN);
        return -1;
    }

    const struct icmp_hdr *h = (const struct icmp_hdr *)pkt;

    uint16_t id  = ntohs(h->id);
    uint16_t seq = ntohs(h->seq);
    const char *tname = icmp_type_name(h->type, is_ipv6);

    printf("%s: type=%u(%s) code=%u cksum=0x%04x id=%u seq=%u\n",
           is_ipv6 ? "ICMPv6" : "ICMP",
           h->type, tname ? tname : "Unknown",
           h->code, ntohs(h->checksum),
           id, seq);

    return 0;
}
