/*
 * stats.c — 实时流量统计实现
 *
 * 职责：
 *   - 按协议分类统计包数 & 字节数 (TCP / UDP / ICMP / HTTP / HTTPS / DNS / Other)
 *   - 每秒刷新一次打印（由 dispatch_packet 中驱动，有包就检查时间）
 *
 * 分类逻辑基于端口号（HTTP=80/8080, HTTPS=443, DNS=53），不依赖 B 的 parse_dns/parse_http。
 */

#include "common.h"
#include "protocol.h"
#include "stats.h"

/* ================================================================
 *  内部数据
 * ================================================================ */

static struct proto_stats g_stats[STAT_COUNT] = {
    [STAT_TCP]    = { .name = "TCP" },
    [STAT_UDP]    = { .name = "UDP" },
    [STAT_ICMP]   = { .name = "ICMP" },
    [STAT_HTTP]   = { .name = "HTTP" },
    [STAT_HTTPS]  = { .name = "HTTPS" },
    [STAT_DNS]    = { .name = "DNS" },
    [STAT_OTHER]  = { .name = "Other" },
};

static time_t   g_last_print = 0;
static time_t   g_start_time = 0;
static uint64_t g_total_pkts = 0;
static int      g_auto_print = 1;  /* 默认开启，UI 模式关闭 */

/* ================================================================
 *  内部分类：根据原始包快速判断协议
 *  只解析到 L4 端口即停止，不深入应用层。
 * ================================================================ */

static stat_proto_t classify(const uint8_t *pkt, uint32_t len)
{
    if (len < ETH_HDR_LEN)
        return STAT_OTHER;

    const struct eth_hdr *eth = (const struct eth_hdr *)pkt;
    uint16_t eth_type = ntohs(eth->type);

    /* VLAN 跳过（极少数场景） */
    if (eth_type == ETH_TYPE_VLAN) {
        if (len < ETH_HDR_LEN + 4)
            return STAT_OTHER;
        eth_type = ntohs(*(const uint16_t *)(pkt + ETH_HDR_LEN + 2));
    }

    if (eth_type != ETH_TYPE_IPV4 && eth_type != ETH_TYPE_IPV6)
        return STAT_OTHER;

    /* 计算 L3 起始偏移 */
    uint32_t l3_off = ETH_HDR_LEN;
    if (ntohs(eth->type) == ETH_TYPE_VLAN)
        l3_off += 4;

    if (eth_type == ETH_TYPE_IPV4) {
        if (len < l3_off + sizeof(struct ipv4_hdr))
            return STAT_OTHER;
        const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(pkt + l3_off);
        uint8_t hlen = IPV4_IHL(ip);
        if (hlen < sizeof(struct ipv4_hdr) || len < l3_off + hlen)
            return STAT_OTHER;

        switch (ip->proto) {
        case IP_PROTO_TCP:
            if (len >= l3_off + hlen + sizeof(struct tcp_hdr)) {
                const struct tcp_hdr *tcp =
                    (const struct tcp_hdr *)(pkt + l3_off + hlen);
                uint16_t dport = ntohs(tcp->dst_port);
                uint16_t sport = ntohs(tcp->src_port);
                if (sport == 80 || dport == 80 ||
                    sport == 8080 || dport == 8080)
                    return STAT_HTTP;
                if (sport == 443 || dport == 443)
                    return STAT_HTTPS;
            }
            return STAT_TCP;
        case IP_PROTO_UDP:
            if (len >= l3_off + hlen + sizeof(struct udp_hdr)) {
                const struct udp_hdr *udp =
                    (const struct udp_hdr *)(pkt + l3_off + hlen);
                uint16_t dport = ntohs(udp->dst_port);
                uint16_t sport = ntohs(udp->src_port);
                if (sport == 53 || dport == 53)
                    return STAT_DNS;
            }
            return STAT_UDP;
        case IP_PROTO_ICMP:
            return STAT_ICMP;
        default:
            return STAT_OTHER;
        }
    } else {
        /* IPv6：简化处理，不追踪扩展头链 */
        if (len < l3_off + sizeof(struct ipv6_hdr))
            return STAT_OTHER;
        const struct ipv6_hdr *ip6 = (const struct ipv6_hdr *)(pkt + l3_off);
        uint32_t l4_off = l3_off + sizeof(struct ipv6_hdr);

        switch (ip6->next_hdr) {
        case IP_PROTO_TCP:
            if (len >= l4_off + sizeof(struct tcp_hdr)) {
                const struct tcp_hdr *tcp =
                    (const struct tcp_hdr *)(pkt + l4_off);
                uint16_t dport = ntohs(tcp->dst_port);
                uint16_t sport = ntohs(tcp->src_port);
                if (sport == 80 || dport == 80 ||
                    sport == 8080 || dport == 8080)
                    return STAT_HTTP;
                if (sport == 443 || dport == 443)
                    return STAT_HTTPS;
            }
            return STAT_TCP;
        case IP_PROTO_UDP:
            if (len >= l4_off + sizeof(struct udp_hdr)) {
                const struct udp_hdr *udp =
                    (const struct udp_hdr *)(pkt + l4_off);
                uint16_t dport = ntohs(udp->dst_port);
                uint16_t sport = ntohs(udp->src_port);
                if (sport == 53 || dport == 53)
                    return STAT_DNS;
            }
            return STAT_UDP;
        case IP_PROTO_ICMPV6:
            return STAT_ICMP;
        default:
            return STAT_OTHER;
        }
    }
}

/* ================================================================
 *  公开接口
 * ================================================================ */

const struct proto_stats *stats_get(stat_proto_t proto)
{
    if (proto >= STAT_COUNT) return NULL;
    return &g_stats[proto];
}

void stats_update(const uint8_t *packet, uint32_t len)
{
    stat_proto_t p = classify(packet, len);
    g_stats[p].pkt_count++;
    g_stats[p].byte_count += len;
    g_total_pkts++;

    /* 记录起始时间 */
    if (g_start_time == 0)
        g_start_time = time(NULL);

    /* 每秒刷新：由 dispatch_packet 驱动，有包才检查 */
    time_t now = time(NULL);
    if (g_auto_print && now != g_last_print) {
        g_last_print = now;
        stats_print();
    }
}

void stats_print(void)
{
    printf("\n--------------------------------------------------\n");
    printf("  %-8s %12s %15s\n", "Proto", "Packets", "Bytes");
    printf("--------------------------------------------------\n");

    uint64_t total_pkts = 0, total_bytes = 0;
    for (int i = 0; i < STAT_COUNT; i++) {
        if (g_stats[i].pkt_count == 0 && g_stats[i].byte_count == 0)
            continue;
        printf("  %-8s %12lu %15lu\n",
               g_stats[i].name,
               (unsigned long)g_stats[i].pkt_count,
               (unsigned long)g_stats[i].byte_count);
        total_pkts  += g_stats[i].pkt_count;
        total_bytes += g_stats[i].byte_count;
    }

    printf("--------------------------------------------------\n");

    /* 实时速率 */
    if (g_start_time > 0) {
        time_t elapsed = time(NULL) - g_start_time;
        if (elapsed < 1) elapsed = 1;
        unsigned long pps = (unsigned long)(g_total_pkts / (uint64_t)elapsed);
        unsigned long bps = (unsigned long)(total_bytes / (uint64_t)elapsed);
        printf("  %-8s %12lu %15lu  %lu pkt/s, %lu B/s\n", "Total",
               (unsigned long)total_pkts, (unsigned long)total_bytes,
               pps, bps);
    } else {
        printf("  %-8s %12lu %15lu\n", "Total",
               (unsigned long)total_pkts, (unsigned long)total_bytes);
    }
    printf("--------------------------------------------------\n\n");
}

void stats_reset(void)
{
    for (int i = 0; i < STAT_COUNT; i++) {
        g_stats[i].pkt_count  = 0;
        g_stats[i].byte_count = 0;
    }
    g_last_print = 0;
}

void stats_set_auto_print(int enable)
{
    g_auto_print = enable;
}
