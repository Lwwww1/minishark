/*
 * capture.c — 抓包引擎实现
 *
 * 职责：
 *   - 通过 libpcap 打开网卡、设置混杂模式
 *   - 在抓包回调中逐层解析协议（L2→L3→L4）
 *   - 留好 BPF 过滤器接口（Day 3 集成）
 *
 * 本文件暂时内联了基本的协议解析打印逻辑。
 * 等 B 同学的 protocol.c 就绪后，可将打印逻辑迁移过去，
 * capture.c 只负责抓包和分发给 parse_eth() 等函数。
 */

#include "common.h"
#include "capture.h"
#include "protocol.h"

/* ================================================================
 *  内部状态
 * ================================================================ */

static pcap_t *g_handle = NULL;   /* 供 signal_handler 调用 capture_stop */

/* ================================================================
 *  辅助：MAC 地址格式化
 * ================================================================ */

static const char *mac_ntoa(const uint8_t *mac)
{
    static char buf[7][18]; /* 支持 7 个并发调用 */
    static int idx = 0;
    char *b = buf[idx];
    idx = (idx + 1) % 7;
    snprintf(b, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return b;
}

/* ================================================================
 *  辅助：IP 地址格式化
 * ================================================================ */

static const char *ip4_ntoa(uint32_t ip)
{
    struct in_addr a;
    a.s_addr = ip;
    return inet_ntoa(a);
}

static const char *ip6_ntoa(const uint8_t *ip6)
{
    static char buf[7][INET6_ADDRSTRLEN];
    static int idx = 0;
    char *b = buf[idx];
    idx = (idx + 1) % 7;
    return inet_ntop(AF_INET6, ip6, b, INET6_ADDRSTRLEN);
}

/* ================================================================
 *  辅助：协议名
 * ================================================================ */

static const char *proto_name(uint8_t proto)
{
    switch (proto) {
    case IP_PROTO_ICMP:   return "ICMP";
    case IP_PROTO_TCP:    return "TCP";
    case IP_PROTO_UDP:    return "UDP";
    default:              return "???";
    }
}

/* ================================================================
 *  辅助：帧类型 (Ethertype)
 * ================================================================ */

static const char *eth_type_name(uint16_t type)
{
    switch (type) {
    case ETH_TYPE_IPV4: return "IPv4";
    case ETH_TYPE_ARP:  return "ARP";
    case ETH_TYPE_VLAN: return "VLAN";
    case ETH_TYPE_IPV6: return "IPv6";
    default:            return "???";
    }
}

/* ================================================================
 *  各层打印函数（临时代替 B 同学 protocol.c 的 parse_* 函数）
 *  后续重构时替换为对 B 同学函数的调用即可。
 * ================================================================ */

static void print_eth(const struct eth_hdr *eth)
{
    uint16_t type = ntohs(eth->type);
    printf("  Eth:  %s -> %s  type=0x%04x(%s)\n",
           mac_ntoa(eth->src),
           mac_ntoa(eth->dst),
           type, eth_type_name(type));
}

static void print_ipv4(const struct ipv4_hdr *ip)
{
    uint8_t flags = (ntohs(ip->frag_off) & 0xE000) >> 13; /* 高 3 位 */

    printf("  IPv4: %s -> %s  proto=%u(%s)  ttl=%u  len=%u  "
           "DF=%u MF=%u\n",
           ip4_ntoa(ip->src),
           ip4_ntoa(ip->dst),
           ip->proto, proto_name(ip->proto),
           ip->ttl,
           ntohs(ip->total_len),
           (flags >> 1) & 1,   /* Don't Fragment */
           flags & 1);          /* More Fragments */
}

static void print_ipv6(const struct ipv6_hdr *ip6)
{
    printf("  IPv6: %s -> %s  next=%u  hop=%u  len=%u\n",
           ip6_ntoa(ip6->src),
           ip6_ntoa(ip6->dst),
           ip6->next_hdr,
           ip6->hop_limit,
           ntohs(ip6->payload_len));
}

static void print_tcp(const struct tcp_hdr *tcp)
{
    uint8_t fl = tcp->flags;
    printf("  TCP:  %u -> %u  SEQ=%u ACK=%u  "
           "flags=[%s%s%s%s%s%s%s%s%s]  win=%u\n",
           ntohs(tcp->src_port), ntohs(tcp->dst_port),
           ntohl(tcp->seq), ntohl(tcp->ack),
           (fl & TCP_FLAG_SYN) ? "S" : "",
           (fl & TCP_FLAG_ACK) ? "A" : "",
           (fl & TCP_FLAG_FIN) ? "F" : "",
           (fl & TCP_FLAG_RST) ? "R" : "",
           (fl & TCP_FLAG_PSH) ? "P" : "",
           (fl & TCP_FLAG_URG) ? "U" : "",
           (fl & TCP_FLAG_ECE) ? "E" : "",
           (fl & TCP_FLAG_CWR) ? "C" : "",
           (fl == 0)        ? "." : "",
           ntohs(tcp->window));
}

static void print_udp(const struct udp_hdr *udp)
{
    printf("  UDP:  %u -> %u  len=%u\n",
           ntohs(udp->src_port), ntohs(udp->dst_port),
           ntohs(udp->length));
}

static void print_icmp(const struct icmp_hdr *icmp)
{
    const char *type_str = "???";
    switch (icmp->type) {
    case ICMP_TYPE_ECHO_REPLY:   type_str = "EchoReply"; break;
    case ICMP_TYPE_DEST_UNREACH: type_str = "DestUnreach"; break;
    case ICMP_TYPE_ECHO_REQUEST: type_str = "EchoRequest"; break;
    case ICMP_TYPE_TIME_EXCEEDED:type_str = "TimeExceeded"; break;
    }
    printf("  ICMP: type=%u(%s) code=%u  id=%u seq=%u\n",
           icmp->type, type_str, icmp->code,
           ntohs(icmp->id), ntohs(icmp->seq));
}

/* ================================================================
 *  逐层解析：以太网 → IP → 传输层
 * ================================================================ */

void dispatch_packet(const struct pcap_pkthdr *header, const u_char *packet)
{
    /* 防止截断包 */
    if (header->caplen < ETH_HDR_LEN) {
        printf("[WARN] packet too short for Ethernet header (%u bytes)\n",
               header->caplen);
        return;
    }

    printf("=== Packet #%-6u  ts=%lu.%06lu  len=%u  caplen=%u ===\n",
           header->caplen, /* 简化计数器，后续可加全局 seq */
           (unsigned long)header->ts.tv_sec,
           (unsigned long)header->ts.tv_usec,
           header->len, header->caplen);

    /* ---------- L2: 以太网 ---------- */
    const struct eth_hdr *eth = (const struct eth_hdr *)packet;
    uint16_t eth_type = ntohs(eth->type);
    print_eth(eth);

    const u_char *l3 = packet + ETH_HDR_LEN;
    uint32_t l3_offset = ETH_HDR_LEN;

    /* 跳过 VLAN 标签（支持 802.1Q 单层） */
    if (eth_type == ETH_TYPE_VLAN && header->caplen >= ETH_HDR_LEN + 4) {
        uint16_t vlan_type = ntohs(*(const uint16_t *)(l3 + 2));
        printf("  VLAN: tpid=0x8100  tci=0x%04x  type=0x%04x\n",
               ntohs(*(const uint16_t *)l3), vlan_type);
        l3 += 4;
        l3_offset += 4;
        eth_type = vlan_type;
    }

    /* ---------- L3: IP ---------- */
    switch (eth_type) {
    case ETH_TYPE_IPV4: {
        if (header->caplen < l3_offset + sizeof(struct ipv4_hdr)) {
            printf("  [WARN] packet too short for IPv4 header\n");
            return;
        }
        const struct ipv4_hdr *ip = (const struct ipv4_hdr *)l3;
        uint8_t hlen = IPV4_IHL(ip);
        if (hlen < sizeof(struct ipv4_hdr)) {
            printf("  [WARN] invalid IPv4 IHL: %u\n", hlen);
            return;
        }
        print_ipv4(ip);

        if (header->caplen < l3_offset + hlen) {
            printf("  [WARN] packet truncated after IPv4 header\n");
            return;
        }
        const u_char *l4 = l3 + hlen;

        /* ---------- L4 ---------- */
        switch (ip->proto) {
        case IP_PROTO_TCP:
            if (header->caplen >= l3_offset + hlen + sizeof(struct tcp_hdr))
                print_tcp((const struct tcp_hdr *)l4);
            else
                printf("  [WARN] TCP header truncated\n");
            break;
        case IP_PROTO_UDP:
            if (header->caplen >= l3_offset + hlen + sizeof(struct udp_hdr))
                print_udp((const struct udp_hdr *)l4);
            else
                printf("  [WARN] UDP header truncated\n");
            break;
        case IP_PROTO_ICMP:
            if (header->caplen >= l3_offset + hlen + sizeof(struct icmp_hdr))
                print_icmp((const struct icmp_hdr *)l4);
            else
                printf("  [WARN] ICMP header truncated\n");
            break;
        default:
            printf("  L4:   proto=%u(%s)  payload=%u bytes\n",
                   ip->proto, proto_name(ip->proto),
                   (unsigned)(header->caplen > l3_offset + hlen
                              ? header->caplen - l3_offset - hlen : 0));
            break;
        }
        break;
    }
    case ETH_TYPE_IPV6: {
        if (header->caplen < l3_offset + sizeof(struct ipv6_hdr)) {
            printf("  [WARN] packet too short for IPv6 header\n");
            return;
        }
        const struct ipv6_hdr *ip6 = (const struct ipv6_hdr *)l3;
        print_ipv6(ip6);

        const u_char *l4 = l3 + sizeof(struct ipv6_hdr);

        /* 简化：不处理 IPv6 扩展头链，直接按 next_hdr 判断 */
        switch (ip6->next_hdr) {
        case IP_PROTO_TCP:
            if (header->caplen >= l3_offset + sizeof(struct ipv6_hdr) + sizeof(struct tcp_hdr))
                print_tcp((const struct tcp_hdr *)l4);
            break;
        case IP_PROTO_UDP:
            if (header->caplen >= l3_offset + sizeof(struct ipv6_hdr) + sizeof(struct udp_hdr))
                print_udp((const struct udp_hdr *)l4);
            break;
        case IP_PROTO_ICMPV6:
            if (header->caplen >= l3_offset + sizeof(struct ipv6_hdr) + sizeof(struct icmp_hdr))
                print_icmp((const struct icmp_hdr *)l4);
            break;
        default:
            printf("  L4:   next_hdr=%u  payload=%u bytes\n",
                   ip6->next_hdr,
                   (unsigned)(header->caplen > l3_offset + sizeof(struct ipv6_hdr)
                              ? header->caplen - l3_offset - sizeof(struct ipv6_hdr) : 0));
            break;
        }
        break;
    }
    case ETH_TYPE_ARP:
        printf("  (ARP packet, skipping...)\n");
        break;
    default:
        printf("  (unknown Ethertype 0x%04x, skipping...)\n", eth_type);
        break;
    }

    printf("\n");
}

/* ================================================================
 *  libpcap 回调（由 pcap_loop / pcap_dispatch 触发）
 *  这里只是把参数转发给 dispatch_packet，
 *  后续 Day 6~7 会改为写入环形缓冲区供另一线程消费。
 * ================================================================ */

static void pcap_callback(u_char *user, const struct pcap_pkthdr *header,
                          const u_char *packet)
{
    (void)user;
    dispatch_packet(header, packet);
}

/* ================================================================
 *  公开接口
 * ================================================================ */

pcap_t *capture_init(const char *iface, const char *filter_expr)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;

    /* -------- 确定网卡 -------- */
    if (iface == NULL || strlen(iface) == 0) {
        /* 未指定接口：用系统第一个可用网卡 */
        pcap_if_t *alldevs = NULL;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            LOG_ERROR("pcap_findalldevs: %s", errbuf);
            return NULL;
        }
        if (alldevs == NULL) {
            LOG_ERROR("no network interfaces found");
            return NULL;
        }
        iface = alldevs->name;
        LOG_INFO("auto-selected interface: %s", iface);
        /* TODO: pcap_freealldevs(alldevs) — 留到 capture_stop */
    }

    LOG_INFO("opening interface: %s", iface);

    /* -------- 打开网卡（混杂模式） -------- */
    handle = pcap_open_live(
        iface,
        MAX_PKT_SIZE,   /* snaplen: 抓满整包 */
        1,              /* promisc: 混杂模式 */
        1000,           /* timeout: 1 秒 */
        errbuf
    );

    if (handle == NULL) {
        LOG_ERROR("pcap_open_live failed: %s", errbuf);
        return NULL;
    }

    /* -------- 检查链路层类型 -------- */
    int dlt = pcap_datalink(handle);
    if (dlt != DLT_EN10MB) {
        LOG_ERROR("unsupported datalink type %d (expected Ethernet %d)",
                  dlt, DLT_EN10MB);
        pcap_close(handle);
        return NULL;
    }
    LOG_INFO("datalink type: EN10MB (Ethernet)");

    /* -------- BPF 过滤（Day 3 完整集成） -------- */
    if (filter_expr != NULL && strlen(filter_expr) > 0) {
        struct bpf_program fp;
        bpf_u_int32 net = 0, mask = 0;

        /* 获取网卡子网掩码（非必须，但某些 filter 表达式需要） */
        if (pcap_lookupnet(iface, &net, &mask, errbuf) == -1) {
            LOG_INFO("pcap_lookupnet: %s (using 0.0.0.0/0)", errbuf);
        }

        if (pcap_compile(handle, &fp, filter_expr, 1, mask) == -1) {
            LOG_ERROR("pcap_compile failed: %s", pcap_geterr(handle));
            pcap_close(handle);
            return NULL;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            LOG_ERROR("pcap_setfilter failed: %s", pcap_geterr(handle));
            pcap_freecode(&fp);
            pcap_close(handle);
            return NULL;
        }

        pcap_freecode(&fp);
        LOG_INFO("BPF filter applied: \"%s\"", filter_expr);
    }

    /* -------- 增大内核缓冲区（减少丢包） -------- */
    if (pcap_set_buffer_size(handle, 32 * 1024 * 1024) != 0) {
        LOG_INFO("pcap_set_buffer_size not supported, using default");
    } else {
        LOG_INFO("capture buffer set to 32 MB");
    }

    g_handle = handle;
    return handle;
}

void capture_start(pcap_t *handle)
{
    if (handle == NULL) {
        LOG_ERROR("capture_start: handle is NULL");
        return;
    }

    LOG_INFO("capturing started. Press Ctrl+C to stop.");

    /* pcap_loop(handle, -1, callback, user):
     *   cnt = -1 → 无限循环，直到 pcap_breakloop 或信号中断 */
    int ret = pcap_loop(handle, -1, pcap_callback, NULL);

    if (ret == PCAP_ERROR_BREAK) {
        LOG_INFO("capture loop broken by user");
    } else if (ret < 0) {
        LOG_ERROR("pcap_loop error: %s", pcap_geterr(handle));
    }
}

void capture_stop(pcap_t *handle)
{
    if (handle != NULL) {
        pcap_breakloop(handle);
        pcap_close(handle);
        g_handle = NULL;
        LOG_INFO("capture resources released");
    }
}

void capture_break(void)
{
    LOG_INFO("capture_break() called, g_handle=%p", (void *)g_handle);
    if (g_handle != NULL) {
        pcap_breakloop(g_handle);
    }
}
