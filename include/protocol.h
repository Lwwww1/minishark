#ifndef PROTOCOL_H
#define PROTOCOL_H

/*
 * protocol.h — 网络协议头结构体定义
 *
 * 涵盖 Ethernet / IPv4 / IPv6 / TCP / UDP / ICMP 的线缆格式 (wire format) 结构体。
 * 所有结构体均使用 __attribute__((packed))，确保与网络字节序严格对齐，
 * 可直接对 libpcap 抓取的原始包数据进行强制转换访问。
 *
 * 命名约定：使用小写缩写（如 eth_hdr, tcp_hdr），避免与系统 netinet/ *.h
 * 中的 iphdr / tcphdr / udphdr 等类型发生冲突。
 */

#include <stdint.h>
#include <netinet/in.h>

/* ============================================================
 *  以太网 (Ethernet II) — RFC 894
 *  固定首部长度 14 字节: 6 字节目的 MAC + 6 字节源 MAC + 2 字节类型
 * ============================================================ */

#define ETH_ADDR_LEN 6           /* MAC 地址长度 */
#define ETH_HDR_LEN  14          /* 以太网首部长度（不含 802.1Q VLAN tag） */

/* 上层协议类型 (Ethertype)，网络字节序 */
#define ETH_TYPE_IPV4   0x0800
#define ETH_TYPE_ARP    0x0806
#define ETH_TYPE_VLAN   0x8100   /* 802.1Q VLAN 标签 */
#define ETH_TYPE_IPV6   0x86DD

struct eth_hdr {
    uint8_t  dst[ETH_ADDR_LEN]; /* 目的 MAC 地址 */
    uint8_t  src[ETH_ADDR_LEN]; /* 源 MAC 地址 */
    uint16_t type;              /* 上层协议类型 (Ethertype) */
} __attribute__((packed));

/* ============================================================
 *  IPv4 — RFC 791
 *  首部最小 20 字节，含 options 后最大 60 字节
 * ============================================================ */

#define IPV4_ADDR_LEN 4

/* IP 协议号 (Protocol) */
#define IP_PROTO_ICMP   1
#define IP_PROTO_TCP    6
#define IP_PROTO_UDP    17
#define IP_PROTO_ICMPV6 58

/* IP 分片标志位 (位于 frag_off 高 3 位) */
#define IPV4_FLAG_RF    0x8000   /* 保留位 (Reserved) */
#define IPV4_FLAG_DF    0x4000   /* Don't Fragment — 不分片 */
#define IPV4_FLAG_MF    0x2000   /* More Fragments — 还有后续分片 */

/* IPv4 首部基本字段 */
struct ipv4_hdr {
    uint8_t  ver_ihl;           /* 高 4 位: 版本(4)；低 4 位: 首部长度(单位 4 字节) */
    uint8_t  tos;               /* Type of Service / DSCP+ECN */
    uint16_t total_len;         /* 整个 IP 包长度 (含首部)，单位字节 */
    uint16_t ident;             /* 分片标识 */
    uint16_t frag_off;          /* 高 3 位 flags + 低 13 位 片偏移 (8 字节为单位) */
    uint8_t  ttl;               /* 生存时间 (Time To Live) */
    uint8_t  proto;             /* 上层协议号 */
    uint16_t checksum;          /* 首部校验和 */
    uint32_t src;               /* 源 IP 地址 (网络字节序) */
    uint32_t dst;               /* 目的 IP 地址 (网络字节序) */
    /* 可变长 options 字段省略，由代码按 IHL*4 访问 */
} __attribute__((packed));

/* 取 IPv4 版本号 */
#define IPV4_VERSION(hdr) ((hdr)->ver_ihl >> 4)
/* 取 IPv4 首部长度（字节） */
#define IPV4_IHL(hdr)     (((hdr)->ver_ihl & 0x0F) * 4)

/* ============================================================
 *  IPv6 — RFC 8200
 *  固定首部 40 字节
 * ============================================================ */

#define IPV6_ADDR_LEN 16

struct ipv6_hdr {
    uint32_t ver_tc_fl;         /* 高 4 位 version + 8 位 traffic class + 20 位 flow label */
    uint16_t payload_len;       /* 载荷长度 (不含 40 字节首部) */
    uint8_t  next_hdr;          /* 下一个扩展头/上层协议 */
    uint8_t  hop_limit;         /* 跳数限制 */
    uint8_t  src[IPV6_ADDR_LEN]; /* 源 IPv6 地址 */
    uint8_t  dst[IPV6_ADDR_LEN]; /* 目的 IPv6 地址 */
} __attribute__((packed));

#define IPV6_VERSION(hdr) (((ntohl((hdr)->ver_tc_fl)) >> 28) & 0x0F)

/* ============================================================
 *  TCP — RFC 793
 *  首部最小 20 字节，含 options 后最大 60 字节
 * ============================================================ */

#define TCP_HDR_MIN_LEN 20

/* TCP 标志位 (data_off 字节的低 6 位) */
#define TCP_FLAG_CWR  0x80  /* Congestion Window Reduced */
#define TCP_FLAG_ECE  0x40  /* ECN-Echo */
#define TCP_FLAG_URG  0x20  /* Urgent pointer field is significant */
#define TCP_FLAG_ACK  0x10  /* Acknowledgment field is significant */
#define TCP_FLAG_PSH  0x08  /* Push function */
#define TCP_FLAG_RST  0x04  /* Reset the connection */
#define TCP_FLAG_SYN  0x02  /* Synchronize sequence numbers */
#define TCP_FLAG_FIN  0x01  /* No more data from sender */

struct tcp_hdr {
    uint16_t src_port;          /* 源端口 */
    uint16_t dst_port;          /* 目的端口 */
    uint32_t seq;               /* 序列号 */
    uint32_t ack;               /* 确认号 */
    uint8_t  data_off;          /* 高 4 位 数据偏移(单位 4 字节) + 保留 4 位 */
    uint8_t  flags;             /* 8 个标志位 (CWR/ECE/URG/ACK/PSH/RST/SYN/FIN) */
    uint16_t window;            /* 接收窗口大小 */
    uint16_t checksum;          /* 校验和 (含伪首部) */
    uint16_t urgent;            /* 紧急指针 */
    /* 可变长 options 字段省略，按 data_off*4 访问 */
} __attribute__((packed));

/* TCP 首部长度（字节） */
#define TCP_DATA_OFFSET(hdr) ((((hdr)->data_off) >> 4) * 4)

/* ============================================================
 *  UDP — RFC 768
 *  固定首部 8 字节
 * ============================================================ */

#define UDP_HDR_LEN 8

struct udp_hdr {
    uint16_t src_port;          /* 源端口 */
    uint16_t dst_port;          /* 目的端口 */
    uint16_t length;            /* UDP 段总长度 (含首部)，单位字节 */
    uint16_t checksum;          /* 校验和，0 表示未计算 (IPv6 强制) */
} __attribute__((packed));

/* ============================================================
 *  ICMP — RFC 792
 *  基本首部 8 字节 (type + code + checksum + 4 字节可变字段)
 *  下面给出常见 Echo Request/Reply 的字段视图
 * ============================================================ */

#define ICMP_HDR_LEN 8

/* 常见 ICMP type 常量 (子集) */
#define ICMP_TYPE_ECHO_REPLY   0
#define ICMP_TYPE_DEST_UNREACH 3
#define ICMP_TYPE_SRC_QUENCH   4  /* 已废弃 */
#define ICMP_TYPE_REDIRECT     5
#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_TIME_EXCEEDED 11
#define ICMP_TYPE_PARAM_PROBLEM 12

/* ICMPv6 (type 由 IP_PROTO_ICMPV6 = 58 标识) 常见类型 */
#define ICMPV6_TYPE_DEST_UNREACH  1
#define ICMPV6_TYPE_ECHO_REQUEST  128
#define ICMPV6_TYPE_ECHO_REPLY    129

struct icmp_hdr {
    uint8_t  type;              /* 类型 */
    uint8_t  code;              /* 代码 (含义依赖于 type) */
    uint16_t checksum;          /* 校验和 */
    uint16_t id;                /* 标识符 (用于 Echo Request/Reply 匹配) */
    uint16_t seq;               /* 序号 (用于 Echo Request/Reply 匹配) */
    /* 之后是 ICMP payload，如 Echo 携带的数据 */
} __attribute__((packed));

/* ============================================================
 *  DNS — RFC 1035
 *  固定首部 12 字节
 * ============================================================ */

#define DNS_HDR_LEN 12
#define DNS_PORT    53

/* DNS 标志位 (flags 字段，网络字节序展开后使用) */
#define DNS_FLAG_QR        0x8000  /* 查询(0) / 响应(1) */
#define DNS_FLAG_OPCODE_MASK 0x7800  /* 操作码掩码 */
#define DNS_FLAG_AA        0x0400  /* Authoritative Answer */
#define DNS_FLAG_TC        0x0200  /* Truncation */
#define DNS_FLAG_RD        0x0100  /* Recursion Desired */
#define DNS_FLAG_RA        0x0080  /* Recursion Available */
#define DNS_FLAG_RCODE_MASK 0x000F /* 响应码掩码 */

/* DNS 资源记录类型 (QTYPE / TYPE) */
#define DNS_TYPE_A     1   /* IPv4 地址 */
#define DNS_TYPE_NS    2   /* 域名服务器 */
#define DNS_TYPE_CNAME 5   /* 别名 (规范名称) */
#define DNS_TYPE_SOA   6   /* Start Of Authority */
#define DNS_TYPE_PTR   12  /* 指针记录 */
#define DNS_TYPE_MX    15  /* 邮件交换 */
#define DNS_TYPE_TXT   16  /* 文本记录 */
#define DNS_TYPE_AAAA  28  /* IPv6 地址 */
#define DNS_TYPE_SRV   33  /* 服务定位 */

/* DNS 类 (QCLASS / CLASS) */
#define DNS_CLASS_IN   1   /* Internet */

struct dns_hdr {
    uint16_t id;        /* 会话标识 */
    uint16_t flags;     /* 标志字段 */
    uint16_t qdcount;   /* 问题数 (Question Count) */
    uint16_t ancount;   /* 回答数 (Answer Count) */
    uint16_t nscount;   /* 授权数 (Authority Count) */
    uint16_t arcount;   /* 附加数 (Additional Count) */
} __attribute__((packed));

/* ============================================================
 *  HTTP — RFC 7230
 * ============================================================ */

#define HTTP_PORT    80
#define HTTP_PORT_ALT 8080

/* ============================================================
 *                 协议解析函数声明
 *  所有 parser 接受从当前层起始的字节流和长度，
 *  解析失败（截断、字段越界）时返回 -1，成功返回 0。
 *  parse_icmp 的 is_ipv6 标志用于选择 ICMPv4 与 ICMPv6 的类型常量。
 * ============================================================ */

int parse_eth (const uint8_t *pkt, size_t len);
int parse_ipv4(const uint8_t *pkt, size_t len);
int parse_ipv6(const uint8_t *pkt, size_t len);
int parse_tcp (const uint8_t *pkt, size_t len);
int parse_udp (const uint8_t *pkt, size_t len);
int parse_icmp(const uint8_t *pkt, size_t len, int is_ipv6);
int parse_dns (const uint8_t *pkt, size_t len);
int parse_http(const uint8_t *pkt, size_t len);

#endif /* PROTOCOL_H */
