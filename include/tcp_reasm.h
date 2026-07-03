#ifndef TCP_REASM_H
#define TCP_REASM_H

/*
 * tcp_reasm.h — TCP 流重组框架
 *
 * 提供基于五元组哈希表的 TCP 流跟踪、按 SEQ 排序的段插入、
 * 以及 TCP 状态机（SYN → ESTABLISHED → FIN）功能。
 *
 * 用法：
 *   tcp_reasm_init();
 *   tcp_reasm_insert(eth_frame, frame_len);   // 处理每个 TCP 包
 *   struct tcp_stream *s = tcp_reasm_get_stream(&key);
 *   tcp_state_machine(s, flags, seq, ack, is_client);
 *   tcp_reasm_destroy();
 */

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 *  常量定义
 * ============================================================ */

/* 哈希表桶数（素数，利于均匀分布） */
#define REASM_HASH_SIZE 1021

/* 单段最大数据量 */
#define TCP_SEG_MAX_DATA 65535

/* ============================================================
 *  TCP 连接状态 — 简化状态机
 *
 *  CLOSED → SYN_RCVD → ESTABLISHED → FIN_RCVD → CLOSING → CLOSED
 *                    ↓
 *                （RST 直接回到 CLOSED）
 * ============================================================ */

typedef enum {
    TCP_STATE_CLOSED      = 0,  /* 初始/已关闭 */
    TCP_STATE_SYN_RCVD    = 1,  /* 收到 SYN */
    TCP_STATE_ESTABLISHED = 2,  /* 三次握手完成，数据交换 */
    TCP_STATE_FIN_RCVD    = 3,  /* 收到一个方向的 FIN */
    TCP_STATE_CLOSING     = 4,  /* 两个方向都收到 FIN */
} tcp_state_t;

/* ============================================================
 *  五元组键
 *
 *  支持 IPv4 与 IPv6，通过 af 字段区分。
 *  src/dst 使用 union 共用体以减少结构体大小。
 * ============================================================ */

#define TCP_KEY_AF_IPV4 4
#define TCP_KEY_AF_IPV6 6

struct tcp_key {
    uint8_t  af;            /* 地址族: 4=IPv4, 6=IPv6 */
    union {
        uint32_t ipv4;                     /* IPv4 地址（网络字节序） */
        uint8_t  ipv6[16];                 /* IPv6 地址（网络字节序） */
    } src;                                  /* 源地址 */
    union {
        uint32_t ipv4;
        uint8_t  ipv6[16];
    } dst;                                  /* 目的地址 */
    uint16_t src_port;                      /* 源端口（网络字节序） */
    uint16_t dst_port;                      /* 目的端口（网络字节序） */
    uint8_t  proto;                         /* 协议号（通常为 6=TCP） */
};

/* ============================================================
 *  TCP 段（载荷缓冲区中的一块数据）
 *
 *  按 SEQ 升序插入到 tcp_stream.segments 链表中。
 * ============================================================ */

struct tcp_segment {
    uint32_t seq;                    /* TCP 序列号（原始值，网络序未转换） */
    uint32_t seq_len;                /* 该段覆盖的数据字节数 (不含 SYN/FIN) */
    uint8_t  data[TCP_SEG_MAX_DATA]; /* 载荷数据 */
    uint16_t data_len;               /* 实际载荷长度 */
    uint8_t  flags;                  /* TCP 标志位副本 */
    struct tcp_segment *next;        /* 链表后继（按 SEQ 升序） */
};

/* ============================================================
 *  TCP 流上下文
 *
 *  每个五元组对应一个流，保存状态机位置、ISN、期望 SEQ、
 *  以及乱序段链表。
 * ============================================================ */

struct tcp_stream {
    struct tcp_key         key;             /* 五元组标识 */
    tcp_state_t            state;           /* 连接状态 */
    uint32_t               client_isn;      /* 客户端初始序列号 */
    uint32_t               server_isn;      /* 服务端初始序列号 */
    uint32_t               client_next_seq; /* 期望的下一个客户端数据 SEQ */
    uint32_t               server_next_seq; /* 期望的下一个服务端数据 SEQ */
    struct tcp_segment    *segments;        /* 乱序段链表（按 SEQ 升序） */
    uint32_t               seg_count;       /* 乱序段数量 */
    struct tcp_stream     *next;            /* 哈希表冲突链指针 */
};

/* ============================================================
 *  公共接口函数
 * ============================================================ */

/*
 * tcp_reasm_init — 初始化 TCP 重组模块
 *
 * 分配并清空哈希表。在主循环开始前调用一次。
 */
void tcp_reasm_init(void);

/*
 * tcp_reasm_destroy — 销毁 TCP 重组模块
 *
 * 释放所有流、段、哈希表内存。程序退出前调用。
 */
void tcp_reasm_destroy(void);

/*
 * tcp_reasm_insert — 处理一个 TCP 包
 *
 * 从原始以太网帧中提取五元组 + TCP 头信息，
 * 查找或创建对应流，驱动状态机，并按 SEQ 插入载荷。
 *
 * 参数:
 *   pkt — 完整以太网帧（含 Ethernet 头）
 *   len — pkt 可访问字节数
 *
 * 返回: 0 成功，-1 失败（非 TCP、截断、解析错误等）
 */
int tcp_reasm_insert(const uint8_t *pkt, size_t len);

/*
 * tcp_reasm_get_stream — 根据五元组查找流
 *
 * 返回流指针，未找到时返回 NULL。
 */
struct tcp_stream *tcp_reasm_get_stream(const struct tcp_key *key);

/*
 * tcp_state_machine — TCP 状态机
 *
 * 根据当前状态、TCP 标志、SEQ/ACK 进行状态迁移。
 *
 * 参数:
 *   stream        — 流上下文
 *   flags         — TCP 标志位 (TCP_FLAG_*)
 *   seq           — 该段的 SEQ 号（主机序）
 *   ack           — 该段的 ACK 号（主机序）
 *   is_from_client — 非0表示客户端→服务端，0表示服务端→客户端
 */
void tcp_state_machine(struct tcp_stream *stream, uint8_t flags,
                       uint32_t seq, uint32_t ack, int is_from_client);

/*
 * tcp_reasm_extract_key — 从以太网帧提取五元组
 *
 * 不修改流的内部状态，只提取五元组。非 TCP 包返回 -1。
 *
 * 参数:
 *   pkt — 完整以太网帧
 *   len — 帧长度
 *   key — [输出] 提取到的五元组
 *
 * 返回: 0 成功，-1 失败（非 TCP 或解析错误）
 */
int tcp_reasm_extract_key(const uint8_t *pkt, size_t len, struct tcp_key *key);

/* 仅用于测试/调试：获取当前流数量 */
int tcp_reasm_stream_count(void);

/* 仅用于测试/调试：获取当前段总数 */
int tcp_reasm_segment_count(void);

#endif /* TCP_REASM_H */
