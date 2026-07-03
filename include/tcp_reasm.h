#ifndef TCP_REASM_H
#define TCP_REASM_H

/*
 * tcp_reasm.h — TCP 流重组框架
 *
 * 提供基于五元组哈希表的 TCP 流跟踪、按 SEQ 排序的段插入、
 * TCP 状态机、重叠/重传处理、以及连续数据重组。
 *
 * 用法：
 *   tcp_reasm_init();
 *   tcp_reasm_insert(eth_frame, frame_len);   // 处理每个 TCP 包
 *   struct tcp_stream *s = tcp_reasm_get_stream(&key);
 *   const uint8_t *data = tcp_reasm_get_data(s, &len);
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

/* 重组缓冲区初始分配大小 */
#define REASM_BUF_INIT_SIZE 4096

/* 重组缓冲区最大大小（防止内存耗尽） */
#define REASM_BUF_MAX_SIZE (32 * 1024 * 1024)

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
 *  INSERT 返回码（增强版）
 * ============================================================ */

#define TCP_INSERT_OK         0   /* 正常插入 */
#define TCP_INSERT_DUP       -2   /* 完全重复段，已丢弃 */
#define TCP_INSERT_RETRANSMIT -3  /* 重传段（部分重叠），已处理 */
#define TCP_INSERT_OVERLAP    -4  /* 部分重叠段，已截断后插入 */

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
    uint32_t seq;                    /* TCP 序列号（主机序） */
    uint32_t seq_len;                /* 该段覆盖的序列空间长度 (含 SYN/FIN) */
    uint8_t  data[TCP_SEG_MAX_DATA]; /* 载荷数据 */
    uint16_t data_len;               /* 实际载荷长度（不含 SYN/FIN） */
    uint8_t  flags;                  /* TCP 标志位副本 */
    struct tcp_segment *next;        /* 链表后继（按 SEQ 升序） */
};

/* ============================================================
 *  TCP 流上下文
 *
 *  每个五元组对应一个流，保存状态机位置、ISN、期望 SEQ、
 *  乱序段链表、以及连续重组缓冲区。
 * ============================================================ */

struct tcp_stream {
    struct tcp_key         key;             /* 五元组标识 */
    tcp_state_t            state;           /* 连接状态 */
    uint32_t               client_isn;      /* 客户端初始序列号 */
    uint32_t               server_isn;      /* 服务端初始序列号 */
    uint32_t               client_next_seq; /* 期望的下一个客户端数据 SEQ */
    uint32_t               server_next_seq; /* 期望的下一个服务端数据 SEQ */
    struct tcp_segment    *segments;        /* 未重组段链表（按 SEQ 升序） */
    uint32_t               seg_count;       /* 未重组段数量 */

    /* ---- 连续重组缓冲区 ---- */
    uint8_t               *reasm_buf;       /* 已重组的连续数据 */
    uint32_t               reasm_len;       /* 已重组数据的字节数 */
    uint32_t               reasm_cap;       /* reasm_buf 已分配容量 */
    uint32_t               reasm_next_seq;  /* 重组区期望的下一个绝对 SEQ */
    int                    reasm_active;    /* 1=已初始化重组 */

    /* ---- 统计 ---- */
    uint32_t               dup_count;       /* 重复段计数 */
    uint32_t               retrans_count;   /* 重传段计数 */
    uint32_t               overlap_count;   /* 部分重叠段计数 */
    uint32_t               ooo_count;       /* 乱序段计数 */

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
 * 释放所有流、段、重组缓冲区内存。程序退出前调用。
 */
void tcp_reasm_destroy(void);

/*
 * tcp_reasm_insert — 处理一个 TCP 包
 *
 * 从原始以太网帧中提取五元组 + TCP 头信息，
 * 查找或创建对应流，驱动状态机，按 SEQ 插入载荷（含重叠处理），
 * 并尝试推进连续重组。
 *
 * 参数:
 *   pkt — 完整以太网帧（含 Ethernet 头）
 *   len — pkt 可访问字节数
 *
 * 返回:  0 成功（正常插入）
 *        -1 失败（解析错误、非 TCP、截断等）
 *        -2 完全重复段已丢弃 (TCP_INSERT_DUP)
 *        -3 重传段已处理 (TCP_INSERT_RETRANSMIT)
 *        -4 部分重叠段已截断插入 (TCP_INSERT_OVERLAP)
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
 */
void tcp_state_machine(struct tcp_stream *stream, uint8_t flags,
                       uint32_t seq, uint32_t ack, int is_from_client);

/*
 * tcp_reasm_extract_key — 从以太网帧提取五元组
 *
 * 不修改流的内部状态，只提取五元组。非 TCP 包返回 -1。
 *
 * 返回: 0 成功，-1 失败（非 TCP 或解析错误）
 */
int tcp_reasm_extract_key(const uint8_t *pkt, size_t len, struct tcp_key *key);

/*
 * tcp_reasm_assemble — 将流中连续的前缀段重组到缓冲区
 *
 * 遍历 segments 链表，将 SEQ == reasm_next_seq 的连续段
 * 逐个追加到 reasm_buf 并移出链表。
 *
 * 返回追加到 reasm_buf 的字节数。
 */
uint32_t tcp_reasm_assemble(struct tcp_stream *stream);

/*
 * tcp_reasm_get_data — 获取已重组的连续数据
 *
 * 返回指向重组数据的指针及其长度。
 * 返回的指针在下次对同一流的操作前有效。
 *
 * 参数:
 *   stream — 流指针
 *   len    — [输出] 数据长度
 *
 * 返回: 指向重组数据的指针，无数据则返回 NULL 且 *len=0
 */
const uint8_t *tcp_reasm_get_data(struct tcp_stream *stream, uint32_t *len);

/*
 * tcp_reasm_get_stream_stats — 获取流的统计信息
 *
 * 填充 dup_count、retrans_count、overlap_count、ooo_count。
 */
void tcp_reasm_get_stream_stats(struct tcp_stream *stream,
                                uint32_t *dup, uint32_t *retrans,
                                uint32_t *overlap, uint32_t *ooo);

/* 仅用于测试/调试：获取当前流数量 */
int tcp_reasm_stream_count(void);

/* 仅用于测试/调试：获取当前段总数 */
int tcp_reasm_segment_count(void);

#endif /* TCP_REASM_H */
