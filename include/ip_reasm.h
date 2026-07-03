#ifndef IP_REASM_H
#define IP_REASM_H

/*
 * ip_reasm.h — IP 分片重组模块
 *
 * 支持 IPv4 与 IPv6 分片重组。
 *
 * 用法：
 *   ip_reasm_init();
 *   int ret = ip_reasm_insert(pkt, len, &out_buf, &out_len);
 *   if (ret == 1) { // 重组完成
 *       process(out_buf, out_len);
 *       free(out_buf);
 *   }
 *   ip_reasm_destroy();
 */

#include <stdint.h>
#include <stddef.h>
#include <time.h>

/* ============================================================
 *  常量
 * ============================================================ */

/* 分片哈希表大小 */
#define IP_FRAG_HASH_SIZE 257

/* 单个分片流的最大分片数 */
#define IP_FRAG_MAX_FRAGMENTS 64

/* 分片超时时间（秒）— 超时未完成则丢弃 */
#define IP_FRAG_TIMEOUT 30

/* 最大重组后 IP 包大小 */
#define IP_REASM_MAX_SIZE 65535

/* ============================================================
 *  分片流状态
 * ============================================================ */

/* 分片链表节点 */
struct ip_frag {
    uint16_t offset;            /* 分片偏移量（字节） */
    uint16_t data_len;          /* 分片数据长度 */
    uint8_t  mf;                /* More Fragments 标志 */
    uint8_t *data;              /* 分片数据副本 */
    struct ip_frag *next;       /* 按 offset 升序 */
};

/* 分片流键 */
struct ip_frag_key {
    uint32_t src[4];            /* 源地址（IPv4 用低 32 位，IPv6 用全部 128 位） */
    uint32_t dst[4];            /* 目的地址 */
    uint32_t ident;             /* 分片标识符 */
    uint8_t  proto;             /* 上层协议号 */
    uint8_t  version;           /* 4=IPv4, 6=IPv6 */
};

/* 分片流 */
struct ip_frag_stream {
    struct ip_frag_key  key;
    uint16_t            total_data_len;  /* 预期的总数据长度（不含 IP 头） */
    uint16_t            received_len;    /* 已收到的数据长度 */
    uint16_t            frag_count;      /* 已有分片数 */
    time_t              first_seen;      /* 创建时间（用于超时） */
    uint8_t            *ip_header;       /* IP 头副本（来自第一个分片） */
    uint8_t             ip_hdr_len;      /* IP 头长度 */
    struct ip_frag     *fragments;       /* 分片链表（按 offset 升序） */
    struct ip_frag_stream *next;         /* 哈希表链 */
};

/* ============================================================
 *  API 函数
 * ============================================================ */

/*
 * ip_reasm_init — 初始化 IP 分片重组模块
 */
void ip_reasm_init(void);

/*
 * ip_reasm_destroy — 释放所有分片缓存
 */
void ip_reasm_destroy(void);

/*
 * ip_reasm_insert — 插入一个 IP 分片
 *
 * 参数:
 *   pkt     — 完整的以太网帧（含以太网头）
 *   len     — 帧长度
 *   out_buf — [输出] 如果重组完成，指向新分配的重组后 IP 包缓冲区
 *             （调用方需 free()）
 *   out_len — [输出] 重组后数据长度
 *
 * 返回:
 *   -1  错误（非 IP 分片、参数无效）
 *    0  分片已缓存，但尚未重组完成
 *    1  重组完成，out_buf/out_len 有效
 *
 * 注意：IPv4 分片重组后输出的是完整 IPv4 包（含 IPv4 头）；
 *       IPv6 分片重组后输出的是完整 IPv6 包（含 IPv6 头）。
 */
int ip_reasm_insert(const uint8_t *pkt, size_t len,
                    uint8_t **out_buf, uint16_t *out_len);

/*
 * ip_reasm_cleanup — 清理超时的分片流
 *
 * 删除所有超时（IP_FRAG_TIMEOUT 秒未完成）的分片流。
 * 返回已清理的流数量。
 */
int ip_reasm_cleanup(void);

/*
 * ip_reasm_stream_count — 当前活跃的分片流数
 */
int ip_reasm_stream_count(void);

/*
 * ip_reasm_frag_count — 当前缓存的总分片数
 */
int ip_reasm_frag_count(void);

#endif /* IP_REASM_H */
