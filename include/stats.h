#ifndef STATS_H
#define STATS_H

/*
 * stats.h — 实时流量统计接口
 *
 * 支持按协议（TCP/UDP/ICMP/HTTP/HTTPS/DNS）和按 IP 统计包数与字节数。
 * stats_update() 由 capture 回调每个包调用一次；
 * stats_print()  可按需或定时打印当前统计快照。
 */

#include <stdint.h>
#include <time.h>

/* 协议分类枚举 */
typedef enum {
    STAT_TCP    = 0,
    STAT_UDP,
    STAT_ICMP,
    STAT_HTTP,      /* TCP port 80, 8080 */
    STAT_HTTPS,     /* TCP port 443 */
    STAT_DNS,       /* UDP port 53 */
    STAT_OTHER,
    STAT_COUNT      /* 分类总数 */
} stat_proto_t;

/* 按协议的统计项 */
struct proto_stats {
    const char *name;
    uint64_t    pkt_count;
    uint64_t    byte_count;
};

/* 获取指定协议的统计数据（只读） */
const struct proto_stats *stats_get(stat_proto_t proto);

/* 每个抓到的包调用一次，自动分类并累加 */
void stats_update(const uint8_t *packet, uint32_t len);

/* 打印当前统计快照 */
void stats_print(void);

/* 归零所有计数器 */
void stats_reset(void);

/* 开关自动打印（UI 模式下关闭，防止 printf 与 ncurses 冲突） */
void stats_set_auto_print(int enable);

#endif /* STATS_H */
