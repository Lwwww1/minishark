#ifndef CAPTURE_H
#define CAPTURE_H

/*
 * capture.h — 抓包引擎接口
 *
 * 基于 libpcap API，提供：
 *   - 网卡混杂模式抓包
 *   - BPF 过滤（预留）
 *   - 抓包循环回调
 *   - 优雅停止
 */

#include <pcap.h>

/* 初始化抓包引擎 */
pcap_t *capture_init(const char *iface, const char *filter_expr);

/* 启动抓包循环（阻塞，直到 g_running == 0 或被 pcap_breakloop） */
void capture_start(pcap_t *handle);

/* 停止抓包并释放资源 */
void capture_stop(pcap_t *handle);

/* 异步打断正在运行的抓包循环（安全地供信号处理器调用） */
void capture_break(void);

/* 包分发函数：从 pcap 回调中解析协议栈 */
void dispatch_packet(const struct pcap_pkthdr *header, const u_char *packet);

#endif /* CAPTURE_H */
