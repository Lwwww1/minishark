#ifndef FILTER_H
#define FILTER_H

/*
 * filter.h — BPF 过滤器接口
 *
 * 封装 libpcap 的 BPF 编译和应用逻辑。
 * 支持通过命令行参数 -f 传入过滤表达式（如 "tcp port 80"）。
 */

#include <pcap.h>

/*
 * 编译 BPF 过滤表达式并应用到 pcap 句柄。
 *
 * @param handle      pcap_open_live() 返回的句柄
 * @param filter_expr BPF 过滤表达式字符串
 * @param iface       网卡名称（用于 pcap_lookupnet 获取子网掩码）
 * @return            0 成功，-1 失败
 */
int filter_compile(pcap_t *handle, const char *filter_expr, const char *iface);

#endif /* FILTER_H */
