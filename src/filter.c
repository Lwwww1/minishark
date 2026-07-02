/*
 * filter.c — BPF 过滤器实现
 *
 * 职责：
 *   - 编译 libpcap BPF 过滤表达式
 *   - 将编译后的 filter 应用到抓包句柄
 *
 * 从 capture.c 中抽取，独立成模块以便维护和测试。
 */

#include "common.h"
#include "filter.h"

int filter_compile(pcap_t *handle, const char *filter_expr, const char *iface)
{
    struct bpf_program fp;
    bpf_u_int32 net = 0, mask = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (filter_expr == NULL || strlen(filter_expr) == 0) {
        LOG_INFO("no filter expression, capturing all packets");
        return 0;
    }

    if (handle == NULL) {
        LOG_ERROR("filter_compile: handle is NULL");
        return -1;
    }

    /*
     * 获取网卡子网掩码。某些 filter 表达式（如 "net 192.168.1.0/24"）
     * 需要知道本地子网，这里对 lo 等虚拟接口容错。
     */
    if (iface != NULL && pcap_lookupnet(iface, &net, &mask, errbuf) == -1) {
        LOG_INFO("pcap_lookupnet(%s): %s (fallback to 0.0.0.0/0)", iface, errbuf);
        net  = 0;
        mask = 0;
    } else if (iface == NULL) {
        LOG_INFO("no interface specified, using 0.0.0.0/0 for filter mask");
    }

    /* 编译 BPF 表达式 */
    if (pcap_compile(handle, &fp, filter_expr, 1, mask) == -1) {
        LOG_ERROR("pcap_compile: %s", pcap_geterr(handle));
        return -1;
    }

    /* 安装 filter */
    if (pcap_setfilter(handle, &fp) == -1) {
        LOG_ERROR("pcap_setfilter: %s", pcap_geterr(handle));
        pcap_freecode(&fp);
        return -1;
    }

    pcap_freecode(&fp);
    LOG_INFO("BPF filter applied: \"%s\"", filter_expr);
    return 0;
}
