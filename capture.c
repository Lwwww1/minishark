/*
 * capture.c — 抓包引擎实现
 *
 * 职责：
 *   - 通过 libpcap 打开网卡、设置混杂模式
 *   - 在抓包回调中调用 B 同学的 protocol.c 解析函数
 *   - 管理抓包生命周期（init → start → break → stop）
 *
 * 注意：本文件不包含协议解析逻辑，所有解析委托给 protocol.c 的 parse_* 函数。
 */

#include "common.h"
#include "capture.h"
#include "filter.h"
#include "protocol.h"
#include "stats.h"

/* ================================================================
 *  内部状态
 * ================================================================ */

static pcap_t *g_handle = NULL;   /* 供 capture_break 访问 */

/* ================================================================
 *  包分发 → B 同学的 parse_eth()
 * ================================================================ */

void dispatch_packet(const struct pcap_pkthdr *header, const u_char *packet)
{
    if (header->caplen < ETH_HDR_LEN) {
        printf("[WARN] packet too short for Ethernet (%u bytes)\n",
               header->caplen);
        return;
    }

    printf("=== Packet  ts=%lu.%06lu  len=%u  caplen=%u ===\n",
           (unsigned long)header->ts.tv_sec,
           (unsigned long)header->ts.tv_usec,
           header->len, header->caplen);

    /* VLAN (802.1Q) 跳过：parse_eth 尚未支持 VLAN 剥离，
     * 这里遇到 VLAN 帧时直接跳过（局域网内不常见） */
    const struct eth_hdr *eth = (const struct eth_hdr *)packet;
    if (ntohs(eth->type) == ETH_TYPE_VLAN) {
        printf("  (VLAN-tagged, skipped)\n\n");
        return;
    }

    /* 流量统计（端口号分类） */
    stats_update(packet, header->len);

    /* 委托给 B 同学的逐层解析：ETH → IP → TCP/UDP/ICMP */
    parse_eth(packet, header->caplen);

    printf("\n");
}

/* ================================================================
 *  libpcap 回调
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

    /* 确定网卡 */
    if (iface == NULL || strlen(iface) == 0) {
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
    }

    LOG_INFO("opening interface: %s", iface);

    /* 打开网卡（混杂模式） */
    handle = pcap_open_live(iface, MAX_PKT_SIZE, 1, 1000, errbuf);
    if (handle == NULL) {
        LOG_ERROR("pcap_open_live failed: %s", errbuf);
        return NULL;
    }

    /* 检查链路层类型 */
    int dlt = pcap_datalink(handle);
    if (dlt != DLT_EN10MB) {
        LOG_ERROR("unsupported datalink type %d (expected Ethernet %d)",
                  dlt, DLT_EN10MB);
        pcap_close(handle);
        return NULL;
    }
    LOG_INFO("datalink type: EN10MB (Ethernet)");

    /* BPF 过滤 */
    if (filter_compile(handle, filter_expr, iface) != 0) {
        LOG_ERROR("filter setup failed");
        pcap_close(handle);
        return NULL;
    }

    /* 增大内核缓冲区 */
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
    if (g_handle != NULL) {
        pcap_breakloop(g_handle);
    }
}
