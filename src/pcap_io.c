/*
 * pcap_io.c — PCAP 文件读写实现
 *
 * 职责：
 *   - pcap_write_open / pcap_write_pkt / pcap_write_close：实时保存
 *   - pcap_read_open：离线回放
 *
 * 所有函数都是 libpcap API 的薄封装，逻辑简洁。
 */

#include "common.h"
#include "pcap_io.h"

pcap_dumper_t *pcap_write_open(const char *filename, pcap_t *handle)
{
    if (filename == NULL || handle == NULL) {
        LOG_ERROR("pcap_write_open: invalid arguments");
        return NULL;
    }

    pcap_dumper_t *dumper = pcap_dump_open(handle, filename);
    if (dumper == NULL) {
        LOG_ERROR("pcap_dump_open(%s): %s", filename, pcap_geterr(handle));
        return NULL;
    }

    LOG_INFO("pcap output file opened: %s", filename);
    return dumper;
}

void pcap_write_pkt(pcap_dumper_t *dumper,
                    const struct pcap_pkthdr *header,
                    const u_char *packet)
{
    if (dumper == NULL || header == NULL || packet == NULL)
        return;
    pcap_dump((u_char *)dumper, header, packet);
}

void pcap_write_close(pcap_dumper_t *dumper)
{
    if (dumper != NULL) {
        pcap_dump_close(dumper);
        LOG_INFO("pcap output file closed");
    }
}

pcap_t *pcap_read_open(const char *filename, char *errbuf)
{
    if (filename == NULL) {
        snprintf(errbuf, PCAP_ERRBUF_SIZE, "pcap_read_open: filename is NULL");
        return NULL;
    }

    pcap_t *handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        return NULL;
    }

    LOG_INFO("offline pcap file opened: %s", filename);
    return handle;
}
