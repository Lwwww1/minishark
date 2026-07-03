#ifndef PCAP_IO_H
#define PCAP_IO_H

/*
 * pcap_io.h — PCAP 文件读写接口
 *
 * 封装 libpcap 的文件操作：写入实时捕获、读取离线回放。
 * 命令行通过 -w <file> 和 -r <file> 切换模式。
 */

#include <pcap.h>

/* 创建 pcap 写入器，返回 dumper 句柄 */
pcap_dumper_t *pcap_write_open(const char *filename, pcap_t *handle);

/* 写入一个数据包 */
void pcap_write_pkt(pcap_dumper_t *dumper,
                    const struct pcap_pkthdr *header,
                    const u_char *packet);

/* 关闭写入器 */
void pcap_write_close(pcap_dumper_t *dumper);

/* 打开离线 pcap 文件用于回放，返回 pcap_t 句柄（等同实时抓包句柄） */
pcap_t *pcap_read_open(const char *filename, char *errbuf);

#endif /* PCAP_IO_H */
