/*
 * main.c — 程序入口
 *
 * Day 7: 双线程架构
 *   capture 线程 → rb_push() → [ring_buffer] → rb_pop() → parse 线程
 *
 * 用法：
 *   实时抓包:   sudo ./my_sniffer [-i eth0] [-f "tcp"] [-w out.pcap]
 *   离线回放:   sudo ./my_sniffer -r in.pcap [-f "tcp"]
 */

#include "common.h"
#include "capture.h"
#include "filter.h"
#include "pcap_io.h"
#include "ring_buffer.h"

volatile int g_running = 1;

static void signal_handler(int sig)
{
    (void)sig;
    g_running = 0;
    capture_break();
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -i <iface>   Network interface to capture (default: auto)\n");
    printf("  -f <filter>  BPF filter expression (e.g. \"tcp port 80\")\n");
    printf("  -r <file>    Read packets from pcap file\n");
    printf("  -w <file>    Write packets to pcap file\n");
    printf("  -h           Show this help\n");
}

/* ================================================================
 *  parse 线程：从 ring buffer 取包 → 调用 dispatch_packet 解析
 * ================================================================ */

static void *parse_thread_fn(void *arg)
{
    ring_buffer_t *rb = (ring_buffer_t *)arg;
    struct pcap_pkthdr header;
    uint8_t           buf[MAX_PKT_SIZE];
    uint32_t          len;

    LOG_INFO("parse thread started");

    while (g_running || rb_count(rb) > 0) {
        int got = rb_pop_timeout(rb, &header, buf, &len, 100);
        if (got > 0) {
            dispatch_packet(&header, buf);
        }
        /* timeout → 检查 g_running，若为 0 且 buffer 空则退出 */
    }

    LOG_INFO("parse thread stopped");
    return NULL;
}

/* ================================================================
 *  capture 线程：调用 capture_start（内部 pcap_loop）
 * ================================================================ */

static void *capture_thread_fn(void *arg)
{
    pcap_t *handle = (pcap_t *)arg;
    LOG_INFO("capture thread started");
    capture_start(handle);
    LOG_INFO("capture thread stopped");
    return NULL;
}

/* ================================================================
 *  main
 * ================================================================ */

int main(int argc, char *argv[])
{
    const char *iface       = NULL;
    const char *filter_expr = NULL;
    const char *read_file   = NULL;
    const char *write_file  = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "i:f:r:w:h")) != -1) {
        switch (opt) {
        case 'i': iface       = optarg; break;
        case 'f': filter_expr = optarg; break;
        case 'r': read_file   = optarg; break;
        case 'w': write_file  = optarg; break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    LOG_INFO("minishark starting...");

    pcap_t        *handle = NULL;
    pcap_dumper_t *dumper = NULL;

    /* ---- 初始化环形缓冲区 ---- */
    ring_buffer_t *rb = rb_init(MAX_BUFFER_COUNT);
    if (rb == NULL) {
        LOG_ERROR("failed to create ring buffer");
        return 1;
    }

    /* ---- 打开数据源 ---- */
    if (read_file != NULL) {
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_read_open(read_file, errbuf);
        if (handle == NULL) {
            LOG_ERROR("failed to open pcap file: %s", errbuf);
            rb_destroy(rb);
            return 1;
        }
        if (filter_compile(handle, filter_expr, iface) != 0) {
            LOG_ERROR("filter setup failed");
            capture_stop(handle);
            rb_destroy(rb);
            return 1;
        }
    } else {
        handle = capture_init(iface, filter_expr);
        if (handle == NULL) {
            LOG_ERROR("failed to initialize capture engine");
            rb_destroy(rb);
            return 1;
        }
        if (write_file != NULL) {
            dumper = pcap_write_open(write_file, handle);
            if (dumper == NULL) {
                capture_stop(handle);
                rb_destroy(rb);
                return 1;
            }
            capture_set_dumper(dumper);
        }
    }

    /* ---- 多线程模式：capture 线程 → rb → parse 线程 ---- */
    capture_set_ring_buffer(rb);

    pthread_t capture_thread, parse_thread;

    if (pthread_create(&capture_thread, NULL, capture_thread_fn, handle) != 0) {
        LOG_ERROR("pthread_create (capture) failed");
        capture_stop(handle);
        if (dumper) pcap_write_close(dumper);
        rb_destroy(rb);
        return 1;
    }

    if (pthread_create(&parse_thread, NULL, parse_thread_fn, rb) != 0) {
        LOG_ERROR("pthread_create (parse) failed");
        capture_break();
        pthread_join(capture_thread, NULL);
        capture_stop(handle);
        if (dumper) pcap_write_close(dumper);
        rb_destroy(rb);
        return 1;
    }

    /* 等待线程结束 */
    pthread_join(capture_thread, NULL);
    pthread_join(parse_thread, NULL);

    /* 性能统计 */
    capture_print_stats(handle);

    /* 清理 */
    capture_stop(handle);
    if (dumper) pcap_write_close(dumper);
    rb_destroy(rb);

    LOG_INFO("minishark stopped.");
    return 0;
}
