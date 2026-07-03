#include "common.h"
#include "capture.h"
#include "filter.h"
#include "pcap_io.h"

volatile int g_running = 1;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
    capture_break();
}

static void print_usage(const char *prog) {
    printf("Usage: %s [options]\n", prog);
    printf("Options:\n");
    printf("  -i <iface>   Network interface to capture (default: any)\n");
    printf("  -f <filter>  BPF filter expression (e.g. \"tcp port 80\")\n");
    printf("  -r <file>    Read packets from pcap file\n");
    printf("  -w <file>    Write packets to pcap file\n");
    printf("  -h           Show this help\n");
}

int main(int argc, char *argv[]) {
    const char *iface = NULL;
    const char *filter_expr = NULL;
    const char *read_file = NULL;
    const char *write_file = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "i:f:r:w:h")) != -1) {
        switch (opt) {
        case 'i': iface = optarg; break;
        case 'f': filter_expr = optarg; break;
        case 'r': read_file = optarg; break;
        case 'w': write_file = optarg; break;
        case 'h': print_usage(argv[0]); return 0;
        default:  print_usage(argv[0]); return 1;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    LOG_INFO("minishark starting...");

    pcap_t        *handle  = NULL;
    pcap_dumper_t *dumper  = NULL;

    if (read_file != NULL) {
        /* ---- 离线回放模式 ---- */
        char errbuf[PCAP_ERRBUF_SIZE];
        handle = pcap_read_open(read_file, errbuf);
        if (handle == NULL) {
            LOG_ERROR("failed to open pcap file: %s", errbuf);
            return 1;
        }

        /* 离线模式也需要支持 BPF 过滤 */
        if (filter_compile(handle, filter_expr, iface) != 0) {
            LOG_ERROR("filter setup failed");
            capture_stop(handle);
            return 1;
        }
    } else {
        /* ---- 实时抓包模式 ---- */
        handle = capture_init(iface, filter_expr);
        if (handle == NULL) {
            LOG_ERROR("failed to initialize capture engine");
            return 1;
        }

        if (write_file != NULL) {
            dumper = pcap_write_open(write_file, handle);
            if (dumper == NULL) {
                LOG_ERROR("failed to open output file");
                capture_stop(handle);
                return 1;
            }
            capture_set_dumper(dumper);
        }
    }

    /* 启动抓包/回放循环（阻塞直到 EOF 或 Ctrl+C） */
    capture_start(handle);

    /* 清理 */
    if (dumper) pcap_write_close(dumper);
    capture_stop(handle);

    LOG_INFO("minishark stopped.");

    return 0;
}
