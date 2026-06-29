#include "common.h"

volatile int g_running = 1;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
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

    /* TODO Day 2: 初始化抓包引擎 */
    /* TODO Day 3: 集成 BPF 过滤 */
    /* TODO Day 5: PCAP 文件读写模式切换 */

    LOG_INFO("minishark stopped.");

    return 0;
}
