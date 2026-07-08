/*
 * ui.c — ncurses 终端界面
 *
 * 单 stdscr 布局，手动绘制分割线，避免多窗口重叠问题。
 */

#include "common.h"
#include "ui.h"
#include "protocol.h"
#include "stats.h"

#include <ncurses.h>
#include <pthread.h>
#include <string.h>

#define MAX_DISPLAY_PKTS  1024

/* ================================================================
 *  包摘要结构
 * ================================================================ */

struct pkt_entry {
    struct pcap_pkthdr header;
    uint8_t  l3_proto, l4_proto;
    char     src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    char     src_mac[18], dst_mac[18];
    uint16_t src_port, dst_port;
    uint32_t len;
    uint8_t  ip_ttl, ip_ihl, ip_df, ip_mf;
    uint16_t ip_total;
    uint8_t  tcp_flags, udp_notcp;
    uint16_t tcp_window, l4_len, payload_len;
    uint32_t tcp_seq, tcp_ack;
    uint8_t  data[MAX_PKT_SIZE];
};

static struct pkt_entry g_pkts[MAX_DISPLAY_PKTS];
static int  g_pkt_count  = 0;
static int  g_selected   = -1;
static int  g_show_stats = 1;
static int  g_expanded   = 1;
static volatile int g_ui_running = 1;
static pthread_mutex_t g_lock;

/* ================================================================
 *  布局常量
 * ================================================================ */

static int g_rows, g_cols;
static int LIST_H, DETAIL_H, g_stats_h;

static void calc_layout(void)
{
    getmaxyx(stdscr, g_rows, g_cols);
    LIST_H   = g_rows - 12;               /* 包列表 */
    DETAIL_H = 8;                       /* 协议树 */
    g_stats_h  = g_show_stats ? 7 : 0;    /* 统计 */
    if (LIST_H < 6) LIST_H = 6;
}

/* ================================================================
 *  快速解析
 * ================================================================ */

static const char *proto_short(int l3, int l4, uint16_t sp, uint16_t dp)
{
    if (l3 == 0) return "ARP";
    if (l4 == IP_PROTO_TCP) {
        if (sp == 80 || dp == 80 || sp == 8080 || dp == 8080) return "HTTP";
        if (sp == 443 || dp == 443) return "HTTPS";
        return "TCP";
    }
    if (l4 == IP_PROTO_UDP) {
        if (sp == 53 || dp == 53) return "DNS";
        if (sp == 123|| dp == 123)return "NTP";
        return "UDP";
    }
    if (l4 == IP_PROTO_ICMP || l4 == IP_PROTO_ICMPV6) return "ICMP";
    if (l3 == 4) return "IPv4";
    if (l3 == 6) return "IPv6";
    return "???";
}

static void quick_parse(struct pkt_entry *e, const uint8_t *pkt, uint32_t len)
{
    memset(e, 0, sizeof(*e) - sizeof(e->data));
    if (len < ETH_HDR_LEN) return;

    const struct eth_hdr *eth = (const struct eth_hdr *)pkt;
    uint16_t etype = ntohs(eth->type);

    snprintf(e->src_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->src[0], eth->src[1], eth->src[2],
             eth->src[3], eth->src[4], eth->src[5]);
    snprintf(e->dst_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->dst[0], eth->dst[1], eth->dst[2],
             eth->dst[3], eth->dst[4], eth->dst[5]);

    if (etype == ETH_TYPE_ARP) { e->l3_proto = 0; return; }

    uint32_t l3_off = ETH_HDR_LEN;
    if (etype == ETH_TYPE_IPV4 && len >= l3_off + sizeof(struct ipv4_hdr)) {
        const struct ipv4_hdr *ip = (const struct ipv4_hdr *)(pkt + l3_off);
        uint8_t hl = IPV4_IHL(ip);
        uint16_t frag = ntohs(ip->frag_off);
        e->l3_proto = 4;  e->l4_proto = ip->proto;
        e->ip_ttl   = ip->ttl;  e->ip_ihl   = hl;
        e->ip_total = ntohs(ip->total_len);
        e->ip_df    = (frag >> 14) & 1;
        e->ip_mf    = (frag >> 13) & 1;
        inet_ntop(AF_INET, &ip->src, e->src, sizeof(e->src));
        inet_ntop(AF_INET, &ip->dst, e->dst, sizeof(e->dst));
        uint32_t l4_off = l3_off + hl;

        if (ip->proto == IP_PROTO_TCP && len >= l4_off + sizeof(struct tcp_hdr)) {
            const struct tcp_hdr *tcp = (const struct tcp_hdr *)(pkt + l4_off);
            e->src_port  = ntohs(tcp->src_port);
            e->dst_port  = ntohs(tcp->dst_port);
            e->tcp_flags = tcp->flags;   e->tcp_window = ntohs(tcp->window);
            e->tcp_seq   = ntohl(tcp->seq);  e->tcp_ack = ntohl(tcp->ack);
            e->l4_len    = TCP_DATA_OFFSET(tcp);
        } else if (ip->proto == IP_PROTO_UDP && len >= l4_off + sizeof(struct udp_hdr)) {
            const struct udp_hdr *udp = (const struct udp_hdr *)(pkt + l4_off);
            e->src_port = ntohs(udp->src_port);
            e->dst_port = ntohs(udp->dst_port);
            e->l4_len   = sizeof(struct udp_hdr);
            e->udp_notcp = 1;
        }
        if (e->l4_len && ip->total_len > hl + e->l4_len)
            e->payload_len = (uint16_t)(ip->total_len - hl - e->l4_len);
    } else if (etype == ETH_TYPE_IPV6 && len >= l3_off + sizeof(struct ipv6_hdr)) {
        const struct ipv6_hdr *ip6 = (const struct ipv6_hdr *)(pkt + l3_off);
        e->l3_proto = 6;  e->l4_proto = ip6->next_hdr;
        inet_ntop(AF_INET6, ip6->src, e->src, sizeof(e->src));
        inet_ntop(AF_INET6, ip6->dst, e->dst, sizeof(e->dst));
        uint32_t l4_off = l3_off + sizeof(struct ipv6_hdr);
        if (ip6->next_hdr == IP_PROTO_TCP && len >= l4_off + sizeof(struct tcp_hdr)) {
            const struct tcp_hdr *tcp = (const struct tcp_hdr *)(pkt + l4_off);
            e->src_port = ntohs(tcp->src_port);  e->dst_port = ntohs(tcp->dst_port);
            e->tcp_flags= tcp->flags;  e->tcp_window = ntohs(tcp->window);
            e->tcp_seq  = ntohl(tcp->seq);  e->tcp_ack = ntohl(tcp->ack);
            e->l4_len   = TCP_DATA_OFFSET(tcp);
        } else if (ip6->next_hdr == IP_PROTO_UDP && len >= l4_off + sizeof(struct udp_hdr)) {
            const struct udp_hdr *udp = (const struct udp_hdr *)(pkt + l4_off);
            e->src_port = ntohs(udp->src_port);  e->dst_port = ntohs(udp->dst_port);
            e->l4_len   = sizeof(struct udp_hdr);  e->udp_notcp = 1;
        }
        if (e->l4_len && ntohs(ip6->payload_len) > 0)
            e->payload_len = ntohs(ip6->payload_len);
    }
}

/* ================================================================
 *  绘制
 * ================================================================ */

/* 画一行分隔线 */
static void draw_sep(int row)
{
    mvwhline(stdscr, row, 0, ACS_HLINE, g_cols);
    mvwaddch(stdscr, row, 0,        ACS_LTEE);
    mvwaddch(stdscr, row, g_cols - 1, ACS_RTEE);
}

/* 画标题栏 */
static void draw_title(int row, const char *text)
{
    wattron(stdscr, A_REVERSE);
    mvwhline(stdscr, row, 0, ' ', g_cols);
    mvwprintw(stdscr, row, 1, " %s ", text);
    wattroff(stdscr, A_REVERSE);
}

/* ── 包列表 ── */

static void draw_list(void)
{
    if (!g_pkt_count) return;

    int y = 0;
    draw_title(y, "Packet List");
    y++;

    /* 列头 */
    wattron(stdscr, A_BOLD);
    mvwprintw(stdscr, y, 1, "%-4s %-9s %-6s %-24s %-24s %s",
              "#", "Time", "Proto", "Source", "Destination", "Info");
    wattroff(stdscr, A_BOLD);
    y++;

    int sel = g_selected;
    if (sel < 0 && g_pkt_count > 0) sel = g_pkt_count - 1;

    int start = sel - (LIST_H - 3) / 2;
    if (start < 0) start = 0;
    if (start + LIST_H - 3 > g_pkt_count) start = g_pkt_count - (LIST_H - 3);
    if (start < 0) start = 0;

    int max_items = LIST_H - 3;
    for (int i = 0; i < max_items && start + i < g_pkt_count; i++) {
        int idx = start + i;
        struct pkt_entry *e = &g_pkts[idx];

        char info[80] = "";
        if (e->l4_proto == IP_PROTO_TCP || e->l4_proto == IP_PROTO_UDP)
            snprintf(info, sizeof(info), "%u -> %u", e->src_port, e->dst_port);
        else if (e->l3_proto == 0)
            snprintf(info, sizeof(info), "who-has");

        char sf[64], df[64];
        if (e->src_port) {
            snprintf(sf, sizeof(sf), "%s:%u", e->src, e->src_port);
            snprintf(df, sizeof(df), "%s:%u", e->dst, e->dst_port);
        } else {
            snprintf(sf, sizeof(sf), "%s", e->src[0] ? e->src : e->src_mac);
            snprintf(df, sizeof(df), "%s", e->dst[0] ? e->dst : e->dst_mac);
        }

        if (idx == sel) wattron(stdscr, A_STANDOUT);
        mvwprintw(stdscr, y + i, 1, "%-4d %02lu:%02lu.%03lu %-6s %-24s %-24s %s",
                  idx + 1,
                  (unsigned long)(e->header.ts.tv_sec % 100),
                  (unsigned long)(e->header.ts.tv_usec / 10000),
                  (unsigned long)((e->header.ts.tv_usec % 10000) / 10),
                  proto_short(e->l3_proto, e->l4_proto, e->src_port, e->dst_port),
                  sf, df, info);
        if (idx == sel) wattroff(stdscr, A_STANDOUT);
    }
}

/* ── 协议树 ── */

static void draw_detail(void)
{
    int y = LIST_H;
    draw_sep(y);
    y++;
    draw_title(y, "Protocol Tree (Enter=expand/collapse, Up/Dn=nav)");
    y++;

    int sel = g_selected;
    if (sel < 0 && g_pkt_count > 0) sel = g_pkt_count - 1;
    if (sel < 0 || sel >= g_pkt_count) {
        mvwprintw(stdscr, y, 2, "(no packet selected)");
        return;
    }

    struct pkt_entry *e = &g_pkts[sel];
    int line = y;
    int max_line = y + DETAIL_H - 3;

    /* Frame */
    if (line < max_line - 1)
        mvwprintw(stdscr, ++line, 2, "Frame %d: %u bytes on wire, %s",
                  sel + 1, e->len, e->l3_proto == 0 ? "ARP" : "Ethernet II");

    /* Ethernet */
    if (line < max_line - 1)
        mvwprintw(stdscr, ++line, 2, "  Ethernet II: %s -> %s",
                  e->src_mac, e->dst_mac);

    if (!g_expanded) {
        if (line < max_line - 1)
            mvwprintw(stdscr, ++line, 2, "  [...] Press Enter to expand protocol details");
        return;
    }

    /* IPv4/IPv6 */
    if (e->l3_proto == 4 && line < max_line - 1) {
        mvwprintw(stdscr, ++line, 2, "  IPv4: %s -> %s", e->src, e->dst);
        if (line < max_line - 1)
            mvwprintw(stdscr, ++line, 4, "TTL: %u  IHL: %u bytes  Total: %u bytes  %s%s%s",
                      e->ip_ttl, e->ip_ihl, e->ip_total,
                      e->ip_df ? "DF" : "", (e->ip_df && e->ip_mf) ? "," : "",
                      e->ip_mf ? "MF" : "");
    } else if (e->l3_proto == 6 && line < max_line - 1) {
        mvwprintw(stdscr, ++line, 2, "  IPv6: %s -> %s", e->src, e->dst);
    } else if (e->l3_proto == 0 && line < max_line - 1) {
        mvwprintw(stdscr, ++line, 2, "  ARP Request/Reply");
    }

    /* TCP/UDP */
    if (e->l4_proto == IP_PROTO_TCP && line < max_line - 1) {
        char fs[32] = "";
        uint8_t fl = e->tcp_flags;
        if (fl & TCP_FLAG_SYN) strcat(fs, "SYN,");
        if (fl & TCP_FLAG_ACK) strcat(fs, "ACK,");
        if (fl & TCP_FLAG_FIN) strcat(fs, "FIN,");
        if (fl & TCP_FLAG_RST) strcat(fs, "RST,");
        if (fl & TCP_FLAG_PSH) strcat(fs, "PSH,");
        if (fl & TCP_FLAG_URG) strcat(fs, "URG,");
        if (fs[0]) fs[strlen(fs)-1] = '\0';
        else strcpy(fs, "None");

        mvwprintw(stdscr, ++line, 2, "  TCP: %u -> %u  HdrLen: %u bytes",
                  e->src_port, e->dst_port, e->l4_len);
        if (line < max_line - 1)
            mvwprintw(stdscr, ++line, 4, "SEQ: 0x%08x  ACK: 0x%08x  Win: %u  Flags: %s",
                      e->tcp_seq, e->tcp_ack, e->tcp_window, fs);
    } else if (e->l4_proto == IP_PROTO_UDP && line < max_line - 1) {
        mvwprintw(stdscr, ++line, 2, "  UDP: %u -> %u  Length: %u bytes (payload: %u)",
                  e->src_port, e->dst_port,
                  e->payload_len + 8, e->payload_len);
    }

    if (e->payload_len > 0 && line < max_line - 1) {
        mvwprintw(stdscr, ++line, 2, "  Application Payload: %u bytes", e->payload_len);
    }
}

/* ── 统计面板 ── */

static void draw_stats_panel(void)
{
    if (!g_show_stats) return;

    int y = LIST_H + 1 + DETAIL_H;
    draw_sep(y);
    y++;
    draw_title(y, "Traffic Statistics (s=toggle)");
    y++;

    int printed = 0;
    for (int i = 0; i < STAT_COUNT && y < g_rows - 1; i++) {
        const struct proto_stats *ps = stats_get((stat_proto_t)i);
        if (ps && (ps->pkt_count || ps->byte_count)) {
            mvwprintw(stdscr, y++, 2, "%-8s %6lu pkts  %10lu bytes",
                      ps->name, (unsigned long)ps->pkt_count,
                      (unsigned long)ps->byte_count);
            printed++;
        }
    }
    if (!printed)
        mvwprintw(stdscr, y, 2, "(no traffic yet)");
}

/* ── 状态栏 ── */

static void draw_status(void)
{
    int y = g_rows - 1;
    wattron(stdscr, A_REVERSE);
    mvwhline(stdscr, y, 0, ' ', g_cols);
    mvwprintw(stdscr, y, 1, " minishark | %d packets | q:quit s:stats "
              "Up/Dn:nav Enter:expand ", g_pkt_count);
    wattroff(stdscr, A_REVERSE);
}

static void redraw_all(void)
{
    erase();
    calc_layout();
    draw_list();
    draw_detail();
    draw_stats_panel();
    draw_status();
    refresh();
}

/* ================================================================
 *  键盘
 * ================================================================ */

static int handle_input(int ch)
{
    switch (ch) {
    case 'q': case 'Q': g_ui_running = 0; return 0;
    case 's': case 'S':
        g_show_stats = !g_show_stats;
        redraw_all(); return 1;
    case KEY_UP:
        if (g_selected < 0) g_selected = g_pkt_count - 1;
        if (g_selected > 0) g_selected--;
        redraw_all(); return 1;
    case KEY_DOWN:
        if (g_selected < 0) g_selected = g_pkt_count - 1;
        if (g_selected < g_pkt_count - 1) g_selected++;
        redraw_all(); return 1;
    case KEY_NPAGE:
        if (g_selected < 0) g_selected = g_pkt_count - 1;
        g_selected += 10;
        if (g_selected >= g_pkt_count) g_selected = g_pkt_count - 1;
        redraw_all(); return 1;
    case KEY_PPAGE:
        if (g_selected < 0) g_selected = g_pkt_count - 1;
        g_selected -= 10;
        if (g_selected < 0) g_selected = 0;
        redraw_all(); return 1;
    case KEY_HOME: g_selected = 0;               redraw_all(); return 1;
    case KEY_END:  g_selected = g_pkt_count - 1; redraw_all(); return 1;
    case '\n': case '\r': case KEY_ENTER:
        g_expanded = !g_expanded; redraw_all(); return 1;
    case KEY_RESIZE:
        erase(); clearok(stdscr, TRUE);
        refresh();
        redraw_all(); return 1;
    default: return 1;
    }
}

/* ================================================================
 *  公开 API
 * ================================================================ */

void ui_run(ring_buffer_t *rb)
{
    if (!rb) { LOG_ERROR("ui_run: ring_buffer is NULL"); return; }
    pthread_mutex_init(&g_lock, NULL);

    initscr(); cbreak(); noecho(); curs_set(0);
    keypad(stdscr, TRUE); timeout(50);
    if (has_colors()) { start_color(); use_default_colors(); }

    calc_layout();
    mvwprintw(stdscr, g_rows / 2, g_cols / 2 - 10, "Waiting for packets...");
    refresh();

    while (g_ui_running) {
        struct pcap_pkthdr hdr;
        uint8_t buf[MAX_PKT_SIZE];
        uint32_t len;

        if (rb_pop_timeout(rb, &hdr, buf, &len, 50) > 0) {
            pthread_mutex_lock(&g_lock);
            int idx = g_pkt_count % MAX_DISPLAY_PKTS;
            g_pkts[idx].header = hdr;
            g_pkts[idx].len    = len;
            if (len > MAX_PKT_SIZE) len = MAX_PKT_SIZE;
            memcpy(g_pkts[idx].data, buf, len);
            quick_parse(&g_pkts[idx], buf, len);
            g_pkt_count++;
            stats_update(buf, len);
            redraw_all();
            pthread_mutex_unlock(&g_lock);
        }

        int ch = getch();
        if (ch != ERR && !handle_input(ch)) break;
    }

    endwin();
    pthread_mutex_destroy(&g_lock);
}
