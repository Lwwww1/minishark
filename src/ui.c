/*
 * ui.c — ncurses 终端界面 (v3)
 *
 * 按键:
 *   f           — 输入显示过滤关键字（支持 proto/port/IP）
 *   /           — 搜索下一个匹配包
 *   s           — 切换统计面板
 *   h           — 切换 Hex dump
 *   Enter       — 展开/折叠协议树
 *   q           — 退出
 *   ↑↓ PgUp/Dn — 导航
 */

#include "common.h"
#include "capture.h"
#include "ui.h"
#include "protocol.h"
#include "stats.h"
#include <ncurses.h>
#include <pthread.h>
#include <string.h>
#include <ctype.h>

#define MAX_DISPLAY_PKTS  1024
#define FILTER_LEN 64

/* ================================================================
 *  包摘要
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
static int  g_show_hex   = 0;
static volatile int g_ui_running = 1;
static pthread_mutex_t g_lock;

static const char *g_filter         = NULL;
static char       *g_write_file_ui  = NULL;  /* UI 交互式保存的文件名 */
static char g_disp_filter[FILTER_LEN] = "";  /* 显示过滤关键字 */
static int  g_filtered_count = 0;
extern volatile int g_cap_done;               /* capture.c */

static int g_rows, g_cols;
static int g_list_h, g_detail_h, g_stats_h;

/* 前向声明 */
static const char *proto_short(int l3, int l4, uint16_t sp, uint16_t dp);

/* ================================================================
 *  显示过滤
 * ================================================================ */

static int match_filter(struct pkt_entry *e)
{
    if (!g_disp_filter[0]) return 1;

    char lower[FILTER_LEN];
    for (int i = 0; g_disp_filter[i] && i < FILTER_LEN - 1; i++)
        lower[i] = (char)tolower((unsigned char)g_disp_filter[i]);
    lower[strlen(g_disp_filter)] = '\0';

    /* 协议名匹配 */
    const char *pname = proto_short(e->l3_proto, e->l4_proto, e->src_port, e->dst_port);
    char plow[16];
    for (int i = 0; pname[i] && i < (int)sizeof(plow) - 1; i++)
        plow[i] = (char)tolower((unsigned char)pname[i]);
    plow[strlen(pname)] = '\0';
    if (strstr(plow, lower)) return 1;

    /* 端口号匹配 */
    char portstr[12];
    snprintf(portstr, sizeof(portstr), "%u", e->src_port);
    if (strstr(portstr, lower)) return 1;
    snprintf(portstr, sizeof(portstr), "%u", e->dst_port);
    if (strstr(portstr, lower)) return 1;

    /* IP 地址子串匹配 */
    char srcl[INET6_ADDRSTRLEN], dstl[INET6_ADDRSTRLEN];
    for (int i = 0; e->src[i] && i < (int)sizeof(srcl) - 1; i++)
        srcl[i] = (char)tolower((unsigned char)e->src[i]);
    srcl[strlen(e->src)] = '\0';
    for (int i = 0; e->dst[i] && i < (int)sizeof(dstl) - 1; i++)
        dstl[i] = (char)tolower((unsigned char)e->dst[i]);
    dstl[strlen(e->dst)] = '\0';
    if (strstr(srcl, lower)) return 1;
    if (strstr(dstl, lower)) return 1;

    /* MAC 地址子串匹配 */
    if (strstr(e->src_mac, lower)) return 1;
    if (strstr(e->dst_mac, lower)) return 1;

    return 0;
}

/* ================================================================
 *  布局
 * ================================================================ */

static void calc_layout(void)
{
    getmaxyx(stdscr, g_rows, g_cols);
    int avail = g_rows - 2;
    int need  = g_show_stats ? 7 : 0;
    g_detail_h = 8;
    if (need + g_detail_h + 8 > avail) {
        g_detail_h = 6;
        if (need + g_detail_h + 8 > avail)
            need = avail - g_detail_h - 8;
    }
    g_stats_h = need;
    g_list_h  = avail - g_detail_h - need;
    if (g_list_h < 5) g_list_h = 5;
}

/* ================================================================
 *  解析
 * ================================================================ */

static const char *proto_short(int l3, int l4, uint16_t sp, uint16_t dp)
{
    if (l3 == 0) return (l4 == 1) ? "ARP-R" : "ARP-Q";
    if (l4 == IP_PROTO_TCP) {
        if (sp == 80 || dp == 80) return "HTTP";
        if (sp == 443|| dp == 443)return "HTTPS";
        if (sp == 22 || dp == 22) return "SSH";
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
    e->l3_proto = e->l4_proto = 0;
    e->src[0] = e->dst[0] = '\0';
    e->src_mac[0] = e->dst_mac[0] = '\0';
    e->src_port = e->dst_port = 0;
    e->ip_ttl = e->ip_ihl = e->ip_df = e->ip_mf = 0;
    e->ip_total = 0;
    e->tcp_flags = e->udp_notcp = 0;
    e->tcp_window = e->l4_len = e->payload_len = 0;
    e->tcp_seq = e->tcp_ack = 0;

    if (len < ETH_HDR_LEN) return;

    const struct eth_hdr *eth = (const struct eth_hdr *)pkt;
    uint16_t etype = ntohs(eth->type);

    snprintf(e->src_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->src[0], eth->src[1], eth->src[2],
             eth->src[3], eth->src[4], eth->src[5]);
    snprintf(e->dst_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             eth->dst[0], eth->dst[1], eth->dst[2],
             eth->dst[3], eth->dst[4], eth->dst[5]);

    if (etype == ETH_TYPE_ARP) {
        e->l3_proto = 0;
        /* ARP 操作码在以太网头的 offset 20 处 (2 bytes, 网络序) */
        if (len >= ETH_HDR_LEN + 8) {
            uint16_t arp_op = ntohs(*(const uint16_t *)(pkt + ETH_HDR_LEN + 6));
            e->l4_proto = (arp_op == 2) ? 1 : 0;  /* 1=Reply, 0=Request */
        }
        return;
    }

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
            e->src_port = ntohs(tcp->src_port); e->dst_port = ntohs(tcp->dst_port);
            e->tcp_flags= tcp->flags;  e->tcp_window = ntohs(tcp->window);
            e->tcp_seq  = ntohl(tcp->seq);  e->tcp_ack = ntohl(tcp->ack);
            e->l4_len   = TCP_DATA_OFFSET(tcp);
        } else if (ip->proto == IP_PROTO_UDP && len >= l4_off + sizeof(struct udp_hdr)) {
            const struct udp_hdr *udp = (const struct udp_hdr *)(pkt + l4_off);
            e->src_port = ntohs(udp->src_port); e->dst_port = ntohs(udp->dst_port);
            e->l4_len   = sizeof(struct udp_hdr);  e->udp_notcp = 1;
        }
        if (e->l4_len && ip->total_len > hl + e->l4_len)
            e->payload_len = (uint16_t)(ip->total_len - hl - e->l4_len);
    } else if (etype == ETH_TYPE_IPV6 && len >= l3_off + sizeof(struct ipv6_hdr)) {
        const struct ipv6_hdr *ip6 = (const struct ipv6_hdr *)(pkt + l3_off);
        e->l3_proto = 6;  e->l4_proto = ip6->next_hdr;
        e->ip_total = (uint16_t)(ntohs(ip6->payload_len) + sizeof(struct ipv6_hdr));
        inet_ntop(AF_INET6, ip6->src, e->src, sizeof(e->src));
        inet_ntop(AF_INET6, ip6->dst, e->dst, sizeof(e->dst));
        uint32_t l4_off = l3_off + sizeof(struct ipv6_hdr);
        if (ip6->next_hdr == IP_PROTO_TCP && len >= l4_off + sizeof(struct tcp_hdr)) {
            const struct tcp_hdr *tcp = (const struct tcp_hdr *)(pkt + l4_off);
            e->src_port = ntohs(tcp->src_port); e->dst_port = ntohs(tcp->dst_port);
            e->tcp_flags= tcp->flags;  e->tcp_window = ntohs(tcp->window);
            e->tcp_seq  = ntohl(tcp->seq);  e->tcp_ack = ntohl(tcp->ack);
            e->l4_len   = TCP_DATA_OFFSET(tcp);
        } else if (ip6->next_hdr == IP_PROTO_UDP && len >= l4_off + sizeof(struct udp_hdr)) {
            const struct udp_hdr *udp = (const struct udp_hdr *)(pkt + l4_off);
            e->src_port = ntohs(udp->src_port); e->dst_port = ntohs(udp->dst_port);
            e->l4_len   = sizeof(struct udp_hdr);  e->udp_notcp = 1;
        }
        if (e->l4_len && ntohs(ip6->payload_len) > 0)
            e->payload_len = ntohs(ip6->payload_len);
    }
}

/* ================================================================
 *  绘制
 * ================================================================ */

static void draw_title(int row, const char *text)
{
    wattron(stdscr, A_REVERSE);
    mvwhline(stdscr, row, 0, ' ', g_cols);
    mvwprintw(stdscr, row, 1, " %s ", text);
    wattroff(stdscr, A_REVERSE);
}

static void draw_sep(int row)
{
    mvwhline(stdscr, row, 0, '-' | A_DIM, g_cols);
}

/* ── 包列表 ── */

static void draw_list(void)
{
    int y = 0;
    draw_title(y, "Packet List");
    if (!g_pkt_count) {
        if (g_cap_done)
            mvwprintw(stdscr, 2, 2, "(no packets in file / capture stopped)");
        else
            mvwprintw(stdscr, 2, 2, "(waiting for packets...)");
        return;
    }
    y++;

    wattron(stdscr, A_BOLD);
    mvwprintw(stdscr, y, 1, "%-4s %-9s %-6s %-22s %-22s %s",
              "#", "Time", "Proto", "Source", "Destination", "Info");
    wattroff(stdscr, A_BOLD);
    y++;

    /* 统计过滤匹配的包数 */
    g_filtered_count = 0;
    for (int i = 0; i < g_pkt_count; i++)
        if (match_filter(&g_pkts[i])) g_filtered_count++;

    int sel = g_selected;
    if (sel < 0 && g_pkt_count > 0) sel = g_pkt_count - 1;

    /* 找到过滤后的第 N 个 */
    int visible_idx[1024]; /* 最多显示 1024 个过滤后的包 */
    int vis_count = 0;
    for (int i = 0; i < g_pkt_count; i++)
        if (match_filter(&g_pkts[i])) visible_idx[vis_count++] = i;

    int sel_vis = -1;
    for (int i = 0; i < vis_count; i++) {
        if (visible_idx[i] == sel) { sel_vis = i; break; }
    }
    if (sel_vis < 0 && vis_count > 0) { sel_vis = vis_count - 1; sel = visible_idx[sel_vis]; }

    int start = sel_vis - (g_list_h - 4) / 2;
    if (start < 0) start = 0;
    if (start + g_list_h - 4 > vis_count) start = vis_count - (g_list_h - 4);
    if (start < 0) start = 0;

    for (int i = 0; i < g_list_h - 4 && start + i < vis_count; i++) {
        int idx = visible_idx[start + i];
        struct pkt_entry *e = &g_pkts[idx];

        char info[80] = "";
        if (e->l4_proto == IP_PROTO_TCP || e->l4_proto == IP_PROTO_UDP)
            snprintf(info, sizeof(info), "%u->%u", e->src_port, e->dst_port);
        else if (e->l3_proto == 0)
            snprintf(info, sizeof(info), e->l4_proto ? "reply" : "who-has");

        char sf[64], df[64];
        if (e->src_port) {
            snprintf(sf, sizeof(sf), "%s:%u", e->src, e->src_port);
            snprintf(df, sizeof(df), "%s:%u", e->dst, e->dst_port);
        } else {
            snprintf(sf, sizeof(sf), "%s", e->src[0] ? e->src : e->src_mac);
            snprintf(df, sizeof(df), "%s", e->dst[0] ? e->dst : e->dst_mac);
        }

        if (idx == sel) wattron(stdscr, A_STANDOUT);
        mvwprintw(stdscr, y + i, 1, "%-4d %02lu:%02lu.%03lu %-6s %-22s %-22s %s",
                  idx + 1,
                  (unsigned long)(e->header.ts.tv_sec % 100),
                  (unsigned long)(e->header.ts.tv_usec / 10000),
                  (unsigned long)((e->header.ts.tv_usec % 10000) / 10),
                  proto_short(e->l3_proto, e->l4_proto, e->src_port, e->dst_port),
                  sf, df, info);
        if (idx == sel) wattroff(stdscr, A_STANDOUT);
    }
}

/* ── Hex dump ── */

static void draw_hex(struct pkt_entry *e)
{
    int y = g_list_h + 1;
    draw_sep(y); y++;
    draw_title(y, "Hex Dump (h=toggle)");
    y++;

    uint32_t display_len = e->len;
    if (display_len > 512) display_len = 512;

    for (uint32_t offset = 0; offset < display_len && y < g_list_h + 1 + g_detail_h; offset += 16) {
        char hex[49] = "", ascii[17] = "";
        for (int i = 0; i < 16 && offset + i < display_len; i++) {
            uint8_t b = e->data[offset + i];
            sprintf(hex + i * 3, "%02x ", b);
            ascii[i] = (b >= 0x20 && b < 0x7f) ? (char)b : '.';
        }
        ascii[16] = '\0';
        mvwprintw(stdscr, y++, 2, "%04x  %-48s |%s|", offset, hex, ascii);
        if (y >= g_rows - 1) break;
    }
    if (display_len < e->len)
        mvwprintw(stdscr, y++, 2, "  ... (%u more bytes)", e->len - display_len);
}

/* ── 协议树 ── */

static void draw_detail(void)
{
    int y = g_list_h + 1;
    draw_sep(y); y++;
    draw_title(y, g_show_hex ? "Protocol Tree (h=toggle back)"
               : "Protocol Tree (Enter=expand, h=hex)");
    y++;

    int sel = g_selected;
    if (sel < 0 && g_pkt_count > 0) sel = g_pkt_count - 1;
    if (sel < 0 || sel >= g_pkt_count) {
        mvwprintw(stdscr, y, 2, "(no packet selected)");
        return;
    }

    struct pkt_entry *e = &g_pkts[sel];
    int max_y = g_list_h + 1 + g_detail_h;

    if (y < max_y - 1)
        mvwprintw(stdscr, ++y, 2, "Frame %d: %u bytes on wire, %s",
                  sel + 1, e->len,
                  e->l3_proto == 0 ? "ARP" : "Ethernet II");

    if (y < max_y - 1)
        mvwprintw(stdscr, ++y, 2, "  Eth: %s -> %s",
                  e->src_mac, e->dst_mac);

    if (!g_expanded) {
        if (y < max_y - 1)
            mvwprintw(stdscr, ++y, 2, "  [...] Press Enter to expand");
        return;
    }

    if (e->l3_proto == 4 && y < max_y - 1) {
        mvwprintw(stdscr, ++y, 2, "  IPv4: %s -> %s", e->src, e->dst);
        if (y < max_y - 1)
            mvwprintw(stdscr, ++y, 4, "TTL:%u IHL:%ub Total:%ub %s%s",
                      e->ip_ttl, e->ip_ihl, e->ip_total,
                      e->ip_df ? "DF " : "", e->ip_mf ? "MF" : "");
    } else if (e->l3_proto == 6 && y < max_y - 1) {
        mvwprintw(stdscr, ++y, 2, "  IPv6: %s -> %s", e->src, e->dst);
    } else if (e->l3_proto == 0 && y < max_y - 1) {
        mvwprintw(stdscr, ++y, 2, "  ARP Request/Reply");
    }

    if (e->l4_proto == IP_PROTO_TCP && y < max_y - 1) {
        char fs[32] = "";
        uint8_t fl = e->tcp_flags;
        if (fl & TCP_FLAG_SYN) strcat(fs, "SYN ");
        if (fl & TCP_FLAG_ACK) strcat(fs, "ACK ");
        if (fl & TCP_FLAG_FIN) strcat(fs, "FIN ");
        if (fl & TCP_FLAG_RST) strcat(fs, "RST ");
        if (fl & TCP_FLAG_PSH) strcat(fs, "PSH ");
        if (fl & TCP_FLAG_URG) strcat(fs, "URG ");
        if (!fs[0]) strcpy(fs, "None");

        mvwprintw(stdscr, ++y, 2, "  TCP: %u -> %u  HdrLen:%ub  Win:%u",
                  e->src_port, e->dst_port, e->l4_len, e->tcp_window);
        if (y < max_y - 1)
            mvwprintw(stdscr, ++y, 4, "SEQ:0x%08x  ACK:0x%08x  Flags:%s",
                      e->tcp_seq, e->tcp_ack, fs);
    } else if (e->l4_proto == IP_PROTO_UDP && y < max_y - 1) {
        mvwprintw(stdscr, ++y, 2, "  UDP: %u -> %u  HdrLen:8  Payload:%ub",
                  e->src_port, e->dst_port, e->payload_len);
    }
}

/* ── 统计 ── */

static void draw_stats_panel(void)
{
    if (!g_show_stats) return;
    int y = g_list_h + 1 + g_detail_h;
    draw_sep(y); y++;
    draw_title(y, "Traffic Statistics (s=toggle)");
    y++;

    int printed = 0;
    for (int i = 0; i < STAT_COUNT && y < g_rows - 1; i++) {
        const struct proto_stats *ps = stats_get((stat_proto_t)i);
        if (ps && (ps->pkt_count || ps->byte_count)) {
            mvwprintw(stdscr, y++, 2, "%-8s %6lu pkts %10lu bytes",
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

    char buf[256];
    int pos = snprintf(buf, sizeof(buf), " minishark | %d pkts%s",
                       g_pkt_count,
                       g_cap_done ? " [EOF]" : "");
    if (g_disp_filter[0])
        pos += snprintf(buf + pos, sizeof(buf) - pos,
                        " | filter:%s (%d vis)", g_disp_filter, g_filtered_count);
    if (g_filter && g_filter[0])
        pos += snprintf(buf + pos, sizeof(buf) - pos, " | BPF:%s", g_filter);
    if (g_write_file_ui && g_write_file_ui[0])
        pos += snprintf(buf + pos, sizeof(buf) - pos, " | [REC] %s", g_write_file_ui);
    pos += snprintf(buf + pos, sizeof(buf) - pos, " | stat:%s",
                    g_show_stats ? "ON" : "OFF");
    if (g_show_hex)
        pos += snprintf(buf + pos, sizeof(buf) - pos, " | HEX");
    snprintf(buf + pos, sizeof(buf) - pos,
             " | q:quit f:filter ESC:clear n:next w:save h:hex");

    mvwprintw(stdscr, y, 1, "%s", buf);
    wattroff(stdscr, A_REVERSE);
}

static void redraw_all(void)
{
    erase();
    calc_layout();
    draw_list();
    if (g_show_hex) {
        int sel = g_selected;
        if (sel < 0 && g_pkt_count > 0) sel = g_pkt_count - 1;
        if (sel >= 0 && sel < g_pkt_count)
            draw_hex(&g_pkts[sel]);
        else
            draw_detail();
    } else {
        draw_detail();
    }
    draw_stats_panel();
    draw_status();
    refresh();
}

/* ================================================================
 *  输入模式：读取一行文本
 * ================================================================ */

static int input_line(const char *prompt, char *buf, int maxlen)
{
    echo();
    curs_set(1);
    int y = g_rows - 1;
    wattron(stdscr, A_REVERSE);
    mvwhline(stdscr, y, 0, ' ', g_cols);
    mvwprintw(stdscr, y, 1, " %s ", prompt);
    wattroff(stdscr, A_REVERSE);
    wmove(stdscr, y, (int)strlen(prompt) + 3);
    wrefresh(stdscr);

    int pos = 0;
    buf[0] = '\0';
    timeout(-1);  /* 阻塞等待 */
    while (1) {
        int ch = getch();
        if (ch == '\n' || ch == '\r' || ch == KEY_ENTER) break;
        if (ch == 27) { buf[0] = '\0'; break; }  /* ESC 取消 */
        if (ch == KEY_BACKSPACE || ch == 127 || ch == '\b') {
            if (pos > 0) { pos--; buf[pos] = '\0'; }
        } else if (ch >= 32 && ch < 127 && pos < maxlen - 1) {
            buf[pos++] = (char)ch;
            buf[pos] = '\0';
        }
        /* 重绘输入行 */
        wattron(stdscr, A_REVERSE);
        mvwhline(stdscr, y, 0, ' ', g_cols);
        mvwprintw(stdscr, y, 1, " %s %s ", prompt, buf);
        wattroff(stdscr, A_REVERSE);
        wmove(stdscr, y, (int)strlen(prompt) + 3 + pos);
        wrefresh(stdscr);
    }
    timeout(50);
    noecho();
    curs_set(0);
    return (int)strlen(buf);
}

/* ================================================================
 *  键盘
 * ================================================================ */

static int handle_input(int ch)
{
    switch (ch) {
    case 'q': case 'Q': g_ui_running = 0; return 0;

    case 's': case 'S':
        g_show_stats = !g_show_stats; redraw_all(); return 1;

    case 'h': case 'H':
        g_show_hex = !g_show_hex; redraw_all(); return 1;

    case 'f': case 'F': {
        char buf[FILTER_LEN];
        int n = input_line("Filter (proto/port/IP, Enter=apply, ESC=clear):",
                           buf, FILTER_LEN);
        if (n > 0) {
            strncpy(g_disp_filter, buf, FILTER_LEN - 1);
            g_disp_filter[FILTER_LEN - 1] = '\0';
        } else if (n == 0 && buf[0] == '\0') {
            g_disp_filter[0] = '\0';  /* ESC 清除过滤 */
        }
        redraw_all();
        return 1;
    }

    case '/': {
        char buf[FILTER_LEN];
        int n = input_line("Search:", buf, FILTER_LEN);
        if (n > 0) {
            strncpy(g_disp_filter, buf, FILTER_LEN - 1);
            g_disp_filter[FILTER_LEN - 1] = '\0';
            /* 搜索 + 跳到第一个匹配 */
            for (int i = 0; i < g_pkt_count; i++) {
                if (match_filter(&g_pkts[i])) {
                    g_selected = i;
                    break;
                }
            }
        }
        redraw_all();
        return 1;
    }

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

    case 27:  /* ESC: 清除过滤 */
        g_disp_filter[0] = '\0'; redraw_all(); return 1;

    case 'w': case 'W':
        if (g_write_file_ui) {
            /* 第二次按 w：停止保存 */
            FILE *sav = freopen("/dev/null", "w", stdout); (void)sav;
            capture_close_dumper();
            sav = freopen("/dev/tty", "w", stdout); (void)sav;
            free(g_write_file_ui);
            g_write_file_ui = NULL;
        } else {
            char fn[128];
            int n = input_line("Save to file (Enter=auto, ESC=cancel):",
                               fn, sizeof(fn));
            if (n == 0 && fn[0] == '\0') {
                time_t now = time(NULL);
                snprintf(fn, sizeof(fn), "capture_%ld.pcap", (long)now);
            } else if (n > 0) {
                size_t flen = strlen(fn);
                if (flen < 5 || strcasecmp(fn + flen - 5, ".pcap") != 0) {
                    if (flen < sizeof(fn) - 6) strcat(fn, ".pcap");
                }
            }
            { FILE *sv = freopen("/dev/null", "w", stdout); (void)sv;
            if (capture_open_dumper(fn) == 0) {
                g_write_file_ui = strdup(fn);
                for (int i = 0; i < g_pkt_count; i++) {
                    int idx = i % MAX_DISPLAY_PKTS;
                    pcap_dump((u_char *)capture_get_dumper(),
                              &g_pkts[idx].header, g_pkts[idx].data);
                }
            }
            sv = freopen("/dev/tty", "w", stdout); (void)sv; }
        }
        redraw_all(); return 1;

    case 'n': case 'N': {
        /* 跳转到下一个匹配的包 */
        int cur = (g_selected < 0) ? g_pkt_count - 1 : g_selected;
        for (int i = 1; i < g_pkt_count; i++) {
            int idx = (cur + i) % g_pkt_count;
            if (match_filter(&g_pkts[idx])) {
                g_selected = idx; break;
            }
        }
        redraw_all(); return 1;
    }

    case KEY_RESIZE: clearok(stdscr, TRUE); redraw_all(); return 1;

    default: return 1;
    }
}

/* ================================================================
 *  公开 API
 * ================================================================ */

void ui_run(ring_buffer_t *rb, const char *filter, const char *write_file)
{
    if (!rb) { LOG_ERROR("ui_run: ring_buffer is NULL"); return; }
    pthread_mutex_init(&g_lock, NULL);

    g_filter = filter ? filter : NULL;
    if (write_file && write_file[0])
        g_write_file_ui = strdup(write_file);
    stats_set_auto_print(0);

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
