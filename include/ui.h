#ifndef UI_H
#define UI_H

/*
 * ui.h — ncurses 终端界面接口
 *
 * 三栏布局：包列表 | 协议树/Hex | 统计面板
 *
 * 按键:
 *   q / Ctrl+C  — 退出
 *   s           — 切换统计面板
 *   h           — 切换 Hex dump 视图
 *   ↑ ↓ PgUp PgDn — 导航包列表
 *   Enter       — 展开/折叠协议树
 */

#include "ring_buffer.h"

/*
 * @param rb         环形缓冲区
 * @param filter     BPF 过滤表达式 (NULL=无过滤), 仅用于状态栏显示
 * @param write_file 输出 pcap 文件 (NULL=不保存), 仅用于状态栏显示
 */
void ui_run(ring_buffer_t *rb, const char *filter, const char *write_file);

#endif /* UI_H */
