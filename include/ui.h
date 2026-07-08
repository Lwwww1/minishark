#ifndef UI_H
#define UI_H

/*
 * ui.h — ncurses 终端界面接口
 *
 * 提供三栏布局：
 *   - 顶部：实时包列表（滚动）
 *   - 中部：选中包的协议树详情
 *   - 底部：流量统计面板
 *
 * 按键：
 *   q / Ctrl+C  — 退出
 *   s           — 切换统计面板
 *   ↑ ↓ PgUp PgDn — 滚动包列表
 *   Enter       — 展开/折叠协议树
 */

#include "ring_buffer.h"

/* 启动 ncurses UI 主循环（阻塞，从 ring buffer 取包显示） */
void ui_run(ring_buffer_t *rb);

#endif /* UI_H */
