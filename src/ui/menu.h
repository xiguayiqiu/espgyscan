#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 按键键码（特殊键>0xFF；普通字符返回 ASCII） */
enum {
    MENU_KEY_UP    = 0x101,
    MENU_KEY_DOWN  = 0x102,
    MENU_KEY_LEFT  = 0x103,
    MENU_KEY_RIGHT = 0x104,
};

#define MENU_KEY_ESC   0x1B
#define MENU_KEY_ENTER '\r'

/* 菜单动作回调 */
typedef void (*menu_handler_t)(void);

typedef struct menu_screen_s menu_screen_t;

/* 菜单项：submenu 与 handler 二选一 */
typedef struct {
    const char *title;              /* 菜单项标题 */
    const menu_screen_t *submenu;   /* 选中后进入的子菜单（可为 NULL） */
    menu_handler_t handler;         /* 选中后执行的动作（可为 NULL） */
} menu_item_t;

struct menu_screen_s {
    const char *title;              /* 屏幕标题，如 "主菜单" */
    const menu_item_t *items;
    int item_count;
};

/*
 * 从根菜单开始交互（阻塞，直到根菜单按 ESC 退出）
 *
 * 按键:
 *   WASD / 方向键   移动选择器
 *   Enter           确认
 *   ESC             返回上级菜单（根菜单时退出）
 */
void menu_run(const menu_screen_t *screen);

/* 阻塞等待一个按键（返回键码或 ASCII 字符）；无按键不返回 */
int menu_wait_key(void);

/* 非阻塞读取一个按键；无按键返回 -1（供模块在等待过程中实现取消） */
int menu_key_now(void);

/*
 * 注册"顶级菜单结束"处理器。
 * 主菜单(顶级)按 ESC/q 时会调用它(如关机确认)；处理器内确认后不再返回，
 * 取消则返回并继续停留在主菜单。
 */
void menu_set_exit_handler(menu_handler_t handler);

/*
 * 读取一行文本到 buf（自动回显，支持退格）
 * 成功返回输入长度（不含结尾 '\0'）；ESC 取消返回 -1
 */
int menu_read_line(char *buf, size_t size);

/*
 * 光标选择：从 items（count 项）中用 上/下(或 WASD) 移动、Enter 确认、
 * ESC 取消。title 为提示标题（可为 NULL）。
 * 返回选中的下标(0 起)；ESC 取消返回 -1。
 */
int menu_select(const char **items, int count, const char *title);

#ifdef __cplusplus
}
#endif


