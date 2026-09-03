/*
 * menu.c - 串口交互式菜单框架（支持多级菜单）
 *
 * 按键:
 *   W/↑ S/↓    上/下移动选择器
 *   A/← D/→    左/右（纵向列表无效果，预留）
 *   Enter       确认
 *   ESC         返回上级菜单（根菜单时退出）
 *   q           根菜单时退出（快捷键）
 *
 * 按键读取使用非阻塞轮询：空闲时降载等待，无按键不重绘，
 * 因此可以区分"单独 ESC"和"方向键前缀(ESC [ x)"。
 */

#include "menu.h"
#include <stdio.h>
#include <inttypes.h>
#include "esp_system.h"
#include "esp_heap_caps.h"
#include "esp_flash.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "wifi_scan.h"
#include "ble_scan.h"
#include "eth_netif.h"
#include "i18n.h"

/*
 * 控制台 stdin 为非阻塞读取：无数据时 getchar() 立即返回 EOF。
 * 因此用"轮询 + 延时"等待按键，空闲时不会空转，也不会阻塞在
 * 底层读上导致 select 失效环境下无法响应（如 QEMU）。
 */

/* ANSI 控制序列 */
#define ANSI_CLEAR_SCREEN  "\033[2J"
#define ANSI_CURSOR_HOME   "\033[H"

/* ANSI 颜色（串口/终端支持时生效） */
#define ANSI_BOLD    "\033[1m"
#define ANSI_DIM     "\033[2m"
#define ANSI_RESET   "\033[0m"
#define ANSI_RED     "\033[31m"
#define ANSI_GREEN   "\033[32m"
#define ANSI_YELLOW  "\033[33m"
#define ANSI_BLUE    "\033[34m"
#define ANSI_MAGENTA "\033[35m"
#define ANSI_CYAN    "\033[36m"
#define ANSI_WHITE   "\033[37m"
#define ANSI_BG_BLUE "\033[44m"

/* 立即读取一个字节；无输入返回 -1 */
static int read_char_now(void)
{
    int c = getchar();
    return (c == EOF) ? -1 : c;
}

/* 非阻塞读取一个按键；无按键返回 -1（用于等待过程实现取消） */
int menu_key_now(void)
{
    int c = read_char_now();
    return c;   /* 普通字符直接返回；0x1B 由调用方按 ESC 处理 */
}

/* 轮询等待一个字节；timeout_ms<0 表示无限等待，超时返回 -1 */
static int read_byte(int timeout_ms)
{
    TickType_t start = xTaskGetTickCount();

    while (1) {
        int c = read_char_now();
        if (c >= 0) {
            return c;
        }
        if (timeout_ms >= 0 &&
            (xTaskGetTickCount() - start) >= pdMS_TO_TICKS(timeout_ms)) {
            return -1;
        }
        vTaskDelay(pdMS_TO_TICKS(15));   /* 无按键时降载轮询，绝不空转 */
    }
}

/* 阻塞等待一个按键（组合方向键/功能键），无按键不返回 */
int menu_wait_key(void)
{
    int c = read_byte(-1);          /* 等待首个字节 */
    if (c != MENU_KEY_ESC) {
        return c;
    }
    /* 收到 ESC：可能是方向键前缀，60ms 内等待后续字节 */
    int c2 = read_byte(60);
    if (c2 == '[' || c2 == 'O') {
        int c3 = read_byte(100);
        switch (c3) {
        case 'A': return MENU_KEY_UP;
        case 'B': return MENU_KEY_DOWN;
        case 'C': return MENU_KEY_RIGHT;
        case 'D': return MENU_KEY_LEFT;
        default:  return MENU_KEY_ESC;   /* 未知序列按 ESC */
        }
    }
    return MENU_KEY_ESC;            /* 单独的 ESC */
}

/* 读取一行文本（自动回显，支持退格/ESC 取消） */
int menu_read_line(char *buf, size_t size)
{
    if (buf == NULL || size == 0) {
        return -1;
    }
    size_t i = 0;

    while (1) {
        int key = menu_wait_key();
        if (key == '\r' || key == '\n') {
            buf[i] = '\0';
            printf("\n");
            return (int)i;
        }
        if (key == MENU_KEY_ESC) {
            buf[i] = '\0';
            printf("\n");
            return -1;
        }
        if (key == 0x7F || key == '\b') {   /* 退格 */
            if (i > 0) {
                i--;
                printf("\b \b");
            }
            continue;
        }
        if (key >= 0x20 && key < 0x7F) {    /* 可打印 ASCII */
            if (i < size - 1) {
                buf[i++] = (char)key;
                printf("%c", key);          /* 回显 */
            }
        }
        /* 其它键忽略 */
    }
}

/* 光标选择：上/下移动，Enter 确认，ESC 取消 */
int menu_select(const char **items, int count, const char *title)
{
    if (items == NULL || count <= 0) {
        return -1;
    }
    int selected = 0;
    while (1) {
        printf(ANSI_CLEAR_SCREEN ANSI_CURSOR_HOME);
        if (title != NULL && *title != '\0') {
            printf(ANSI_CYAN "---- %s ----" ANSI_RESET "\n", title);
        }
        for (int i = 0; i < count; i++) {
            if (i == selected) {
                printf(ANSI_GREEN ANSI_BOLD "> %s" ANSI_RESET "\n", items[i]);
            } else {
                printf("  %s\n", items[i]);
            }
        }
        printf("\n" ANSI_DIM "%s" ANSI_RESET "\n",
               i18n_t("上/下 移动   Enter 确认   ESC 取消"));
        int key = menu_wait_key();
        if (key == MENU_KEY_UP || key == 'w' || key == 'W') {
            selected = (selected - 1 + count) % count;
        } else if (key == MENU_KEY_DOWN || key == 's' || key == 'S') {
            selected = (selected + 1) % count;
        } else if (key == MENU_KEY_ENTER || key == '\n') {
            return selected;
        } else if (key == MENU_KEY_ESC || key == 'q' || key == 'Q') {
            return -1;
        }
    }
}

/* 上下双框样式：两个 '│' 之间的内容可用列宽 */
#define MENU_INNER_W 46

/* 近似显示宽度：ASCII=1 列，CJK/宽字符≈2 列（用于右侧边框对齐） */
static int utf8_dispwidth(const char *s)
{
    int w = 0;
    const unsigned char *p = (const unsigned char *)s;
    while (*p != 0) {
        if (*p < 0x80) {
            w++; p++;
        } else if ((*p & 0xE0) == 0xC0) {
            w += 1; p += 2;
        } else if ((*p & 0xF0) == 0xE0) {
            w += 2; p += 3;                 /* CJK 等宽字符 */
        } else {
            w += 1; p += 1;
        }
    }
    return w;
}

/* 顶边：┌ + 若干 ─ + [colored title] + 若干 ─ + ┐（title 居中） */
static void box_hline(int n)
{
    for (int i = 0; i < n; i++) {
        printf("─");
    }
}

static void box_top(const char *title, const char *color)
{
    printf("┌");
    /* title 显示宽度 + 两侧空格(2) */
    int dw = (title != NULL && *title != '\0') ? (utf8_dispwidth(title) + 2) : 0;
    int left = (MENU_INNER_W - dw) / 2;
    if (left < 0) {
        left = 0;
    }
    box_hline(left);
    if (dw > 0) {
        if (color != NULL) {
            printf("%s", color);
        }
        printf(" %s ", title);
        if (color != NULL) {
            printf(ANSI_RESET);
        }
        int right = MENU_INNER_W - left - dw;
        if (right < 0) {
            right = 0;
        }
        box_hline(right);
    } else {
        box_hline(MENU_INNER_W - left);
    }
    printf("┐\n");
}

/* 底边：└ + ─×N + ┘ */
static void box_bottom(void)
{
    printf("└");
    box_hline(MENU_INNER_W);
    printf("┘\n");
}

/* 内容行：│ <content> <右补空格> │，text 可带颜色前缀(不计宽度) */
static void box_row(const char *content, const char *color)
{
    printf("│ ");
    if (color != NULL) {
        printf("%s", color);
    }
    printf("%s", content);
    if (color != NULL) {
        printf(ANSI_RESET);
    }
    int used = utf8_dispwidth(content);
    for (int i = used; i < MENU_INNER_W - 2; i++) {
        putchar(' ');
    }
    printf(" │\n");
}

/* 欢迎横幅 + 网络/蓝牙/内存状态 + 当前屏幕标题 */
static void print_screen(const menu_screen_t *screen, int selected)
{
    size_t free_heap  = esp_get_free_heap_size();
    size_t total_heap = heap_caps_get_total_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    uint32_t flash_size = 0;
    char net_status[64];
    char bt_status[48];
    char net_row[80];
    char bt_row[80];
    char mem_row[80];
    char flash_row[80];
    char item_row[80];
    esp_flash_get_size(NULL, &flash_size);
    wifi_get_status_text(net_status, sizeof(net_status));
    if (eth_has_ip()) {
        eth_get_status_text(net_status, sizeof(net_status));
    }
    ble_get_status_text(bt_status, sizeof(bt_status));

    printf(ANSI_CLEAR_SCREEN ANSI_CURSOR_HOME);

    /* ---------- 上框：品牌 + 系统状态 ---------- */
    box_top(i18n_t("欢迎使用 espgyscan"), ANSI_YELLOW);

    snprintf(net_row, sizeof(net_row), "%s %s",
             I18N("网络：", "Net: "), net_status);
    box_row(net_row, ANSI_CYAN);

    snprintf(bt_row, sizeof(bt_row), "%s %s",
             I18N("蓝牙：", "BLE: "), bt_status);
    box_row(bt_row, ANSI_BLUE);

    snprintf(mem_row, sizeof(mem_row), "%s %zu KB / %zu KB",
             I18N("内存：", "RAM: "), free_heap / 1024, total_heap / 1024);
    box_row(mem_row, ANSI_YELLOW);

    snprintf(flash_row, sizeof(flash_row), "%s %" PRIu32 " MB",
             I18N("储存(Flash)：", "Flash: "), flash_size / (1024 * 1024));
    box_row(flash_row, ANSI_MAGENTA);

    box_bottom();
    printf("\n");

    /* ---------- 下框：菜单列表 ---------- */
    box_top(i18n_t(screen->title ? screen->title : ""), ANSI_WHITE);

    for (int i = 0; i < screen->item_count; i++) {
        if (i == selected) {
            snprintf(item_row, sizeof(item_row), "> %s",
                     i18n_t(screen->items[i].title));
            box_row(item_row, ANSI_GREEN ANSI_BOLD);
        } else {
            snprintf(item_row, sizeof(item_row), "  %s",
                     i18n_t(screen->items[i].title));
            box_row(item_row, ANSI_DIM);
        }
    }

    box_bottom();
    printf("\n");
    printf(ANSI_DIM);
    printf(I18N("WASD/方向键 移动   Enter 确认   ESC 返回/退出\n",
                "WASD/Arrows  Move   Enter  OK   ESC  Back/Exit\n"));
    printf(ANSI_RESET);
}

/* 动作执行结束后等待 ESC 返回 */
static void wait_return(void)
{
    printf("\n%s\n", i18n_t("按 ESC 返回菜单..."));
    while (1) {
        int key = menu_wait_key();
        if (key == MENU_KEY_ESC || key == MENU_KEY_ENTER || key == '\n' || key == 'q' || key == 'Q') {
            break;
        }
    }
    /* 注意：不要在这里丢弃后续按键——用户紧接着的 ESC/Enter
     * 可能是返回主菜单/退出菜单的意图，吞掉会导致"无法退出"。 */
}

/* 递归运行一个菜单屏幕 */
static menu_handler_t s_exit_handler = NULL;

void menu_set_exit_handler(menu_handler_t handler)
{
    s_exit_handler = handler;
}

static void run_screen(const menu_screen_t *screen, bool is_root)
{
    if (screen == NULL || screen->items == NULL || screen->item_count <= 0) {
        return;
    }

    int selected = 0;

    while (1) {
        print_screen(screen, selected);
        int key = menu_wait_key();

        if (key == MENU_KEY_UP || key == 'w' || key == 'W') {
            selected = (selected - 1 + screen->item_count) % screen->item_count;
        } else if (key == MENU_KEY_DOWN || key == 's' || key == 'S') {
            selected = (selected + 1) % screen->item_count;
        } else if (key == MENU_KEY_LEFT || key == 'a' || key == 'A' ||
                   key == MENU_KEY_RIGHT || key == 'd' || key == 'D') {
            /* 纵向列表无左右移动，忽略 */
        } else if (key == MENU_KEY_ENTER || key == '\n') {
            const menu_item_t *item = &screen->items[selected];
            if (item->submenu != NULL) {
                run_screen(item->submenu, false);
            } else if (item->handler != NULL) {
                printf("\n");
                item->handler();
                wait_return();
            }
        } else if (key == MENU_KEY_ESC || key == 'q' || key == 'Q') {
            if (is_root) {
                /* 主菜单是顶级菜单：结束程序需"关机"。
                 * 有退出处理器(关机确认)时调用它；确认后不再返回，取消则继续。 */
                if (s_exit_handler != NULL) {
                    s_exit_handler();
                    continue;   /* 用户取消关机 → 留在主菜单 */
                }
                printf("\n%s\n", i18n_t("已退出菜单"));
            }
            return;   /* 子菜单返回上级 */
        }
    }
}

void menu_run(const menu_screen_t *screen)
{
    /* 无缓冲，保证按键/输出立即生效 */
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    run_screen(screen, true);
}

