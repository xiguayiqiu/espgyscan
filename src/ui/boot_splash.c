/*
 * boot_splash.c - ESP32-S3 (GYscan) 开机 ASCII 动画
 *
 * 启动时在串口控制台播放：
 *   1. 清屏并隐藏光标，逐行刷出大字 "ESP32"(青色)
 *   2. 逐行刷出大字 "GYscan"(绿色)
 *   3. 打字机式副标题
 *   4. 进度条填充动画
 *
 * 特点：纯 printf 输出，不依赖任何外设，QEMU/真机串口均适用。
 * 大字样式参考 FIGlet "slant" 字体(ASCII 字符生成)。
 */

#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "boot_splash.h"

/* ANSI 控制序列(仅对支持 ANSI 的终端生效，普通串口工具也能显示文本) */
#define ANSI_CLEAR_SCREEN  "\033[2J"
#define ANSI_CURSOR_HOME   "\033[H"
#define ANSI_HIDE_CURSOR   "\033[?25l"
#define ANSI_SHOW_CURSOR   "\033[?25h"
#define ANSI_BOLD          "\033[1m"
#define ANSI_DIM           "\033[2m"
#define ANSI_CYAN          "\033[36m"
#define ANSI_GREEN         "\033[32m"
#define ANSI_YELLOW        "\033[33m"
#define ANSI_RESET         "\033[0m"

/* 大字画布：每行约 50 列，适合 80 列终端居中显示 */
static const char *const ART_ESP32[] = {
    "    ___________ ____ ________ ",
    "   / ____/ ___// __ \\__  /__ \\",
    "  / __/  \\__ \\/ /_/ //_ <__/ /",
    " / /___ ___/ / ____/__/ / __/ ",
    "/_____//____/_/   /____/____/ ",
    NULL
};

static const char *const ART_GYSCAN[] = {
    "   ________  __                    ",
    "  / ____/\\ \\/ /_____________ _____ ",
    " / / __   \\  / ___/ ___/ __ `/ __ \\",
    "/ /_/ /   / (__  ) /__/ /_/ / / / /",
    "\\____/   /_/____/\\___/\\__,_/_/ /_/ ",
    NULL
};

/* 以"逐行扫出"方式渲染一组大字，行间延迟 delay_ms */
static void art_reveal(const char *const rows[], const char *color, uint32_t delay_ms)
{
    for (int i = 0; rows[i] != NULL; i++) {
        int len = (int)strlen(rows[i]);
        int pad = (len < 80) ? (80 - len) / 2 : 0;   /* 居中 */
        printf("%s%*s%s%s\n", color, pad, "", rows[i], ANSI_RESET);
        fflush(stdout);
        vTaskDelay(pdMS_TO_TICKS(delay_ms));
    }
}

/* 打字机效果：普通字符逐个慢速打出，空格/汉字按字节快放，保证流畅 */
static void type_line(const char *color, const char *s)
{
    printf("%s", color);
    for (const char *p = s; *p != '\0'; p++) {
        putchar((int)*p);
        fflush(stdout);
        if ((unsigned char)*p < 0x80 && *p != ' ' && *p != '\t') {
            vTaskDelay(pdMS_TO_TICKS(10));
        }
    }
    printf("%s\n", ANSI_RESET);
}

/* 进度条："["=====>...."]" 逐格填充 */
static void progress_bar(void)
{
    const int total = 24;
    for (int i = 0; i < total; i++) {
        printf("\r  [");
        for (int j = 0; j < total; j++) {
            if (j < i) putchar('=');
            else if (j == i) putchar('>');
            else putchar(' ');
        }
        putchar(']');
        fflush(stdout);
        vTaskDelay(pdMS_TO_TICKS(40));
    }
    printf("\r  [");
    for (int j = 0; j < total; j++) putchar('=');
    printf("] %sOK%s\n", ANSI_CYAN, ANSI_RESET);
}

void boot_splash_show(void)
{
    printf(ANSI_CLEAR_SCREEN ANSI_CURSOR_HOME ANSI_HIDE_CURSOR);

    /* 1) ESP32 大字 */
    art_reveal(ART_ESP32, ANSI_CYAN ANSI_BOLD, 60);
    putchar('\n');

    /* 2) GYscan 大字 */
    art_reveal(ART_GYSCAN, ANSI_GREEN ANSI_BOLD, 60);
    putchar('\n');

    /* 3) 副标题(打字机) */
    type_line(ANSI_YELLOW, "  ESP32-S3 边缘安全调试工具 | GYscan");
    type_line(ANSI_DIM, "  ESP32-S3 Edge Security Debug Tool");
    putchar('\n');

    /* 4) 进度条 */
    printf("  ");
    progress_bar();

    type_line(ANSI_GREEN, "  系统启动中，请稍候...");

    printf(ANSI_SHOW_CURSOR);
    fflush(stdout);
}
