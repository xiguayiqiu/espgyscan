#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 初始化 USB HID 键盘设备（TinyUSB），ESP 通过 USB 线连接电脑后会被识别为键盘 */
esp_err_t hid_keyboard_init(void);

/* USB 键盘是否已被电脑枚举（USB 线连接成功） */
bool hid_keyboard_is_mounted(void);

/* 通过 HID 输入一段 ASCII 文本（自动处理大小写与符号） */
esp_err_t hid_keyboard_type_text(const char *text);

/*
 * 通过 HID 按下特殊键（按下并释放）
 * 支持的名称: ENTER/RETURN, ESC, TAB, BACKSPACE, DELETE/DEL, SPACE,
 * UP, DOWN, LEFT, RIGHT, HOME, END, PAGE_UP, PAGE_DOWN, INSERT,
 * F1~F12, CTRL_A~CTRL_Z, ALT_TAB, WIN, WIN_R 等
 */
esp_err_t hid_keyboard_press_name(const char *name);

/*
 * 通过 HID 发送任意组合键（按下并释放），用于 keyhub 无线键盘。
 * modifier: KEYBOARD_MODIFIER_* 位或（LEFTSHIFT/LEFTCTRL/LEFTALT/LEFTGUI...）。
 * keycodes: 最多 6 个同时按下的 HID 键码数组（如 HID_KEY_A），可为 NULL。
 * 此接口可表达任意组合键（Ctrl+Shift+K、Alt+Tab、Win+R、Ctrl+Alt+Delete 等）。
 */
esp_err_t hid_keyboard_press_report(uint8_t modifier, const uint8_t *keycodes);

/* 把单个 ASCII 字符（可打印或 \n \r \t）即时输入（keyhub 文本流用） */
esp_err_t hid_keyboard_type_char(char c);

#ifdef __cplusplus
}
#endif
