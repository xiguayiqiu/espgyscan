/*
 * hid_keyboard.c - USB HID 键盘设备（键盘模拟输入）
 *
 * 使用 TinyUSB 将 ESP32-S3 的 USB-OTG 口模拟为 HID 键盘。
 * 通过 USB 线连接电脑后，即可通过本模块注入按键/文本。
 *
 * 相关命令: type <文本> / key <名称>（经 1234 端口远程触发）
 */

#include "hid_keyboard.h"
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "class/hid/hid_device.h"

static const char *TAG = "hid";

/* ---------- TinyUSB HID 键盘描述符 ---------- */

#define TUSB_DESC_TOTAL_LEN (TUD_CONFIG_DESC_LEN + CFG_TUD_HID * TUD_HID_DESC_LEN)

static const uint8_t hid_report_descriptor[] = {
    TUD_HID_REPORT_DESC_KEYBOARD(HID_REPORT_ID(HID_ITF_PROTOCOL_KEYBOARD)),
};

static const char *hid_string_descriptor[5] = {
    (char[]){0x09, 0x04},          /* 0: 语言(英语) */
    "espgyscan",                   /* 1: Manufacturer */
    "gyscan Keyboard",             /* 2: Product */
    "123456",                      /* 3: Serial */
    "gyscan HID Keyboard",         /* 4: HID 接口 */
};

static const uint8_t hid_configuration_descriptor[] = {
    TUD_CONFIG_DESCRIPTOR(1, 1, 0, TUSB_DESC_TOTAL_LEN, TUSB_DESC_CONFIG_ATT_REMOTE_WAKEUP, 100),
    TUD_HID_DESCRIPTOR(0, 4, false, sizeof(hid_report_descriptor), 0x81, 16, 10),
};

/* ---------- TinyUSB 回调 ---------- */

uint8_t const *tud_hid_descriptor_report_cb(uint8_t instance)
{
    (void)instance;
    return hid_report_descriptor;
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id,
                               hid_report_type_t report_type,
                               uint8_t *buffer, uint16_t reqlen)
{
    (void)instance; (void)report_id; (void)report_type; (void)buffer; (void)reqlen;
    return 0;
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id,
                           hid_report_type_t report_type,
                           uint8_t const *buffer, uint16_t bufsize)
{
    (void)instance; (void)report_id; (void)report_type; (void)buffer; (void)bufsize;
}

/* ---------- 内部实现 ---------- */

static SemaphoreHandle_t s_hid_lock = NULL;

/* TinyUSB 内置的 ASCII -> (shift, keycode) 转换表（宏需要外层大括号包裹） */
static const uint8_t s_keycode_map[128][2] = { HID_ASCII_TO_KEYCODE };

typedef struct {
    const char *name;
    uint8_t modifier;
    uint8_t keycode;
} special_key_t;

static const special_key_t s_special_keys[] = {
    { "ENTER",      0,                              HID_KEY_ENTER },
    { "RETURN",     0,                              HID_KEY_ENTER },
    { "ESC",        0,                              HID_KEY_ESCAPE },
    { "TAB",        0,                              HID_KEY_TAB },
    { "SPACE",      0,                              HID_KEY_SPACE },
    { "BACKSPACE",  0,                              HID_KEY_BACKSPACE },
    { "DELETE",     0,                              HID_KEY_DELETE },
    { "DEL",        0,                              HID_KEY_DELETE },
    { "INSERT",     0,                              HID_KEY_INSERT },
    { "HOME",       0,                              HID_KEY_HOME },
    { "END",        0,                              HID_KEY_END },
    { "PAGE_UP",    0,                              HID_KEY_PAGE_UP },
    { "PAGE_DOWN",  0,                              HID_KEY_PAGE_DOWN },
    { "UP",         0,                              HID_KEY_ARROW_UP },
    { "DOWN",       0,                              HID_KEY_ARROW_DOWN },
    { "LEFT",       0,                              HID_KEY_ARROW_LEFT },
    { "RIGHT",      0,                              HID_KEY_ARROW_RIGHT },
    { "F1",         0,                              HID_KEY_F1 },
    { "F2",         0,                              HID_KEY_F2 },
    { "F3",         0,                              HID_KEY_F3 },
    { "F4",         0,                              HID_KEY_F4 },
    { "F5",         0,                              HID_KEY_F5 },
    { "F6",         0,                              HID_KEY_F6 },
    { "F7",         0,                              HID_KEY_F7 },
    { "F8",         0,                              HID_KEY_F8 },
    { "F9",         0,                              HID_KEY_F9 },
    { "F10",        0,                              HID_KEY_F10 },
    { "F11",        0,                              HID_KEY_F11 },
    { "F12",        0,                              HID_KEY_F12 },
    { "CTRL_A",     KEYBOARD_MODIFIER_LEFTCTRL,     HID_KEY_A },
    { "CTRL_B",     KEYBOARD_MODIFIER_LEFTCTRL,     HID_KEY_B },
    { "CTRL_C",     KEYBOARD_MODIFIER_LEFTCTRL,     HID_KEY_C },
    { "CTRL_D",     KEYBOARD_MODIFIER_LEFTCTRL,     HID_KEY_D },
    { "CTRL_E",     KEYBOARD_MODIFIER_LEFTCTRL,     HID_KEY_E },
    { "CTRL_F",     KEYBOARD_MODIFIER_LEFTCTRL,     HID_KEY_F },
    { "CTRL_V",     KEYBOARD_MODIFIER_LEFTCTRL,     HID_KEY_V },
    { "CTRL_X",     KEYBOARD_MODIFIER_LEFTCTRL,     HID_KEY_X },
    { "CTRL_Z",     KEYBOARD_MODIFIER_LEFTCTRL,     HID_KEY_Z },
    { "ALT_TAB",    KEYBOARD_MODIFIER_LEFTALT,      HID_KEY_TAB },
    { "WIN",        KEYBOARD_MODIFIER_LEFTGUI,      0 },
};

/* 发送一次 按键(按下+释放) */
static void send_key(uint8_t modifier, uint8_t keycode)
{
    uint8_t keycodes[6] = { keycode, 0, 0, 0, 0, 0 };
    tud_hid_keyboard_report(HID_ITF_PROTOCOL_KEYBOARD, modifier, keycodes);
    vTaskDelay(pdMS_TO_TICKS(20));
    tud_hid_keyboard_report(HID_ITF_PROTOCOL_KEYBOARD, 0, NULL);   /* 释放 */
    vTaskDelay(pdMS_TO_TICKS(10));
}

/*
 * 预检 USB-OTG(DWC2) 控制器是否真实存在。
 * 与 TinyUSB dwc2 驱动使用相同的基址/偏移/校验值：
 * QEMU 等未模拟 USB 硬件的平台读回 0，直接跳过初始化，
 * 避免 tinyusb_driver_install 空等 5 秒并刷错误日志。
 */
static bool usb_otg_present(void)
{
    volatile uint32_t *gsnpsid =
        (volatile uint32_t *)(0x60080000UL + 0x40);   /* DWC2 FS 基址 + GSNPSID 偏移 */
    uint32_t id = *gsnpsid & 0xFFFF0000u;
    return (id == 0x4f540000u) || (id == 0x55310000u) || (id == 0x55320000u);
}

esp_err_t hid_keyboard_init(void)
{
    if (!usb_otg_present()) {
        ESP_LOGW(TAG, "未检测到 USB-OTG 控制器(模拟器/无硬件?)，跳过 USB 键盘初始化");
        return ESP_ERR_NOT_SUPPORTED;
    }

    if (s_hid_lock == NULL) {
        s_hid_lock = xSemaphoreCreateMutex();
    }

    ESP_LOGI(TAG, "初始化 USB HID 键盘...");

    tinyusb_config_t tusb_cfg = TINYUSB_DEFAULT_CONFIG();
    tusb_cfg.descriptor.device = NULL;
    tusb_cfg.descriptor.full_speed_config = hid_configuration_descriptor;
    tusb_cfg.descriptor.string = hid_string_descriptor;
    tusb_cfg.descriptor.string_count = sizeof(hid_string_descriptor) / sizeof(hid_string_descriptor[0]);
#if (TUD_OPT_HIGH_SPEED)
    tusb_cfg.descriptor.high_speed_config = hid_configuration_descriptor;
#endif

    esp_err_t ret = tinyusb_driver_install(&tusb_cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "TinyUSB 初始化失败: %s", esp_err_to_name(ret));
        return ret;
    }
    ESP_LOGI(TAG, "USB HID 键盘就绪（USB 线连接电脑后自动枚举为键盘）");
    return ESP_OK;
}

bool hid_keyboard_is_mounted(void)
{
    return tud_mounted();
}

esp_err_t hid_keyboard_type_text(const char *text)
{
    if (text == NULL || s_hid_lock == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (xSemaphoreTake(s_hid_lock, pdMS_TO_TICKS(500)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    if (!tud_mounted()) {
        xSemaphoreGive(s_hid_lock);
        return ESP_ERR_INVALID_STATE;
    }

    int typed = 0;
    for (const char *p = text; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        if (c >= 128) {
            continue;   /* 仅支持 ASCII，非 ASCII 字符跳过 */
        }
        const uint8_t *map = s_keycode_map[c];
        if (map[1] == 0) {
            continue;
        }
        uint8_t modifier = map[0] ? KEYBOARD_MODIFIER_LEFTSHIFT : 0;
        send_key(modifier, map[1]);
        typed++;
    }

    xSemaphoreGive(s_hid_lock);
    ESP_LOGI(TAG, "键盘输入完成，共 %d 个字符", typed);
    return ESP_OK;
}

esp_err_t hid_keyboard_press_name(const char *name)
{
    if (name == NULL || s_hid_lock == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    for (int i = 0; i < (int)(sizeof(s_special_keys) / sizeof(s_special_keys[0])); i++) {
        if (strcasecmp(name, s_special_keys[i].name) == 0) {
            if (xSemaphoreTake(s_hid_lock, pdMS_TO_TICKS(500)) != pdTRUE) {
                return ESP_ERR_TIMEOUT;
            }
            if (!tud_mounted()) {
                xSemaphoreGive(s_hid_lock);
                return ESP_ERR_INVALID_STATE;
            }
            send_key(s_special_keys[i].modifier, s_special_keys[i].keycode);
            xSemaphoreGive(s_hid_lock);
            ESP_LOGI(TAG, "已发送按键 %s", name);
            return ESP_OK;
        }
    }
    return ESP_ERR_NOT_FOUND;
}

/* 发送任意组合键（按下+释放）：用于 keyhub 无线键盘的任意键/组合键模拟 */
static esp_err_t hid_press_report_locked(uint8_t modifier, const uint8_t *keycodes)
{
    uint8_t kc[6] = { 0, 0, 0, 0, 0, 0 };
    if (keycodes != NULL) {
        for (int i = 0; i < 6; i++) {
            kc[i] = keycodes[i];
        }
    }
    if (xSemaphoreTake(s_hid_lock, pdMS_TO_TICKS(500)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    if (!tud_mounted()) {
        xSemaphoreGive(s_hid_lock);
        return ESP_ERR_INVALID_STATE;
    }
    tud_hid_keyboard_report(HID_ITF_PROTOCOL_KEYBOARD, modifier, kc);
    vTaskDelay(pdMS_TO_TICKS(15));
    tud_hid_keyboard_report(HID_ITF_PROTOCOL_KEYBOARD, 0, NULL);
    vTaskDelay(pdMS_TO_TICKS(10));
    xSemaphoreGive(s_hid_lock);
    return ESP_OK;
}

esp_err_t hid_keyboard_press_report(uint8_t modifier, const uint8_t *keycodes)
{
    if (s_hid_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    return hid_press_report_locked(modifier, keycodes);
}

esp_err_t hid_keyboard_type_char(char c)
{
    if (s_hid_lock == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    unsigned char uc = (unsigned char)c;
    if (uc == '\r') {
        uc = '\n';
    }
    if (uc == '\n') {
        return hid_press_report_locked(0, (const uint8_t[]){ HID_KEY_ENTER });
    }
    if (uc == '\t') {
        return hid_press_report_locked(0, (const uint8_t[]){ HID_KEY_TAB });
    }
    if (uc >= 32 && uc < 128) {
        const uint8_t *map = s_keycode_map[uc];
        if (map[1] == 0) {
            return ESP_OK;
        }
        uint8_t mod = map[0] ? KEYBOARD_MODIFIER_LEFTSHIFT : 0;
        return hid_press_report_locked(mod, &map[1]);
    }
    return ESP_OK;   /* 其他控制字符忽略 */
}


