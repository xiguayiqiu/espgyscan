#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 连接 menuconfig 中配置的 WiFi，等待获得 IP
 * 返回 ESP_OK 表示已连接；否则返回错误码
 */
esp_err_t wifi_sta_connect(void);

/* 当前是否已连接 WiFi */
bool wifi_is_connected(void);

/*
 * 使用运行时指定的 SSID/密码连接 WiFi（会覆盖 menuconfig 默认，
 * 对后续自动重连也生效）
 */
esp_err_t wifi_connect_custom(const char *ssid, const char *password);

/* 断开当前 WiFi 连接 */
esp_err_t wifi_disconnect(void);

/* 当前生效的 SSID（menuconfig 默认或运行时设置的） */
const char *wifi_get_active_ssid(void);

/* 生成 WiFi 状态文本：如 "已连接 MyWiFi (192.168.1.5)" 或 "未连接" */
void wifi_get_status_text(char *buf, size_t buf_sz);

#ifdef __cplusplus
}
#endif
