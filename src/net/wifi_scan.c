/*
 * wifi_scan.c - WiFi STA 连接
 *
 * 功能：
 *   - wifi_sta_connect(): 连接 menuconfig 中配置的 WiFi，等待获得 IP
 *
 * 相关配置项见 Kconfig.projbuild 中的 "gyscan Configuration" 菜单。
 */

#include "wifi_scan.h"
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "sdkconfig.h"
#include "i18n.h"

static const char *TAG = "wifi";

#define WIFI_GOT_IP_BIT BIT0
#define WIFI_FAIL_BIT   BIT1

static EventGroupHandle_t s_wifi_events;
static bool s_wifi_inited = false;
static int s_retry_count = 0;

/* 当前生效的连接凭据：默认来自 menuconfig，可在运行时覆盖 */
static char s_active_ssid[33] = CONFIG_GYSCAN_WIFI_SSID;
static char s_active_password[65] = CONFIG_GYSCAN_WIFI_PASSWORD;

static void wifi_event_handler(void *arg, esp_event_base_t base,
                               int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry_count++ < CONFIG_GYSCAN_WIFI_MAX_RETRY) {
            ESP_LOGW(TAG, "连接断开，重试中(%d/%d)...",
                     s_retry_count, CONFIG_GYSCAN_WIFI_MAX_RETRY);
            esp_wifi_connect();
        } else {
            xEventGroupSetBits(s_wifi_events, WIFI_FAIL_BIT);
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "获取到 IP: " IPSTR, IP2STR(&event->ip_info.ip));
        s_retry_count = 0;
        xEventGroupSetBits(s_wifi_events, WIFI_GOT_IP_BIT);
    }
}

/* 初始化 WiFi(STA)（只执行一次）；失败不崩溃，返回错误码 */
static esp_err_t wifi_common_init(void)
{
    if (s_wifi_inited) {
        return ESP_OK;
    }

    esp_err_t ret = esp_netif_init();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        return ret;
    }
    ret = esp_event_loop_create_default();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        return ret;
    }
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ret = esp_wifi_init(&cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_init 失败: %s (当前平台可能不支持 WiFi)",
                 esp_err_to_name(ret));
        return ret;
    }
    ret = esp_wifi_set_mode(WIFI_MODE_STA);
    if (ret != ESP_OK) {
        return ret;
    }
    ret = esp_wifi_start();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_start 失败: %s", esp_err_to_name(ret));
        return ret;
    }

    s_wifi_inited = true;
    ESP_LOGI(TAG, "WiFi (STA) 已初始化");
    return ESP_OK;
}

/* 使用当前生效的 SSID/密码发起连接并等待 IP */
static esp_err_t wifi_connect_active(void)
{
    /* 已连接则直接返回 */
    wifi_ap_record_t ap = {0};
    if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        ESP_LOGI(TAG, "已连接到 %s", ap.ssid);
        return ESP_OK;
    }

    xEventGroupClearBits(s_wifi_events, WIFI_GOT_IP_BIT | WIFI_FAIL_BIT);
    s_retry_count = 0;

    wifi_config_t cfg = {0};
    strncpy((char *)cfg.sta.ssid, s_active_ssid, sizeof(cfg.sta.ssid) - 1);
    if (strlen(s_active_password) > 0) {
        strncpy((char *)cfg.sta.password, s_active_password, sizeof(cfg.sta.password) - 1);
    }
    cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;

    esp_err_t ret = esp_wifi_set_config(WIFI_IF_STA, &cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "设置 WiFi 配置失败: %s", esp_err_to_name(ret));
        return ret;
    }
    ESP_LOGI(TAG, "正在连接 %s ...", s_active_ssid);
    esp_wifi_connect();

    EventBits_t bits = xEventGroupWaitBits(s_wifi_events,
                                           WIFI_GOT_IP_BIT | WIFI_FAIL_BIT,
                                           pdFALSE, pdFALSE,
                                           pdMS_TO_TICKS(CONFIG_GYSCAN_WIFI_CONNECT_TIMEOUT_MS));
    if (bits & WIFI_GOT_IP_BIT) {
        return ESP_OK;
    }

    ESP_LOGE(TAG, "连接失败或超时，请检查 SSID/密码与信号强度");
    return ESP_ERR_WIFI_NOT_CONNECT;
}

esp_err_t wifi_sta_connect(void)
{
    esp_err_t ret = wifi_common_init();
    if (ret != ESP_OK) {
        return ret;
    }

    if (s_wifi_events == NULL) {
        s_wifi_events = xEventGroupCreate();
        ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                   &wifi_event_handler, NULL));
        ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                   &wifi_event_handler, NULL));
    }

    return wifi_connect_active();
}

esp_err_t wifi_connect_custom(const char *ssid, const char *password)
{
    if (ssid == NULL || ssid[0] == '\0') {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t ret = wifi_common_init();
    if (ret != ESP_OK) {
        return ret;
    }
    if (s_wifi_events == NULL) {
        s_wifi_events = xEventGroupCreate();
        ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                                   &wifi_event_handler, NULL));
        ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                                   &wifi_event_handler, NULL));
    }

    strncpy(s_active_ssid, ssid, sizeof(s_active_ssid) - 1);
    s_active_ssid[sizeof(s_active_ssid) - 1] = '\0';
    if (password != NULL) {
        strncpy(s_active_password, password, sizeof(s_active_password) - 1);
        s_active_password[sizeof(s_active_password) - 1] = '\0';
    } else {
        s_active_password[0] = '\0';
    }
    ESP_LOGI(TAG, "已更新连接目标: %s", s_active_ssid);

    return wifi_connect_active();
}

esp_err_t wifi_disconnect(void)
{
    if (!s_wifi_inited) {
        return ESP_ERR_INVALID_STATE;
    }
    esp_err_t ret = esp_wifi_disconnect();
    if (ret == ESP_OK) {
        ESP_LOGI(TAG, "WiFi 已断开");
    } else if (ret == ESP_ERR_WIFI_NOT_CONNECT) {
        ESP_LOGI(TAG, "WiFi 当前未连接");
        return ESP_OK;
    }
    return ret;
}

const char *wifi_get_active_ssid(void)
{
    return s_active_ssid;
}

void wifi_get_status_text(char *buf, size_t buf_sz)
{
    if (buf == NULL || buf_sz == 0) {
        return;
    }
    if (!s_wifi_inited) {
        snprintf(buf, buf_sz, "%s", i18n_t("未启用"));
        return;
    }
    esp_netif_t *nif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    esp_netif_ip_info_t ip;
    if (nif != NULL && esp_netif_get_ip_info(nif, &ip) == ESP_OK) {
        char ipstr[16];
        snprintf(ipstr, sizeof(ipstr), IPSTR, IP2STR(&ip.ip));
        snprintf(buf, buf_sz, I18N("已连接 %s (%s)", "Connected %s (%s)"),
                 s_active_ssid, ipstr);
    } else {
        snprintf(buf, buf_sz, I18N("未连接 (目标 %s)", "Not connected (target %s)"),
                 s_active_ssid);
    }
}

bool wifi_is_connected(void)
{
    if (!s_wifi_inited) {
        return false;
    }
    wifi_ap_record_t ap = {0};
    return esp_wifi_sta_get_ap_info(&ap) == ESP_OK;
}
