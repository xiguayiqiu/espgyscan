/*
 * eth_netif.c - QEMU 以太网支持 (OpenCores MAC, openeth)
 *
 * ESP32-S3 的 QEMU 模拟提供 open_eth 网卡；其 openeth MAC 与
 * 通用 PHY 由 esp_eth 组件实现(CONFIG_ETH_USE_OPENETH)。
 * 本模块仅在 CONFIG_ETH_USE_OPENETH=y 时参与编译，
 * 用于在 QEMU 中让 HTTP(80)/gyscan(1234) 服务真正可访问。
 */

#include "eth_netif.h"
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_eth.h"
#include "esp_event.h"
#include "sdkconfig.h"
#include "i18n.h"

#if defined(CONFIG_ETH_USE_OPENETH)

#include "esp_eth_mac_openeth.h"

static const char *TAG = "eth";

static esp_netif_t *s_eth_netif = NULL;
static esp_eth_handle_t s_eth_handle = NULL;
static volatile bool s_got_ip = false;

static void eth_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    esp_eth_handle_t eth = *(esp_eth_handle_t *)data;
    (void)eth;
    switch (id) {
    case ETHERNET_EVENT_CONNECTED:
        ESP_LOGI(TAG, "Ethernet Link Up");
        break;
    case ETHERNET_EVENT_DISCONNECTED:
        ESP_LOGI(TAG, "Ethernet Link Down");
        break;
    default:
        break;
    }
}

static void eth_got_ip_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    ip_event_got_ip_t *ev = (ip_event_got_ip_t *)data;
    s_got_ip = true;
    ESP_LOGI(TAG, "Ethernet Got IP: " IPSTR, IP2STR(&ev->ip_info.ip));
}

bool eth_start(void)
{
    if (s_eth_netif != NULL) {
        return true;   /* 已启动 */
    }

    esp_err_t ret = esp_netif_init();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "netif init failed: %s", esp_err_to_name(ret));
        return false;
    }
    ret = esp_event_loop_create_default();
    if (ret != ESP_OK && ret != ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "event loop failed: %s", esp_err_to_name(ret));
        return false;
    }

    /* openeth MAC (QEMU) + 通用 PHY */
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    esp_eth_mac_t *mac = esp_eth_mac_new_openeth(&mac_config);
    if (mac == NULL) {
        ESP_LOGE(TAG, "create openeth MAC failed");
        return false;
    }
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    esp_eth_phy_t *phy = esp_eth_phy_new_generic(&phy_config);
    if (phy == NULL) {
        ESP_LOGE(TAG, "create PHY failed");
        mac->del(mac);
        return false;
    }

    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    if (esp_eth_driver_install(&eth_config, &s_eth_handle) != ESP_OK) {
        ESP_LOGE(TAG, "eth driver install failed");
        phy->del(phy);
        mac->del(mac);
        return false;
    }

    /* netif + glue */
    esp_netif_config_t netif_cfg = ESP_NETIF_DEFAULT_ETH();
    s_eth_netif = esp_netif_new(&netif_cfg);
    esp_eth_netif_glue_handle_t glue = esp_eth_new_netif_glue(s_eth_handle);
    if (esp_netif_attach(s_eth_netif, glue) != ESP_OK) {
        ESP_LOGE(TAG, "netif attach failed");
        return false;
    }

    esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &eth_got_ip_handler, NULL);

    if (esp_eth_start(s_eth_handle) != ESP_OK) {
        ESP_LOGE(TAG, "eth start failed");
        return false;
    }
    ESP_LOGI(TAG, "QEMU 以太网已启动，等待 DHCP...");
    return true;
}

bool eth_got_ip(void)
{
    return s_got_ip;
}

bool eth_has_ip(void)
{
    esp_netif_t *nif = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_ip_info_t ip;
    if (nif != NULL && esp_netif_get_ip_info(nif, &ip) == ESP_OK && ip.ip.addr != 0) {
        return true;
    }
    return false;
}

void eth_get_status_text(char *buf, size_t buf_sz)
{
    if (buf == NULL || buf_sz == 0) {
        return;
    }
    esp_netif_t *nif = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_ip_info_t ip;
    if (nif != NULL && esp_netif_get_ip_info(nif, &ip) == ESP_OK && ip.ip.addr != 0) {
        char ipstr[16];
        snprintf(ipstr, sizeof(ipstr), IPSTR, IP2STR(&ip.ip));
        snprintf(buf, buf_sz, I18N("已连接 以太网 (%s)", "Connected Ethernet (%s)"), ipstr);
    } else {
        snprintf(buf, buf_sz, "%s", i18n_t("未连接"));
    }
}

#else  /* !CONFIG_ETH_USE_OPENETH */
/* 真机 / 未启用 openeth：空实现，不影响 WiFi 流程 */
bool eth_start(void) { return false; }
bool eth_got_ip(void) { return false; }
bool eth_has_ip(void) { return false; }
void eth_get_status_text(char *buf, size_t buf_sz)
{
    if (buf != NULL && buf_sz > 0) {
        snprintf(buf, buf_sz, "%s", i18n_t("未连接"));
    }
}
#endif
