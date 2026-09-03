/*
 * ble_scan.c - 蓝牙(BLE)探测与配对
 *
 * 使用 ESP-IDF 内置的 NimBLE 协议栈：
 *   - ble_scan_run(): 扫描附近 BLE 广播设备并打印列表
 *   - ble_pair_run(): 扫描 → 用户选择设备 → 连接 → 发起配对/加密
 *
 * 注意：ESP32-S3 仅支持 BLE（不支持经典蓝牙）。
 * 扫描时长由 CONFIG_GYSCAN_BLE_SCAN_DURATION_MS 配置。
 */

#include "ble_scan.h"
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_err.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"
#include "sdkconfig.h"
#include "menu.h"
#include "i18n.h"

static const char *TAG = "ble";

/* 数字键选择最多支持 9 个设备 */
#define BLE_MAX_DEVS   9
#define BLE_CONN_TIMEOUT_MS   15000
#define BLE_SECURITY_TIMEOUT_MS 20000

typedef struct {
    ble_addr_t addr;
    char name[32];
    int8_t rssi;
} ble_dev_t;

static bool s_ble_inited = false;
static SemaphoreHandle_t s_op_sem = NULL;

/* 扫描结果 */
static ble_dev_t s_devs[BLE_MAX_DEVS];
static int s_dev_count = 0;

/* 当前等待的阶段（用于事件回调判断何时通知）：0空闲 1扫描 2连接 3加密 */
static int s_waiting = 0;
static bool s_pairing = false;
static bool s_op_ok = false;
static uint16_t s_conn_handle = 0;

/* 解析广播数据中的设备名 */
static const char *parse_dev_name(const struct ble_gap_disc_desc *disc,
                                  char *out, size_t out_sz)
{
    struct ble_hs_adv_fields fields;
    if (ble_hs_adv_parse_fields(&fields, disc->data, disc->length_data) == 0 &&
        fields.name != NULL && fields.name_len > 0) {
        int len = fields.name_len < (int)(out_sz - 1) ? fields.name_len : (int)(out_sz - 1);
        memcpy(out, fields.name, len);
        out[len] = '\0';
        return out;
    }
    snprintf(out, out_sz, "<无名称>");
    return out;
}

static void addr_to_str(const ble_addr_t *addr, char *out, size_t sz)
{
    snprintf(out, sz, "%02x:%02x:%02x:%02x:%02x:%02x",
             addr->val[5], addr->val[4], addr->val[3],
             addr->val[2], addr->val[1], addr->val[0]);
}

/* 收集一条扫描结果（探测/配对共用） */
static void collect_device(const struct ble_gap_disc_desc *disc)
{
    if (s_dev_count >= BLE_MAX_DEVS) {
        return;
    }
    ble_dev_t *d = &s_devs[s_dev_count];
    memcpy(&d->addr, &disc->addr, sizeof(d->addr));
    parse_dev_name(disc, d->name, sizeof(d->name));
    d->rssi = disc->rssi;
    s_dev_count++;

    char addr_str[18];
    addr_to_str(&disc->addr, addr_str, sizeof(addr_str));
    printf("  [%02d] %-20s  %s  RSSI: %d dBm\n",
           s_dev_count, d->name, addr_str, disc->rssi);
}

/* GAP 事件回调：扫描结果、连接、配对加密 */
static int ble_gap_event_handler(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {
    case BLE_GAP_EVENT_DISC:
        collect_device(&event->disc);
        return 0;

    case BLE_GAP_EVENT_DISC_COMPLETE:
        if (s_waiting == 1 && s_op_sem) {
            xSemaphoreGive(s_op_sem);
        }
        return 0;

    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            s_conn_handle = event->connect.conn_handle;
            ESP_LOGI(TAG, "已连接 (conn=%u)", s_conn_handle);
            if (s_pairing) {
                ESP_LOGI(TAG, "正在发起配对/加密...");
                int rc = ble_gap_security_initiate(s_conn_handle);
                if (rc != 0) {
                    ESP_LOGE(TAG, "发起配对失败 rc=%d", rc);
                    s_op_ok = false;
                    ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
                }
            }
        } else {
            ESP_LOGW(TAG, "连接失败 status=%d", event->connect.status);
            s_op_ok = false;
        }
        if (s_waiting == 2 && s_op_sem) {
            xSemaphoreGive(s_op_sem);
        }
        return 0;

    case BLE_GAP_EVENT_ENC_CHANGE:
        if (event->enc_change.status == 0) {
            ESP_LOGI(TAG, "配对/加密成功 ✓");
            s_op_ok = true;
            ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        } else {
            ESP_LOGW(TAG, "配对/加密失败 status=%d", event->enc_change.status);
            s_op_ok = false;
            ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        }
        if (s_waiting == 3 && s_op_sem) {
            xSemaphoreGive(s_op_sem);
        }
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "连接已断开 reason=%d", event->disconnect.reason);
        if (s_waiting == 3 && s_op_sem) {
            xSemaphoreGive(s_op_sem);
        }
        return 0;

    default:
        return 0;
    }
}

/* NimBLE host 任务 */
static void ble_host_task(void *param)
{
    nimble_port_run();          /* 直到 nimble_port_stop() 才返回 */
    nimble_port_freertos_deinit();
}

static void ble_on_sync(void)
{
    ESP_LOGI(TAG, "NimBLE host 已同步");
}

static void ble_on_reset(int reason)
{
    ESP_LOGW(TAG, "NimBLE 重置, reason=%d", reason);
}

/* 初始化 NimBLE（只执行一次） */
static esp_err_t ble_scan_init(void)
{
    if (s_ble_inited) {
        return ESP_OK;
    }

    int rc = nimble_port_init();    /* 内部会初始化并启用 BT 控制器 */
    if (rc != ESP_OK) {
        ESP_LOGE(TAG, "NimBLE 初始化失败: %d", rc);
        return rc;
    }

    ble_hs_cfg.reset_cb = ble_on_reset;
    ble_hs_cfg.sync_cb = ble_on_sync;

    /* 配对参数：无输入输出能力 → "just works" 配对 */
    ble_hs_cfg.sm_io_cap = BLE_HS_IO_NO_INPUT_OUTPUT;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;

    nimble_port_freertos_init(ble_host_task);
    s_ble_inited = true;
    return ESP_OK;
}

/* 等待 host 同步完成 */
static bool ble_wait_synced(void)
{
    int tries = 0;
    while (!ble_hs_synced() && tries++ < 100) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    return ble_hs_synced();
}

/* 蓝牙状态文本（欢迎横幅用） */
void ble_get_status_text(char *buf, size_t buf_sz)
{
    if (buf == NULL || buf_sz == 0) {
        return;
    }
    if (!s_ble_inited) {
        snprintf(buf, buf_sz, "%s", i18n_t("未启用"));
        return;
    }
    if (!ble_hs_synced()) {
        snprintf(buf, buf_sz, "%s", i18n_t("初始化中..."));
        return;
    }
    switch (s_waiting) {
    case 1: snprintf(buf, buf_sz, "BLE %s", i18n_t("扫描中...")); break;
    case 2: snprintf(buf, buf_sz, "BLE %s", i18n_t("连接中...")); break;
    case 3: snprintf(buf, buf_sz, "BLE %s", i18n_t("配对中...")); break;
    default:
        snprintf(buf, buf_sz, I18N("BLE 已就绪", "BLE ready"));
        break;
    }
}

/*
 * 等待操作完成，同时允许 ESC 取消。
 * 返回: 0=完成(收到信号)  1=用户ESC取消  2=超时
 */
static int wait_op_or_esc(TickType_t timeout_ticks)
{
    TickType_t start = xTaskGetTickCount();
    while (1) {
        if (s_op_sem != NULL &&
            xSemaphoreTake(s_op_sem, pdMS_TO_TICKS(100)) == pdTRUE) {
            return 0;
        }
        if (menu_wait_key() == MENU_KEY_ESC) {
            return 1;   /* 取消 */
        }
        taskYIELD();
        if (timeout_ticks != portMAX_DELAY &&
            (xTaskGetTickCount() - start) >= timeout_ticks) {
            return 2;   /* 超时 */
        }
    }
}

/* 启动一次扫描并等待完成；返回设备数，-1 失败，-2 用户取消 */
static int ble_scan_collect(void)
{
    printf("%s %s\n", i18n_t("正在扫描，请稍候..."), i18n_t("按 ESC 取消"));

    s_dev_count = 0;
    s_pairing = false;
    s_waiting = 1;
    xSemaphoreTake(s_op_sem, 0);

    uint8_t own_addr_type;
    int rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "无法确定本机地址类型: rc=%d", rc);
        s_waiting = 0;
        return -1;
    }

    struct ble_gap_disc_params params = {
        .filter_duplicates = 1,     /* 过滤重复广播 */
        .passive = 1,               /* 被动扫描 */
        .itvl = 0,
        .window = 0,
        .filter_policy = 0,
        .limited = 0,
    };

    rc = ble_gap_disc(own_addr_type, CONFIG_GYSCAN_BLE_SCAN_DURATION_MS,
                      &params, ble_gap_event_handler, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "启动扫描失败: rc=%d", rc);
        s_waiting = 0;
        return -1;
    }

    int wr = wait_op_or_esc(pdMS_TO_TICKS(CONFIG_GYSCAN_BLE_SCAN_DURATION_MS + 3000));
    if (wr == 1) {
        ble_gap_disc_cancel();
        s_waiting = 0;
        return -2;   /* 取消 */
    }
    if (wr == 2) {
        ble_gap_disc_cancel();
    }
    s_waiting = 0;
    return s_dev_count;
}


void ble_scan_run(void)
{
    printf("\n========== %s (%.1fs) ==========\n",
           i18n_t("蓝牙探测"), (float)CONFIG_GYSCAN_BLE_SCAN_DURATION_MS / 1000.0f);

    if (ble_scan_init() != ESP_OK) {
        printf("%s\n", i18n_t("蓝牙初始化失败"));
        return;
    }
    if (s_op_sem == NULL) {
        s_op_sem = xSemaphoreCreateBinary();
    }
    if (!ble_wait_synced()) {
        printf("%s\n", i18n_t("蓝牙 host 同步超时"));
        return;
    }

    int n = ble_scan_collect();
    if (n == -2) {
        printf("%s\n", i18n_t("扫描已取消"));
        return;
    }
    if (n < 0) {
        printf("%s\n", i18n_t("扫描失败"));
        return;
    }
    printf("========== %s: %d ==========\n",
           i18n_t("共发现设备数"), n);
}

/* 打印设备列表并等待用户输入选择，返回 1~n；0=取消 */
static int select_device(void)
{
    if (s_dev_count == 0) {
        printf("%s\n", i18n_t("未发现任何设备"));
        return 0;
    }
    printf(i18n_t("请选择要配对的设备编号 (1-%d), 0 取消: "), s_dev_count);

    while (1) {
        int key = menu_wait_key();
        if (key == '0') {
            printf("\n%s\n", i18n_t("已取消配对"));
            return 0;
        }
        if (key >= '1' && key <= '9') {
            int idx = key - '0';
            if (idx <= s_dev_count) {
                printf("\n");
                return idx;
            }
        }
        if (key == MENU_KEY_ESC) {
            printf("\n%s\n", i18n_t("已取消配对"));
            return 0;
        }
    }
}

void ble_pair_run(void)
{
    printf("\n========== %s ==========\n", i18n_t("蓝牙配对"));

    if (ble_scan_init() != ESP_OK) {
        printf("%s\n", i18n_t("蓝牙初始化失败"));
        return;
    }
    if (s_op_sem == NULL) {
        s_op_sem = xSemaphoreCreateBinary();
    }
    if (!ble_wait_synced()) {
        printf("%s\n", i18n_t("蓝牙 host 同步超时"));
        return;
    }

    /* 1. 扫描（ESC 可取消） */
    int n = ble_scan_collect();
    if (n == -2) {
        printf("%s\n", i18n_t("已取消配对"));
        return;
    }
    if (n <= 0) {
        printf("%s\n", i18n_t("未发现可配对设备"));
        return;
    }

    /* 2. 选择设备 */
    int sel = select_device();
    if (sel <= 0) {
        return;
    }
    ble_dev_t *target = &s_devs[sel - 1];
    char addr_str[18];
    addr_to_str(&target->addr, addr_str, sizeof(addr_str));
    printf(i18n_t("配对目标: %s (%s)"), target->name, addr_str);
    printf("\n");

    /* 3. 连接（先取消可能残留的扫描；ESC 可取消） */
    ble_gap_disc_cancel();
    s_pairing = true;
    s_op_ok = false;
    s_waiting = 2;
    xSemaphoreTake(s_op_sem, 0);

    uint8_t own_addr_type;
    int rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        ESP_LOGE(TAG, "无法确定本机地址: rc=%d", rc);
        return;
    }

    printf("%s\n", i18n_t("连接中，ESC 取消..."));
    rc = ble_gap_connect(own_addr_type, &target->addr, BLE_CONN_TIMEOUT_MS,
                         NULL, ble_gap_event_handler, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "发起连接失败 rc=%d", rc);
        s_pairing = false;
        return;
    }

    int wr = wait_op_or_esc(pdMS_TO_TICKS(BLE_CONN_TIMEOUT_MS + 5000));
    if (wr == 1) {
        printf("%s\n", i18n_t("已取消配对"));
        s_pairing = false;
        s_waiting = 0;
        ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        return;
    }
    if (wr == 2) {
        printf("%s\n", i18n_t("连接超时"));
        s_pairing = false;
        s_waiting = 0;
        return;
    }

    /* 4. 等待配对/加密结果（ESC 可取消） */
    s_waiting = 3;
    xSemaphoreTake(s_op_sem, 0);
    printf("%s\n", i18n_t("配对中，ESC 取消..."));
    wr = wait_op_or_esc(pdMS_TO_TICKS(BLE_SECURITY_TIMEOUT_MS));
    if (wr == 1) {
        printf("%s\n", i18n_t("已取消配对"));
        ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    } else if (wr == 2) {
        printf("%s\n", i18n_t("配对等待超时"));
        ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    }

    s_pairing = false;
    s_waiting = 0;
    printf("========== %s: %s ==========\n",
           i18n_t("配对结果"), s_op_ok ? "OK" : I18N("失败/未完成", "Failed/Incomplete"));
}


/* ---------------- Lua 友好的非交互式 API ---------------- */

/* 解析地址字符串 "aa:bb:cc:dd:ee:ff" 到 ble_addr_t；成功返回 0 */
static int parse_addr_str(const char *addr_str, ble_addr_t *out)
{
    if (addr_str == NULL || out == NULL)
        return -1;
    unsigned int v[6];
    if (sscanf(addr_str, "%x:%x:%x:%x:%x:%x",
               &v[5], &v[4], &v[3], &v[2], &v[1], &v[0]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        out->val[i] = (uint8_t)v[i];
    out->type = BLE_ADDR_RANDOM;
    return 0;
}

int ble_scan_perform(int duration_ms)
{
    if (ble_scan_init() != ESP_OK)
        return -1;
    if (s_op_sem == NULL)
        s_op_sem = xSemaphoreCreateBinary();
    if (!ble_wait_synced())
        return -1;

    s_dev_count = 0;
    s_pairing = false;
    s_waiting = 1;
    xSemaphoreTake(s_op_sem, 0);

    uint8_t own_addr_type;
    int rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        s_waiting = 0;
        return -1;
    }

    struct ble_gap_disc_params params = {
        .filter_duplicates = 1,
        .passive = 1,
        .itvl = 0, .window = 0,
        .filter_policy = 0, .limited = 0,
    };
    rc = ble_gap_disc(own_addr_type, duration_ms, &params,
                      ble_gap_event_handler, NULL);
    if (rc != 0) {
        s_waiting = 0;
        return -1;
    }

    if (xSemaphoreTake(s_op_sem, pdMS_TO_TICKS(duration_ms + 3000)) != pdTRUE)
        ble_gap_disc_cancel();
    s_waiting = 0;
    return s_dev_count;
}

int ble_scan_result_count(void)
{
    return s_dev_count;
}

esp_err_t ble_scan_result_get(int idx, char *name, size_t name_sz,
                              char *addr_str, size_t addr_sz, int8_t *rssi)
{
    if (idx < 0 || idx >= s_dev_count)
        return ESP_ERR_INVALID_ARG;
    const ble_dev_t *d = &s_devs[idx];
    if (name && name_sz > 0) {
        strncpy(name, d->name, name_sz - 1);
        name[name_sz - 1] = '\0';
    }
    if (addr_str && addr_sz > 0)
        addr_to_str(&d->addr, addr_str, addr_sz);
    if (rssi)
        *rssi = d->rssi;
    return ESP_OK;
}

static esp_err_t connect_and_pair(const ble_addr_t *addr)
{
    uint8_t own_addr_type;
    int rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0)
        return ESP_ERR_INVALID_STATE;

    s_pairing = true;
    s_op_ok = false;
    s_waiting = 2;
    xSemaphoreTake(s_op_sem, 0);

    rc = ble_gap_connect(own_addr_type, addr, BLE_CONN_TIMEOUT_MS,
                         NULL, ble_gap_event_handler, NULL);
    if (rc != 0) {
        s_pairing = false;
        return ESP_FAIL;
    }
    if (xSemaphoreTake(s_op_sem, pdMS_TO_TICKS(BLE_CONN_TIMEOUT_MS + 5000)) != pdTRUE) {
        ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        s_pairing = false;
        s_waiting = 0;
        return ESP_ERR_TIMEOUT;
    }

    /* 等待加密 */
    s_waiting = 3;
    xSemaphoreTake(s_op_sem, 0);
    if (xSemaphoreTake(s_op_sem, pdMS_TO_TICKS(BLE_SECURITY_TIMEOUT_MS)) != pdTRUE) {
        ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        s_pairing = false;
        s_waiting = 0;
        return ESP_ERR_TIMEOUT;
    }
    s_pairing = false;
    s_waiting = 0;
    return s_op_ok ? ESP_OK : ESP_FAIL;
}

esp_err_t ble_pair_address(const char *addr_str)
{
    if (addr_str == NULL)
        return ESP_ERR_INVALID_ARG;
    if (ble_scan_init() != ESP_OK)
        return ESP_FAIL;
    if (s_op_sem == NULL)
        s_op_sem = xSemaphoreCreateBinary();
    if (!ble_wait_synced())
        return ESP_ERR_INVALID_STATE;

    ble_addr_t addr;
    if (parse_addr_str(addr_str, &addr) != 0)
        return ESP_ERR_INVALID_ARG;
    return connect_and_pair(&addr);
}

esp_err_t ble_disconnect(void)
{
    if (s_conn_handle == 0)
        return ESP_ERR_INVALID_STATE;
    int rc = ble_gap_terminate(s_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    s_conn_handle = 0;
    return (rc == 0) ? ESP_OK : ESP_FAIL;
}
