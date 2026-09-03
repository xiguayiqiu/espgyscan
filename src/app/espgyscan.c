/*
 * espgyscan - ESP32-S3 边缘安全调试工具
 *
 * 主菜单：WiFi设置 / 蓝牙设置 / 边缘安全 / 运行Lua脚本 / TF卡设置 / 语言 / 关机
 *   WiFi 设置: 连接/手动输入SSID/断开/网络状态
 *   蓝牙设置:  蓝牙配对(扫描→选择→配对)
 * 边缘安全:  蓝牙探测 / 键盘模拟注入 / 连接gyscan(Go程序)
 *   运行Lua脚本: 列出脚本并执行(print 实时回显)
 *   TF 卡设置: 挂载/卸载/格式化外置 TF 卡
 *   存储策略(自动): 有 TF 卡(已挂载)则资源/脚本全部存与跑在 TF 卡;
 *     无 TF 卡则上传文件放内存(RAM)、Lua 直接从内存执行(不写 Flash,延长寿命);
 *     支持删除文件/文件夹(递归), 对应 gyscan esp rm
 *
 * 启动后：
 *   - USB HID 键盘设备（USB 线连接电脑后即被识别为键盘）
 *   - 自动连接 WiFi，成功后启动 HTTP 服务器（访问返回 "esp-gyscan：ok"）
 *   - 后台 LED 闪烁作为运行状态指示
 *
 * 按键: WASD/方向键 移动选择器, Enter 确认, ESC 返回上级;
 *       顶级主菜单按 ESC/q 进入"关机"确认(回车关机, ESC 继续运行)。
 * 注: 1234 远程控制端口为后期功能，暂未启用。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_sleep.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "led_strip.h"
#include "sdkconfig.h"

#include "menu.h"
#include "wifi_scan.h"
#include "ble_scan.h"
#include "tcp_client.h"
#include "hid_keyboard.h"
#include "http_server.h"
#include "tcp_server.h"
#include "script_store.h"
#include "sdcard.h"
#include "arp_mitm.h"
#include "net_scan.h"
#include "i18n.h"
#include "eth_netif.h"
#include "boot_splash.h"
#include "lua_embed.h"
#include "lua_net.h"

static const char *TAG = "espgyscan";

/* ANSI 控制序列 */
#define ANSI_CLEAR_SCREEN  "\033[2J"
#define ANSI_CURSOR_HOME   "\033[H"

#define BLINK_GPIO CONFIG_BLINK_GPIO

/* ---------------- LED 状态指示灯 ---------------- */

#ifdef CONFIG_BLINK_LED_STRIP
static led_strip_handle_t led_strip;

static void blink_task(void *arg)
{
    bool on = false;
    while (1) {
        if (led_strip != NULL) {
            if (on) {
                led_strip_set_pixel(led_strip, 0, 16, 16, 16);
            } else {
                led_strip_clear(led_strip);
            }
            led_strip_refresh(led_strip);
        }
        on = !on;
        vTaskDelay(CONFIG_BLINK_PERIOD / portTICK_PERIOD_MS);
    }
}

/* 初始化 LED（WS2812）；失败不崩溃，仅告警 */
static void configure_led(void)
{
    led_strip_config_t strip_config = {
        .strip_gpio_num = BLINK_GPIO,
        .max_leds = 1,
    };
    led_strip_rmt_config_t rmt_config = {
        .resolution_hz = 10 * 1000 * 1000,
        .flags.with_dma = false,
    };
    esp_err_t ret = led_strip_new_rmt_device(&strip_config, &rmt_config, &led_strip);
    if (ret != ESP_OK) {
        led_strip = NULL;
        ESP_LOGW(TAG, "LED(WS2812) 初始化失败: %s，LED 功能不可用", esp_err_to_name(ret));
        return;
    }
    led_strip_clear(led_strip);
}

#elif CONFIG_BLINK_LED_GPIO

static void blink_task(void *arg)
{
    bool on = false;
    while (1) {
        gpio_set_level(BLINK_GPIO, on);
        on = !on;
        vTaskDelay(CONFIG_BLINK_PERIOD / portTICK_PERIOD_MS);
    }
}

static void configure_led(void)
{
    gpio_reset_pin(BLINK_GPIO);
    gpio_set_direction(BLINK_GPIO, GPIO_MODE_OUTPUT);
}

#else
static void blink_task(void *arg)
{
    vTaskDelete(NULL);
}
static void configure_led(void) {}
#endif

/* LED 初始化+闪烁放后台任务：某些平台(如 QEMU)无 RMT/LED 硬件，
 * 后台失败不影响菜单与主流程 */
static void led_task(void *arg)
{
    configure_led();
    blink_task(NULL);   /* 内部循环，不会返回 */
    vTaskDelete(NULL);
}

/* ---------------- 菜单动作 ---------------- */

/* ---- 边缘安全 - 攻击工具 ---- */
static void action_ble_scan(void)     { ble_scan_run(); }
static void action_tcp_connect(void)  { tcp_client_run(); }

/* ---- ARP 中间人(ARP MITM) ---- */

/* 局域网存活主机扫描+选择 */
#define ARP_SELECT_MAX 48
static char   s_arp_hosts[ARP_SELECT_MAX][16];
static int    s_arp_host_count = 0;
static volatile bool s_arp_scan_done = false;

static void arp_scan_hit(const char *host, void *ctx)
{
    (void)ctx;
    int i = s_arp_host_count;
    if (i < ARP_SELECT_MAX) {
        snprintf(s_arp_hosts[i], 16, "%s", host);
        s_arp_host_count = i + 1;
    }
}

static void arp_scan_task(void *arg)
{
    char own_ip[16], netmask[16];
    memcpy(own_ip, arg, 16);
    memcpy(netmask, (char *)arg + 16, 16);
    net_scan_alive_hosts(own_ip, netmask, 250, arp_scan_hit, NULL);
    s_arp_scan_done = true;
    vTaskDelete(NULL);
}

/* 获取活跃接口(ETH_DEF 优先，其次 WIFI_STA_DEF)的 IP/掩码/网关。
 * 任一输出指针可为 NULL(不关心)。返回是否有 IP。 */
static bool arp_get_netinfo(char *ip_out, size_t ip_sz,
                            char *mask_out, size_t mask_sz,
                            char *gw_out, size_t gw_sz)
{
    static const char *const keys[] = { "ETH_DEF", "WIFI_STA_DEF" };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        esp_netif_t *nif = esp_netif_get_handle_from_ifkey(keys[i]);
        if (nif == NULL) {
            continue;
        }
        esp_netif_ip_info_t n;
        if (esp_netif_get_ip_info(nif, &n) != ESP_OK || n.ip.addr == 0) {
            continue;
        }
        if (ip_out) {
            esp_ip4addr_ntoa(&n.ip, ip_out, (int)ip_sz);
        }
        if (mask_out) {
            esp_ip4addr_ntoa(&n.netmask, mask_out, (int)mask_sz);
        }
        if (gw_out) {
            esp_ip4addr_ntoa(&n.gw, gw_out, (int)gw_sz);
        }
        return true;
    }
    return false;
}

/* 扫描局域网并用光标选择受害主机；成功返回 0 并写入 target；取消返回 -1 */
static int arp_select_victim(char *target, size_t sz)
{
    if (sz < 16) {
        return -1;
    }
    /* 获取活跃接口(以太网/WiFi)的 IP/掩码 */
    char own_ip[16] = "", netmask[16] = "";
    if (!arp_get_netinfo(own_ip, sizeof(own_ip), netmask, sizeof(netmask), NULL, 0)) {
        printf("%s\n", i18n_t("未获取到本机 IP，无法扫描(请先连接网络)"));
        return -1;
    }

    s_arp_host_count = 0;
    s_arp_scan_done = false;
    static char scan_arg[32];
    memset(scan_arg, 0, sizeof(scan_arg));
    memcpy(scan_arg, own_ip, 16);
    memcpy(scan_arg + 16, netmask, 16);
    xTaskCreate(arp_scan_task, "arp_scan", 4096, scan_arg, 5, NULL);

    int selected = 0;
    uint32_t last_draw = (uint32_t)-1;
    printf("%s\n", i18n_t("正在扫描局域网... (上/下移动 Enter选择 ESC取消)"));
    while (1) {
        /* 每秒刷新一次列表，扫描结束也要刷新 */
        uint32_t now = (uint32_t)(xTaskGetTickCount() / configTICK_RATE_HZ);
        int redraw = (now != last_draw);
        last_draw = now;
        if (s_arp_scan_done) {
            redraw = 1;
        }
        if (redraw) {
            printf(ANSI_CLEAR_SCREEN);
            printf("---- %s ----\n", i18n_t("选择受害主机"));
            printf("%s\n\n", s_arp_scan_done ? i18n_t("扫描完成") :
                   i18n_t("正在扫描..."));
            for (int i = 0; i < s_arp_host_count; i++) {
                printf("%s %s\n", (i == selected) ? ">" : " ", s_arp_hosts[i]);
            }
            if (s_arp_host_count == 0 && s_arp_scan_done) {
                printf("%s\n", i18n_t("未发现在线主机(可重新扫描)"));
            }
        }

        int key = menu_key_now();
        if (key < 0) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        if (key == MENU_KEY_ESC) {
            /* ESC 可能是方向键前缀：交给 menu_wait_key 解码完整序列 */
            key = menu_wait_key();
        }
        if (key == MENU_KEY_UP || key == 'w' || key == 'W') {
            if (selected > 0) {
                selected--;
            }
        } else if (key == MENU_KEY_DOWN || key == 's' || key == 'S') {
            if (selected < s_arp_host_count - 1) {
                selected++;
            }
        } else if (key == MENU_KEY_LEFT || key == 'a' || key == 'A' ||
                   key == MENU_KEY_RIGHT || key == 'd' || key == 'D') {
            /* 纵向列表无左右，忽略 */
        } else if (key == MENU_KEY_ENTER || key == '\n') {
            if (s_arp_host_count > 0) {
                if (selected < s_arp_host_count) {
                    snprintf(target, sz, "%s", s_arp_hosts[selected]);
                }
                break;
            }
        } else if (key == MENU_KEY_ESC) {
            return -1;
        }
    }
    return 0;
}

static void action_arp_mitm_start(void)
{
    if (arp_mitm_is_running()) {
        printf("%s\n", I18N("ARP MITM 已在运行中，请先停止再重新启动",
                            "ARP MITM already running, stop it first"));
        return;
    }
    /* 自动检测网关(路由器) IP（以太网/WiFi 双接口） */
    char gateway[16] = "";
    arp_get_netinfo(NULL, 0, NULL, 0, gateway, sizeof(gateway));
    if (gateway[0] == '\0') {
        printf("%s\n", i18n_t("未检测到网关，请输入"));
        printf("%s", I18N("输入网关(路由器) IP: ", "Enter gateway (router) IP: "));
        if (menu_read_line(gateway, sizeof(gateway)) < 0 || gateway[0] == '\0') {
            printf("%s\n", i18n_t("已取消"));
            return;
        }
    }

    /* 扫描局域网并用光标选择受害主机 */
    char target[16];
    if (arp_select_victim(target, sizeof(target)) < 0) {
        printf("\n%s\n", i18n_t("已取消"));
        return;
    }
    printf("\n%s: %s\n", I18N("已选择受害主机", "Selected victim"), target);

    esp_err_t r = arp_mitm_start(target, gateway);
    if (r == ESP_OK) {
        printf("%s: %s <-> %s\n", I18N("ARP MITM 已启动", "ARP MITM started"),
               target, gateway);
    } else {
        printf("%s: %s\n", I18N("启动失败(IP 无效?)", "Start failed (invalid IP?)"),
               esp_err_to_name(r));
    }
}

static void action_arp_mitm_stop(void)
{
    esp_err_t r = arp_mitm_stop();
    printf("%s (%s)\n",
           (r == ESP_OK) ? I18N("ARP MITM 已停止", "ARP MITM stopped")
                         : I18N("停止失败", "Stop failed"),
           esp_err_to_name(r));
}

static void action_arp_mitm_status(void)
{
    char st[64];
    arp_mitm_status_text(st, sizeof(st));
    printf("%s: %s\n", I18N("ARP MITM", "ARP MITM"), st);
    if (arp_mitm_is_running()) {
        printf("%s\n", I18N("提示: 流量正在经过本机(中间人)", 
                            "Traffic is passing through this device (MITM)"));
    }
}

static void action_hid_status(void)
{
    printf("USB 键盘: %s\n", hid_keyboard_is_mounted() ? "已连接电脑" : "未连接(等待USB枚举)");
    printf("提示: 用 USB 线将 ESP32-S3 的 USB-OTG 口连接到电脑\n");
    printf("      电脑会识别出一个名为 gyscan Keyboard 的键盘设备\n");
}

static void action_hid_test(void)
{
    if (!hid_keyboard_is_mounted()) {
        printf("USB 键盘未连接电脑，请用 USB 线将 ESP 连接到电脑\n");
        return;
    }
    printf("正在注入测试文本: hello gyscan 123\n");
    esp_err_t r = hid_keyboard_type_text("hello gyscan 123\n");
    if (r == ESP_OK) {
        printf("键盘注入测试完成 (请查看电脑上焦点窗口)\n");
    } else {
        printf("键盘注入失败: %s\n", esp_err_to_name(r));
    }
}

/* ---- WiFi 设置 ---- */
static void action_wifi_connect(void)
{
    printf("连接目标 SSID: %s\n", wifi_get_active_ssid());
    if (wifi_is_connected()) {
        printf("WiFi 已连接\n");
        return;
    }
    esp_err_t r = wifi_sta_connect();
    if (r == ESP_OK) {
        printf("WiFi 连接成功\n");
    } else {
        printf("WiFi 连接失败: %s\n", esp_err_to_name(r));
    }
}

static void action_wifi_setup(void)
{
    char ssid[33];
    char password[65];

    printf("当前 SSID: %s\n", wifi_get_active_ssid());
    printf("输入 WiFi 名称(SSID): ");
    if (menu_read_line(ssid, sizeof(ssid)) < 0 || ssid[0] == '\0') {
        printf("已取消\n");
        return;
    }
    printf("输入 WiFi 密码(直接回车表示开放网络): ");
    if (menu_read_line(password, sizeof(password)) < 0) {
        printf("已取消\n");
        return;
    }
    esp_err_t r = wifi_connect_custom(ssid, password);
    if (r == ESP_OK) {
        printf("已连接到 %s ✓\n", ssid);
    } else {
        printf("连接失败: %s (SSID/密码错误或信号差)\n", esp_err_to_name(r));
    }
}

static void action_wifi_disconnect(void)
{
    esp_err_t r = wifi_disconnect();
    if (r == ESP_OK) {
        printf("已断开 WiFi\n");
    } else {
        printf("断开失败: %s\n", esp_err_to_name(r));
    }
}

/* 获取当前可用的网络接口 IP 文本（QEMU=以太网 ETH_DEF，真机=WiFi STA）。
 * 未取到时写入 "未连接" */
static void get_active_ip_str(char *out, size_t out_sz)
{
    static const char *const keys[] = { "ETH_DEF", "WIFI_STA_DEF" };
    esp_netif_ip_info_t ip;
    for (int i = 0; i < (int)(sizeof(keys) / sizeof(keys[0])); i++) {
        esp_netif_t *nif = esp_netif_get_handle_from_ifkey(keys[i]);
        if (nif != NULL && esp_netif_get_ip_info(nif, &ip) == ESP_OK && ip.ip.addr != 0) {
            snprintf(out, out_sz, IPSTR, IP2STR(&ip.ip));
            return;
        }
    }
    snprintf(out, out_sz, "%s", "未连接");
}

static void action_http_status(void)
{
    char ip_str[32] = "未连接";
    get_active_ip_str(ip_str, sizeof(ip_str));

    printf("WiFi 状态: %s\n", wifi_is_connected() ? "已连接" : "未连接");
    printf("当前 SSID: %s\n", wifi_get_active_ssid());
    printf("ESP IP: %s\n", ip_str);
    printf("HTTP 服务器: %s (端口 %d)\n",
           http_server_is_running() ? "运行中" : "未运行", CONFIG_GYSCAN_HTTP_PORT);
    if (strcmp(ip_str, "未连接") != 0) {
        printf("测试: curl http://%s/  → 返回 esp-gyscan：ok\n", ip_str);
    }
}

static void action_tcp_status2(void)
{
    char ip_str[32] = "未连接";
    get_active_ip_str(ip_str, sizeof(ip_str));

    printf("gyscan 控制服务器: %s (端口 %d)\n",
           tcp_server_is_running() ? "运行中" : "未运行", CONFIG_GYSCAN_TCP_PORT);
    printf("当前客户端数: %d\n", tcp_server_client_count());
    printf("ESP IP: %s\n", ip_str);
    if (strcmp(ip_str, "未连接") != 0) {
        printf("提示: gyscan 主程序执行: ./gyscan esp connect --cidr %s/24\n", ip_str);
    }
    printf("协议: hello/ls/read/write/delete/run/keymap/scan/close\n");
}

/* ---- 蓝牙设置 ---- */
static void action_ble_pair(void) { ble_pair_run(); }

/* ---- 语言 ---- */
static void action_set_zh(void) { i18n_set_lang(LANG_ZH); }
static void action_set_en(void) { i18n_set_lang(LANG_EN); }

/* ---- Lua 脚本（存储介质自动：TF 卡 或 内存 RAM） ---- */

#define LUA_SCRIPT_LIST_MAX 32
#define LUA_SCRIPT_NAME_MAX 64

static char s_script_names[LUA_SCRIPT_LIST_MAX][LUA_SCRIPT_NAME_MAX];
static int s_script_count = 0;

/* script_store_list 回调：收集脚本名（只统计常规文件） */
static void lua_script_collect(const char *name, void *ctx)
{
    (void)ctx;
    if (s_script_count < LUA_SCRIPT_LIST_MAX) {
        snprintf(s_script_names[s_script_count], LUA_SCRIPT_NAME_MAX, "%s", name);
        s_script_count++;
    }
}

/* 列出当前介质(仅常规文件, 不列文件夹)并选择编号；返回选中的下标(0 起)，
 * 取消/失败返回 -1。介质为空时提示先上传。 */
static int menu_pick_script(void)
{
    s_script_count = 0;
    esp_err_t r = script_store_list(lua_script_collect, NULL);
    if (r != ESP_OK || s_script_count == 0) {
        printf("\n%s\n", I18N("脚本目录为空(先用 gyscan esp upload 上传 .lua)",
                              "No scripts yet (upload .lua via gyscan esp upload first)"));
        return -1;
    }

    printf("\n%s:\n", I18N("可用 Lua 脚本", "Available Lua scripts"));
    for (int i = 0; i < s_script_count; i++) {
        printf("  [%d] %s\n", i + 1, s_script_names[i]);
    }
    printf("\n");

    char input[16];
    printf("%s", I18N("输入脚本编号并回车 (0 取消): ",
                      "Enter script number and press Enter (0 = cancel): "));
    if (menu_read_line(input, sizeof(input)) < 0) {   /* ESC 取消 */
        printf("\n%s\n", i18n_t("已取消"));
        return -1;
    }
    int num = atoi(input);
    if (num >= 1 && num <= s_script_count) {
        return num - 1;
    }
    if (num == 0) {
        printf("%s\n", i18n_t("已取消"));
        return -1;
    }
    printf("\n%s\n", i18n_t("无效的选择"));
    return -1;
}

/* 运行脚本：Lua print 输出走 stdout，直接显示在串口终端 */
static void action_lua_run(void)
{
    int idx = menu_pick_script();
    if (idx < 0) {
        return;
    }

    const char *name = s_script_names[idx];
    printf("\n%s: %s\n", i18n_t("正在运行脚本"), name);

    /* out_cb=NULL：Lua print 输出默认落到串口 stdout（终端直接可见） */
    char err[256];
    esp_err_t r = script_execute(name, NULL, NULL, err, sizeof(err));
    if (r == ESP_OK) {
        printf("\n%s\n", i18n_t("脚本执行完成"));
    } else {
        printf("\n%s: %s\n", i18n_t("脚本执行失败"), err);
    }
}

/* 删除脚本/文件（当前介质：TF 卡或内存 RAM） */
static void action_lua_delete(void)
{
    int idx = menu_pick_script();
    if (idx < 0) {
        return;
    }
    const char *name = s_script_names[idx];
    printf("\n%s: %s\n", I18N("确认删除", "Confirm delete"), name);
    printf("%s\n", I18N("(y=删除, ESC/其它=取消)",
                        "(y=Delete, ESC/other=Cancel)"));
    while (1) {
        int key = menu_wait_key();
        if (key == 'y' || key == 'Y') {
            break;
        }
        if (key == MENU_KEY_ESC || key == 'n' || key == 'N') {
            printf("%s\n", i18n_t("已取消"));
            return;
        }
    }
    esp_err_t r = script_store_rm(name);
    if (r == ESP_OK) {
        printf("%s: %s\n", I18N("已删除", "Deleted"), name);
    } else if (r == ESP_ERR_NOT_FOUND) {
        printf("%s: %s\n", i18n_t("文件不存在"), name);
    } else {
        printf("%s: %s\n", I18N("删除失败", "Delete failed"),
               esp_err_to_name(r));
    }
}

/* 查看当前脚本存储介质与 RAM 用量 */
static void action_lua_storage(void)
{
    printf("\n%s\n", I18N("--- 脚本存储(自动) ---", "--- Script Storage (auto) ---"));
    printf("%s: %s\n", I18N("当前介质", "Active media"), script_store_media_name());
    if (script_store_media() == SCRIPT_MEDIA_RAM) {
        printf("%s: %d 个文件 / %d KB\n", I18N("RAM 用量", "RAM usage"),
               script_store_ram_file_count(),
               (int)(script_store_ram_bytes() / 1024));
    }
    printf("%s\n", I18N("规则: 存在TF卡并已挂载 → 全部在TF卡; 否则 → 内存RAM(不写Flash, 重启清空)",
                        "Rule: TF card mounted -> all on TF card; else -> RAM (no flash write, lost on reboot)"));
}

/* ---- TF 卡设置 ---- */

static void action_sd_status(void)
{
    if (sdcard_is_mounted()) {
        char st[64] = {0};
        sdcard_status(st, sizeof(st));
        printf("%s\n", I18N("--- TF 卡状态 ---", "--- TF Card Status ---"));
        printf("%s: %s\n", i18n_t("挂载点"), SDCARD_MOUNT_POINT);
        /* st = "mounted, X MB" -> 只展示容量部分 */
        char *cap = strchr(st, ',');
        printf("%s: %s\n", I18N("容量", "Capacity"),
               cap ? cap + 2 : st);
        printf("%s\n", I18N("已挂载", "Mounted"));
    } else {
        printf("%s\n", i18n_t("TF 卡状态"));
        printf("%s\n", I18N("未挂载", "Not mounted"));
    }
    printf("%s", I18N("脚本存储介质(自动): ", "Script storage (auto): "));
    printf("%s\n", script_store_media_name());
    if (!sdcard_is_mounted()) {
        printf("%s\n", I18N("提示: 插入TF卡并\"挂载 TF 卡\"后，上传/下载/运行全部走 TF 卡；"
                            "未挂载时脚本只存内存(RAM, 重启清空)",
                            "Hint: mount the TF card to store/run everything on it; "
                            "otherwise scripts live in RAM only (lost on reboot)"));
    }
}

static void action_sd_mount(void)
{
    if (sdcard_is_mounted()) {
        printf("%s\n", I18N("TF 卡已挂载", "TF card already mounted"));
        return;
    }
    printf("%s\n", I18N("正在挂载 TF 卡...", "Mounting TF card..."));
    esp_err_t r = sdcard_mount();
    if (r == ESP_OK) {
        printf("%s\n", I18N("TF 卡挂载成功", "TF card mounted successfully"));
        /* 挂载成功后脚本存储自动切到 TF 卡（无需手动切换） */
        printf("%s\n", I18N("TF 卡已就绪: 脚本存储自动切换为 TF 卡",
                            "TF card ready: script storage now on TF card automatically"));
    } else {
        printf("%s\n", I18N("TF 卡挂载失败: 请检查接线/供电/卡是否插好",
                            "Mount failed: check wiring/power/card"));
    }
}

static void action_sd_unmount(void)
{
    if (!sdcard_is_mounted()) {
        printf("%s\n", I18N("TF 卡未挂载", "TF card not mounted"));
        return;
    }
    /* 卸载后存储自动回落到内存 RAM（不写内部 Flash），无需手动切换介质 */
    printf("%s\n", I18N("正在卸载 TF 卡...", "Unmounting TF card..."));
    esp_err_t r = sdcard_unmount();
    if (r == ESP_OK) {
        printf("%s\n", I18N("TF 卡已安全卸载", "TF card unmounted"));
    } else {
        printf("%s: %s\n", I18N("卸载失败", "Unmount failed"),
               esp_err_to_name(r));
    }
}

static void action_sd_format(void)
{
    if (!sdcard_is_mounted()) {
        printf("%s\n", I18N("请先挂载 TF 卡再格式化",
                            "Mount the TF card first before formatting"));
        return;
    }
    printf("\n%s\n", I18N("确认格式化 TF 卡? 将删除卡上所有数据! (y=格式化, ESC=取消)",
                          "Format TF card? ALL data will be erased! (y=Format, ESC=Cancel)"));
    while (1) {
        int key = menu_wait_key();
        if (key == 'y' || key == 'Y') {
            break;
        }
        if (key == MENU_KEY_ESC || key == 'n' || key == 'N') {
            printf("%s\n", i18n_t("已取消"));
            return;
        }
    }
    printf("%s\n", I18N("正在格式化...", "Formatting..."));
    esp_err_t r = sdcard_format();
    printf("%s\n", (r == ESP_OK)
                       ? I18N("格式化完成", "Format complete")
                       : I18N("格式化失败", "Format failed"));
}

/* 主要关机确认 */
static void action_shutdown(void)
{
    printf("\n%s\n", I18N("确认关机? (回车=关机, ESC=继续运行)",
                         "Confirm shutdown? (Enter=Shutdown, ESC=Cancel)"));
    while (1) {
        int key = menu_wait_key();
        if (key == MENU_KEY_ENTER || key == '\n' || key == 'y' || key == 'Y') {
            break;
        }
        if (key == MENU_KEY_ESC || key == 'n' || key == 'N') {
            printf("%s\n", i18n_t("已取消"));
            return;
        }
    }

    printf("%s\n", i18n_t("正在关机..."));
    fflush(stdout);
    vTaskDelay(pdMS_TO_TICKS(150));   /* 让串口输出发送完 */

    ESP_LOGI(TAG, "进入深度睡眠(关机)。按 BOOT/EN 键唤醒重新运行。");

    /* 按 BOOT(GPIO0, 默认上拉) 可唤醒；若接真实电源管理可在此关断供电 */
    esp_sleep_enable_ext0_wakeup(GPIO_NUM_0, 0);
    esp_deep_sleep_start();            /* 不返回 */
}

/* ---------------- 菜单结构（支持子菜单，ESC 返回上级） ---------------- */

static const menu_screen_t s_wifi_menu;
static const menu_screen_t s_bt_menu;
static const menu_screen_t s_lua_menu;
static const menu_screen_t s_edge_menu;
static const menu_screen_t s_keyboard_menu;
static const menu_screen_t s_arp_menu;
static const menu_screen_t s_lang_menu;
static const menu_screen_t s_sd_menu;

/* 边缘安全：集中所有攻击/渗透测试工具 */
static const menu_item_t s_edge_items[] = {
    { "蓝牙探测",               NULL, action_ble_scan },
    { "ARP 中间人",             &s_arp_menu, NULL },
    { "键盘模拟输入",           &s_keyboard_menu, NULL },
    { "连接 gyscan (Go程序)",    NULL, action_tcp_connect },
};

static const menu_screen_t s_edge_menu = {
    "边缘安全",
    s_edge_items,
    sizeof(s_edge_items) / sizeof(s_edge_items[0]),
};

/* ARP 中间人子菜单 */
static const menu_item_t s_arp_items[] = {
    { "启动 ARP MITM",   NULL, action_arp_mitm_start },
    { "停止 ARP MITM",   NULL, action_arp_mitm_stop },
    { "ARP MITM 状态",   NULL, action_arp_mitm_status },
};

static const menu_screen_t s_arp_menu = {
    "ARP 中间人",
    s_arp_items,
    sizeof(s_arp_items) / sizeof(s_arp_items[0]),
};

static const menu_item_t s_keyboard_items[] = {
    { "注入测试文本",   NULL, action_hid_test },
    { "USB 键盘状态",   NULL, action_hid_status },
};

static const menu_screen_t s_keyboard_menu = {
    "键盘模拟",
    s_keyboard_items,
    sizeof(s_keyboard_items) / sizeof(s_keyboard_items[0]),
};

/* WiFi 设置 */
static const menu_item_t s_wifi_items[] = {
    { "连接 WiFi",              NULL, action_wifi_connect },
    { "手动输入 SSID/密码",      NULL, action_wifi_setup },
    { "断开 WiFi",              NULL, action_wifi_disconnect },
    { "网络与 HTTP 状态",        NULL, action_http_status },
    { "gyscan控制(1234)状态",    NULL, action_tcp_status2 },
};

static const menu_screen_t s_wifi_menu = {
    "WiFi 设置",
    s_wifi_items,
    sizeof(s_wifi_items) / sizeof(s_wifi_items[0]),
};

/* 蓝牙设置 */
static const menu_item_t s_bt_items[] = {
    { "蓝牙配对",   NULL, action_ble_pair },
};

static const menu_screen_t s_bt_menu = {
    "蓝牙设置",
    s_bt_items,
    sizeof(s_bt_items) / sizeof(s_bt_items[0]),
};

/* Lua 脚本子菜单：运行 / 删除 / 存储查看（介质自动 = TF 卡或内存 RAM） */
static const menu_item_t s_lua_items[] = {
    { "运行 Lua 脚本", NULL, action_lua_run },
    { "删除脚本文件",  NULL, action_lua_delete },
    { "查看脚本存储",  NULL, action_lua_storage },
};

static const menu_screen_t s_lua_menu = {
    "Lua 脚本",
    s_lua_items,
    sizeof(s_lua_items) / sizeof(s_lua_items[0]),
};

/* TF 卡设置 */
static const menu_item_t s_sd_items[] = {
    { "TF 卡状态",        NULL, action_sd_status },
    { "挂载 TF 卡",       NULL, action_sd_mount },
    { "卸载 TF 卡",       NULL, action_sd_unmount },
    { "格式化 TF 卡",     NULL, action_sd_format },
};

static const menu_screen_t s_sd_menu = {
    "TF 卡设置",
    s_sd_items,
    sizeof(s_sd_items) / sizeof(s_sd_items[0]),
};

/* 语言切换 */
static const menu_item_t s_lang_items[] = {
    { "中文",    NULL, action_set_zh },
    { "English", NULL, action_set_en },
};

static const menu_screen_t s_lang_menu = {
    "语言",
    s_lang_items,
    sizeof(s_lang_items) / sizeof(s_lang_items[0]),
};

/* 主菜单：功能入口 + 语言切换 + 关机 */
static const menu_item_t s_root_items[] = {
    { "WiFi 设置",     &s_wifi_menu, NULL },
    { "蓝牙设置",      &s_bt_menu,   NULL },
    { "边缘安全",      &s_edge_menu, NULL },
    { "Lua 脚本",       &s_lua_menu,  NULL },
    { "TF 卡设置",     &s_sd_menu,   NULL },
    { "语言",          &s_lang_menu, NULL },
    { "关机",          NULL,         action_shutdown },
};

static const menu_screen_t s_root_menu = {
    "主菜单",
    s_root_items,
    sizeof(s_root_items) / sizeof(s_root_items[0]),
};

/* 菜单运行在独立任务中，栈空间足够 WiFi/BLE/TCP 使用 */
static void menu_task(void *arg)
{
    /* 顶级主菜单按 ESC/q → 关机确认 */
    menu_set_exit_handler(action_shutdown);
    menu_run(&s_root_menu);
    vTaskDelete(NULL);
}

/* 后台初始化 USB HID 键盘：初始化耗时长(QEMU下会失败)，不阻塞开机 */
static void hid_task(void *arg)
{
    esp_err_t r = hid_keyboard_init();
    if (r != ESP_OK) {
        ESP_LOGW(TAG, "USB HID 键盘初始化失败(%s)，USB 键盘功能不可用",
                 esp_err_to_name(r));
    }
    vTaskDelete(NULL);
}

/* WiFi 后台自动连接（阻塞型，独立任务；QEMU 中 WiFi 卡住也不影响其它网络） */
static void wifi_auto_task(void *arg)
{
    int fail_count = 0;
    while (1) {
        if (wifi_is_connected()) {
            vTaskDelay(pdMS_TO_TICKS(10000));
            continue;
        }
        esp_err_t err = wifi_sta_connect();
        if (err == ESP_OK) {
            fail_count = 0;
            ESP_LOGI(TAG, "WiFi 已连接: %s", wifi_get_active_ssid());
        } else if (err == ESP_ERR_NOT_SUPPORTED || err == ESP_ERR_INVALID_STATE) {
            ESP_LOGW(TAG, "当前平台不支持 WiFi");
            vTaskDelay(pdMS_TO_TICKS(30000));
            continue;
        } else {
            fail_count++;
            ESP_LOGW(TAG, "WiFi 连接失败(%s)", esp_err_to_name(err));
        }
        vTaskDelay(pdMS_TO_TICKS((fail_count >= 3) ? 30000 : 10000));
    }
    vTaskDelete(NULL);
}

/* 网络监视任务：WiFi 或 以太网(openeth/QEMU) 任一就绪即启动服务 */
static void net_task(void *arg)
{
#if defined(CONFIG_ETH_USE_OPENETH)
    ESP_LOGW(TAG, "并行启动 QEMU 以太网(openeth)...");
    eth_start();
#endif

    xTaskCreate(wifi_auto_task, "wifi", 8192, NULL, 5, NULL);

    while (1) {
#if defined(CONFIG_ETH_USE_OPENETH)
        /* QEMU 下 esp_event 事件循环可能不调度 IP_EVENT_ETH_GOT_IP，
         * 因此除事件标志(eth_got_ip)外，再直接轮询 netif 上的 IP 兑底 */
        if (eth_got_ip() || eth_has_ip()) {
            ESP_LOGI(TAG, "以太网就绪，启动服务: HTTP(%d) + gyscan控制(%d)",
                     CONFIG_GYSCAN_HTTP_PORT, CONFIG_GYSCAN_TCP_PORT);
            http_server_start();
            tcp_server_start();
            break;
        }
#endif /* CONFIG_ETH_USE_OPENETH */
        if (wifi_is_connected()) {
            ESP_LOGI(TAG, "WiFi 就绪，启动服务: HTTP(%d) + gyscan控制(%d)",
                     CONFIG_GYSCAN_HTTP_PORT, CONFIG_GYSCAN_TCP_PORT);
            http_server_start();
            tcp_server_start();
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
    vTaskDelete(NULL);
}

/* 开机后台探测并自动挂载 TF 卡：挂载成功后脚本/资源介质自动变为 TF 卡(/sdcard)。
 * 没有 TF 卡模块时直接跳过探测，脚本/资源默认使用内存 RAM(不写 Flash)：
 *   - QEMU(openeth) 环境：无 TF 卡模拟，直接跳过；
 *   - CONFIG_GYSCAN_SDCARD_AUTO_DETECT 关闭：不做开机探测；
 * 手动"挂载 TF 卡"不受影响。 */
static void sd_auto_mount_task(void *arg)
{
#if defined(CONFIG_ETH_USE_OPENETH)
    ESP_LOGI(TAG, "QEMU 环境无 TF 卡模块模拟: 跳过自动挂载, 默认使用内存 RAM(不写 Flash)");
#elif defined(CONFIG_GYSCAN_SDCARD_ENABLE) && defined(CONFIG_GYSCAN_SDCARD_AUTO_DETECT)
    esp_err_t r = sdcard_mount();
    if (r == ESP_OK) {
        ESP_LOGI(TAG, "TF 卡已自动挂载，脚本存储介质: %s", script_store_media_name());
    } else {
        ESP_LOGW(TAG, "未探测到 TF 卡(%s)，脚本/资源使用内存 RAM(不写 Flash)",
                 esp_err_to_name(r));
    }
#else
    ESP_LOGI(TAG, "TF 卡自动探测已关闭/未启用: 脚本/资源默认使用内存 RAM(不写 Flash)");
#endif
    vTaskDelete(NULL);
}

void app_main(void)
{
    boot_splash_show();

    /* 初始化 NVS（WiFi/BLE 需要） */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* 存储层：自动介质(有TF卡→TF卡; 无→内存RAM, 不写Flash) */
    script_store_init();
    /* Lua 运行时创建时自动注册内置 net 模块(HTTP/HTTPS/DNS/TCP, 无需 luarocks) */
    lua_embed_set_init_hook(gyscan_lua_net_register);
#if defined(CONFIG_GYSCAN_SDCARD_ENABLE)
    /* 后台自动挂载 TF 卡(有卡自动全走 TF 卡；无卡/关闭探测则默认内存 RAM) */
    xTaskCreate(sd_auto_mount_task, "sd_mount", 4096, NULL, 4, NULL);
#else
    ESP_LOGI(TAG, "未启用 TF 卡支持: 脚本/资源默认使用内存 RAM(不写 Flash)");
#endif

    /* USB HID 键盘设备（后台初始化，不阻塞启动；menuconfig 可关闭） */
#ifdef CONFIG_GYSCAN_ENABLE_USB_HID
    xTaskCreate(hid_task, "hid", 4096, NULL, 4, NULL);
#endif

    /* LED 闪烁作为运行指示（后台任务，QEMU 等无 RMT 环境自动跳过） */
    xTaskCreate(led_task, "led", 2048, NULL, 4, NULL);

    /* 自动连接 WiFi，成功后启动 HTTP 状态服务（无 WiFi 平台自动跳过） */
    xTaskCreate(net_task, "net", 8192, NULL, 5, NULL);

    /* 进入交互菜单 */
    ESP_LOGI(TAG, "启动调试菜单...");
    xTaskCreate(menu_task, "menu", 8192, NULL, 5, NULL);
}

