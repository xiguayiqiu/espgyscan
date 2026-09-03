/*
 * net_scan.c - 网段/端口扫描（ESP 作为 TCP 客户端探测）
 *
 * 使用非阻塞 connect + select 实现快速探测；结果经回调实时上报。
 */

#include "net_scan.h"
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "esp_log.h"

static const char *TAG = "scan";

#define SCAN_CONN_TIMEOUT_DEFAULT_MS 250

/* 常见服务端口 */
static const uint16_t s_common_ports[] = {
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
    993, 995, 1080, 1433, 1521, 3306, 3389, 5432, 5900,
    6379, 8000, 8080, 8443, 8888, 9090, 27017,
};

static const char *ip_str(uint32_t ip, char *buf, size_t sz)
{
    snprintf(buf, sz, "%u.%u.%u.%u",
             (unsigned)(ip & 0xff), (unsigned)((ip >> 8) & 0xff),
             (unsigned)((ip >> 16) & 0xff), (unsigned)((ip >> 24) & 0xff));
    return buf;
}

/* 探测单端口：
 * 返回 0 = 开放(收到应答/SYN-ACK)，1 = 拒绝(收到 RST，主机在线端口关闭)，
 *     -1 = 超时无响应(主机大概率离线) */
static int tcp_probe(uint32_t ip, uint16_t port, int timeout_ms)
{
    int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s < 0) {
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(ip);

    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(s, (struct sockaddr *)&addr, sizeof(addr));
    int result = -1;
    if (ret == 0) {
        result = 0;
    } else if (errno == EINPROGRESS) {
        fd_set wset;
        FD_ZERO(&wset);
        FD_SET(s, &wset);
        struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        ret = select(s + 1, NULL, &wset, NULL, &tv);
        if (ret > 0 && FD_ISSET(s, &wset)) {
            int so_err = 0;
            socklen_t slen = sizeof(so_err);
            getsockopt(s, SOL_SOCKET, SO_ERROR, &so_err, &slen);
            if (so_err == 0) {
                result = 0;                      /* 开放 */
            } else if (so_err == ECONNREFUSED) {
                result = 1;                      /* 拒绝(RST)，主机在线 */
            }
        }
    } else if (errno == ECONNREFUSED) {
        result = 1;                              /* 立即拒绝，主机在线 */
    }
    close(s);
    return result;
}

/* 探测单端口是否开放 */
static int port_open(uint32_t ip, uint16_t port, int timeout_ms)
{
    return tcp_probe(ip, port, timeout_ms) == 0;
}

esp_err_t net_scan_host_ports(const char *host, const uint16_t *ports, int port_n,
                              int timeout_ms, scan_hit_fn hit, void *ctx)
{
    uint32_t ip;
    if (inet_pton(AF_INET, host, &ip) != 1) {
        return ESP_ERR_INVALID_ARG;
    }
    ip = ntohl(ip);
    if (timeout_ms <= 0) {
        timeout_ms = SCAN_CONN_TIMEOUT_DEFAULT_MS;
    }

    for (int i = 0; i < port_n; i++) {
        if (port_open(ip, ports[i], timeout_ms) && hit) {
            char ipb[16];
            hit(ip_str(ip, ipb, sizeof(ipb)), ports[i], ctx);
        }
        vTaskDelay(pdMS_TO_TICKS(2));
    }
    return ESP_OK;
}

esp_err_t net_scan_host_common(const char *host, int timeout_ms,
                               scan_hit_fn hit, void *ctx)
{
    return net_scan_host_ports(host, s_common_ports,
                               sizeof(s_common_ports) / sizeof(s_common_ports[0]),
                               timeout_ms, hit, ctx);
}

esp_err_t net_scan_host_range(const char *host, uint16_t lo, uint16_t hi,
                              int timeout_ms, scan_hit_fn hit, void *ctx)
{
    uint32_t ip;
    if (inet_pton(AF_INET, host, &ip) != 1) {
        return ESP_ERR_INVALID_ARG;
    }
    ip = ntohl(ip);
    if (timeout_ms <= 0) {
        timeout_ms = SCAN_CONN_TIMEOUT_DEFAULT_MS;
    }
    if (hi < lo) {
        return ESP_ERR_INVALID_ARG;
    }
    int range = (int)hi - (int)lo + 1;
    if (range > 4096) {
        range = 4096;   /* 限制单次范围，避免长时间阻塞 */
        hi = lo + 4095;
    }

    for (uint16_t p = lo; p <= hi; p++) {
        if (port_open(ip, p, timeout_ms) && hit) {
            char ipb[16];
            hit(ip_str(ip, ipb, sizeof(ipb)), p, ctx);
        }
        if ((p & 0xFF) == 0) {
            vTaskDelay(pdMS_TO_TICKS(5));   /* 每 256 端口让出一点 */
        }
    }
    return ESP_OK;
}

esp_err_t net_scan_cidr(const char *cidr, int timeout_ms,
                        scan_hit_fn hit, void *ctx)
{
    /* 解析 a.b.c.d/prefix */
    unsigned a, b, c, d, prefix;
    if (sscanf(cidr, "%u.%u.%u.%u/%u", &a, &b, &c, &d, &prefix) != 5) {
        return ESP_ERR_INVALID_ARG;
    }
    if (a > 255 || b > 255 || c > 255 || d > 255 || prefix > 32) {
        return ESP_ERR_INVALID_ARG;
    }
    uint32_t base = ((a << 24) | (b << 16) | (c << 8) | d);
    uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
    uint32_t start = base & mask;
    uint32_t end = start | ~mask;

    /* 防止扫描范围过大：最多 254 个主机 */
    uint32_t total = end - start + 1;
    if (total > 254) {
        total = 254;
        end = start + total - 1;
    }

    ESP_LOGI(TAG, "CIDR 扫描 %s (%u 个主机)", cidr, (unsigned)total);

    for (uint32_t ip = start + 1; ip < start + total; ip++) {
        char host[16];
        ip_str(ip, host, sizeof(host));
        /* 对每个主机探测通用服务端口 */
        for (size_t i = 0; i < sizeof(s_common_ports) / sizeof(s_common_ports[0]); i++) {
            if (port_open(ip, s_common_ports[i], timeout_ms > 0 ? timeout_ms : 150)) {
                if (hit) {
                    char ipb[16];
                    hit(ip_str(ip, ipb, sizeof(ipb)), s_common_ports[i], ctx);
                }
            }
        }
        vTaskDelay(pdMS_TO_TICKS(3));
    }
    return ESP_OK;
}

/* 探测主机是否在线：任一常见端口有响应(开放或拒绝)即认为在线 */
int net_host_is_up(const char *host, int timeout_ms)
{
    uint32_t ip;
    if (inet_pton(AF_INET, host, &ip) != 1) {
        return 0;
    }
    ip = ntohl(ip);
    if (timeout_ms <= 0) {
        timeout_ms = SCAN_CONN_TIMEOUT_DEFAULT_MS;
    }
    static const uint16_t probe_ports[] = { 80, 22, 443, 445, 8080 };
    for (size_t i = 0; i < sizeof(probe_ports) / sizeof(probe_ports[0]); i++) {
        int r = tcp_probe(ip, probe_ports[i], timeout_ms);
        if (r == 0 || r == 1) {
            return 1;
        }
    }
    return 0;
}

/* 扫描网段内存活主机 */
esp_err_t net_scan_alive_hosts(const char *own_ip, const char *netmask,
                               int timeout_ms, alive_host_fn alive, void *ctx)
{
    uint32_t ip, mask;
    if (inet_pton(AF_INET, own_ip, &ip) != 1 ||
        inet_pton(AF_INET, netmask, &mask) != 1) {
        return ESP_ERR_INVALID_ARG;
    }
    ip = ntohl(ip);
    mask = ntohl(mask);
    if (timeout_ms <= 0) {
        timeout_ms = SCAN_CONN_TIMEOUT_DEFAULT_MS;
    }
    if (mask == 0) {
        mask = 0x00FFFFFF;   /* 兜底 /24 */
    }

    uint32_t start = ip & mask;
    uint32_t broadcast = start | ~mask;
    if (broadcast - start > 254) {
        broadcast = start + 254;   /* 限制扫描规模 */
    }

    ESP_LOGI(TAG, "存活主机扫描: %u.%u.%u.1-… ", 
             (unsigned)((start + 1) >> 24) & 0xff, (unsigned)((start + 1) >> 16) & 0xff,
             (unsigned)((start + 1) >> 8) & 0xff, 0);

    for (uint32_t h = 0; (start + 1 + h) < broadcast; h++) {
        uint32_t cand = start + 1 + h;
        if (cand == ip) {
            continue;   /* 跳过 ESP 自身 */
        }
        int up = 0;
        static const uint16_t probe_ports[] = { 80, 22 };
        for (size_t i = 0; i < sizeof(probe_ports) / sizeof(probe_ports[0]); i++) {
            int r = tcp_probe(cand, probe_ports[i], timeout_ms);
            if (r == 0 || r == 1) {
                up = 1;
                break;
            }
        }
        if (up && alive) {
            char hostb[16];
            alive(ip_str(cand, hostb, sizeof(hostb)), ctx);
        }
        if ((h & 0x1F) == 0x1F) {
            vTaskDelay(pdMS_TO_TICKS(2));   /* 周期让出 CPU */
        }
    }
    return ESP_OK;
}
