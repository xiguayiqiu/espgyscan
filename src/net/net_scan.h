#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 命中回调：ip:port 开放 */
typedef void (*scan_hit_fn)(const char *host, uint16_t port, void *ctx);

/* 存活主机回调：ip 主机在线 */
typedef void (*alive_host_fn)(const char *host, void *ctx);

/* 探测网段内存活主机（用 TCP 连接触发，返回拒绝/开放都算在线）。
 * own_ip/netmask 为点分十进制；每个在线主机回调一次 alive(host, ctx)。
 * 同步阻塞；timeout_ms<0 用默认值。 */
esp_err_t net_scan_alive_hosts(const char *own_ip, const char *netmask,
                               int timeout_ms, alive_host_fn alive, void *ctx);

/* 探测单个主机是否在线（TCP 探测；返回 1 在线 / 0 离线） */
int net_host_is_up(const char *host, int timeout_ms);

/* 扫描单个主机的端口列表 */
esp_err_t net_scan_host_ports(const char *host, const uint16_t *ports, int port_n,
                              int timeout_ms, scan_hit_fn hit, void *ctx);

/* 扫描单个主机的常见服务端口（默认端口表） */
esp_err_t net_scan_host_common(const char *host, int timeout_ms,
                               scan_hit_fn hit, void *ctx);

/* 扫描单个主机的端口区间 */
esp_err_t net_scan_host_range(const char *host, uint16_t lo, uint16_t hi,
                              int timeout_ms, scan_hit_fn hit, void *ctx);

/* 扫描 CIDR 网段（自动探测各主机通用服务端口） */
esp_err_t net_scan_cidr(const char *cidr, int timeout_ms,
                        scan_hit_fn hit, void *ctx);

#ifdef __cplusplus
}
#endif
