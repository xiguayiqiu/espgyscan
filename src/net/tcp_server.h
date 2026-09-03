#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 启动远程控制 TCP 服务器（端口 CONFIG_GYSCAN_TCP_PORT，默认 1234）
 * 服务器任务会等待 WiFi 连接后自动开始监听 */
esp_err_t tcp_server_start(void);

/* 停止远程控制服务器 */
void tcp_server_stop(void);

/* 服务器是否正在运行 */
bool tcp_server_is_running(void);

/* 当前连接的客户端数量 */
int tcp_server_client_count(void);

/* 向所有已连接客户端转发一行 ARP 抓包数据（自动加 "ARP " 前缀） */
void tcp_server_arp_forward(const char *data);

#ifdef __cplusplus
}
#endif
