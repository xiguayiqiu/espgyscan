#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 连接 gyscan (Go程序) 服务器：
 *  1. 确保已连接 WiFi（自动连接 menuconfig 中配置的 AP）
 *  2. TCP 连接 CONFIG_GYSCAN_SERVER_HOST:CONFIG_GYSCAN_SERVER_PORT
 *  3. 发送 CONFIG_GYSCAN_CMD 命令，打印服务器响应
 */
void tcp_client_run(void);

#ifdef __cplusplus
}
#endif
