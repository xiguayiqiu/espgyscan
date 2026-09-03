#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 启动 HTTP 服务器（端口 CONFIG_GYSCAN_HTTP_PORT，默认 80）
 * 用 curl / wget / 浏览器访问任意路径都会返回 "esp-gyscan：ok"
 */
esp_err_t http_server_start(void);

/* 停止 HTTP 服务器 */
void http_server_stop(void);

/* HTTP 服务器是否在运行 */
bool http_server_is_running(void);

#ifdef __cplusplus
}
#endif
