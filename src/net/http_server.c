/*
 * http_server.c - HTTP 服务器
 *
 * 使用 esp_http_server 组件。ESP 启动并连上网络后自动运行，
 * 通过 curl / wget / 浏览器访问时，根据 gyscan 控制服务是否就绪返回：
 *   ESP-GYscan:ok      —— 可被 gyscan 连接（1234 控制服务运行中）
 *   ESP-GYscan:error   —— 不可被 gyscan 连接（控制服务未就绪/异常）
 */

#include "http_server.h"
#include <string.h>
#include "esp_http_server.h"
#include "esp_log.h"
#include "sdkconfig.h"
#include "tcp_server.h"

static const char *TAG = "http";

static httpd_handle_t s_server = NULL;

static const char s_ok_body[]    = "ESP-GYscan:ok\n";
static const char s_err_body[]   = "ESP-GYscan:error\n";

static esp_err_t ok_get_handler(httpd_req_t *req)
{
    /* gyscan 控制服务(1234)运行中 → 可被 gyscan 连接 → ok；否则 error */
    const char *body = tcp_server_is_running() ? s_ok_body : s_err_body;
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_set_status(req, HTTPD_200);
    httpd_resp_send(req, body, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static void register_handlers(httpd_handle_t server)
{
    /* 根路径 + 常用别名路径都返回同样的内容 */
    static const char *uris[] = { "/", "/ok", "/status" };
    for (int i = 0; i < (int)(sizeof(uris) / sizeof(uris[0])); i++) {
        httpd_uri_t uri = {
            .uri = uris[i],
            .method = HTTP_GET,
            .handler = ok_get_handler,
            .user_ctx = NULL,
        };
        esp_err_t err = httpd_register_uri_handler(server, &uri);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "注册 %s 处理器失败: %s", uris[i], esp_err_to_name(err));
        }
    }
}

esp_err_t http_server_start(void)
{
    if (s_server != NULL) {
        return ESP_OK;   /* 已在运行 */
    }

    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.server_port = CONFIG_GYSCAN_HTTP_PORT;
    cfg.lru_purge_enable = true;

    esp_err_t ret = httpd_start(&s_server, &cfg);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "HTTP 服务器启动失败: %s", esp_err_to_name(ret));
        s_server = NULL;
        return ret;
    }

    register_handlers(s_server);
    ESP_LOGI(TAG, "HTTP 服务器已启动 (端口 %d)，访问返回 ESP-GYscan:ok/error",
             CONFIG_GYSCAN_HTTP_PORT);
    return ESP_OK;
}

void http_server_stop(void)
{
    if (s_server != NULL) {
        httpd_stop(s_server);
        s_server = NULL;
        ESP_LOGI(TAG, "HTTP 服务器已停止");
    }
}

bool http_server_is_running(void)
{
    return s_server != NULL;
}
