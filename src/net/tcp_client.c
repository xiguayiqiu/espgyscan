/*
 * tcp_client.c - 连接 gyscan (Go程序) 服务器
 *
 * 流程：确保 WiFi 连接 -> 解析地址 -> 非阻塞 connect(带超时) ->
 *       发送配置的命令 -> 接收并打印服务器响应。
 *
 * 服务器地址/端口/命令等均可在 menuconfig 中配置。
 */

#include "tcp_client.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include "lwip/sockets.h"
#include "lwip/netdb.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "sdkconfig.h"
#include "wifi_scan.h"

static const char *TAG = "tcp";

void tcp_client_run(void)
{
    printf("\n========== 连接 gyscan (Go程序) ==========\n");

    /* 1. 确保 WiFi 已连接 */
    if (wifi_sta_connect() != ESP_OK) {
        printf("WiFi 未连接，无法连接 gyscan 服务器\n");
        return;
    }
    printf("服务器: %s:%d\n", CONFIG_GYSCAN_SERVER_HOST, CONFIG_GYSCAN_SERVER_PORT);

    /* 2. 创建 socket */
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        ESP_LOGE(TAG, "创建 socket 失败: errno=%d", errno);
        return;
    }

    /* 3. 解析服务器地址（支持 IP 或域名） */
    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(CONFIG_GYSCAN_SERVER_PORT);

    if (inet_pton(AF_INET, CONFIG_GYSCAN_SERVER_HOST, &dest.sin_addr) != 1) {
        struct hostent *he = gethostbyname(CONFIG_GYSCAN_SERVER_HOST);
        if (he != NULL && he->h_addr_list[0] != NULL) {
            memcpy(&dest.sin_addr.s_addr, he->h_addr, he->h_length);
        } else {
            printf("无法解析服务器地址: %s\n", CONFIG_GYSCAN_SERVER_HOST);
            close(sock);
            return;
        }
    }
    if (dest.sin_addr.s_addr == 0) {
        printf("无法解析服务器地址: %s\n", CONFIG_GYSCAN_SERVER_HOST);
        close(sock);
        return;
    }

    /* 4. 非阻塞 connect + select 超时 */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int ret = connect(sock, (struct sockaddr *)&dest, sizeof(dest));
    if (ret < 0 && errno != EINPROGRESS) {
        ESP_LOGE(TAG, "connect 失败: errno=%d (%s)", errno, strerror(errno));
        close(sock);
        return;
    }

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    struct timeval tv = { .tv_sec = CONFIG_GYSCAN_CONNECT_TIMEOUT_S, .tv_usec = 0 };
    ret = select(sock + 1, NULL, &wset, NULL, &tv);
    if (ret <= 0 || !FD_ISSET(sock, &wset)) {
        printf("连接服务器超时\n");
        close(sock);
        return;
    }
    int so_err = 0;
    socklen_t slen = sizeof(so_err);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_err, &slen);
    if (so_err != 0) {
        ESP_LOGE(TAG, "连接被拒绝: errno=%d (%s)", so_err, strerror(so_err));
        close(sock);
        return;
    }
    fcntl(sock, F_SETFL, flags);    /* 恢复阻塞模式 */
    printf("已连接服务器 ✓\n");

    /* 5. 发送命令 */
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "%s\n", CONFIG_GYSCAN_CMD);
    printf("发送命令: %s", cmd);
    send(sock, cmd, strlen(cmd), 0);

    /* 6. 接收并打印服务器响应 */
    struct timeval rtv = { .tv_sec = CONFIG_GYSCAN_RECV_TIMEOUT_S, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &rtv, sizeof(rtv));

    char buf[256];
    int len;
    printf("--- 服务器响应 ---\n");
    while ((len = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[len] = '\0';
        printf("%s", buf);
    }
    if (len < 0) {
        printf("\n(接收超时，服务器未继续发送数据)\n");
    }
    printf("--- 连接结束 ---\n");

    close(sock);
}
