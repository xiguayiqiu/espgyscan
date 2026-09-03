/*
 * lua_net.c - 固件内置 Lua 网络模块 (net)
 *
 * 脚本可直接使用全局 net 表进行网络访问，全部基于 ESP-IDF 原生组件
 * (lwIP / esp_http_client / esp-tls / mbedtls 证书包) 实现，
 * 不需要任何 luarocks 依赖，也无需额外文件系统资源：
 *
 *   net.resolve(host)                  → ip | nil, err        (DNS 解析)
 *   net.http_get(url[, timeout_ms])    → status, body | nil, err  (支持 https)
 *   net.http_post(url, body[, ct][, timeout_ms]) → status, body | nil, err
 *   net.tcp_query(host, port, payload[, max_resp][, timeout_ms])
 *                                     → response | nil, err   (原始 TCP 一问一答)
 *
 * HTTPS 默认携带完整 CA 证书包(esp_crt_bundle)自动校验服务器证书。
 * 均为同步阻塞调用；脚本运行期间 Lua 解释器串行执行，互不干扰。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <fcntl.h>
#include <sys/select.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_timer.h"

#include "lua.h"
#include "lauxlib.h"
#include "esp_log.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "lwip/sockets.h"
#include "lwip/netdb.h"

#include "lua_net.h"
#include "lua_pcap.h"
#include "lua_ble.h"
#include "sdkconfig.h"

/* 与 esp-idf mbedtls 库保持同一套编译配置，否则 x509 等结构体布局不一致 */
#ifndef MBEDTLS_CONFIG_FILE
#define MBEDTLS_CONFIG_FILE "mbedtls/esp_config.h"
#endif
#include "mbedtls/x509_crt.h"

static const char *TAG = "lua_net";

/* 响应/数据上限：GET/POST body 与 tcp_query 单次读取的最大字节数 */
#define LUA_NET_MAX_BODY  (64 * 1024)

/* ---------------- 响应收集 ---------------- */

typedef struct {
    char *buf;
    size_t cap;
    size_t used;
    int   overflow;
} net_body_t;

static net_body_t net_body_new(void)
{
    net_body_t b;
    b.cap = 4096;               /* 小缓冲起步，随数据增长按需扩容 */
    b.buf = malloc(b.cap);
    b.used = 0;
    b.overflow = 0;
    return b;
}

static void net_body_free(net_body_t *b)
{
    free(b->buf);
    b->buf = NULL;
}

static esp_err_t collect_on_data(esp_http_client_event_t *evt)
{
    if (evt->event_id != HTTP_EVENT_ON_DATA) {
        return ESP_OK;
    }
    net_body_t *b = (net_body_t *)evt->user_data;
    if (b == NULL || b->overflow) {
        return ESP_OK;
    }
    size_t n = evt->data_len;
    if (b->used + n > b->cap) {
        if (b->cap >= LUA_NET_MAX_BODY || b->used + n > LUA_NET_MAX_BODY) {
            b->overflow = 1;   /* 超过上限(64KB)：丢弃后续并标记 */
            return ESP_OK;
        }
        size_t ncap = b->cap * 2;
        if (ncap < b->used + n) {
            ncap = b->used + n;
        }
        if (ncap > LUA_NET_MAX_BODY) {
            ncap = LUA_NET_MAX_BODY;
        }
        char *nbuf = realloc(b->buf, ncap);
        if (nbuf == NULL) {
            b->overflow = 1;
            return ESP_OK;
        }
        b->buf = nbuf;
        b->cap = ncap;
    }
    memcpy(b->buf + b->used, evt->data, n);
    b->used += n;
    return ESP_OK;
}

/* ---------------- DNS：net.resolve ---------------- */

/* 主机名清洗：剥掉误带的 http:// https:// 前缀与路径，如 "https://kali.org/" */
static const char *sanitize_host(const char *host, char *buf, size_t sz)
{
    const char *p = host;
    if (p != NULL && strncmp(p, "https://", 8) == 0) {
        p += 8;
    } else if (p != NULL && strncmp(p, "http://", 7) == 0) {
        p += 7;
    }
    snprintf(buf, sz, "%s", (p != NULL) ? p : "");
    char *slash = strchr(buf, '/');
    if (slash != NULL) {
        *slash = '\0';
    }
    return buf;
}

static int lua_net_resolve(lua_State *L)
{
    char hostbuf[128];
    const char *host = sanitize_host(luaL_checkstring(L, 1), hostbuf,
                                     sizeof(hostbuf));
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0 || res == NULL) {
        lua_pushnil(L);
        lua_pushfstring(L, "DNS 解析失败: %s (rc=%d)", host, rc);
        return 2;
    }
    struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
    char *ip = inet_ntoa(sa->sin_addr);
    lua_pushstring(L, (ip != NULL) ? ip : "0.0.0.0");
    freeaddrinfo(res);
    return 1;
}

/* ---------------- HTTP(S)：net.http_get / net.http_post ---------------- */

/* 返回: 成功 -> status, body ；失败 -> nil, err */
static int lua_net_http_request(lua_State *L, int is_post,
                                const char *url, int timeout_ms,
                                const char *body, size_t body_len,
                                const char *content_type)
{
    net_body_t b = net_body_new();
    if (b.buf == NULL) {
        lua_pushnil(L);
        lua_pushliteral(L, "内存不足");
        return 2;
    }

    esp_http_client_config_t cfg = {
        .url = url,
        .method = is_post ? HTTP_METHOD_POST : HTTP_METHOD_GET,
        .timeout_ms = timeout_ms,
        .event_handler = collect_on_data,
        .user_data = &b,
        .crt_bundle_attach = esp_crt_bundle_attach,   /* https 自动校验证书 */
        .disable_auto_redirect = false,               /* 跟随重定向 */
    };
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (client == NULL) {
        net_body_free(&b);
        lua_pushnil(L);
        lua_pushliteral(L, "esp_http_client_init 失败");
        return 2;
    }
    if (is_post) {
        esp_http_client_set_method(client, HTTP_METHOD_POST);
        esp_http_client_set_header(client, "Content-Type", content_type);
        esp_http_client_set_post_field(client, body, (int)body_len);
    }

    esp_err_t err = esp_http_client_perform(client);
    int status = (err == ESP_OK) ? esp_http_client_get_status_code(client) : 0;
    esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        net_body_free(&b);
        lua_pushnil(L);
        lua_pushfstring(L, "HTTP 请求失败: %s (url=%s)", esp_err_to_name(err), url);
        return 2;
    }
    if (b.overflow) {
        net_body_free(&b);
        lua_pushnil(L);
        lua_pushfstring(L, "响应体超过上限 %d 字节", (int)LUA_NET_MAX_BODY);
        return 2;
    }
    lua_pushinteger(L, status);
    lua_pushlstring(L, b.buf, b.used);
    net_body_free(&b);
    return 2;
}

static int lua_net_http_get(lua_State *L)
{
    const char *url = luaL_checkstring(L, 1);
    int timeout_ms = (int)luaL_optinteger(L, 2, 5000);
    return lua_net_http_request(L, 0, url, timeout_ms, NULL, 0, NULL);
}

static int lua_net_http_post(lua_State *L)
{
    const char *url = luaL_checkstring(L, 1);
    size_t body_len = 0;
    const char *body = luaL_checklstring(L, 2, &body_len);
    const char *ct = luaL_optstring(L, 3, "application/x-www-form-urlencoded");
    int timeout_ms = (int)luaL_optinteger(L, 4, 5000);
    return lua_net_http_request(L, 1, url, timeout_ms, body, body_len, ct);
}

/* ---------------- 原始 TCP：net.tcp_query ---------------- */

static int lua_net_tcp_query(lua_State *L)
{
    const char *host_in = luaL_checkstring(L, 1);
    int port = (int)luaL_checkinteger(L, 2);
    size_t plen = 0;
    const char *payload = luaL_checklstring(L, 3, &plen);
    size_t max_resp = (size_t)luaL_optinteger(L, 4, 8192);
    int timeout_ms = (int)luaL_optinteger(L, 5, 5000);
    if (port <= 0 || port > 65535) {
        lua_pushnil(L);
        lua_pushliteral(L, "端口无效");
        return 2;
    }
    if (max_resp <= 0) {
        max_resp = 8192;
    }
    if (max_resp > LUA_NET_MAX_BODY) {
        max_resp = LUA_NET_MAX_BODY;
    }
    char hostbuf[128];
    const char *host = sanitize_host(host_in, hostbuf, sizeof(hostbuf));

    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || res == NULL) {
        lua_pushnil(L);
        lua_pushfstring(L, "DNS 解析失败: %s", host);
        return 2;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    memcpy(&addr, res->ai_addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    freeaddrinfo(res);

    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "socket 创建失败: %s", strerror(errno));
        return 2;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc != 0) {
        close(fd);
        lua_pushnil(L);
        lua_pushfstring(L, "TCP 连接失败: %s", strerror(errno));
        return 2;
    }

    /* 发送全部载荷(二进制安全) */
    size_t off = 0;
    while (off < plen) {
        int w = send(fd, payload + off, plen - off, 0);
        if (w <= 0) {
            close(fd);
            lua_pushnil(L);
            lua_pushfstring(L, "TCP 发送失败: %s", strerror(errno));
            return 2;
        }
        off += (size_t)w;
    }

    /* 读取应答直到对端关闭/超时/达到上限 */
    char *resp = malloc(max_resp);
    size_t used = 0;
    char tmp[512];
    int read_err = 0;
    if (resp == NULL) {
        close(fd);
        lua_pushnil(L);
        lua_pushliteral(L, "内存不足");
        return 2;
    }
    while (used < max_resp) {
        int r = recv(fd, tmp, sizeof(tmp), 0);
        if (r > 0) {
            size_t n = (size_t)r;
            if (used + n > max_resp) {
                n = max_resp - used;
            }
            memcpy(resp + used, tmp, n);
            used += n;
            if (n < (size_t)r) {
                break;   /* 已达上限，剩余丢弃 */
            }
        } else if (r == 0) {
            break;   /* 对端关闭 */
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;   /* 空闲超时 */
            }
            read_err = 1;
            break;
        }
    }
    close(fd);

    if (read_err) {
        free(resp);
        lua_pushnil(L);
        lua_pushfstring(L, "TCP 读取失败: %s", strerror(errno));
        return 2;
    }
    lua_pushlstring(L, resp, used);
    free(resp);
    return 1;
}


/* ================ LuaSocket 兼容模块: socket / socket.http ================
 * LuaSocket 风格的脚本(客户端/服务端/select)无需 luarocks 即可在固件运行。
 *   socket.tcp()/socket.bind()/socket.connect()/socket.select()/gettime()/sleep()
 *   tcp: bind/listen/accept/send/receive/settimeout/setoption/
 *        getpeername/getsockname/close
 *   socket.http.request()
 * 内部采用非阻塞 fd + select 驱动：timeout=-1 无限阻塞；timeout=0 非阻塞；
 * timeout>0 有界等待；超时错误字符串为 "timeout"。
 */

#define SOCKET_MT "gyscan.socket.tcp"

static int lua_socket_udp(lua_State *L);
static int lua_udp_setup_mt(lua_State *L);
static int luaopen_socket_dns(lua_State *L);
static int luaopen_mime(lua_State *L);

typedef struct {
    int    fd;         /* -1 = 已关闭 */
    double timeout;    /* 秒; -1=无限(阻塞), 0=非阻塞, >0=有界 */
} tcp_obj_t;

static tcp_obj_t *tcp_check(lua_State *L, int idx)
{
    return (tcp_obj_t *)luaL_checkudata(L, idx, SOCKET_MT);
}

static void tcp_set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void tcp_close_fd(tcp_obj_t *o)
{
    if (o->fd >= 0) {
        close(o->fd);
        o->fd = -1;
    }
}

/* 构造 TCP userdata(自动置非阻塞) */
static int tcp_new_userdata(lua_State *L, int fd, double timeout)
{
    tcp_obj_t *o = (tcp_obj_t *)lua_newuserdatauv(L, sizeof(tcp_obj_t), 0);
    o->fd = fd;
    o->timeout = timeout;
    luaL_setmetatable(L, SOCKET_MT);
    if (fd >= 0) {
        tcp_set_nonblock(fd);
    }
    return 1;
}

/* select 等待可读(rw=0)/可写(rw=1)。返回 1=就绪 0=超时 -1=出错 */
static int fd_wait_io(int fd, double timeout, int rw)
{
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    struct timeval tv;
    struct timeval *tvp = NULL;
    if (timeout >= 0) {
        tv.tv_sec = (long)timeout;
        tv.tv_usec = (suseconds_t)((timeout - (long)timeout) * 1000000.0);
        tvp = &tv;
    }
    int rc = select(fd + 1, (rw == 0) ? &fds : NULL,
                    (rw == 1) ? &fds : NULL, NULL, tvp);
    if (rc == 0) {
        return 0;
    }
    if (rc < 0) {
        return -1;
    }
    return 1;
}

static int tcp_wait_io(tcp_obj_t *o, int rw)
{
    return fd_wait_io(o->fd, o->timeout, rw);
}

static int lua_socket_gettime(lua_State *L)
{
    lua_pushnumber(L, (lua_Number)(esp_timer_get_time() / 1000000.0));
    return 1;
}

static int lua_socket_sleep(lua_State *L)
{
    double sec = luaL_optnumber(L, 1, 0);
    if (sec > 0) {
        vTaskDelay(pdMS_TO_TICKS((TickType_t)(sec * 1000.0)));
    }
    return 0;
}

/* 主机名(或 "*"=任意地址)解析 */
static int resolve_addr(const char *host_in, uint16_t port, struct sockaddr_in *out)
{
    memset(out, 0, sizeof(*out));
    out->sin_family = AF_INET;
    out->sin_port = htons(port);
    if (host_in == NULL || host_in[0] == '\0' || strcmp(host_in, "*") == 0) {
        out->sin_addr.s_addr = htonl(INADDR_ANY);
        return 0;
    }
    char hostbuf[128];
    const char *host = sanitize_host(host_in, hostbuf, sizeof(hostbuf));
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || res == NULL) {
        return -1;
    }
    memcpy(&out->sin_addr, &((struct sockaddr_in *)res->ai_addr)->sin_addr,
           sizeof(out->sin_addr));
    freeaddrinfo(res);
    return 0;
}

/* 带超时的非阻塞 connect。返回0成功; err 填错误文本(超时为 "timeout") */
static int tcp_connect_with_timeout(int fd, const struct sockaddr_in *sa,
                                    double sec, char *err, size_t err_sz)
{
    tcp_set_nonblock(fd);
    int rc = connect(fd, (const struct sockaddr *)sa, sizeof(*sa));
    if (rc == 0) {
        return 0;
    }
    if (errno != EINPROGRESS && errno != EWOULDBLOCK && errno != EALREADY) {
        snprintf(err, err_sz, "%s", strerror(errno));
        return -1;
    }
    double tw = (sec >= 0) ? sec : 10.0;
    fd_set wf;
    FD_ZERO(&wf);
    FD_SET(fd, &wf);
    struct timeval tv;
    struct timeval *tvp = NULL;
    if (tw >= 0) {
        tv.tv_sec = (long)tw;
        tv.tv_usec = (suseconds_t)((tw - (long)tw) * 1000000.0);
        tvp = &tv;
    }
    rc = select(fd + 1, NULL, &wf, NULL, tvp);
    if (rc == 0) {
        snprintf(err, err_sz, "timeout");
        return -1;
    }
    if (rc < 0) {
        snprintf(err, err_sz, "%s", strerror(errno));
        return -1;
    }
    int soerr = 0;
    socklen_t sl = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0) {
        snprintf(err, err_sz, "%s", strerror((soerr != 0) ? soerr : errno));
        return -1;
    }
    return 0;
}

static int lua_socket_tcp(lua_State *L)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "socket 创建失败: %s", strerror(errno));
        return 2;
    }
    return tcp_new_userdata(L, fd, -1.0);
}

static int lua_socket_tcp_close(lua_State *L)
{
    tcp_obj_t *o = tcp_check(L, 1);
    tcp_close_fd(o);
    return 0;
}

static int lua_socket_tcp_settimeout(lua_State *L)
{
    tcp_obj_t *o = tcp_check(L, 1);
    if (lua_isnoneornil(L, 2)) {
        o->timeout = -1.0;   /* 不限时(阻塞) */
    } else {
        double t = (double)luaL_checknumber(L, 2);
        o->timeout = (t < 0) ? -1.0 : t;
    }
    lua_pushinteger(L, 1);
    return 1;
}

static int lua_socket_tcp_connect(lua_State *L)
{
    tcp_obj_t *o = tcp_check(L, 1);
    const char *host = luaL_checkstring(L, 2);
    int port = (int)luaL_checkinteger(L, 3);
    if (o->fd < 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "socket closed");
        return 2;
    }
    struct sockaddr_in sa;
    if (resolve_addr(host, (uint16_t)port, &sa) != 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "DNS 解析失败: %s", host);
        return 2;
    }
    char err[160] = {0};
    if (tcp_connect_with_timeout(o->fd, &sa, o->timeout, err, sizeof(err)) != 0) {
        tcp_close_fd(o);
        lua_pushnil(L);
        lua_pushstring(L, err);
        return 2;
    }
    lua_pushinteger(L, 1);
    return 1;
}

/* socket.bind(host, port[, backlog]) -> server(已 listen) */
static int do_tcp_bind(int *out_fd, const char *host, int port, int backlog,
                       char *err, size_t err_sz)
{
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        snprintf(err, err_sz, "%s", strerror(errno));
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    if (resolve_addr(host, (uint16_t)port, &sa) != 0) {
        snprintf(err, err_sz, "DNS 解析失败: %s", host ? host : "*");
        close(fd);
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        snprintf(err, err_sz, "bind 失败: %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, backlog) != 0) {
        snprintf(err, err_sz, "listen 失败: %s", strerror(errno));
        close(fd);
        return -1;
    }
    *out_fd = fd;
    return 0;
}

static int lua_socket_bind(lua_State *L)
{
    const char *host = luaL_optstring(L, 1, "*");
    int port = (int)luaL_checkinteger(L, 2);
    int backlog = (int)luaL_optinteger(L, 3, 32);
    int fd = -1;
    char err[192] = {0};
    if (do_tcp_bind(&fd, host, port, backlog, err, sizeof(err)) != 0) {
        lua_pushnil(L);
        lua_pushstring(L, err);
        return 2;
    }
    return tcp_new_userdata(L, fd, -1.0);
}

/* server:accept() -> client | nil, err(timeout 表示暂无连接) */
static int lua_socket_tcp_accept(lua_State *L)
{
    tcp_obj_t *o = tcp_check(L, 1);
    if (o->fd < 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "socket closed");
        return 2;
    }
    /* 非阻塞下等新连接；阻塞下等 timeout 或无限 */
    int wr = tcp_wait_io(o, 0);
    if (wr == 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "timeout");
        return 2;
    }
    if (wr < 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "%s", strerror(errno));
        return 2;
    }
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    int cfd = accept(o->fd, (struct sockaddr *)&sa, &sl);
    if (cfd < 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "%s",
                        (errno == EAGAIN || errno == EWOULDBLOCK)
                            ? "timeout" : strerror(errno));
        return 2;
    }
    return tcp_new_userdata(L, cfd, o->timeout);   /* 客户端继承服务端超时 */
}

/* tcp:bind(host, port) -> 1 ; 需再 listen() */
static int lua_socket_tcp_bind(lua_State *L)
{
    tcp_obj_t *o = tcp_check(L, 1);
    const char *host = luaL_optstring(L, 2, "*");
    int port = (int)luaL_checkinteger(L, 3);
    if (o->fd < 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "socket closed");
        return 2;
    }
    int one = 1;
    setsockopt(o->fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    if (resolve_addr(host, (uint16_t)port, &sa) != 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "DNS 解析失败: %s", host);
        return 2;
    }
    if (bind(o->fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "bind 失败: %s", strerror(errno));
        return 2;
    }
    lua_pushinteger(L, 1);
    return 1;
}

static int lua_socket_tcp_listen(lua_State *L)
{
    tcp_obj_t *o = tcp_check(L, 1);
    int backlog = (int)luaL_optinteger(L, 2, 32);
    if (o->fd < 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "socket closed");
        return 2;
    }
    if (listen(o->fd, backlog) != 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "listen 失败: %s", strerror(errno));
        return 2;
    }
    lua_pushinteger(L, 1);
    return 1;
}

static int sock_addr_name(lua_State *L, int which)
{
    tcp_obj_t *o = tcp_check(L, 1);
    if (o->fd < 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "socket closed");
        return 2;
    }
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    int rc = (which == 0) ? getpeername(o->fd, (struct sockaddr *)&sa, &sl)
                          : getsockname(o->fd, (struct sockaddr *)&sa, &sl);
    if (rc != 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "%s", strerror(errno));
        return 2;
    }
    char *ip = inet_ntoa(sa.sin_addr);
    lua_pushstring(L, (ip != NULL) ? ip : "0.0.0.0");
    lua_pushinteger(L, ntohs(sa.sin_port));
    return 2;
}

static int lua_socket_tcp_getpeername(lua_State *L) { return sock_addr_name(L, 0); }
static int lua_socket_tcp_getsockname(lua_State *L) { return sock_addr_name(L, 1); }

static int lua_socket_tcp_setoption(lua_State *L)
{
    tcp_obj_t *o = tcp_check(L, 1);
    const char *name = luaL_checkstring(L, 2);
    if (o->fd < 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "socket closed");
        return 2;
    }
    int opt = 0;
    int level = 0;
    const char *val = NULL;
    if (strcmp(name, "tcp-nodelay") == 0) {
        opt = TCP_NODELAY;
        level = IPPROTO_TCP;
        val = luaL_optstring(L, 3, "true");
    } else if (strcmp(name, "keepalive") == 0) {
        opt = SO_KEEPALIVE;
        level = SOL_SOCKET;
        val = luaL_optstring(L, 3, "true");
    } else if (strcmp(name, "reuseaddr") == 0) {
        opt = SO_REUSEADDR;
        level = SOL_SOCKET;
        val = luaL_optstring(L, 3, "true");
    } else {
        lua_pushnil(L);
        lua_pushliteral(L, "unsupported option");
        return 2;
    }
    int on = (strcmp(val, "false") == 0 || strcmp(val, "0") == 0) ? 0 : 1;
    if (setsockopt(o->fd, level, opt, &on, sizeof(on)) != 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "setoption 失败: %s", strerror(errno));
        return 2;
    }
    lua_pushinteger(L, 1);
    return 1;
}

/* sock:send(data[, i[, j]]) -> j | nil, err */
static int lua_socket_tcp_send(lua_State *L)
{
    tcp_obj_t *o = tcp_check(L, 1);
    size_t dlen = 0;
    const char *data = luaL_checklstring(L, 2, &dlen);
    if (o->fd < 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "socket closed");
        return 2;
    }
    lua_Integer i = luaL_optinteger(L, 3, 1);
    lua_Integer j = luaL_optinteger(L, 4, (lua_Integer)dlen);
    if (i < 1) i = 1;
    if (j > (lua_Integer)dlen) j = (lua_Integer)dlen;
    if (i > j) {
        lua_pushinteger(L, i - 1);
        return 1;
    }
    const char *p = data + (size_t)(i - 1);
    size_t left = (size_t)(j - i + 1);
    while (left > 0) {
        int wr = tcp_wait_io(o, 1);
        if (wr <= 0) {
            lua_pushnil(L);
            lua_pushstring(L, (wr == 0) ? "timeout" : strerror(errno));
            return 2;
        }
        int w = send(o->fd, p, left, 0);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            lua_pushnil(L);
            lua_pushfstring(L, "%s", strerror(errno));
            return 2;
        }
        if (w == 0) {
            continue;
        }
        p += (size_t)w;
        left -= (size_t)w;
    }
    lua_pushinteger(L, j);
    return 1;
}

/* sock:receive([pattern]) -> data | nil, err
 * pattern: "*l"(默认)一行 / "*a"到关闭 / 数字=精确字节 */
static int lua_socket_tcp_receive(lua_State *L)
{
    tcp_obj_t *o = tcp_check(L, 1);
    if (o->fd < 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "socket closed");
        return 2;
    }
    int mode = 0;   /* 0=*l 1=*a 2=count */
    size_t want = 0;
    if (lua_isnumber(L, 2)) {
        mode = 2;
        lua_Integer n = luaL_checkinteger(L, 2);
        want = (n > 0) ? (size_t)n : 0;
    } else if (!lua_isnoneornil(L, 2)) {
        size_t pl = 0;
        const char *pat = luaL_checklstring(L, 2, &pl);
        if (pl >= 2 && pat[0] == '*' && pat[1] == 'a') {
            mode = 1;
        }
    }

    net_body_t b = net_body_new();
    if (b.buf == NULL) {
        lua_pushnil(L);
        lua_pushliteral(L, "内存不足");
        return 2;
    }
    int err_kind = 0;   /* 1=timeout 2=closed 3=other */
    char errbuf[160] = {0};

    while (1) {
        if (mode == 2 && b.used >= want) {
            break;
        }
        if (mode == 0 && b.used > 0 && b.buf[b.used - 1] == '\n') {
            break;
        }
        /* 需要更多数据前等待可读 */
        int wr = tcp_wait_io(o, 0);
        if (wr <= 0) {
            err_kind = (wr == 0) ? 1 : 3;
            if (wr < 0) snprintf(errbuf, sizeof(errbuf), "%s", strerror(errno));
            break;
        }
        /* 读入一块(尽量多, 行模式至多读到含换行为止) */
        int need = (mode == 2) ? (int)(want - b.used) : 512;
        if (b.used + (size_t)need > b.cap) {
            size_t nc = b.used + (size_t)need;
            if (nc > LUA_NET_MAX_BODY) nc = LUA_NET_MAX_BODY;
            if (nc > b.cap) {
                char *nb = realloc(b.buf, nc);
                if (nb == NULL) {
                    free(b.buf);
                    lua_pushnil(L);
                    lua_pushliteral(L, "内存不足");
                    return 2;
                }
                b.buf = nb;
                b.cap = nc;
            }
        }
        int r = recv(o->fd, b.buf + b.used, b.cap - b.used, 0);
        if (r > 0) {
            b.used += (size_t)r;
            if (mode == 0) {
                /* 若缓冲中已有换行, 只保留到该行为止 */
                for (size_t k = b.used > 0 ? b.used - (size_t)r : 0;
                     k < b.used; k++) {
                    if (b.buf[k] == '\n') {
                        b.used = k + 1;
                        break;
                    }
                }
            }
            continue;
        }
        if (r == 0) {
            err_kind = 2;
            break;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            err_kind = 1;
        } else {
            err_kind = 3;
            snprintf(errbuf, sizeof(errbuf), "%s", strerror(errno));
        }
        break;
    }

    if (mode == 0 && b.used > 0 && b.buf[b.used - 1] == '\n') {
        /* 去掉行尾 \n 及可选 \r */
        if (b.used >= 1) b.used--;
        if (b.used > 0 && b.buf[b.used - 1] == '\r') b.used--;
        lua_pushlstring(L, b.buf, b.used);
        free(b.buf);
        return 1;
    }
    if (b.used > 0) {
        /* 已收到部分数据(非阻塞/超时/EOF 前的残余) */
        lua_pushlstring(L, b.buf, b.used);
        free(b.buf);
        return 1;
    }
    free(b.buf);
    lua_pushnil(L);
    if (err_kind == 1) {
        lua_pushliteral(L, "timeout");
    } else if (err_kind == 2) {
        lua_pushliteral(L, "closed");
    } else if (err_kind == 3) {
        lua_pushstring(L, errbuf);
    } else {
        lua_pushliteral(L, "unknown");
    }
    return 2;
}

/* socket.connect(host, port[, timeout]) -> sock | nil, err */
static int lua_socket_connect(lua_State *L)
{
    const char *host = luaL_checkstring(L, 1);
    int port = (int)luaL_checkinteger(L, 2);
    double tmo = luaL_optnumber(L, 3, 10.0);
    struct sockaddr_in sa;
    if (resolve_addr(host, (uint16_t)port, &sa) != 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "DNS 解析失败: %s", host);
        return 2;
    }
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "socket 创建失败: %s", strerror(errno));
        return 2;
    }
    char err[160] = {0};
    if (tcp_connect_with_timeout(fd, &sa, tmo, err, sizeof(err)) != 0) {
        close(fd);
        lua_pushnil(L);
        lua_pushstring(L, err);
        return 2;
    }
    return tcp_new_userdata(L, fd, tmo);
}

/* socket.select(readt, writet[, timeout]) -> ready_read, ready_write */
static int lua_socket_select(lua_State *L)
{
    fd_set rf, wf;
    FD_ZERO(&rf);
    FD_ZERO(&wf);
    int rtab = (lua_type(L, 1) == LUA_TTABLE) ? 1 : -1;
    int wtab = (lua_type(L, 2) == LUA_TTABLE) ? 1 : -1;
    int maxfd = -1;
    int rcnt = 0, wcnt = 0;
    static int rfd[64], wfd[64], rkey[64], wkey[64];

    if (rtab == 1) {
        size_t n = lua_rawlen(L, 1);
        for (size_t k = 1; k <= n && rcnt < 64; k++) {
            lua_rawgeti(L, 1, (lua_Integer)k);
            if (luaL_testudata(L, -1, SOCKET_MT) != NULL) {
                tcp_obj_t *o = (tcp_obj_t *)lua_touserdata(L, -1);
                if (o->fd >= 0) {
                    rfd[rcnt] = o->fd;
                    rkey[rcnt] = (int)k;
                    rcnt++;
                    FD_SET(o->fd, &rf);
                    if (o->fd > maxfd) maxfd = o->fd;
                }
            }
            lua_pop(L, 1);
        }
    }
    if (wtab == 1) {
        size_t n = lua_rawlen(L, 2);
        for (size_t k = 1; k <= n && wcnt < 64; k++) {
            lua_rawgeti(L, 2, (lua_Integer)k);
            if (luaL_testudata(L, -1, SOCKET_MT) != NULL) {
                tcp_obj_t *o = (tcp_obj_t *)lua_touserdata(L, -1);
                if (o->fd >= 0) {
                    wfd[wcnt] = o->fd;
                    wkey[wcnt] = (int)k;
                    wcnt++;
                    FD_SET(o->fd, &wf);
                    if (o->fd > maxfd) maxfd = o->fd;
                }
            }
            lua_pop(L, 1);
        }
    }
    if (maxfd < 0) {
        lua_newtable(L);
        lua_newtable(L);
        return 2;
    }

    struct timeval tv;
    struct timeval *tvp = NULL;
    if (!lua_isnoneornil(L, 3)) {
        double t = (double)luaL_checknumber(L, 3);
        if (t < 0) t = 0;
        tv.tv_sec = (long)t;
        tv.tv_usec = (suseconds_t)((t - (long)t) * 1000000.0);
        tvp = &tv;
    }
    int rc = select(maxfd + 1, (rtab == 1) ? &rf : NULL,
                    (wtab == 1) ? &wf : NULL, NULL, tvp);
    if (rc < 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "select 失败: %s", strerror(errno));
        return 1;
    }
    lua_newtable(L);   /* ready_read */
    lua_newtable(L);   /* ready_write */
    int outi = 0;
    if (rc > 0) {
        if (rtab == 1) {
            for (int k = 0; k < rcnt; k++) {
                if (FD_ISSET(rfd[k], &rf)) {
                    lua_rawgeti(L, 1, rkey[k]);
                    outi++;
                    lua_rawseti(L, -3, outi);   /* 加入 ready_read */
                }
            }
        }
        int outw = 0;
        if (wtab == 1) {
            for (int k = 0; k < wcnt; k++) {
                if (FD_ISSET(wfd[k], &wf)) {
                    lua_rawgeti(L, 2, wkey[k]);
                    outw++;
                    lua_rawseti(L, -2, outw);   /* 加入 ready_write */
                }
            }
        }
    }
    return 2;
}

static int tcp_obj_gc(lua_State *L)
{
    tcp_obj_t *o = (tcp_obj_t *)luaL_checkudata(L, 1, SOCKET_MT);
    tcp_close_fd(o);
    return 0;
}

static const luaL_Reg tcp_methods[] = {
    { "bind",        lua_socket_tcp_bind },
    { "listen",      lua_socket_tcp_listen },
    { "accept",      lua_socket_tcp_accept },
    { "connect",     lua_socket_tcp_connect },
    { "send",        lua_socket_tcp_send },
    { "receive",     lua_socket_tcp_receive },
    { "settimeout",  lua_socket_tcp_settimeout },
    { "setoption",   lua_socket_tcp_setoption },
    { "getpeername", lua_socket_tcp_getpeername },
    { "getsockname", lua_socket_tcp_getsockname },
    { "close",       lua_socket_tcp_close },
    { NULL, NULL },
};

static int luaopen_socket(lua_State *L)
{
    luaL_newmetatable(L, SOCKET_MT);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, tcp_methods, 0);
    lua_pushcfunction(L, tcp_obj_gc);
    lua_setfield(L, -2, "__gc");
    lua_pop(L, 1);

    static const luaL_Reg sf[] = {
        { "tcp",     lua_socket_tcp },
        { "bind",    lua_socket_bind },
        { "connect", lua_socket_connect },
        { "select",  lua_socket_select },
        { "gettime", lua_socket_gettime },
        { "sleep",   lua_socket_sleep },
        { NULL, NULL },
    };
    luaL_newlib(L, sf);
    lua_pushcfunction(L, lua_socket_udp);
    lua_setfield(L, -2, "udp");
    return 1;
}

/* socket.http.request(url[, body]) -> body, code, headers | nil, err */
static int lua_socket_http_request(lua_State *L)
{
    int has_body = lua_type(L, 2) == LUA_TSTRING;
    if (has_body) {
        lua_net_http_post(L);
    } else {
        lua_net_http_get(L);
    }
    if (lua_isnil(L, -2)) {
        return 2;   /* nil, err */
    }
    int status = (int)lua_tointeger(L, -2);
    size_t blen = 0;
    const char *body = lua_tolstring(L, -1, &blen);
    lua_pop(L, 2);
    lua_pushlstring(L, body, blen);
    lua_pushinteger(L, status);
    lua_newtable(L);
    return 3;
}

static int luaopen_socket_http(lua_State *L)
{
    static const luaL_Reg hf[] = {
        { "request", lua_socket_http_request },
        { NULL, NULL },
    };
    luaL_newlib(L, hf);
    return 1;
}

static int strcasecmp_impl(const char *a, const char *b)
{
    while (*a && *b) {
        unsigned char ca = (unsigned char)*a, cb = (unsigned char)*b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 1;
        a++;
        b++;
    }
    return (*a == *b) ? 0 : 1;
}

/* ================ LuaOpenSSL 兼容: openssl.x509 (基于 mbedTLS) ================ */

#define X509_MT "gyscan.openssl.x509"

typedef struct {
    mbedtls_x509_crt crt;
    int              parsed;
} x509_obj_t;

static x509_obj_t *x509_check(lua_State *L, int idx)
{
    return (x509_obj_t *)luaL_checkudata(L, idx, X509_MT);
}

/* mbedtls 时间(UTC) -> unix 秒 */
static lua_Integer x509_epoch(const mbedtls_x509_time *t)
{
    int y = t->year, m = t->mon, d = t->day;
    long long yy = y - (m <= 2 ? 1 : 0);
    long long era = (yy >= 0 ? yy : yy - 399) / 400;
    long long yoe = yy - era * 400;
    long long doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    long long doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    long long days = era * 146097 + doe - 719468;
    long long secs = days * 86400 + t->hour * 3600 + t->min * 60 + t->sec;
    return (lua_Integer)secs;
}

static int x509_dn_push(lua_State *L, const mbedtls_x509_name *dn)
{
    char buf[512];
    int n = mbedtls_x509_dn_gets(buf, sizeof(buf), dn);
    if (n < 0) {
        lua_pushnil(L);
        lua_pushliteral(L, "DN 解析失败");
        return 2;
    }
    if (n >= (int)sizeof(buf)) {
        buf[sizeof(buf) - 4] = '.';
        buf[sizeof(buf) - 3] = '.';
        buf[sizeof(buf) - 2] = '.';
        buf[sizeof(buf) - 1] = '\0';
    }
    lua_pushstring(L, buf);
    return 1;
}

static int x509_subject(lua_State *L)
{
    x509_obj_t *o = x509_check(L, 1);
    return x509_dn_push(L, &o->crt.subject);
}

static int x509_issuer(lua_State *L)
{
    x509_obj_t *o = x509_check(L, 1);
    return x509_dn_push(L, &o->crt.issuer);
}

static int x509_not_before(lua_State *L)
{
    x509_obj_t *o = x509_check(L, 1);
    lua_pushinteger(L, x509_epoch(&o->crt.valid_from));
    return 1;
}

static int x509_not_after(lua_State *L)
{
    x509_obj_t *o = x509_check(L, 1);
    lua_pushinteger(L, x509_epoch(&o->crt.valid_to));
    return 1;
}

/* 通配匹配: pattern 可为 example.com 或 *.example.com */
static int host_wild_match(const char *host, const char *pattern)
{
    if (pattern[0] == '*' && pattern[1] == '.') {
        const char *dot = strchr(host, '.');
        if (dot == NULL) return 0;
        return strcasecmp_impl(dot + 1, pattern + 2) == 0;
    }
    return strcasecmp_impl(host, pattern) == 0;
}

static int x509_checkhost(lua_State *L)
{
    x509_obj_t *o = x509_check(L, 1);
    const char *host = luaL_checkstring(L, 2);
    int found = 0;
    const mbedtls_x509_sequence *san = &o->crt.subject_alt_names;
    while (san != NULL && !found) {
        mbedtls_x509_subject_alternative_name node;
        if (mbedtls_x509_parse_subject_alt_name(&san->buf, &node) == 0) {
            if (node.type == MBEDTLS_X509_SAN_DNS_NAME) {
                const mbedtls_x509_buf *nb = &node.san.unstructured_name;
                char dn[256];
                size_t ln = (nb->len < sizeof(dn) - 1) ? nb->len : sizeof(dn) - 1;
                memcpy(dn, nb->p, ln);
                dn[ln] = '\0';
                if (host_wild_match(host, dn)) {
                    found = 1;
                }
            }
        }
        san = san->next;
    }
    lua_pushboolean(L, found);
    return 1;
}

static int x509_obj_gc(lua_State *L)
{
    x509_obj_t *o = (x509_obj_t *)luaL_checkudata(L, 1, X509_MT);
    if (o->parsed) {
        mbedtls_x509_crt_free(&o->crt);
        o->parsed = 0;
    }
    return 0;
}

static int x509_tostring(lua_State *L)
{
    x509_obj_t *o = x509_check(L, 1);
    char buf[300];
    mbedtls_x509_dn_gets(buf, sizeof(buf) - 16, &o->crt.subject);
    lua_pushfstring(L, "x509 certificate: %s", buf);
    return 1;
}

static const luaL_Reg x509_methods[] = {
    { "subject",   x509_subject },
    { "issuer",    x509_issuer },
    { "notBefore", x509_not_before },
    { "notAfter",  x509_not_after },
    { "checkhost", x509_checkhost },
    { NULL, NULL },
};

/* 简易 base64(PEM 块) → 二进制；返回解码长度(<=cap)，失败 -1 */
static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static int b64_decode(const char *in, size_t inlen, unsigned char *out, size_t cap)
{
    unsigned int buf = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < inlen; i++) {
        char c = in[i];
        if (c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t') {
            continue;   /* 忽略换行/空白与填充 */
        }
        int v = b64_val(c);
        if (v < 0) {
            return -1;
        }
        buf = (buf << 6) | (unsigned int)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o < cap) {
                out[o++] = (unsigned char)((buf >> bits) & 0xFF);
            }
            if (bits >= 8) {
                bits = 0;   /* 防御：正常流式解码不会走到 */
            }
        }
    }
    return (int)o;
}

/* openssl.x509.read(pem) -> cert | nil, err
 * mbedtls 库的 PEM 读取在当前固件配置下不可用，这里先做 PEM→DER 解码，
 * 再走已验证可用的 DER 解析路径；直接传 DER 字节串也可。 */
static int x509_read(lua_State *L)
{
    size_t len = 0;
    const char *data = luaL_checklstring(L, 1, &len);
    if (len == 0 || len > 100 * 1024) {
        lua_pushnil(L);
        lua_pushliteral(L, "证书内容为空或过大");
        return 2;
    }

    x509_obj_t *o = (x509_obj_t *)lua_newuserdatauv(L, sizeof(x509_obj_t), 0);
    memset(&o->crt, 0, sizeof(o->crt));
    o->parsed = 0;
    luaL_setmetatable(L, X509_MT);
    mbedtls_x509_crt_init(&o->crt);

    unsigned char *der = NULL;
    size_t derlen = 0;
    int rc;

    if (len >= 11 && memcmp(data, "-----BEGIN", 10) == 0) {
        /* PEM: 从 BEGIN 行之后取 base64 主体，止于 END 标记 */
        const char *body = memchr(data, '\n', len);
        const char *end = data + len;
        if (body == NULL) {
            mbedtls_x509_crt_free(&o->crt);
            lua_pushnil(L);
            lua_pushliteral(L, "PEM 格式错误");
            return 2;
        }
        body++;
        const char *tail = body;
        while (tail + 8 <= end && strncmp(tail, "-----END", 8) != 0) {
            tail++;
        }
        size_t b64len = (size_t)(tail - body);
        der = malloc(b64len / 4 * 3 + 4);
        if (der == NULL) {
            mbedtls_x509_crt_free(&o->crt);
            lua_pushnil(L);
            lua_pushliteral(L, "内存不足");
            return 2;
        }
        int n = b64_decode(body, b64len, der, b64len);
        if (n <= 0) {
            free(der);
            mbedtls_x509_crt_free(&o->crt);
            lua_pushnil(L);
            lua_pushliteral(L, "PEM base64 解码失败");
            return 2;
        }
        derlen = (size_t)n;
        rc = mbedtls_x509_crt_parse(&o->crt, der, derlen);
        free(der);
    } else {
        /* 已是 DER 原始字节 */
        rc = mbedtls_x509_crt_parse(&o->crt, (const unsigned char *)data, len);
    }

    if (rc != 0) {
        mbedtls_x509_crt_free(&o->crt);
        lua_pushnil(L);
        lua_pushfstring(L, "证书解析失败 (mbedtls error %d), 请确认 PEM/DER 格式",
                        (int)-rc);
        return 2;
    }
    o->parsed = 1;
    return 1;
}

static int openssl_version(lua_State *L)
{
    lua_pushstring(L, "mbedtls (esp-idf)");
    return 1;
}
/* 读取固件嵌入的证书（无需文件系统，编译时固化） */
static int x509_read_embedded(lua_State *L)
{
    const char *name = luaL_optstring(L, 1, "server.crt");
    const char *start = NULL;
    size_t len = 0;

    if (strcmp(name, "server.crt") == 0) {
        extern const char _binary_server_crt_start[] asm("_binary_server_crt_start");
        extern const char _binary_server_crt_end[] asm("_binary_server_crt_end");
        start = _binary_server_crt_start;
        len = (size_t)(_binary_server_crt_end - _binary_server_crt_start);
    } else if (strcmp(name, "server.key") == 0) {
        extern const char _binary_server_key_start[] asm("_binary_server_key_start");
        extern const char _binary_server_key_end[] asm("_binary_server_key_end");
        start = _binary_server_key_start;
        len = (size_t)(_binary_server_key_end - _binary_server_key_start);
    } else {
        lua_pushnil(L);
        lua_pushfstring(L, "unknown embedded cert: %s (available: server.crt, server.key)", name);
        return 2;
    }

    /* 复用 x509_read 的 DER/PEM 解析路径 */
    lua_settop(L, 0);
    lua_pushlstring(L, start, len);
    return x509_read(L);
}

static int luaopen_openssl(lua_State *L)
{
    luaL_newmetatable(L, X509_MT);
    lua_pushvalue(L, -1);
    lua_setfield(L, -2, "__index");
    luaL_setfuncs(L, x509_methods, 0);
    lua_pushcfunction(L, x509_obj_gc);
    lua_setfield(L, -2, "__gc");
    lua_pushcfunction(L, x509_tostring);
    lua_setfield(L, -2, "__tostring");
    lua_pop(L, 1);

    static const luaL_Reg xf[] = {
        { "version", openssl_version },
        { NULL, NULL },
    };
    static const luaL_Reg xs[] = {
        { "read", x509_read },
        { "read_embedded", x509_read_embedded },
        { NULL, NULL },
    };
    luaL_newlib(L, xf);
    luaL_newlib(L, xs);
    lua_setfield(L, -2, "x509");
    return 1;
}



/* ================ UDP (socket.udp) + socket.dns + mime(base64) ================ */

#define UDP_MT "gyscan.socket.udp"

typedef struct {
    int fd;
    double timeout;
    int connected;                 /* 已 connect 到对端 */
    struct sockaddr_in peer;
} udp_obj_t;

static udp_obj_t *udp_check(lua_State *L, int idx)
{
    return (udp_obj_t *)luaL_checkudata(L, idx, UDP_MT);
}

static int udp_new_userdata(lua_State *L, int fd)
{
    udp_obj_t *o = (udp_obj_t *)lua_newuserdatauv(L, sizeof(udp_obj_t), 0);
    o->fd = fd;
    o->timeout = -1.0;
    o->connected = 0;
    memset(&o->peer, 0, sizeof(o->peer));
    luaL_setmetatable(L, UDP_MT);
    if (fd >= 0) tcp_set_nonblock(fd);
    return 1;
}

static int lua_socket_udp(lua_State *L)
{
    lua_udp_setup_mt(L);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        lua_pushnil(L);
        lua_pushfstring(L, "udp 创建失败: %s", strerror(errno));
        return 2;
    }
    return udp_new_userdata(L, fd);
}

static int lua_udp_settimeout(lua_State *L)
{
    udp_obj_t *o = udp_check(L, 1);
    if (lua_isnoneornil(L, 2)) o->timeout = -1.0;
    else o->timeout = (luaL_checknumber(L, 2) < 0) ? -1.0
                                                   : (double)lua_tonumber(L, 2);
    lua_pushinteger(L, 1);
    return 1;
}

static int lua_udp_close(lua_State *L)
{
    udp_obj_t *o = udp_check(L, 1);
    if (o->fd >= 0) close(o->fd);
    o->fd = -1;
    return 0;
}

static int udp_gc(lua_State *L)
{
    udp_obj_t *o = udp_check(L, 1);
    if (o->fd >= 0) close(o->fd);
    o->fd = -1;
    return 0;
}

/* udp:connect(host, port) / :setpeername() */
static int lua_udp_connect(lua_State *L)
{
    udp_obj_t *o = udp_check(L, 1);
    const char *host = luaL_checkstring(L, 2);
    int port = (int)luaL_checkinteger(L, 3);
    if (o->fd < 0) {
        lua_pushnil(L); lua_pushliteral(L, "socket closed"); return 2;
    }
    if (resolve_addr(host, (uint16_t)port, &o->peer) != 0) {
        lua_pushnil(L); lua_pushfstring(L, "DNS 解析失败: %s", host); return 2;
    }
    o->connected = 1;
    lua_pushinteger(L, 1);
    return 1;
}

static int udp_send_common(lua_State *L, const struct sockaddr_in *to,
                           int need_connected)
{
    udp_obj_t *o = udp_check(L, 1);
    size_t len = 0;
    const char *data = luaL_checklstring(L, 2, &len);
    if (o->fd < 0 || (need_connected && !o->connected)) {
        lua_pushnil(L); lua_pushliteral(L, "udp 未连接"); return 2;
    }
    int wr = fd_wait_io(o->fd, o->timeout, 1);
    if (wr <= 0) {
        lua_pushnil(L); lua_pushstring(L, (wr == 0) ? "timeout" : strerror(errno));
        return 2;
    }
    int n = (int)sendto(o->fd, data, len, 0,
                        (const struct sockaddr *)to, sizeof(*to));
    if (n < 0) {
        lua_pushnil(L); lua_pushfstring(L, "udp 发送失败: %s", strerror(errno));
        return 2;
    }
    lua_pushinteger(L, n);
    return 1;
}

static int lua_udp_send(lua_State *L)
{
    udp_obj_t *o = udp_check(L, 1);
    if (!o->connected) {
        lua_pushnil(L); lua_pushliteral(L, "udp 未 connect"); return 2;
    }
    return udp_send_common(L, &o->peer, 1);
}

static int lua_udp_sendto(lua_State *L)
{
    const char *host = luaL_checkstring(L, 3);
    int port = (int)luaL_checkinteger(L, 4);
    struct sockaddr_in sa;
    if (resolve_addr(host, (uint16_t)port, &sa) != 0) {
        lua_pushnil(L); lua_pushfstring(L, "DNS 解析失败: %s", host); return 2;
    }
    return udp_send_common(L, &sa, 0);
}

static int udp_recv_common(lua_State *L, int want_from)
{
    udp_obj_t *o = udp_check(L, 1);
    if (o->fd < 0) {
        lua_pushnil(L); lua_pushliteral(L, "socket closed"); return 2;
    }
    size_t want = (size_t)luaL_optinteger(L, 2, 2048);
    if (want == 0 || want > 65507) want = 65507;
    int rd = fd_wait_io(o->fd, o->timeout, 0);
    if (rd <= 0) {
        lua_pushnil(L); lua_pushstring(L, (rd == 0) ? "timeout" : strerror(errno));
        return 2;
    }
    char *buf = malloc(want);
    if (buf == NULL) {
        lua_pushnil(L); lua_pushliteral(L, "内存不足"); return 2;
    }
    struct sockaddr_in from;
    socklen_t sl = sizeof(from);
    int n = (int)recvfrom(o->fd, buf, want, 0,
                          (struct sockaddr *)&from, &sl);
    if (n < 0) {
        free(buf);
        lua_pushnil(L); lua_pushfstring(L, "udp 接收失败: %s", strerror(errno));
        return 2;
    }
    lua_pushlstring(L, buf, (size_t)n);
    free(buf);
    if (want_from) {
        char *ip = inet_ntoa(from.sin_addr);
        lua_pushstring(L, ip ? ip : "0.0.0.0");
        lua_pushinteger(L, ntohs(from.sin_port));
        return 3;
    }
    return 1;
}

static int lua_udp_receive(lua_State *L)      { return udp_recv_common(L, 0); }
static int lua_udp_receivefrom(lua_State *L)  { return udp_recv_common(L, 1); }

static int udp_getsockname(lua_State *L)
{
    udp_obj_t *o = udp_check(L, 1);
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    if (o->fd < 0 || getsockname(o->fd, (struct sockaddr *)&sa, &sl) != 0) {
        lua_pushnil(L); lua_pushliteral(L, "getsockname 失败"); return 2;
    }
    char *ip = inet_ntoa(sa.sin_addr);
    lua_pushstring(L, ip ? ip : "0.0.0.0");
    lua_pushinteger(L, ntohs(sa.sin_port));
    return 2;
}

static const luaL_Reg udp_methods[] = {
    { "settimeout", lua_udp_settimeout },
    { "close",      lua_udp_close },
    { "connect",    lua_udp_connect },
    { "setpeername",lua_udp_connect },
    { "send",       lua_udp_send },
    { "sendto",     lua_udp_sendto },
    { "receive",    lua_udp_receive },
    { "receivefrom",lua_udp_receivefrom },
    { "getsockname",udp_getsockname },
    { NULL, NULL },
};

static int lua_udp_setup_mt(lua_State *L)
{
    if (luaL_newmetatable(L, UDP_MT)) {
        lua_pushvalue(L, -1);
        lua_setfield(L, -2, "__index");
        luaL_setfuncs(L, udp_methods, 0);
        lua_pushcfunction(L, udp_gc);
        lua_setfield(L, -2, "__gc");
        lua_pop(L, 1);
    }
    return 1;
}

/* ---------------- socket.dns ---------------- */

static int lua_dns_toip(lua_State *L)
{
    char hostbuf[128];
    const char *host = sanitize_host(luaL_checkstring(L, 1), hostbuf,
                                     sizeof(hostbuf));
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, NULL, &hints, &res) != 0 || res == NULL) {
        lua_pushnil(L);
        lua_pushfstring(L, "DNS 解析失败: %s", host);
        return 2;
    }
    struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
    char *ip = inet_ntoa(sa->sin_addr);
    lua_pushstring(L, ip ? ip : "0.0.0.0");
    freeaddrinfo(res);
    return 1;
}

static int luaopen_socket_dns(lua_State *L)
{
    static const luaL_Reg dnsf[] = {
        { "toip", lua_dns_toip },
        { NULL, NULL },
    };
    luaL_newlib(L, dnsf);
    return 1;
}

/* ---------------- mime: base64 编解码 ---------------- */

static const char B64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int lua_mime_b64(lua_State *L)   /* 编码 */
{
    size_t len = 0;
    const unsigned char *in =
        (const unsigned char *)luaL_checklstring(L, 1, &len);
    size_t cap = ((len + 2) / 3) * 4 + 1;
    char *out = malloc(cap);
    if (out == NULL) {
        lua_pushnil(L); lua_pushliteral(L, "内存不足"); return 2;
    }
    size_t o = 0;
    for (size_t i = 0; i < len; i += 3) {
        unsigned int v = in[i] << 16;
        if (i + 1 < len) v |= in[i + 1] << 8;
        if (i + 2 < len) v |= in[i + 2];
        out[o++] = B64_CHARS[(v >> 18) & 63];
        out[o++] = B64_CHARS[(v >> 12) & 63];
        out[o++] = (i + 1 < len) ? B64_CHARS[(v >> 6) & 63] : '=';
        out[o++] = (i + 2 < len) ? B64_CHARS[v & 63] : '=';
    }
    lua_pushlstring(L, out, o);
    free(out);
    return 1;
}

static int lua_mime_unb64(lua_State *L) /* 解码 */
{
    size_t len = 0;
    const char *in = luaL_checklstring(L, 1, &len);
    unsigned char *buf = malloc(len + 1);
    if (buf == NULL) {
        lua_pushnil(L); lua_pushliteral(L, "内存不足"); return 2;
    }
    int n = b64_decode(in, len, buf, len + 1);
    if (n < 0) {
        free(buf);
        lua_pushnil(L); lua_pushliteral(L, "base64 解码失败"); return 2;
    }
    lua_pushlstring(L, (char *)buf, (size_t)n);
    free(buf);
    return 1;
}

static int luaopen_mime(lua_State *L)
{
    static const luaL_Reg mimef[] = {
        { "b64",   lua_mime_b64 },
        { "unb64", lua_mime_unb64 },
        { NULL, NULL },
    };
    luaL_newlib(L, mimef);
    return 1;
}


/* ---------------- 模块注册 ---------------- */

static const luaL_Reg net_funcs[] = {
    { "resolve",   lua_net_resolve },
    { "http_get",  lua_net_http_get },
    { "http_post", lua_net_http_post },
    { "tcp_query", lua_net_tcp_query },
    { NULL, NULL },
};

static int luaopen_net(lua_State *L)
{
    luaL_newlib(L, net_funcs);
    return 1;
}

void gyscan_lua_net_register(lua_State *L)
{
    /* 注册 net */
    luaL_requiref(L, "net", luaopen_net, 1);
    lua_pop(L, 1);

    /* 注册 LuaSocket 兼容 socket + socket.http（附到 socket 表上） */
    luaL_requiref(L, "socket", luaopen_socket, 1);
    luaL_requiref(L, "socket.http", luaopen_socket_http, 1);
    lua_setfield(L, -2, "http");
    lua_pop(L, 1);

    /* 注册 openssl (x509 证书解析, 基于 mbedTLS) */
    luaL_requiref(L, "openssl", luaopen_openssl, 1);
    lua_pop(L, 1);

    /* 注册 socket.dns / mime(base64) */
    luaL_requiref(L, "socket.dns", luaopen_socket_dns, 1);
    lua_pop(L, 1);
    luaL_requiref(L, "mime", luaopen_mime, 1);
    lua_pop(L, 1);

    ESP_LOGI(TAG, "Lua 网络库已注册: net/socket/http/openssl/dns/mime/udp (无需 luarocks)");

    gyscan_lua_pcap_register(L);

    /* 注册 ble (BLE 扫描/配对, NimBLE, 无需 luarocks) */
    gyscan_lua_ble_register(L);
}
