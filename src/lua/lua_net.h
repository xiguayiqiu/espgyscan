/*
 * lua_net.h - 固件内置 Lua 网络模块 (net)
 *
 * 在 Lua 运行时创建时由 init 钩子注册全局 net 表，脚本可直接使用：
 *   net.resolve(host)                         → ip  | nil, err
 *   net.http_get(url[, timeout_ms])           → status, body | nil, err
 *   net.http_post(url, body[, content_type][, timeout_ms])
 *                                            → status, body | nil, err
 *   net.tcp_query(host, port, payload[, max_resp][, timeout_ms])
 *                                            → response(string) | nil, err
 *
 * 全部基于 ESP-IDF 原生组件(lwIP/esp_http_client/esp-tls)实现，
 * 无需任何 luarocks 依赖；HTTPS 走内置 CA 证书包自动校验证书。
 */
#pragma once

#include <stddef.h>

/* lua_State 前置声明（避免本公开头文件依赖 lua 源码 include 路径） */
#ifndef LUA_VERSION_MAJOR
struct lua_State;
typedef struct lua_State lua_State;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 注册全局 net 模块(供 lua_embed_set_init_hook 使用)。 */
void gyscan_lua_net_register(lua_State *L);

#ifdef __cplusplus
}
#endif
