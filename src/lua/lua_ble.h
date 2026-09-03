/*
 * lua_ble.h - 固件内置 Lua BLE 模块
 *
 * 在 Lua 运行时创建时由 init 钩子注册全局 ble 表，脚本可直接使用：
 *   ble.scan([duration_ms])   -> { devices } | nil, err   (扫描附近 BLE 设备)
 *   ble.status()              -> string                    (蓝牙状态文本)
 *   ble.pair(addr)            -> true | nil, err           (配对指定地址 "aa:bb:cc:dd:ee:ff")
 *   ble.disconnect()          -> true | nil, err           (断开当前连接)
 *
 * 全部基于 ESP-IDF 原生 NimBLE 协议栈(与 ble_scan.c 同一套 API)，
 * 无需 luarocks / libpcap。ESP32-S3 仅支持 BLE（不支持经典蓝牙）。
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

/* 注册全局 ble 模块(经 gyscan_lua_net_register 调用)。 */
void gyscan_lua_ble_register(lua_State *L);

#ifdef __cplusplus
}
#endif