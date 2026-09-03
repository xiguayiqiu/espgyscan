/*
 * lua_pcap.h - 固件内置 Lua 抓包模块 (pcap)
 *
 * 在 Lua 运行时创建时（由 init 钩子调用）注册全局 pcap 表，脚本可直接使用：
 *   pcap.open([snaplen])          → handle | nil, err   (开启 WiFi 混杂模式抓包)
 *   pcap.next(handle[, timeout_ms]) → frame | nil, err    (取下一帧; 超时返回 nil)
 *   pcap.close(handle)            → true                       (关闭抓包)
 *   pcap.filter(handle[, bpf])      → true                       (设置/清除简易过滤)
 *   pcap.interfaces()              → { "wlan0", ... }         (可用抓包接口列表)
 *   pcap.parse(data[, offset])     → {src,dst,ethertype,payload} (解析 802.3 头)
 *
 * 全部基于 ESP-IDF 原生 esp_wifi 混杂模式(与 arp_mitm 同一套 API)，
 * 接收 AP 解密后转发给本机的明文数据帧；不依赖任何 luarocks / libpcap。
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

/* 注册全局 pcap 模块(经 lua_embed_set_init_hook 调用)。 */
void gyscan_lua_pcap_register(lua_State *L);

#ifdef __cplusplus
}
#endif