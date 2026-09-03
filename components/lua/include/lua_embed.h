/*
 * lua_embed.h - LUA 运行时嵌入 API（esp32-s3 gyscan）
 *
 * 在固件中嵌入 Lua 5.4，供 run 命令加载并执行 .lua 脚本。
 *
 * 并发模型：Lua 解释器状态为单实例，所有进入解释器的执行
 * （lua_embed_run_file）由内部互斥锁串行化；脚本 print 输出经
 * 每次 run 传入的 out_cb/out_ctx 转发，保证不同调用方的输出不会串扰。
 */
#pragma once

#include "esp_err.h"
#include <stddef.h>

/* lua_State 前置声明（避免本公开头文件依赖 lua 源码 include 路径；
 * 若 lua.h 已先行包含(LUA_VERSION_MAJOR 已定义)则跳过重复声明） */
#ifndef LUA_VERSION_MAJOR
struct lua_State;
typedef struct lua_State lua_State;
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* 脚本 stdout 的接收回调：往目标写出 len 字节；ctx 由调用方提供 */
typedef void (*lua_embed_output_cb)(const char *data, size_t len, void *ctx);

/*
 * 初始化 Lua 运行时（惰性：首次 run 自动初始化，也可显式调用）。
 * 返回 ESP_OK 或 ESP_ERR_NO_MEM。线程安全。
 */
esp_err_t lua_embed_init(void);

/*
 * 加载并执行一个 .lua 文件（线程安全，内部串行化执行）。
 *   path     脚本绝对路径（SD 卡 /sdcard 下，或其它已挂载 VFS 路径）。
 *   out_cb   本次执行的 stdout 接收器（可为 NULL，落到串口 stdout）。
 *   out_ctx  随 out_cb 透传给接收器。
 *   err/err_sz  失败时写入错误描述（可为 NULL/0）。
 * 成功返回 ESP_OK；脚本语法/运行错误返回 ESP_FAIL（err 含详情）。
 * 阻塞直到脚本返回或出错。
 */
esp_err_t lua_embed_run_file(const char *path, lua_embed_output_cb out_cb,
                             void *out_ctx, char *err, size_t err_sz);

/*
 * 直接执行内存中的一段 Lua 代码（线程安全，内部串行化执行）。
 * 不涉及任何文件系统，代码只在 RAM 中（不写入 Flash），用于无 TF 卡
 * 时运行上传脚本 / eval 等场景。
 *   code/code_len   Lua 源码（字节数）；code 无需以 '\0' 结尾。
 *   chunkname       伪文件名，必须以 '@' 开头（如 "@ram/demo.lua"），
 *                   错误信息会带该名称与行号；可为调用方定位用。
 *   其余参数含义与 lua_embed_run_file 相同。
 */
esp_err_t lua_embed_run_buffer(const char *code, size_t code_len,
                               const char *chunkname,
                               lua_embed_output_cb out_cb, void *out_ctx,
                               char *err, size_t err_sz);

/* Lua 状态创建后的初始化钩子：可用于注册 require("xxx") 业务模块 */
typedef void (*lua_embed_init_hook_t)(lua_State *L);

/* 设置状态创建钩子（状态已存在时不会重复触发；线程安全）。 */
void lua_embed_set_init_hook(lua_embed_init_hook_t hook);

/* 释放运行时（线程安全；会先等待正在执行的脚本结束）。 */
void lua_embed_deinit(void);

#ifdef __cplusplus
}
#endif