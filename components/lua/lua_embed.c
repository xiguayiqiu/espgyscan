/*
 * lua_embed.c - LUA 运行时嵌入实现（esp32-s3 gyscan）
 *
 * 提供三个由 lua_write.h 宏引用的输出函数，以及项目面向的加载/执行 API：
 *   - gyscan_lua_writestring / gyscan_lua_writeline / gyscan_lua_writestringerror
 *   - lua_embed_init() / lua_embed_run_file() / lua_embed_deinit()
 *
 * 并发模型：
 *   Lua 状态 (lua_State) 为单实例，非线程安全；因此 lua_embed_run_file()
 *   全程持有互斥锁，把「进入解释器」的执行串行化——同一时刻只有一个
 *   调用方在跑脚本。每次 run 的 stdout 接收器 (out_cb/out_ctx) 作为
 *   「当前执行上下文」在锁内暂存，print/错误输出只发给本次 run 的调用方，
 *   从而避免多客户端并发 run 时输出串扰或栈/堆被并发破坏。
 */

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include "lua_embed.h"

static const char *TAG = "lua";

/* 串行化 Lua 解释器访问的互斥锁（惰性创建） */
static SemaphoreHandle_t s_lua_lock = NULL;

/* 惰性创建的 Lua 状态；重复 run 复用，避免重复初始化开销 */
static lua_State *s_L = NULL;

/* 「当前正在执行的 run」的输出接收器——仅在持有 s_lua_lock 时访问 */
static lua_embed_output_cb s_run_out_cb = NULL;
static void *s_run_out_ctx = NULL;

/* 状态创建后的初始化钩子（注册业务 Lua 模块用，如 net 网络库） */
static lua_embed_init_hook_t s_init_hook = NULL;

/* ---------------- 内部辅助 ---------------- */

static void lua_embed_lock(void)
{
    if (s_lua_lock == NULL) {
        s_lua_lock = xSemaphoreCreateMutex();
    }
    xSemaphoreTake(s_lua_lock, portMAX_DELAY);
}

static void lua_embed_unlock(void)
{
    xSemaphoreGive(s_lua_lock);
}

void lua_embed_set_init_hook(lua_embed_init_hook_t hook)
{
    lua_embed_lock();
    s_init_hook = hook;
    lua_embed_unlock();
}

/* ---------------- 输出回调（被 lua_write.h 宏引用，须持锁调用） ---------------- */

void gyscan_lua_writestring(const char *s, size_t l)
{
    if (s_run_out_cb != NULL) {
        s_run_out_cb(s, l, s_run_out_ctx);
    } else {
        fwrite(s, sizeof(char), l, stdout);   /* 默认落到串口 */
    }
}

void gyscan_lua_writeline(void)
{
    gyscan_lua_writestring("\n", 1);
}

void gyscan_lua_writestringerror(const char *s, const char *p)
{
    /* Lua 内部总是以 (fmt, 单个值) 形式调用（见 lauxlib.c/ldblib.c）。
     * 格式化为单条消息后走当前 run 的接收器。 */
    char buf[256];
    if (p != NULL) {
        snprintf(buf, sizeof(buf), s, p);
    } else {
        snprintf(buf, sizeof(buf), "%s", s);
    }
    gyscan_lua_writestring(buf, strlen(buf));
}

/* ---------------- 运行时生命周期（加锁版，供公开 API 复用） ---------------- */

/* Lua 内存分配器：转发到标准 realloc（堆在内部 SRAM/PSRAM 由链路决定） */
static void *lua_embed_alloc(void *ud, void *ptr, size_t osize, size_t nsize)
{
    (void)ud;
    (void)osize;
    if (nsize == 0) {
        free(ptr);
        return NULL;
    }
    return realloc(ptr, nsize);
}

/* 前置条件：已持有 s_lua_lock */
static esp_err_t lua_embed_init_locked(void)
{
    if (s_L != NULL) {
        return ESP_OK;
    }
    s_L = lua_newstate(lua_embed_alloc, NULL);
    if (s_L == NULL) {
        ESP_LOGE(TAG, "lua_newstate 失败");
        return ESP_ERR_NO_MEM;
    }
    luaL_openlibs(s_L);

    /* 状态首次创建后调用注册钩子（可注册 require 模块，如 net 网络库） */
    if (s_init_hook != NULL) {
        s_init_hook(s_L);
    }

    ESP_LOGI(TAG, "Lua 运行时已就绪 (%s)", LUA_RELEASE);
    return ESP_OK;
}

esp_err_t lua_embed_init(void)
{
    esp_err_t ret;
    lua_embed_lock();
    ret = lua_embed_init_locked();
    lua_embed_unlock();
    return ret;
}

/* ---------------- 上层执行 API ---------------- */

/* 公共执行骨架：持锁登记输出上下文 → 加载(文件/内存) → pcall → 清理。
 * is_buffer=1 时 src/len 为内存代码；否则 ref 为文件路径。前置条件：无锁。 */
static esp_err_t lua_embed_run_source(int is_buffer, const char *src, size_t len,
                                      const char *ref,
                                      lua_embed_output_cb out_cb, void *out_ctx,
                                      char *err, size_t err_sz)
{
    esp_err_t ret = ESP_FAIL;

    lua_embed_lock();

    /* 登记本次 run 的输出上下文（持锁期间唯一，避免并发串扰） */
    lua_embed_output_cb saved_cb = s_run_out_cb;
    void *saved_ctx = s_run_out_ctx;
    s_run_out_cb = out_cb;
    s_run_out_ctx = out_ctx;

    if (lua_embed_init_locked() == ESP_OK) {
        int rc = is_buffer ? luaL_loadbuffer(s_L, src, len, ref)
                           : luaL_loadfile(s_L, ref);
        if (rc != LUA_OK) {
            if (err != NULL && err_sz > 0) {
                snprintf(err, err_sz, "%s", lua_tostring(s_L, -1));
            }
            lua_pop(s_L, 1);
            ESP_LOGE(TAG, "加载失败: %s", ref);
        } else {
            rc = lua_pcall(s_L, 0, LUA_MULTRET, 0);
            if (rc != LUA_OK) {
                if (err != NULL && err_sz > 0) {
                    snprintf(err, err_sz, "%s", lua_tostring(s_L, -1));
                }
                lua_pop(s_L, 1);   /* 移除错误对象 */
                ESP_LOGE(TAG, "脚本运行失败: %s", ref);
            } else {
                ret = ESP_OK;
            }
        }
        /* 保证 pcall 后栈清理干净，下次 run 从干净栈开始 */
        lua_settop(s_L, 0);
    } else {
        if (err != NULL && err_sz > 0) {
            snprintf(err, err_sz, "Lua 运行时初始化失败");
        }
    }

    /* 恢复并清空输出上下文，解锁 */
    s_run_out_cb = saved_cb;
    s_run_out_ctx = saved_ctx;
    lua_embed_unlock();

    return ret;
}

esp_err_t lua_embed_run_file(const char *path, lua_embed_output_cb out_cb,
                             void *out_ctx, char *err, size_t err_sz)
{
    if (path == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    ESP_LOGI(TAG, "执行脚本文件: %s", path);
    return lua_embed_run_source(0, NULL, 0, path, out_cb, out_ctx, err, err_sz);
}

esp_err_t lua_embed_run_buffer(const char *code, size_t len,
                               const char *chunkname,
                               lua_embed_output_cb out_cb, void *out_ctx,
                               char *err, size_t err_sz)
{
    if (code == NULL || len == 0 || chunkname == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    ESP_LOGI(TAG, "执行内存代码(%u 字节, %s)", (unsigned)len, chunkname);
    return lua_embed_run_source(1, code, len, chunkname,
                                out_cb, out_ctx, err, err_sz);
}

void lua_embed_deinit(void)
{
    lua_embed_lock();
    if (s_L != NULL) {
        lua_close(s_L);
        s_L = NULL;
    }
    lua_embed_unlock();
}