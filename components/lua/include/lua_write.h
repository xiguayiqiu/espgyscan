/*
 * lua_write.h - 将 Lua 的 print / 错误输出重定向到项目提供的回调。
 *
 * 通过「先包含本头、再包含 lauxlib.h」的方式，利用 lauxlib.h 中
 *   #if !defined(lua_writestring) ... endif
 * 的保护逻辑，在 Lua 引擎编译单元里用自定义实现覆盖默认的 stdout print。
 */
#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 由 luagyscan 组件实现：把 Lua print 的数据写入当前输出目标 */
void gyscan_lua_writestring(const char *s, size_t l);
void gyscan_lua_writeline(void);
void gyscan_lua_writestringerror(const char *s, const char *p);

#ifdef __cplusplus
}
#endif

#define lua_writestring(s, l)      gyscan_lua_writestring((s), (l))
#define lua_writeline()            gyscan_lua_writeline()
#define lua_writestringerror(s, p) gyscan_lua_writestringerror((s), (p))