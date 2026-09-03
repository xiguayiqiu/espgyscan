# Lua 5.4 运行时组件。
# 将 third_party/lua/src 的 Lua 核心编译进本组件，供 main 调用。

set(LUA_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/../../third_party/lua/src")

# 收集 Lua 全部 .c，排除两个独立程序（lua.c=standalone REPL、luac.c=编译器）
# 与构建工具 Makefile 使用的辅助文件。
file(GLOB LUA_C_SOURCES "${LUA_SRC_DIR}/*.c")
list(FILTER LUA_C_SOURCES EXCLUDE REGEX "/(lua|luac)\\.c$")

idf_component_register(
    SRCS "lua_embed.c" ${LUA_C_SOURCES}
    INCLUDE_DIRS "include" "${LUA_SRC_DIR}"
    PRIV_REQUIRES spiffs
)

# 让所有 Lua 源文件在包含 lauxlib.h 之前先定义 lua_writestring 等宏，
# 从而把 print / 错误输出重定向到 gyscan_lua_writestring 等回调。
target_compile_options(${COMPONENT_LIB} PRIVATE
    "-include" "${CMAKE_CURRENT_LIST_DIR}/include/lua_write.h"
)