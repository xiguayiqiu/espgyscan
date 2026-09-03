#pragma once

#include "esp_err.h"
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 单文件大小上限（上传/下载缓冲共用） */
#define SCRIPT_FILE_MAX  (60 * 1024)
/* 文件名/条目名最大长度(不含结尾 '\0') */
#define SCRIPT_NAME_MAX  64

/*
 * 存储介质（自动选择，无需手动切换）：
 *   - TF 卡已挂载         → SCRIPT_MEDIA_SDCARD（ls/read/write/rm/run 全在 /sdcard）
 *   - 无 TF 卡(未挂载)    → SCRIPT_MEDIA_RAM（文件只放内存，运行走 Lua loadbuffer，
 *                           不写内部 Flash，延长 Flash 寿命；重启后 RAM 内容清空）
 */
typedef enum {
    SCRIPT_MEDIA_RAM = 0,
    SCRIPT_MEDIA_SDCARD,
} script_media_t;

/* 初始化存储层（创建 RAM 后端；不挂载 SPIFFS，避免写 Flash） */
esp_err_t script_store_init(void);

/* 当前生效介质：TF 卡已挂载返回 SDCARD，否则 RAM */
script_media_t script_store_media(void);

/* 当前介质中文名，如 "TF 卡 (/sdcard)" / "内存 RAM" */
const char *script_store_media_name(void);

/* RAM 后端统计（无 TF 卡时文件在内存中的数量/字节数） */
int  script_store_ram_file_count(void);
size_t script_store_ram_bytes(void);

/* 列出当前介质根目录下的常规文件，每个经 line_cb 输出（菜单运行用） */
esp_err_t script_store_list(void (*line_cb)(const char *name, void *ctx),
                            void *ctx);

/* 列出当前介质根目录全部条目（is_dir=true 表示目录；RAM 只有文件） */
esp_err_t script_store_list_all(void (*cb)(const char *name, bool is_dir,
                                           void *ctx), void *ctx);

/* 读取文件内容到 buf（buf_sz 需容纳完整文件，超出返回 ESP_ERR_INVALID_SIZE） */
esp_err_t script_store_read(const char *name, char *buf, size_t buf_sz,
                            size_t *out_len);

/* 写入文件。当前介质为 RAM 时仅存内存(重启清空)；为 SD 时写入 TF 卡。
 * name 必须为单层文件名(不含路径分隔符)。 */
esp_err_t script_store_write(const char *name, const char *data, size_t len);

/*
 * 删除文件或目录：
 *   - RAM 介质：删除内存中的文件（不支持目录）。
 *   - SD 介质：name 为文件则删除；为目录(可含子目录路径)则递归删除。
 * name 禁止含 ".." / 反斜杠 / 绝对路径，防止越出存储根目录。
 */
esp_err_t script_store_rm(const char *name);

/* 脚本执行期间的 stdout 输出接收（print 等），用于转发到客户端 */
typedef void (*script_output_cb)(const char *data, size_t len, void *ctx);

/*
 * 执行脚本：
 *   - SD 介质：读取 TF 卡上的文件交给 Lua 引擎执行；
 *   - RAM 介质：直接从内存执行(Lua loadbuffer)，不写任何 Flash。
 * 线程安全：Lua 运行时内部串行化执行；print 输出经 out_cb/out_ctx 实时转发
 * (out_cb 为 NULL 时落到串口 stdout)。
 */
esp_err_t script_execute(const char *name, script_output_cb out_cb,
                         void *out_ctx, char *msg, size_t msg_sz);

#ifdef __cplusplus
}
#endif
