/*
 * script_store.c - 脚本/资源存储与执行（自动介质：TF 卡 或 内存 RAM）
 *
 * 存储策略（自动，无需手动切换，也不写内部 Flash）：
 *   - TF 卡已挂载(存在 SD/TF 卡模块) → 所有 ls/read/write/rm/run 全部在 TF 卡(/sdcard)
 *   - 无 TF 卡或未挂载             → 全部在内存(RAM)中完成：upload 的文件只存 RAM，
 *                                   脚本执行走 Lua loadbuffer(内存加载)，不写 Flash，
 *                                   以延长 Flash 芯片使用寿命；重启后 RAM 内容清空。
 *
 * 因此本模块不再注册/使用内部 SPIFFS(/spiffs) 分区。
 *
 * 并发：所有公开操作由 s_lock 串行化；script_execute 会把执行代码拷贝到临时缓冲
 * 后释放锁再交给 Lua 引擎，避免执行期间数据被其他写/删操作释放。
 */

#include "script_store.h"
#include "lua_embed.h"
#include "sdcard.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"

static const char *TAG = "script";

/* ---------------- RAM 文件存储（无 TF 卡时的后备介质） ---------------- */

#define RAM_MAX_FILES    24
#define RAM_TOTAL_MAX    (3 * SCRIPT_FILE_MAX)   /* 内存中所有文件总字节上限(约180KB) */

typedef struct {
    bool      used;
    char      name[SCRIPT_NAME_MAX];
    uint8_t  *data;    /* 堆副本，data[len]='\0' 便于以字符串方式使用 */
    size_t    len;
} ram_file_t;

static ram_file_t s_ram[RAM_MAX_FILES];
static size_t s_ram_bytes = 0;

/* 存储层互斥锁（RAM 读写 + SD 文件操作共用） */
static SemaphoreHandle_t s_lock = NULL;

static void store_lock(void)
{
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
    }
    xSemaphoreTake(s_lock, portMAX_DELAY);
}

static void store_unlock(void)
{
    xSemaphoreGive(s_lock);
}

/* ---------------- 名称/路径校验 ---------------- */

/* 单层文件名（write/read/run 用）：不得包含任何路径分隔符 */
static bool name_is_flat(const char *name)
{
    if (name == NULL || name[0] == '\0') {
        return false;
    }
    size_t n = strlen(name);
    if (n >= SCRIPT_NAME_MAX) {
        return false;
    }
    return (strchr(name, '/') == NULL && strchr(name, '\\') == NULL);
}

/* 相对路径(rm 用)：允许子目录层级，但禁止越界成分 */
static bool rel_path_is_safe(const char *name)
{
    if (name == NULL || name[0] == '\0' || name[0] == '/') {
        return false;
    }
    if (strlen(name) >= 120) {
        return false;
    }
    if (strchr(name, '\\') != NULL || strstr(name, "..") != NULL ||
        strstr(name, "//") != NULL) {
        return false;
    }
    return true;
}

/* 拼出 /sdcard/<name>；name 末尾多余 '/' 自动去掉 */
static int sd_build_path(const char *name, char *path, size_t path_sz)
{
    char buf[128];
    size_t n = strlen(name);
    while (n > 1 && name[n - 1] == '/') {
        n--;
    }
    if (n >= sizeof(buf)) {
        return -1;
    }
    memcpy(buf, name, n);
    buf[n] = '\0';
    int w = snprintf(path, path_sz, "%s/%s", SDCARD_MOUNT_POINT, buf);
    return (w > 0 && (size_t)w < path_sz) ? 0 : -1;
}

/* ---------------- RAM 后端 ---------------- */

static ram_file_t *ram_find(const char *name)
{
    for (int i = 0; i < RAM_MAX_FILES; i++) {
        if (s_ram[i].used && strcmp(s_ram[i].name, name) == 0) {
            return &s_ram[i];
        }
    }
    return NULL;
}

static ram_file_t *ram_free_slot(void)
{
    for (int i = 0; i < RAM_MAX_FILES; i++) {
        if (!s_ram[i].used) {
            return &s_ram[i];
        }
    }
    return NULL;
}

static void ram_free_entry(ram_file_t *f)
{
    if (f->data != NULL) {
        free(f->data);
    }
    s_ram_bytes -= f->len;
    memset(f, 0, sizeof(*f));
}

static esp_err_t ram_write_file(const char *name, const char *data, size_t len)
{
    if (len > SCRIPT_FILE_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }
    ram_file_t *f = ram_find(name);
    /* 覆盖写与新建都需满足总量上限（覆盖时不重复计算旧文件占用的空间） */
    size_t other = s_ram_bytes - ((f != NULL) ? f->len : 0);
    if (other + len > RAM_TOTAL_MAX) {
        return ESP_ERR_NO_MEM;
    }
    if (f == NULL) {
        f = ram_free_slot();
        if (f == NULL) {
            return ESP_ERR_NO_MEM;
        }
    } else {
        ram_free_entry(f);
    }
    uint8_t *copy = malloc(len + 1);
    if (copy == NULL) {
        return ESP_ERR_NO_MEM;
    }
    memcpy(copy, data, len);
    copy[len] = '\0';
    f->used = true;
    snprintf(f->name, sizeof(f->name), "%s", name);
    f->data = copy;
    f->len  = len;
    s_ram_bytes += len;
    return ESP_OK;
}

/* ---------------- SD 递归删除 ---------------- */

static esp_err_t sd_rm_recursive(const char *path, int depth)
{
    if (depth > 32) {
        return ESP_FAIL;
    }
    DIR *d = opendir(path);
    if (d == NULL) {
        return ESP_ERR_NOT_FOUND;
    }
    esp_err_t ret = ESP_OK;
    struct dirent *ent;
    while (ret == ESP_OK && (ent = readdir(d)) != NULL) {
        const char *nm = ent->d_name;
        if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0) {
            continue;
        }
        char child[256];
        size_t base = strlen(path), nl = strlen(nm);
        if (base + nl + 2 > sizeof(child)) {
            ret = ESP_ERR_INVALID_SIZE;   /* 路径过深/过长，保护性中止 */
            break;
        }
        memcpy(child, path, base);
        child[base] = '/';
        memcpy(child + base + 1, nm, nl + 1);
        struct stat st;
        if (stat(child, &st) != 0) {
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            ret = sd_rm_recursive(child, depth + 1);
        } else if (remove(child) != 0) {
            ret = ESP_FAIL;
        }
    }
    closedir(d);
    if (ret != ESP_OK) {
        return ret;
    }
    return (rmdir(path) == 0) ? ESP_OK : ESP_FAIL;
}

/* 删除 SD 上的文件或文件夹(递归)；绝对路径/越界已在调用前校验 */
static esp_err_t sd_rm_path(const char *name)
{
    char path[160];
    if (sd_build_path(name, path, sizeof(path)) != 0) {
        return ESP_ERR_INVALID_ARG;
    }
    struct stat st;
    if (stat(path, &st) != 0) {
        return ESP_ERR_NOT_FOUND;
    }
    if (S_ISDIR(st.st_mode)) {
        return sd_rm_recursive(path, 0);
    }
    return (remove(path) == 0) ? ESP_OK : ESP_FAIL;
}

/* ---------------- 介质判定 ---------------- */

script_media_t script_store_media(void)
{
    return sdcard_is_mounted() ? SCRIPT_MEDIA_SDCARD : SCRIPT_MEDIA_RAM;
}

const char *script_store_media_name(void)
{
    return sdcard_is_mounted() ? "TF 卡 (/sdcard)" : "内存 RAM (重启清空)";
}

esp_err_t script_store_init(void)
{
    store_lock();
    store_unlock();
    ESP_LOGI(TAG, "脚本存储就绪: 自动介质 = 内存 RAM(无TF卡) / TF 卡(已挂载)");
    ESP_LOGI(TAG, "不使用内部 Flash 存储脚本(保护 Flash 寿命)");
    return ESP_OK;
}

int script_store_ram_file_count(void)
{
    int n = 0;
    store_lock();
    for (int i = 0; i < RAM_MAX_FILES; i++) {
        if (s_ram[i].used) {
            n++;
        }
    }
    store_unlock();
    return n;
}

size_t script_store_ram_bytes(void)
{
    store_lock();
    size_t b = s_ram_bytes;
    store_unlock();
    return b;
}

/* ---------------- 列表 ---------------- */

esp_err_t script_store_list(void (*line_cb)(const char *name, void *ctx),
                            void *ctx)
{
    if (line_cb == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    store_lock();
    esp_err_t ret = ESP_OK;
    if (script_store_media() == SCRIPT_MEDIA_SDCARD) {
        DIR *d = opendir(SDCARD_MOUNT_POINT);
        if (d == NULL) {
            ret = ESP_FAIL;
        } else {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                if (ent->d_type == DT_REG) {
                    line_cb(ent->d_name, ctx);
                }
            }
            closedir(d);
        }
    } else {
        for (int i = 0; i < RAM_MAX_FILES; i++) {
            if (s_ram[i].used) {
                line_cb(s_ram[i].name, ctx);
            }
        }
    }
    store_unlock();
    return ret;
}

esp_err_t script_store_list_all(void (*cb)(const char *name, bool is_dir,
                                           void *ctx), void *ctx)
{
    if (cb == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    store_lock();
    esp_err_t ret = ESP_OK;
    if (script_store_media() == SCRIPT_MEDIA_SDCARD) {
        DIR *d = opendir(SDCARD_MOUNT_POINT);
        if (d == NULL) {
            ret = ESP_FAIL;
        } else {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                const char *nm = ent->d_name;
                if (strcmp(nm, ".") == 0 || strcmp(nm, "..") == 0) {
                    continue;
                }
                cb(nm, (ent->d_type == DT_DIR), ctx);
            }
            closedir(d);
        }
    } else {
        for (int i = 0; i < RAM_MAX_FILES; i++) {
            if (s_ram[i].used) {
                cb(s_ram[i].name, false, ctx);
            }
        }
    }
    store_unlock();
    return ret;
}

/* ---------------- 读 / 写 / 删 ---------------- */

esp_err_t script_store_read(const char *name, char *buf, size_t buf_sz,
                            size_t *out_len)
{
    if (name == NULL || buf == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    store_lock();
    esp_err_t ret;
    if (script_store_media() == SCRIPT_MEDIA_SDCARD) {
        if (!name_is_flat(name)) {
            ret = ESP_ERR_INVALID_ARG;
        } else {
            char path[160];
            if (sd_build_path(name, path, sizeof(path)) != 0) {
                ret = ESP_ERR_INVALID_ARG;
            } else {
                FILE *f = fopen(path, "r");
                if (f == NULL) {
                    ret = ESP_ERR_NOT_FOUND;
                } else {
                    size_t n = fread(buf, 1, buf_sz - 1, f);
                    fclose(f);
                    buf[n] = '\0';
                    if (out_len != NULL) {
                        *out_len = n;
                    }
                    ret = ESP_OK;
                }
            }
        }
    } else {
        ram_file_t *f = ram_find(name);
        if (f == NULL) {
            ret = ESP_ERR_NOT_FOUND;
        } else if (f->len > buf_sz - 1) {
            ret = ESP_ERR_INVALID_SIZE;
        } else {
            memcpy(buf, f->data, f->len);
            buf[f->len] = '\0';
            if (out_len != NULL) {
                *out_len = f->len;
            }
            ret = ESP_OK;
        }
    }
    store_unlock();
    return ret;
}

esp_err_t script_store_write(const char *name, const char *data, size_t len)
{
    if (name == NULL || data == NULL) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!name_is_flat(name)) {
        return ESP_ERR_INVALID_ARG;   /* 禁止路径分隔符/穿越 */
    }
    if (len > SCRIPT_FILE_MAX) {
        return ESP_ERR_INVALID_SIZE;
    }
    store_lock();
    esp_err_t ret;
    if (script_store_media() == SCRIPT_MEDIA_SDCARD) {
        char path[160];
        if (sd_build_path(name, path, sizeof(path)) != 0) {
            ret = ESP_ERR_INVALID_ARG;
        } else {
            FILE *f = fopen(path, "w");
            if (f == NULL) {
                ESP_LOGW(TAG, "写入失败: %s", path);
                ret = ESP_FAIL;
            } else {
                size_t n = fwrite(data, 1, len, f);
                fclose(f);
                ret = (n == len) ? ESP_OK : ESP_FAIL;
            }
        }
    } else {
        ret = ram_write_file(name, data, len);
    }
    store_unlock();
    return ret;
}

esp_err_t script_store_rm(const char *name)
{
    if (name == NULL || name[0] == '\0') {
        return ESP_ERR_INVALID_ARG;
    }
    store_lock();
    esp_err_t ret;
    if (script_store_media() == SCRIPT_MEDIA_SDCARD) {
        ret = rel_path_is_safe(name) ? sd_rm_path(name)
                                     : ESP_ERR_INVALID_ARG;
    } else {
        ram_file_t *f = ram_find(name);
        if (f == NULL) {
            ret = ESP_ERR_NOT_FOUND;
        } else {
            ram_free_entry(f);
            ret = ESP_OK;
        }
    }
    store_unlock();
    return ret;
}

/* ---------------- 执行 ---------------- */

esp_err_t script_execute(const char *name, script_output_cb out_cb,
                         void *out_ctx, char *msg, size_t msg_sz)
{
    if (name == NULL) {
        if (msg != NULL) snprintf(msg, msg_sz, "脚本名为空");
        return ESP_ERR_INVALID_ARG;
    }

    store_lock();
    esp_err_t ret;
    if (script_store_media() == SCRIPT_MEDIA_SDCARD) {
        if (!name_is_flat(name)) {
            if (msg != NULL) snprintf(msg, msg_sz, "脚本名无效: %s", name);
            ret = ESP_ERR_INVALID_ARG;
        } else {
            char path[160];
            struct stat st;
            if (sd_build_path(name, path, sizeof(path)) != 0 ||
                stat(path, &st) != 0) {
                if (msg != NULL) snprintf(msg, msg_sz, "脚本不存在: %s (介质: %s)",
                                          name, script_store_media_name());
                ret = ESP_ERR_NOT_FOUND;
            } else {
                store_unlock();   /* 释放存储锁，交给 Lua 引擎(文件方式读取) */
                ret = lua_embed_run_file(path, out_cb, out_ctx, msg, msg_sz);
                return (ret == ESP_OK) ? ESP_OK : ESP_FAIL;
            }
        }
        store_unlock();
        return ret;
    }

    /* RAM 介质：把代码拷贝到临时缓冲后释放锁，再走内存执行(Lua loadbuffer) */
    ram_file_t *f = ram_find(name);
    if (f == NULL) {
        if (msg != NULL) snprintf(msg, msg_sz, "脚本不存在: %s (内存中)", name);
        store_unlock();
        return ESP_ERR_NOT_FOUND;
    }
    uint8_t *code = malloc(f->len + 1);
    if (code == NULL) {
        if (msg != NULL) snprintf(msg, msg_sz, "内存不足");
        store_unlock();
        return ESP_ERR_NO_MEM;
    }
    memcpy(code, f->data, f->len + 1);
    size_t code_len = f->len;
    store_unlock();

    char chunk[SCRIPT_NAME_MAX + 8];
    snprintf(chunk, sizeof(chunk), "@ram/%s", name);
    ret = lua_embed_run_buffer((const char *)code, code_len, chunk,
                               out_cb, out_ctx, msg, msg_sz);
    free(code);
    return (ret == ESP_OK) ? ESP_OK : ESP_FAIL;
}
