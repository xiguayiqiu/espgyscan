/*
 * sdcard.h - SD/TF 卡管理 API（SDSPI 方式，挂载点 /sdcard）
 *
 * 提供外置 TF 卡的挂载 / 卸载 / 格式化 / 状态查询，供主菜单
 * "TF 卡设置"使用，并把脚本/资源存储扩展到 SD 卡的大空间。
 */
#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SDCARD_MOUNT_POINT "/sdcard"

/* 挂载 TF 卡（含 FAT 文件系统）。已挂载时直接返回 ESP_OK。
 * 在后台任务中执行并带超时(SD_OP_TIMEOUT_MS)：无卡/坏卡时不会卡死调用方，
 * 超时返回 ESP_ERR_TIMEOUT。 */
esp_err_t sdcard_mount(void);

/* 卸载 TF 卡。未挂载时返回 ESP_OK（幂等）。 */
esp_err_t sdcard_unmount(void);

/* 格式化 TF 卡(FAT32)。需先挂载。会删除卡上所有数据。
 * 同样在后台任务中执行，带超时返回。 */
esp_err_t sdcard_format(void);

/* TF 卡当前是否已挂载可用 */
bool sdcard_is_mounted(void);

/* 获取 TF 卡容量(字节)，未挂载时返回 0 */
uint64_t sdcard_get_capacity(void);

/*
 * 获取状态文本（用于菜单显示），如
 *   "已挂载 /sdcard (容量 14879 MB)" 或 "未挂载"。
 * 英文由调用方通过 I18N 处理，本函数只返回信息数据。
 */
esp_err_t sdcard_status(char *buf, size_t buf_sz);

#ifdef __cplusplus
}
#endif