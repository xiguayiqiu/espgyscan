#pragma once

#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 扫描附近的 BLE 设备并打印列表（阻塞直到扫描结束） */
void ble_scan_run(void);

/* 非交互式扫描（供 Lua 调用）：初始化 + 执行扫描，返回发现的设备数（<0=错误） */
int ble_scan_perform(int duration_ms);

/* 获取最近一次扫描发现的设备数量 */
int ble_scan_result_count(void);

/* 获取最近一次扫描的第 idx 个设备（0 写入 name/addr_str/rssi）；成功返回 ESP_OK */
esp_err_t ble_scan_result_get(int idx, char *name, size_t name_sz,
                              char *addr_str, size_t addr_sz, int8_t *rssi);

/* 蓝牙配对流程（阻塞）：扫描 → 选择设备 → 连接 → 发起配对/加密
 * 需要用户输入数字选择设备；过程中按 ESC 可取消 */
void ble_pair_run(void);

/* 非交互式配对（供 Lua 调用）：连接并配对指定地址字符串 "aa:bb:cc:dd:ee:ff" */
esp_err_t ble_pair_address(const char *addr_str);

/* 断开当前 BLE 连接（供 Lua 调用） */
esp_err_t ble_disconnect(void);

/* 生成蓝牙状态文本：如 "已就绪" / "未启用" / "扫描中..." */
void ble_get_status_text(char *buf, size_t buf_sz);

#ifdef __cplusplus
}
#endif
