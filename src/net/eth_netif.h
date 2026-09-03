#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * QEMU 以太网支持：使用 OpenCores Ethernet MAC(openeth)，
 * 仅在 CONFIG_ETH_USE_OPENETH=y(QEMU 专用)时编译生效。
 * 真机请保持 CONFIG_ETH_USE_OPENETH=n。
 */

/* 初始化并启动以太网；返回是否已启动 */
bool eth_start(void);

/* 以太网是否已通过 DHCP 获得 IP（事件标志版，事件循环正常时置位） */
bool eth_got_ip(void);

/* 以太网是否已通过 DHCP 获得 IP（轮询版：直接查 netif IP。
 * QEMU 下 esp_event 事件循环可能不调度 IP_EVENT_ETH_GOT_IP，
 * 此时 eth_got_ip() 恒为 false，需用本函数兜底） */
bool eth_has_ip(void);

/* 生成以太网状态文本：如 "已连接 以太网 (10.0.2.15)" 或 "未连接"
 * （无 openeth 编译时为空实现，返回 "未连接"/"Not connected"） */
void eth_get_status_text(char *buf, size_t buf_sz);

#ifdef __cplusplus
}
#endif
