#pragma once

#include "esp_err.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ARP 中间人(ARP MITM)攻击模块。
 *
 * 原理：向目标主机与网关持续发送伪造的 ARP 应答，使双方 ARP 缓存中
 * 的对方 IP 都指向 ESP 的 MAC，从而让目标是物品之间的流量经过 ESP，
 * 实现中间人转发/嗅探。
 *
 * 使用方式：
 *   arp_mitm_start(target_ip, gateway_ip)  开始攻击（IP 为点分十进制字符串）
 *   arp_mitm_stop()                        停止攻击并恢复
 *   arp_mitm_is_running()                  查询是否正在攻击
 */

/* 启动 ARP MITM。target_ip 为受害主机 IP，gateway_ip 为网关(路由器) IP。 */
esp_err_t arp_mitm_start(const char *target_ip, const char *gateway_ip);

/* 停止 ARP MITM */
esp_err_t arp_mitm_stop(void);

/* 是否正在攻击 */
bool arp_mitm_is_running(void);

/* 生成状态文本，如 "中对 192.168.1.100 <-> 192.168.1.1" 或 "未启动" */
void arp_mitm_status_text(char *buf, size_t buf_sz);

#ifdef __cplusplus
}
#endif
