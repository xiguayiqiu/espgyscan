/*
 * i18n.c - 界面国际化（中文/English）
 *
 * 以中文为 key 的中英字典。菜单渲染层在显示前调用 i18n_t()，
 * 动态文案用 I18N(zh, en) 宏按当前语言选择格式串。
 */

#include "i18n.h"
#include <string.h>

static i18n_lang_t s_lang = LANG_ZH;

typedef struct {
    const char *zh;
    const char *en;
} i18n_entry_t;

static const i18n_entry_t s_dict[] = {
    /* ---- 菜单屏幕/项目 ---- */
    { "主菜单",          "Main Menu" },
    { "WiFi 设置",       "WiFi Settings" },
    { "蓝牙设置",        "Bluetooth Settings" },
    { "边缘安全",        "Edge Security" },
    { "运行 Lua 脚本",   "Run Lua Script" },
    { "TF 卡设置",       "TF Card Settings" },
    { "TF 卡状态",       "TF Card Status" },
    { "挂载 TF 卡",      "Mount TF Card" },
    { "卸载 TF 卡",      "Unmount TF Card" },
    { "格式化 TF 卡",    "Format TF Card" },
    { "切换脚本存储介质", "Switch Script Media" },
    { "Lua 脚本",          "Lua Scripts" },
    { "删除脚本文件",      "Delete Script File" },
    { "查看脚本存储",      "Script Storage" },
    { "文件不存在",        "File not found" },
    { "挂载点",          "Mount point" },
    { "容量",            "Capacity" },
    { "已挂载",          "Mounted" },
    { "未挂载",          "Not mounted" },
    { "TF 卡已挂载",     "TF card already mounted" },
    { "TF 卡未挂载",     "TF card not mounted" },
    { "脚本目录为空(先用 gyscan esp upload 上传 .lua)",
      "No scripts yet (upload .lua via 'gyscan esp upload')" },
    { "可用 Lua 脚本",   "Available Lua Scripts" },
    { "输入脚本编号并回车 (0 取消): ",
      "Enter script number and press Enter (0 = cancel): " },
    { "无效的选择",       "Invalid selection" },
    { "正在运行脚本",     "Running script" },
    { "脚本执行完成",     "Script finished" },
    { "脚本执行失败",     "Script error" },
    { "语言",            "Language" },
    { "网络功能",        "Network" },
    { "键盘模拟",        "Keyboard" },
    { "键盘模拟输入",    "Keyboard Injection" },
    { "蓝牙探测",        "BLE Scan" },
    { "蓝牙配对",        "BLE Pairing" },
    { "ARP 中间人",      "ARP MITM" },
    { "启动 ARP MITM",   "Start ARP MITM" },
    { "停止 ARP MITM",   "Stop ARP MITM" },
    { "ARP MITM 状态",   "ARP MITM Status" },
    { "连接 WiFi",       "Connect WiFi" },
    { "手动输入 SSID/密码", "Manual SSID/Password" },
    { "断开 WiFi",       "Disconnect WiFi" },
    { "网络与 HTTP 状态", "Network & HTTP Status" },
    { "gyscan控制(1234)状态", "gyscan Control (1234)" },
    { "注入测试文本",    "Type Test Text" },
    { "USB 键盘状态",    "USB Keyboard Status" },
    { "连接 gyscan (Go程序)", "Connect gyscan (Go)" },
    { "中文",            "Chinese" },
    { "English",         "English" },
    { "关机",            "Shutdown" },
    { "确认关机? (回车=关机, ESC=继续运行)", "Confirm shutdown? (Enter=Shutdown, ESC=Cancel)" },
    { "正在关机...",      "Shutting down..." },

    /* ---- 欢迎横幅标签 ---- */
    { "网络",            "WiFi" },
    { "蓝牙",            "Bluetooth" },
    { "内存",            "RAM" },
    { "储存(Flash)",     "Flash" },

    /* ---- 菜单按键提示 ---- */
    { "WASD/方向键 移动   Enter 确认   ESC 返回/退出",
      "WASD/Arrows Move   Enter OK   ESC Back/Exit" },
    { "按 ESC 返回菜单...", "Press ESC to return..." },
    { "已退出菜单",       "Menu exited" },
    { "菜单为空",         "Empty menu" },

    /* ---- 通用状态 ---- */
    { "未启用",          "Not enabled" },
    { "未连接",          "Not connected" },
    { "已连接",          "Connected" },
    { "未连接 (目标 %s)", "Not connected (target %s)" },
    { "已连接 %s (%s)",   "Connected %s (%s)" },
    { "初始化中...",      "Initializing..." },
    { "扫描中...",        "Scanning..." },
    { "连接中...",        "Connecting..." },
    { "配对中...",        "Pairing..." },
    { "已取消配对",       "Pairing cancelled" },
    { "已取消",           "Cancelled" },
    { "蓝牙初始化失败",   "Bluetooth init failed" },
    { "蓝牙 host 同步超时", "Bluetooth host sync timeout" },
    { "未发现任何设备",   "No devices found" },
    { "未发现可配对设备", "No pairable device found" },
    { "配对目标: %s (%s)", "Pairing target: %s (%s)" },
    { "连接超时",         "Connect timeout" },
    { "配对等待超时",     "Pairing wait timeout" },
    { "正在扫描，请稍候...", "Scanning, please wait..." },
    { "按 ESC 取消",      "Press ESC to cancel" },
    { "扫描失败",         "Scan failed" },
    { "扫描已取消",       "Scan cancelled" },
    { "配对结果",         "Pairing result" },

    /* ---- WiFi / HTTP ---- */
    { "WiFi 连接成功",    "WiFi connected" },
    { "WiFi 已连接",      "WiFi connected" },
    { "已断开 WiFi",      "WiFi disconnected" },
    { "WiFi 连接失败: %s", "WiFi connect failed: %s" },
    { "当前 SSID: %s",    "Current SSID: %s" },
    { "已连接到 %s ✓",    "Connected to %s ✓" },
    { "输入 WiFi 名称(SSID): ", "Enter WiFi SSID: " },
    { "输入 WiFi 密码(直接回车表示开放网络): ", "Enter WiFi password (empty = open): " },
    { "断开失败: %s",     "Disconnect failed: %s" },
    { "HTTP 服务器: %s (端口 %d)", "HTTP server: %s (port %d)" },
    { "ESP IP: %s",       "ESP IP: %s" },
    { "运行中",           "Running" },
    { "未运行",           "Stopped" },

    /* ---- HID ---- */
    { "USB 键盘: %s",     "USB Keyboard: %s" },
    { "已连接电脑",       "Connected to PC" },
    { "未连接(等待USB枚举)", "Not connected (waiting USB)" },
    { "正在注入测试文本: %s", "Injecting test text: %s" },
    { "键盘注入测试完成 (请查看电脑上焦点窗口)", "Injection done (check PC focus window)" },
    { "键盘注入失败: %s", "Injection failed: %s" },
    { "USB 键盘未连接电脑，请用 USB 线将 ESP 连接到电脑", "USB keyboard not connected; plug ESP into PC via USB" },

    /* ---- 蓝牙配对流程 ---- */
    { "蓝牙配对",         "BLE Pairing" },
    { "请选择要配对的设备编号 (1-%d), 0 取消: ",
      "Select device to pair (1-%d), 0 cancel: " },
    { "配对中，ESC 取消...", "Pairing, ESC to cancel..." },
    { "连接中，ESC 取消...", "Connecting, ESC to cancel..." },

    /* ---- ARP 中间人：扫描+光标选择 ---- */
    { "选择受害主机",     "Select Victim Host" },
    { "扫描完成",         "Scan finished" },
    { "正在扫描...",      "Scanning..." },
    { "正在扫描局域网... (上/下移动 Enter选择 ESC取消)",
      "Scanning LAN... (Up/Down Move Enter Select ESC Cancel)" },
    { "未发现在线主机(可重新扫描)", "No online hosts found (re-scan)" },
    { "未获取到本机 IP，无法扫描(请先连接网络)",
      "No local IP, cannot scan (connect network first)" },
    { "已选择受害主机",   "Victim selected" },
    { "未检测到网关，请输入", "Gateway not detected, enter manually" },
};

#define DICT_SIZE (sizeof(s_dict) / sizeof(s_dict[0]))

void i18n_set_lang(i18n_lang_t lang)
{
    s_lang = lang;
}

i18n_lang_t i18n_lang(void)
{
    return s_lang;
}

int i18n_is_en(void)
{
    return s_lang == LANG_EN;
}

const char *i18n_t(const char *zh)
{
    if (zh == NULL || s_lang != LANG_EN) {
        return zh;
    }
    for (size_t i = 0; i < DICT_SIZE; i++) {
        if (strcmp(s_dict[i].zh, zh) == 0) {
            return s_dict[i].en;
        }
    }
    return zh;
}
