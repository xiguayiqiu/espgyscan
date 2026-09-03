# espgyscan

基于 **ESP-IDF v6.0.2** 的 **ESP32-S3** 边缘安全调试工具。

## 功能

启动后串口显示欢迎信息与交互式菜单（`>` 为选择器，支持**多级子菜单**）：

```
----- 欢迎使用esp-gyscan----
内存：xxx KB / xxx KB
储存(Flash)：16 MB
---- 主菜单----
> WiFi 设置
  蓝牙设置
  边缘安全
  Lua 脚本
  TF 卡设置
  语言
```

主菜单入口如下（功能入口 + 语言切换 + 关机）：

| 主菜单项 | 内容 | 定位 |
| ------- | ---- | ---- |
| **WiFi 设置** | 连接 WiFi / 手动输入 SSID/密码 / 断开 / 网络与HTTP状态 | 无线配置 |
| **蓝牙设置** | 蓝牙配对（扫描 → 选择 → 配对） | 蓝牙配置 |
| **边缘安全** | 蓝牙探测、ARP 中间人、键盘模拟注入、连接 gyscan(Go程序) | **攻击/渗透测试工具** |
| **Lua 脚本** | 运行已存脚本 / 删除脚本文件 / 查看脚本存储介质；内置 `net`/`pcap`/`ble` 等标准库 | 脚本运行与删除 |
| **TF 卡设置** | TF 卡状态 / 挂载 / 卸载 / 格式化 | 外置存储 |
| **语言** | 中文 / English | 界面语言切换 |

### 菜单按键

| 按键 | 功能 |
| ---- | ---- |
| `W` / `S` / `↑` / `↓` | 移动选择器 |
| `A` / `D` / `←` / `→` | 左右（纵向列表预留） |
| `Enter` | 确认 |
| `ESC` | 返回上级菜单（根菜单时退出） |

### 手动输入（运行时配置 WiFi）

进入 **WiFi 设置 → 手动输入 SSID/密码** 后，可直接在串口输入 WiFi 名称与密码
（支持回显与退格，`ESC` 取消）。配置后立即连接，并对后续自动重连生效。

### HTTP 状态服务

ESP 启动后自动连接网络（可使用运行时手动配置的 SSID），成功后启动
**HTTP 服务器（端口 80）**。使用 `curl`、`wget` 或浏览器访问，用于探测
设备是否可被 gyscan 连接：

```bash
curl http://<ESP的IP>/
# gyscan 控制服务(1234)运行中 → ESP-GYscan:ok     （可被 gyscan 连接）
# gyscan 控制服务未就绪   → ESP-GYscan:error      （不可被 gyscan 连接）
```

### gyscan 控制服务（端口 1234）

ESP 联网后默认开启 **1234 端口**，与 gyscan 主程序(freeclient)配合。freeclient 命令：

```bash
gyscan esp connect                  # 扫描并连接 espgyscan 设备

gyscan esp ip                       # 查看 ESP 网络信息(接口/IP/网关/MAC)
gyscan esp free                     # 查看 ESP 内存(RAM)状态
gyscan esp lsblk                    # 查看 ESP Flash 分区表与 TF 卡
gyscan esp version                  # 查看 ESP 固件版本
gyscan esp ls                       # 查看 ESP 上的文件(目录以 / 结尾)
gyscan esp run demo.lua             # 触发 ESP 运行它已存储的脚本(demo.lua)
gyscan esp upload demo.lua          # 把脚本/文件存入 ESP(先上传再 run)
gyscan esp download demo.lua out.lua  # 从 ESP 下载文件
gyscan esp rm demo.lua              # 删除 ESP 上的文件/文件夹(可递归删除文件夹)
gyscan esp keymap start|stop        # 开启/关闭键盘记录并实时回传
gyscan esp scan 192.168.1.0/24      # 扫描网段服务
gyscan esp scan 192.168.1.5 -p 1-1000   # 扫描端口范围
gyscan esp arp 192.168.1.100 192.168.1.1  # 启动 ARP 中间人，实时回传被劫持流量
gyscan esp arp 192.168.1.100 192.168.1.1 -o cap.txt  # 抓包另存到本地文件
gyscan esp arp stop                 # 停止 ARP 中间人
gyscan esp arp status               # 查看 ARP 中间人状态
gyscan esp close                    # 断开连接
```

#### 内存与存储状态

**`gyscan esp free`** — 查看 ESP32 内存(RAM)使用状态：

```bash
$ gyscan esp free

ESP32 内存状态 @ 192.168.1.5:1234
  总内存      : 242.17 KB
  已用        : 118.02 KB (48.7%)
  剩余        : 124.15 KB
  历史最小剩余: 116.82 KB
  最大连续块  : 76.00 KB
```

**`gyscan esp lsblk`** — 查看 ESP32 Flash 分区表和 TF 卡状态：

```bash
$ gyscan esp lsblk

ESP32 Flash 分区表 @ 192.168.1.5:1234
  TYPE SUB      LABEL        ADDR       SIZE       FLAGS
  data 0x02     nvs          0x009000   24.00 KB
  data 0x01     phy_init     0x00f000   4.00 KB
  app  factory  factory      0x010000   4.00 MB
  data 0x82     storage      0x410000   512.00 KB

  DEV  SIZE       FLAGS
  sdcard  14.50 GB  -
```

> **说明**：`lsblk` 显示内部 Flash 分区表；当 TF 卡已挂载时，额外显示 TF 卡容量。

**`gyscan esp version`** — 查看 ESP32 固件版本：

```bash
$ gyscan esp version

固件版本: 0.10
ESP-IDF : v6.0.2
```

> **存储介质（自动）**：有 TF 卡并已挂载 → 上传/下载/运行/删除全部在 **TF 卡
> (`/sdcard`)**；无 TF 卡 → 文件只保存在**内存 RAM**，脚本由固件从内存直接执行
> （**不写内部 Flash**，延长 Flash 芯片寿命），重启后 RAM 内容清空。
>
> **run 的语义**：`esp run demo.lua` 只把脚本名发给 ESP，由 ESP **自身读取并执行**，
> gyscan 不解析、不执行任何脚本代码。

文本行协议（详见 `freeclient/internal/esp`）：

| 请求 | 响应 |
| ---- | ---- |
| `hello` | `OK hello espgyscan`（设备发现用） |
| `netinfo` | `OK netinfo iface=.. ip=.. netmask=.. gw=.. mac=.. ssid=.. heap=..`（`gyscan esp ip` 用，未连接项为 `-`） |
| `free` | `OK free total=.. free=.. min_free=.. largest_block=..`（`gyscan esp free` 用，内存 KB） |
| `lsblk` | `OK lsblk` + `[flash]`分区行 + 可选 `[sdcard]`行 + `END lsblk`（`gyscan esp lsblk` 用，Flash 分区表 + TF 卡容量） |
| `version` | `OK version <固件版本> idf=<IDF版本>`（`gyscan esp version` 用，固件版本取自 `project(... VERSION)`） |
| `push <name> <len>` | 收到 `<len>` 字节后回复 `OK push <name> <len>`（上传文件到 ESP，等同 `write`） |
| `pull <name>` | `OK pull <len>` + 原始字节（下载 ESP 文件，等同 `read`） |
| `devices` | `OK devices count=N` + 每行 `device <ip> fd=<n>` + `END devices`（列出当前 TCP 客户端） |
| `server-kill` | `OK server-kill` 并停止 1234 控制服务 |
| `server-start` | `OK server-start`（重启 1234 控制服务；已在运行则 `OK server-start already running`） |
| `reboot` | `OK reboot` 后 ESP 重启 |
| `poweroff` | `OK poweroff` 后进入深度睡眠（GPIO0 拉低唤醒） |
| `status` | `OK status ip=.. heap=.. hid=.. ssid=..` |
| `storage` | `OK storage media=sd\|ram files=N ...`（查询当前存储介质；有TF卡即 sd） |
| `ls` | 每行一个条目（目录以 `/` 结尾），`END ls count=N` 结束 |
| `read <name>` | `OK read <len>` + 原始字节 |
| `write <name> <len>` | 收到 `<len>` 字节后回复 `OK write`（写入当前介质） |
| `rm <name>` / `delete <name>` | 删除文件；TF 卡上为文件夹时**递归删除** → `OK rm <name>` |
| `run <name>` | 执行 .lua 脚本；print 输出实时回传，`END run` 或 `ERR run ...` 结束 |
| `keymap on\|off` | `OK keymap on`；`on` 后转发 `KEYLOG <文本>` 事件 |
| `KEYDATA <文本>` | 上报按键记录 → ESP 广播 `KEYLOG` 给所有客户端 |
| `scan <ip\|网段> [-p 范围]` | 实时推送 `SVC ip port`，`END scan` 结束 |
| `arp <目标IP> <网关IP>` | 启动 ARP 中间人攻击 → `OK arp start <目标IP> <网关IP>` |
| `arp stop` | 停止 ARP 中间人 → `OK arp stop` |
| `arp status` | 查询状态 → `OK arp status running=<0\|1> <详情>` |
| `ARP <抓包行>` | ARP 运行中 ESP 向所有客户端广播被劫持的抓包数据（一行一帧） |
| `type <文本>` / `key <名称>` | USB 键盘注入 |
| `close` | `OK close` 并断开 |

> 键盘记录：ESP 自身为 USB **HID 键盘设备**，按键数据由电脑端采集
> （gyscan 代理）通过 `KEYDATA` 上报，ESP 转发 `KEYLOG` 事件，
> freeclient `esp keymap start` 实时显示。

> **ARP 中间人启动**：ESP 无全键盘，启动时**自动扫描局域网**，
> 用 **上/下 + Enter** 光标选择受害主机 IP；网关从 WiFi 接口自动检测
> (检测不到再手动输入)。

> **ARP 中间人抓包/存储路由**：
> - 启用混杂模式(RX)接收被劫持的数据帧，WPA2 网络中 AP 解密并转发给 ESP
>   的 MAC，因此抓包在 WPA2 下同样可用；注入为尽力而为。
> - 已挂载可用 TF 卡：抓包追加写入 `/sdcard/arp_capture.log`（**默认不写 Flash**）。
> - 未挂载 TF 卡：打印到串口，并同步通过 `ARP <抓包行>` 回传给连接的 gyscan；
>   freeclient `esp arp <目标IP> <网关IP> -o cap.txt` 可将抓包另存到本地文件。
> - 每个抓包行为单帧记录：时间戳、源/目的 MAC、EtherType、长度与十六进制负载。

### Lua 脚本引擎

存储介质自动策略：**有 TF 卡(已挂载)** → 脚本/资源全部在 `/sdcard`（TF 卡）；
**无 TF 卡** → 脚本只保存在内存 RAM，由固件内嵌 **Lua 5.4 运行时**
（`components/lua`，源码在 `third_party/lua`）**直接从内存执行**（不写 Flash）：

```bash
gyscan esp upload demo.lua   # 无TF卡→内存RAM；有TF卡→写入TF卡
gyscan esp run demo.lua
# Hello from Lua on ESP32-S3!
# Lua says 1 1
# ...
gyscan esp rm demo.lua       # 删除文件；删除文件夹传目录名(TF卡上递归删除)
```

- 脚本 `print` / 输出经 TCP 实时回传发起 `run` 的客户端；
- 语法/运行错误返回 `ERR run <chunk>:<行号> <原因>`；
- Lua 引擎为纯 C 静态组件，不依赖任何外置运行时，惰性初始化。
- 也可直接在 **设备本地菜单** 操作：主菜单 → **Lua 脚本** →
  运行 Lua 脚本 / 删除脚本文件 / 查看脚本存储，输出实时显示在串口终端。

#### 脚本内置 net 网络模块（无需 luarocks）

固件把网络栈(lwIP / esp_http_client / esp-tls)以 Lua C 模块编译进运行时，
脚本创建即自动注册全局 `net` 表，不依赖任何 luarocks 包：

```lua
local net = require("net")

net.resolve("example.com")                      --> "93.184.216.34" | nil, err
local status, body = net.http_get("http://10.0.2.2/", 5000)   -- 支持 http/https
print("GET", status, body)

local st, resp = net.http_post("https://host/api", "x=1", "application/x-www-form-urlencoded", 5000)
print("POST", st, resp)

local reply = net.tcp_query("10.0.2.2", 19000, "ping\r\n", 4096, 5000)
print("TCP", reply)
```

- `net.http_get(url[, timeout_ms])` / `net.http_post(url, body[, content_type][, timeout_ms])`
  → 成功返回 `status, body`，失败返回 `nil, err`；HTTPS 由内置 CA 证书包自动校验；
- `net.tcp_query(host, port, payload[, max_resp][, timeout_ms])` → 原始 TCP 一问一答；
- 响应/数据上限 64KB，超限返回错误；全部为阻塞同步调用。
- 主机名自动剥掉误带的 `http://` `https://` 前缀与路径（如 `connect("https://kali.org/", 443)`）。

#### LuaSocket 兼容 `socket` / `socket.http`（无需 luarocks）

为了让 LuaSocket 风格的脚本直接运行（如 `freeclient/prot.lua` 的端口扫描），
固件还内置了 LuaSocket 常用子集：

```lua
local socket = require("socket")          -- 顶层模块
local sock = socket.tcp()                 -- 创建 TCP 对象
sock:settimeout(0.5)                      -- 超时(秒)
local ok, err = sock:connect("kali.org", 443)   -- err=="timeout" 表示超时
if ok then
  sock:send("GET / HTTP/1.0\r\n\r\n")
  print(sock:receive("*l"))               -- 读一行 / "*a" 全部 / 数字=精确字节
  sock:close()
end

local http = require("socket.http")
local body, code = http.request("http://host/")   -- 或 POST: http.request(url, body)
print(code, body)
```

支持（客户端+服务端+事件循环，兼容 LuaSocket 常见写法）：
`socket.tcp()`、`socket.connect()`、`socket.bind(host, port[, backlog])`、
`socket.select(readt[, writet[, timeout]])`、`socket.gettime()`、`socket.sleep()`，
TCP 对象方法 `bind/listen/accept/connect/send/receive/settimeout/setoption/
getpeername/getsockname/close`，及 `socket.http.request`。

UDP 也已内置：
- `socket.udp()`，方法 `settimeout/connect/setpeername/send/sendto/
  receive/receivefrom/getsockname/close`；
- 额外模块：`require("socket.dns")`（`toip`）、`require("mime")`
  （`b64`/`unb64`，HTTP Basic 认证、SMTP 等常用）。

- `settimeout(t)`：`t<0/省略`=阻塞，`t=0`=非阻塞，`t>0`=有界等待；
- `accept()` 无连接时返回 `nil,"timeout"`；`receive()` 支持 `"*l"` 行 /
  `"*a"` 全部 / 数字精确字节；断开会返回 `nil,"closed"`；
- `freeclient/server.lua`（多客户端聊天室, bind+select+accept+广播）已在此库上跑通；
- HTTPS 仍建议使用 `net.http_get`（esp-tls + CA 证书包）。

#### `openssl` X.509 证书解析（基于 mbedTLS，无需 luarocks）

```lua
local ssl = require("openssl")
local cert, err = ssl.x509.read(pem_or_der)   -- PEM / DER 均可
if cert then
  print(cert:subject())      -- 如 CN=example.com
  print(cert:issuer())
  print(cert:notBefore())    -- unix 秒
  print(cert:notAfter())
  print(cert:checkhost("example.com"))  -- 校验域名/SAN(含 *. 通配)
end
```

##### 固件嵌入SSL证书（无需上传文件）

固件已内置完整 SSL 证书 `server.crt` / `server.key`（CN=espgyscan.local，含完整 X509v3 扩展，有效期 10 年），脚本可直接读取，无需上传文件：

```lua
local ssl = require("openssl")

-- 读取固件嵌入的证书（无需文件系统）
local cert = ssl.x509.read_embedded("server.crt")
if cert then
  print("Subject: " .. cert:subject())
  print("Issuer:  " .. cert:issuer())
  print("Valid:   " .. cert:notBefore() .. " ~ " .. cert:notAfter())
else
  print("embedded cert not found")
end

-- 也可读取嵌入的私钥（仅用于调试输出，不导出私钥内容）
local key = ssl.x509.read_embedded("server.key")
```

> **注意**：嵌入的证书为自签名 SSL 证书（`main/data/server.crt`），含完整 X509v3 扩展（SAN、密钥用法、扩展密钥用法），可用于开发测试。生产环境请替换为自己的证书后重新编译，或上传自定义证书到 TF 卡用 `ssl.x509.read()` 读取。

- `freeclient/ssl.lua`（证书文件检查：subject/issuer/有效期/域名匹配）使用的 API 均已内置；
- 证书文件需上传到已挂载 TF 卡(如 `/sdcard/server.crt`)，脚本内用绝对路径打开，
  或直接把 PEM/DER 内容作为字符串传入 `ssl.x509.read()`（RAM 脚本无真实文件系统路径）。

## 环境要求

- 已安装 ESP-IDF（本仓库在 v6.0.2 下验证），执行 `idf.py --version` 确认
- 首次构建需要联网拉取托管组件 `espressif/led_strip`、`espressif/esp_tinyusb`

## 配置

`idf.py menuconfig` → **gyscan Configuration**：

| 配置项 | 默认值 | 说明 |
| ------ | ------ | ---- |
| WiFi SSID / 密码 | `MyWiFi` | 自动连接的 WiFi |
| HTTP 服务器端口 | `80` | curl/wget/浏览器访问的端口 |
| 远程控制 TCP 端口 | `1234` | 后期功能，暂未启用 |
| 蓝牙扫描时长 | `5000ms` | "蓝牙探测"持续时间 |

## 构建与烧录

```bash
# 1. 设置目标芯片（首次）
idf.py set-target esp32s3

# 2. （可选）配置 WiFi 等

### Lua 内置 pcap 库（WiFi 混杂模式抓包）

固件内置 `pcap` 模块，基于 ESP-IDF 原生 `esp_wifi` 混杂模式（与 `arp_mitm` 同一套 API），**无需 libpcap / luarocks**。脚本可直接抓取 WiFi 数据帧，适用于被动流量分析、协议调试等场景。

> **前提**：ESP 必须已连接 WiFi（AP 解密后转发给本机的明文数据帧）；仅支持**单个活跃 handle**。

```lua
-- 开启抓包（可选 snaplen，默认 256 字节）
local h = pcap.open()
if not h then print("open failed"); return end

-- 可选：设置简易过滤字符串（nil 清除）
pcap.filter(h, "ip tcp")

-- 循环抓 10 帧，每帧最多等 1 秒
for i = 1, 10 do
  local f = pcap.next(h, 1000)
  if not f then print("timeout"); break end
  -- f = { data, src, dst, ethertype, timestamp, length, rssi }
  print(string.format("[%u] %s -> %s eth=0x%04x len=%u rssi=%d",
        f.timestamp, f.src, f.dst, fethertype, f.length, f.rssi))
end

pcap.close(h)
```

#### API 速查

| 函数 | 签名 | 返回值 | 说明 |
| ---- | ---- | ------ | ---- |
| `pcap.open` | `([snaplen])` | `handle` \| `nil, err` | 开启 WiFi 混杂模式抓包，返回句柄 |
| `pcap.next` | `(handle[, timeout_ms])` | `frame` \| `nil` | 取下一帧；`timeout_ms` 省略则阻塞等待，超时返回 `nil` |
| `pcap.close` | `(handle)` | `true` | 关闭抓包，恢复 WiFi 省电模式 |
| `pcap.filter` | `(handle[, bpf])` | `true` | 设置/清除简易过滤字符串（`nil` 或省略清除） |
| `pcap.interfaces` | `()` | `{ "wlan0", ... }` | 可用抓包接口列表 |
| `pcap.parse` | `(data[, offset])` | `{src,dst,ethertype,payload}` | 解析 802.3 以太网头（原始字节 → 字段） |

#### frame 字段说明

`pcap.next` 返回的帧表包含：

| 字段 | 类型 | 说明 |
| ---- | ---- | ---- |
| `data` | string | 内层 LLC/SNAP 负载原始字节（已被 snaplen 截断） |
| `src` | string | 源 MAC 地址，如 `"aa:bb:cc:dd:ee:ff"` |
| `dst` | string | 目的 MAC 地址 |
| `ethertype` | integer | 以太网类型，如 `0x0800`=IPv4, `0x0806`=ARP |
| `timestamp` | integer | 时间戳（微秒，`esp_timer_get_time` 派生） |
| `length` | integer | `data` 实际长度 |
| `rssi` | integer | 信号强度（dBm） |

#### 实现要点

- **混杂模式回调**运行在 WiFi RX 任务上下文，仅做帧快照（malloc → 队列），快速返回
- 解析逻辑与 `arp_mitm.promisc_rx_cb` 一致：仅处理 Data 帧（type=2），支持 QoS Data（头长 26 字节），从 LLC/SNAP 偏移 +6 处提取 ethertype
- 捕获期间自动 `esp_wifi_set_ps(WIFI_PS_NONE)` 关闭省电，`pcap.close` 或 `__gc` 时恢复 `WIFI_PS_MIN_MODEM`
- 句柄带 `__gc` 元方法，脚本忘写 `pcap.close` 时也能自动清理

### Lua 内置 BLE 库（NimBLE 扫描/配对）

固件内置 `ble` 模块，基于 ESP-IDF 原生 NimBLE 协议栈（与 `ble_scan.c` 同一套 API），**无需 luarocks**。脚本可直接扫描附近 BLE 广播设备、查询状态、发起配对。ESP32-S3 仅支持 BLE（不支持经典蓝牙）。

```lua
-- 查询蓝牙状态
print(ble.status())   -- "已就绪" / "未启用"

-- 扫描附近 BLE 设备（默认 5 秒，可指定毫秒数）
local devs = ble.scan(5000)
if devs then
  for i, d in ipairs(devs) do
    print(string.format("[%d] %-20s %s  RSSI: %d dBm", i, d.name, d.addr, d.rssi))
  end
end

-- 与指定地址的设备配对（阻塞，直到成功/超时）
local ok, err = ble.pair("aa:bb:cc:dd:ee:ff")
if ok then print("paired") else print("pair failed: " .. err) end

-- 断开当前连接
ble.disconnect()
```

#### API 速查

| 函数 | 签名 | 返回值 | 说明 |
| ---- | ---- | ------ | ---- |
| `ble.scan` | `([duration_ms])` | `{ devices }` \| `nil, err` | 扫描附近 BLE 设备；duration 范围 500..60000 ms，默认 5000 |
| `ble.status` | `()` | string | 蓝牙状态文本，如 "已就绪"/"未启用" |
| `ble.pair` | `(addr)` | `true` \| `nil, err` | 连接并配对指定地址（格式 `aa:bb:cc:dd:ee:ff`） |
| `ble.disconnect` | `()` | `true` \| `nil, err` | 断开当前 BLE 连接 |

#### device 字段说明

`ble.scan` 返回的设备表中，每个设备包含：

| 字段 | 类型 | 说明 |
| ---- | ---- | ---- |
| `name` | string | 设备广播名（解析自 Advertising Data），无名称时为 `"<无名称>"` |
| `addr` | string | BLE 地址，如 `"aa:bb:cc:dd:ee:ff"` |
| `rssi` | integer | 信号强度（dBm） |

#### 实现要点

- 底层调用 `ble_scan_perform()` / `ble_pair_address()` / `ble_disconnect()`，均为 ble_scan.c 新增的非交互式 API
- 扫描使用被动扫描（`passive=1`）、自动过滤重复广播（`filter_duplicates=1`）
- 配对流程：连接（15s 超时）→ 发起加密（20s 超时），共享 `ble_gap_event_handler` GAP 事件回调
- 扫描/配对期间阻塞 Lua 协程（`xSemaphoreTake`），不占用额外任务栈
- 地址解析支持 `aa:bb:cc:dd:ee:ff` 冒号分隔格式，自动识别为随机地址类型


idf.py menuconfig

# 3. 编译（注意：芯片 16MB，已按 8MB Flash 配置烧录）
idf.py build

# 4. 烧录并打开串口监视器（波特率 115200）
idf.py -p /dev/ttyUSB0 flash monitor
```

> 退出串口监视器：`Ctrl+]`

## Flash 说明

- 芯片：**16MB** Flash
- 烧录配置：**8MB**（`CONFIG_ESPTOOLPY_FLASHSIZE_8MB=y`）
- 分区表：自定义（nvs + phy_init + **4MB app**），见 `partitions.csv`

## LED 引脚说明

| 开发板 | LED | GPIO |
| ------ | --- | ---- |
| ESP32-S3-DevKitC-1 v1.0 | WS2812 RGB | GPIO48 |
| ESP32-S3-DevKitC-1 v1.1+ | WS2812 RGB | GPIO38 |
| 自接普通 LED | GPIO 电平 | 任意空闲 GPIO |

如需使用普通 GPIO LED，在 `idf.py menuconfig` → **Blink Configuration** → 将 LED 类型改为 `GPIO`，并修改 GPIO 号。

## 项目结构

```
espgyscan/
├── CMakeLists.txt          # 顶层 CMake
├── partitions.csv          # 自定义分区表（8MB / 4MB app + storage）
├── sdkconfig.defaults      # 默认配置（目标芯片、蓝牙、Flash、TinyUSB 等）
├── main/                   # ESP-IDF main 组件（仅构建配置）
│   ├── CMakeLists.txt      # 引用 ../src 源码
│   ├── Kconfig.projbuild   # menuconfig 选项定义
│   └── idf_component.yml   # 托管组件依赖（led_strip、esp_tinyusb）
├── components/lua/         # Lua 引擎 IDF 组件（lua_embed.c / include/）
├── third_party/lua/        # Lua 5.4.7 官方源码（纯 C，静态编译进固件）
├── src/                    # 【全部固件源码】
│   ├── espgyscan.c         # 主程序：主菜单 + 后台任务
│   ├── menu.c / menu.h     # 菜单框架（WASD/方向键/ESC/Enter、多级菜单、行输入）
│   ├── i18n.c / i18n.h     # 界面国际化（中/英）
│   ├── wifi_scan.c / .h    # WiFi 连接/运行时SSID配置/断开/状态
│   ├── ble_scan.c / .h     # BLE 探测 + 蓝牙配对(可ESC取消) + 状态
│   ├── tcp_client.c / .h   # TCP 客户端（连接 Go 程序）
│   ├── hid_keyboard.c / .h # USB HID 键盘设备
│   ├── http_server.c / .h  # HTTP 状态服务
│   ├── tcp_server.c / .h   # gyscan 控制服务器(1234)
│   ├── script_store.c / .h # 脚本存储(自动: TF卡 或 内存RAM, 不写Flash) + run(Lua)执行
│   ├── lua/lua_net.c / .h  # 内置 Lua net 模块(HTTP/HTTPS/DNS/TCP, 无需 luarocks)
│   ├── lua/lua_pcap.c / .h  # 内置 Lua pcap 模块(WiFi 混杂模式抓包, 无需 libpcap)
│   ├── lua/lua_ble.c / .h   # 内置 Lua BLE 模块(NimBLE 扫描/配对, 无需 luarocks)
│   ├── net_scan.c / .h     # 网段/端口扫描
│   ├── net_scan.c / .h     # 网段/端口扫描
│   ├── net_scan.c / .h     # 网段/端口扫描
│   └── arp_mitm.c / .h     # ARP 中间人(ARP MITM)攻击
├── freeclient/             # gyscan 主程序(Go, cobra CLI)
├── tools/
│   └── gyscan_client.go    # Go 远程控制客户端（后期 1234 端口使用）
└── .gitignore
```

### 主菜单（国际化 + 状态总览）

```
----- 欢迎使用esp-gyscan----     ← 顶部实时显示
网络：已连接 MyWiFi (192.168.1.5)
蓝牙：BLE 已就绪
内存：xxx KB / xxx KB
储存(Flash)：16 MB
---- 主菜单----
> WiFi 设置
  蓝牙设置
  边缘安全
  Lua 脚本       ← 运行/删除脚本、查看脚本存储(自动介质)
  TF 卡设置
  语言            ← 主菜单语言切换(中文 / English)
```

- **语言切换**：主菜单 → 语言 → 中文/English，全部界面实时切换
- **欢迎信息状态**：网络(WiFi 连接/SSID/IP)、蓝牙状态实时显示
- **蓝牙配对可取消**：扫描/连接/配对阶段均可用 `ESC` 取消

## 常见问题

- **USB 键盘未枚举**：用 USB 线连接 ESP32-S3 的 **USB-OTG 口**（不是串口口）到电脑；
  电脑应识别到 "gyscan Keyboard" 输入设备
- **curl 无法访问**：确认 ESP 已连上 WiFi、手机/电脑与 ESP 在同一局域网；
  菜单 → "HTTP 状态" 可查看 IP 与服务器状态
- **WS2812 灯珠不亮**：确认开发板版本对应的 GPIO（v1.0=48, v1.1+=38）
- **蓝牙探测无结果**：确认周围存在正在广播的 BLE 设备；可调大"蓝牙扫描时长"
- **烧录失败**：检查串口设备号（`ls /dev/ttyUSB*` / `/dev/ttyACM*`），并按住开发板 `BOOT` 键再上电进入下载模式

## QEMU 环境（无硬件调试）

可用 `idf.py qemu monitor` 在 QEMU 中运行本固件，主要用于测试**菜单交互**：

```bash
idf.py qemu monitor     # 首次会自动构建并生成 qemu_flash.bin
```

QEMU 模拟限制说明（固件已做容错，不影响菜单运行）：

| 功能 | QEMU 支持 | 说明 |
| ---- | --------- | ---- |
| 菜单交互 | ✅ | WASD/方向键/ESC/Enter 均可操作 |
| **网络(以太网)** | ✅ | 默认开启 openeth，见下方"QEMU 网络" |
| USB HID 键盘 | ❌ | QEMU 不模拟 USB-OTG，后台自动跳过（不再报错） |
| WS2812 LED | ❌ | QEMU 不模拟 RMT，后台自动跳过 |
| WiFi | ❌ | QEMU 无 WiFi 射频，固件自动转入以太网 |

> 若需在 QEMU 下完全关闭 USB HID 报错日志，可在 menuconfig 中
> 关闭 **gyscan Configuration → 启用 USB HID 键盘设备**（`CONFIG_GYSCAN_ENABLE_USB_HID`）。

### QEMU 网络（以太网 openeth）

QEMU 的 `-nic user,model=open_eth` 模拟的是**以太网卡**（不是 WiFi），
因此固件内置了 QEMU 专用网卡驱动（`eth_netif.c`，OpenCores MAC）：

```bash
# 1) QEMU 以太网已默认开启（sdkconfig 已含 CONFIG_ETH_USE_OPENETH=y）。
#    真机无 EMAC，请勿在真机固件开启此项；如需关闭：
idf.py menuconfig
#   → Component config → Ethernet → Support OpenCores Ethernet MAC (for use with QEMU)  ☑
#   （等效：sdkconfig 写入/移除 CONFIG_ETH_USE_OPENETH=y）

# 2) 构建 + 带网卡与端口转发启动（推荐：idf.py qemu 直接带转发）
idf.py build
idf.py qemu monitor --qemu-extra-args="-nic user,model=open_eth,hostfwd=tcp::1234-:1234,hostfwd=tcp::8080-:80"

# 3) 或手动启动 QEMU
QEMU=~/.espressif/tools/qemu-xtensa/*/qemu/bin/qemu-system-xtensa
$QEMU -M esp32s3 -m 32M \
  -drive file=build/qemu_flash.bin,if=mtd,format=raw \
  -global driver=timer.esp32s3.timg,property=wdt_disable,value=true \
  -nic user,model=open_eth,hostfwd=tcp::1234-:1234,hostfwd=tcp::8080-:80 \
  -nographic -serial tcp::5555,server
```

启动后固件会**自动：WiFi 尝试 + 以太网(openeth)并行**，以太网拿到 DHCP IP
后即启动 HTTP(80) 与 gyscan 控制(1234)。宿主机经转发访问：

> **hostfwd 必须带**：QEMU user 网络下宿主机无法直接访问客户机 IP(10.0.2.15)，
> 只能通过 `hostfwd` 转发访问客户机的端口。

```bash
curl http://127.0.0.1:8080/        # → ESP-GYscan:ok（可被 gyscan 连接）
printf 'hello\r\n' | nc 127.0.0.1 1234   # → OK hello espgyscan
```

> 说明：真机（ESP32-S3 无 EMAC 外设）请保持 `CONFIG_ETH_USE_OPENETH=n`，
> openeth 仅用于 QEMU。若在 QEMU 下发现 TCP 数据面异常，属模拟器限制，
> 可在真实硬件上验证。

#### QEMU 下已知的模拟器怪癖（固件已兼容）

| 现象 | 说明 |
| ---- | ---- |
| 串口出现 `Failed to add multicast filter` 等 `E` 日志 | openeth 无硬件组播地址过滤，lwIP 组播加过滤必然失败，**无害** |
| DHCP 已拿到 IP 但始终无 `Ethernet Got IP` 日志 | QEMU 下 esp_event 事件循环可能不再调度 `IP_EVENT_ETH_GOT_IP`；固件会**直接轮询 netif IP**（`eth_has_ip()`）兑底，HTTP/1234 服务照常启动 |
| 主界面网络一栏显示“未启用/未连接” | 状态在按键刷新时重绘；以太网就绪后按任意键即显示 `已连接 以太网 (10.0.2.15)` |




