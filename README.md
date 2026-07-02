# Minishark — 轻量级网络包嗅探器

基于 libpcap 的协议解析与流量统计工具，支持从链路层到应用层的逐层包解析。

## 环境要求

| 依赖 | 说明 |
|---|---|
| **libpcap**（必需） | 底层抓包引擎，Windows 下为 Npcap/WinPcap |
| **GCC / MinGW**（必需） | 编译工具链 |
| **make**（可选） | 使用 Makefile 构建 |
| **ncurses**（预留） | 后续 UI 模块使用，当前未被链接（`-lncurses` 已标记为弱依赖） |

### Windows 环境准备

1. 安装 [Npcap](https://npcap.com/)（勾选 "Install in WinPcap API-compatible Mode"）
2. 安装 [MinGW-w64](https://www.mingw-w64.org/)（推荐使用 [MSYS2](https://www.msys2.org/)）
3. 将 `mingw64/bin` 加入系统 PATH
4. 在 MSYS2 或 Git Bash 下执行构建

## 构建

```bash
# 编译
make

# 仅清理
make clean

# 编译并运行（需要管理员/root 权限）
make run
```

输出目标文件为 `my_sniffer.exe`（或 `my_sniffer`）。

### 手动编译

```bash
gcc -Wall -Wextra -O2 -g -Iinclude \
    src/main.c src/capture.c src/filter.c src/protocol.c src/stats.c \
    -lpcap -lncurses -o my_sniffer
```

## 使用方法

```
Usage: my_sniffer [options]
Options:
  -i <iface>   网络接口名称（默认：自动选择）
  -f <filter>  BPF 过滤表达式（如 "tcp port 80"）
  -r <file>    PCAP 文件读取（预留）
  -w <file>    写入 PCAP 文件（预留）
  -h           显示帮助
```

### 常用示例

```bash
# 管理员/root 权限运行，自动选择网卡
sudo ./my_sniffer

# 指定网卡
sudo ./my_sniffer -i eth0

# Windows 下管理员运行
./my_sniffer -i \Device\NPF_{...}
.\my_sniffer.exe -i "Wi-Fi"

# 仅捕获 HTTP 流量
sudo ./my_sniffer -f "tcp port 80"

# 仅捕获 DNS 流量
sudo ./my_sniffer -f "udp port 53"

# 捕获所有发往特定主机的流量
sudo ./my_sniffer -f "host 192.168.1.1"

# 捕获 HTTP 和 DNS 流量
sudo ./my_sniffer -f "tcp port 80 or udp port 53"
```

### 获取网卡列表

```bash
# Windows (Npcap)
.\my_sniffer.exe -i help

# Linux
ip link show
# 或
tcpdump --list-interfaces
```

## 输出说明

每次抓包解析一行摘要，格式遵循 tcpdump 风格，从链路层逐层下钻。

### 链路层 (Ethernet)

```
ETH : aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66 | type=0x0800(IPv4)
```

### 网络层 (IPv4 / IPv6)

```
IPv4: 192.168.1.100 -> 93.184.216.34 | proto=6(TCP) ttl=64 ihl=20 total_len=1500 id=0x3a2b frag=@0 cksum=0xabcd
IPv6: 2001:db8::1 -> 2606:2800:220::1 | next=6(TCP) hlim=64 plen=1440 tc=0x00 fl=0x00000
```

### 传输层 (TCP / UDP / ICMP)

```
TCP : 49234 -> 80 | seq=0x12345678 ack=0x87654321 flags=SYN win=65535 cksum=0xabcd urg=0 hdr=20
TCP : 49234 -> 80 | seq=0x12345679 ack=0x87654322 flags=PSH+ACK win=65535 cksum=0xabcd urg=0 hdr=20
UDP : 5353 -> 53 | len=48 cksum=0xabcd
ICMP: type=8(Echo Request) code=0 cksum=0xabcd id=1 seq=1
```

### 应用层 (DNS) — 新增 Day 4

DNS 查询时解析提问区域名，响应时附加回答区中的解析结果：

```
# DNS 查询
UDP : 53530 -> 53 | len=32 cksum=0xabcd
DNS : id=0x1234 Query op=QUERY qd=1 an=0 ns=0 ar=1
DNS :   query[0]: www.example.com (A, class=1)

# DNS 响应
UDP : 53 -> 53530 | len=60 cksum=0xabcd
DNS : id=0x1234 Response op=QUERY qd=1 an=2 ns=0 ar=0 rcode=0(OK)
DNS :   query[0]: www.example.com (A, class=1)
DNS :   answer[0]: www.example.com -> A 93.184.216.34
DNS :   answer[1]: www.example.com -> AAAA 2606:2800:220:1:248:1893:25c8:1946

# CNAME 解析
DNS : id=0x5678 Response op=QUERY qd=1 an=2 ns=0 ar=0 rcode=0(OK)
DNS :   query[0]: www.github.com (A, class=1)
DNS :   answer[0]: www.github.com -> CNAME github.com
DNS :   answer[1]: github.com -> A 140.82.112.3
```

### 应用层 (HTTP) — 新增 Day 4

解析 TCP 负载中的 HTTP 请求行或响应行（仅限单包内完整首行，跨包分段由后续 TCP 重组处理）：

```
# HTTP 请求
TCP : 49234 -> 80 | seq=0x... ack=0x... flags=PSH+ACK win=... cksum=0x... urg=0 hdr=20
HTTP: GET /index.html HTTP/1.1

# HTTP 响应
TCP : 80 -> 49234 | seq=0x... ack=0x... flags=PSH+ACK win=... cksum=0x... urg=0 hdr=20
HTTP: Response HTTP/1.1 200 OK
```

### 实时流量统计

每秒钟在终端输出当前协议分布统计：

```
--------------------------------------------------
  Proto        Packets           Bytes
--------------------------------------------------
  TCP                42            32000
  UDP                15             2400
  ICMP                2              196
  HTTP               18            21400
  HTTPS              24            38500
  DNS                12             1200
--------------------------------------------------
  Total             113            95696
--------------------------------------------------
```

## 项目结构

```
minishark/
├── include/           # 头文件
│   ├── capture.h      # 抓包引擎接口
│   ├── common.h       # 公共宏、类型、日志
│   ├── filter.h       # BPF 过滤器接口
│   ├── protocol.h     # 协议结构体定义 + 解析函数声明
│   └── stats.h        # 流量统计接口
├── src/               # 源文件
│   ├── main.c         # 入口、CLI 参数解析
│   ├── capture.c      # libpcap 抓包引擎
│   ├── filter.c       # BPF 编译/应用
│   ├── protocol.c     # 协议解析实现 (ETH/IP/TCP/UDP/ICMP/DNS/HTTP)
│   └── stats.c        # 实时流量统计
├── doc/
│   └── 项目开发计划书.md   # 开发计划文档
├── Makefile
└── README.md          # 本文件
```

## 支持的协议

| 协议 | RFC | 等级 | 功能 |
|---|---|---|---|
| Ethernet II | RFC 894 | L2 | MAC 地址解析、EtherType 分发 |
| IPv4 | RFC 791 | L3 | 版本/IHL/总长/标识/分片标志/TTL/协议号/校验和 |
| IPv6 | RFC 8200 | L3 | 版本/流量类/流标签/载荷长/下一报头/跳限 |
| TCP | RFC 793 | L4 | 端口/序列号/确认号/标志位/窗口/校验和/紧急指针 |
| UDP | RFC 768 | L4 | 端口/长度/校验和 |
| ICMP / ICMPv6 | RFC 792 / RFC 4443 | L4 | 类型/代码/校验和/标识符/序号 |
| **DNS** | **RFC 1035** | **L7** | **查询域名提取、A/AAAA/CNAME 回答解析** |
| **HTTP** | **RFC 7230** | **L7** | **请求行 (方法/URI/版本)、响应行 (版本/状态码/描述)** |

## 注意事项

1. **管理员/root 权限**：抓包必须具有管理员权限（Windows 以管理员身份运行，Linux 使用 `sudo`）
2. **Npcap 兼容模式**：Windows 安装 Npcap 时须勾选 "Install in WinPcap API-compatible Mode"
3. **VLAN 帧**：当前跳过 802.1Q VLAN 标签帧
4. **分片 IP 包**：IPv4 分片包仅解析首片，非首片跳过
5. **HTTP 分片**：跨 TCP 段的 HTTP 需等 TCP 重组（Day 6+）才能完整解析
6. **Ctrl+C 停止**：抓包循环中按 Ctrl+C 安全终止并打印统计
