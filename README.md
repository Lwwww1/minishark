# Minishark — 轻量级网络包嗅探器 & 协议解析器

基于 **libpcap** 的轻量级网络包嗅探与协议分析工具。从链路层到应用层逐层解析，支持实时抓包、BPF 过滤、PCAP 文件读写、DNS/HTTP 解析和实时流量统计。

> **项目信息**: 题目 #07 | 双人协作 | 周期 2 周（10 个工作日）  
> **当前阶段**: 基础功能已完成（抓包、过滤、解析、统计、文件读写）  
> **开发文档**: [项目开发计划书](doc/项目开发计划书.md)

---

## 目录

- [架构总览](#架构总览)
- [环境要求](#环境要求)
- [构建](#构建)
- [快速开始](#快速开始)
- [命令行选项](#命令行选项)
- [基础功能使用](#基础功能使用)
  - [实时抓包](#1-实时抓包--i)
  - [BPF 过滤](#2-bpf-过滤--f)
  - [写入文件](#3-写入文件--w)
  - [离线回放](#4-离线回放--r)
  - [组合使用](#5-组合使用)
- [协议解析输出说明](#协议解析输出说明)
- [流量统计](#流量统计)
- [测试](#测试)
- [模块详解](#模块详解)
- [支持的协议](#支持的协议)
- [项目结构](#项目结构)
- [开发计划对照](#开发计划对照)
- [注意事项](#注意事项)

---

## 架构总览

```
main.c              — 入口，CLI 参数解析，抓包循环
├── capture.c/h     — libpcap 抓包引擎（混杂模式，回调分发）
├── filter.c/h      — BPF 过滤器编译与应用
├── pcap_io.c/h     — PCAP 文件读写（-w 实时保存，-r 离线回放）
├── protocol.c/h    — 协议解析：ETH → IPv4/IPv6 → TCP/UDP/ICMP → DNS/HTTP
└── stats.c/h       — 实时流量统计（每秒刷新）
```

**解析调用链**:

```
dispatch_packet()
  └─ parse_eth()              —— 以太网帧（L2）
       ├─ parse_ipv4()        —— IPv4（L3）
       │    ├─ parse_tcp()    —— TCP（L4）→ parse_http()
       │    ├─ parse_udp()    —— UDP（L4）→ parse_dns()
       │    └─ parse_icmp()   —— ICMP（L4）
       └─ parse_ipv6()        —— IPv6（L3，支持扩展头遍历）
            ├─ parse_tcp()
            ├─ parse_udp()
            └─ parse_icmp()
```

---

## 环境要求

| 依赖 | 说明 |
|------|------|
| **libpcap**（必需） | 底层抓包引擎，Windows 下为 [Npcap](https://npcap.com/) |
| **GCC / MinGW**（必需） | 编译工具链 |
| **make**（可选） | 使用 Makefile 构建 |

### Windows 环境搭建

1. 安装 [Npcap](https://npcap.com/)（勾选 "Install in WinPcap API-compatible Mode"）
2. 安装 [MSYS2](https://www.msys2.org/) → `pacman -S mingw-w64-ucrt-x86_64-gcc mingw-w64-ucrt-x86_64-pkg-config make`
3. 安装 libpcap for MinGW：
   ```bash
   pacman -S mingw-w64-ucrt-x86_64-libpcap
   ```
4. 将 `ucrt64/bin` 加入系统 PATH
5. 在 MSYS2 或 Git Bash 下执行构建

### Linux 环境搭建

```bash
sudo apt install build-essential libpcap-dev     # Debian/Ubuntu
sudo dnf install gcc make libpcap-devel          # Fedora
```

---

## 构建

```bash
# 编译主程序
make

# 编译并运行（需 root / 管理员权限）
make run

# 编译并运行协议解析单元测试（无需 root）
make test

# 详细模式运行测试（输出每个用例的解析日志）
make test-verbose

# 清理构建产物
make clean
```

输出目标文件为 `my_sniffer`（Linux）或 `my_sniffer.exe`（Windows）。

### 手动编译

```bash
gcc -Wall -Wextra -O2 -g -Iinclude \
    src/main.c src/capture.c src/filter.c \
    src/protocol.c src/stats.c src/pcap_io.c \
    -lpcap -lncurses -o my_sniffer
```

---

## 快速开始

```bash
# 1. 查看帮助
./my_sniffer -h

# 2. 自动选择网卡捕获所有流量（Ctrl+C 停止）
sudo ./my_sniffer

# 3. 仅捕获 HTTP 流量
sudo ./my_sniffer -f "tcp port 80"

# 4. 捕获并保存到文件
sudo ./my_sniffer -f "udp port 53" -w dns_only.pcap

# 5. 离线回放之前保存的文件
./my_sniffer -r dns_only.pcap
```

---

## 命令行选项

```
Usage: my_sniffer [options]
Options:
  -i <iface>   网络接口名称（默认：自动选择第一个可用接口）
  -f <filter>  BPF 过滤表达式（如 "tcp port 80"，默认：无过滤）
  -r <file>    从 PCAP 文件读取并回放数据包
  -w <file>    将实时捕获的数据包写入 PCAP 文件
  -h           显示帮助信息
```

### 获取网卡列表

```bash
# Linux
ip link show
tcpdump --list-interfaces

# Windows（Npcap）
.\my_sniffer.exe -i help
# 或从设备管理器 / Npcap 控制台获取 \Device\NPF_{...}
```

---

## 基础功能使用

### 1. 实时抓包 (`-i`)

不指定 `-i` 时自动选择第一个可用接口：

```bash
# 全量捕获（所有流量）
sudo ./my_sniffer

# 指定接口捕获
sudo ./my_sniffer -i eth0
sudo ./my_sniffer -i "Wi-Fi"         # Windows
sudo ./my_sniffer -i enp0s3          # Linux
```

### 2. BPF 过滤 (`-f`)

使用 Berkeley Packet Filter 语法过滤流量：

```bash
# 按协议
sudo ./my_sniffer -f "tcp"
sudo ./my_sniffer -f "udp"
sudo ./my_sniffer -f "icmp"

# 按端口
sudo ./my_sniffer -f "tcp port 80"          # HTTP
sudo ./my_sniffer -f "tcp port 443"         # HTTPS
sudo ./my_sniffer -f "udp port 53"          # DNS
sudo ./my_sniffer -f "tcp port 22"          # SSH

# 按主机
sudo ./my_sniffer -f "host 192.168.1.1"
sudo ./my_sniffer -f "src host 10.0.0.1"
sudo ./my_sniffer -f "dst host 8.8.8.8"

# 复合条件
sudo ./my_sniffer -f "tcp port 80 and host 192.168.1.100"
sudo ./my_sniffer -f "tcp port 80 or udp port 53"
sudo ./my_sniffer -f "not arp and not icmp"
```

**测试过滤功能**：
```bash
# 终端 1：启动嗅探器过滤 HTTP
sudo ./my_sniffer -f "tcp port 80"

# 终端 2：发 HTTP 请求验证
curl http://example.com
```

### 3. 写入文件 (`-w`)

将实时捕获的数据包保存为 PCAP 文件，可用 Wireshark 或 `-r` 回放：

```bash
# 捕获 HTTP 流量并保存
sudo ./my_sniffer -f "tcp port 80" -w http_capture.pcap

# 捕获全量流量保存
sudo ./my_sniffer -w full_capture.pcap
```

**验证保存的文件**：
```bash
# 方法 1：用本工具回放
./my_sniffer -r http_capture.pcap

# 方法 2：用 Wireshark / tcpdump 打开
tcpdump -r http_capture.pcap
wireshark http_capture.pcap
```

### 4. 离线回放 (`-r`)

从之前保存的 PCAP 文件读取数据包，解析输出到终端。**无需 root 权限**：

```bash
# 基本回放
./my_sniffer -r http_capture.pcap

# 回放 + 过滤（只分析回放文件中符合条件的包）
./my_sniffer -r full_capture.pcap -f "udp port 53"

# 使用测试用 PCAP 文件
wget https://wiki.wireshark.org/SampleCaptures/http.cap
./my_sniffer -r http.cap
```

### 5. 组合使用

```bash
# 实时抓 UDP 53 端口的 DNS 流量 + 保存到文件
sudo ./my_sniffer -f "udp port 53" -w dns.pcap

# 离线回放 DNS 文件 + 再过滤到特定主机
./my_sniffer -r dns.pcap -f "host 8.8.8.8"

# 完整链路：先抓包保存，再离线分析
sudo ./my_sniffer -i eth0 -f "tcp port 80 or tcp port 443" -w session.pcap
./my_sniffer -r session.pcap | head -100
```

---

## 协议解析输出说明

每个数据包从链路层到应用层逐层打印一行摘要。

### 链路层 — Ethernet

```
ETH : aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66 | type=0x0800(IPv4)
```

- `aa:bb:cc:dd:ee:ff` = 源 MAC，`11:22:33:44:55:66` = 目的 MAC
- `type=0x0800(IPv4)` / `0x86DD(IPv6)` / `0x0806(ARP)`
- 如为 **VLAN 标签帧**（type=0x8100），自动解析并打印内层 EtherType：
  ```
  ETH : ... | type=0x8100(VLAN)
    [VLAN: PCP=0 DEI=0 VID=100]
  ETH :   inner type=0x0800(IPv4)
  ```

### 网络层 — IPv4

```
IPv4: 192.168.1.100 -> 93.184.216.34 | proto=6(TCP) ttl=64 ihl=20 total_len=1500 id=0x3a2b frag=@0 cksum=0xabcd
```

- `proto=6(TCP)` / `17(UDP)` / `1(ICMP)`
- `frag=DF@0` = DF 标志 + 片偏移，非首分片自动跳过

### 网络层 — IPv6

```
IPv6: 2001:db8::1 -> 2606:2800:220::1 | next=6(TCP) hlim=64 plen=1440 tc=0x00 fl=0x00000
```

- 自动遍历 IPv6 扩展头（Hop-by-Hop、Routing、Fragment、Dest Opt、AH）
- 遇 Fragment Header 且非首分片时自动跳过
- 扩展头信息实时打印：
  ```
    [IPv6 Fragment: next=6 offset=0 mf=0 id=0xabcdef01]
  ```

### 传输层 — TCP

```
TCP : 49234 -> 80 | seq=0x12345678 ack=0x87654321 flags=SYN win=65535 cksum=0xabcd urg=0 hdr=20
TCP : 49234 -> 80 | seq=0x12345679 ack=0x87654322 flags=PSH+ACK win=65535 cksum=0xabcd urg=0 hdr=20
```

- 标志位字符串：`SYN` / `SYN+ACK` / `PSH+ACK` / `FIN+ACK` / `RST` / `None`
- 常见应用层自动附加解析：端口 80/8080 → HTTP

### 传输层 — UDP

```
UDP : 5353 -> 53 | len=48 cksum=0xabcd
```

- 端口 53 自动附加 DNS 解析

### 传输层 — ICMP / ICMPv6

```
ICMP: type=8(Echo Request) code=0 cksum=0xabcd id=1 seq=1
ICMPv6: type=128(Echo Request) code=0 cksum=0xabcd id=1 seq=1
```

- 支持 15 种 ICMPv4 类型、13 种 ICMPv6 类型（含 NDP、MLD）

### 应用层 — DNS

```
DNS : id=0x1234 Query op=QUERY qd=1 an=0 ns=0 ar=1
DNS :   query[0]: www.example.com (A, class=1)
```

响应包增加回答区解析：
```
DNS : id=0x1234 Response op=QUERY qd=1 an=2 ns=0 ar=0 rcode=0(OK)
DNS :   query[0]: www.example.com (A, class=1)
DNS :   answer[0]: www.example.com -> A 93.184.216.34
DNS :   answer[1]: www.example.com -> AAAA 2606:2800:220:1:248:1893:25c8:1946
```

- 支持 A、AAAA、CNAME、NS、MX、TXT、PTR、SOA、SRV 记录类型
- DNS 域名解压支持压缩指针（RFC 1035），含循环指针防护

### 应用层 — HTTP

请求行：
```
TCP : 49234 -> 80 | seq=0x... ack=0x... flags=PSH+ACK win=... cksum=0x... urg=0 hdr=20
HTTP: GET /index.html HTTP/1.1
HTTP: POST /api/login HTTP/1.1
```

响应行：
```
HTTP: Response HTTP/1.1 200 OK
HTTP: Response HTTP/1.1 404 Not Found
HTTP: Response HTTP/1.1 500 Internal Server Error
```

- 支持 9 种 HTTP 方法：GET、POST、HEAD、PUT、DELETE、CONNECT、OPTIONS、TRACE、PATCH
- 支持 28 种 HTTP 状态码（100~504）
- 仅解析单 TCP 段内的首行，分片 HTTP 需等 TCP 重组阶段

---

## 流量统计

抓包过程中**每秒自动刷新**当前协议分布统计：

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

统计覆盖 7 个分类：TCP、UDP、ICMP、HTTP、HTTPS、DNS、OTHER。

---

## 测试

### 协议解析单元测试

```bash
make test
```

运行 53 个测试用例，覆盖：
- ✅ 各层正常协议路径（ETH→IPv4→TCP→HTTP、ETH→IPv4→UDP→DNS）
- ✅ 截断包检测
- ✅ 畸形字段检测（版本错误、IHL 越界、非法偏移）
- ✅ 异常包防御（DNS 大计数、自引用循环指针）
- ✅ VLAN 标签、IPv6 扩展头
- ✅ 空指针 / 零长度

### 端到端功能验证

```bash
# 1. 实时抓包+BPF过滤
sudo ./my_sniffer -f "tcp port 80"

# 2. 抓包+实时保存
sudo ./my_sniffer -f "udp port 53" -w dns.pcap

# 3. 离线回放
./my_sniffer -r dns.pcap

# 4. 回放+二次过滤
./my_sniffer -r dns.pcap -f "host 8.8.8.8"

# 5. 统计观察
sudo ./my_sniffer
# 同时执行 curl / nslookup / ping 查看统计变化
```

---

## 模块详解

### `capture.c` — 抓包引擎

- 基于 libpcap 的 `pcap_loop()` 事件驱动抓包
- 自动选择网卡或用户通过 `-i` 指定
- 32MB 内核缓冲区，高流量下降低丢包
- 数据结构链路层校验（仅支持 DLT_EN10MB）
- `SIGINT` / `SIGTERM` 安全终止

### `filter.c` — BPF 过滤器

- 封装 `pcap_compile()` + `pcap_setfilter()`
- 支持完整 BPF 表达式语法（同 tcpdump）
- 实时抓包和离线回放均支持过滤

### `protocol.c` — 协议解析

逐层解析链路层到应用层，完整边界检查与健壮性保障：

- 所有 parser 均执行空指针、长度不足、字段越界检查
- IPv4：版本/IHL/total_len 校验、分片处理、扩展选项头边界检查
- IPv6：扩展头链自动遍历（HBH/RH/FH/DOH/AH/ESP），64 层深度上限
- TCP：data_off 范围校验 (`5 ≤ data_off ≤ 15`)、options 边界保护
- UDP：length 字段校验 (`≥ 8`) 与缓冲区一致性检查
- ICMP：完整类型名称映射（v4 15 种 + v6 13 种）
- DNS：计数上限（256）、循环指针检测（255 跳上限）、非对齐内存安全访问
- HTTP：可打印字符检查防垃圾数据、28 种状态码映射

### `pcap_io.c` — PCAP 文件读写

- 写入：实时抓包同时保存为标准 PCAP 格式（兼容 Wireshark）
- 读取：离线回放，支持 BPF 再过滤
- 文件格式：PCAP 全局头 + 每包时间戳/长度/数据

### `stats.c` — 流量统计

- 按 7 个协议分类统计包数和字节数
- 使用 `struct proto_stats` 原子累计
- 每秒自动打印统计面板

---

## 支持的协议

| 协议 | RFC | 等级 | 功能 |
|------|-----|------|------|
| Ethernet II | RFC 894 | L2 | MAC 地址解析、EtherType 分发、VLAN 标签（802.1Q） |
| IPv4 | RFC 791 | L3 | 版本/IHL/总长/标识/分片/TTL/协议号/校验和 |
| IPv6 | RFC 8200 | L3 | 版本/TC/流标签/载荷长/下一头/跳限 + 扩展头链遍历 |
| TCP | RFC 793 | L4 | 端口/SEQ/ACK/标志位字串/窗口/校验和/紧急指针 |
| UDP | RFC 768 | L4 | 端口/长度/校验和 |
| ICMP / ICMPv6 | RFC 792 / 4443 | L4 | 类型/代码/校验和/标识/序号 + 15+13 种类型名称 |
| **DNS** | RFC 1035 | **L7** | **查询域名提取、A/AAAA/CNAME 回答解析、压缩指针** |
| **HTTP** | RFC 7230 | **L7** | **请求行（9 方法）、响应行（28 状态码）** |

---

## 项目结构

```
minishark/
├── include/                # 头文件
│   ├── capture.h           # 抓包引擎接口
│   ├── common.h            # 公共宏、类型、日志
│   ├── filter.h            # BPF 过滤器接口
│   ├── pcap_io.h           # PCAP 文件读写接口
│   ├── protocol.h          # 协议结构体定义 + 解析函数声明
│   └── stats.h             # 流量统计接口
├── src/                    # 源文件
│   ├── main.c              # 入口、CLI 参数解析
│   ├── capture.c           # libpcap 抓包引擎
│   ├── filter.c            # BPF 编译/应用
│   ├── pcap_io.c           # PCAP 文件读写
│   ├── protocol.c          # 协议解析（ETH/IP/TCP/UDP/ICMP/DNS/HTTP）
│   └── stats.c             # 实时流量统计
├── tests/                  # 测试
│   ├── test_protocol.c     # 协议解析单元测试（53 用例）
│   └── README.md           # 测试说明
├── doc/
│   └── 项目开发计划书.md    # 开发计划与团队分工
├── Makefile                # 构建脚本
└── README.md               # 本文件
```

**待开发模块**（第二周选做）：

| 模块 | 文件 | 功能 |
|------|------|------|
| 环形缓冲区 | `ring_buffer.c/h` | 无锁队列，抓包线程→解析线程传递 |
| TCP 流重组 | `tcp_reasm.c/h` | 五元组哈希、SEQ 排序、HTTP 完整提取 |
| TLS SNI | `tls_parser.c/h` | 解析 ClientHello 提取 SNI 域名 |
| ncurses UI | `ui.c/h` | 终端界面、协议树、按键交互 |

---

## 开发计划对照

| 天次 | 功能 | 状态 |
|------|------|------|
| Day 1 | 环境搭建、项目骨架、协议头结构体 | ✅ 完成 |
| Day 2 | 抓包循环、Ethernet/IP 解析 | ✅ 完成 |
| Day 3 | TCP/UDP/ICMP 解析、BPF 过滤 | ✅ 完成 |
| Day 4 | DNS/HTTP 解析、流量统计 | ✅ 完成 |
| Day 5 | PCAP 文件读写、解析完善与边界修复 | ✅ 完成 |
| Day 6 | 环形缓冲区、TCP 流重组基础 | 📋 待开发 |
| Day 7 | TCP 重组完善、HTTP 完整提取 | 📋 待开发 |
| Day 8 | TLS SNI、ncurses UI 基础 | 📋 待开发 |
| Day 9 | ncurses UI 完善、集成联调 | 📋 待开发 |
| Day 10 | 测试、文档、收尾 | 📋 待开发 |

---

## 注意事项

1. **管理员/root 权限**：实时抓包必须具有管理员权限（`sudo` 或以管理员身份运行）
2. **Npcap 兼容模式**：Windows 安装 Npcap 时须勾选 "Install in WinPcap API-compatible Mode"
3. **离线回放无需 root**：`-r` 模式仅读文件，普通用户即可运行
4. **BPF 语法**：过滤表达式与 `tcpdump` 完全兼容
5. **分片 IP 包**：IPv4/IPv6 仅解析首分片，非首分片自动跳过
6. **HTTP 分片**：跨 TCP 段的 HTTP 需等 TCP 重组阶段（Day 6+）才能完整解析
7. **Ctrl+C 停止**：抓包循环中按 Ctrl+C 安全终止并自动清理资源
8. **日志输出**：`[ERROR]` 红色输出到 stderr，解析结果到 stdout，可独立重定向
