# minishark 测试套件

## 协议解析测试 (`test_protocol`)

手工构造原始包缓冲区，全面测试各协议解析器的边界检查和异常处理能力。

### 测试范围

| 模块 | 测试用例数 | 覆盖内容 |
|------|-----------|---------|
| `parse_eth` | 6 | 正常 IPv4/IPv6、空指针、截断、零长度、VLAN 标签 |
| `parse_ipv4` | 11 | 正常 TCP/UDP/ICMP、空指针、截断、版本错误、IHL 越界、total_len < IHL、非首分片 |
| `parse_ipv6` | 5 | 正常 TCP、扩展头链（HBH）、空指针、截断、版本错误 |
| `parse_tcp` | 4 | 正常、空指针、截断、data_off 非法 |
| `parse_udp` | 4 | 正常、空指针、截断、length < 8 |
| `parse_icmp` | 4 | 正常 v4/v6 Echo、空指针、截断 |
| `parse_dns` | 6 | 正常查询/响应、截断、超大 qdcount（防 DoS）、畸形标签、空指针 |
| `parse_http` | 9 | GET/POST、200/404/500 响应、空指针、空数据、二进制数据、未完成行 |
| 综合畸形包 | 4 | 多层截断（eth→IPv4→TCP）、DNS 无限指针循环 |

共计 **53 个测试用例**。

### 编译与运行

```bash
# 在项目根目录执行
make test          # 编译并运行测试（静默模式，只显示结果摘要）
make test-verbose  # 编译并运行测试（显示完整解析输出）
```

或直接编译运行：

```bash
gcc -Wall -Wextra -O2 -g -Iinclude tests/test_protocol.c src/protocol.c -o tests/test_protocol
./tests/test_protocol
```

### 通过标准

每个测试用例通过条件：
- **正常包**：parser 返回 0（成功）
- **截断/畸形包**：parser 返回 -1（明确拒绝）或 0（静默跳过，如非首分片）
- **极端值**：parser 不崩溃、不进入死循环
