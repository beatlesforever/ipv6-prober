# IPv6 Abnormal Header Active Prober

## 项目简介

IPv6 Abnormal Header Active Prober 是一个基于 Python 3 和 Scapy 的命令行工具，用于构造不同类型的 IPv6 探测报文，发送到指定 IPv6 目标地址，并记录目标网络或主机的响应情况。该工具支持多种探测类型，包括普通 ICMPv6 探测、伪造源地址探测、多层扩展头链探测、真正 IPv6 分片探测、路由扩展头探测以及异常扩展头顺序探测。

探测结果可保存为 CSV 或 JSON 格式，方便后续统计分析。本工具专为课程项目设计，适用于授权实验环境中的 IPv6 网络行为研究。

### 主要特性

- **6 种探测类型**: normal、spoofed-src、ext-chain、fragment、routing、abnormal-order
- **可自定义伪造源地址**: 通过 `--spoofed-src` 参数指定
- **可变扩展头链长度**: 通过 `--chain-len` 参数控制（1-8），支持网络测量实验
- **真正的 IPv6 分片**: 使用 Scapy `fragment6()` 构造真正的分片报文，而非原子分片
- **丰富的结果字段**: 包含 ICMPv6 type/code、RTT、Hop Limit 等详细信息
- **追加写入模式**: 支持 `--append` 参数，多次实验结果可合并
- **可追踪的探测报文**: 异常探测类型的 ICMPv6 Echo Request 包含 probe\_id、seq 和可追踪 payload
- **dry-run 预览**: 使用 `show2()` 显示组装后的报文结构，更接近实际发送的报文

### 报文负载策略

- **normal 探测**：不带 Raw payload，构造标准 ICMPv6 Echo Request，以提高基线探测响应率
- **异常探测类型**（spoofed-src、ext-chain、fragment、routing、abnormal-order）：携带可追踪 payload，格式为 `ipv6-prober|探测类型|probe_id|seq`，方便抓包时区分不同探测类型的报文

## 运行环境要求

- **操作系统**: Linux（推荐 Ubuntu 20.04+，Scapy 原始套接字在 Linux 下支持最好）
- **Python 版本**: Python 3.8+
- **权限**: root 权限（发送原始套接字报文需要 sudo）
- **网络**: 需要具备 IPv6 连接的网络环境
- **依赖**: scapy >= 2.5.0

> **注意**: 在 Windows/macOS 上，Scapy 对 IPv6 原始套接字的支持有限，部分探测类型可能无法正常工作。建议在 Linux 环境下运行。

> **网络接口**: 本工具使用 Scapy L3 发送接口，发送接口由系统 IPv6 路由表自动选择。如需确认实际出接口，请使用 `ip -6 route get <target>` 或 tcpdump/Wireshark 抓包。

## 安装方法

```bash
# 克隆或下载项目
cd ipv6_probe_tool

# 安装依赖
pip3 install -r requirements.txt

# 确认 scapy 安装成功
python3 -c "from scapy.all import IPv6; print('scapy OK')"
```

## 使用示例

### 基础用法：普通 ICMPv6 Echo Request 探测

```bash
sudo python3 main.py --target 2001:db8::1 --probe-type normal --count 1 --output results.csv
```

### 伪造源地址探测（自定义伪造源）

```bash
# 使用自定义伪造源地址（必须是合法 IPv6 格式）
sudo python3 main.py --target 2001:db8::1 --probe-type spoofed-src --spoofed-src 2001:db8:1::1

# 测试目标网络对异常源地址的处理行为
sudo python3 main.py --target 2001:db8::1 --probe-type spoofed-src --spoofed-src 2001:cafe::1 --count 3
```

### 扩展头链探测（可变链长）

```bash
# 默认链长为 2（HopByHop + DestOpt）
sudo python3 main.py --target 2001:db8::1 --probe-type ext-chain

# 测试链长为 5 的扩展头链
sudo python3 main.py --target 2001:db8::1 --probe-type ext-chain --chain-len 5

# 实验场景：测试不同链长对响应率的影响
sudo python3 main.py --target 2001:db8::1 --probe-type ext-chain --chain-len 1 --output chain_test.csv
sudo python3 main.py --target 2001:db8::1 --probe-type ext-chain --chain-len 3 --output chain_test.csv --append
sudo python3 main.py --target 2001:db8::1 --probe-type ext-chain --chain-len 5 --output chain_test.csv --append
sudo python3 main.py --target 2001:db8::1 --probe-type ext-chain --chain-len 8 --output chain_test.csv --append
```

### IPv6 分片探测（真正分片）

```bash
# 发送真正分片的 IPv6 报文（使用 fragment6 构造多个分片）
sudo python3 main.py --target 2001:db8::1 --probe-type fragment --count 1

# 预览分片报文结构
sudo python3 main.py --target 2001:db8::1 --probe-type fragment --dry-run
```

### 批量目标探测

```bash
# 从文件读取目标列表，使用分片探测
sudo python3 main.py --targets-file targets.txt --probe-type fragment --count 1

# targets.txt 文件格式（每行一个 IPv6 地址，支持 # 注释）
# 2001:db8::1
# 2001:db8::2
# 2001:db8::3
```

### 预览报文结构（dry-run 模式）

```bash
# 只打印报文结构，不真正发送（适合学习和调试）
sudo python3 main.py --target 2001:db8::1 --probe-type normal --dry-run
sudo python3 main.py --target 2001:db8::1 --probe-type ext-chain --chain-len 3 --dry-run
sudo python3 main.py --target 2001:db8::1 --probe-type fragment --dry-run
```

### 追加模式（多次实验合并结果）

```bash
# 第一次运行：创建文件
sudo python3 main.py --target 2001:db8::1 --probe-type normal --output results.csv

# 第二次运行：追加结果（不会覆盖之前的数据）
sudo python3 main.py --target 2001:db8::1 --probe-type fragment --output results.csv --append

# 第三次运行：继续追加
sudo python3 main.py --target 2001:db8::1 --probe-type routing --output results.csv --append
```

### 其他探测类型

```bash
# 路由扩展头探测（Type 0 已废弃，segleft=1，测试目标是否拒绝）
sudo python3 main.py --target 2001:db8::1 --probe-type routing --verbose

# 异常扩展头顺序探测（DestOpt 在 HopByHop 之前）
sudo python3 main.py --target 2001:db8::1 --probe-type abnormal-order --count 2

# JSON 格式输出
sudo python3 main.py --target 2001:db8::1 --probe-type ext-chain --format json --output results.json
```

## 参数说明

### 基本参数

| 参数               | 说明                   | 默认值                                  |
| ---------------- | -------------------- | ------------------------------------ |
| `--target`       | 单个目标 IPv6 地址         | 无                                    |
| `--targets-file` | 目标 IPv6 地址列表文件（每行一个） | 无                                    |
| `--probe-type`   | 探测类型（见下表）            | 必选                                   |
| `--count`        | 每个目标发送次数             | 1                                    |
| `--interval`     | 发送间隔（秒）              | 1.0                                  |
| `--timeout`      | 等待响应超时（秒）            | 2.0                                  |
| `--output`       | 输出文件路径               | results/probe\_\<类型\>\_\<时间戳\>.csv |
| `--format`       | 输出格式：csv 或 json      | csv                                  |
| `--dry-run`      | 只打印报文结构，不发送          | False                                |
| `--verbose`      | 输出详细日志               | False                                |

### 高级参数

| 参数              | 说明                  | 默认值              | 适用探测类型      |
| --------------- | ------------------- | ---------------- | ----------- |
| `--spoofed-src` | 伪造的源 IPv6 地址（需合法格式） | 2001:db8:dead::1 | spoofed-src |
| `--chain-len`   | 扩展头链长度（1-8）         | 2                | ext-chain   |
| `--append`      | 追加写入结果文件            | False            | 所有类型        |

### 探测类型说明

| 探测类型             | 说明                                  | 报文结构                                                    |
| ---------------- | ----------------------------------- | ------------------------------------------------------- |
| `normal`         | 普通 IPv6 ICMPv6 Echo Request（不带 payload） | IPv6 / ICMPv6EchoRequest                                |
| `spoofed-src`    | 伪造源地址探测（带可追踪 payload）               | IPv6(src=fake) / ICMPv6EchoRequest / Raw                |
| `ext-chain`      | 多层扩展头链探测（带可追踪 payload）              | IPv6 / HopByHop / DestOpt×N / ICMPv6EchoRequest / Raw   |
| `fragment`       | 真正 IPv6 分片探测（使用 fragment6 分片）       | IPv6 / Fragment(offset=0,m=1) / Data + 后续分片             |
| `routing`        | IPv6 路由扩展头探测（Type 0, segleft=1）     | IPv6 / Routing(type=0,segleft=1) / ICMPv6EchoRequest / Raw |
| `abnormal-order` | 异常扩展头顺序探测（带可追踪 payload）             | IPv6 / DestOpt / HopByHop / ICMPv6EchoRequest / Raw     |

## 输出字段说明

每条探测结果包含以下字段：

### 基本字段

| 字段                  | 说明                   |
| ------------------- | -------------------- |
| `probe_id`          | 本次实验唯一 ID（随机生成，用于追踪） |
| `timestamp`         | 探测时间（UTC ISO 格式）     |
| `target`            | 目标 IPv6 地址           |
| `probe_type`        | 探测类型                 |
| `packet_sent`       | 报文是否成功发送（True/False） |
| `response_received` | 是否收到响应（True/False）   |
| `response_type`     | 响应类型描述               |
| `rtt_ms`            | 往返时延（毫秒）             |
| `error`             | 错误信息（如有）             |
| `notes`             | 附加说明                 |

### 响应详情字段

| 字段                 | 说明                  |
| ------------------ | ------------------- |
| `packet_summary`   | 发送报文的 Scapy summary |
| `src_addr`         | 响应报文源地址             |
| `dst_addr`         | 响应报文目的地址            |
| `icmpv6_type`      | ICMPv6 type 字段值（数值） |
| `icmpv6_code`      | ICMPv6 code 字段值（数值） |
| `ttl_or_hlim`      | 响应报文的 Hop Limit     |
| `response_summary` | 响应报文的 Scapy summary |

### ICMPv6 Type/Code 参考值

| Type | 名称                      | 说明        |
| ---- | ----------------------- | --------- |
| 1    | Destination Unreachable | 目标不可达     |
| 2    | Packet Too Big          | 报文过大      |
| 3    | Time Exceeded           | 跳数超限/分片超时 |
| 4    | Parameter Problem       | 参数问题      |
| 128  | Echo Request            | Ping 请求   |
| 129  | Echo Reply              | Ping 响应   |

| Code (Type=1) | 说明                                        |
| ------------- | ----------------------------------------- |
| 0             | No route to destination                   |
| 1             | Communication administratively prohibited |
| 3             | Address unreachable                       |
| 4             | Port unreachable                          |

| Code (Type=2) | 说明               |
| ------------- | ---------------- |
| 0             | MTU 信息在 MTU 字段中 |

| Code (Type=3) | 说明            |
| ------------- | ------------- |
| 0             | Hop limit 超限  |
| 1             | 分片重组超时        |

| Code (Type=4) | 说明                            |
| ------------- | ----------------------------- |
| 0             | Erroneous header field        |
| 1             | Unrecognized Next Header type |
| 2             | Unrecognized IPv6 option      |

## 安全与伦理声明

本工具**仅限**在以下授权环境中使用：

- 授权实验环境
- 校园网可控靶机
- 自建云服务器

**严禁**用于以下用途：

- 未授权的网络扫描或探测
- 攻击、拒绝服务或任何破坏性操作
- 绕过安全检测或防火墙
- 任何违反当地法律法规的行为

### 内置安全限制

- 默认每秒最多发送 1 个包
- `count` 默认值为 1
- `interval` 不允许小于 0.2 秒
- `timeout` 必须大于 0
- `chain-len` 范围为 1-8
- `targets-file` 中目标数量上限为 50 个
- `--spoofed-src` 参数会校验 IPv6 格式合法性
- `dry-run` 模式可预览报文但不发送
- 不实现任何隐蔽、绕过检测、攻击放大或高频扫描功能

使用者需自行承担因不当使用带来的一切法律责任。

## 项目结构

```
ipv6_probe_tool/
  main.py            # 命令行入口，参数解析与主流程
  packet_builder.py  # 报文构造模块（PacketBuilder 类）
  prober.py          # 探测执行模块（Prober 类）
  result_writer.py   # 结果记录模块（ResultWriter 类）
  utils.py           # 工具函数（校验、安全检查、日志等）
  requirements.txt   # Python 依赖
  README.md          # 项目说明
```

## 报文构造原理

工具使用 Scapy 库构造 IPv6 报文，采用 `/` 运算符堆叠协议层：

```python
# 普通 ICMPv6 Echo Request（不带 payload）
pkt = IPv6(dst="2001:db8::1") / ICMPv6EchoRequest(id=probe_id, seq=seq)

# 扩展头链（chain_len=3，带可追踪 payload）
pkt = IPv6(dst="2001:db8::1") / IPv6ExtHdrHopByHop() / IPv6ExtHdrDestOpt() / IPv6ExtHdrDestOpt() / ICMPv6EchoRequest(id=probe_id, seq=seq) / Raw(load=payload)

# 真正分片（使用 fragment6 拆分）
original = IPv6(dst="2001:db8::1") / ICMPv6EchoRequest(id=probe_id, seq=seq) / Raw(load=large_payload)
fragments = fragment6(original, fragSize=512)

# 路由扩展头（segleft=1，强制目标处理）
pkt = IPv6(dst="2001:db8::1") / IPv6ExtHdrRouting(type=0, segleft=1, addresses=[dst]) / ICMPv6EchoRequest(id=probe_id, seq=seq) / Raw(load=payload)
```

异常探测类型的 payload 格式：

```
ipv6-prober|<探测类型>|<probe_id>|<seq>
```

## 实验设计建议

### 实验1：扩展头链长度 vs 响应率

```bash
# 测试不同链长对目标响应的影响
for len in 1 2 3 5 8; do
    sudo python3 main.py --target <目标地址> --probe-type ext-chain --chain-len $len --output chain_results.csv --append
done

# 分析 CSV 文件，绘制 chain_len vs response_rate 曲线
```

### 实验2：伪造源地址过滤测试

```bash
# 测试目标网络是否实施 BCP38 入口过滤
sudo python3 main.py --target <目标地址> --probe-type spoofed-src --spoofed-src <伪造地址>
```

### 实验3：异常扩展头处理测试

```bash
# 测试目标对非标准扩展头顺序的处理
sudo python3 main.py --target <目标地址> --probe-type abnormal-order

# 测试目标对已废弃路由头的处理
# routing probe 构造 RH0 且 Segments Left = 1，用于观察路径和目标对已废弃路由扩展头的处理行为。
# 若无响应，可能是路径设备、目标主机或本地发送路径丢弃；
# 若收到 Parameter Problem，则说明目标或路径中某节点显式拒绝该报文。
sudo python3 main.py --target <目标地址> --probe-type routing
```

### 实验4：IPv6 分片行为测试

```bash
# 测试目标对真正 IPv6 分片的处理
sudo python3 main.py --target <目标地址> --probe-type fragment

# 使用 tcpdump 抓包观察分片重组过程
sudo tcpdump -i <网卡> ip6 -vv
```

## 后续可扩展方向

1. **更多扩展头类型**: 支持 AH、ESP、Mobility 等扩展头的探测
2. **自定义扩展头内容**: 允许用户指定扩展头的具体字段值
3. **多探测类型组合**: 支持一次运行中对同一目标执行多种探测类型
4. **可视化报告**: 生成 HTML 图表报告，直观展示探测结果
5. **IPv6 地址范围扫描**: 支持 CIDR 前缀表示的目标范围（需严格控制扫描速率）
6. **数据库存储**: 将结果写入 SQLite 等数据库，方便长期追踪
7. **多线程/异步探测**: 在安全限制前提下提升批量探测效率
8. **配置文件支持**: 通过 YAML/TOML 配置文件管理探测参数
9. **Docker 化部署**: 提供 Dockerfile 方便环境搭建
10. **响应深度分析**: 对响应报文进行更详细的解析和分类

## 常见问题

### Q: 为什么需要 root 权限？

A: 发送原始套接字（raw socket）报文需要 root 权限。请使用 `sudo` 运行工具。

### Q: Windows 上能运行吗？

A: 可以使用 `--dry-run` 模式预览报文结构，但实际发送需要 Linux 环境。

### Q: 如何验证报文是否正确构造？

A: 使用 `--dry-run` 参数，工具会调用 Scapy 的 `show2()` 方法显示组装后的报文详细结构（包含计算后的校验和和 Next Header 字段），同时显示 `summary()` 和 `hexdump()`。

### Q: 结果文件被覆盖了怎么办？

A: 使用 `--append` 参数可以追加写入，避免覆盖之前的数据。不指定 `--output` 时，结果会自动保存到 `results/` 目录下，文件名包含时间戳，不会冲突。

### Q: 为什么 fragment 探测没有收到响应？

A: 真正的 IPv6 分片需要目标重组所有分片后才会响应。可能原因包括：中间设备丢弃分片、目标不支持分片重组、分片重组超时等。这正是本探测所关注的行为。

### Q: routing 探测的实验结论应该怎么写？

A: routing probe 构造 RH0 且 Segments Left = 1，用于观察路径和目标对已废弃路由扩展头的处理行为。若无响应，可能是路径设备、目标主机或本地发送路径丢弃；若收到 Parameter Problem，则说明目标或路径中某节点显式拒绝该报文。结论应谨慎表述，不要断言特定行为。

## 许可证

本项目仅供教育和研究目的使用。使用者需遵守当地法律法规，不得用于任何非法用途。
