# IPv6 探测工具测试记录

## 测试环境

ssh ubuntu\@170.9.232.205

| 主机           | 公网 IPv6 地址                             |
| ------------ | -------------------------------------- |
| 云服务器         | `2603:c028:4505:b142:0:7859:7328:a163` |
| Windows 本地电脑 | `2402:f000:4:1008:809:9845:ddb9:8a16`  |

## 在服务器上运行

### 1. 克隆项目并配置虚拟环境

```bash
# 克隆项目
git clone https://github.com/beatlesforever/ipv6-prober.git
cd ipv6-prober

# 创建虚拟环境
python3 -m venv .venv

# 激活虚拟环境
source .venv/bin/activate

# 安装依赖
pip install scapy
```

### 2. 运行探测命令

由于发送原始套接字需要 root 权限，需要使用 `sudo` 配合虚拟环境的 Python 解释器：

```bash
# 基本格式
sudo ./.venv/bin/python3 main.py [参数]

# 示例：普通探测
sudo ./.venv/bin/python3 main.py --target 2001:4860:4860::8888 --probe-type normal --count 1

# 示例：JSON 格式输出
sudo ./.venv/bin/python3 main.py --target 2001:4860:4860::8888 --probe-type normal --format json

# 示例：dry-run 模式（预览报文结构）
sudo ./.venv/bin/python3 main.py --target 2001:4860:4860::8888 --probe-type fragment --dry-run
```

> **注意**：使用 `sudo ./.venv/bin/python3` 而不是 `sudo python3`，确保使用虚拟环境中安装的 scapy。

***

## 测试案例 1：普通 ICMPv6 Echo Request 探测

### 测试命令

```bash
sudo ./.venv/bin/python3 main.py \
  --target 2001:4860:4860::8888 \
  --probe-type normal \
  --count 1 \
  --timeout 5 \
  --format json
```

### 运行日志

```
2026-05-12 15:41:28 [INFO] ipv6_prober.main - 共 1 个目标，探测类型: normal，每个目标发送 1 次
2026-05-12 15:41:28 [INFO] ipv6_prober.main - 探测目标 [1/1]: 2001:4860:4860::8888
2026-05-12 15:41:28 [INFO] ipv6_prober.prober - 发送 normal 探测 -> 2001:4860:4860::8888 (第 1/1 次)
2026-05-12 15:41:28 [INFO] ipv6_prober.prober - 收到响应: ICMPv6 Echo Reply, RTT=40.690ms
2026-05-12 15:41:28 [INFO] ipv6_prober.result_writer - 结果已写入: results/probe_normal_20260512_154128.json
2026-05-12 15:41:28 [INFO] ipv6_prober.main - 探测完成，共 1 条结果，已保存到: results/probe_normal_20260512_154128.json
```

### 结果文件 (JSON)

```json
[
  {
    "probe_id": 11491,
    "timestamp": "2026-05-12T15:41:28.044178+00:00",
    "target": "2001:4860:4860::8888",
    "probe_type": "normal",
    "packet_sent": "True",
    "packet_summary": "IPv6 / ICMPv6 Echo Request (id: 0x2ce3 seq: 0x1)",
    "response_received": "True",
    "response_type": "ICMPv6 Echo Reply",
    "src_addr": "2001:4860:4860::8888",
    "dst_addr": "2603:c028:4505:b142:0:7859:7328:a163",
    "icmpv6_type": 129,
    "icmpv6_code": 0,
    "rtt_ms": 40.69,
    "ttl_or_hlim": 120,
    "response_summary": "IPv6 / ICMPv6 Echo Reply (id: 0x2ce3 seq: 0x1)",
    "error": "",
    "notes": "第 1/1 次探测"
  }
]
```

### 结果分析

| 字段                  | 值                    | 说明                     |
| ------------------- | -------------------- | ---------------------- |
| `probe_id`          | 11491                | 本次实验唯一标识               |
| `target`            | 2001:4860:4860::8888 | 目标地址（Google DNS）       |
| `probe_type`        | normal               | 普通探测类型                 |
| `packet_sent`       | True                 | 报文成功发送                 |
| `response_received` | True                 | 收到响应                   |
| `response_type`     | ICMPv6 Echo Reply    | 响应类型为 Ping 响应          |
| `rtt_ms`            | 40.69                | 往返时延 40.69 毫秒          |
| `ttl_or_hlim`       | 120                  | 响应报文的 Hop Limit        |
| `icmpv6_type`       | 129                  | ICMPv6 类型码（Echo Reply） |
| `icmpv6_code`       | 0                    | ICMPv6 代码（正常）          |

***

## 常用命令速查

```bash
# 查看帮助
sudo ./.venv/bin/python3 main.py --help

# 普通探测
sudo ./.venv/bin/python3 main.py --target <IPv6地址> --probe-type normal --count 1

# 扩展头链探测（指定链长）
sudo ./.venv/bin/python3 main.py --target <IPv6地址> --probe-type ext-chain --chain-len 5

# 分片探测
sudo ./.venv/bin/python3 main.py --target <IPv6地址> --probe-type fragment

# 路由扩展头探测
sudo ./.venv/bin/python3 main.py --target <IPv6地址> --probe-type routing

# 异常扩展头顺序探测
sudo ./.venv/bin/python3 main.py --target <IPv6地址> --probe-type abnormal-order

# 伪造源地址探测
sudo ./.venv/bin/python3 main.py --target <IPv6地址> --probe-type spoofed-src --spoofed-src 2001:db8:1::1

# 预览报文结构（不发送）
sudo ./.venv/bin/python3 main.py --target <IPv6地址> --probe-type normal --dry-run

# 查看结果文件
cat results/probe_normal_*.json
cat results/probe_normal_*.csv
```

***

## 注意事项

1. **必须使用 sudo**：发送原始套接字需要 root 权限
2. **使用虚拟环境的 Python**：`sudo ./.venv/bin/python3` 而不是 `sudo python3`
3. **目标地址**：确保目标 IPv6 地址可达，可以用 `ping6` 先测试
4. **结果文件**：默认保存在 `results/` 目录下，文件名包含时间戳

