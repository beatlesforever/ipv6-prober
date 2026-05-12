"""
IPv6 探测执行模块

本模块负责执行 IPv6 探测任务，包括：
- 构造探测报文（调用 PacketBuilder）
- 发送报文并等待响应
- 解析响应结果
- 计算往返时延（RTT）
- 记录探测结果

使用 Scapy 库的 sr1 函数发送报文并接收响应。
"""

import time  # 导入 time 库，用于获取时间和休眠
import logging  # 导入 logging 库，用于记录日志信息
from datetime import datetime, timezone  # 导入 datetime 相关类，用于生成时间戳

# 从 scapy.all 模块导入发送报文和解析响应所需的函数和类
from scapy.all import sr1, ICMPv6EchoReply, ICMPv6DestUnreach, ICMPv6ParamProblem, ICMPv6EchoRequest, IPv6

from packet_builder import PacketBuilder  # 导入 PacketBuilder 类，用于构造探测报文

# 创建当前模块的日志记录器，名称为 "ipv6_prober.prober"
logger = logging.getLogger("ipv6_prober.prober")


class Prober:
    """
    IPv6 探测执行类
    
    负责构造报文、发送探测、收集响应结果。
    支持多种探测类型，通过调用 PacketBuilder 的不同方法来构造不同类型的报文。
    """

    # 探测类型与 PacketBuilder 方法名的映射字典
    # 键：命令行传入的探测类型名称
    # 值：PacketBuilder 类中对应的方法名
    PROBE_METHODS = {
        "normal": "build_normal_probe",  # 普通探测 -> build_normal_probe 方法
        "spoofed-src": "build_spoofed_src_probe",  # 伪造源地址探测 -> build_spoofed_src_probe 方法
        "ext-chain": "build_ext_chain_probe",  # 多层扩展头链探测 -> build_ext_chain_probe 方法
        "fragment": "build_fragment_probe",  # 分片头探测 -> build_fragment_probe 方法
        "routing": "build_routing_probe",  # 路由扩展头探测 -> build_routing_probe 方法
        "abnormal-order": "build_abnormal_order_probe",  # 异常扩展头顺序探测 -> build_abnormal_order_probe 方法
    }

    def __init__(self, timeout: float = 2.0, iface: str = None, verbose: bool = False,
                 spoofed_src: str = None, chain_len: int = 2):
        """
        初始化 Prober 对象
        
        Args:
            timeout: 等待响应的超时时间（秒），默认 2.0 秒
            iface: 指定发送报文的网卡接口名称，默认 None（自动选择）
            verbose: 是否输出详细日志，默认 False
            spoofed_src: 伪造的源 IPv6 地址，仅 spoofed-src 类型使用
            chain_len: 扩展头链长度，仅 ext-chain 类型使用
        """
        self.timeout = timeout
        self.iface = iface
        self.verbose = verbose
        self.spoofed_src = spoofed_src
        self.chain_len = chain_len
        self.builder = PacketBuilder()

    def _classify_response(self, response) -> str:
        """
        分类响应报文的类型
        
        根据响应报文的内容，判断响应类型（Echo Reply、Destination Unreachable 等）。
        
        Args:
            response: Scapy 接收到的响应报文对象，可能为 None
            
        Returns:
            str: 响应类型的描述字符串
        """
        # 如果没有收到响应，返回 "No Response"
        if response is None:
            return "No Response"
        # 如果响应中包含 ICMPv6EchoReply，说明收到了 Echo Reply（ping 响应）
        if ICMPv6EchoReply in response:
            return "ICMPv6 Echo Reply"
        # 如果响应中包含 ICMPv6DestUnreach，说明目标不可达
        if ICMPv6DestUnreach in response:
            return "ICMPv6 Destination Unreachable"
        # 如果响应中包含 ICMPv6ParamProblem，说明参数有问题
        if ICMPv6ParamProblem in response:
            return "ICMPv6 Parameter Problem"
        # 如果是其他类型的响应，返回类型名称
        return f"Other ({response.__class__.__name__})"

    def _build_packet(self, probe_type: str, dst: str, probe_id: int = 0, seq: int = 0):
        """
        根据探测类型构造报文
        
        Args:
            probe_type: 探测类型名称
            dst: 目标 IPv6 地址
            probe_id: 探测标识 ID
            seq: 序列号
            
        Returns:
            Scapy packet 对象
        """
        method_name = self.PROBE_METHODS.get(probe_type)
        if method_name is None:
            raise ValueError(f"不支持的探测类型: {probe_type}")
        method = getattr(self.builder, method_name)
        kwargs = {"dst": dst, "probe_id": probe_id, "seq": seq}
        if probe_type == "spoofed-src":
            kwargs["spoofed_src"] = self.spoofed_src or "2001:db8:dead::1"
        if probe_type == "ext-chain":
            kwargs["chain_len"] = self.chain_len
        return method(**kwargs)

    def dry_run(self, probe_type: str, dst: str):
        """干运行模式：只打印报文结构，不发送"""
        pkt = self._build_packet(probe_type, dst, probe_id=0, seq=0)
        print(f"\n{'='*60}")
        print(f"[DRY-RUN] 探测类型: {probe_type}")
        print(f"[DRY-RUN] 目标地址: {dst}")
        if probe_type == "spoofed-src":
            print(f"[DRY-RUN] 伪造源地址: {self.spoofed_src or '2001:db8:dead::1'}")
        if probe_type == "ext-chain":
            print(f"[DRY-RUN] 扩展头链长度: {self.chain_len}")
        print(f"[DRY-RUN] 报文结构:")
        pkt.show()
        print(f"{'='*60}\n")

    def probe(self, target: str, probe_type: str, count: int = 1,
              interval: float = 1.0, probe_id: int = 0) -> list:
        """
        执行探测任务
        
        Args:
            target: 目标 IPv6 地址
            probe_type: 探测类型名称
            count: 发送探测报文的次数，默认 1
            interval: 两次探测之间的间隔时间（秒），默认 1.0
            probe_id: 本次实验唯一 ID，默认 0
            
        Returns:
            list: 探测结果列表
        """
        results = []
        for i in range(count):
            seq = i + 1
            record = {
                "probe_id": probe_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "target": target,
                "probe_type": probe_type,
                "packet_sent": True,
                "packet_summary": "",
                "response_received": False,
                "response_type": "No Response",
                "src_addr": "",
                "dst_addr": "",
                "icmpv6_type": "",
                "icmpv6_code": "",
                "rtt_ms": None,
                "ttl_or_hlim": None,
                "response_summary": "",
                "error": None,
                "notes": f"第 {i+1}/{count} 次探测",
            }
            try:
                pkt = self._build_packet(probe_type, target, probe_id=probe_id, seq=seq)
                record["packet_summary"] = pkt.summary()
                send_time = time.time()
                logger.info("发送 %s 探测 -> %s (第 %d/%d 次)", probe_type, target, i+1, count)

                # 注意：iface 参数对 L3 I/O (IPv6) 无效，Scapy 会自动选择正确的接口
                # 参考：https://scapy.readthedocs.io/en/latest/usage.html#multicast
                response = sr1(pkt, timeout=self.timeout, verbose=0)
                recv_time = time.time()

                if response is not None:
                    record["response_received"] = True
                    record["response_type"] = self._classify_response(response)
                    record["rtt_ms"] = round((recv_time - send_time) * 1000, 3)
                    record["response_summary"] = response.summary()
                    # 提取响应报文的源地址和目的地址
                    if IPv6 in response:
                        record["src_addr"] = response[IPv6].src
                        record["dst_addr"] = response[IPv6].dst
                    if hasattr(response, "hlim"):
                        record["ttl_or_hlim"] = response.hlim
                    # 提取 ICMPv6 type 和 code
                    if ICMPv6EchoReply in response:
                        record["icmpv6_type"] = response[ICMPv6EchoReply].type
                        record["icmpv6_code"] = response[ICMPv6EchoReply].code
                    elif ICMPv6DestUnreach in response:
                        record["icmpv6_type"] = response[ICMPv6DestUnreach].type
                        record["icmpv6_code"] = response[ICMPv6DestUnreach].code
                    elif ICMPv6ParamProblem in response:
                        record["icmpv6_type"] = response[ICMPv6ParamProblem].type
                        record["icmpv6_code"] = response[ICMPv6ParamProblem].code
                    logger.info(
                        "收到响应: %s, RTT=%.3fms",
                        record["response_type"],
                        record["rtt_ms"] or 0,
                    )
                else:
                    logger.info("未收到响应 (超时 %.1fs)", self.timeout)

            except PermissionError:
                record["error"] = "权限不足，发送原始套接字需要 root 权限"
                record["packet_sent"] = False
                logger.error("权限不足，请使用 sudo 运行")
            except OSError as e:
                record["error"] = f"OS 错误: {e}"
                record["packet_sent"] = False
                logger.error("OS 错误: %s", e)
            except Exception as e:
                record["error"] = f"未知错误: {e}"
                record["packet_sent"] = False
                logger.error("探测异常: %s", e, exc_info=True)

            results.append(record)

            if i < count - 1:
                logger.debug("等待 %.2f 秒后发送下一次探测...", interval)
                time.sleep(interval)

        return results
