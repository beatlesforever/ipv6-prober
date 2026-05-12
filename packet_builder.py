"""
IPv6 探测报文构造模块

本模块负责构造各种类型的 IPv6 探测报文，包括：
- 普通 ICMPv6 Echo Request 探测（标准 ping，不带额外负载）
- 伪造源地址探测
- 多层扩展头链探测
- 分片头探测
- 路由扩展头探测
- 异常扩展头顺序探测

使用 Scapy 库来构造和操作 IPv6 报文。

重要说明：
- normal 类型构造标准 ICMPv6 Echo Request，不带 Raw 负载，确保目标能正常响应
- 其他异常探测类型可携带 Raw 负载用于追踪，因为这些类型本身就是测试异常行为
"""

import logging  # 导入 logging 库，用于记录日志信息

# 从 scapy.all 模块导入构造 IPv6 报文所需的类
from scapy.all import (
    IPv6,  # IPv6 基础头类，用于构造 IPv6 报文的基本头部
    ICMPv6EchoRequest,  # ICMPv6 Echo Request 类，用于构造 ping 请求报文
    IPv6ExtHdrHopByHop,  # IPv6 逐跳选项扩展头，每个路由器都必须处理
    IPv6ExtHdrDestOpt,  # IPv6 目的选项扩展头，仅由目的节点处理
    IPv6ExtHdrFragment,  # IPv6 分片扩展头，用于报文分片
    IPv6ExtHdrRouting,  # IPv6 路由扩展头，用于源路由
    Raw,  # 原始数据类，用于携带任意负载数据
)

# 创建当前模块的日志记录器，名称为 "ipv6_prober.packet_builder"
logger = logging.getLogger("ipv6_prober.packet_builder")

# 定义伪造源地址的默认值，使用文档前缀 2001:db8（RFC 3849 保留用于文档示例）
SPOOFED_SRC_PREFIX = "2001:db8:dead::1"


class PacketBuilder:
    """
    构造各类 IPv6 探测报文的工具类
    
    该类提供了多个方法，用于构造不同类型的 IPv6 探测报文。
    每个方法返回一个 Scapy packet 对象，可以直接发送或进一步修改。
    
    所有方法支持 probe_id 和 seq 参数，用于标识和追踪探测报文。
    
    报文负载策略：
    - normal 类型：不带 Raw 负载，构造标准 ICMPv6 Echo Request，确保目标能正常响应
    - 异常探测类型：可携带 Raw 负载用于追踪，因为这些类型本身就是测试异常行为
    """

    def _build_echo_with_payload(self, probe_id: int = 0, seq: int = 0, probe_type: str = "normal") -> object:
        """构造带 Raw 负载的 ICMPv6 Echo Request
        
        payload 格式: ipv6-prober|探测类型|probe_id|seq
        这样可以更可靠地区分不同探测包的响应。
        
        注意：部分公共目标（如 Google DNS）可能不响应带 Raw 负载的 ICMPv6 请求，
        因此仅用于异常探测类型。normal 类型应使用不带负载的标准 Echo Request。
        
        Args:
            probe_id: 探测标识 ID
            seq: 序列号
            probe_type: 探测类型名称
            
        Returns:
            ICMPv6EchoRequest / Raw 组合的 Scapy packet 对象
        """
        # 网络报文里传输的是字节，不是 Python 字符串，所以要 encode
        payload = f"ipv6-prober|{probe_type}|{probe_id}|{seq}".encode()
        return ICMPv6EchoRequest(id=probe_id, seq=seq) / Raw(load=payload)

    def _build_echo_standard(self, probe_id: int = 0, seq: int = 0) -> object:
        """构造标准 ICMPv6 Echo Request（不带 Raw 负载）
        
        这是标准的 ping 请求格式，不带额外负载。
        大多数目标都能正常响应此格式的报文。
        
        Args:
            probe_id: 探测标识 ID
            seq: 序列号
            
        Returns:
            ICMPv6EchoRequest Scapy packet 对象
        """
        return ICMPv6EchoRequest(id=probe_id, seq=seq)

    def build_normal_probe(self, dst: str, probe_id: int = 0, seq: int = 0) -> object:
        """
        构造普通 IPv6 ICMPv6 Echo Request 探测报文
        
        这是最基础的探测类型，类似于 IPv6 下的 ping6 命令。
        用于测试目标主机是否可达以及网络连通性。
        
        构造标准 ICMPv6 Echo Request，不带 Raw 负载，
        确保公共目标（如 Google DNS）能正常响应。
        
        Args:
            dst: 目标 IPv6 地址字符串
            probe_id: 探测标识 ID，用于区分不同探测实验
            seq: 序列号，用于区分同一实验中的不同探测包
            
        Returns:
            Scapy packet 对象，包含 IPv6 头和 ICMPv6 Echo Request
        """
        # 使用标准 Echo Request，不带 Raw 负载
        pkt = IPv6(dst=dst) / self._build_echo_standard(probe_id, seq)
        logger.debug("构建 normal 探测报文 -> %s (probe_id=%d, seq=%d)", dst, probe_id, seq)
        return pkt

    def build_spoofed_src_probe(self, dst: str, spoofed_src: str = SPOOFED_SRC_PREFIX,
                                 probe_id: int = 0, seq: int = 0) -> object:
        """
        构造伪造源地址的 IPv6 探测报文
        
        通过伪造源地址来测试目标网络对异常源地址的处理行为。
        注意：大多数网络会实施入口过滤（BCP38），丢弃源地址不匹配的报文。
        
        Args:
            dst: 目标 IPv6 地址字符串
            spoofed_src: 伪造的源 IPv6 地址，默认使用 SPOOFED_SRC_PREFIX
            probe_id: 探测标识 ID
            seq: 序列号
            
        Returns:
            Scapy packet 对象，源地址被设置为伪造地址
        """
        # 伪造源地址本身就是异常行为，使用标准 Echo Request 即可
        pkt = IPv6(src=spoofed_src, dst=dst) / self._build_echo_standard(probe_id, seq)
        logger.debug("构建 spoofed-src 探测报文 -> %s (src=%s, probe_id=%d)", dst, spoofed_src, probe_id)
        return pkt

    def build_ext_chain_probe(self, dst: str, chain_len: int = 2,
                               probe_id: int = 0, seq: int = 0) -> object:
        """
        构造多层扩展头链的 IPv6 探测报文
        
        通过 chain_len 参数控制扩展头总数量。
        第一个扩展头固定为 HopByHop，其余扩展头使用 DestOpt。

        chain_len=1: IPv6 / HopByHop / ICMPv6
        chain_len=2: IPv6 / HopByHop / DestOpt / ICMPv6
        chain_len=5: IPv6 / HopByHop / DestOpt / DestOpt / DestOpt / DestOpt / ICMPv6

        实验中可以画出：扩展头数量 vs 响应率，分析目标对扩展头链长度的敏感度。
        
        Args:
            dst: 目标 IPv6 地址字符串
            chain_len: 扩展头总数量（默认 2，即 HopByHop + DestOpt）
            probe_id: 探测标识 ID
            seq: 序列号
            
        Returns:
            Scapy packet 对象，包含指定数量的扩展头
        """
        # 第一个扩展头始终是 HopByHop（RFC 8200 规定 HopByHop 必须在首位）
        pkt = IPv6(dst=dst) / IPv6ExtHdrHopByHop()
        # 剩余的 chain_len - 1 个扩展头使用 DestOpt
        for _ in range(max(0, chain_len - 1)):
            pkt = pkt / IPv6ExtHdrDestOpt()
        # 最后添加标准 ICMPv6 Echo Request（不带 Raw 负载）
        pkt = pkt / self._build_echo_standard(probe_id, seq)
        logger.debug("构建 ext-chain 探测报文 -> %s (chain_len=%d)", dst, chain_len)
        return pkt

    def build_fragment_probe(self, dst: str, probe_id: int = 0, seq: int = 0) -> object:
        """
        构造带有分片扩展头的 IPv6 探测报文
        
        构造一个带有 Fragment 扩展头的 ICMPv6 Echo Request。
        参数 offset=0, m=0 表示这是一个"未分片"的分片头（即单独的分片头，
        后面没有更多分片），用于测试目标对单独分片扩展头的处理行为。
        
        Args:
            dst: 目标 IPv6 地址字符串
            probe_id: 探测标识 ID
            seq: 序列号
            
        Returns:
            Scapy packet 对象，包含分片扩展头
        """
        # 分片头本身就是异常探测，使用标准 Echo Request
        pkt = IPv6(dst=dst) / IPv6ExtHdrFragment(offset=0, m=0) / self._build_echo_standard(probe_id, seq)
        logger.debug("构建 fragment 探测报文 -> %s", dst)
        return pkt

    def build_routing_probe(self, dst: str, probe_id: int = 0, seq: int = 0) -> object:
        """
        构造带有路由扩展头的 IPv6 探测报文
        
        构造一个带有 Routing 扩展头的 ICMPv6 Echo Request。
        使用 Type 0（已废弃）的路由头，用于测试目标是否正确拒绝或处理此类报文。
        
        注意：Type 0 路由头已被 RFC 5095 废弃，因为存在安全隐患。
        多数现代系统会丢弃此类报文或返回 ICMPv6 Parameter Problem，
        这正是本探测所关注的行为。
        
        Args:
            dst: 目标 IPv6 地址字符串
            probe_id: 探测标识 ID
            seq: 序列号
            
        Returns:
            Scapy packet 对象，包含路由扩展头
        """
        # 路由头本身就是异常探测，使用标准 Echo Request
        pkt = IPv6(dst=dst) / IPv6ExtHdrRouting(
            type=0,
            segleft=0,
            addresses=[]
        ) / self._build_echo_standard(probe_id, seq)
        logger.debug("构建 routing 探测报文 -> %s", dst)
        return pkt

    def build_abnormal_order_probe(self, dst: str, probe_id: int = 0, seq: int = 0) -> object:
        """
        构造异常扩展头顺序的 IPv6 探测报文
        
        根据 RFC 8200，IPv6 扩展头的推荐顺序为：
        HopByHop -> DestOpt -> Routing -> Fragment -> Auth -> DestOpt -> Payload
        
        本方法故意构造 DestOpt -> HopByHop 的异常顺序（HopByHop 应该在最前面），
        用于测试目标或中间设备对非标准扩展头顺序的处理行为。
        某些设备可能会丢弃此类报文或返回错误。
        
        Args:
            dst: 目标 IPv6 地址字符串
            probe_id: 探测标识 ID
            seq: 序列号
            
        Returns:
            Scapy packet 对象，扩展头顺序异常
        """
        # 异常顺序本身就是异常探测，使用标准 Echo Request
        pkt = (
            IPv6(dst=dst)
            / IPv6ExtHdrDestOpt()
            / IPv6ExtHdrHopByHop()
            / self._build_echo_standard(probe_id, seq)
        )
        logger.debug("构建 abnormal-order 探测报文 -> %s", dst)
        return pkt
