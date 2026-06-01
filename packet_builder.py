"""
IPv6 探测报文构造模块

本模块负责构造各种类型的 IPv6 探测报文，包括：
- 普通 ICMPv6 Echo Request 探测（标准 ping，基线对照）
- 伪造源地址探测
- 多层扩展头链探测（携带真实选项的 HopByHop / DestOpt）
- 分片头探测（完整 / 不完整 / 重叠 / 微分片）
- 路由扩展头探测（Type 0, segleft=0/1 / 多地址源路由）
- 异常扩展头顺序探测（4 种不同的顺序违规）

使用 Scapy 库来构造和操作 IPv6 报文。

报文负载策略：
- 除 fragment 外，所有探测类型均使用标准 ICMPv6 Echo Request，不带 Raw 负载。
  原因：这些类型的"异常"在 IPv6 层（扩展头 / 源地址 / 顺序等），payload 是干扰变量，
  会让实验结论无法归因——收不到响应时，分不清是 IPv6 头异常被过滤还是 payload 被丢弃。
- fragment 类型需要较大数据才能触发分片，使用全零字节填充，不含追踪字符串。
"""

import logging

from scapy.all import (
    IPv6,
    ICMPv6EchoRequest,
    IPv6ExtHdrHopByHop,
    IPv6ExtHdrDestOpt,
    IPv6ExtHdrFragment,
    IPv6ExtHdrRouting,
    Raw,
    fragment6,
    RouterAlert,
    PadN,
)

logger = logging.getLogger("ipv6_prober.packet_builder")

class PacketBuilder:
    """
    构造各类 IPv6 探测报文的工具类

    每个方法返回一个 Scapy packet 对象或分片报文列表。
    所有探测类型（除 fragment）使用相同的标准 ICMPv6 Echo Request，
    确保只有 IPv6 头结构的差异，实验结果可归因。
    """

    # ============================================================
    #  内部辅助方法
    # ============================================================

    def _build_echo_standard(self, probe_id: int = 0, seq: int = 0):
        """构造标准 ICMPv6 Echo Request（不带 Raw 负载）

        除 fragment 外所有探测类型共用，保证 ICMPv6 部分完全一致。
        """
        return ICMPv6EchoRequest(id=probe_id, seq=seq)

    # ---- normal ----

    def build_normal_probe(self, dst: str, probe_id: int = 0, seq: int = 0):
        """
        构造普通 IPv6 ICMPv6 Echo Request 探测报文（基线对照）

        使用标准 ICMPv6 Echo Request，不带 Raw 负载。
        作为所有异常探测类型的参照基准，确保最大响应率。
        """
        pkt = IPv6(dst=dst) / self._build_echo_standard(probe_id, seq)
        logger.debug("构建 normal -> %s (probe_id=%d, seq=%d)", dst, probe_id, seq)
        return pkt

    # ---- spoofed-src ----

    def build_spoofed_src_probe(self, dst: str,
                                 spoofed_src: str = "2001:db8:dead::1",
                                 probe_id: int = 0, seq: int = 0):
        """
        构造伪造源地址的 IPv6 探测报文

        通过 --spoofed-src 直接指定伪造的源 IPv6 地址。
        常用测试地址示例:
        - 2001:db8:dead::1  (RFC 3849 文档前缀, 不应出现在公网)
        - fe80::1           (链路本地地址, 路由器应丢弃)
        - ff02::1           (组播作源地址, 协议非法)

        Args:
            dst: 目标 IPv6 地址
            spoofed_src: 伪造的源 IPv6 地址
        """
        pkt = IPv6(src=spoofed_src, dst=dst) / self._build_echo_standard(probe_id, seq)
        logger.debug("构建 spoofed-src -> %s (src=%s)", dst, spoofed_src)
        return pkt

    # ---- ext-chain ----

    def build_ext_chain_probe(self, dst: str, chain_len: int = 2,
                               probe_id: int = 0, seq: int = 0):
        """
        构造多层扩展头链的 IPv6 探测报文

        第一个扩展头为 HopByHop（携带 Router Alert 选项，强制中间路由器检查其内容），
        后续扩展头为 DestOpt（携带 PadN 填充选项），确保扩展头不是"空壳"。

        chain_len=1: IPv6 / HopByHop(RouterAlert) / ICMPv6
        chain_len=2: IPv6 / HopByHop(RouterAlert) / DestOpt(PadN) / ICMPv6
        chain_len=N: IPv6 / HopByHop(RouterAlert) + (N-1)×DestOpt(PadN) / ICMPv6

        带真实选项的意义：
        - Router Alert 要求路由器检查扩展头内容，空 HopByHop 可能被硬件快速路径绕过
        - PadN 填充使扩展头长度更接近真实部署场景，而非最小化示例
        """
        # HopByHop 携带 RouterAlert(value=0, MLD)，迫使路由器处理
        pkt = IPv6(dst=dst) / IPv6ExtHdrHopByHop(options=[RouterAlert(value=0)])
        for _ in range(max(0, chain_len - 1)):
            pkt = pkt / IPv6ExtHdrDestOpt(options=[PadN()])
        pkt = pkt / self._build_echo_standard(probe_id, seq)
        logger.debug("构建 ext-chain -> %s (chain_len=%d)", dst, chain_len)
        return pkt

    # ---- fragment ----

    def build_fragment_probe(self, dst: str, probe_id: int = 0, seq: int = 0,
                              fragment_mode: str = "complete"):
        """
        构造 IPv6 分片探测报文，支持多种分片模式

        | fragment_mode | 说明                                               | 安全测试目标                 |
        |---------------|----------------------------------------------------|------------------------------|
        | complete      | 完整分片，所有分片正常发送                          | 基线：设备是否允许分片通过   |
        | incomplete    | 不完整分片，丢弃最后一个分片                        | 重组超时 / 资源消耗行为      |
        | overlap       | 重叠分片，两个分片的数据区域部分冲突                | NIDS 逃避，经典攻击手法      |
        | tiny          | 微分片，fragSize=64，上层协议头被跨分片拆分         | 防火墙分片追踪能力           |

        所有分片模式的 payload 均为全零字节，避免引入额外的特征匹配变量。
        """
        if fragment_mode == "overlap":
            return self._build_fragment_overlap(dst, probe_id, seq)
        elif fragment_mode == "incomplete":
            return self._build_fragment_incomplete(dst, probe_id, seq)
        elif fragment_mode == "tiny":
            return self._build_fragment_tiny(dst, probe_id, seq)
        else:
            return self._build_fragment_complete(dst, probe_id, seq)

    def _build_fragment_complete(self, dst, probe_id, seq):
        """完整分片：fragSize=512，稳定产生 3+ 个分片"""
        payload = b"\x00" * 2000
        pkt = IPv6(dst=dst) / ICMPv6EchoRequest(id=probe_id, seq=seq) / Raw(load=payload)
        fragments = fragment6(pkt, fragSize=512)
        logger.debug("构建 fragment(complete) -> %s (分片数: %d)", dst, len(fragments))
        return fragments

    def _build_fragment_incomplete(self, dst, probe_id, seq):
        """不完整分片：丢弃最后一个分片，目标将永远无法完成重组"""
        payload = b"\x00" * 2000
        pkt = IPv6(dst=dst) / ICMPv6EchoRequest(id=probe_id, seq=seq) / Raw(load=payload)
        fragments = fragment6(pkt, fragSize=512)
        dropped = fragments[-1]
        fragments = fragments[:-1]
        logger.debug("构建 fragment(incomplete) -> %s (发送 %d 个，丢弃最后 1 个: offset=%d)",
                     dst, len(fragments), dropped[IPv6ExtHdrFragment].offset if IPv6ExtHdrFragment in dropped else "?")
        return fragments

    def _build_fragment_overlap(self, dst, probe_id, seq):
        """
        重叠分片：手动构造两个偏移量冲突的分片

        Fragment 1: offset=0,  data=\\x00 * 512 (覆盖字节 0-511)
        Fragment 2: offset=32, data=\\xFF * 512 (覆盖字节 256-767)
        重叠区域: 字节 256-511，两个分片声称的内容不同

        目标重组时面临数据冲突——不同 OS / 设备选择保留哪个分片的数据，
        这是经典的 NIDS 逃避手法（ptacek 1998）。
        """
        frag_id = probe_id & 0xFFFFFFFF
        frag1 = (IPv6(dst=dst) /
                 IPv6ExtHdrFragment(id=frag_id, offset=0, m=1) /
                 Raw(load=b"\x00" * 512))
        frag2 = (IPv6(dst=dst) /
                 IPv6ExtHdrFragment(id=frag_id, offset=32, m=0) /
                 Raw(load=b"\xFF" * 512))
        logger.debug("构建 fragment(overlap) -> %s (offset 0 + offset 32, 重叠 256 bytes)", dst)
        return [frag1, frag2]

    def _build_fragment_tiny(self, dst, probe_id, seq):
        """微分片：fragSize=64，迫使 ICMPv6 头被跨分片拆分，考验防火墙的分片状态追踪"""
        payload = b"\x00" * 2000
        pkt = IPv6(dst=dst) / ICMPv6EchoRequest(id=probe_id, seq=seq) / Raw(load=payload)
        fragments = fragment6(pkt, fragSize=64)
        logger.debug("构建 fragment(tiny) -> %s (分片数: %d, fragSize=64)", dst, len(fragments))
        return fragments

    # ---- routing ----

    def build_routing_probe(self, dst: str, probe_id: int = 0, seq: int = 0,
                             routing_mode: str = "type0-segleft1"):
        """
        构造带有路由扩展头的 IPv6 探测报文

        全部使用 Type 0 路由头（已被 RFC 5095 废弃）。

        | routing_mode      | segleft | addresses                      | 测试目标                     |
        |-------------------|---------|--------------------------------|------------------------------|
        | type0-segleft1    | 1       | [dst]                          | 目标是否按 RFC 5095 拒绝     |
        | type0-segleft0    | 0       | [dst]                          | 对照：segleft=0 应忽略路由头 |

        segleft=1 与 segleft=0 的对比可判断目标是否严格遵循 RFC 5095。
        """
        if routing_mode == "type0-segleft0":
            pkt = (IPv6(dst=dst) /
                   IPv6ExtHdrRouting(type=0, segleft=0, addresses=[dst]) /
                   self._build_echo_standard(probe_id, seq))
        else:  # type0-segleft1
            pkt = (IPv6(dst=dst) /
                   IPv6ExtHdrRouting(type=0, segleft=1, addresses=[dst]) /
                   self._build_echo_standard(probe_id, seq))
        logger.debug("构建 routing(%s) -> %s", routing_mode, dst)
        return pkt

    # ---- abnormal-order ----

    def build_abnormal_order_probe(self, dst: str, probe_id: int = 0, seq: int = 0,
                                    order_type: str = "destopt-before-hbh"):
        """
        构造异常扩展头顺序的 IPv6 探测报文

        RFC 8200 推荐顺序: HopByHop → DestOpt → Routing → Fragment → ...

        | order_type              | 构造                                       | 违规类型               |
        |-------------------------|--------------------------------------------|------------------------|
        | destopt-before-hbh      | DestOpt → HopByHop                         | HopByHop 不在最前面    |
        | fragment-before-hbh     | Fragment → HopByHop                        | 严重违规               |
        | double-hbh              | HopByHop → HopByHop                        | 重复扩展头             |
        | routing-after-fragment  | Fragment → Routing                         | Routing 应在 Fragment 前 |

        RFC 8200 推荐顺序: HopByHop → DestOpt → Routing → Fragment → ...
        DestOpt 在 Fragment 前面是正确顺序（DestOpt 有两个合法位置），不是违规。
        Fragment 在 Routing 前面才是真正的违反推荐顺序。

        RFC 8200 推荐顺序: HopByHop → DestOpt → Routing → Fragment → ...

        注意：DestOpt 有两个合法位置（Routing 前和后），因此 DestOpt → Fragment
        是正确顺序而非违规。Fragment 在 Routing 前才是真正违反推荐顺序。

        不同违规类型触发不同检查逻辑，覆盖更广的设备行为空间。
        """
        echo = self._build_echo_standard(probe_id, seq)

        if order_type == "fragment-before-hbh":
            # Fragment 出现在 HopByHop 之前——最严重的顺序违规之一
            pkt = (IPv6(dst=dst) /
                   IPv6ExtHdrFragment(offset=0, m=0) /
                   IPv6ExtHdrHopByHop() /
                   echo)
        elif order_type == "double-hbh":
            # 两个连续的 HopByHop——违反 RFC 8200 "每种扩展头最多出现一次（除 DestOpt）"
            pkt = (IPv6(dst=dst) /
                   IPv6ExtHdrHopByHop() /
                   IPv6ExtHdrHopByHop() /
                   echo)
        elif order_type == "routing-after-fragment":
            # Fragment 在 Routing 之前——违反 RFC 8200 推荐顺序（Routing 应在 Fragment 前）
            pkt = (IPv6(dst=dst) /
                   IPv6ExtHdrFragment(offset=0, m=0) /
                   IPv6ExtHdrRouting(type=0, segleft=0, addresses=[dst]) /
                   echo)
        else:  # destopt-before-hbh
            pkt = (IPv6(dst=dst) /
                   IPv6ExtHdrDestOpt(options=[PadN()]) /
                   IPv6ExtHdrHopByHop() /
                   echo)

        logger.debug("构建 abnormal-order(%s) -> %s", order_type, dst)
        return pkt
