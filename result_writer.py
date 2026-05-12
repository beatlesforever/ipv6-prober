"""
IPv6 探测结果记录模块

本模块负责将探测结果写入输出文件，支持两种格式：
- CSV 格式：逗号分隔值文件，适合用 Excel 等工具打开查看
- JSON 格式：结构化数据格式，适合程序读取和后续处理

每条探测结果包含以下字段：
- timestamp: 探测时间戳
- target: 目标 IPv6 地址
- probe_type: 探测类型
- packet_sent: 报文是否成功发送
- response_received: 是否收到响应
- response_type: 响应类型
- rtt_ms: 往返时延（毫秒）
- ttl_or_hlim: 响应报文的 Hop Limit
- error: 错误信息
- notes: 备注信息
"""

import csv  # 导入 csv 库，用于写入 CSV 格式文件
import json  # 导入 json 库，用于写入 JSON 格式文件
import logging  # 导入 logging 库，用于记录日志信息
from pathlib import Path  # 导入 Path 类，用于处理文件路径

# 创建当前模块的日志记录器，名称为 "ipv6_prober.result_writer"
logger = logging.getLogger("ipv6_prober.result_writer")

# 定义探测结果的所有字段名称列表（有序）
# 这些字段决定了 CSV 文件的列顺序和 JSON 输出的字段顺序
RESULT_FIELDS = [
    "probe_id",  # 本次实验唯一 ID
    "timestamp",  # 探测时间戳（UTC ISO 格式）
    "target",  # 目标 IPv6 地址
    "probe_type",  # 探测类型（如 normal、fragment 等）
    "packet_sent",  # 报文是否成功发送（True/False）
    "packet_summary",  # 发送报文的 Scapy summary
    "response_received",  # 是否收到响应（True/False）
    "response_type",  # 响应类型（如 ICMPv6 Echo Reply、No Response 等）
    "src_addr",  # 响应报文源地址
    "dst_addr",  # 响应报文目的地址
    "icmpv6_type",  # ICMPv6 type 字段值
    "icmpv6_code",  # ICMPv6 code 字段值
    "rtt_ms",  # 往返时延，单位毫秒
    "ttl_or_hlim",  # 响应报文的 Hop Limit 值
    "response_summary",  # 响应报文的 Scapy summary
    "error",  # 错误信息（如有）
    "notes",  # 备注信息
]


class ResultWriter:
    """
    探测结果写入类
    
    将探测结果写入 CSV 或 JSON 格式的输出文件。
    支持自动创建输出目录，以及对结果数据进行标准化处理。
    """

    def __init__(self, output_path: str, fmt: str = "csv", append: bool = False):
        """
        初始化 ResultWriter 对象
        
        Args:
            output_path: 输出文件路径字符串
            fmt: 输出格式，"csv" 或 "json"，默认 "csv"
            append: 是否追加写入（True=追加，False=覆盖），默认 False
            
        Raises:
            ValueError: 不支持的输出格式
        """
        self.output_path = Path(output_path)
        self.fmt = fmt.lower()
        self.append = append
        if self.fmt not in ("csv", "json"):
            raise ValueError(f"不支持的输出格式: {fmt}，可选 csv 或 json")

    def write(self, results: list):
        """
        将探测结果写入文件
        
        根据指定的输出格式，调用对应的写入方法。
        写入前会自动创建输出目录。
        
        Args:
            results: 探测结果列表，每个元素是一个字典
        """
        # 如果结果列表为空，记录警告日志并直接返回
        if not results:
            logger.warning("无探测结果可写入")  # 记录警告日志
            return  # 直接返回，不执行写入操作

        # 自动创建输出文件所在的目录
        # parents=True: 同时创建所有不存在的父目录
        # exist_ok=True: 如果目录已存在不报错
        self.output_path.parent.mkdir(parents=True, exist_ok=True)

        # 根据输出格式选择对应的写入方法
        if self.fmt == "csv":
            self._write_csv(results)  # 调用 CSV 写入方法
        else:
            self._write_json(results)  # 调用 JSON 写入方法

        # 记录日志：结果已成功写入文件
        logger.info("结果已写入: %s", self.output_path)

    def _write_csv(self, results: list):
        """
        将结果写入 CSV 文件
        
        支持 append 模式：追加时不写表头，直接在文件末尾添加数据行。
        
        Args:
            results: 探测结果列表
        """
        file_exists = self.output_path.exists() and self.output_path.stat().st_size > 0
        mode = "a" if (self.append and file_exists) else "w"
        write_header = not (self.append and file_exists)
        with open(self.output_path, mode, newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=RESULT_FIELDS)
            if write_header:
                writer.writeheader()
            for row in results:
                writer.writerow(self._normalize_row(row))

    def _write_json(self, results: list):
        """
        将结果写入 JSON 文件
        
        支持 append 模式：读取已有数据，合并后重新写入。
        
        Args:
            results: 探测结果列表
        """
        existing = []
        if self.append and self.output_path.exists():
            try:
                with open(self.output_path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except (json.JSONDecodeError, ValueError):
                logger.warning("追加模式读取已有 JSON 失败，将覆盖写入")
        with open(self.output_path, "w", encoding="utf-8") as f:
            json.dump(
                existing + [self._normalize_row(r) for r in results],
                f,
                ensure_ascii=False,
                indent=2,
            )

    @staticmethod
    def _normalize_row(row: dict) -> dict:
        """
        标准化一行结果数据
        
        对结果字典进行标准化处理，确保：
        1. 所有字段都存在（缺失的填充为空字符串）
        2. None 值替换为空字符串（避免 CSV/JSON 中出现 null）
        3. 布尔值转换为字符串（避免 CSV 中显示不直观）
        
        Args:
            row: 原始结果字典
            
        Returns:
            dict: 标准化后的结果字典
        """
        normalized = {}  # 初始化标准化后的字典
        # 遍历所有字段名
        for field in RESULT_FIELDS:
            val = row.get(field)  # 获取该字段的值，如果不存在则返回 None
            if val is None:
                normalized[field] = ""  # None 值替换为空字符串
            elif isinstance(val, bool):
                normalized[field] = str(val)  # 布尔值转换为字符串 "True" 或 "False"
            else:
                normalized[field] = val  # 其他类型的值保持不变
        return normalized  # 返回标准化后的字典
