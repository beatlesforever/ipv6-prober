"""
IPv6 探测工具 - 工具函数模块

本模块提供 IPv6 探测工具所需的各种工具函数和常量，包括：
- 安全限制常量（最大目标数、最小间隔等）
- 免责声明
- IPv6 地址验证
- 目标文件加载
- 安全检查
- 日志配置
- root 权限检查
"""

import ipaddress  # 导入 ipaddress 库，用于验证和处理 IPv6 地址
import logging  # 导入 logging 库，用于记录日志信息
import sys  # 导入 sys 库，用于访问系统相关信息（如平台检测）

# ==================== 安全限制常量 ====================
# 这些常量定义了工具的安全限制，防止误用或滥用

MAX_TARGETS = 50  # 单次探测的最大目标数量限制，防止大规模扫描
MIN_INTERVAL = 0.2  # 两次探测之间的最小时间间隔（秒），防止高频发送
DEFAULT_INTERVAL = 1.0  # 默认的发送间隔时间（秒）
DEFAULT_COUNT = 1  # 默认的每个目标发送次数
DEFAULT_TIMEOUT = 2  # 默认的等待响应超时时间（秒）

# ==================== 免责声明 ====================
# 程序启动时打印的免责声明，提醒用户仅限授权环境使用
DISCLAIMER = """
============================================================
  IPv6 Abnormal Header Active Prober
  免责声明 / Disclaimer
------------------------------------------------------------
  本工具仅限在授权实验环境、校园网可控靶机或自建云服务器中使用。
  严禁用于未授权扫描、攻击、绕过检测或任何违法用途。
  使用者需自行承担因不当使用带来的一切法律责任。
  By running this tool, you confirm that you have proper
  authorization to probe the specified targets.
============================================================
"""

# 创建当前模块的日志记录器，名称为 "ipv6_prober"
logger = logging.getLogger("ipv6_prober")


def print_disclaimer():
    """
    打印免责声明
    
    在程序启动时调用，向用户展示使用限制和法律声明。
    """
    print(DISCLAIMER)  # 将免责声明输出到控制台


def validate_ipv6(addr: str) -> str:
    """
    验证 IPv6 地址格式
    
    使用 ipaddress 库验证输入的字符串是否为有效的 IPv6 地址。
    
    Args:
        addr: 待验证的 IPv6 地址字符串
        
    Returns:
        str: 规范化后的 IPv6 地址字符串
        
    Raises:
        ValueError: 输入不是有效的 IPv6 地址
    """
    try:
        # 尝试将输入字符串解析为 IPv6 地址对象
        # IPv6Address 会自动进行格式验证和规范化
        ip = ipaddress.IPv6Address(addr)
        # 返回规范化后的地址字符串（如压缩形式）
        return str(ip)
    except ipaddress.AddressValueError:
        # 如果解析失败，抛出更友好的错误信息
        raise ValueError(f"无效的 IPv6 地址: {addr}")


def load_targets_from_file(filepath: str) -> list:
    """
    从文件加载目标 IPv6 地址列表
    
    读取指定文件，解析其中的 IPv6 地址。
    文件格式：每行一个 IPv6 地址，支持 # 开头的注释行。
    
    Args:
        filepath: 目标文件路径
        
    Returns:
        list: 验证后的 IPv6 地址列表
        
    Raises:
        ValueError: 目标数量超过上限
        FileNotFoundError: 文件不存在
    """
    targets = []  # 初始化目标地址列表
    # 打开文件进行读取，使用 UTF-8 编码
    with open(filepath, "r", encoding="utf-8") as f:
        # 逐行读取文件内容
        for line in f:
            line = line.strip()  # 去除行首尾的空白字符
            # 跳过空行和以 # 开头的注释行
            if not line or line.startswith("#"):
                continue  # 跳过当前行，处理下一行
            # 验证 IPv6 地址格式
            validated = validate_ipv6(line)
            # 将验证通过的地址添加到列表
            targets.append(validated)
    # 检查目标数量是否超过上限
    if len(targets) > MAX_TARGETS:
        raise ValueError(
            f"目标数量 {len(targets)} 超过上限 {MAX_TARGETS}，"
            f"请减少目标或修改 MAX_TARGETS 常量"
        )
    # 返回验证后的目标地址列表
    return targets


def check_safety(count: int, interval: float):
    """
    执行安全检查
    
    检查探测参数是否符合安全限制要求。
    这是防止工具被滥用的重要措施。
    
    Args:
        count: 每个目标的发送次数
        interval: 两次探测之间的间隔时间（秒）
        
    Raises:
        ValueError: 参数不符合安全限制
    """
    # 检查发送次数是否合法（至少发送 1 次）
    if count < 1:
        raise ValueError(f"count 不能小于 1，当前值: {count}")
    # 检查发送间隔是否合法（不能太快，防止高频扫描）
    if interval < MIN_INTERVAL:
        raise ValueError(
            f"interval 不能小于 {MIN_INTERVAL} 秒，当前值: {interval}"
        )


def setup_logging(verbose: bool = False):
    """
    配置日志系统
    
    设置日志级别和格式。verbose 模式下输出更详细的调试信息。
    
    Args:
        verbose: 是否启用详细日志模式，默认 False
    """
    # 根据 verbose 参数决定日志级别
    # DEBUG 级别会输出所有日志，INFO 级别只输出重要信息
    level = logging.DEBUG if verbose else logging.INFO
    # 配置日志系统的基本参数
    logging.basicConfig(
        level=level,  # 日志级别
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",  # 日志格式：时间 [级别] 名称 - 消息
        datefmt="%Y-%m-%d %H:%M:%S",  # 时间格式：年-月-日 时:分:秒
    )


def require_root():
    """
    检查 root 权限
    
    在 Linux 系统上检查当前用户是否有 root 权限。
    发送原始套接字报文通常需要 root 权限。
    如果没有 root 权限，会输出警告信息。
    """
    # 检查是否为 Linux 系统，且 sys.flags 存在（确保是正常的 Python 环境）
    if sys.platform.startswith("linux") and getattr(sys, "flags", None) is not None:
        import os  # 导入 os 模块用于获取用户 ID
        # os.geteuid() 返回当前用户的有效用户 ID
        # root 用户的 UID 为 0
        if os.geteuid() != 0:
            # 非 root 用户，输出警告信息
            logger.warning(
                "当前非 root 用户，发送原始套接字报文可能需要 root 权限。"
                "如遇权限错误，请使用 sudo 运行。"
            )
