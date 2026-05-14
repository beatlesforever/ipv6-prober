#!/usr/bin/env python3
"""
IPv6 Abnormal Header Active Prober - 主程序入口

本模块是 IPv6 异常报文主动探测工具的命令行入口，负责：
1. 解析命令行参数
2. 执行安全检查
3. 收集并验证目标地址
4. 调用探测模块执行探测任务
5. 将结果写入输出文件

使用方式示例：

    # 基础用法：对单个目标进行普通 ICMPv6 Echo Request 探测
    sudo python3 main.py --target 2001:db8::1 --probe-type normal --count 1

    # 批量探测：从文件读取目标列表，使用分片探测类型，仅预览报文不发送
    sudo python3 main.py --targets-file targets.txt --probe-type fragment --dry-run

    # 伪造源地址探测：指定自定义伪造源地址（必须是合法 IPv6 格式）
    sudo python3 main.py --target 2001:db8::1 --probe-type spoofed-src --spoofed-src 2001:db8:1::1

    # 扩展头链探测：测试不同长度的扩展头链
    sudo python3 main.py --target 2001:db8::1 --probe-type ext-chain --chain-len 5

    # 追加模式：多次运行结果写入同一文件
    sudo python3 main.py --target 2001:db8::1 --probe-type normal --output results.csv --append
"""

import argparse
import sys
import logging
import random
from datetime import datetime
from pathlib import Path

from utils import (
    validate_ipv6,
    load_targets_from_file,
    check_safety,
    setup_logging,
    require_root,
    DEFAULT_COUNT,
    DEFAULT_INTERVAL,
    DEFAULT_TIMEOUT,
)
from prober import Prober
from result_writer import ResultWriter

logger = logging.getLogger("ipv6_prober.main")

PROBE_TYPES = [
    "normal",
    "spoofed-src",
    "ext-chain",
    "fragment",
    "routing",
    "abnormal-order",
]

RESULTS_DIR = Path("results")


def parse_args():
    """
    解析命令行参数

    使用 argparse 库定义和解析所有命令行选项，包括：
    - 目标指定：--target 或 --targets-file
    - 探测配置：--probe-type, --count, --interval, --timeout
    - 输出配置：--output, --format
    - 其他选项：--iface, --dry-run, --verbose

    Returns:
        argparse.Namespace: 解析后的命令行参数对象
    """
    # 创建 ArgumentParser 对象，设置程序描述和帮助信息格式
    parser = argparse.ArgumentParser(
        description="IPv6 Abnormal Header Active Prober - IPv6 异常报文主动探测工具",  # 程序描述
        formatter_class=argparse.RawDescriptionHelpFormatter,  # 保留帮助信息中的换行格式
        epilog=(  # 在帮助信息末尾添加使用示例
            "示例:\n"
            "  sudo python3 main.py --target 2001:db8::1 --probe-type normal --count 1\n"
            "  sudo python3 main.py --targets-file targets.txt --probe-type fragment --dry-run\n"
            "  sudo python3 main.py --target 2001:db8::1 --probe-type ext-chain --format json --output results.json\n"
        ),
    )
    # 添加 --target 参数：指定单个目标 IPv6 地址
    parser.add_argument(
        "--target",  # 参数名称
        type=str,  # 参数类型为字符串
        default=None,  # 默认值为 None
        help="单个目标 IPv6 地址",  # 帮助说明
    )
    # 添加 --targets-file 参数：指定包含多个目标地址的文件
    parser.add_argument(
        "--targets-file",
        type=str,
        default=None,
        help="目标 IPv6 地址列表文件路径，每行一个地址",
    )
    # 添加 --probe-type 参数：指定探测类型（必选参数）
    parser.add_argument(
        "--probe-type",
        type=str,
        choices=PROBE_TYPES,  # 限制可选值为 PROBE_TYPES 列表中的值
        required=True,  # 此参数为必选
        help="探测类型",
    )
    # 添加 --count 参数：指定每个目标发送探测报文的次数
    parser.add_argument(
        "--count",
        type=int,
        default=DEFAULT_COUNT,  # 使用默认常量值
        help=f"每个目标发送次数 (默认: {DEFAULT_COUNT})",
    )
    # 添加 --interval 参数：指定两次探测之间的时间间隔
    parser.add_argument(
        "--interval",
        type=float,
        default=DEFAULT_INTERVAL,
        help=f"发送间隔秒数 (默认: {DEFAULT_INTERVAL}, 最小: 0.2)",
    )
    # 添加 --timeout 参数：指定等待响应的超时时间
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"等待响应超时秒数 (默认: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="输出文件路径 (默认: results/probe_<类型>_<时间戳>.csv)",
    )
    # 添加 --format 参数：指定输出格式
    parser.add_argument(
        "--format",
        type=str,
        choices=["csv", "json"],  # 只能选择 csv 或 json
        default="csv",
        help="输出格式 (默认: csv)",
    )
    # 添加 --dry-run 参数：只打印报文不发送
    parser.add_argument(
        "--dry-run",
        action="store_true",  # 出现此参数则设为 True
        default=False,
        help="只打印构造的报文，不真正发送",
    )
    # 添加 --verbose 参数：输出详细日志
    parser.add_argument(
        "--verbose",
        action="store_true",
        default=False,
        help="输出详细日志",
    )
    # 添加 --spoofed-src 参数：指定伪造的源 IPv6 地址
    parser.add_argument(
        "--spoofed-src",
        type=str,
        default=None,
        help="伪造的源 IPv6 地址（仅 spoofed-src 类型有效）",
    )
    # 添加 --chain-len 参数：指定扩展头链长度
    parser.add_argument(
        "--chain-len",
        type=int,
        default=2,
        help="扩展头链长度，仅 ext-chain 类型有效 (默认: 2)",
    )
    # 添加 --append 参数：追加写入结果文件
    parser.add_argument(
        "--append",
        action="store_true",
        default=False,
        help="追加写入结果文件，而非覆盖",
    )
    # 解析命令行参数并返回结果
    return parser.parse_args()


def collect_targets(args) -> list:
    """
    收集并验证所有目标 IPv6 地址

    从命令行参数中提取目标地址，支持两种方式：
    1. --target: 单个 IPv6 地址
    2. --targets-file: 包含多个地址的文件

    同时对地址进行去重处理，避免重复探测。

    Args:
        args: argparse 解析后的参数对象

    Returns:
        list: 去重后的有效 IPv6 地址列表

    Raises:
        ValueError: 未指定任何目标或目标地址格式无效
    """
    targets = []  # 初始化目标地址列表
    # 如果指定了 --target 参数，验证并添加到列表
    if args.target:
        validated = validate_ipv6(args.target)  # 验证 IPv6 地址格式
        targets.append(validated)  # 添加到目标列表
    # 如果指定了 --targets-file 参数，从文件加载目标地址
    if args.targets_file:
        file_targets = load_targets_from_file(args.targets_file)  # 从文件读取目标地址
        targets.extend(file_targets)  # 将文件中的目标地址添加到列表
    # 如果目标列表为空，抛出异常
    if not targets:
        raise ValueError("未指定任何目标，请使用 --target 或 --targets-file")
    # 对目标地址进行去重处理
    seen = set()  # 用于记录已见过的地址
    unique = []  # 存储去重后的地址
    for t in targets:  # 遍历所有目标地址
        if t not in seen:  # 如果该地址未被记录过
            seen.add(t)  # 添加到已见集合
            unique.append(t)  # 添加到去重列表
    return unique  # 返回去重后的目标地址列表


def main():
    """
    主函数 - 程序入口点

    执行流程：
    1. 解析命令行参数
    2. 配置日志系统
    3. 执行安全检查（count、interval 限制）
    4. 收集并验证目标地址
    5. 检查 root 权限（发送原始套接字需要）
    6. 如果是 dry-run 模式，仅展示报文结构
    7. 否则执行实际探测，收集结果
    8. 将结果写入输出文件
    """
    args = parse_args()  # 步骤1：解析命令行参数
    setup_logging(verbose=args.verbose)  # 步骤3：配置日志系统，根据 verbose 参数决定日志详细程度

    # 步骤4：执行安全检查，确保 count 和 interval 参数符合安全限制
    try:
        check_safety(args.count, args.interval, args.timeout)  # 检查 count >= 1、interval >= 0.2、timeout > 0
    except ValueError as e:  # 如果安全检查失败
        logger.error("安全检查未通过: %s", e)  # 记录错误日志
        sys.exit(1)  # 以错误状态码 1 退出程序

    # 步骤5：收集并验证目标地址
    try:
        targets = collect_targets(args)  # 获取所有有效的目标 IPv6 地址
    except ValueError as e:  # 如果目标地址无效
        logger.error("目标地址错误: %s", e)  # 记录错误日志
        sys.exit(1)  # 以错误状态码 1 退出程序

    # 步骤5.5：验证 --spoofed-src 参数是否为合法 IPv6 地址
    if args.spoofed_src:
        try:
            validate_ipv6(args.spoofed_src)
        except ValueError as e:
            logger.error("伪造源地址无效: %s", e)
            sys.exit(1)

    # 步骤5.6：验证 --chain-len 参数范围
    if args.probe_type == "ext-chain":
        if args.chain_len < 1:
            logger.error("--chain-len 必须 >= 1，当前值: %d", args.chain_len)
            sys.exit(1)
        if args.chain_len > 8:
            logger.error("--chain-len 建议不超过 8，当前值: %d，避免生成过长异常链", args.chain_len)
            sys.exit(1)

    # 记录探测任务的基本信息
    logger.info("共 %d 个目标，探测类型: %s，每个目标发送 %d 次", len(targets), args.probe_type, args.count)

    # 生成本次实验的唯一 probe_id
    probe_id = random.randint(1, 65535)

    # 创建 Prober 对象，传入所有配置参数
    prober = Prober(
        timeout=args.timeout,
        verbose=args.verbose,
        spoofed_src=args.spoofed_src,
        chain_len=args.chain_len,
    )

    # 步骤7：如果是 dry-run 模式，仅展示报文结构，不发送
    if args.dry_run:
        logger.info("=== DRY-RUN 模式：仅展示报文，不发送 ===")  # 记录 dry-run 模式提示
        for target in targets:  # 遍历所有目标地址
            prober.dry_run(args.probe_type, target)  # 调用 dry_run 方法展示报文结构
        return  # 直接返回，不执行实际探测

    require_root()  # 步骤6：检查是否有 root 权限（发送原始套接字需要）

    # 步骤8：执行实际探测，收集结果
    all_results = []  # 初始化结果列表，用于存储所有探测结果
    for idx, target in enumerate(targets):  # 遍历所有目标地址，idx 为索引（从0开始）
        logger.info("探测目标 [%d/%d]: %s", idx + 1, len(targets), target)  # 记录当前探测的目标
        # 调用 prober.probe 方法执行探测，返回结果列表
        results = prober.probe(
            target=target,
            probe_type=args.probe_type,
            count=args.count,
            interval=args.interval,
            probe_id=probe_id,
        )
        all_results.extend(results)  # 将本次探测结果添加到总结果列表

    # 步骤9：将结果写入输出文件
    # 确定输出文件路径
    if args.output:
        output_path = Path(args.output)
    else:
        # 自动生成文件名：results/probe_<探测类型>_<时间戳>.<格式>
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = "csv" if args.format == "csv" else "json"
        filename = f"probe_{args.probe_type}_{timestamp}.{ext}"
        output_path = RESULTS_DIR / filename

    writer = ResultWriter(output_path=str(output_path), fmt=args.format, append=args.append)
    writer.write(all_results)

    logger.info("探测完成，共 %d 条结果，已保存到: %s", len(all_results), output_path)


# Python 程序入口点：当直接运行此脚本时执行 main 函数
if __name__ == "__main__":
    main()
