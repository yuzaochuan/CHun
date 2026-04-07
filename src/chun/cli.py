"""CHun 命令行入口。"""

from __future__ import annotations

import argparse
from pathlib import Path


DESCRIPTION = "CHun 命令行工具：查看当前工作区与环境状态。"


def build_parser() -> argparse.ArgumentParser:
    """构建 CLI 参数解析器。"""
    parser = argparse.ArgumentParser(prog="chun", description=DESCRIPTION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    info_parser = subparsers.add_parser("info", help="查看包和工作区信息")
    info_parser.add_argument("--cwd", default=".", help="要检查的工作目录")

    return parser


def cmd_info(cwd: str) -> int:
    """输出工作区信息，便于脚本化检查。"""
    path = Path(cwd).resolve()
    print(f"chun 工作区: {path}")
    print("状态: 可用")
    return 0


def main(argv: list[str] | None = None) -> int:
    """运行 CLI 并返回退出码。"""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "info":
        return cmd_info(args.cwd)

    parser.error(f"未知命令: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
