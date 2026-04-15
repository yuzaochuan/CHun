"""离线构建 CHun libc catalog 数据库。"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from chun.core.catalog import build_libc_database, default_db_path, default_raw_dir


def build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器。"""
    parser = argparse.ArgumentParser(description="构建 CHun libc catalog SQLite 数据库。")
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=default_raw_dir(),
        help="原始 libc 数据目录，默认使用 data/libc/raw。",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=default_db_path(),
        help="输出 sqlite 数据库路径，默认使用 data/libc/libc.db。",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="保留全部符号；默认只构建 catalog_symbols.yaml 中定义的核心符号集。",
    )
    return parser


def main() -> int:
    """执行离线构建入口。"""
    args = build_parser().parse_args()
    summary = build_libc_database(
        raw_dir=args.raw_dir,
        output_path=args.output,
        include_all=args.all,
    )
    print(f"built {summary.output_path}")
    print(f"raw_dir={summary.raw_dir}")
    print(f"libc_count={summary.libc_count}")
    print(f"symbol_count={summary.symbol_count}")
    print(f"source_hash={summary.source_hash}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
