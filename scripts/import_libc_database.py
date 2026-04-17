"""从本地 libc-database 风格目录导入 libc 到 CHun raw/db。"""

from __future__ import annotations

import argparse
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RAW_DIR = PROJECT_ROOT / "data" / "libc" / "raw"


@dataclass(slots=True)
class ImportSummary:
    discovered: int = 0
    imported: int = 0
    skipped_existing: int = 0
    rebuilt_symbols: int = 0
    missing_so: int = 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="导入本地 libc-database 风格目录。")
    parser.add_argument(
        "source",
        type=Path,
        help="源目录，可直接指向 libc-database 根目录或其中的 db/。",
    )
    parser.add_argument(
        "--raw-dir",
        type=Path,
        default=DEFAULT_RAW_DIR,
        help="CHun raw 目录，默认 data/libc/raw。",
    )
    parser.add_argument(
        "--rebuild-sparse-symbols",
        action="store_true",
        help="当源 .symbols 过于稀疏时，尝试用本地 .so 重建。",
    )
    parser.add_argument(
        "--min-symbol-lines",
        type=int,
        default=32,
        help="低于这个行数时视为稀疏符号文件；默认 32。",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="最多导入多少个条目，默认不限制。",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只打印计划，不写入目标目录。",
    )
    return parser


def resolve_db_dir(path: Path) -> Path:
    if path.name == "db" and path.is_dir():
        return path
    db_dir = path / "db"
    if db_dir.is_dir():
        return db_dir
    raise SystemExit(f"无法在 {path} 下找到 db 目录。")


def count_symbol_lines(path: Path) -> int:
    if not path.is_file():
        return 0
    return sum(1 for line in path.read_text(encoding="utf-8", errors="ignore").splitlines() if line.strip())


def rebuild_symbols(raw_dir: Path, so_path: Path, output_path: Path) -> bool:
    command = (
        "cd \"$1\" && "
        ". common/libc.sh && "
        "(dump_symbols \"$2\"; dump_libc_start_main_ret \"$2\"; dump_bin_sh \"$2\") "
        "| awk 'NF>=2 && $2 ~ /^[0-9A-Fa-f]+$/ { seen[$1]=$2 } END { for (k in seen) print k, seen[k] }' "
        "| sort > \"$3\""
    )
    completed = subprocess.run(
        ["bash", "-lc", command, "--", str(raw_dir), str(so_path), str(output_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.returncode == 0 and output_path.is_file() and output_path.stat().st_size > 0


def import_database(
    source_db: Path,
    target_raw_dir: Path,
    *,
    rebuild_sparse_symbols: bool,
    min_symbol_lines: int,
    limit: int | None,
    dry_run: bool,
) -> ImportSummary:
    target_db = target_raw_dir / "db"
    target_db.mkdir(parents=True, exist_ok=True)
    summary = ImportSummary()

    for info_path in sorted(source_db.glob("*.info")):
        if limit is not None and summary.imported >= limit:
            break
        libc_id = info_path.stem
        summary.discovered += 1

        target_info = target_db / info_path.name
        if target_info.exists():
            summary.skipped_existing += 1
            continue

        source_symbols = source_db / f"{libc_id}.symbols"
        source_url = source_db / f"{libc_id}.url"
        source_so = source_db / f"{libc_id}.so"

        sparse = count_symbol_lines(source_symbols) < min_symbol_lines
        will_rebuild = rebuild_sparse_symbols and sparse and source_so.is_file()

        if dry_run:
            action = "rebuild-symbols" if will_rebuild else "copy"
            print(f"{libc_id} [{action}]")
            summary.imported += 1
            if will_rebuild:
                summary.rebuilt_symbols += 1
            elif not source_so.is_file():
                summary.missing_so += 1
            continue

        shutil.copy2(info_path, target_info)
        if source_url.is_file():
            shutil.copy2(source_url, target_db / source_url.name)
        if source_so.is_file():
            shutil.copy2(source_so, target_db / source_so.name)
        else:
            summary.missing_so += 1

        target_symbols = target_db / f"{libc_id}.symbols"
        if will_rebuild:
            ok = rebuild_symbols(target_raw_dir, target_db / source_so.name, target_symbols)
            if ok:
                summary.rebuilt_symbols += 1
            elif source_symbols.is_file():
                shutil.copy2(source_symbols, target_symbols)
        elif source_symbols.is_file():
            shutil.copy2(source_symbols, target_symbols)

        summary.imported += 1
    return summary


def main() -> int:
    args = build_parser().parse_args()
    source_db = resolve_db_dir(args.source)
    summary = import_database(
        source_db,
        args.raw_dir,
        rebuild_sparse_symbols=args.rebuild_sparse_symbols,
        min_symbol_lines=args.min_symbol_lines,
        limit=args.limit,
        dry_run=args.dry_run,
    )
    print(f"discovered={summary.discovered}")
    print(f"imported={summary.imported}")
    print(f"skipped_existing={summary.skipped_existing}")
    print(f"rebuilt_symbols={summary.rebuilt_symbols}")
    print(f"missing_so={summary.missing_so}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
