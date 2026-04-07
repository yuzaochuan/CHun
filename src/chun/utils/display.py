"""输出展示辅助模块。"""

from __future__ import annotations

from typing import Any, Iterable

from .._compat import log


def format_value(value: Any) -> str:
    """统一格式化值，地址优先按十六进制展示。"""
    if isinstance(value, int):
        return f"{value:#014x}" if value > 0xFFFFFFFF else f"{value:#010x}"
    return str(value)


def print_section(title: str) -> None:
    """打印分区标题。"""
    log.info(f"[{title}]")


def print_registry_snapshot(
    address_rows: Iterable[tuple[str, int, str, str, float]],
    base_rows: Iterable[tuple[str, int, str, float]],
    misc_rows: Iterable[tuple[str, Any]],
) -> None:
    """按固定布局输出 Registry 快照。"""
    print("\n" + "=" * 72)
    log.success("CHUN 状态快照")
    print("-" * 72)

    has_output = False

    address_rows = list(address_rows)
    if address_rows:
        has_output = True
        print_section("地址记录")
        for name, value, kind, source, confidence in address_rows:
            log.info(
                f"{name:<24} {format_value(value):<18} "
                f"kind={kind:<12} src={source:<12} conf={confidence:.2f}"
            )

    base_rows = list(base_rows)
    if base_rows:
        has_output = True
        print_section("Base 记录")
        for name, base, source, confidence in base_rows:
            log.info(
                f"{name:<24} {format_value(base):<18} "
                f"src={source:<12} conf={confidence:.2f}"
            )

    misc_rows = list(misc_rows)
    if misc_rows:
        has_output = True
        print_section("杂项记录")
        for name, value in misc_rows:
            log.info(f"{name:<24} {format_value(value)}")

    if not has_output:
        log.warning("当前 Registry 还没有记录。")

    print("=" * 72 + "\n")
