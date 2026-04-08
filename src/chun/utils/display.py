"""输出展示辅助模块。"""

from __future__ import annotations

import re
import unicodedata
from typing import Any, Iterable

from .._compat import log

_ANSI_RESET = "\033[0m"
_ANSI_GREEN = "\033[32m"
_ANSI_YELLOW = "\033[33m"
_ANSI_RED = "\033[31m"
_ANSI_GRAY = "\033[90m"
_ANSI_CYAN = "\033[36m"
_ANSI_BLUE = "\033[34m"
_ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*m")


def format_value(value: Any) -> str:
    """统一格式化值，地址优先按十六进制展示。"""
    if isinstance(value, int):
        return f"{value:#014x}" if value > 0xFFFFFFFF else f"{value:#010x}"
    return str(value)


def print_section(title: str) -> None:
    """打印分区标题。"""
    log.info(f"[{title}]")


def _colorize(text: str, ansi_color: str) -> str:
    """返回带 ANSI 颜色的文本。"""
    return f"{ansi_color}{text}{_ANSI_RESET}"


def _infer_status(score: float, threshold: float) -> str:
    """根据分数与阈值生成展示层状态。"""
    if score >= threshold:
        return "ACCEPTED"
    if score >= max(0.0, threshold - 0.10):
        return "WEAK"
    if score >= 0.20:
        return "CONFLICT"
    return "REJECTED"


def _status_with_color(status: str) -> str:
    """根据状态添加配色。"""
    if status == "ACCEPTED":
        return _colorize(status, _ANSI_GREEN)
    if status == "WEAK":
        return _colorize(status, _ANSI_YELLOW)
    if status == "CONFLICT":
        return _colorize(status, _ANSI_RED)
    return _colorize(status, _ANSI_GRAY)


def _fmt_address(value: int) -> str:
    """地址字段统一使用青色强调。"""
    return _colorize(format_value(value), _ANSI_CYAN)


def print_event_line(level: str, message: str) -> None:
    """事件流输出：统一符号与语气。"""
    if level == "success":
        log.success(message)
        return
    if level == "warning":
        log.warning(message)
        return
    if level == "error":
        log.error(message)
        return
    log.info(message)


def _strip_ansi(text: str) -> str:
    """去掉 ANSI 转义序列，便于计算可视宽度。"""
    return _ANSI_PATTERN.sub("", text)


def _visual_width(text: str) -> int:
    """计算字符串在终端中的可视宽度（考虑中文宽字符）。"""
    width = 0
    for char in _strip_ansi(text):
        if unicodedata.combining(char):
            continue
        if unicodedata.east_asian_width(char) in {"W", "F"}:
            width += 2
        else:
            width += 1
    return width


def _slice_to_width(text: str, max_width: int) -> str:
    """按可视宽度截断字符串，并尽量保留 ANSI 序列。"""
    if max_width <= 0:
        return ""
    tokens = re.findall(r"\x1b\[[0-9;]*m|.", text, flags=re.DOTALL)
    out: list[str] = []
    used = 0
    for token in tokens:
        if _ANSI_PATTERN.fullmatch(token):
            out.append(token)
            continue
        char_width = 0 if unicodedata.combining(token) else (
            2 if unicodedata.east_asian_width(token) in {"W", "F"} else 1
        )
        if used + char_width > max_width:
            break
        out.append(token)
        used += char_width
    return "".join(out)


def _print_box(title: str, lines: list[str], width: int = 78) -> None:
    """打印统一风格的 ASCII 卡片。"""
    safe_width = max(52, width)
    inner = safe_width - 4
    label = f" {title} "
    left = max(0, (inner - len(label)) // 2)
    right = max(0, inner - len(label) - left)
    print("+" + "-" * left + label + "-" * right + "+")
    for line in lines:
        content = line
        if _visual_width(content) > inner:
            content = _slice_to_width(content, max(0, inner - 3)) + "..."
        padding = max(0, inner - _visual_width(content))
        print(f"| {content}{' ' * padding} |")
    print("+" + "-" * inner + "+")


def print_infer_card(
    *,
    target: str,
    leak_name: str,
    leak_value: int,
    base_name: str,
    candidate_base: int,
    score: float,
    threshold: float,
    reasons: Iterable[str],
    derived_rows: Iterable[tuple[str, int]] = (),
) -> str:
    """输出 infer 结果卡片，并返回状态字符串。"""
    status = _infer_status(score, threshold)
    lines = [
        f"target     {target}",
        f"status     {_status_with_color(status)}",
        f"leak       {leak_name} -> {_fmt_address(leak_value)}",
        f"base       {base_name} -> {_fmt_address(candidate_base)}",
        f"score      {score:.2f} / 1.00 (threshold={threshold:.2f})",
        "-" * 72,
        "Evidence:",
    ]
    for reason in reasons:
        marker = "+"
        if "(-" in reason:
            marker = "-"
        elif "不符" in reason or "冲突" in reason or "异常" in reason:
            marker = "-"
        lines.append(f"  {marker} {reason}")

    derived_rows = list(derived_rows)
    if derived_rows:
        lines.extend(["-" * 72, "Derived:"])
        for name, value in derived_rows:
            lines.append(f"  {_colorize(name, _ANSI_BLUE)} -> {_fmt_address(value)}")

    lines.extend(
        [
            "-" * 72,
            "Next:",
            "  try: resolve_bin_sh / resolve system / second libc leak",
        ]
    )
    print()
    _print_box("CHun Infer", lines)
    return status


def print_infer_debug(
    *,
    raw_base: int,
    aligned_base: int,
    address_class: str,
    threshold: float,
    source: str,
    confidence: float,
    reasons: Iterable[str],
) -> None:
    """verbose 模式下输出 infer 调试展开。"""
    lines = [
        f"raw_base      {format_value(raw_base)}",
        f"aligned_base  {format_value(aligned_base)}",
        f"addr_class    {address_class}",
        f"threshold     {threshold:.2f}",
        f"source        {source}",
        f"confidence    {confidence:.2f}",
        "-" * 72,
        "Score Breakdown:",
    ]
    pattern = re.compile(r"\(([+-]\d+\.\d+)\)")
    for reason in reasons:
        match = pattern.search(reason)
        if match:
            lines.append(f"  {match.group(1):>6}  {reason}")
        else:
            lines.append(f"  {'+0.00':>6}  {reason}")
    print()
    _print_box("CHun Infer Debug", lines)


def print_registry_snapshot(
    address_rows: Iterable[tuple[str, int, str, str, float]],
    base_rows: Iterable[tuple[str, int, str, float]],
    misc_rows: Iterable[tuple[str, Any]],
    verbose: bool = False,
) -> None:
    """按固定布局输出 Registry 快照。

    - 默认简洁视图：只突出“名字 + 值”
    - 详细视图（verbose）：展开 kind/source/confidence
    """
    print("\n" + "=" * 72)
    log.success("CHUN 状态快照")
    print("-" * 72)

    has_output = False

    address_rows = list(address_rows)
    if address_rows:
        has_output = True
        print_section("地址记录")
        for name, value, kind, source, confidence in address_rows:
            if verbose:
                log.info(
                    f"{name:<24} {format_value(value):<18} "
                    f"kind={kind:<12} src={source:<12} conf={confidence:.2f}"
                )
            else:
                log.info(f"{name:<24} {format_value(value)}")

    base_rows = list(base_rows)
    if base_rows:
        has_output = True
        print_section("Base 记录")
        for name, base, source, confidence in base_rows:
            if verbose:
                log.info(
                    f"{name:<24} {format_value(base):<18} "
                    f"src={source:<12} conf={confidence:.2f}"
                )
            else:
                log.info(f"{name:<24} {format_value(base)}")

    misc_rows = list(misc_rows)
    if misc_rows:
        has_output = True
        print_section("杂项记录")
        for name, value in misc_rows:
            log.info(f"{name:<24} {format_value(value)}")

    if not has_output:
        log.warning("当前 Registry 还没有记录。")

    print("=" * 72 + "\n")


def show_snapshot(
    address_rows: Iterable[tuple[str, int, str, str, float]],
    base_rows: Iterable[tuple[str, int, str, float]],
    misc_rows: Iterable[tuple[str, Any]],
    verbose: bool = False,
) -> None:
    """`print_registry_snapshot()` 的语义化别名。"""
    print_registry_snapshot(
        address_rows=address_rows,
        base_rows=base_rows,
        misc_rows=misc_rows,
        verbose=verbose,
    )
