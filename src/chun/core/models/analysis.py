"""Bridge / analysis 相关结果模型。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .records import Fact


@dataclass(slots=True)
class GdbMiResult:
    """GDB/MI 命令执行结果。"""

    command: str
    result_class: str
    payload: object
    console: list[str] = field(default_factory=list)
    records: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ResolvedSymbolResult:
    """DynELF 或其他解析流程的符号解析结果。"""

    symbol: str
    library: str | None
    address: int
    fact_name: str
    stored_fact: Fact


@dataclass(slots=True)
class CrashAnalysisResult:
    """Corefile 分析结果。"""

    core_path: str | None
    signal: object | None
    fault_addr: int | None
    pc: int | None
    sp: int | None
    registers: dict[str, int]
    maps: list[dict[str, object]]
    cyclic_offset: int | None = None


__all__ = [
    "CrashAnalysisResult",
    "GdbMiResult",
    "ResolvedSymbolResult",
]
