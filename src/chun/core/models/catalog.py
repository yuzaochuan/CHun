"""Libc catalog 相关数据模型。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class LibcLeakConstraint:
    """单条 libc 泄漏约束。"""

    symbol_name: str
    leaked_value: int
    tail_bits: int = 12

    @property
    def offset_12bit(self) -> int:
        """返回用于 catalog 检索的低位偏移。"""
        return self.leaked_value & ((1 << self.tail_bits) - 1)


@dataclass(slots=True)
class LibcCandidate:
    """匹配得到的 libc 候选。"""

    libc_id: int
    name: str
    arch: str
    build_id: str | None = None
    matched_symbols: tuple[str, ...] = ()
    matched_count: int = 0
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(slots=True)
class LibcSearchResult:
    """一次 libc catalog 查询的结构化结果。"""

    constraints: tuple[LibcLeakConstraint, ...]
    candidates: list[LibcCandidate]
    exact_match: bool
    query_mode: str


__all__ = [
    "LibcCandidate",
    "LibcLeakConstraint",
    "LibcSearchResult",
]
