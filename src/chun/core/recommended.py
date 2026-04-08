"""推荐用户接口（高频写题能力收口层）。

这个模块专门承载“普通打题最常用的方法”，目的只有一个：
让 `Tool` 主文件保持精简，同时把易用 API 放在独立位置维护。
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING

from .registry import BaseCandidate, RecordKind, RecordSource

if TYPE_CHECKING:
    from .tool import MyTool
    from .target import TubeLike


class RecommendedToolAPI:
    """面向日常做题场景的便捷 API。

    使用方式：
    `t.api.record_libc_symbol(...)`
    `t.api.infer_libc_base_from(...)`
    """

    def __init__(self, tool: "MyTool") -> None:
        # 仅保存对主工具的引用，所有能力仍复用原有 Registry/Target。
        self._tool = tool

    def connect(self, host: str | None = None, port: int | None = None) -> "TubeLike":
        """语义化远程连接别名。"""
        return self._tool.start(host=host, port=port, remote_mode=True)

    def show(self, verbose: bool = False) -> None:
        """透传到主工具的快照输出。"""
        self._tool.show(verbose=verbose)

    def record_libc_symbol(
        self,
        name: str,
        value: int,
        source: RecordSource | str = RecordSource.MANUAL,
        confidence: float = 0.90,
        notes: str = "",
        meta: dict[str, Any] | None = None,
    ) -> None:
        """记录 libc 符号泄漏（推荐日常使用）。"""
        key = name if "@libc" in name else f"{name}@libc"
        self._tool.reg.add_address(
            name=key,
            value=value,
            kind=RecordKind.LIBC_SYMBOL,
            source=source,
            confidence=confidence,
            notes=notes,
            meta=meta,
        )

    def record_stack_ptr(
        self,
        name: str,
        value: int,
        source: RecordSource | str = RecordSource.MANUAL,
        confidence: float = 0.80,
        notes: str = "",
        meta: dict[str, Any] | None = None,
    ) -> None:
        """记录栈指针泄漏。"""
        self._tool.reg.add_address(
            name=name,
            value=value,
            kind=RecordKind.STACK_PTR,
            source=source,
            confidence=confidence,
            notes=notes,
            meta=meta,
        )

    def record_heap_ptr(
        self,
        name: str,
        value: int,
        source: RecordSource | str = RecordSource.MANUAL,
        confidence: float = 0.80,
        notes: str = "",
        meta: dict[str, Any] | None = None,
    ) -> None:
        """记录堆指针泄漏。"""
        self._tool.reg.add_address(
            name=name,
            value=value,
            kind=RecordKind.HEAP_PTR,
            source=source,
            confidence=confidence,
            notes=notes,
            meta=meta,
        )

    def record_base(
        self,
        name: str,
        base: int,
        source: RecordSource | str = RecordSource.MANUAL,
        confidence: float = 0.90,
        notes: str = "",
        meta: dict[str, Any] | None = None,
    ) -> None:
        """记录已确认的 base。"""
        payload = dict(meta or {})
        if notes:
            payload.setdefault("notes", notes)
        self._tool.reg.add_base(
            name=name,
            base=base,
            source=source,
            confidence=confidence,
            derived_from="manual-record",
            meta=payload,
        )

    def record_derived(
        self,
        name: str,
        value: int,
        confidence: float = 0.80,
        notes: str = "",
        meta: dict[str, Any] | None = None,
    ) -> None:
        """记录派生地址（如 one_gadget / ROP 关键点）。"""
        self._tool.reg.add_address(
            name=name,
            value=value,
            kind=RecordKind.GENERIC,
            source=RecordSource.DERIVED,
            confidence=confidence,
            notes=notes,
            meta=meta,
        )

    def record_note(self, key: str, value: Any) -> None:
        """记录非地址杂项信息。"""
        self._tool.reg.add_log(**{key: value})

    def infer_libc_base_from(
        self,
        leak_name: str,
        libc_sym: str | None = None,
        base_name: str = "libc",
        min_accept_score: float | None = None,
    ) -> BaseCandidate:
        """从 libc 泄漏推导 libc base。"""
        if self._tool.libc is None:
            raise RuntimeError("当前实例没有可用 libc 对象，无法推导 libc base。")

        record_key = leak_name if self._tool.reg.get_record(leak_name) else f"{leak_name}@libc"
        symbol_name = libc_sym or self._tool._normalize_symbol_name(leak_name)
        try:
            symbol_offset = int(self._tool.libc.sym[symbol_name])
        except Exception as exc:
            raise KeyError(f"libc 符号不存在或不可读：{symbol_name}") from exc

        return self._tool.reg.infer_base(
            leak_name=record_key,
            symbol_offset=symbol_offset,
            base_name=base_name,
            min_accept_score=min_accept_score,
            source=RecordSource.DERIVED,
            store=True,
        )

    def infer_pie_base_from(
        self,
        leak_name: str,
        elf_sym: str = "main",
        base_name: str = "pie",
        min_accept_score: float | None = None,
    ) -> BaseCandidate:
        """从程序代码段泄漏推导 PIE base。"""
        if self._tool.elf is None:
            raise RuntimeError("当前实例没有可用 ELF 对象，无法推导 PIE base。")

        record_key = leak_name if self._tool.reg.get_record(leak_name) else f"{leak_name}@elf"
        try:
            symbol_offset = int(self._tool.elf.sym[elf_sym])
        except Exception as exc:
            raise KeyError(f"ELF 符号不存在或不可读：{elf_sym}") from exc

        return self._tool.reg.infer_base(
            leak_name=record_key,
            symbol_offset=symbol_offset,
            base_name=base_name,
            min_accept_score=min_accept_score,
            source=RecordSource.DERIVED,
            store=True,
        )

