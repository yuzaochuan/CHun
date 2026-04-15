"""Resolve service。"""

from __future__ import annotations

from typing import Callable, Mapping, Protocol, SupportsInt

from ...bridges.pwntools import MemLeakAdapter
from ..errors import ResolverError
from ..inference import InferenceService
from ..models import BaseInferenceResult, RecordDomain, ResolvedSymbolResult
from ..registry import EvidenceRegistry
from .dynelf import DynELFResolver


class SupportsSym(Protocol):
    """最小 ELF 协议：只要求提供 ``sym`` 映射。"""

    sym: Mapping[str, SupportsInt]


class ResolveService:
    """围绕 pwntools / DynELF 的最小解析入口。"""

    def __init__(
        self,
        registry: EvidenceRegistry,
        infer: InferenceService,
        *,
        memleak_adapter_cls: type[MemLeakAdapter] = MemLeakAdapter,
        dynelf_resolver_cls: type[DynELFResolver] = DynELFResolver,
    ) -> None:
        self.registry = registry
        self.infer = infer
        self.memleak_adapter_cls = memleak_adapter_cls
        self.dynelf_resolver = dynelf_resolver_cls(registry, adapter_cls=memleak_adapter_cls)
        self.default_elf: object | None = None
        self.default_libc_elf: object | None = None

    def bind_defaults(
        self,
        *,
        elf: object | None = None,
        libc_elf: object | None = None,
    ) -> None:
        """绑定当前会话默认使用的 ELF / libc ELF 对象。"""
        self.default_elf = elf
        self.default_libc_elf = libc_elf

    def memleak(
        self,
        leak_primitive: Callable[..., bytes | bytearray | None],
        *,
        domain: RecordDomain = RecordDomain.RESOLVE,
        chunk_size: int = 8,
        memleak_cls: type | None = None,
    ) -> MemLeakAdapter:
        return self.memleak_adapter_cls(
            leak_primitive,
            self.registry,
            domain=domain,
            chunk_size=chunk_size,
            memleak_cls=memleak_cls,
        )

    def symbol_via_dynelf(
        self,
        symbol: str,
        *,
        leak_primitive: Callable[..., bytes | bytearray | None] | None = None,
        memleak: object | None = None,
        pointer: int | None,
        lib: str | None = None,
        elf: object | None = None,
        fact_name: str | None = None,
        domain: RecordDomain = RecordDomain.RESOLVE,
        memleak_cls: type | None = None,
        dynelf_cls: type | None = None,
    ) -> ResolvedSymbolResult:
        return self.dynelf_resolver.lookup(
            symbol,
            leak_primitive=leak_primitive,
            memleak=memleak,
            pointer=pointer,
            lib=lib,
            elf=elf,
            fact_name=fact_name,
            domain=domain,
            memleak_cls=memleak_cls,
            dynelf_cls=dynelf_cls,
        )

    def libc_base_from_elf_symbol(
        self,
        observation_name: str,
        *,
        libc_elf: SupportsSym | None = None,
        elf: SupportsSym | None = None,
        symbol: str,
        fact_name: str = "libc.base",
    ) -> BaseInferenceResult:
        candidate = (
            libc_elf
            if libc_elf is not None
            else self.default_libc_elf
            if self.default_libc_elf is not None
            else elf
            if elf is not None
            else self.default_elf
        )
        if candidate is None:
            raise ResolverError("libc_elf 或 elf 至少需要提供一个。")
        if not hasattr(candidate, "sym"):
            raise ResolverError("libc_elf 需要提供 .sym 映射。")
        symbol_offset = int(candidate.sym[symbol])
        return self.infer.libc_base_from_symbol_leak(
            observation_name,
            symbol_offset=symbol_offset,
            fact_name=fact_name,
        )

    def pie_base_from_elf_symbol(
        self,
        observation_name: str,
        *,
        elf: SupportsSym | None = None,
        symbol: str,
        fact_name: str = "elf.base",
    ) -> BaseInferenceResult:
        candidate = elf if elf is not None else self.default_elf
        if candidate is None:
            raise ResolverError("elf 至少需要提供一个。")
        if not hasattr(candidate, "sym"):
            raise ResolverError("elf 需要提供 .sym 映射。")
        symbol_offset = int(candidate.sym[symbol])
        return self.infer.pie_base_from_symbol_leak(
            observation_name,
            symbol_offset=symbol_offset,
            fact_name=fact_name,
        )


__all__ = ["ResolveService"]
