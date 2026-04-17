"""Resolve service。"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Mapping, Protocol, SupportsInt

from ...bridges.pwntools import MemLeakAdapter
from ..catalog import LibcCatalogService
from ..errors import ResolverError
from ..inference import InferenceService
from ..models import BaseInferenceResult, RecordDomain, ResolvedSymbolResult
from ..registry import EvidenceRegistry
from .dynelf import DynELFResolver

if TYPE_CHECKING:
    from ..session import CHunSession


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
        session: "CHunSession | None" = None,
        catalog_service: LibcCatalogService | None = None,
        memleak_adapter_cls: type[MemLeakAdapter] = MemLeakAdapter,
        dynelf_resolver_cls: type[DynELFResolver] = DynELFResolver,
    ) -> None:
        self.registry = registry
        self.infer = infer
        self.session = session
        self.catalog_service = catalog_service if catalog_service is not None else infer.libc_catalog
        self.memleak_adapter_cls = memleak_adapter_cls
        self.dynelf_resolver = dynelf_resolver_cls(registry, adapter_cls=memleak_adapter_cls)

    def _session_elf(self) -> object | None:
        return None if self.session is None else self.session.elf

    def _session_libc_elf(self) -> object | None:
        return None if self.session is None else self.session.libc_elf

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
            else elf
            if elf is not None
            else self._session_libc_elf()
            if self._session_libc_elf() is not None
            else self._session_elf()
        )
        if candidate is None:
            raise ResolverError("缺少可用的 libc_elf / elf，请显式传参或先绑定到 session。")
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
        candidate = elf if elf is not None else self._session_elf()
        if candidate is None:
            raise ResolverError("缺少可用的 elf，请显式传参或先绑定到 session。")
        if not hasattr(candidate, "sym"):
            raise ResolverError("elf 需要提供 .sym 映射。")
        symbol_offset = int(candidate.sym[symbol])
        return self.infer.pie_base_from_symbol_leak(
            observation_name,
            symbol_offset=symbol_offset,
            fact_name=fact_name,
        )

    def symbol(self, name: str) -> int:
        """基于已确认的 libc base/version 计算绝对地址。"""
        if self.catalog_service is None:
            raise ResolverError("缺少 catalog_service 依赖。")

        base_record = self.registry.get_fact("libc.base")
        if base_record is None:
            observation = self.registry.get_observation("libc.base")
            base_value = observation.value if observation is not None else None
        else:
            base_value = base_record.value
        if not isinstance(base_value, int):
            raise ResolverError("缺少已确认的 libc.base。")

        version_fact = self.registry.get_fact("libc.version")
        if version_fact is None:
            raise ResolverError("缺少已确认的 libc.version。")
        libc_id = version_fact.metadata.get("libc_id")
        if not isinstance(libc_id, int):
            raise ResolverError("libc.version 缺少 libc_id 元数据。")

        try:
            offset = self.catalog_service.get_offset(libc_id, name)
        except Exception as exc:
            raise ResolverError(f"无法解析符号 {name}。") from exc
        return base_value + offset


__all__ = ["ResolveService"]
