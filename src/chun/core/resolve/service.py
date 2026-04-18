"""Resolve service。"""

from __future__ import annotations

import re
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

    def _normalize_symbol_name(self, raw_name: str) -> str:
        if self.catalog_service is not None:
            normalize = getattr(self.catalog_service, "_normalize_name", None)
            if callable(normalize):
                return str(normalize(raw_name))

        return re.split(r"[@_](got|plt|got\.plt)", raw_name, flags=re.IGNORECASE)[0].strip()

    @staticmethod
    def _offset_from_bound_object(obj: object, value: SupportsInt) -> int:
        resolved = int(value)
        base_hint = getattr(obj, "address", 0)
        if isinstance(base_hint, int) and base_hint > 0 and resolved >= base_hint:
            return resolved - base_hint
        return resolved

    def _resolve_from_bound_libc(self, name: str, *, base_value: int) -> int | None:
        libc_elf = self._session_libc_elf()
        if libc_elf is None:
            return None

        normalized = self._normalize_symbol_name(name)
        for attr in ("sym", "symbols"):
            table = getattr(libc_elf, attr, None)
            if not isinstance(table, Mapping):
                continue
            for candidate in (name, normalized):
                if candidate not in table:
                    continue
                return base_value + self._offset_from_bound_object(libc_elf, table[candidate])

        if normalized == "str_bin_sh":
            search = getattr(libc_elf, "search", None)
            if callable(search):
                try:
                    match = next(search(b"/bin/sh"))
                except Exception:
                    return None
                return base_value + self._offset_from_bound_object(libc_elf, match)
        return None

    def _read_libc_base(self) -> int:
        base_record = self.registry.get_fact("libc.base")
        if base_record is None:
            observation = self.registry.get_observation("libc.base")
            base_value = observation.value if observation is not None else None
        else:
            base_value = base_record.value
        if not isinstance(base_value, int):
            raise ResolverError("缺少已确认的 libc.base。")
        return base_value

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
        """基于已确认的 libc base 按 mix 模式计算 libc 绝对地址。"""
        base_value = self._read_libc_base()

        resolved = self._resolve_from_bound_libc(name, base_value=base_value)
        if resolved is not None:
            return resolved

        if self.catalog_service is None:
            raise ResolverError(f"无法解析符号 {name}：缺少 catalog_service，且未命中已绑定 libc_elf。")

        version_fact = self.registry.get_fact("libc.version")
        if version_fact is None:
            raise ResolverError(f"无法解析符号 {name}：未命中已绑定 libc_elf，且缺少已确认的 libc.version。")
        libc_id = version_fact.metadata.get("libc_id")
        if not isinstance(libc_id, int):
            raise ResolverError("libc.version 缺少 libc_id 元数据。")

        try:
            offset = self.catalog_service.get_offset(libc_id, name)
        except Exception as exc:
            raise ResolverError(f"无法解析符号 {name}。") from exc
        return base_value + offset


__all__ = ["ResolveService"]
