"""MemLeak 适配层。"""

from __future__ import annotations

import inspect
from typing import Any, Callable

from ... import _compat
from ...core.models import ContextKind, ObservationKind, RecordDomain
from ...core.registry import EvidenceRegistry


class MemLeakAdapter:
    """把通用 leak primitive 适配成 pwntools MemLeak。"""

    def __init__(
        self,
        leak_primitive: Callable[..., bytes | bytearray | None],
        registry: EvidenceRegistry,
        *,
        domain: RecordDomain = RecordDomain.RESOLVE,
        chunk_size: int = 8,
        memleak_cls: type | None = None,
    ) -> None:
        self.leak_primitive = leak_primitive
        self.registry = registry
        self.domain = domain
        self.chunk_size = chunk_size
        self.memleak_cls = memleak_cls or _compat.MemLeak
        self._memleak: object | None = None
        self._takes_size = self._detect_size_arg(leak_primitive)

    @staticmethod
    def _detect_size_arg(leak_primitive: Callable[..., object]) -> bool:
        try:
            signature = inspect.signature(leak_primitive)
        except (TypeError, ValueError):
            return False
        params = [
            item
            for item in signature.parameters.values()
            if item.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
        ]
        return len(params) >= 2

    def _call_primitive(self, address: int) -> bytes | None:
        if self._takes_size:
            data = self.leak_primitive(address, self.chunk_size)
        else:
            data = self.leak_primitive(address)
        if data is None:
            payload = None
        else:
            payload = bytes(data)
        self.registry.record_observation(
            f"resolve.leak.0x{address:x}",
            payload,
            kind=ObservationKind.MEMORY_LEAK,
            domain=self.domain,
            source="memleak-adapter",
            tags=["memleak", "leak"],
            metadata={"address": address, "chunk_size": self.chunk_size},
            overwrite=True,
        )
        return payload

    def create(
        self,
        *,
        search_range: int = 20,
        reraise: bool = True,
        relative: bool = False,
    ) -> object:
        if self._memleak is None:
            self._memleak = self.memleak_cls(
                self._call_primitive,
                search_range=search_range,
                reraise=reraise,
                relative=relative,
            )
            self.registry.set_context(
                "resolve.memleak.chunk_size",
                self.chunk_size,
                kind=ContextKind.SESSION,
                domain=self.domain,
            )
        return self._memleak

    def raw(self, address: int, size: int) -> bytes | None:
        memleak = self.create()
        if not hasattr(memleak, "raw"):
            raise TypeError("MemLeak 对象不支持 raw()。")
        return memleak.raw(address, size)


__all__ = ["MemLeakAdapter"]
