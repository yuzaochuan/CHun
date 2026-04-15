"""CHun 顶层会话对象。"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..bridges.gdb import GdbMiBridge, PwntoolsGdbBridge
from ..transports.base import BaseTransport
from .analysis import CorefileAnalyzer
from .catalog import LibcCatalogService
from .inference import InferenceService
from .models import ContextKind, RecordDomain, TargetSpec, TransportSpec
from .registry import EvidenceRegistry
from .resolve import ResolveService


@dataclass(slots=True)
class CHunSession:
    """当前阶段稳定的会话对象。

    当前阶段把 transport、registry、inference 与 bridge 一并挂回 session：
    - `target`：目标描述
    - `transport_spec`：transport 配置
    - `transport`：实际 transport 实例
    - `registry` / `rec`：统一事实层入口
    - `infer`：最小 inference 服务
    - `dbg` / `gdb_mi`：调试桥接入口
    - `resolve`：pwntools / DynELF 解析入口
    - `crash`：core dump 分析入口
    """

    target: TargetSpec
    transport_spec: TransportSpec
    transport: BaseTransport
    registry: EvidenceRegistry = field(default_factory=EvidenceRegistry)
    libc_catalog: LibcCatalogService = field(default_factory=LibcCatalogService)
    infer: InferenceService = field(init=False)
    dbg: PwntoolsGdbBridge = field(init=False)
    gdb_mi: GdbMiBridge = field(init=False)
    resolve: ResolveService = field(init=False)
    crash: CorefileAnalyzer = field(init=False)

    def __post_init__(self) -> None:
        self.infer = InferenceService(self.registry, libc_catalog=self.libc_catalog)
        self.dbg = PwntoolsGdbBridge(self.registry, self.target, lambda: self.raw)
        self.gdb_mi = GdbMiBridge(self.registry, self.target)
        self.resolve = ResolveService(self.registry, self.infer, catalog_service=self.libc_catalog)
        self.crash = CorefileAnalyzer(self.registry)
        self._seed_context()

    def _seed_context(self) -> None:
        self.registry.set_context(
            "session.target",
            self.target,
            kind=ContextKind.TARGET,
            domain=RecordDomain.TARGET,
        )
        self.registry.set_context(
            "session.target.kind",
            self.target.kind,
            kind=ContextKind.TARGET,
            domain=RecordDomain.TARGET,
        )
        self.registry.set_context(
            "session.transport",
            self.transport_spec,
            kind=ContextKind.TRANSPORT,
            domain=RecordDomain.TRANSPORT,
        )
        self.registry.set_context(
            "session.transport.kind",
            self.transport_spec.kind,
            kind=ContextKind.TRANSPORT,
            domain=RecordDomain.TRANSPORT,
        )
        self.registry.set_context(
            "session.transport.is_open",
            bool(getattr(self.transport, "is_open", False)),
            kind=ContextKind.TRANSPORT,
            domain=RecordDomain.TRANSPORT,
        )

    def _sync_transport_context(self) -> None:
        self.registry.set_context(
            "session.transport.is_open",
            bool(getattr(self.transport, "is_open", False)),
            kind=ContextKind.TRANSPORT,
            domain=RecordDomain.TRANSPORT,
        )
        raw = getattr(self.transport, "raw", None)
        if raw is not None:
            self.registry.set_context(
                "session.transport.raw_type",
                type(raw).__name__,
                kind=ContextKind.TRANSPORT,
                domain=RecordDomain.TRANSPORT,
            )

    def open(self) -> "CHunSession":
        """显式打开 transport。"""
        self.transport.open()
        self._sync_transport_context()
        return self

    def close(self) -> None:
        """关闭 transport。"""
        self.transport.close()
        self._sync_transport_context()

    def reconnect(self) -> None:
        """重建 transport。"""
        self.transport.reconnect()
        self._sync_transport_context()

    @property
    def rec(self) -> EvidenceRegistry:
        """`registry` 的语义化短别名。"""
        return self.registry

    @property
    def io(self) -> BaseTransport:
        """提供统一 runtime 入口，并在首次访问时延迟打开 transport。"""
        if not self.transport.is_open:
            self.transport.open()
            self._sync_transport_context()
        return self.transport

    @property
    def raw(self) -> Any:
        """返回底层 transport 的原始对象。"""
        return self.io.raw

    def __enter__(self) -> "CHunSession":
        return self.open()

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()


__all__ = ["CHunSession"]
