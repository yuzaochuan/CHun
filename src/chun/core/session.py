"""CHun 顶层会话对象。"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..bridges.gdb import GdbMiBridge, PwntoolsGdbBridge
from .analysis import CorefileAnalyzer
from .inference import InferenceService
from .models import ContextKind, RecordDomain, TargetSpec, TransportSpec
from .registry import EvidenceRegistry
from .resolve import ResolveService


@dataclass(slots=True)
class CHunSession:
    """第二阶段最小可用会话对象。

    当前阶段把 registry 和最小 inference 一并挂回 session：
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
    transport: object
    registry: EvidenceRegistry = field(default_factory=EvidenceRegistry)
    infer: InferenceService | None = None
    dbg: PwntoolsGdbBridge | None = None
    gdb_mi: GdbMiBridge | None = None
    resolve: ResolveService | None = None
    crash: CorefileAnalyzer | None = None

    def __post_init__(self) -> None:
        if self.infer is None:
            self.infer = InferenceService(self.registry)
        if self.dbg is None:
            self.dbg = PwntoolsGdbBridge(self.registry, self.target, lambda: self.raw)
        if self.gdb_mi is None:
            self.gdb_mi = GdbMiBridge(self.registry, self.target)
        if self.resolve is None:
            self.resolve = ResolveService(self.registry, self.infer)
        if self.crash is None:
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
    def io(self) -> object:
        """提供统一 runtime 入口，并在首次访问时延迟打开 transport。"""
        if not self.transport.is_open:
            self.transport.open()
            self._sync_transport_context()
        return self.transport

    @property
    def raw(self) -> object:
        """返回底层 transport 的原始对象。"""
        return self.io.raw

    def __enter__(self) -> "CHunSession":
        return self.open()

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()


Session = CHunSession


__all__ = ["CHunSession", "Session"]
