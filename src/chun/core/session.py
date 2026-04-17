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
    elf: object | None = field(default=None, init=False, repr=False)
    libc_elf: object | None = field(default=None, init=False, repr=False)
    infer: InferenceService = field(init=False)
    dbg: PwntoolsGdbBridge = field(init=False)
    gdb_mi: GdbMiBridge = field(init=False)
    resolve: ResolveService = field(init=False)
    crash: CorefileAnalyzer = field(init=False)

    def __post_init__(self) -> None:
        self.infer = InferenceService(self.registry, libc_catalog=self.libc_catalog, session=self)
        self.dbg = PwntoolsGdbBridge(self.registry, self.target, lambda: self.raw)
        self.gdb_mi = GdbMiBridge(self.registry, self.target)
        self.resolve = ResolveService(
            self.registry,
            self.infer,
            catalog_service=self.libc_catalog,
            session=self,
        )
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

    def bind_binaries(
        self,
        *,
        elf: object | None = None,
        libc_elf: object | None = None,
    ) -> "CHunSession":
        """绑定当前会话使用的 ELF / libc ELF 富对象，并同步标量上下文。"""
        if elf is not None:
            self.elf = elf
            self._sync_binary_context("binary", elf, kind=ContextKind.ENVIRONMENT)
            self._sync_arch_context(elf)
        if libc_elf is not None:
            self.libc_elf = libc_elf
            self._sync_binary_context("libc", libc_elf, kind=ContextKind.LIBC)
        return self

    def _sync_binary_context(self, prefix: str, binary: object, *, kind: ContextKind) -> None:
        path = getattr(binary, "path", None)
        arch = getattr(binary, "arch", None)
        bits = getattr(binary, "bits", None)

        if isinstance(path, str) and path:
            self.registry.set_context(
                f"{prefix}.path",
                path,
                kind=kind,
                domain=RecordDomain.ELF if prefix == "binary" else RecordDomain.LIBC,
            )
        if isinstance(arch, str) and arch:
            self.registry.set_context(
                f"{prefix}.arch",
                arch,
                kind=kind,
                domain=RecordDomain.ELF if prefix == "binary" else RecordDomain.LIBC,
            )
        if isinstance(bits, int):
            self.registry.set_context(
                f"{prefix}.bits",
                bits,
                kind=kind,
                domain=RecordDomain.ELF if prefix == "binary" else RecordDomain.LIBC,
            )

    def _sync_arch_context(self, binary: object) -> None:
        bits = getattr(binary, "bits", None)
        endian = getattr(binary, "endian", None)
        pointer_size = getattr(binary, "bytes", None)

        if isinstance(bits, int):
            self.registry.set_context(
                "arch.bits",
                bits,
                kind=ContextKind.ENVIRONMENT,
                domain=RecordDomain.ELF,
            )
        if isinstance(endian, str) and endian:
            self.registry.set_context(
                "arch.endian",
                endian,
                kind=ContextKind.ENVIRONMENT,
                domain=RecordDomain.ELF,
            )
        if isinstance(pointer_size, int):
            self.registry.set_context(
                "arch.pointer_size",
                pointer_size,
                kind=ContextKind.ENVIRONMENT,
                domain=RecordDomain.ELF,
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

    @property
    def libc_base(self) -> int:
        """返回当前 session 中已确认的 libc base。"""
        try:
            return self.registry.require_int_fact("libc.base")
        except KeyError as exc:
            raise RuntimeError(
                "libc.base 尚未推导，可能是多候选情况，请明确指定或编写爆破逻辑。"
            ) from exc
        except TypeError as exc:
            raise RuntimeError("libc.base 已存在，但其值不是整数。") from exc

    @property
    def libc_version(self) -> str:
        """返回当前 session 中已确认的 libc 版本名。"""
        try:
            return self.registry.require_str_fact("libc.version")
        except KeyError as exc:
            raise RuntimeError("libc.version 尚未确认。") from exc
        except TypeError as exc:
            raise RuntimeError("libc.version 已存在，但其值不是字符串。") from exc

    def __enter__(self) -> "CHunSession":
        return self.open()

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.close()


__all__ = ["CHunSession"]
