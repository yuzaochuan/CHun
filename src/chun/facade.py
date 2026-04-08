"""CHun 顶层工厂入口。"""

from __future__ import annotations

from typing import Callable, Sequence

from .core.models import TargetSpec, TransportSpec
from .core.session import CHunSession
from .transports import build_transport

DEFAULT_TERMINAL: tuple[str, ...] = ("tmux", "splitw", "-h")


class CHun:
    """按目标类型构建会话的入口工厂。"""

    @classmethod
    def from_specs(cls, target: TargetSpec, transport: TransportSpec) -> CHunSession:
        return CHunSession(
            target=target,
            transport_spec=transport,
            transport=build_transport(target, transport),
        )

    @classmethod
    def process(
        cls,
        binary: str,
        *,
        argv: Sequence[str] | None = None,
        libc: str | None = None,
        ld: str | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        log_level: str = "info",
        terminal: Sequence[str] = DEFAULT_TERMINAL,
    ) -> CHunSession:
        target = TargetSpec(
            kind="process",
            binary=binary,
            libc=libc,
            ld=ld,
            argv=list(argv or [binary]),
            env=dict(env or {}),
            cwd=cwd,
            metadata={
                "log_level": log_level,
                "terminal": list(terminal),
            },
        )
        transport = TransportSpec(kind="pwntools-tube")
        return cls.from_specs(target, transport)

    @classmethod
    def remote(
        cls,
        host: str,
        port: int,
        *,
        binary: str | None = None,
        libc: str | None = None,
        timeout: float | None = None,
        log_level: str = "info",
        terminal: Sequence[str] = DEFAULT_TERMINAL,
    ) -> CHunSession:
        target = TargetSpec(
            kind="remote",
            binary=binary,
            libc=libc,
            host=host,
            port=port,
            metadata={
                "log_level": log_level,
                "terminal": list(terminal),
            },
        )
        transport = TransportSpec(kind="pwntools-tube", timeout=timeout)
        return cls.from_specs(target, transport)

    @classmethod
    def ssh_process(
        cls,
        host: str,
        *,
        user: str,
        binary: str,
        argv: Sequence[str] | None = None,
        port: int = 22,
        password: str | None = None,
        keyfile: str | None = None,
        key_password: str | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        log_level: str = "info",
        terminal: Sequence[str] = DEFAULT_TERMINAL,
    ) -> CHunSession:
        target = TargetSpec(
            kind="ssh",
            binary=binary,
            argv=list(argv or [binary]),
            env=dict(env or {}),
            cwd=cwd,
            ssh_host=host,
            ssh_port=port,
            ssh_user=user,
            ssh_password=password,
            ssh_keyfile=keyfile,
            ssh_key_password=key_password,
            metadata={
                "log_level": log_level,
                "terminal": list(terminal),
            },
        )
        transport = TransportSpec(kind="pwntools-tube")
        return cls.from_specs(target, transport)

    @classmethod
    def http(
        cls,
        base_url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool = True,
        verify: bool = True,
        client_factory: Callable[[TargetSpec, TransportSpec], object] | None = None,
    ) -> CHunSession:
        target = TargetSpec(kind="http", base_url=base_url)
        metadata: dict[str, object] = {}
        if client_factory is not None:
            metadata["client_factory"] = client_factory
        transport = TransportSpec(
            kind="httpx",
            timeout=timeout,
            headers=dict(headers or {}),
            follow_redirects=follow_redirects,
            verify=verify,
            metadata=metadata,
        )
        return cls.from_specs(target, transport)

    @classmethod
    def websocket(
        cls,
        ws_url: str,
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        connect_timeout: float | None = None,
        connection_factory: Callable[[TargetSpec, TransportSpec], object] | None = None,
    ) -> CHunSession:
        target = TargetSpec(kind="websocket", ws_url=ws_url)
        metadata: dict[str, object] = {}
        if connection_factory is not None:
            metadata["connection_factory"] = connection_factory
        transport = TransportSpec(
            kind="websocket",
            timeout=timeout,
            connect_timeout=connect_timeout,
            headers=dict(headers or {}),
            metadata=metadata,
        )
        return cls.from_specs(target, transport)

    @classmethod
    def blind(
        cls,
        connection_factory: Callable[[], object],
        *,
        timeout: float | None = None,
    ) -> CHunSession:
        target = TargetSpec(kind="blind")
        transport = TransportSpec(
            kind="blind-reconnect",
            timeout=timeout,
            metadata={"connection_factory": connection_factory},
        )
        return cls.from_specs(target, transport)


__all__ = ["CHun", "DEFAULT_TERMINAL"]
