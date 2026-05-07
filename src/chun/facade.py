"""CHun 顶层工厂入口。"""

from __future__ import annotations

from typing import TYPE_CHECKING, Callable, Sequence

if TYPE_CHECKING:
    from .core.models import TargetSpec, TransportSpec
    from .core.session import CHunSession
    from .script.entry import ScriptEntry

DEFAULT_TERMINAL: tuple[str, ...] = ("tmux", "splitw", "-h")


class CHun:
    """按目标类型构建会话的入口工厂。"""

    @staticmethod
    def _resolve_terminal(terminal: Sequence[str] | None) -> list[str]:
        if terminal:
            return list(terminal)
        return list(DEFAULT_TERMINAL)

    @classmethod
    def _build_process_target(
        cls,
        binary: str,
        *,
        argv: Sequence[str] | None = None,
        libc: str | None = None,
        ld: str | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        log_level: str = "debug",
        terminal: Sequence[str] = DEFAULT_TERMINAL,
    ) -> TargetSpec:
        from .core.models import TargetSpec

        return TargetSpec(
            kind="process",
            binary=binary,
            libc=libc,
            ld=ld,
            argv=list(argv or [binary]),
            env=dict(env or {}),
            cwd=cwd,
            metadata={
                "log_level": log_level,
                "terminal": cls._resolve_terminal(terminal),
            },
        )

    @classmethod
    def _build_remote_target(
        cls,
        host: str,
        port: int,
        *,
        binary: str | None = None,
        libc: str | None = None,
        log_level: str = "debug",
        terminal: Sequence[str] = DEFAULT_TERMINAL,
    ) -> TargetSpec:
        from .core.models import TargetSpec

        return TargetSpec(
            kind="remote",
            binary=binary,
            libc=libc,
            host=host,
            port=port,
            metadata={
                "log_level": log_level,
                "terminal": cls._resolve_terminal(terminal),
            },
        )

    @classmethod
    def _build_ssh_target(
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
        log_level: str = "debug",
        terminal: Sequence[str] = DEFAULT_TERMINAL,
    ) -> TargetSpec:
        from .core.models import TargetSpec

        return TargetSpec(
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
                "terminal": cls._resolve_terminal(terminal),
            },
        )

    @staticmethod
    def _build_http_target(base_url: str) -> TargetSpec:
        from .core.models import TargetSpec

        return TargetSpec(kind="http", base_url=base_url)

    @staticmethod
    def _build_websocket_target(ws_url: str) -> TargetSpec:
        from .core.models import TargetSpec

        return TargetSpec(kind="websocket", ws_url=ws_url)

    @staticmethod
    def _build_blind_target() -> TargetSpec:
        from .core.models import TargetSpec

        return TargetSpec(kind="blind")

    @staticmethod
    def _build_pwntools_tube_transport(
        *, timeout: float | None = None
    ) -> TransportSpec:
        from .core.models import TransportSpec

        return TransportSpec(kind="pwntools-tube", timeout=timeout)

    @staticmethod
    def _build_http_transport(
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        follow_redirects: bool = True,
        verify: bool = True,
        client_factory: Callable[[TargetSpec, TransportSpec], object] | None = None,
    ) -> TransportSpec:
        from .core.models import TransportSpec

        metadata: dict[str, object] = {}
        if client_factory is not None:
            metadata["client_factory"] = client_factory
        return TransportSpec(
            kind="httpx",
            timeout=timeout,
            headers=dict(headers or {}),
            follow_redirects=follow_redirects,
            verify=verify,
            metadata=metadata,
        )

    @staticmethod
    def _build_websocket_transport(
        *,
        headers: dict[str, str] | None = None,
        timeout: float | None = None,
        connect_timeout: float | None = None,
        connection_factory: Callable[[TargetSpec, TransportSpec], object] | None = None,
    ) -> TransportSpec:
        from .core.models import TransportSpec

        metadata: dict[str, object] = {}
        if connection_factory is not None:
            metadata["connection_factory"] = connection_factory
        return TransportSpec(
            kind="websocket",
            timeout=timeout,
            connect_timeout=connect_timeout,
            headers=dict(headers or {}),
            metadata=metadata,
        )

    @staticmethod
    def _build_blind_transport(
        connection_factory: Callable[[], object],
        *,
        timeout: float | None = None,
    ) -> TransportSpec:
        from .core.models import TransportSpec

        return TransportSpec(
            kind="blind-reconnect",
            timeout=timeout,
            metadata={"connection_factory": connection_factory},
        )

    @classmethod
    def from_specs(cls, target: TargetSpec, transport: TransportSpec) -> CHunSession:
        from .core.session import CHunSession
        from .transports import build_transport

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
        target = cls._build_process_target(
            binary,
            argv=argv,
            libc=libc,
            ld=ld,
            env=env,
            cwd=cwd,
            log_level=log_level,
            terminal=terminal,
        )
        transport = cls._build_pwntools_tube_transport()
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
        log_level: str = "debug",
        terminal: Sequence[str] = DEFAULT_TERMINAL,
    ) -> CHunSession:
        target = cls._build_remote_target(
            host,
            port,
            binary=binary,
            libc=libc,
            log_level=log_level,
            terminal=terminal,
        )
        transport = cls._build_pwntools_tube_transport(timeout=timeout)
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
        target = cls._build_ssh_target(
            host,
            user=user,
            binary=binary,
            argv=argv,
            port=port,
            password=password,
            keyfile=keyfile,
            key_password=key_password,
            env=env,
            cwd=cwd,
            log_level=log_level,
            terminal=terminal,
        )
        transport = cls._build_pwntools_tube_transport()
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
        target = cls._build_http_target(base_url)
        transport = cls._build_http_transport(
            headers=headers,
            timeout=timeout,
            follow_redirects=follow_redirects,
            verify=verify,
            client_factory=client_factory,
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
        target = cls._build_websocket_target(ws_url)
        transport = cls._build_websocket_transport(
            headers=headers,
            timeout=timeout,
            connect_timeout=connect_timeout,
            connection_factory=connection_factory,
        )
        return cls.from_specs(target, transport)

    @classmethod
    def blind(
        cls,
        connection_factory: Callable[[], object],
        *,
        timeout: float | None = None,
    ) -> CHunSession:
        target = cls._build_blind_target()
        transport = cls._build_blind_transport(
            connection_factory,
            timeout=timeout,
        )
        return cls.from_specs(target, transport)

    @classmethod
    def script(
        cls,
        binary: str,
        *,
        host: str | None = None,
        port: int | None = None,
        libc: str | None = None,
        ld: str | None = None,
        argv: Sequence[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        timeout: float | None = None,
        cache: bool = True,
        cache_dir: str | None = None,
        auto_local_libc: bool = False,
        log_level: str = "debug",
        terminal: Sequence[str] = DEFAULT_TERMINAL,
    ) -> ScriptEntry:
        from .script.entry import ScriptEntry

        """返回面向手写 exp 的薄 facade。"""
        return ScriptEntry(
            cls,
            binary,
            host=host,
            port=port,
            libc=libc,
            ld=ld,
            argv=argv,
            env=env,
            cwd=cwd,
            timeout=timeout,
            cache=cache,
            cache_dir=cache_dir,
            auto_local_libc=auto_local_libc,
            log_level=log_level,
            terminal=terminal,
        )


__all__ = ["CHun", "DEFAULT_TERMINAL"]
