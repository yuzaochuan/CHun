"""脚本模式 facade。"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any, Sequence

from ._compat import ELF, args, context, log
from .core.errors import TransportConfigError
from .core.models import TargetSpec

if TYPE_CHECKING:
    from .core.session import CHunSession

DEFAULT_SCRIPT_TERMINAL: tuple[str, ...] = ("tmux", "splitw", "-h")


class ScriptEntry:
    """为手写 exp 保留薄包装入口。"""

    def __init__(
        self,
        factory: type[Any],
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
        log_level: str = "info",
        terminal: Sequence[str] = ("tmux", "splitw", "-h"),
    ) -> None:
        self._factory = factory
        resolved_terminal = tuple(terminal) if terminal else DEFAULT_SCRIPT_TERMINAL
        self.target = self._factory._build_process_target(
            binary,
            argv=argv,
            libc=libc,
            ld=ld,
            env=env,
            cwd=cwd,
            log_level=log_level,
            terminal=resolved_terminal,
        )
        self.target.host = host
        self.target.port = port
        self.timeout = timeout
        self.elf: Any = None
        self.libc: Any = None
        self._session: CHunSession | None = None
        self._initialize_script_context()

    def _initialize_script_context(self) -> None:
        log_level = self.target.metadata.get("log_level", "info")
        terminal = self.target.metadata.get("terminal", list(DEFAULT_SCRIPT_TERMINAL))
        context.log_level = str(log_level)
        context.terminal = list(terminal)

        if self.target.binary is None:
            raise TransportConfigError("CHun.script(...) 需要提供 binary。")

        self.elf = context.binary = ELF(self.target.binary, checksec=False)
        self.libc = self._load_libc()

    def _load_libc(self) -> Any:
        libc_path = self.target.libc
        if libc_path is not None:
            return ELF(libc_path, checksec=False)

        try:
            libc_elf = self.elf.libc
        except Exception:
            return None

        libc_path = getattr(libc_elf, "path", None)
        if isinstance(libc_path, str) and libc_path:
            self.target.libc = libc_path
        return libc_elf

    def _target_for_mode(self) -> TargetSpec:
        if args.REMOTE:
            if self.target.host is None or self.target.port is None:
                raise TransportConfigError(
                    "REMOTE 模式需要在 CHun.script(...) 中提供 host 和 port。"
                )
            return self._factory._build_remote_target(
                self.target.host,
                self.target.port,
                binary=self.target.binary,
                libc=self.target.libc,
                log_level=str(self.target.metadata.get("log_level", "info")),
                terminal=list(
                    self.target.metadata.get("terminal", list(DEFAULT_SCRIPT_TERMINAL))
                ),
            )
        return replace(self.target, kind="process")

    def _build_session(self) -> "CHunSession":
        target = self._target_for_mode()
        transport = self._factory._build_pwntools_tube_transport(timeout=self.timeout)
        return self._factory.from_specs(target, transport)

    def start(self) -> "CHunSession":
        """根据 pwntools args 选择本地或远程 session。"""
        if self._session is None:
            self._session = self._build_session()
        return self._session

    def gdb(self, script: str = "") -> object | None:
        """仅在本地 process 且传入 GDB 参数时 attach。"""
        if not args.GDB:
            return None

        session = self.start()
        if session.target.kind != "process":
            log.warning("当前为 REMOTE 模式，跳过 GDB attach。")
            return None
        return session.dbg.attach(script=script)

    @property
    def session(self) -> "CHunSession":
        """返回当前已启动 session。"""
        if self._session is None:
            raise RuntimeError("ScriptEntry 尚未启动，请先调用 start()。")
        return self._session

    @property
    def io(self) -> Any:
        """暴露当前 session 的 io。"""
        return self.session.io


__all__ = ["ScriptEntry"]
