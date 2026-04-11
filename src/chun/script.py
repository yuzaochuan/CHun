"""脚本模式 facade。"""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, Any, Sequence

from ._compat import ELF, args, context, log
from .bridges.gdb import PwntoolsGdbBridge
from .core.analysis import CorefileAnalyzer
from .core.errors import TransportConfigError
from .core.inference import InferenceService
from .core.models import TargetSpec
from .core.registry import EvidenceRegistry
from .core.resolve import ResolveService

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
        log_level: str = "debug",
        terminal: Sequence[str] = ("tmux", "splitw", "-h"),
    ) -> None:
        self._factory = factory
        resolved_terminal = tuple(terminal) if terminal else DEFAULT_SCRIPT_TERMINAL
        self._target = self._factory._build_process_target(
            binary,
            argv=argv,
            libc=libc,
            ld=ld,
            env=env,
            cwd=cwd,
            log_level=log_level,
            terminal=resolved_terminal,
        )
        self._target.host = host
        self._target.port = port
        self.timeout = timeout
        self._elf: Any = None
        self._libc: Any = None
        self._session: CHunSession | None = None
        self._initialize_script_context()

    def _initialize_script_context(self) -> None:
        log_level = self.target.metadata.get("log_level", "debug")
        terminal = self.target.metadata.get("terminal", list(DEFAULT_SCRIPT_TERMINAL))
        context.log_level = str(log_level)
        context.terminal = list(terminal)

        if self.target.binary is None:
            raise TransportConfigError("CHun.script(...) 需要提供 binary。")

        self._elf = ELF(self.target.binary, checksec=False)
        context._tls["binary"] = self._elf
        self._libc = self._load_libc()

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
                log_level=(
                    str(self.target.metadata.get("log_level", "debug"))
                    if args.GDB
                    else "info"
                ),
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
        """启动并缓存当前脚本对应的 `CHunSession`。"""
        if self._session is None:
            self._session = self._build_session()
        return self._session

    def gdb(self, script: str = "") -> object | None:
        """在 `GDB` 模式下对本地 process session 执行 attach。"""
        if not args.GDB:
            return None

        session = self.start()
        if session.target.kind != "process":
            log.warning("当前为 REMOTE 模式，跳过 GDB attach。")
            return None
        return session.dbg.attach(script=script)

    @property
    def session(self) -> "CHunSession":
        """返回当前已启动的 session，用于访问完整框架能力。"""
        if self._session is None:
            raise RuntimeError("ScriptEntry 尚未启动，请先调用 start()。")
        return self._session

    @property
    def io(self) -> Any:
        """返回当前 session 的 `io` 入口，适合直接做 tube 交互。"""
        return self.session.io

    @property
    def target(self) -> TargetSpec:
        """返回脚本入口缓存的 `TargetSpec` 配置。"""
        return self._target

    @property
    def elf(self) -> Any:
        """返回脚本初始化时加载的主程序 `ELF` 对象。"""
        return self._elf

    @property
    def libc(self) -> Any:
        """返回脚本初始化时解析出的 libc `ELF` 对象。"""
        return self._libc

    @property
    def rec(self) -> EvidenceRegistry:
        """访问 session 的事实记录入口，常用于记录 leak 和 context。"""
        return self.session.rec

    @property
    def infer(self) -> InferenceService:
        """访问 session 的最小 inference 服务。"""
        return self.session.infer

    @property
    def resolve(self) -> ResolveService:
        """访问 session 的解析服务，用于符号、DynELF 等推导。"""
        return self.session.resolve

    @property
    def dbg(self) -> PwntoolsGdbBridge:
        """访问 session 的交互式 GDB bridge。"""
        return self.session.dbg

    @property
    def crash(self) -> CorefileAnalyzer:
        """访问 session 的 core dump / crash 分析入口。"""
        return self.session.crash

    def send(self, data: bytes) -> None:
        """转发到当前 `io.send()`。"""
        self.io.send(data)

    def sendline(self, data: bytes) -> None:
        """转发到当前 `io.sendline()`。"""
        self.io.sendline(data)

    def sendafter(self, delim: bytes, data: bytes) -> None:
        """转发到当前 `io.sendafter()`。"""
        self.io.sendafter(delim, data)

    def sendlineafter(self, delim: bytes, data: bytes) -> None:
        """转发到当前 `io.sendlineafter()`。"""
        self.io.sendlineafter(delim, data)

    def recv(self, n: int = 4096) -> bytes:
        """转发到当前 `io.recv()`。"""
        return self.io.recv(n)

    def recvuntil(self, delim: bytes, drop: bool = False) -> bytes:
        """转发到当前 `io.recvuntil()`。"""
        return self.io.recvuntil(delim, drop=drop)

    def recvline(self, keepends: bool = True) -> bytes:
        """转发到当前 `io.recvline()`。"""
        return self.io.recvline(keepends=keepends)

    def interactive(self) -> None:
        """转发到当前 `io.interactive()`。"""
        self.io.interactive()

    def sl(self, data: bytes) -> None:
        """`sendline()` 的快捷别名。"""
        self.sendline(data)

    def sa(self, delim: bytes, data: bytes) -> None:
        """`sendafter()` 的快捷别名。"""
        self.sendafter(delim, data)

    def sla(self, delim: bytes, data: bytes) -> None:
        """`sendlineafter()` 的快捷别名。"""
        self.sendlineafter(delim, data)

    def ru(self, delim: bytes, drop: bool = False) -> bytes:
        """`recvuntil()` 的快捷别名。"""
        return self.recvuntil(delim, drop=drop)

    def rl(self, keepends: bool = True) -> bytes:
        """`recvline()` 的快捷别名。"""
        return self.recvline(keepends=keepends)

    def ia(self) -> None:
        """`interactive()` 的快捷别名。"""
        self.interactive()

    def __getattr__(self, name: str) -> Any:
        """将未显式声明的低频方法兜底转发到当前 `io`。"""
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.io, name)


__all__ = ["ScriptEntry"]
