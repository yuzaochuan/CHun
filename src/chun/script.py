"""脚本模式 facade。"""

from __future__ import annotations
import sys
import termios
import tty
from dataclasses import replace
from typing import TYPE_CHECKING, Any, Literal, Sequence

from ._compat import ELF, args, context, gdb, log, pause
from .bridges.gdb import PwntoolsGdbBridge
from .core.analysis import CorefileAnalyzer
from .core.errors import TransportConfigError
from .core.inference import InferenceService
from .core.models import RecordDomain, TargetSpec
from .core.registry import EvidenceRegistry
from .core.resolve import ResolveService
from .transports.pwntools_tube import PwntoolsTubeTransport

if TYPE_CHECKING:
    from .core.session import CHunSession

DEFAULT_SCRIPT_TERMINAL: tuple[str, ...] = ("tmux", "splitw", "-h", "-d")


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
        terminal: Sequence[str] = DEFAULT_SCRIPT_TERMINAL,
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
        self._set_context_binary(self._elf)
        self._libc = self._load_libc()

    @staticmethod
    def _set_context_binary(binary: Any) -> None:
        try:
            context.binary = binary
            return
        except Exception:
            pass

        tls = getattr(context, "_tls", None)
        if isinstance(tls, dict):
            tls["binary"] = binary
            return
        if tls is not None:
            try:
                setattr(tls, "binary", binary)
                return
            except Exception:
                pass

        object.__setattr__(context, "binary", binary)

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

    def start(self) -> "ScriptEntry":
        """启动并缓存当前脚本对应的 `CHunSession`，并返回脚本入口自身。"""
        if self._session is None:
            self._session = self._build_session()
            self._session.resolve.bind_defaults(elf=self.elf, libc_elf=self.libc)
        return self

    def gdb(self, script: str = "") -> object | None:
        """在 `GDB` 模式下对本地 process session 执行 attach。"""
        if not args.GDB:
            return None

        self.start()
        session = self.as_session
        if session.target.kind != "process":
            log.warning("当前为 REMOTE 模式，跳过 GDB attach。")
            return None
        return session.dbg.attach(script=script)

    def debug(self, script: str = "") -> "ScriptEntry":
        """在 `GDB` 下启动本地 process，并将 tube 接入当前脚本入口。"""
        if not args.GDB:
            return self.start()

        self.start()
        session = self.as_session
        if session.target.kind != "process":
            raise TransportConfigError("ScriptEntry.debug() 仅支持本地 process 目标。")
        if not isinstance(session.transport, PwntoolsTubeTransport):
            raise TransportConfigError(
                "ScriptEntry.debug() 仅支持 pwntools-tube transport。"
            )
        if session.transport.is_open:
            session.close()

        argv = list(session.target.argv)
        if not argv:
            if session.target.binary is None:
                raise TransportConfigError("process 模式至少需要 binary 或 argv。")
            argv = [session.target.binary]

        debug_tube = gdb.debug(
            argv,
            gdbscript=script or None,
            exe=session.target.binary,
            env=session.target.env or None,
            api=True,
            cwd=session.target.cwd,
        )
        session.transport.adopt_tube(debug_tube)
        session.dbg.bind_runtime(controller=getattr(debug_tube, "gdb", None))
        if hasattr(session, "_sync_transport_context"):
            session._sync_transport_context()
        self._wait_for_debugger_keypress()
        return self

    @staticmethod
    def _wait_for_debugger_keypress() -> None:
        stream = sys.stdin
        if not hasattr(stream, "isatty") or not stream.isatty():
            pause()
            return

        log.info("GDB 已就绪，按任意键继续 exp ...")
        fd = stream.fileno()
        old_attrs = termios.tcgetattr(fd)
        try:
            tty.setraw(fd)
            stream.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_attrs)

    @property
    def as_session(self) -> "CHunSession":
        """返回当前已启动的 session，用于访问完整框架能力。"""
        if self._session is None:
            raise RuntimeError("ScriptEntry 尚未启动，请先调用 start()。")
        return self._session

    @property
    def io(self) -> Any:
        """返回当前 session 的 `io` 入口，适合直接做 tube 交互。"""
        return self.as_session.io

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
    def libc_base(self) -> int:
        """返回当前 session 中已确认的 libc base。"""
        fact = self.rec.get_fact("libc.base")
        if fact is None or not isinstance(fact.value, int):
            raise RuntimeError(
                "libc.base 尚未推导，可能是多候选情况，请明确指定或编写爆破逻辑。"
            )
        return fact.value

    @property
    def libc_version(self) -> str:
        """返回当前 session 中已确认的 libc 版本名。"""
        fact = self.rec.get_fact("libc.version")
        if fact is None or not isinstance(fact.value, str):
            raise RuntimeError("libc.version 尚未确认。")
        return fact.value

    @property
    def rec(self) -> EvidenceRegistry:
        """访问 session 的事实记录入口，常用于记录 leak 和 context。"""
        return self.as_session.rec

    @property
    def infer(self) -> InferenceService:
        """访问 session 的最小 inference 服务。"""
        return self.as_session.infer

    @property
    def resolve(self) -> ResolveService:
        """访问 session 的解析服务，用于符号、DynELF 等推导。"""
        return self.as_session.resolve

    @property
    def dbg(self) -> PwntoolsGdbBridge:
        """访问 session 的交互式 GDB bridge。"""
        return self.as_session.dbg

    @property
    def crash(self) -> CorefileAnalyzer:
        """访问 session 的 core dump / crash 分析入口。"""
        return self.as_session.crash

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

    @staticmethod
    def _coerce_delim_or_regex(value: bytes | str, *, field_name: str) -> bytes | str:
        if isinstance(value, (bytes, str)):
            return value
        raise ValueError(f"{field_name} 必须是 bytes 或 str。")

    @staticmethod
    def _extract_regex_capture(match: object) -> bytes:
        if isinstance(match, bytes):
            return match
        if isinstance(match, str):
            return match.encode()
        if hasattr(match, "group"):
            groups = match.groups()  # type: ignore[attr-defined]
            if groups:
                group = groups[0]
            else:
                group = match.group(1)  # type: ignore[attr-defined]
            if isinstance(group, bytes):
                return group
            if isinstance(group, str):
                return group.encode()
            raise ValueError("regex capture 必须是 bytes 或 str。")
        if isinstance(match, (tuple, list)) and match:
            group = match[0]
            if isinstance(group, bytes):
                return group
            if isinstance(group, str):
                return group.encode()
        raise ValueError("recvregex(capture=True) 未返回可用的捕获组。")

    def recv_leak(
        self,
        name: str,
        delim: bytes | str | None = None,
        *,
        regex: bytes | str | None = None,
        domain: RecordDomain | None = None,
        offset: int = 0,
        source: str = "leak",
        mode: Literal["raw", "hex"] = "raw",
        size: int | None = None,
        strip_newline: bool = True,
    ) -> int:
        """接收一个泄漏值，完成解析、修正并自动写入 registry。"""
        if delim is not None and regex is not None:
            raise ValueError("delim 和 regex 不能同时提供。")
        if mode not in {"raw", "hex"}:
            raise ValueError("mode 必须是 'raw' 或 'hex'。")

        resolved_domain = domain or RecordDomain.LIBC
        payload: bytes

        if regex is not None:
            compiled = self._coerce_delim_or_regex(regex, field_name="regex")
            matched = self.recvregex(compiled, capture=True)
            payload = self._extract_regex_capture(matched)
        else:
            if delim is not None:
                resolved_delim = self._coerce_delim_or_regex(delim, field_name="delim")
                self.recvuntil(resolved_delim)
            if mode == "raw":
                default_size = 4 if int(getattr(self.elf, "bits", 64)) <= 32 else 6
                payload = self.recv(size or default_size)
                if strip_newline:
                    payload = payload.rstrip(b"\r\n")
            else:
                payload = self.recvline(keepends=not strip_newline)
                if strip_newline:
                    payload = payload.strip()

        if mode == "raw":
            pointer_width = int(getattr(self.elf, "bytes", 8))
            leak_bytes = payload[:pointer_width]
            leak_val = int.from_bytes(leak_bytes.ljust(pointer_width, b"\x00"), "little")
        else:
            text = payload.decode().strip()
            if not text:
                raise ValueError("未读取到可解析的十六进制泄漏。")
            try:
                leak_val = int(text, 16)
            except ValueError as exc:
                raise ValueError(f"无法解析十六进制泄漏：{text}") from exc

        actual_val = leak_val - offset
        self.rec.record_symbol_leak(
            name,
            actual_val,
            domain=resolved_domain,
            source=source,
        )
        log.success(f"Leak [{name}] captured: {hex(actual_val)}")
        return actual_val

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

    def __enter__(self) -> "ScriptEntry":
        self.start()
        self.as_session.open()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.as_session.close()

    def __getattr__(self, name: str) -> Any:
        """将未显式声明的低频方法兜底转发到当前 `io`。"""
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.io, name)


__all__ = ["ScriptEntry"]
