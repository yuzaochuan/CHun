"""脚本模式 facade。"""

from __future__ import annotations

import sys
import termios
import tty
import re
from dataclasses import replace
from typing import TYPE_CHECKING, Any, Literal, Mapping, Sequence

from ._compat import ELF, args, context, gdb, log, pause
from .bridges.gdb import PwntoolsGdbBridge
from .core.analysis import CorefileAnalyzer
from .core.errors import TransportConfigError
from .core.inference import InferenceService
from .core.models import (
    AddressLike,
    FmtExecutionReceipt,
    FmtExecutionResult,
    FmtExecutionMethod,
    FmtLayoutPolicy,
    FmtResultKind,
    FmtWriteCandidate,
    FmtWriteComparison,
    FmtTaskPolicy,
    FmtWriteStrategy,
    RenderedFmtTask,
    FmtRenderStep,
    RecordDomain,
    TargetSpec,
    ValueLike,
)
from .core.registry import EvidenceRegistry
from .core.resolve import ResolveService
from .plugins.fmt import FmtService
from .plugins.fmt.runtime import dispatch_fmt_payload
from .transports.pwntools_tube import PwntoolsTubeTransport

if TYPE_CHECKING:
    from .core.session import CHunSession

DEFAULT_SCRIPT_TERMINAL: tuple[str, ...] = ("tmux", "splitw", "-h")
_HEX_POINTER_RE = re.compile(rb"0x[0-9a-fA-F]+")


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
            self._session.bind_binaries(elf=self.elf, libc_elf=self.libc)
        return self

    def gdb(self, script: str = "") -> object | None:
        """在 `GDB` 模式下对本地 process session 执行 attach。"""
        if not args.GDB:
            return None

        self.start()
        session = self.session
        if session.target.kind != "process":
            log.warning("当前为 REMOTE 模式，跳过 GDB attach。")
            return None
        return session.dbg.attach(script=script)

    def debug(self, script: str = "") -> "ScriptEntry":
        """在 `GDB` 下启动本地 process，并将 tube 接入当前脚本入口。"""
        if not args.GDB:
            return self.start()

        self.start()
        session = self.session
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
    def libc_base(self) -> int:
        """返回当前 session 中已确认的 libc base。"""
        return self.session.libc_base

    @property
    def libc_version(self) -> str:
        """返回当前 session 中已确认的 libc 版本名。"""
        return self.session.libc_version

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

    @property
    def fmt(self) -> "_ScriptFmtFacade":
        """访问 session 的 fmt 服务。"""
        return _ScriptFmtFacade(self.session.fmt)

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
        delim_end: bytes | str | None = None,
        regex: bytes | str | None = None,
        domain: RecordDomain | None = None,
        offset: int = 0,
        source: str = "leak",
        mode: Literal["raw", "hex"] = "raw",
        index: int = 0,
        size: int | None = None,
        strip_newline: bool = True,
    ) -> int:
        """接收一个泄漏值，完成解析、修正并自动写入 registry。"""
        if delim is not None and regex is not None:
            raise ValueError("delim 和 regex 不能同时提供。")
        if delim_end is not None and regex is not None:
            raise ValueError("delim_end 和 regex 不能同时提供。")
        if mode not in {"raw", "hex"}:
            raise ValueError("mode 必须是 'raw' 或 'hex'。")
        if mode == "raw" and delim_end is not None:
            raise ValueError("mode='raw' 时不支持 delim_end。")

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
                if delim_end is not None:
                    resolved_delim_end = self._coerce_delim_or_regex(
                        delim_end, field_name="delim_end"
                    )
                    payload = self.recvuntil(resolved_delim_end, drop=True)
                else:
                    payload = self.recvline(keepends=not strip_newline)
                    if strip_newline:
                        payload = payload.strip()

        if mode == "raw":
            pointer_width = int(getattr(self.elf, "bytes", 8))
            leak_bytes = payload[:pointer_width]
            leak_val = int.from_bytes(
                leak_bytes.ljust(pointer_width, b"\x00"), "little"
            )
        else:
            matches = _HEX_POINTER_RE.findall(payload)
            if not matches:
                text = payload.decode(errors="replace").strip()
                raise ValueError("未读取到可解析的十六进制泄漏。")
            try:
                selected = matches[index]
            except IndexError as exc:
                tokens = ",".join(token.decode() for token in matches)
                raise ValueError(
                    f"共匹配到 {len(matches)} 个地址：{tokens}，index={index} 越界。"
                ) from exc
            if len(matches) > 1:
                tokens = ",".join(token.decode() for token in matches)
                log.warning(
                    f"共匹配到 {len(matches)} 个地址：{tokens}|默认选 {selected.decode()}"
                )
            leak_val = int(selected, 16)

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
        self.session.open()
        return self

    def __exit__(self, _exc_type: object, _exc: object, _tb: object) -> None:
        self.session.close()

    def __getattr__(self, name: str) -> Any:
        """将未显式声明的低频方法兜底转发到当前 `io`。"""
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.io, name)


__all__ = ["ScriptEntry"]


class _ScriptFmtWriteAction:
    """脚本态 fmt.write(...) 的延迟门面。"""

    def __init__(
        self,
        service: FmtService,
        *,
        target: AddressLike,
        value: ValueLike,
        strategy: FmtWriteStrategy,
        offset: int | None,
        task_policy: FmtTaskPolicy,
        data_offset: int | None,
        delim: bytes | str | None,
        head: bytes | None,
        head_numbwritten: int,
        end: bytes | None,
    ) -> None:
        self._service = service
        self._target = target
        self._value = value
        self._strategy = strategy
        self._offset = offset
        self._task_policy = task_policy
        self._data_offset = data_offset
        self._delim = delim
        self._head = head
        self._head_numbwritten = head_numbwritten
        self._end = end

    def info(
        self,
        buflen: int | None = None,
        *,
        strategies: Sequence[FmtWriteStrategy | str] = (
            FmtWriteStrategy.AUTO,
            FmtWriteStrategy.BYTE,
            FmtWriteStrategy.SHORT,
            FmtWriteStrategy.INT,
        ),
        show_hex: bool = False,
    ) -> Any:
        result = self._service.compare_write(
            self._target,
            self._value,
            strategies=strategies,
            offset=self._offset,
            task_policy=self._task_policy,
            data_offset=self._data_offset,
            buflen=buflen,
            end=self._end,
            show_hex=show_hex,
            loginfo=False,
        )
        if self._head:
            result = _apply_head_to_comparison(
                self._service,
                result,
                offset=self._offset,
                data_offset=self._data_offset,
                head=self._head,
                head_numbwritten=self._head_numbwritten,
            )
        log_fn = getattr(self._service, "_log_compare_write_result", None)
        if callable(log_fn):
            log_fn(result)
        return result

    def send(self, _buflen: int | None = None, *, show_hex: bool = False) -> Any:
        _ = (_buflen, show_hex)
        plan = self._service.plan_write(
            self._target,
            self._value,
            strategy=self._strategy,
            offset=self._offset,
            task_policy=self._task_policy,
            data_offset=self._data_offset,
        )
        if self._head:
            resolved_offset = _resolve_script_fmt_offset(
                self._service,
                plan=plan,
                offset=self._offset,
            )
            rendered = _render_headed_single_task(
                self._service,
                plan=plan,
                offset=resolved_offset,
                data_offset=self._data_offset,
                head=self._head,
                head_numbwritten=self._head_numbwritten,
            )
            rendered_items = (rendered,)
        else:
            resolved_offset = _resolve_script_fmt_offset(
                self._service,
                plan=plan,
                offset=self._offset,
            )
            rendered_items = self._service.render_plan(
                plan,
                offset=resolved_offset,
                data_offset=self._data_offset,
                store=False,
            )
        _warn_for_script_fmt_send(
            rendered_items,
            buflen=_buflen,
            end=self._end,
        )
        if self._delim is not None:
            self._service.session.io.recvuntil(_normalize_recv_delim(self._delim))
        if self._head:
            return _execute_headed_single_task(
                self._service,
                plan=plan,
                rendered=rendered_items[0],
                offset=resolved_offset,
                end=self._end,
            )
        return self._service.execute_plan(
            plan,
            offset=resolved_offset,
            data_offset=self._data_offset,
            receive=False,
            end=self._end,
        )


class _ScriptFmtWritesAction:
    """脚本态 fmt.writes(...) 的延迟门面。"""

    def __init__(
        self,
        service: FmtService,
        *,
        writes: Mapping[AddressLike, ValueLike] | Sequence[tuple[AddressLike, ValueLike]],
        strategy: FmtWriteStrategy,
        offset: int | None,
        task_policy: FmtTaskPolicy,
        data_offset: int | None,
        delim: bytes | str | None,
        end: bytes | None,
    ) -> None:
        self._service = service
        self._writes = writes
        self._strategy = strategy
        self._offset = offset
        self._task_policy = task_policy
        self._data_offset = data_offset
        self._delim = delim
        self._end = end

    def info(
        self,
        buflen: int | None = None,
        *,
        strategies: Sequence[FmtWriteStrategy | str] = (
            FmtWriteStrategy.AUTO,
            FmtWriteStrategy.BYTE,
            FmtWriteStrategy.SHORT,
            FmtWriteStrategy.INT,
        ),
        show_hex: bool = False,
    ) -> Any:
        return self._service.compare_writes(
            self._writes,
            strategies=strategies,
            offset=self._offset,
            task_policy=self._task_policy,
            data_offset=self._data_offset,
            buflen=buflen,
            end=self._end,
            show_hex=show_hex,
            loginfo=True,
        )

    def send(self, _buflen: int | None = None, *, show_hex: bool = False) -> Any:
        _ = (_buflen, show_hex)
        plan = self._service.plan_writes(
            self._writes,
            strategy=self._strategy,
            offset=self._offset,
            task_policy=self._task_policy,
            data_offset=self._data_offset,
        )
        rendered_items = self._service.render_plan(
            plan,
            offset=self._offset,
            data_offset=self._data_offset,
            store=False,
        )
        _warn_for_script_fmt_send(
            rendered_items,
            buflen=_buflen,
            end=self._end,
        )
        if self._delim is not None:
            self._service.session.io.recvuntil(_normalize_recv_delim(self._delim))
        return self._service.execute_plan(
            plan,
            offset=self._offset,
            data_offset=self._data_offset,
            receive=False,
            end=self._end,
        )


class _ScriptFmtFacade:
    """脚本态 fmt 语法糖：默认打开 offset 探测日志。"""

    def __init__(self, service: FmtService) -> None:
        self._service = service

    def find_offset(self, **kwargs: Any) -> Any:
        kwargs.setdefault("loginfo", True)
        return self._service.find_offset(**kwargs)

    def write(
        self,
        target: AddressLike,
        value: ValueLike,
        delim: bytes | str | None = None,
        offset: int | None = None,
        *,
        strategy: FmtWriteStrategy | str = FmtWriteStrategy.AUTO,
        task_policy: FmtTaskPolicy | str = FmtTaskPolicy.PACKED,
        data_offset: int | None = None,
        head: bytes | None = None,
        head_numbwritten: int = 0,
        end: bytes | None = b"\n",
    ) -> _ScriptFmtWriteAction:
        return _ScriptFmtWriteAction(
            self._service,
            target=target,
            value=value,
            strategy=self._normalize_strategy(strategy),
            offset=offset,
            task_policy=self._normalize_task_policy(task_policy),
            data_offset=data_offset,
            delim=delim,
            head=head,
            head_numbwritten=head_numbwritten,
            end=end,
        )

    def compare_write(
        self,
        target: AddressLike,
        value: ValueLike,
        *,
        strategies: Sequence[FmtWriteStrategy | str] = (
            FmtWriteStrategy.AUTO,
            FmtWriteStrategy.BYTE,
            FmtWriteStrategy.SHORT,
            FmtWriteStrategy.INT,
        ),
        offset: int | None = None,
        task_policy: FmtTaskPolicy | str = FmtTaskPolicy.PACKED,
        data_offset: int | None = None,
        buflen: int | None = None,
        end: bytes | None = b"\n",
        show_hex: bool = False,
        loginfo: bool = True,
    ) -> Any:
        return self._service.compare_write(
            target,
            value,
            strategies=strategies,
            offset=offset,
            task_policy=self._normalize_task_policy(task_policy),
            data_offset=data_offset,
            buflen=buflen,
            end=end,
            show_hex=show_hex,
            loginfo=loginfo,
        )

    def writes(
        self,
        writes: Mapping[AddressLike, ValueLike] | Sequence[tuple[AddressLike, ValueLike]],
        delim: bytes | str | None = None,
        offset: int | None = None,
        *,
        strategy: FmtWriteStrategy | str = FmtWriteStrategy.AUTO,
        task_policy: FmtTaskPolicy | str = FmtTaskPolicy.PACKED,
        data_offset: int | None = None,
        end: bytes | None = b"\n",
    ) -> _ScriptFmtWritesAction:
        return _ScriptFmtWritesAction(
            self._service,
            writes=writes,
            strategy=self._normalize_strategy(strategy),
            offset=offset,
            task_policy=self._normalize_task_policy(task_policy),
            data_offset=data_offset,
            delim=delim,
            end=end,
        )

    def compare_writes(
        self,
        writes: Mapping[AddressLike, ValueLike] | Sequence[tuple[AddressLike, ValueLike]],
        *,
        strategies: Sequence[FmtWriteStrategy | str] = (
            FmtWriteStrategy.AUTO,
            FmtWriteStrategy.BYTE,
            FmtWriteStrategy.SHORT,
            FmtWriteStrategy.INT,
        ),
        offset: int | None = None,
        task_policy: FmtTaskPolicy | str = FmtTaskPolicy.PACKED,
        data_offset: int | None = None,
        buflen: int | None = None,
        end: bytes | None = b"\n",
        show_hex: bool = False,
        loginfo: bool = True,
    ) -> Any:
        return self._service.compare_writes(
            writes,
            strategies=strategies,
            offset=offset,
            task_policy=self._normalize_task_policy(task_policy),
            data_offset=data_offset,
            buflen=buflen,
            end=end,
            show_hex=show_hex,
            loginfo=loginfo,
        )

    @staticmethod
    def _normalize_strategy(strategy: FmtWriteStrategy | str) -> FmtWriteStrategy:
        if isinstance(strategy, FmtWriteStrategy):
            return strategy
        return FmtWriteStrategy(str(strategy).lower())

    @staticmethod
    def _normalize_task_policy(policy: FmtTaskPolicy | str) -> FmtTaskPolicy:
        if isinstance(policy, FmtTaskPolicy):
            return policy
        return FmtTaskPolicy(str(policy).lower())

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self._service, name)


def _normalize_recv_delim(delim: bytes | str) -> bytes:
    if isinstance(delim, bytes):
        return delim
    return delim.encode()


def _resolve_script_fmt_offset(
    service: FmtService,
    *,
    plan: object,
    offset: int | None,
) -> int:
    if offset is not None:
        return offset
    plan_offset = getattr(plan, "offset", None)
    if isinstance(plan_offset, int):
        return plan_offset
    return int(service.get_offset(required=True).index)


def _render_headed_single_task(
    service: FmtService,
    *,
    plan: object,
    offset: int,
    data_offset: int | None,
    head: bytes,
    head_numbwritten: int,
) -> RenderedFmtTask:
    from pwnlib.fmtstr import AtomWrite, make_payload_dollar
    from pwnlib.util.cyclic import cyclic

    tasks = tuple(getattr(plan, "tasks"))
    if len(tasks) != 1:
        raise ValueError("head 目前仅支持单 task 的 write 发送。")

    task = tasks[0]
    pointer_size = int(getattr(plan, "pointer_size"))
    bits = int(getattr(plan, "bits"))
    endian = str(getattr(plan, "endian"))
    no_dollars = bool(getattr(plan, "metadata", {}).get("no_dollars", False))
    counter_size = 4 if bits <= 32 else 8
    atoms = [
        AtomWrite(atom.address, atom.width, atom.value, mask=atom.mask)
        for atom in task.atoms
    ]
    stabilization_steps = 0

    with context.local(bits=bits, endian=endian):
        if data_offset is not None:
            raw_fmt, data = make_payload_dollar(
                data_offset,
                atoms,
                numbwritten=head_numbwritten,
                countersize=counter_size,
                no_dollars=no_dollars,
            )
            required_prefix_len = (data_offset - offset) * pointer_size
            padding_len = required_prefix_len - (len(head) + len(raw_fmt))
            if padding_len < 0:
                raise ValueError("head 过长，显式 data_offset 无法容纳当前 payload。")
            resolved_data_offset = data_offset
        else:
            fmt_bytes = b""
            data = b""
            for stabilization_steps in range(1, 33):
                slot_delta = (len(head) + len(fmt_bytes)) // pointer_size
                candidate_data_offset = offset + slot_delta
                raw_fmt, data = make_payload_dollar(
                    candidate_data_offset,
                    atoms,
                    numbwritten=head_numbwritten,
                    countersize=counter_size,
                    no_dollars=no_dollars,
                )
                padding_len = (-(len(head) + len(raw_fmt))) % pointer_size
                total_prefix_len = len(head) + len(raw_fmt) + padding_len
                new_data_offset = offset + (total_prefix_len // pointer_size)
                if new_data_offset == candidate_data_offset:
                    resolved_data_offset = new_data_offset
                    break
                fmt_bytes = raw_fmt + cyclic(padding_len)
            else:
                raise RuntimeError("head payload did not converge")

    padding_bytes = cyclic(padding_len)
    current_counter = head_numbwritten
    steps: list[FmtRenderStep] = []
    for index, (chun_atom, atom) in enumerate(zip(task.atoms, atoms, strict=True)):
        padding = atom.compute_padding(current_counter)
        counter_after = (current_counter + padding) % (1 << (counter_size * 8))
        steps.append(
            FmtRenderStep(
                task_index=task.task_index,
                atom=chun_atom,
                arg_index=resolved_data_offset + index,
                specifier=_specifier_for_width(chun_atom.width),
                counter_before=current_counter,
                counter_after=counter_after,
                padding=padding,
                modulus=1 << (chun_atom.width * 8),
                address_offset=index * pointer_size,
                metadata={"backend": "pwntools", "head": head},
            )
        )
        current_counter = counter_after

    fmt_bytes = head + raw_fmt
    payload = fmt_bytes + padding_bytes + data
    return RenderedFmtTask(
        task_index=task.task_index,
        atoms=tuple(task.atoms),
        steps=tuple(steps),
        fmt_bytes=fmt_bytes,
        data_bytes=data,
        payload=payload,
        offset=offset,
        data_offset=resolved_data_offset,
        backend="pwntools",
        layout=FmtLayoutPolicy.ADDRESSES_LAST,
        initial_counter=head_numbwritten,
        final_counter=current_counter,
        metadata={
            "backend": "pwntools",
            "head": head,
            "head_numbwritten": head_numbwritten,
            "padding_len": len(padding_bytes),
            "data_offset": resolved_data_offset,
            "stabilization_steps": stabilization_steps,
        },
    )


def _execute_headed_single_task(
    service: FmtService,
    *,
    plan: object,
    rendered: RenderedFmtTask,
    offset: int,
    end: bytes | None,
) -> FmtExecutionResult:
    response, dispatch, metadata = dispatch_fmt_payload(
        service.session,
        rendered.payload,
        receive=False,
        newline=(end is None),
        end=end,
        recv_bytes=4096,
        recv_until=None,
    )
    receipt = FmtExecutionReceipt(
        task_index=rendered.task_index,
        rendered=rendered,
        payload=rendered.payload,
        offset=offset,
        transport_kind=service.session.transport_spec.kind,
        dispatch=FmtExecutionMethod(dispatch),
        response=response,
        source="fmt.execute(head)",
        metadata=metadata,
    )
    return FmtExecutionResult(
        kind=FmtResultKind.EXECUTION,
        plan=plan,
        receipts=(receipt,),
        offset=offset,
        result_prefix="fmt.write",
        source="fmt.execute(head)",
        metadata={"head": rendered.metadata.get("head"), "data_offset": rendered.data_offset},
    )


def _apply_head_to_comparison(
    service: FmtService,
    result: FmtWriteComparison,
    *,
    offset: int | None,
    data_offset: int | None,
    head: bytes,
    head_numbwritten: int,
) -> FmtWriteComparison:
    candidates: list[FmtWriteCandidate] = []
    for candidate in result.candidates:
        if not candidate.ok or candidate.plan is None:
            candidates.append(candidate)
            continue
        try:
            resolved_offset = _resolve_script_fmt_offset(
                service,
                plan=candidate.plan,
                offset=offset,
            )
            rendered = _render_headed_single_task(
                service,
                plan=candidate.plan,
                offset=resolved_offset,
                data_offset=data_offset,
                head=head,
                head_numbwritten=head_numbwritten,
            )
            candidates.append(
                FmtWriteCandidate(
                    strategy=candidate.strategy,
                    plan=candidate.plan,
                    rendered_tasks=(rendered,),
                    metadata=dict(candidate.metadata),
                )
            )
        except Exception as exc:
            candidates.append(
                FmtWriteCandidate(
                    strategy=candidate.strategy,
                    error=f"{type(exc).__name__}: {exc}",
                    metadata=dict(candidate.metadata),
                )
            )
    return FmtWriteComparison(
        target=result.target,
        value=result.value,
        candidates=tuple(candidates),
        metadata=dict(result.metadata),
    )


def _specifier_for_width(width: int) -> str:
    return {
        1: "hhn",
        2: "hn",
        4: "n",
        8: "lln",
    }[width]


def _warn_for_script_fmt_send(
    rendered_items: Sequence[object],
    *,
    buflen: int | None,
    end: bytes | None,
) -> None:
    suffix_len = len(end or b"")
    total_send_len = sum(
        len(getattr(item, "payload", b"")) + suffix_len for item in rendered_items
    )
    max_pad = max(
        (
            int(getattr(step, "padding", 0))
            for item in rendered_items
            for step in getattr(item, "steps", ())
        ),
        default=0,
    )
    pad_time = _pad_time_for_max_padding(max_pad)

    if buflen is not None and total_send_len > buflen:
        log.error(
            f"fmt 发送长度 {total_send_len}B 超过 buflen={buflen}B，仍继续发送。"
        )
    if pad_time in {"HIGH", "EXTREME"}:
        log.warning(
            f"fmt 的 pad_time 为 {pad_time}（max_pad={max_pad}），服务端可能变慢或超时。"
        )


def _pad_time_for_max_padding(max_pad: int) -> str:
    if max_pad < 0x100:
        return "LOW"
    if max_pad < 0x1000:
        return "MEDIUM"
    if max_pad < 0x10000:
        return "HIGH"
    return "EXTREME"
